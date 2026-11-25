/**
 * Known state → known state. An instruction may name the state it starts from and the state it must
 * end in, at two levels:
 *
 *   TREE (fleet-wide, boot-independent): the tree's history root before the operation and after it. The operation
 *   digest covers `seq`, so the end root is fixed the moment the instruction is written:
 *     to = SHA256("shirudo-tree-history\0" ‖ from ‖ operation_digest(seq, op, id, selector, artifact)).
 *   The gate appends only if the tree is at `from` now (compare-and-swap) and proves the publication arrived at `to`.
 *
 *   NODE (per machine, per boot): the TPM-quoted register before the sync and the register the sync must produce.
 *   Shirudo extends the register with the load/unload event, then the tree_op event, for each operation it applies, so
 *   the end value is computable from the quoted start value before anything runs. A key can be released ahead of the
 *   upgrade, sealed to the predicted end state: the machine can open it only by arriving exactly there.
 *
 * Not an upgrade followed by a new quote: a planned transition between two values both known in advance.
 */
import { createHash } from 'node:crypto';
import { ZERO32, eventDigest, historyStep, operationDigest, rawOf } from './canonical.ts';
import type { EventRecord, Publication, ShirudoDigest, TreeOperation } from './canonical.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const strip = (s: string) => s.replace(/^sha256:/, '').toLowerCase();
const HEX64 = /^[0-9a-f]{64}$/;

/** Tree-level transition, carried in the instruction. Roots are lowercase hex (Shirudo's outcomes.history_root form). */
export type TreeTransition = { seq: number; from_history_root: string; to_history_root: string };

/** The tree's head: last seq and the history root over every operation up to it. */
export function treeHead(pub: Publication): { seq: number; history_root: string } {
  let root: Buffer = pub.base.seq === 0 ? Buffer.from(ZERO32) : pub.base.history_root ? Buffer.from(strip(pub.base.history_root), 'hex') : (() => { throw new Error('treeHead: base.seq > 0 without base.history_root'); })();
  let seq = pub.base.seq;
  for (const op of [...pub.operations].sort((a, b) => a.seq - b.seq)) {
    if (op.seq !== seq + 1) throw new Error(`treeHead: operations are not contiguous at seq ${op.seq}`);
    if (operationDigest(op) !== op.operation_digest) throw new Error(`treeHead: operation ${op.seq} digest does not recompute`);
    root = historyStep(root, op.operation_digest); seq = op.seq;
  }
  return { seq, history_root: hex(root) };
}

/** The tree transition an operation makes when appended at `head.seq + 1`. */
export function planTreeTransition(head: { seq: number; history_root: string }, opDigestAt: (seq: number) => ShirudoDigest): TreeTransition {
  const seq = head.seq + 1;
  return { seq, from_history_root: strip(head.history_root), to_history_root: hex(historyStep(Buffer.from(strip(head.history_root), 'hex'), opDigestAt(seq))) };
}

/** Null when the transition is internally consistent for this operation digest; else the problem. */
export function treeTransitionProblem(t: TreeTransition, opDigestAtSeq: ShirudoDigest): string | null {
  if (!Number.isSafeInteger(t?.seq) || t.seq <= 0) return 'transition.seq';
  if (!HEX64.test(t.from_history_root ?? '') || !HEX64.test(t.to_history_root ?? '')) return 'transition roots must be 64 lowercase hex';
  if (t.seq === 1 && t.from_history_root !== hex(ZERO32)) return 'transition at seq 1 must start from the zero root';
  return hex(historyStep(Buffer.from(t.from_history_root, 'hex'), opDigestAtSeq)) === t.to_history_root ? null : 'transition.to_history_root does not follow from from_history_root and the operation';
}

// ── node level ────────────────────────────────────────────────────────────────────────────────────────────────────

/** What one applied operation will extend into the register, in order (eventlog.rst; observed on a real target). */
export type PredictedEvent = { type: 'upatch_load' | 'upatch_unload' | 'tree_op'; digest: string; seq: number; name?: string };

/**
 * Events a sync will extend for `op`, given the publication (to find what a delete unloads). `applies` is whether this
 * node's selector matches: an applied add loads then records; an applied delete unloads the payload of the add it
 * retires, then records. An operation the node does not apply is NOT predicted here: the caller must say so explicitly
 * (`applies: false` throws), because guessing the unapplied outcome would make the prediction a claim we have not observed.
 */
export function predictOperationEvents(op: TreeOperation, pub: Publication, opts: { applies: boolean; upatchName?: string }): PredictedEvent[] {
  if (!opts.applies) throw new Error('predictOperationEvents: unapplied outcome not modelled (not observed on a real target)');
  const name = opts.upatchName ?? op.id;
  const ev = (r: Partial<EventRecord>) => hex(eventDigest(r as EventRecord)!);
  let payload: ShirudoDigest;
  if (op.op === 'add') payload = op.artifact.payload_sha256;
  else {
    const prior = pub.operations.filter((o) => o.op === 'add' && o.id === op.id && o.seq < op.seq).at(-1);
    if (!prior) throw new Error(`predictOperationEvents: delete of ${op.id} at seq ${op.seq} retires no earlier add`);
    payload = prior.artifact.payload_sha256;
  }
  const loadType = op.op === 'add' ? 'upatch_load' as const : 'upatch_unload' as const;
  return [
    { type: loadType, seq: op.seq, name, digest: ev({ type: loadType, upatch: { name, payload_sha256: payload } }) },
    { type: 'tree_op', seq: op.seq, digest: ev({ type: 'tree_op', tree: { seq: op.seq, operation_digest: op.operation_digest } }) },
  ];
}

/** Fold predicted events onto a register value: reg' = SHA256(reg ‖ event_digest), as the TPM NV extend does. */
export function predictRegister(from: string, events: { digest: string }[]): string {
  return events.reduce((reg, e) => createHash('sha256').update(Buffer.concat([Buffer.from(reg, 'hex'), rawOf(e.digest)])).digest('hex'), strip(from));
}

/** Node-level transition: the quoted start, the operations the sync will apply, and the end value they must produce. */
export type NodeTransition = {
  boot_id: string;
  from_register: string;
  from_seq: number;
  to_seq: number;
  operations: { seq: number; operation_digest: ShirudoDigest }[];
  events: PredictedEvent[];
  to_register: string;
};

export function planNodeTransition(args: {
  bootId: string; fromRegister: string; fromSeq: number; pub: Publication;
  applies: (op: TreeOperation) => boolean; upatchName?: (op: TreeOperation) => string | undefined; toSeq?: number;
}): NodeTransition {
  const ops = args.pub.operations.filter((o) => o.seq > args.fromSeq && o.seq <= (args.toSeq ?? Infinity)).sort((a, b) => a.seq - b.seq);
  if (!ops.length) throw new Error('planNodeTransition: nothing to apply');
  const events = ops.flatMap((o) => { const n = args.upatchName?.(o); return predictOperationEvents(o, args.pub, { applies: args.applies(o), ...(n ? { upatchName: n } : {}) }); });
  return {
    boot_id: args.bootId, from_register: strip(args.fromRegister), from_seq: args.fromSeq, to_seq: ops.at(-1)!.seq,
    operations: ops.map((o) => ({ seq: o.seq, operation_digest: o.operation_digest })), events, to_register: predictRegister(args.fromRegister, events),
  };
}

export type Arrival = { arrived: boolean; rows: { check: string; pass: boolean; detail: string }[] };

/**
 * Did the node travel the planned path? Takes TPM-quoted evidence AFTER the sync (register value verified by
 * `attest verify`) and its eventlog: same boot, the start value appears in the replay exactly where the plan began, the
 * events after it are exactly the predicted ones, and the quoted end value is the predicted one.
 */
export function checkArrival(plan: NodeTransition, after: { boot_id: string; register: string; eventlog: EventRecord[] }): Arrival {
  const rows: Arrival['rows'] = [];
  rows.push({ check: 'same-boot', pass: after.boot_id === plan.boot_id, detail: after.boot_id === plan.boot_id ? plan.boot_id : `planned ${plan.boot_id}, quoted ${after.boot_id}` });
  // Walk this boot's replay to find the start value, then compare what followed it.
  const boot = after.eventlog.filter((r) => r.boot_id === plan.boot_id);
  let start = -1; boot.forEach((r, i) => { if (r.type === 'init') start = i; });
  let reg = hex(ZERO32); let at = -1;
  const recs = start < 0 ? [] : boot.slice(start);
  const digests = recs.map((r) => { const d = eventDigest(r); return d ? hex(d) : null; });
  if (plan.from_register === reg) at = 0;
  for (let i = 0; i < digests.length && at < 0; i++) { reg = predictRegister(reg, [{ digest: digests[i] ?? '00'.repeat(32) }]); if (reg === plan.from_register) at = i + 1; }
  rows.push({ check: 'start-on-path', pass: at >= 0, detail: at >= 0 ? `start value reached after ${at} record(s) of this boot` : 'the quoted start value never occurs in this boot\'s replay' });
  const tail = at >= 0 ? digests.slice(at) : [];
  const same = tail.length === plan.events.length && tail.every((d, i) => d === plan.events[i]!.digest);
  rows.push({ check: 'path-exact', pass: same, detail: same ? `${plan.events.length} predicted event(s), nothing else` : `predicted ${plan.events.length} event(s): ${plan.events.map((e) => e.type).join(',')}; measured ${tail.length}: ${recs.slice(Math.max(at, 0)).map((r) => r.type).join(',')}` });
  rows.push({ check: 'end-value', pass: strip(after.register) === plan.to_register, detail: `${strip(after.register).slice(0, 16)}… vs predicted ${plan.to_register.slice(0, 16)}…` });
  return { arrived: rows.every((r) => r.pass), rows };
}
