/**
 * Known state → known state, pinned against REAL Shirudo output (vectors/real-tree.json, real-transition.json):
 * the end state is predicted from the start state and the instruction alone, then compared with what Shirudo and the
 * TPM actually produced.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  checkArrival, eventDigest,
  planNodeTransition, planTreeTransition, predictOperationEvents, predictRegister, replayRegister, treeHead, treeTransitionProblem,
} from '../src/index.ts';
import type { EventRecord, Publication } from '../src/index.ts';

const v = JSON.parse(readFileSync(join(import.meta.dirname, '../vectors/real-tree.json'), 'utf8'));
const pub = JSON.parse(Buffer.from(v.publication_b64, 'base64').toString('utf8')) as Publication;
const upTo = (seq: number): Publication => ({ ...pub, operations: pub.operations.filter((o) => o.seq <= seq), head: { seq } });

test('tree: the head root of the real publication equals Shirudo\'s own history-root fold', () => {
  assert.equal(treeHead(pub).history_root, v.history_root_fold);
});

test('tree: the end root is predicted from the start root and the operation alone (seq 2 → 3, real tree)', () => {
  const t = planTreeTransition(treeHead(upTo(2)), (seq) => { const o = pub.operations.find((x) => x.seq === seq)!; return o.operation_digest; });
  assert.equal(t.seq, 3);
  assert.equal(t.to_history_root, treeHead(pub).history_root);
  assert.equal(treeTransitionProblem(t, pub.operations[2]!.operation_digest), null);
  assert.match(treeTransitionProblem({ ...t, to_history_root: '1'.repeat(64) }, pub.operations[2]!.operation_digest)!, /does not follow/);
});

// One tree and one boot of a real target: TPM-certified registers after seq 1 (D), seq 2 (F), seq 3 (E).
const x = JSON.parse(readFileSync(join(import.meta.dirname, '../vectors/real-transition.json'), 'utf8'));
const xpub = x.publication as Publication;
const D = x.evidence.D, F = x.evidence.F, E = x.evidence.E;

test('node: from the certified register after seq 1, the register after seq 2 and after seq 3 is predicted exactly', () => {
  for (const ev of [D, E, F]) { assert.equal(ev.verify_verdict, 'ok'); assert.equal(replayRegister(ev.eventlog, { expected: ev.register }).status, 'match'); }
  const toF = planNodeTransition({ bootId: D.boot_id, fromRegister: D.register, fromSeq: 1, toSeq: 2, pub: xpub, applies: () => true });
  assert.deepEqual(toF.events.map((y) => y.type), ['upatch_unload', 'tree_op']);
  assert.equal(toF.to_register, F.register, 'D → F: predicted before, certified after');
  const toE = planNodeTransition({ bootId: D.boot_id, fromRegister: D.register, fromSeq: 1, pub: xpub, applies: () => true });
  assert.equal(toE.to_register, E.register, 'D → E across two operations');
  const fToE = planNodeTransition({ bootId: F.boot_id, fromRegister: F.register, fromSeq: 2, pub: xpub, applies: () => true });
  assert.equal(fToE.to_register, E.register, 'F → E');
});

test('node: a delete unloads the payload that was LOADED, not the delete artifact\'s own payload (observed)', () => {
  const del = xpub.operations.find((o) => o.seq === 2)!;
  const [unload] = predictOperationEvents(del, xpub, { applies: true });
  const measured = F.eventlog.find((r: EventRecord) => r.type === 'upatch_unload');
  assert.equal(unload!.digest, measured.digest.replace(/^sha256:/, ''));
  assert.notEqual(del.artifact.payload_sha256, measured.upatch.payload_sha256);
});

test('arrival: the real path is on plan; a different start, an extra event or another boot is off plan', () => {
  const plan = planNodeTransition({ bootId: D.boot_id, fromRegister: D.register, fromSeq: 1, toSeq: 2, pub: xpub, applies: () => true });
  const ok = checkArrival(plan, { boot_id: F.boot_id, register: F.register, eventlog: F.eventlog });
  assert.equal(ok.arrived, true, JSON.stringify(ok.rows));

  // Arrival checked against a later state (seq 3 also happened): the path is not exact and the end value differs.
  const past = checkArrival(plan, { boot_id: E.boot_id, register: E.register, eventlog: E.eventlog });
  assert.deepEqual(past.rows.filter((y) => !y.pass).map((y) => y.check).sort(), ['end-value', 'path-exact']);

  const wrongStart = { ...plan, from_register: '11'.repeat(32) };
  assert.equal(checkArrival(wrongStart, { boot_id: F.boot_id, register: F.register, eventlog: F.eventlog }).rows.find((y) => y.check === 'start-on-path')!.pass, false);

  // A direct load right after the planned sync: the end value moves and the path is not exact.
  const extra: EventRecord = { ...F.eventlog[1], upatch: { name: 'rogue', payload_sha256: F.eventlog[1].upatch.payload_sha256 } };
  extra.digest = eventDigest(extra)!.toString('hex');
  const r2 = checkArrival(plan, { boot_id: F.boot_id, register: predictRegister(F.register, [{ digest: extra.digest }]), eventlog: [...F.eventlog, extra] });
  assert.deepEqual(r2.rows.filter((y) => !y.pass).map((y) => y.check).sort(), ['end-value', 'path-exact']);

  assert.equal(checkArrival(plan, { boot_id: 'another-boot', register: F.register, eventlog: F.eventlog }).rows.find((y) => y.check === 'same-boot')!.pass, false);
});

test('node: an operation the node does not apply is refused by the predictor, not guessed', () => {
  assert.throws(() => planNodeTransition({ bootId: 'b', fromRegister: '00'.repeat(32), fromSeq: 0, pub, applies: () => false }), /not modelled/);
});
