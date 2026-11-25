#!/usr/bin/env node
/**
 * rootz-shirudo-verify: check a Shirudo node's TPM register yourself, and plan a transition from a known state to a
 * known state before you run it. Zero dependencies; Node ≥ 22.18 (runs TypeScript directly).
 *
 *   replay   <evidence.json>                         eventlog → register, compared with the quoted value
 *   head     <publication.json>                      tree head seq and history root
 *   plan     <start-evidence.json> <publication.json> [--from-seq N] [--to-seq N]
 *                                                    the register the sync will produce, before it runs
 *   arrival  <plan.json> <after-evidence.json>        did the node travel exactly the planned path?
 *
 * <evidence.json> is `shirudo attest` output. This tool does NOT verify the TPM quote signature: run
 * `shirudo attest verify` on the same file first. A log that agrees with itself proves nothing without that.
 */
import { readFileSync } from 'node:fs';
import { checkArrival, planNodeTransition, replayRegister, treeHead } from './index.ts';
import type { NodeTransition, Publication } from './index.ts';

const [cmd, ...rest] = process.argv.slice(2);
const flags = new Map<string, string>(); const args: string[] = [];
for (let i = 0; i < rest.length; i++) { const a = rest[i]!; if (a.startsWith('--')) flags.set(a.slice(2), rest[++i] ?? ''); else args.push(a); }
const json = (p: string | undefined) => { if (!p) usage(); return JSON.parse(readFileSync(p!, 'utf8')); };
const out = (v: unknown, ok = true) => { console.log(JSON.stringify(v, null, 2)); process.exit(ok ? 0 : 1); };
function usage(): never { console.error('usage: rootz-shirudo-verify replay|head|plan|arrival … (see the header of src/cli.ts)'); process.exit(2); }

if (cmd === 'replay') {
  const ev = json(args[0]);
  const r = replayRegister(ev.eventlog, { bootId: ev.boot_id, expected: ev.register?.value });
  out({ status: r.status, register: r.register, quoted: ev.register?.value ?? null, records: r.records.length, problems: r.problems }, r.status === 'match');
} else if (cmd === 'head') {
  out(treeHead(json(args[0]) as Publication));
} else if (cmd === 'plan') {
  const ev = json(args[0]); const pub = json(args[1]) as Publication;
  const r = replayRegister(ev.eventlog, { bootId: ev.boot_id, expected: ev.register?.value });
  if (r.status !== 'match') out({ error: 'the start evidence does not replay to its quoted register', replay: r.status, problems: r.problems }, false);
  // Default start: the last tree_op this boot measured.
  const lastOp = [...r.records].reverse().find((x) => x.type === 'tree_op')?.tree?.seq ?? 0;
  const fromSeq = flags.has('from-seq') ? Number(flags.get('from-seq')) : lastOp;
  out(planNodeTransition({ bootId: ev.boot_id, fromRegister: ev.register.value, fromSeq, pub, applies: () => true, ...(flags.has('to-seq') ? { toSeq: Number(flags.get('to-seq')) } : {}) }));
} else if (cmd === 'arrival') {
  const plan = json(args[0]) as NodeTransition; const ev = json(args[1]);
  const a = checkArrival(plan, { boot_id: ev.boot_id, register: ev.register.value, eventlog: ev.eventlog });
  out(a, a.arrived);
} else usage();
