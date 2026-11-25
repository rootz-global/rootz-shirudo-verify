/** The published real-target run (runs/2026-11-25-known-state) re-checked from its files: anyone can reproduce the verdicts. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { checkArrival, replayRegister } from '../src/index.ts';

const dir = join(import.meta.dirname, '../runs/2026-11-25-known-state');
const j = (f: string) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
const arrive = (plan: string, ev: string) => { const e = j(ev); return checkArrival(j(plan), { boot_id: e.boot_id, register: e.register.value, eventlog: e.eventlog }); };

test('run: every evidence file replays to its quoted register', () => {
  for (const f of ['KS-start-evidence.json', 'KS-arrived-evidence.json', 'KS-offpath-evidence.json']) {
    const e = j(f); assert.equal(replayRegister(e.eventlog, { bootId: e.boot_id, expected: e.register.value }).status, 'match', f);
  }
});
test('run: plan 1 starts at the quoted start and the node arrived on plan', () => {
  assert.equal(j('KS-plan-1.json').from_register, j('KS-start-evidence.json').register.value);
  assert.equal(arrive('KS-plan-1.json', 'KS-arrived-evidence.json').arrived, true);
});
test('run: plan 2 with a rogue op on the path is off plan (path and end value)', () => {
  const a = arrive('KS-plan-2.json', 'KS-offpath-evidence.json');
  assert.equal(a.arrived, false);
  assert.deepEqual(a.rows.filter((r) => !r.pass).map((r) => r.check).sort(), ['end-value', 'path-exact']);
});
