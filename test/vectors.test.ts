/**
 * Rootz's re-implementation of Shirudo's canonical forms, replayed offline against REAL Shirudo output
 * (vectors/real-tree.json, written by deploy/shirudo/pin.mts from `shirudo bpm build/push/tree append` at
 * shirudo-dev/shirudo@0132734). No Shirudo needed to run this test.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describeArtifact, foldHistory, operationDigest, upatchHeader } from '../src/index.ts';
import type { Publication } from '../src/index.ts';

const v = JSON.parse(readFileSync(join(import.meta.dirname, '../vectors/real-tree.json'), 'utf8'));
const pub = JSON.parse(Buffer.from(v.publication_b64, 'base64').toString('utf8')) as Publication;
const up = Object.fromEntries(Object.entries(v.upatches_b64 as Record<string, string>).map(([k, b]) => [k, Buffer.from(b, 'base64')]));

test('real tree: every published operation_digest recomputes from Rootz canonical form', () => {
  assert.equal(pub.operations.length, 3);
  for (const op of pub.operations) assert.equal(operationDigest(op), op.operation_digest, `seq ${op.seq}`);
});

test('real tree: the artifact predicted from the .upatch BEFORE append equals what Shirudo published', () => {
  const [add, del, fleet] = pub.operations;
  assert.deepEqual(describeArtifact(up.canary_load!, v.tree_repository).artifact, add!.artifact);
  assert.deepEqual(describeArtifact(up.canary_unload!, v.tree_repository).artifact, del!.artifact);
  assert.deepEqual(describeArtifact(up.fleet_load!, v.tree_repository).artifact, fleet!.artifact);
  assert.equal(upatchHeader(up.canary_load!).name, add!.id);
});

test('real tree: the same source built twice is two payloads — build evidence must bind the payload, never the source', () => {
  const [add, , fleet] = pub.operations;
  // Finding 2026-11-24: one BPF source, two `bpm build` runs (versions 1.0.0 and 1.0.1) → two payload_sha256 values.
  assert.notEqual(add!.artifact.payload_sha256, fleet!.artifact.payload_sha256);
  assert.ok(add!.selector.labels && !fleet!.selector.labels, 'canary-scoped vs fleet-scoped');
  assert.notEqual(add!.operation_digest, fleet!.operation_digest);
});

test('real tree: a one-byte change in the selector is a different operation (the instruction cannot be stretched)', () => {
  const add = pub.operations[0]!;
  assert.notEqual(operationDigest({ ...add, selector: { ...add.selector, labels: { role: ['locaL'] } } }), add.operation_digest);
  assert.equal(foldHistory(pub.operations.map((o) => o.operation_digest)).toString('hex'), v.history_root_fold);
});

test('real TPM evidence: Rootz replays the eventlog to the exact register value the TPM certified (attest verify: ok)', async () => {
  const { replayRegister } = await import('../src/index.ts');
  const ev = JSON.parse(readFileSync(join(import.meta.dirname, '../vectors/real-eventlog.json'), 'utf8'));
  const r = replayRegister(ev.eventlog, { expected: ev.register_value });
  assert.equal(r.status, 'match');
  assert.equal(r.register, ev.register_value);
  // One changed byte anywhere in a record breaks it.
  const bad = structuredClone(ev.eventlog); bad[1].upatch.name += 'x';
  assert.equal(replayRegister(bad, { expected: ev.register_value }).status, 'mismatch');
});
