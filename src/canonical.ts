/**
 * Shirudo's own canonical forms, re-implemented so a Rootz verifier recomputes every digest itself and never trusts a
 * printout of the tool it is checking. Source of truth: shirudo-dev/shirudo@0132734
 *   - operation digest:  util/bpm_tree.c tree_operation_digest(), Documentation/reference/formats/upatch-tree.rst
 *   - JSON string escape: util/json.c put_string_n()
 *   - history root:      util/chain_history.c chain_history_step()
 *   - register events:   Documentation/reference/eventlog.rst "Event digests" and "Replay"
 * Vectors in ../vectors/ are pinned against real `shirudo` output (see test/canonical.test.ts).
 */
import { createHash } from 'node:crypto';

export type ShirudoDigest = `sha256:${string}`; // Shirudo writes digests as "sha256:" + 64 lowercase hex
const HEX64 = /^[0-9a-f]{64}$/;
const SHA = /^sha256:[0-9a-f]{64}$/;

export type Selector = {
  architecture?: string[];
  kconfig?: Record<string, string[]>;
  kernel_build_id?: string[];
  kernel_release_prefix?: string[];
  labels?: Record<string, string[]>;
};
export type Artifact = { repository: string; manifest_digest: ShirudoDigest; layer_digest: ShirudoDigest; payload_sha256: ShirudoDigest };
/** The five keys the operation digest covers. */
export type OperationCore = { seq: number; op: 'add' | 'delete'; id: string; selector: Selector; artifact: Artifact };
export type TreeOperation = OperationCore & { fixes?: string[]; operation_digest: ShirudoDigest };
export type Publication = {
  schema: 1;
  tree_id: string;
  generation: number;
  parent_manifest_digest?: ShirudoDigest;
  base: { seq: number; segment_manifest_digest?: ShirudoDigest; history_root?: string };
  operations: TreeOperation[];
  head: { seq: number };
};

/** util/json.c: escape `"` and `\`, \n \r \t by name, other C0 controls as \u00xx (lowercase), everything else verbatim UTF-8. */
export function jsonString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"' || ch === '\\') out += '\\' + ch;
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c === 0) throw new Error('shirudo: NUL in a string is refused by the writer (EILSEQ)');
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

/** Byte order, as qsort with strcmp over UTF-8 does. */
function byteCompare(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

const list = (vals: string[]) => '[' + vals.map(jsonString).join(',') + ']';
const kv = (obj: Record<string, string[]>) =>
  '{' + Object.keys(obj).sort(byteCompare).map((k) => jsonString(k) + ':' + list(obj[k]!)).join(',') + '}';

/**
 * tree_emit_selector(): keys in the order architecture, kconfig, kernel_build_id, kernel_release_prefix, labels;
 * empty lists and empty maps left out; map keys in byte order; list values in the published order. Always emitted,
 * `{}` when nothing selects.
 */
export function selectorJson(s: Selector): string {
  const parts: string[] = [];
  if (s.architecture?.length) parts.push('"architecture":' + list(s.architecture));
  if (s.kconfig && Object.keys(s.kconfig).length) parts.push('"kconfig":' + kv(s.kconfig));
  if (s.kernel_build_id?.length) parts.push('"kernel_build_id":' + list(s.kernel_build_id));
  if (s.kernel_release_prefix?.length) parts.push('"kernel_release_prefix":' + list(s.kernel_release_prefix));
  if (s.labels && Object.keys(s.labels).length) parts.push('"labels":' + kv(s.labels));
  return '{' + parts.join(',') + '}';
}

/** `bpm tree append` sorts every selector list in byte order before it publishes; the instruction must do the same. */
export function normalizeSelector(s: Selector): Selector {
  const sortList = (v?: string[]) => (v && v.length ? [...v].sort(byteCompare) : undefined);
  const sortMap = (m?: Record<string, string[]>) => {
    if (!m || !Object.keys(m).length) return undefined;
    const out: Record<string, string[]> = {};
    for (const k of Object.keys(m).sort(byteCompare)) out[k] = [...m[k]!].sort(byteCompare);
    return out;
  };
  const r: Selector = {};
  const a = sortList(s.architecture); if (a) r.architecture = a;
  const k = sortMap(s.kconfig ?? (s as { kernel_config?: Record<string, string[]> }).kernel_config); if (k) r.kconfig = k;
  const b = sortList(s.kernel_build_id); if (b) r.kernel_build_id = b;
  const p = sortList(s.kernel_release_prefix); if (p) r.kernel_release_prefix = p;
  const l = sortMap(s.labels); if (l) r.labels = l;
  return r;
}

/** The exact bytes Shirudo hashes for an operation: {seq, op, id, selector, artifact}, compact. */
export function operationCanonical(op: OperationCore): string {
  if (!Number.isSafeInteger(op.seq) || op.seq <= 0) throw new Error('shirudo: seq must be a positive integer');
  const a = op.artifact;
  return '{"seq":' + op.seq + ',"op":' + jsonString(op.op) + ',"id":' + jsonString(op.id) + ',"selector":' + selectorJson(op.selector) +
    ',"artifact":{"repository":' + jsonString(a.repository) + ',"manifest_digest":' + jsonString(a.manifest_digest) +
    ',"layer_digest":' + jsonString(a.layer_digest) + ',"payload_sha256":' + jsonString(a.payload_sha256) + '}}';
}

export function operationDigest(op: OperationCore): ShirudoDigest {
  return `sha256:${createHash('sha256').update(operationCanonical(op), 'utf8').digest('hex')}`;
}

export function isShirudoDigest(v: unknown): v is ShirudoDigest {
  return typeof v === 'string' && SHA.test(v);
}
export function rawOf(d: ShirudoDigest | string): Buffer {
  const hex = d.startsWith('sha256:') ? d.slice(7) : d;
  if (!HEX64.test(hex)) throw new Error(`shirudo: not a sha256 digest: ${d}`);
  return Buffer.from(hex, 'hex');
}

const sha = (...parts: Uint8Array[]) => createHash('sha256').update(Buffer.concat(parts)).digest();
const tag = (t: string) => Buffer.from(t + '\0', 'utf8');
const be64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
export const ZERO32 = Buffer.alloc(32);

/** outcomes.history_root: SHA256("shirudo-tree-history\0" ‖ prev ‖ op_digest). Same on every node at the same seq. */
export function historyStep(prev: Uint8Array, opDigest: ShirudoDigest): Buffer {
  return sha(tag('shirudo-tree-history'), prev, rawOf(opDigest));
}
/** projection_root: SHA256(prev ‖ op_digest), only over operations the node applied (outcomes 1 and 3). */
export function projectionStep(prev: Uint8Array, opDigest: ShirudoDigest): Buffer {
  return sha(prev, rawOf(opDigest));
}
export function foldHistory(digests: ShirudoDigest[], from: Uint8Array = ZERO32): Buffer {
  return digests.reduce<Buffer>((acc, d) => historyStep(acc, d), Buffer.from(from));
}

/** One line of /var/lib/shirudo/eventlog (reference/eventlog.rst). Only the fields Rootz reads are typed. */
export type EventRecord = {
  schema: 1; ts: string; nv_index?: string; alg?: string; digest: string; type: string; boot_id?: string;
  upatch?: { name: string; payload_sha256: string };
  key?: { fingerprint?: string; cert_sha256: string };
  tree?: { seq: number; op?: string; id?: string; operation_digest: ShirudoDigest };
  cert_sha256?: string; set?: { name: string; payload_sha256: string; type?: string }[]; tree_root?: string;
  chain?: string;
  [k: string]: unknown;
};

/** set_digest: SHA256 of one line "<payload_sha256> <name>\n" per member (prefixed "java " for java), sorted by name. */
export function setDigest(set: { name: string; payload_sha256: string; type?: string }[]): Buffer {
  const lines = [...set].sort((a, b) => byteCompare(a.name, b.name))
    .map((m) => `${m.type === 'java' ? 'java ' : ''}${m.payload_sha256.replace(/^sha256:/, '')} ${m.name}\n`).join('');
  return createHash('sha256').update(lines, 'utf8').digest();
}

/**
 * The event digest an extend computed, derived from the record's own fields (eventlog.rst "Event digests").
 * Returns null for a record type this reader does not derive (it is then reported, never silently trusted).
 */
export function eventDigest(r: EventRecord): Buffer | null {
  const name = (s: string) => Buffer.from(s, 'utf8');
  switch (r.type) {
    case 'upatch_load': return r.upatch ? sha(tag('shirudo-upatch'), rawOf(r.upatch.payload_sha256), name(r.upatch.name)) : null;
    case 'upatch_unload': return r.upatch ? sha(tag('shirudo-unload'), rawOf(r.upatch.payload_sha256), name(r.upatch.name)) : null;
    case 'java_load': return r.upatch ? sha(tag('shirudo-java'), rawOf(r.upatch.payload_sha256), name(r.upatch.name)) : null;
    case 'java_unload': return r.upatch ? sha(tag('shirudo-java-unload'), rawOf(r.upatch.payload_sha256), name(r.upatch.name)) : null;
    case 'key_revoke': return r.key ? sha(tag('shirudo-key-revoke'), rawOf(r.key.cert_sha256)) : null;
    case 'tree_op': return r.tree ? sha(tag('shirudo-tree'), be64(r.tree.seq), rawOf(r.tree.operation_digest)) : null;
    case 'init': {
      if (typeof r.cert_sha256 !== 'string' || !Array.isArray(r.set) || typeof r.tree_root !== 'string') return null;
      return sha(tag('shirudo-init'), rawOf(r.cert_sha256), setDigest(r.set), rawOf(r.tree_root));
    }
    default: return null;
  }
}

export type Replay = {
  /** match: every record's digest derives from its fields and the fold equals `expected`. */
  status: 'match' | 'mismatch' | 'not-evaluable';
  register: string | null;
  records: EventRecord[];
  problems: { index: number; reason: string }[];
};

/**
 * Fold this boot's records from the last `init` (register starts at zero there), checking each record's digest against
 * its fields. `expected` is the register value from TPM-quoted evidence (`attest verify`); without it the result is
 * not-evaluable, because a log that agrees with itself proves nothing.
 */
export function replayRegister(lines: EventRecord[], opts: { bootId?: string; expected?: string } = {}): Replay {
  const problems: Replay['problems'] = [];
  const boot = opts.bootId ? lines.filter((r) => r.boot_id === opts.bootId) : lines;
  let start = -1;
  boot.forEach((r, i) => { if (r.type === 'init') start = i; });
  if (start < 0) return { status: 'not-evaluable', register: null, records: [], problems: [{ index: -1, reason: 'no init record: this boot has no replay' }] };
  const records = boot.slice(start);
  let reg = Buffer.from(ZERO32);
  records.forEach((r, i) => {
    const d = eventDigest(r);
    if (!d) { problems.push({ index: i, reason: `record type ${r.type} not derivable here` }); return; }
    if (typeof r.digest !== 'string' || d.toString('hex') !== r.digest.replace(/^sha256:/, '')) problems.push({ index: i, reason: 'digest does not derive from the record fields' });
    reg = sha(reg, d);
  });
  const register = reg.toString('hex');
  if (problems.length) return { status: 'mismatch', register, records, problems };
  if (!opts.expected) return { status: 'not-evaluable', register, records, problems: [{ index: -1, reason: 'no TPM-quoted register value supplied' }] };
  return { status: register === opts.expected.replace(/^sha256:/, '').toLowerCase() ? 'match' : 'mismatch', register, records, problems };
}

/** Parse an eventlog file's text the way Shirudo's readers do: a last line without "\n" is no record yet. */
export function parseEventlog(text: string): EventRecord[] {
  if (text.includes('\0')) throw new Error('shirudo eventlog: NUL in file fails the replay');
  const lines = text.split('\n');
  lines.pop(); // the part after the last "\n" is an unfinished append (or empty)
  return lines.filter((l) => l.length > 0).map((l) => JSON.parse(l) as EventRecord);
}

/**
 * The artifact `bpm tree append` will publish for one .upatch, computed BEFORE the append so the officer can sign the
 * exact operation (tools/shirudo-build/bpm-publish.c tree_describe_artifact(); util/bpm_oci.c bpm_oci_emit_descriptor()).
 * Header: name at offset 16 (256 bytes, NUL-padded), payload_sha256 at 272 (32 bytes) (reference/formats/upatch-format.rst).
 */
export const OCI_MANIFEST_MEDIA = 'application/vnd.oci.image.manifest.v1+json';
export const UPATCH_MEDIA = 'application/vnd.shirudo.upatch.v1';
export const EMPTY_CONFIG_MEDIA = 'application/vnd.oci.empty.v1+json';

export function upatchHeader(bytes: Uint8Array): { name: string; payload_sha256: ShirudoDigest } {
  const b = Buffer.from(bytes);
  if (b.length < 304) throw new Error('upatch: shorter than its header');
  const raw = b.subarray(16, 272);
  const end = raw.indexOf(0);
  const name = raw.subarray(0, end < 0 ? raw.length : end).toString('utf8');
  return { name, payload_sha256: `sha256:${b.subarray(272, 304).toString('hex')}` };
}

export function describeArtifact(upatchBytes: Uint8Array, treeRepository: string): { artifact: Artifact; manifest: string; tag: string; name: string } {
  const { name, payload_sha256 } = upatchHeader(upatchBytes);
  const hexOf = (x: Uint8Array | string) => createHash('sha256').update(x).digest('hex');
  const layer = `sha256:${hexOf(upatchBytes)}`;
  const config = `sha256:${hexOf('{}')}`;
  const manifest = '{"schemaVersion":2,"mediaType":' + jsonString(OCI_MANIFEST_MEDIA) + ',"artifactType":' + jsonString(UPATCH_MEDIA) +
    ',"config":{"mediaType":' + jsonString(EMPTY_CONFIG_MEDIA) + ',"digest":' + jsonString(config) + ',"size":2}' +
    ',"layers":[{"mediaType":' + jsonString(UPATCH_MEDIA) + ',"digest":' + jsonString(layer) + ',"size":' + upatchBytes.length + '}]' +
    ',"annotations":{"org.opencontainers.image.title":' + jsonString(`${name}.upatch`) + '}}';
  return {
    name, manifest, tag: `upatch-${name}-${payload_sha256.slice(7, 23)}`,
    artifact: { repository: treeRepository, manifest_digest: `sha256:${hexOf(manifest)}`, layer_digest: layer as ShirudoDigest, payload_sha256 },
  };
}
