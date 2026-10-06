/**
 * Alias Transparency Profile (`alias-transparency/0.1`, draft), stage 1: alias normalization and the
 * KEYTRANS building blocks — VRF input and index, commitments, the prefix tree, the log tree, the
 * Configuration and tree head, the implicit binary search tree and the binary ladder.
 *
 * Spec: T§2, T§3, T§4, T§5 (`v0.10/dsip-alias-transparency-profile-v0.10-draft.md`); draft-ietf-keytrans-protocol
 * for the structures. The exact byte layouts and output shapes are the vectors README's, "Kind: `alias-transparency`".
 */
import { createHash, createHmac, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import { vrfVerify } from "./vrf.js";

const hex = (s: string): Buffer => Buffer.from(s, "hex");
const sha256 = (...parts: Uint8Array[]): Buffer => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const u8 = (n: number): Buffer => Buffer.of(n);
const u16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const u64 = (n: number | bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const ZERO32 = Buffer.alloc(32);

/** The commitment key Kc. Spec: T§5 item 3 */
const KC = hex("d821f8790d97709796b4d7903357c3f5");
/** KT_128_SHA256_Ed25519. Spec: T§2 */
const SUITE_KT_128_SHA256_ED25519 = 2;
/** contactMonitoring. Spec: T§2 */
const MODE_CONTACT_MONITORING = 1;

const LABEL = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;

/**
 * Normalize an alias; `null` when it is not one.
 * Spec: T§3
 * Impl (spec-gap 104): ASCII-only — printable-ASCII local part with case kept, A-label domains only (labels of
 * `[A-Za-z0-9-]`, not beginning or ending with `-`), lowercased; at most 255 bytes.
 */
export function normalizeAlias(alias: string): string | null {
  const at = alias.lastIndexOf("@");
  if (at < 0) return null;
  const local = alias.slice(0, at);
  const domain = alias.slice(at + 1);
  if (local.length === 0) return null;
  for (const ch of local) {
    const c = ch.codePointAt(0)!;
    if (c < 0x21 || c > 0x7e || ch === "@") return null;
  }
  const labels = domain.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
  const out = `${local}@${domain.toLowerCase()}`;
  return Buffer.byteLength(out, "utf8") <= 255 ? out : null;
}

/** `VrfInput { opaque label<0..2^8-1>; uint32 version; }`; `null` when it does not encode. Spec: T§5 item 1 */
export function vrfInput(label: string, version: number): Buffer | null {
  const l = Buffer.from(label, "utf8");
  if (l.length > 255 || !Number.isInteger(version) || version < 0 || version > 0xffffffff) return null;
  return Buffer.concat([u8(l.length), l, u32(version)]);
}

/** `HMAC-SHA256(Kc, CommitmentValue)` over an already-encoded body after the opening. Spec: T§5 item 3 */
const commit = (opening: Buffer, body: Buffer): Buffer => createHmac("sha256", KC).update(opening).update(body).digest();

/** The prefix tree's root over leaves with distinct 32-byte indexes. Spec: T§5 item 4 */
function prefixRoot(leaves: { index: Buffer; commitment: Buffer }[], depth: number): Buffer {
  if (leaves.length === 1) return sha256(Buffer.of(0x02), leaves[0]!.index, leaves[0]!.commitment);
  const bit = (b: Buffer): number => (b[depth >> 3]! >> (7 - (depth & 7))) & 1;
  const side = (v: number): Buffer => {
    const sub = leaves.filter((l) => bit(l.index) === v);
    return sub.length ? prefixRoot(sub, depth + 1) : ZERO32;
  };
  return sha256(Buffer.of(0x03), side(0), side(1));
}

/** The log tree's value over the leaf values [lo, hi). Spec: T§5 item 5 */
function logValue(leaves: Buffer[], lo: number, hi: number): Buffer {
  if (hi - lo === 1) return leaves[lo]!;
  let k = 1;
  while (k * 2 < hi - lo) k *= 2;
  const tag = (n: number): Buffer => Buffer.of(n === 1 ? 0x00 : 0x01);
  return sha256(tag(k), logValue(leaves, lo, lo + k), tag(hi - lo - k), logValue(leaves, lo + k, hi));
}

/**
 * A Configuration for mode 1, as the vectors carry it. Spec: T§5 item 6
 * Impl: the KEYTRANS editors' copy (2026-09-16) layout the README follows — mode 1 has no `leaf_public_key`.
 */
interface Configuration {
  ciphersuite: number;
  mode: number;
  signature_public_key: string;
  vrf_public_key: string;
  max_ahead: number;
  max_behind: number;
  reasonable_monitoring_window: number;
  maximum_lifetime: number | null;
}

/** TLS-encode a Configuration. Spec: T§5 item 6; `[KT]` §11.2 */
export function encodeConfiguration(c: Configuration): Buffer {
  const key = (k: string): Buffer => Buffer.concat([u16(hex(k).length), hex(k)]);
  return Buffer.concat([
    u16(c.ciphersuite),
    u8(c.mode),
    key(c.signature_public_key),
    key(c.vrf_public_key),
    u64(c.max_ahead),
    u64(c.max_behind),
    u64(c.reasonable_monitoring_window),
    c.maximum_lifetime === null ? u8(0) : Buffer.concat([u8(1), u64(c.maximum_lifetime)]),
  ]);
}

/**
 * Parse a Configuration and accept it under T§2: suite, then mode, then shape.
 * Spec: T§2, T§4, T§5 item 6
 * Impl (spec-gap 104): suite 0x0002 and mode 1 only; every key must be 32 bytes (all three are Ed25519 keys
 * under that suite); a u64 above 2^53−1 is malformed, so every value is an exact JSON number.
 */
export function acceptConfiguration(bytes: Buffer): JsonObject {
  let at = 0;
  const take = (n: number): Buffer | null => {
    if (at + n > bytes.length) return null;
    const out = bytes.subarray(at, at + n);
    at += n;
    return out;
  };
  const malformed = { error: "malformed" };
  const suite = take(2);
  if (!suite) return malformed;
  if (suite.readUInt16BE() !== SUITE_KT_128_SHA256_ED25519) return { error: "unsupported-suite" };
  const mode = take(1);
  if (!mode) return malformed;
  if (mode[0] !== MODE_CONTACT_MONITORING) return { error: "unsupported-mode" };
  const keys: string[] = [];
  for (let i = 0; i < 2; i++) {
    const len = take(2);
    if (!len) return malformed;
    const key = take(len.readUInt16BE());
    if (!key || key.length !== 32) return malformed;
    keys.push(key.toString("hex"));
  }
  const u64At = (): number | null => {
    const v = take(8);
    if (!v) return null;
    const n = v.readBigUInt64BE();
    return n > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(n);
  };
  const ints: number[] = [];
  for (let i = 0; i < 3; i++) {
    const v = u64At();
    if (v === null) return malformed;
    ints.push(v);
  }
  const present = take(1);
  if (!present || present[0]! > 1) return malformed;
  let lifetime: number | null = null;
  if (present[0] === 1) {
    lifetime = u64At();
    if (lifetime === null) return malformed;
  }
  if (at !== bytes.length) return malformed;
  return {
    config: {
      signature_public_key: keys[0]!,
      vrf_public_key: keys[1]!,
      max_ahead: ints[0]!,
      max_behind: ints[1]!,
      reasonable_monitoring_window: ints[2]!,
      maximum_lifetime: lifetime,
    },
  };
}

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verify(key: Buffer, message: Buffer, signature: Buffer): boolean {
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI_ED25519, key]), format: "der", type: "spki" });
    return cryptoVerify(null, message, pub, signature);
  } catch {
    return false;
  }
}

/** Verify a tree head's signature over `TreeHeadTBS`. Spec: T§4, T§5 item 7 */
export function verifyTreeHead(configuration: Buffer, treeSize: number, root: Buffer, signature: Buffer): JsonObject {
  const accepted = acceptConfiguration(configuration);
  if (!("config" in accepted)) return accepted;
  const key = hex((accepted["config"] as JsonObject)["signature_public_key"] as string);
  const tbs = Buffer.concat([configuration, u64(treeSize), root]);
  return { valid: ed25519Verify(key, tbs, signature) };
}

/** The implicit binary search tree over n entries: its root and frontier. Spec: T§5 item 8; `[KT]` Appendix A */
export function searchTree(n: number): { root: number; frontier: number[] } {
  const N = BigInt(n);
  const level = (x: bigint): bigint => {
    let k = 0n;
    while ((x >> k) & 1n) k++;
    return k;
  };
  const left = (x: bigint): bigint => x ^ (1n << (level(x) - 1n));
  const right = (x: bigint): bigint => {
    x ^= 3n << (level(x) - 1n);
    while (x >= N) x = left(x);
    return x;
  };
  let root = 1n;
  while (root * 2n <= N) root *= 2n;
  root -= 1n;
  const frontier = [root];
  while (frontier[frontier.length - 1]! !== N - 1n) frontier.push(right(frontier[frontier.length - 1]!));
  return { root: Number(root), frontier: frontier.map(Number) };
}

/** The base binary ladder for a version. Spec: T§5 item 8; `[KT]` Appendix B */
export function ladder(version: number): number[] {
  const out: number[] = [];
  for (let i = 0; ; i++) {
    const v = 2 ** i - 1;
    out.push(v);
    if (v > version) break;
  }
  let lo = out.length >= 2 ? out[out.length - 2]! : 0;
  let hi = out[out.length - 1]!;
  while (lo + 1 < hi) {
    const mid = Math.floor((lo + hi) / 2);
    out.push(mid);
    if (mid <= version) lo = mid;
    else hi = mid;
  }
  return out;
}

/** Run one `alias-transparency` vector's check. Spec: T§2–T§5; README "Kind: `alias-transparency`" */
export function runAliasTransparency(input: JsonObject): Json | undefined {
  switch (input["check"]) {
    case "alias": {
      const label = normalizeAlias(input["alias"] as string);
      return label === null ? { error: "not-an-alias" } : { label };
    }
    case "vrf-input": {
      const bytes = vrfInput(input["label"] as string, input["version"] as number);
      return bytes ? { bytes: bytes.toString("hex") } : { error: "vrf-input" };
    }
    case "vrf-verify": {
      const beta = vrfVerify(hex(input["public_key"] as string), hex(input["alpha"] as string), hex(input["proof"] as string));
      return beta ? { valid: true, beta: beta.toString("hex") } : { valid: false, beta: null };
    }
    case "index": {
      const alpha = vrfInput(input["label"] as string, input["version"] as number);
      if (!alpha) return { error: "vrf-input" };
      const beta = vrfVerify(hex(input["public_key"] as string), alpha, hex(input["proof"] as string));
      return beta ? { index: beta.subarray(0, 32).toString("hex") } : { error: "vrf-invalid" };
    }
    case "commitment": {
      const opening = hex(input["opening"] as string);
      if (opening.length !== 16) return { error: "opening" };
      const label = vrfInput(input["label"] as string, input["version"] as number);
      if (!label) return { error: "label" };
      const value = Buffer.from(input["value"] as string, "utf8");
      return { commitment: commit(opening, Buffer.concat([label, u32(value.length), value])).toString("hex") };
    }
    case "commitment-raw":
      return { commitment: commit(hex(input["opening"] as string), hex(input["body"] as string)).toString("hex") };
    case "prefix-root": {
      const leaves = (input["leaves"] as JsonObject[]).map((l) => ({
        index: hex(l["index"] as string),
        commitment: hex(l["commitment"] as string),
      }));
      const distinct = new Set(leaves.map((l) => l.index.toString("hex")));
      const shaped = leaves.every((l) => l.index.length === 32 && l.commitment.length === 32);
      if (leaves.length === 0 || !shaped || distinct.size !== leaves.length) return { error: "malformed" };
      return { root: prefixRoot(leaves, 0).toString("hex") };
    }
    case "prefix-parent": {
      const side = (v: Json | undefined): Buffer => (v === null || v === undefined ? ZERO32 : hex(v as string));
      return { hash: sha256(Buffer.of(0x03), side(input["left"]), side(input["right"])).toString("hex") };
    }
    case "log-root": {
      const leaves = (input["entries"] as JsonObject[]).map((e) =>
        sha256(u64(e["timestamp"] as number), hex(e["prefix_root"] as string)),
      );
      if (leaves.length === 0) return { error: "malformed" };
      return { root: logValue(leaves, 0, leaves.length).toString("hex") };
    }
    case "configuration":
      return { bytes: encodeConfiguration(input["config"] as unknown as Configuration).toString("hex") };
    case "configuration-accept":
      return acceptConfiguration(hex(input["bytes"] as string));
    case "tree-head":
      return verifyTreeHead(
        hex(input["configuration"] as string),
        input["tree_size"] as number,
        hex(input["root"] as string),
        hex(input["signature"] as string),
      );
    case "search-tree":
      return searchTree(input["n"] as number);
    case "ladder":
      return { ladder: ladder(input["version"] as number) };
    default:
      return undefined;
  }
}
