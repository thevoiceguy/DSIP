/**
 * Presence Profile sealed records (draft, `presence/0.2`): audience tags and keys derived from the identity's
 * key agreement secret, a record's state sealed and opened, the keys a grant carries, and what a subscriber
 * can read of a body.
 *
 * Spec: P§12.1 (HKDF-SHA256 from the clamped X25519 secret: tags, key ids, keys), P§12.2 (the record:
 * `{"state":"S"}` padded to 128 bytes, AES-256-GCM, the AAD), P§12.3 (`presence_keys`: HPKE to the grantee),
 * P§12.4 (unreadable records, in order, take no part in combining)
 * (`v1.0/dsip-presence-profile-v1.0-draft.md`). Contract: `impl/vectors/README.md`, "Kind: `presence`".
 */
import { createCipheriv, createDecipheriv, createHmac } from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import { b64urlDecode, utf8Decode } from "../encoding.js";
import { HPKE_SEALED_ALG, hpkeOpen } from "../hpke.js";
import { aggregatePresence, type AggregatePresence, type PresenceRecordView } from "./presence.js";

/** Spec: P§12.2 — every sealed state's plaintext length. */
export const SEALED_PLAINTEXT_LEN = 128;
/** Spec: P§12.2 — nonce (12) ‖ ciphertext (128) ‖ tag (16). */
export const SEALED_STATE_LEN = 12 + SEALED_PLAINTEXT_LEN + 16;
/** Spec: P§12.1 — the scope of records with no audience. */
export const MAIN_SCOPE = "main";

const TOKEN = /^[a-z][a-z0-9-]*$/;
const KID = /^(main|[a-z][a-z0-9-]*)\.(0|[1-9][0-9]*)$/;
const ZERO = Buffer.from([0]);

/** RFC 7748 `decodeScalar25519`. Spec: P§12.1 — keys derive from the secret as clamped. */
export function clampSecret(secret: Buffer): Buffer {
  const s = Buffer.from(secret);
  s[0] = s[0]! & 248;
  s[31] = (s[31]! & 127) | 64;
  return s;
}

/** RFC 5869 HKDF-SHA256, empty salt (32 zero bytes as the HMAC key), IKM the clamped secret. Spec: P§12.1 */
function hkdf(secret: Buffer, info: Buffer, length: number): Buffer {
  const prk = createHmac("sha256", Buffer.alloc(32)).update(clampSecret(secret)).digest();
  let out = Buffer.alloc(0);
  let block = Buffer.alloc(0);
  for (let i = 1; out.length < length; i++) {
    block = createHmac("sha256", prk).update(Buffer.concat([block, info, Buffer.from([i])])).digest();
    out = Buffer.concat([out, block]);
  }
  return out.subarray(0, length);
}

function joined(...parts: string[]): Buffer {
  return Buffer.concat(parts.flatMap((p, i) => (i === 0 ? [Buffer.from(p, "utf8")] : [ZERO, Buffer.from(p, "utf8")])));
}

/** RFC 4648 base32, lower case, without padding. */
function base32Lower(bytes: Buffer): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(acc << (5 - bits)) & 31];
  return out;
}

/** The wire name of the audience the subject labels `label`. Spec: P§12.1 */
export function audienceTag(secret: Buffer, subject: string, label: string): string {
  return "k-" + base32Lower(hkdf(secret, joined("dsip presence audience v1", subject, label), 10));
}

/** The 32-byte key `kid` names. Spec: P§12.1 */
export function presenceKey(secret: Buffer, subject: string, kid: string): Buffer {
  return hkdf(secret, joined("dsip presence key v1", subject, kid), 32);
}

/** A key id's scope: the part before its last `.`. Spec: P§12.1 */
export function kidScope(kid: string): string {
  const dot = kid.lastIndexOf(".");
  return dot < 0 ? kid : kid.slice(0, dot);
}

/** The fields of a sealed record that its AAD binds. Spec: P§12.2 */
export interface SealedRecordFields {
  subject: string;
  device: string;
  audience?: string;
  kid: string;
  seq: number;
  expires_at: number;
}

function u64be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

/** Spec: P§12.2 — `dsip presence v1 ‖ 0 ‖ subject ‖ 0 ‖ device ‖ 0 ‖ audience ‖ 0 ‖ kid ‖ 0 ‖ u64be(seq) ‖ u64be(expires_at)`. */
function recordAad(r: SealedRecordFields): Buffer {
  return Buffer.concat([
    joined("dsip presence v1", r.subject, r.device, r.audience ?? "", r.kid),
    ZERO,
    u64be(r.seq),
    u64be(r.expires_at),
  ]);
}

/** A record's `sealed_state`: the state sealed under `key` with `nonce`. Spec: P§12.2 */
export function sealRecord(r: SealedRecordFields, state: string, key: Buffer, nonce: Buffer): string {
  const plaintext = Buffer.alloc(SEALED_PLAINTEXT_LEN, 0x20);
  Buffer.from(JSON.stringify({ state }), "utf8").copy(plaintext);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(recordAad(r));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]).toString("base64url");
}

/** Why a sealed record cannot be read, in P§12.4's order. */
export type Unreadable = "presence-key-unknown" | "sealed-too-short" | "aead-open-failed" | "presence-plaintext-invalid";

/** The state of a sealed record (raw: P§5's fallback is the combining rule's), or why it is unreadable. Spec: P§12.4 */
export function openRecord(r: SealedRecordFields, sealedState: string, keys: (kid: string) => Buffer | undefined): { state: string } | { unreadable: Unreadable } {
  const key = keys(r.kid);
  if (key === undefined) return { unreadable: "presence-key-unknown" };
  const sealed = b64urlDecode(sealedState);
  if (sealed === null || sealed.length !== SEALED_STATE_LEN) return { unreadable: "sealed-too-short" };
  let plaintext: Buffer;
  try {
    const d = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
    d.setAAD(recordAad(r));
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    plaintext = Buffer.concat([d.update(sealed.subarray(12, sealed.length - 16)), d.final()]);
  } catch {
    return { unreadable: "aead-open-failed" };
  }
  const body = parseObject(plaintext);
  const state = body?.["state"];
  if (body === null || Object.keys(body).length !== 1 || typeof state !== "string" || state.length > 64 || !TOKEN.test(state)) {
    return { unreadable: "presence-plaintext-invalid" };
  }
  return { state };
}

/** UTF-8 JSON text (trailing spaces allowed) that is an object, or `null`. */
function parseObject(bytes: Buffer): JsonObject | null {
  const text = utf8Decode(bytes);
  if (text === null) return null;
  try {
    const v = JSON.parse(text) as Json;
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as JsonObject) : null;
  } catch {
    return null;
  }
}

/** Why a grant's `presence_keys` cannot be read. Spec: P§12.3 */
export type GrantKeysError = "sealed-alg-unsupported" | "sealed-open-failed" | "sealed-plaintext-invalid";

/**
 * The keys a grant carries (`kid` → key), opened with the grantee identity's secret as stored. A grant names no
 * scope but `main` and its own `presence_audience`; a later entry for one `kid` replaces an earlier.
 *
 * Spec: P§12.3.
 */
export function openGrantKeys(grant: JsonObject, secret: Buffer): Map<string, Buffer> | GrantKeysError {
  const sealed = grant["presence_keys"] as JsonObject;
  if (sealed["alg"] !== HPKE_SEALED_ALG) return "sealed-alg-unsupported";
  const enc = b64urlDecode(String(sealed["enc"]));
  const ct = b64urlDecode(String(sealed["ct"]));
  const aad = joined(String(grant["id"]), String(grant["from"]), String(grant["to"]));
  const plaintext = enc && ct ? hpkeOpen(enc, clampSecret(secret), Buffer.from("dsip presence keys v1"), aad, ct) : null;
  if (plaintext === null) return "sealed-open-failed";
  if (plaintext.length === 0 || plaintext.length % 256 !== 0) return "sealed-plaintext-invalid";
  const body = parseObject(plaintext);
  const entries = body?.["keys"];
  if (body === null || Object.keys(body).length !== 1 || !Array.isArray(entries)) return "sealed-plaintext-invalid";
  const scopes = new Set([MAIN_SCOPE]);
  if (typeof grant["presence_audience"] === "string") scopes.add(grant["presence_audience"]);
  const out = new Map<string, Buffer>();
  for (const e of entries) {
    if (e === null || typeof e !== "object" || Array.isArray(e)) return "sealed-plaintext-invalid";
    const { kid, key } = e as JsonObject;
    if (Object.keys(e).length !== 2 || typeof kid !== "string" || typeof key !== "string") return "sealed-plaintext-invalid";
    if (!KID.test(kid) || !scopes.has(kidScope(kid))) return "sealed-plaintext-invalid";
    const bytes = b64urlDecode(key);
    if (bytes === null || bytes.length !== 32) return "sealed-plaintext-invalid";
    out.set(kid, bytes);
  }
  return out;
}

/** A record of a body as a subscriber reads it: plain, or sealed. Spec: P§3, P§12.2 */
export type BodyRecord = SealedRecordFields & { state?: string; sealed_state?: string };

/**
 * The identity's presence from a body's records: each sealed one opened with the keys held; one that cannot be
 * read takes no part, and its device is listed in `unreadable` (sorted, once each).
 *
 * Spec: P§12.4, P§4.
 */
export function viewPresence(records: BodyRecord[], keys: (kid: string) => Buffer | undefined, asserted: string | undefined, now: number): AggregatePresence & { unreadable: string[] } {
  const readable: PresenceRecordView[] = [];
  const unreadable = new Set<string>();
  for (const r of records) {
    if (r.sealed_state === undefined) {
      readable.push({ state: r.state!, expires_at: r.expires_at });
      continue;
    }
    const opened = openRecord(r, r.sealed_state, keys);
    if ("state" in opened) readable.push({ state: opened.state, expires_at: r.expires_at });
    else unreadable.add(r.device);
  }
  return { ...aggregatePresence(readable, asserted, now), unreadable: [...unreadable].sort() };
}

/** The `presence` checks of P§12. A check this module does not cover returns `undefined`. */
export function runSealedPresence(context: JsonObject, input: JsonObject): Json | undefined {
  const hex = (k: string) => Buffer.from(String(input[k]), "hex");
  const held = (input["keys"] ?? {}) as JsonObject;
  const keys = (kid: string) => (typeof held[kid] === "string" ? Buffer.from(held[kid], "hex") : undefined);
  switch (input["check"]) {
    case "audience-tag":
      return { tag: audienceTag(hex("secret_hex"), String(input["subject"]), String(input["label"])) };
    case "key":
      return { key_hex: presenceKey(hex("secret_hex"), String(input["subject"]), String(input["kid"])).toString("hex") };
    case "seal-record":
      return { sealed_state: sealRecord(input["record"] as unknown as SealedRecordFields, String(input["state"]), hex("key_hex"), hex("nonce_hex")) };
    case "open-record": {
      const r = input["record"] as unknown as BodyRecord;
      const opened = openRecord(r, String(r.sealed_state), keys);
      return "state" in opened ? { verdict: "accept", state: opened.state } : { verdict: "reject", code: opened.unreadable };
    }
    case "grant-keys-open": {
      const opened = openGrantKeys(input["grant"] as JsonObject, hex("recipient_secret_hex"));
      if (typeof opened === "string") return { verdict: "reject", code: opened };
      return { verdict: "accept", keys: Object.fromEntries([...opened].map(([kid, k]) => [kid, k.toString("hex")])) };
    }
    case "view":
      return viewPresence(
        (input["records"] ?? []) as unknown as BodyRecord[],
        keys,
        input["asserted"] as string | undefined,
        context["now"] as number,
      ) as unknown as Json;
    default:
      return undefined;
  }
}
