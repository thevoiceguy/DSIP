/**
 * The cryptographic formats of the Messaging Profile below MLS itself: extension encoding, the
 * DSIP authentication service for MLS leaves, AES-256-GCM sealing, and HPKE for sealed introductions.
 *
 * Spec: M§6.2 (credentials), M§6.3 (`dsip_conversation` bytes), M§6.9 (HPKE suite, RFC 9180 base
 * mode), M§8.4 / M§11.1 / M§12.2 (sealing and its AAD), M§14.1 (sealed introductions), M§17
 * (codepoints), RFC 9420 §2.1.2 (variable-length integers).
 */
import {
  createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman,
} from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import { b64urlDecode, ed25519FromMultibase, utf8Decode } from "../encoding.js";
import { decodePayload, delegationSubject, type ReceiverContext } from "../envelope.js";
import { reject, type Verdict } from "../verdict.js";
import { checkConversationExt } from "./message.js";

/** Spec: M§17 — private-use MLS extension type carrying the leaf's DeviceDelegation. */
export const DSIP_DELEGATION = 0xf0d1;
/** Spec: M§17 — private-use MLS GroupContext extension type. */
export const DSIP_CONVERSATION = 0xf0d2;

// ---- RFC 9420 §2.1.2 extension encoding

/** `uint16 type ‖ minimal variable-length size ‖ data`. */
export function encodeExtension(type: number, data: Buffer): Buffer {
  const n = data.length;
  const size =
    n < 0x40 ? Buffer.from([n])
    : n < 0x4000 ? Buffer.from([0x40 | (n >> 8), n & 0xff])
    : Buffer.from([0x80 | (n >>> 24), (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  return Buffer.concat([Buffer.from([type >> 8, type & 0xff]), size, data]);
}

/** Decode one extension; the length must be minimal and nothing may follow the data. */
export function decodeExtension(bytes: Buffer): Verdict {
  if (bytes.length < 3) return reject("mls-truncated");
  const prefix = bytes[2]! >> 6;
  if (prefix === 3) return reject("mls-length-invalid"); // the 8-byte form exceeds MLS's 30-bit bound
  const width = 1 << prefix;
  if (bytes.length < 2 + width) return reject("mls-truncated");
  let n = bytes[2]! & 0x3f;
  for (let i = 1; i < width; i++) n = n * 256 + bytes[2 + i]!;
  if ((width === 2 && n < 0x40) || (width === 4 && n < 0x4000)) return reject("mls-length-non-minimal");
  const data = bytes.subarray(2 + width);
  if (data.length < n) return reject("mls-truncated");
  if (data.length > n) return reject("mls-trailing-bytes");
  return { verdict: "accept", extension_type: bytes.readUInt16BE(0), data_hex: data.toString("hex") };
}

/** Spec: M§6.3 — the extension data is UTF-8 JSON obeying §10.3, then the `dsip-conversation` shape. */
export function checkConversationBytes(data: Buffer): Verdict {
  const value = decodePayload(data);
  if (value["verdict"] === "reject" && typeof value["code"] === "string") return reject(value["code"]);
  return checkConversationExt(value as JsonObject);
}

// ---- M§6.2 the DSIP authentication service

/** Spec: M§6.2 — the checks, in the order the profile lists them. */
export function checkCredential(
  credential: { credential_type: number; identity_hex: string },
  signatureKey: Buffer,
  extensions: { extension_type: number; data_hex: string }[],
  ctx: ReceiverContext,
): Verdict {
  if (credential.credential_type !== 1) return reject("credential-type"); // `basic` only in 1.0
  const device = utf8Decode(Buffer.from(credential.identity_hex, "hex"));
  if (device === null || !/^did:[a-z0-9]+:\S+$/.test(device)) return reject("credential-identity");
  const delegations = extensions.filter((e) => e.extension_type === DSIP_DELEGATION);
  if (delegations.length === 0) return reject("delegation-missing");
  if (delegations.length > 1) return reject("delegation-invalid"); // exactly one
  // the data is the compact envelope as ASCII bytes
  const compact = Buffer.from(delegations[0]!.data_hex, "hex").toString("latin1");
  const bound = delegationSubject(compact, device, "dsip.messaging", ctx);
  if ("verdict" in bound) return bound;
  // one device key signs both DSIP envelopes and MLS leaf operations
  const deviceKey = device.startsWith("did:key:") ? ed25519FromMultibase(device.slice("did:key:".length)) : null;
  if (!deviceKey || !deviceKey.equals(signatureKey)) return reject("credential-key-mismatch");
  return { verdict: "accept", identity: bound.subject, device };
}

// ---- AES-256-GCM sealing

function u64be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

/** What is being sealed, and the values its AAD binds. */
export interface SealUse {
  use: "blob" | "activity" | "archive";
  group_hex?: string;
  epoch?: number;
  seq?: number;
}

/** Spec: M§8.4 (no AAD), M§11.1 (`group_id ‖ epoch`), M§12.2 (`group_id ‖ seq`); integers are 8-byte big-endian. */
function aad(u: SealUse): Buffer {
  if (u.use === "blob") return Buffer.alloc(0);
  return Buffer.concat([Buffer.from(u.group_hex!, "hex"), u64be(u.use === "activity" ? u.epoch! : u.seq!)]);
}

/** `nonce (12) ‖ ciphertext ‖ tag (16)`. */
export function seal(u: SealUse, key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad(u));
  return Buffer.concat([nonce, c.update(plaintext), c.final(), c.getAuthTag()]);
}

/** Open sealed bytes. Spec: M§8.4 rule 7 — a blob's size and hash are verified before decrypting. */
export function open(u: SealUse & { size?: number; sha256?: string }, key: Buffer, sealed: Buffer): Verdict {
  if (u.use === "blob") {
    if (u.size !== undefined && sealed.length !== u.size) return reject("blob-size-mismatch");
    if (u.sha256 !== undefined && createHash("sha256").update(sealed).digest("hex") !== u.sha256) return reject("blob-hash-mismatch");
  }
  if (sealed.length < 28) return reject("sealed-too-short");
  try {
    const d = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
    d.setAAD(aad(u));
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    const plaintext = Buffer.concat([d.update(sealed.subarray(12, sealed.length - 16)), d.final()]);
    return { verdict: "accept", plaintext_hex: plaintext.toString("hex") };
  } catch {
    return reject("aead-open-failed");
  }
}

// ---- HPKE: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, base mode (RFC 9180)

const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), Buffer.from([0x00, 0x20])]);
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), Buffer.from([0x00, 0x20, 0x00, 0x01, 0x00, 0x01])]);
const PKCS8_X25519 = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519 = Buffer.from("302a300506032b656e032100", "hex");

function hmac(key: Buffer, data: Buffer): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function labeledExtract(suite: Buffer, salt: Buffer, label: string, ikm: Buffer): Buffer {
  return hmac(salt.length ? salt : Buffer.alloc(32), Buffer.concat([Buffer.from("HPKE-v1"), suite, Buffer.from(label), ikm]));
}

function labeledExpand(suite: Buffer, prk: Buffer, label: string, info: Buffer, length: number): Buffer {
  const labeled = Buffer.concat([Buffer.from([length >> 8, length & 0xff]), Buffer.from("HPKE-v1"), suite, Buffer.from(label), info]);
  let out: Buffer = Buffer.alloc(0);
  let block: Buffer = Buffer.alloc(0);
  for (let i = 1; out.length < length; i++) {
    block = hmac(prk, Buffer.concat([block, labeled, Buffer.from([i])]));
    out = Buffer.concat([out, block]);
  }
  return out.subarray(0, length);
}

function x25519Private(sk: Buffer) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_X25519, sk]), format: "der", type: "pkcs8" });
}

function x25519Public(sk: Buffer): Buffer {
  return Buffer.from(createPublicKey(x25519Private(sk)).export({ format: "der", type: "spki" })).subarray(-32);
}

function x25519(sk: Buffer, pk: Buffer): Buffer {
  return diffieHellman({
    privateKey: x25519Private(sk),
    publicKey: createPublicKey({ key: Buffer.concat([SPKI_X25519, pk]), format: "der", type: "spki" }),
  });
}

/** RFC 9180 §7.1.3 DeriveKeyPair for X25519. */
export function hpkeDeriveKeyPair(ikm: Buffer): { sk: Buffer; pk: Buffer } {
  const sk = labeledExpand(KEM_SUITE, labeledExtract(KEM_SUITE, Buffer.alloc(0), "dkp_prk", ikm), "sk", Buffer.alloc(0), 32);
  return { sk, pk: x25519Public(sk) };
}

/** Single-shot base-mode open (sequence 0); `null` when it does not open. Spec: M§6.9 */
export function hpkeOpen(enc: Buffer, skR: Buffer, info: Buffer, aadBytes: Buffer, ct: Buffer): Buffer | null {
  try {
    const dh = x25519(skR, enc);
    const kemContext = Buffer.concat([enc, x25519Public(skR)]);
    const sharedSecret = labeledExpand(KEM_SUITE, labeledExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dh), "shared_secret", kemContext, 32);
    const empty = Buffer.alloc(0);
    const context = Buffer.concat([
      Buffer.from([0x00]), // mode_base
      labeledExtract(HPKE_SUITE, empty, "psk_id_hash", empty),
      labeledExtract(HPKE_SUITE, empty, "info_hash", info),
    ]);
    const secret = labeledExtract(HPKE_SUITE, sharedSecret, "secret", empty);
    const key = labeledExpand(HPKE_SUITE, secret, "key", context, 16);
    const nonce = labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12);
    if (ct.length < 16) return null;
    const d = createDecipheriv("aes-128-gcm", key, nonce);
    d.setAAD(aadBytes);
    d.setAuthTag(ct.subarray(ct.length - 16));
    return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  } catch {
    return null;
  }
}

/** Spec: M§6.9 — the X25519 key of an Ed25519 identity key, as `did:key` derives it: the clamped SHA-512 half of the seed. */
export function x25519FromEd25519Seed(seed: Buffer): { sk: Buffer; pk: Buffer } {
  const sk = Buffer.from(createHash("sha512").update(seed).digest().subarray(0, 32));
  sk[0] = sk[0]! & 248;
  sk[31] = (sk[31]! & 127) | 64;
  return { sk, pk: x25519Public(sk) };
}

// ---- M§14.1 sealed introductions

const SEALED_ALG = "hpke-base-x25519-sha256-aes128gcm";
const SEALED_INFO = Buffer.from("dsip sealed introduction v1");
/** Spec: §19.4 — `purpose` is at most 280 characters, sealed or not. */
const MAX_PURPOSE_CHARS = 280;

/** The purpose of an introduction, opening `sealed` with the recipient's key agreement key. Spec: M§14.1 */
export function openIntroduction(payload: JsonObject, recipientSk: Buffer): Verdict {
  const sealed = payload["sealed"] as JsonObject | undefined;
  if (!sealed) return { verdict: "accept", purpose: (payload["purpose"] ?? null) as Json };
  if (sealed["alg"] !== SEALED_ALG) return reject("sealed-alg-unsupported");
  // AAD = id ‖ 0x00 ‖ from ‖ 0x00 ‖ to: a sealed body cannot be spliced into another introduction
  const zero = Buffer.from([0]);
  const aadBytes = Buffer.concat([
    Buffer.from(payload["id"] as string, "utf8"), zero, Buffer.from(payload["from"] as string, "utf8"), zero,
    Buffer.from(payload["to"] as string, "utf8"),
  ]);
  const enc = b64urlDecode(sealed["enc"] as string);
  const ct = b64urlDecode(sealed["ct"] as string);
  const plaintext = enc && ct ? hpkeOpen(enc, recipientSk, SEALED_INFO, aadBytes, ct) : null;
  if (!plaintext) return reject("sealed-open-failed");
  let value: Json;
  try {
    value = JSON.parse(utf8Decode(plaintext) ?? "!");
  } catch {
    return reject("sealed-plaintext-invalid");
  }
  // the plaintext is exactly {"purpose": "…"}
  const exact = value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === 1 && typeof value["purpose"] === "string";
  if (!exact) return reject("sealed-plaintext-invalid");
  const purpose = (value as JsonObject)["purpose"] as string;
  return [...purpose].length > MAX_PURPOSE_CHARS ? reject("purpose-too-long") : { verdict: "accept", purpose };
}
