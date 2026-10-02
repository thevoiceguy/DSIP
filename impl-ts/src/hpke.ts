/**
 * HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM — the one
 * suite DSIP uses, for sealed introductions and sealed bodies.
 *
 * Spec: M§6.9 (HPKE suite, RFC 9180 base mode; `did:key` X25519 derivation), M§14.1, §19.4, §10.4.
 */
import { createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";

/** Spec: §10.4, M§14.1 — the registered `sealed.alg` for this suite. */
export const HPKE_SEALED_ALG = "hpke-base-x25519-sha256-aes128gcm";

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

