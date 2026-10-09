/**
 * Verifying a number binding: a STIR-signed compact JWS saying that a phone number is used by a DID, checked
 * offline against the certificate chain, the trust list, the DID's document and the clock.
 *
 * Spec: N§3.1 (format), N§3.2 (the certificate), N§3.3 (the back-reference), N§3.4 (verification, the check
 * order and the reasons); §10.2 (signature over bytes), §10.3 (integers only); RFC 7515 (JWS), RFC 7493 (I-JSON).
 * Impl: the vectors README ("Kind: `tn-binding`") fixes what N§3.4 leaves to the verifier (spec-gap 110).
 */
import { verify } from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import { parseIJson } from "../did/webvh.js";
import { b64urlDecode, isUlid, utf8Decode } from "../encoding.js";
import {
  attestedBy, base64Decode, covers, p256Key, parseCertificate, pemBlocks, signedBy, signedEs256,
  type Certificate, type KnownExtensions,
} from "./x509.js";

/** Spec: N§3.1 — the binding's lifetime cap, 604,800 s (7 days). */
const MAX_LIFETIME = 604800;
/** Spec: N§3.4 step 5 — `iat` may run ahead of the clock by the §12.9 tolerance, 300 s. */
const IAT_TOLERANCE = 300;
/** The P-256 group order n. Spec: README step 3 (0 < r, s < n). */
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
/** Spec: N§1, N§3.1 — E.164: `+`, then 2 to 15 digits, the first not `0`. */
const E164 = /^\+[1-9][0-9]{1,14}$/;

/** The relying party's side of a verification: the vector's `context`. */
export interface TnContext {
  /** The STI-CA list: DER certificates in padded base64. */
  trust_anchors: string[];
  /** What each `x5u` URL serves. */
  certificates: Record<string, string>;
  /** The SPC lookup: digits (no `+`) assigned to each Service Provider Code. */
  spc_numbers: Record<string, string[]>;
  /** Whether policy requires the step 8 status check. */
  require_status: boolean;
  /** What each status URL answers. */
  status: Record<string, string>;
}

/** The outcome of N§3.4. */
export type TnOutcome =
  | { outcome: "verified"; tn: string; did: string; expires: number; attested_by: string | null }
  | { outcome: "rejected"; reason: string };

const rejected = (reason: string): TnOutcome => ({ outcome: "rejected", reason });
const isObject = (v: Json | undefined): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/**
 * A segment's JSON: strict UTF-8 (a BOM kept, so it fails to parse), then I-JSON, then an object.
 *
 * Spec: N§3.1 ("JSON in both segments is UTF-8 I-JSON (RFC 7493). Integers have no fraction or exponent").
 */
function segmentObject(bytes: Buffer): JsonObject | null {
  const text = utf8Decode(bytes); // fatal, ignoreBOM: a leading U+FEFF stays in the text, and JSON.parse refuses it
  if (text === null) return null;
  const value = parseIJson(text);
  return isObject(value) ? value : null;
}

/** A JSON value that is an integer (I-JSON has already ruled out fractions, exponents and out-of-range values). */
const isInt = (v: Json | undefined): v is number => typeof v === "number" && Number.isInteger(v);

/** The parsed parts of a well-formed binding. */
interface Parsed {
  signingInput: Buffer;
  signature: Buffer;
  header: JsonObject;
  payload: JsonObject;
}

/**
 * Step 1, `malformed`: the shape, the JSON, the header and the payload.
 *
 * Spec: N§3.1, N§3.4 step 1; README step 1.
 */
function parseBinding(binding: Json | undefined): Parsed | null {
  if (typeof binding !== "string") return null;
  const segs = binding.split(".");
  if (segs.length !== 3) return null;
  const decoded = segs.map(b64urlDecode);
  if (decoded.some((d) => d === null)) return null;
  const [h, p, s] = decoded as [Buffer, Buffer, Buffer];
  if (segs[2]!.length === 0) return null;
  const header = segmentObject(h);
  const payload = segmentObject(p);
  if (!header || !payload) return null;

  // Spec: N§3.1 protected header table; "A header with a `crit` member is malformed".
  if (header["alg"] !== "ES256" || header["typ"] !== "dsip-tn-binding+jwt") return null;
  if (typeof header["x5u"] !== "string" || !header["x5u"].startsWith("https://")) return null;
  if (own(header, "crit")) return null;

  // Spec: N§3.1 payload table.
  const { tn, did, iat, exp, jti } = payload;
  if (typeof tn !== "string" || !E164.test(tn)) return null;
  if (typeof did !== "string" || !did.startsWith("did:")) return null;
  if (!isInt(iat) || iat < 0 || !isInt(exp) || exp <= iat) return null;
  if (typeof jti !== "string" || !isUlid(jti)) return null;
  if (own(payload, "status")) {
    const status = payload["status"]; // README: `null` is not absent
    if (typeof status !== "string" || !status.startsWith("https://")) return null;
  }
  // Spec: §10.2 — the signing input is the segments as received, never re-encoded.
  return { signingInput: Buffer.from(`${segs[0]}.${segs[1]}`, "ascii"), signature: s, header, payload };
}

/** A path certificate with its decoded extensions. */
interface PathCert {
  cert: Certificate;
  ext: KnownExtensions;
}

/**
 * The checks every certificate on the path passes, by position, and the link to the next one.
 *
 * Spec: N§3.2 (path, algorithms), N§3.4 step 2; README step 2 "Links", "Every certificate on the path",
 * "Issuers", "Leaf".
 */
function pathHolds(path: Certificate[], anchorEnds: boolean, now: number): PathCert[] | null {
  const out: PathCert[] = [];
  for (let p = 0; p < path.length; p++) {
    const cert = path[p]!;
    const ext = cert.known; // decoded, and the TNAuthList well-formed, when the block parsed
    if (!signedEs256(cert) || !p256Key(cert)) return null;
    if (!(cert.notBefore <= now && now <= cert.notAfter)) return null;
    if (ext.unknownCritical) return null;
    // Links: every certificate except an anchor that ends the path is issued by the next one.
    const last = p === path.length - 1;
    if (!last) {
      const next = path[p + 1]!;
      if (!cert.issuer.equals(next.subject) || !signedBy(cert, p256Key(next))) return null;
    } else if (!anchorEnds) return null; // a path always ends at an anchor (unreachable by construction)
    if (p >= 1) {
      // Issuers (RFC 5280 §4.2.1.9, §4.2.1.3)
      if (!ext.basicConstraints?.ca) return null;
      if (ext.keyUsage && !ext.keyUsage.keyCertSign) return null;
      const L = ext.basicConstraints.pathLen;
      if (L !== undefined && BigInt(p - 1) > L) return null;
    } else if (ext.keyUsage && !ext.keyUsage.digitalSignature) return null;
    out.push({ cert, ext });
  }
  return out;
}

/**
 * Step 2, `untrusted-certificate`: fetch, PEM, parse, build the path to a trust anchor, check it.
 *
 * Spec: N§3.2, N§3.4 step 2; README step 2.
 * Spec: README step 2 and "Context": every block parses, after an anchor too; a trust-list entry that is not
 * padded base64 or does not parse is ignored; when several anchors qualify as the issuing anchor, step 2 passes
 * if the path through any one of them passes (they are tried in trust-list order).
 */
function certificatePath(url: string, ctx: TnContext, now: number): PathCert[] | null {
  const text = own(ctx.certificates ?? {}, url) ? ctx.certificates[url] : undefined;
  if (typeof text !== "string") return null;
  const blocks = pemBlocks(text);
  if (!blocks) return null;
  let chain: Certificate[];
  try {
    chain = blocks.map(parseCertificate);
  } catch {
    return null;
  }
  const anchorsDer = (ctx.trust_anchors ?? []).map((a) => (typeof a === "string" ? base64Decode(a) : null)).filter((a): a is Buffer => a !== null);
  const at = chain.findIndex((c) => anchorsDer.some((a) => a.equals(c.raw)));
  if (at >= 0) return pathHolds(chain.slice(0, at + 1), true, now);

  const last = chain[chain.length - 1]!;
  for (const der of anchorsDer) {
    let anchor: Certificate;
    try {
      anchor = parseCertificate(der);
    } catch {
      continue;
    }
    if (!anchor.subject.equals(last.issuer) || !signedBy(last, p256Key(anchor))) continue;
    const held = pathHolds([...chain, anchor], true, now);
    if (held) return held;
  }
  return null;
}

/**
 * Step 3, `signature`: 64 bytes of r‖s, each in (0, n), verified by the leaf key over the signing input.
 *
 * Spec: N§3.4 step 3, §10.2; RFC 7518 §3.4 (ES256 signature form). A high s is accepted.
 */
function signatureHolds(parsed: Parsed, leaf: Certificate): boolean {
  const sig = parsed.signature;
  if (sig.length !== 64) return false;
  const r = BigInt(`0x${sig.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
  if (r <= 0n || r >= P256_N || s <= 0n || s >= P256_N) return false;
  const key = p256Key(leaf);
  if (!key) return false;
  try {
    return verify("sha256", parsed.signingInput, { key, dsaEncoding: "ieee-p1363" }, sig);
  } catch {
    return false;
  }
}

/** A binding that has passed N§3.4 steps 1–5: its payload's members and the leaf certificate. */
export interface StepsPassed {
  /** The payload's `tn`. */
  tn: string;
  /** The payload's `did`. */
  did: string;
  /** The payload's `iat`. */
  iat: number;
  /** The payload's `exp`. */
  exp: number;
  /** The payload's `status`, when present. */
  status: string | undefined;
  /** The leaf certificate's `attested_by` name. */
  attestedBy: string | null;
}

/**
 * N§3.4 steps 1–5, the ones that need no DID resolution: format, certificate path, signature, coverage, time.
 *
 * Spec: N§3.4 steps 1–5; README "Kind: `tn-binding`" (check order) and `check: "store"` ("A node resolves no DIDs,
 * so it applies verification steps 1–5 only").
 */
export function verifyFirstSteps(ctx: TnContext, binding: Json | undefined, now: number): StepsPassed | { reason: string } {
  // 1. malformed
  const parsed = parseBinding(binding);
  if (!parsed) return { reason: "malformed" };
  const { header, payload } = parsed;
  const tn = payload["tn"] as string;
  const iat = payload["iat"] as number;
  const exp = payload["exp"] as number;

  // 2. untrusted-certificate
  const path = certificatePath(header["x5u"] as string, ctx, now);
  if (!path) return { reason: "untrusted-certificate" };
  const leaf = path[0]!;

  // 3. signature
  if (!signatureHolds(parsed, leaf.cert)) return { reason: "signature" };

  // 4. not-authorized-for-tn (N§3.2 coverage and nested coverage)
  const digits = tn.slice(1);
  const spc = ctx.spc_numbers ?? {};
  if (!leaf.ext.tnAuthList) return { reason: "not-authorized-for-tn" };
  if (path.some((c) => c.ext.tnAuthList && !covers(c.ext.tnAuthList, digits, spc))) return { reason: "not-authorized-for-tn" };

  // 5. time, in this order (README step 5)
  if (exp - iat > MAX_LIFETIME) return { reason: "lifetime-too-long" };
  if (iat > now + IAT_TOLERANCE) return { reason: "not-yet-valid" };
  if (now >= exp) return { reason: "expired" };

  const status = payload["status"];
  return {
    tn, did: payload["did"] as string, iat, exp,
    status: typeof status === "string" ? status : undefined,
    attestedBy: attestedBy(leaf.cert),
  };
}

/** A binding that has passed all eight steps. */
export type FullyVerified = StepsPassed;

/**
 * N§3.4 steps 1–8 against the DID being checked and its document; the passed binding, or the first failing reason.
 *
 * Spec: N§3.4; README "Kind: `tn-binding`".
 */
export function verifyAll(
  ctx: TnContext, binding: Json | undefined, checking: Json | undefined, doc: Json | undefined, now: number,
): FullyVerified | { reason: string } {
  const first = verifyFirstSteps(ctx, binding, now);
  if ("reason" in first) return first;
  const { tn, did } = first;

  // 6. did-mismatch: exact comparison
  if (did !== checking) return { reason: "did-mismatch" };

  // 7. not-claimed-by-did (N§3.3): `tel:` + `tn`, exactly
  if (!isObject(doc) || doc["id"] !== checking) return { reason: "not-claimed-by-did" };
  const aka = doc["alsoKnownAs"];
  if (!Array.isArray(aka) || !aka.some((a) => a === `tel:${tn}`)) return { reason: "not-claimed-by-did" };

  // 8. status, only under a policy that requires it (§18.3)
  if (ctx.require_status === true) {
    const url = first.status;
    const answers = ctx.status ?? {};
    // README "Context": an answer other than `good` or `revoked` is no answer.
    if (url === undefined || !own(answers, url)) return { reason: "status-unavailable" };
    if (answers[url] === "revoked") return { reason: "revoked" };
    if (answers[url] !== "good") return { reason: "status-unavailable" };
  }
  return first;
}

/**
 * Verify a number binding: N§3.4 steps 1–8 in order, the first failure giving the reason.
 *
 * Spec: N§3.4; README "Kind: `tn-binding`".
 */
export function verifyTnBinding(ctx: TnContext, input: JsonObject): TnOutcome {
  const v = verifyAll(ctx, input["binding"], input["did"], input["did_document"], input["now"] as number);
  if ("reason" in v) return rejected(v.reason);
  return { outcome: "verified", tn: v.tn, did: v.did, expires: v.exp, attested_by: v.attestedBy };
}

/**
 * Read a held binding's payload without verifying it: the second of three `.`-separated segments, base64url, as an
 * I-JSON object with a string `did` and integer `iat` and `exp`. The header and the signature are not looked at.
 *
 * Spec: README `check: "store"` — a held binding "passed this check earlier and is not verified again; only its
 * payload is read".
 * Impl: an entry whose payload cannot be read so (which this check never stores) is dropped with the expired ones
 * (not pinned).
 */
export function readPayload(binding: Json | undefined): { tn: Json | undefined; did: string; iat: number; exp: number } | null {
  if (typeof binding !== "string") return null;
  const segs = binding.split(".");
  if (segs.length !== 3) return null;
  const bytes = b64urlDecode(segs[1]!);
  if (!bytes) return null;
  const p = segmentObject(bytes);
  if (!p) return null;
  const { tn, did, iat, exp } = p;
  if (typeof did !== "string" || !isInt(iat) || !isInt(exp)) return null;
  return { tn, did, iat, exp };
}
