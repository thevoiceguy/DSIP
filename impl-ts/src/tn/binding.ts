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

/**
 * Verify a number binding: N§3.4 steps 1–8 in order, the first failure giving the reason.
 *
 * Spec: N§3.4; README "Kind: `tn-binding`".
 */
export function verifyTnBinding(ctx: TnContext, input: JsonObject): TnOutcome {
  const now = input["now"] as number;
  const checking = input["did"];

  // 1. malformed
  const parsed = parseBinding(input["binding"]);
  if (!parsed) return rejected("malformed");
  const { header, payload } = parsed;
  const tn = payload["tn"] as string;
  const did = payload["did"] as string;
  const iat = payload["iat"] as number;
  const exp = payload["exp"] as number;

  // 2. untrusted-certificate
  const path = certificatePath(header["x5u"] as string, ctx, now);
  if (!path) return rejected("untrusted-certificate");
  const leaf = path[0]!;

  // 3. signature
  if (!signatureHolds(parsed, leaf.cert)) return rejected("signature");

  // 4. not-authorized-for-tn (N§3.2 coverage and nested coverage)
  const digits = tn.slice(1);
  const spc = ctx.spc_numbers ?? {};
  if (!leaf.ext.tnAuthList) return rejected("not-authorized-for-tn");
  if (path.some((c) => c.ext.tnAuthList && !covers(c.ext.tnAuthList, digits, spc))) return rejected("not-authorized-for-tn");

  // 5. time, in this order (README step 5)
  if (exp - iat > MAX_LIFETIME) return rejected("lifetime-too-long");
  if (iat > now + IAT_TOLERANCE) return rejected("not-yet-valid");
  if (now >= exp) return rejected("expired");

  // 6. did-mismatch: exact comparison
  if (did !== checking) return rejected("did-mismatch");

  // 7. not-claimed-by-did (N§3.3): `tel:` + `tn`, exactly
  const doc = input["did_document"];
  if (!isObject(doc) || doc["id"] !== checking) return rejected("not-claimed-by-did");
  const aka = doc["alsoKnownAs"];
  if (!Array.isArray(aka) || !aka.some((a) => a === `tel:${tn}`)) return rejected("not-claimed-by-did");

  // 8. status, only under a policy that requires it (§18.3)
  if (ctx.require_status === true) {
    const url = payload["status"];
    const answers = ctx.status ?? {};
    // README "Context": an answer other than `good` or `revoked` is no answer.
    if (typeof url !== "string" || !own(answers, url)) return rejected("status-unavailable");
    if (answers[url] === "revoked") return rejected("revoked");
    if (answers[url] !== "good") return rejected("status-unavailable");
  }

  return { outcome: "verified", tn, did, expires: exp, attested_by: attestedBy(leaf.cert) };
}
