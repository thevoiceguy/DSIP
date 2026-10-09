/**
 * A DSIP↔PSTN gateway as a relying party on both sides: verifying a PSTN caller's SHAKEN PASSporT (G§5), routing
 * a dialled number to the DSIP identity bound to it (G§3.2, N§6.1), and asserting a DSIP caller's bound number
 * toward the PSTN under the gateway's own STIR certificate (N§4.1).
 *
 * Spec: G§5 (`attestation`, `verified`, a PASSporT whose `orig` names another number is discarded), G§3.2 (the
 * "resolved DSIP target"), G§4.2 (`identity.unknown`), G§7 (`identity-not-assertable`), N§4 "Toward the PSTN" (a
 * `From` asserted only under a certificate that covers the number; RFC 9060 delegate certificates), N§6 route 1;
 * RFC 8224 §6.2 (verification), §8.3 (canonical numbers); RFC 8225 (PASSporT); RFC 8588 (SHAKEN).
 * Impl: the vectors README ("Kind: `tn-binding`", "Gateway checks") fixes the rule order and the reasons
 * (spec-gap 110 item I); verification steps 2–4 are N§3.4's, shared with `binding.ts`.
 */
import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import {
  certificatePath, coverageHolds, isInt, signatureHolds, splitJws, type PathCert, type TnContext,
} from "./binding.js";
import { checkTelClaim, selectBinding } from "./claim.js";
import { p256Key } from "./x509.js";

/** Spec: N§1, N§3.1 — E.164: `+`, then 2 to 15 digits, the first not `0`. */
const E164 = /^\+[1-9][0-9]{1,14}$/;
/** Spec: README `check: "passport"` rule 7 — RFC 8224 §6.2.1's freshness window, 60 s either way. */
const FRESHNESS = 60;

const isObject = (v: Json | undefined): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/**
 * A number's canonical form: a leading `+` removed, then every `-`, `.`, `(`, `)` and SP; 1 to 15 digits remain,
 * or the number has no canonical form (`null`) and matches nothing.
 *
 * Spec: RFC 8224 §8.3; README `check: "passport"`, "Numbers are compared canonically".
 * Impl: a value that is not a string has no canonical form.
 */
export function canonicalNumber(v: Json | undefined): string | null {
  if (typeof v !== "string") return null;
  const bare = (v.startsWith("+") ? v.slice(1) : v).replace(/[-.() ]/g, "");
  return /^[0-9]{1,15}$/.test(bare) ? bare : null;
}

/** The outcome of a gateway's PASSporT verification: the `attestation` and `verified` of its G§5 `tel` claim. */
export type PassportOutcome =
  | { attest: string; verified: true }
  | { attest: string; verified: false; reason: string };

/**
 * The `Identity` header value read as a token and parameters (RFC 8224 §4): `null` when it does not read.
 *
 * Spec: README `check: "passport"` rule 2 — split on `;`; the token and each name and value stripped of SP and
 * HT at both ends; a part without `=`, an empty name, an empty value or a repeated name is malformed; names
 * compared case-insensitively; `info` required, its value `<`, the URI, `>`.
 * Impl: a parameter's value starts after its first `=` (a URI may contain `=`). Parameter values are compared
 * exactly (`alg=es256` is `unsupported`); not pinned.
 */
function readIdentityHeader(value: string): { token: string; info: string; params: Map<string, string> } | null {
  const strip = (s: string) => s.replace(/^[ \t]+|[ \t]+$/g, "");
  const parts = value.split(";");
  const token = strip(parts[0]!);
  const params = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const eq = part.indexOf("=");
    if (eq < 0) return null;
    const name = strip(part.slice(0, eq)).toLowerCase();
    const val = strip(part.slice(eq + 1));
    if (name === "" || val === "" || params.has(name)) return null;
    params.set(name, val);
  }
  const info = params.get("info");
  if (info === undefined || info.length < 2 || !info.startsWith("<") || !info.endsWith(">")) return null;
  return { token, info: info.slice(1, -1), params };
}

/** A PASSporT whose header and payload are well-formed (README rule 4). */
interface Passport {
  signingInput: Buffer;
  signature: Buffer;
  x5u: string;
  attest: string;
  orig: string;
  dest: string[];
  iat: number;
}

/**
 * A SHAKEN PASSporT's shape: the compact JWS (verification step 1's shape and JSON rules), the header, the payload.
 *
 * Spec: README `check: "passport"` rule 4; RFC 8225 §5, RFC 8588 §3–§4. Other members are ignored.
 */
function readPassport(token: string): Passport | null {
  const jws = splitJws(token);
  if (!jws) return null;
  const { header, payload } = jws;
  if (header["alg"] !== "ES256" || header["typ"] !== "passport" || header["ppt"] !== "shaken") return null;
  const x5u = header["x5u"];
  if (typeof x5u !== "string" || !x5u.startsWith("https://")) return null;
  const attest = payload["attest"];
  if (attest !== "A" && attest !== "B" && attest !== "C") return null;
  const orig = payload["orig"];
  const dest = payload["dest"];
  if (!isObject(orig) || !isObject(dest)) return null;
  const origTn = canonicalNumber(orig["tn"]);
  if (origTn === null) return null;
  const destTn = dest["tn"];
  if (!Array.isArray(destTn) || destTn.length === 0) return null;
  const dests: string[] = [];
  for (const d of destTn) {
    const c = canonicalNumber(d);
    if (c === null) return null;
    dests.push(c);
  }
  const iat = payload["iat"];
  if (!isInt(iat) || iat < 0) return null;
  return { signingInput: jws.signingInput, signature: jws.signature, x5u, attest, orig: origTn, dest: dests, iat };
}

/**
 * A gateway's verification of the `Identity` header on an inbound INVITE: the attestation level it may carry into
 * its G§5 claim, and whether it verified.
 *
 * Spec: G§5 ("`verified` is `true` only when the PASSporT signature and X.509 chain verified and its `orig`
 * matches the SIP `From` number. A PASSporT whose `orig` names a different number MUST be discarded (attestation
 * `none`)"); RFC 8224 §6.2 (the verifier's steps), §6.2.1 (freshness), §6.2.3 (an unprocessable header is
 * ignored); RFC 8588 §3 (`B` and `C` attest no authority over the number).
 * Spec: README `check: "passport"` — the eleven rules in order; `require_status` and `status` never consulted.
 */
export function verifyPassport(ctx: TnContext, input: JsonObject): PassportOutcome {
  const none = (reason: string): PassportOutcome => ({ attest: "none", verified: false, reason });
  const now = input["now"] as number;
  // 1. no-identity-header
  const identity = input["identity"];
  if (typeof identity !== "string") return none("no-identity-header");
  // 2. malformed: the header value
  const header = readIdentityHeader(identity);
  if (!header) return none("malformed");
  // 3. unsupported: an alg or ppt the verifier cannot process (RFC 8224 §6.2.3)
  const alg = header.params.get("alg");
  const ppt = header.params.get("ppt");
  if ((alg !== undefined && alg !== "ES256") || (ppt !== undefined && ppt !== "shaken")) return none("unsupported");
  // 4. malformed: the token
  const pp = readPassport(header.token);
  if (!pp) return none("malformed");
  // 5. orig-mismatch: the PASSporT attests some other call and is discarded whole (G§5)
  if (pp.orig !== canonicalNumber(input["from_tn"])) return none("orig-mismatch");

  const failed = (reason: string): PassportOutcome => ({ attest: pp.attest, verified: false, reason });
  // 6. dest-mismatch
  const to = canonicalNumber(input["to_tn"]);
  if (to === null || !pp.dest.includes(to)) return failed("dest-mismatch");
  // 7. stale (RFC 8224 §6.2.1)
  if (Math.abs(now - pp.iat) > FRESHNESS) return failed("stale");
  // 8. x5u-mismatch: the header's x5u is the info URI, exactly
  if (pp.x5u !== header.info) return failed("x5u-mismatch");
  // 9. untrusted-certificate: verification step 2
  const path = certificatePath(pp.x5u, ctx, now);
  if (!path) return failed("untrusted-certificate");
  // 10. signature: verification step 3
  if (!signatureHolds(pp, path[0]!.cert)) return failed("signature");
  // 11. not-authorized-for-tn, for A only: verification step 4 (RFC 8588 §3)
  if (pp.attest === "A" && !coverageHolds(path, pp.orig, ctx)) return failed("not-authorized-for-tn");
  return { attest: pp.attest, verified: true };
}

/** The outcome of resolving a dialled number to the DSIP identity the gateway invites. */
export type RouteOutcome =
  | { outcome: "configured"; did: string }
  | { outcome: "binding"; did: string; attested_by: string | null; issued: number; others: string[] }
  | { outcome: "none" };

/**
 * A gateway's resolution of an inbound PSTN call's dialled number: the operator's table first, then the N§6
 * route 1 bindings, else the INVITE is refused `identity.unknown`.
 *
 * Spec: G§3.2 ("resolved DSIP target"), G§4.2 (`identity.unknown`, 404, Q.850 cause 1), N§6 route 1 (the reader
 * verifies every returned binding in full and chooses by N§7), §8.1 (a node is a hints tier: the operator's own
 * table is never overridden by a binding).
 * Spec: README `check: "route"` — `configured` first, then the `select` check for an E.164 `to_tn`, then `none`.
 */
export function routeNumber(ctx: TnContext, input: JsonObject): RouteOutcome {
  const to = input["to_tn"];
  // 1. the operator's table: its statement about its own trunk
  const configured = input["configured"];
  if (isObject(configured) && typeof to === "string" && own(configured, to)) {
    const did = configured[to];
    if (typeof did === "string") return { outcome: "configured", did };
  }
  // 2. a binding the number's subject published (N§6 route 1), chosen by N§7
  if (typeof to === "string" && E164.test(to)) {
    const found = selectBinding(ctx, { tn: to, bindings: input["bindings"] ?? null, documents: input["documents"] ?? null, now: input["now"] ?? null });
    if (found.outcome === "found") {
      return { outcome: "binding", did: found.did, attested_by: found.attested_by, issued: found.issued, others: found.others };
    }
  }
  // 3. the gateway refuses the INVITE `identity.unknown`
  return { outcome: "none" };
}

/** The PASSporT a gateway signs, decoded: its protected header and its claims. */
export interface SignedPassport {
  /** The protected header. */
  header: JsonObject;
  /** The claims. */
  claims: JsonObject;
  /** The compact JWS: the `Identity` header's token. */
  token: string;
}

/** The outcome of asserting a DSIP caller's number toward the PSTN. */
export interface AssertOutcome {
  /** The SIP `From` user the gateway presents, or `null` (its own identity). */
  from: string | null;
  /** The decoded PASSporT, or `null` when none is signed. */
  passport: { header: JsonObject; claims: JsonObject } | null;
  /** Whether the number is asserted; false is G§7's `identity-not-assertable`. */
  assertable: boolean;
  /** Why it is not, when it is not. */
  reason?: string;
}

/**
 * JSON with members in lexicographic order and no whitespace, at every level.
 *
 * Spec: RFC 8225 §9 (the PASSporT's deterministic serialization: members sorted, no whitespace); README
 * `check: "assert"` rule 7.
 * Impl: member names are ordered by UTF-16 code unit (`Array.prototype.sort` default), which is code point order
 * for the ASCII names a PASSporT uses.
 */
export function canonicalJson(v: Json): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (isObject(v)) {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k] as Json)}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

/**
 * The gateway's private key, when `gateway.key` is a string holding a PKCS#8 PEM P-256 private key.
 *
 * Spec: README `check: "assert"` — context `gateway.key` "is the private key of that chain's leaf: a P-256 key as
 * a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`)"; rule 3 `no-certificate`.
 * Impl: the text must carry the PKCS#8 marker; a SEC1 `EC PRIVATE KEY` block is not a PKCS#8 PEM (not pinned).
 */
function gatewayKey(key: Json | undefined): KeyObject | null {
  if (typeof key !== "string" || !key.includes("-----BEGIN PRIVATE KEY-----")) return null;
  try {
    const k = createPrivateKey({ key, format: "pem" });
    return k.asymmetricKeyType === "ec" && k.asymmetricKeyDetails?.namedCurve === "prime256v1" ? k : null;
  } catch {
    return null;
  }
}

/** Whether the private key's public point is the leaf certificate's. Spec: README `check: "assert"` rule 6. */
function keyMatches(key: KeyObject, leaf: PathCert): boolean {
  const leafKey = p256Key(leaf.cert);
  if (!leafKey) return false;
  const a = createPublicKey(key).export({ format: "jwk" });
  const b = leafKey.export({ format: "jwk" });
  return a.x === b.x && a.y === b.y;
}

/**
 * Sign a SHAKEN PASSporT: the two objects serialized per RFC 8225 §9, base64url-encoded, joined by `.`, and
 * ES256-signed over that signing input (RFC 7515 §5.1; RFC 7518 §3.4: the signature is r‖s).
 *
 * Spec: RFC 8225 §9, RFC 8588 §4, RFC 7515 §5.1; README `check: "assert"` rule 7.
 */
export function signPassport(key: KeyObject, header: JsonObject, claims: JsonObject): SignedPassport {
  const enc = (o: JsonObject) => Buffer.from(canonicalJson(o), "utf8").toString("base64url");
  const signingInput = `${enc(header)}.${enc(claims)}`;
  const sig = sign("sha256", Buffer.from(signingInput, "ascii"), { key, dsaEncoding: "ieee-p1363" });
  return { header, claims, token: `${signingInput}.${sig.toString("base64url")}` };
}

/**
 * A gateway carrying a DSIP caller's bound number to the PSTN: the SIP `From` it presents, and the SHAKEN PASSporT
 * it signs under its own STIR certificate when that certificate covers the number.
 *
 * Spec: N§4 "Toward the PSTN" ("A gateway that carries a DSIP caller to the PSTN may assert the `From` number only
 * under a STIR certificate that covers it. Normally that is an RFC 9060 delegate certificate … The binding tells
 * the gateway, per call, that this DSIP identity is the one the number belongs to"); G§7 (`identity-not-assertable`);
 * RFC 8588 §4 (`origid`), RFC 8225 §9.
 * Spec: README `check: "assert"` — the first attested claim (the `claim` check) gives the number, else the first
 * dropped claim's reason or `no-binding`; then `bad-destination`, `no-certificate`, `untrusted-certificate`
 * (step 2 on the gateway's own chain), `not-authorized-for-tn` (step 4 on that path), `key-mismatch`, signed at
 * level `A` with `iat` = `now`.
 * Impl: `origid` is carried into the claims as given (the README says it is a string; not pinned otherwise).
 * Impl: the signed token is produced (`signPassport`) and returned decoded; the vector pins the header and the
 * claims, not the signature.
 */
export function assertNumber(ctx: TnContext & { gateway?: Json }, input: JsonObject): AssertOutcome {
  const now = input["now"] as number;
  // 1. the binding: the first attested `tel` claim gives the number
  const claims = Array.isArray(input["claims"]) ? input["claims"] : [];
  let number: string | null = null;
  let firstDropped: string | null = null;
  for (const claim of claims) {
    const r = checkTelClaim(ctx, { claim, identity: input["identity"] ?? null, did_document: input["did_document"] ?? null, now });
    if (r.outcome === "attested") {
      number = (claim as JsonObject)["number"] as string; // attested: `number` equals the binding's `tn`
      break;
    }
    if (r.outcome === "dropped" && firstDropped === null) firstDropped = r.reason;
  }
  if (number === null) return { from: null, passport: null, assertable: false, reason: firstDropped ?? "no-binding" };

  const not = (reason: string): AssertOutcome => ({ from: number, passport: null, assertable: false, reason });
  // 2. bad-destination
  const to = input["to_tn"];
  if (typeof to !== "string" || !E164.test(to)) return not("bad-destination");
  // 3. no-certificate: the gateway holds no STIR certificate it can sign under
  const gw = ctx.gateway;
  if (!isObject(gw) || typeof gw["x5u"] !== "string") return not("no-certificate");
  const key = gatewayKey(gw["key"]);
  if (!key) return not("no-certificate");
  const x5u = gw["x5u"];
  // 4. untrusted-certificate: step 2 on the gateway's own chain
  const path = certificatePath(x5u, ctx, now);
  if (!path) return not("untrusted-certificate");
  // 5. not-authorized-for-tn: step 4; a delegate certificate covers exactly what its carrier delegated (RFC 9060)
  if (!coverageHolds(path, number.slice(1), ctx)) return not("not-authorized-for-tn");
  // 6. key-mismatch
  if (!keyMatches(key, path[0]!)) return not("key-mismatch");
  // 7. signed, at level A (RFC 8588 §3: the caller proved the number is its own, the certificate authorizes the gateway)
  const header: JsonObject = { alg: "ES256", ppt: "shaken", typ: "passport", x5u };
  const pclaims: JsonObject = {
    attest: "A",
    dest: { tn: [to.slice(1)] },
    iat: now,
    orig: { tn: number.slice(1) },
    origid: input["origid"] ?? null,
  };
  const signed = signPassport(key, header, pclaims);
  return { from: number, passport: { header: signed.header, claims: signed.claims }, assertable: true };
}
