/**
 * The DSIP-JOSE envelope verification pipeline: from received bytes to a verified payload.
 *
 * Spec: §10.2 (signature over the transmitted bytes), §10.3 (payload rules), §7.4 (delegation and
 * revocation), §12.9 (replay window), §20.6 (ULID/`issued_at`), §13.2 (frame cap, hello first).
 * The stage order is the conformance suite's (`impl/vectors/README.md`, "Pipeline order").
 */
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { didOf, isDidUrlWithFragment, resolveKey, type DidDocuments, type Json, type JsonObject } from "./did.js";
import { b64urlDecode, hasFloat, isUlid, ulidSeconds, utf8Decode } from "./encoding.js";
import type { SchemaSet } from "./schema.js";
import { checkPayload, type SemanticContext } from "./semantic.js";
import { reject, type Reject, type Verdict } from "./verdict.js";

/** Spec: §13.2 — a ws/1.0 text frame is at most 65,536 bytes. */
export const MAX_FRAME_BYTES = 65536;
/** Spec: §12.9 — replay window, seconds either side of receipt. */
export const REPLAY_WINDOW_S = 300;
/** Spec: §20.6 — Impl: tolerance between the ULID timestamp and `issued_at` (spec-gap 6). */
export const ULID_TOLERANCE_S = 300;
/** Spec: §19.4 — longest introduction validity, seconds (7 days). */
export const MAX_INTRODUCTION_VALIDITY_S = 604800;

/** A DSIP-JOSE envelope as transmitted. Spec: §10.2 */
export interface Envelope {
  protected: string;
  payload: string;
  signature: string;
}

/** Everything a receiver knows when an envelope arrives. */
export interface ReceiverContext extends SemanticContext {
  /** Receiver clock at receipt, integer seconds. */
  now: number;
  did_documents?: DidDocuments;
  /** Delegations held by the verifier (envelopes). Spec: §7.4 */
  delegations?: Json[];
  /** Delegation revocations held by the verifier (envelopes). Spec: §7.4 (v0.8) */
  revocations?: Json[];
  /** Message ids already seen inside the replay window. Spec: §12.9 */
  seen_ids?: string[];
  /** False while the connection has no verified `hello`. Spec: §13.2 */
  hello_verified?: boolean;
}

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** Ed25519 verification over exact bytes. Spec: §10.2 */
function ed25519Verify(key: Buffer, message: Buffer, signature: Buffer): boolean {
  if (signature.length !== 64) return false;
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI_ED25519, key]), format: "der", type: "spki" });
    return cryptoVerify(null, message, pub, signature);
  } catch {
    return false;
  }
}

/** An envelope whose signature verified. */
interface Opened {
  header: JsonObject;
  kid: string;
  /** The payload exactly as signed. */
  bytes: Buffer;
}

/** Accept a JSON envelope object or the compact `protected.payload.signature` form. */
function asEnvelope(value: Json | undefined): Envelope | null {
  if (typeof value === "string") {
    const parts = value.split(".");
    return parts.length === 3 ? { protected: parts[0]!, payload: parts[1]!, signature: parts[2]! } : null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "payload,protected,signature") return null;
  if (!["protected", "payload", "signature"].every((k) => typeof value[k] === "string")) return null;
  return value as unknown as Envelope;
}

/** Stages 2–5. The payload stays raw bytes until the signature has verified (§10.2). */
function open(value: Json | undefined, documents: DidDocuments): Opened | Reject {
  const env = asEnvelope(value);
  const parts = env && [env.protected, env.payload, env.signature].map(b64urlDecode);
  if (!env || !parts || parts.some((p) => p === null)) return reject("envelope-shape");
  const [headerBytes, bytes, signature] = parts as [Buffer, Buffer, Buffer];

  let header: Json;
  try {
    header = JSON.parse(utf8Decode(headerBytes) ?? "!");
  } catch {
    return reject("header-invalid");
  }
  if (!header || typeof header !== "object" || Array.isArray(header)) return reject("header-invalid");
  if (typeof header["alg"] !== "string" || typeof header["kid"] !== "string") return reject("header-invalid");
  if (header["alg"] !== "EdDSA") return reject("alg-unsupported"); // §10.2: ES256 is MAY; everything else MUST be rejected
  const kid = header["kid"];
  if (!isDidUrlWithFragment(kid)) return reject("kid-invalid");

  const key = resolveKey(kid, documents);
  if (!key) return reject("kid-unresolvable");
  // §10.2: the signing input is the transmitted ASCII text, never a re-serialization.
  const signingInput = Buffer.from(`${env.protected}.${env.payload}`, "ascii");
  if (!ed25519Verify(key, signingInput, signature)) return reject("signature-invalid");
  return { header, kid, bytes };
}

/** Stage 6, first three steps: UTF-8, a JSON object, no floats. Spec: §10.3 */
export function decodePayload(bytes: Uint8Array): JsonObject | Reject {
  const text = utf8Decode(bytes);
  if (text === null) return reject("payload-not-utf8");
  let value: Json;
  try {
    value = JSON.parse(text);
  } catch {
    return reject("payload-not-json");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return reject("payload-not-json");
  if (hasFloat(text)) return reject("payload-float");
  return value;
}

function isReject(v: unknown): v is Reject {
  return !!v && typeof v === "object" && (v as Reject).verdict === "reject";
}

/** A verified `delegation-revocation`. */
interface Revocation {
  subject: string;
  device: string;
  revoked_at: number;
}

/**
 * The revocations that count: signed directly by their subject, `from` = `subject`.
 *
 * Spec: §7.4 (v0.8) — verified by signature and subject, not by a delivery window; found in the
 * verifier's store and in the subject's document (`dsipDelegationRevocations`). Invalid ones are ignored.
 */
function revocationsFor(subject: string, ctx: ReceiverContext): Revocation[] {
  const documents = ctx.did_documents ?? {};
  const published = documents[subject]?.["dsipDelegationRevocations"];
  const out: Revocation[] = [];
  for (const candidate of [...(ctx.revocations ?? []), ...(Array.isArray(published) ? published : [])]) {
    const opened = open(candidate, documents);
    if (isReject(opened)) continue;
    const p = decodePayload(opened.bytes);
    if (isReject(p) || p["type"] !== "delegation-revocation") continue;
    if (p["subject"] !== subject || p["from"] !== subject || didOf(opened.kid) !== subject) continue;
    if (typeof p["device"] !== "string" || typeof p["revoked_at"] !== "number") continue;
    out.push({ subject, device: p["device"], revoked_at: p["revoked_at"] });
  }
  return out;
}

/**
 * Bind `device` to `identity` through a delegation; `null` when bound.
 *
 * Spec: §7.4 — a delegation is an envelope signed directly by a key of the subject (no chains),
 * valid when `issued_at ≤ now < expires_at`, carrying `dsip.signaling`; revocation is checked after
 * the signature, capability and validity checks.
 * Impl: delegations the verifier merely holds for other pairs are irrelevant; a delegation
 * *presented* in the protected header that does not link this pair is `delegation-invalid`.
 */
function bind(device: string, identity: string, header: JsonObject, ctx: ReceiverContext): Reject | null {
  const documents = ctx.did_documents ?? {};
  const presented = Array.isArray(header["delegations"]) ? header["delegations"] : [];
  const candidates = [
    ...presented.map((d) => ({ d, presented: true })),
    ...(ctx.delegations ?? []).map((d) => ({ d, presented: false })),
  ];
  let failure: Reject | null = null;
  for (const { d, presented: wasPresented } of candidates) {
    const verdict = checkDelegation(d, device, identity, documents, ctx);
    if (verdict === "bound") return null;
    if (verdict === "unrelated" && !wasPresented) continue;
    failure ??= verdict === "unrelated" ? reject("delegation-invalid") : verdict;
  }
  return failure ?? reject("signer-mismatch");
}

function checkDelegation(
  candidate: Json,
  device: string,
  identity: string,
  documents: DidDocuments,
  ctx: ReceiverContext,
): "bound" | "unrelated" | Reject {
  const env = asEnvelope(candidate);
  const bytes = env && b64urlDecode(env.payload);
  const claimed = bytes ? decodePayload(bytes) : null;
  if (!claimed || isReject(claimed)) return "unrelated";
  if (claimed["device"] !== device || claimed["subject"] !== identity) return "unrelated";

  const opened = open(candidate, documents);
  if (isReject(opened)) return reject("delegation-invalid");
  if (claimed["type"] !== "DeviceDelegation" || didOf(opened.kid) !== identity) return reject("delegation-invalid");
  const { capabilities, issued_at, expires_at } = claimed;
  if (!Array.isArray(capabilities) || typeof issued_at !== "number" || typeof expires_at !== "number") {
    return reject("delegation-invalid");
  }
  if (!capabilities.includes("dsip.signaling")) return reject("delegation-capability");
  if (!(issued_at <= ctx.now && ctx.now < expires_at)) return reject("delegation-expired");
  const revoked = revocationsFor(identity, ctx).some((r) => r.device === device && issued_at <= r.revoked_at);
  return revoked ? reject("delegation-revoked") : "bound";
}

/**
 * Verify a received envelope: stages 1–14, first failure wins.
 *
 * `frame`, when given, is the exact text frame the envelope arrived in (§13.2 size cap).
 */
export function verifyEnvelope(envelope: Json, ctx: ReceiverContext, schemas: SchemaSet, frame?: string): Verdict {
  if (frame !== undefined && Buffer.byteLength(frame, "utf8") > MAX_FRAME_BYTES) {
    return reject("frame-too-large", "transport.envelope-too-large");
  }
  const opened = open(envelope, ctx.did_documents ?? {});
  if (isReject(opened)) return opened;
  const payload = decodePayload(opened.bytes);
  if (isReject(payload)) return payload;

  const { dsip, type, id, from, issued_at, expires_at } = payload;
  const shaped =
    !!dsip && typeof dsip === "object" && !Array.isArray(dsip) &&
    typeof type === "string" && typeof id === "string" && isUlid(id) && typeof from === "string" &&
    Number.isInteger(issued_at) && Number.isInteger(expires_at);
  if (!shaped) return reject("payload-shape");
  const issued = issued_at as number;
  const expires = expires_at as number;

  // Stage 7: bind kid → from, and on hello from → on_behalf_of (§7.4, §13.2).
  const signer = didOf(opened.kid);
  let identity = from as string;
  let unbound = signer === identity ? null : bind(signer, identity, opened.header, ctx);
  if (!unbound && type === "hello" && typeof payload["on_behalf_of"] === "string") {
    if (payload["on_behalf_of"] !== identity) unbound = bind(identity, payload["on_behalf_of"], opened.header, ctx);
    identity = payload["on_behalf_of"];
  }
  if (unbound) return type === "hello" ? reject(unbound.code, "transport.hello-rejected") : unbound;

  if (expires <= issued) return reject("expiry-order");
  if (type === "introduction") {
    // §12.9 (v0.8): a held introduction has no age bound; its validity is capped instead.
    if (expires - issued > MAX_INTRODUCTION_VALIDITY_S) return reject("introduction-validity");
    if (issued > ctx.now + REPLAY_WINDOW_S) return reject("replay-window");
  } else if (issued < ctx.now - REPLAY_WINDOW_S || issued > ctx.now + REPLAY_WINDOW_S) {
    return reject("replay-window");
  }
  if (expires < ctx.now) return reject("expired", type === "invite" ? "session.expired" : undefined);
  if ((ctx.seen_ids ?? []).includes(id as string)) return reject("duplicate-id");
  const ulidAt = ulidSeconds(id as string);
  if (ulidAt !== null && Math.abs(ulidAt - issued) > ULID_TOLERANCE_S) return reject("ulid-issued-at-mismatch");
  if (ctx.hello_verified === false && type !== "hello") return reject("hello-required", "transport.hello-required");

  const encoded = typeof envelope === "string" ? envelope : JSON.stringify(envelope);
  const verdict = checkPayload(
    payload,
    { ...ctx, signer_kid: opened.kid, encoded_size: ctx.encoded_size ?? Buffer.byteLength(encoded, "utf8") },
    schemas,
  );
  if (verdict.verdict === "reject") return verdict;
  return { ...verdict, type: type as string, signer, identity };
}
