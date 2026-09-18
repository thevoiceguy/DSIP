/**
 * Checks on a decoded payload: version negotiation, shape, and the stateless semantic checks.
 *
 * Spec: §11 (versions), §10.3 (schemas), §15.1 (reason fallback), and the schema README's semantic checks
 * 5, 7, 9, 11, 12.
 */
import { didOf, type Json, type JsonObject } from "./did.js";
import { effectiveAnsweredBy, effectiveReason, effectiveStatus } from "./registry.js";
import type { SchemaSet } from "./schema.js";
import { reject, type Verdict } from "./verdict.js";

/** What the receiver supports. Spec: §11.1 */
export interface Supported {
  /** Highest core version implemented, `major.minor`. */
  core: string;
  /** Profiles implemented, `name/major.minor`. */
  profiles: string[];
  /** Extensions implemented. */
  extensions: string[];
}

/** Receiver context the stateless checks read. Absent members switch their check off. */
export interface SemanticContext {
  supported?: Supported;
  /** The offer an `answer` refers to (check 9). */
  offer?: JsonObject;
  /** Ids of introductions this receiver sent or holds (check 11). */
  known_introductions?: string[];
  /** Id of the client `hello` actually sent on this connection (check 7). */
  sent_hello_id?: string;
  /** Size of the envelope as received, in bytes (check 11). */
  encoded_size?: number;
  /** The `kid` that signed the envelope (check 12). */
  signer_kid?: string;
}

/** Spec: §19.4 — an introduction envelope is at most 4,096 encoded bytes. */
const MAX_INTRODUCTION_BYTES = 4096;
/** Spec: §9.3 — per-event `expires_in` cap for presence. */
const MAX_PRESENCE_SUBSCRIPTION_S = 3600;

function version(text: Json | undefined): [number, number] | null {
  const m = typeof text === "string" ? /^(\d+)\.(\d+)$/.exec(text) : null;
  return m ? [Number(m[1]), Number(m[2])] : null;
}

/**
 * Stage 12. Spec: §11.2 — major versions are incompatible, minor versions are backward-compatible,
 * unknown critical extensions require rejection; §11.3 names the tokens.
 * Impl: a profile list is acceptable when at least one entry matches a supported profile's name and
 * major version; the spec says only "no mutually supported profile version".
 */
export function checkVersion(payload: JsonObject, supported: Supported): Verdict | null {
  const block = payload["dsip"] as JsonObject;
  const ours = version(supported.core);
  const core = version(block["core"]);
  const min = version(block["min_core"]);
  if (!ours || !core || !min) return null; // shape is stage 13's concern
  const minAboveOurs = min[0] > ours[0] || (min[0] === ours[0] && min[1] > ours[1]);
  if (core[0] !== ours[0] || minAboveOurs) return reject("version-unsupported", "session.unsupported-core-version");
  const profiles = Array.isArray(block["profiles"]) ? block["profiles"] : [];
  if (profiles.length > 0) {
    const mutual = profiles.some((p) => {
      const [name, v] = typeof p === "string" ? p.split("/") : [];
      const pv = version(v);
      return supported.profiles.some((s) => {
        const [sname, sv] = s.split("/");
        const spv = version(sv);
        return pv && spv && sname === name && spv[0] === pv[0];
      });
    });
    if (!mutual) return reject("version-unsupported", "session.unsupported-profile-version");
  }
  const critical = Array.isArray(block["critical"]) ? block["critical"] : [];
  if (critical.some((c) => typeof c !== "string" || !supported.extensions.includes(c))) {
    return reject("version-unsupported", "session.unsupported-critical-extension");
  }
  return null;
}

/** Stage 13. Spec: §10.3 */
export function checkShape(payload: JsonObject, schemas: SchemaSet): Verdict | null {
  const type = payload["type"];
  if (typeof type !== "string" || !schemas.isMessageType(type)) return reject("unknown-type");
  return schemas.validMessage(type, payload) ? null : reject("schema-invalid");
}

/** SDP-style answers to an offered direction. Spec: §14.2; Impl: vectors README, check 9 */
const ANSWERS: Record<string, string[]> = {
  sendrecv: ["sendrecv", "sendonly", "recvonly", "inactive"],
  sendonly: ["recvonly", "inactive"],
  recvonly: ["sendonly", "inactive"],
  inactive: ["inactive"],
};

function isSubset(selection: JsonObject, offer: JsonObject): boolean {
  const offered = (offer["media"] ?? []) as JsonObject[];
  for (const sel of (selection["media"] ?? []) as JsonObject[]) {
    const match = offered.find(
      (o) => o["type"] === sel["type"] && (!("purpose" in sel) || o["purpose"] === sel["purpose"]),
    );
    if (!match) return false;
    const ids = ((match["codecs"] ?? []) as JsonObject[]).map((c) => c["id"]);
    if (((sel["codecs"] ?? []) as JsonObject[]).some((c) => !ids.includes(c["id"]!))) return false;
    const offeredDir = (match["direction"] ?? "sendrecv") as string;
    const selectedDir = (sel["direction"] ?? "sendrecv") as string;
    if (!(ANSWERS[offeredDir] ?? []).includes(selectedDir)) return false;
  }
  const transports = ((offer["transports"] ?? []) as JsonObject[]).map((t) => t["id"]);
  return ((selection["transports"] ?? []) as JsonObject[]).every((t) => transports.includes(t["id"]!));
}

/** Stage 14, rejecting half. */
export function checkSemantics(payload: JsonObject, ctx: SemanticContext): Verdict | null {
  const type = payload["type"];
  if ((type === "answer" || type === "reject") && ctx.offer && !isSubset(payload, ctx.offer)) {
    return reject("selection-not-subset"); // check 9
  }
  if (type === "subscribe") {
    const events = (payload["events"] ?? []) as Json[];
    if (events.includes("presence") && (payload["expires_in"] as number) > MAX_PRESENCE_SUBSCRIPTION_S) {
      return reject("subscription-lifetime-exceeded", "policy.subscription-lifetime"); // §9.3
    }
  }
  if (type === "introduction") {
    if ("purpose" in payload && "sealed" in payload) return reject("introduction-purpose-and-sealed"); // §19.4
    if (ctx.encoded_size !== undefined && ctx.encoded_size > MAX_INTRODUCTION_BYTES) {
      return reject("introduction-too-large"); // §19.4
    }
  }
  if (type === "grant" && ctx.known_introductions && !ctx.known_introductions.includes(payload["session"] as string)) {
    return reject("grant-unknown-introduction"); // §19.4
  }
  if (type === "hello" && "in_reply_to" in payload && ctx.sent_hello_id !== undefined) {
    // §13.2, §20.5: anti-splicing — the relay's hello answers the hello this client sent.
    if (payload["in_reply_to"] !== ctx.sent_hello_id) return reject("hello-in-reply-to-mismatch");
  }
  if (type === "key-rotation") {
    // §7.5
    if (payload["from"] !== payload["subject"]) return reject("rotation-subject-mismatch");
    if (payload["next"] === payload["previous"]) return reject("rotation-next-same-as-previous");
    if (ctx.signer_kid !== undefined && ctx.signer_kid !== payload["previous"] && payload["recovery"] !== true) {
      return reject("rotation-signer-not-previous");
    }
  }
  if (type === "delegation-revocation") {
    // §7.4 (v0.8)
    if (payload["from"] !== payload["subject"]) return reject("revocation-subject-mismatch");
    if (ctx.signer_kid !== undefined && didOf(ctx.signer_kid) !== payload["subject"]) {
      return reject("revocation-signer-not-subject");
    }
  }
  return null;
}

/** Stage 14, accepting half: the effective reading of registry-governed values (check 5). */
export function interpret(payload: JsonObject): { effective?: JsonObject; warnings?: string[] } {
  const type = payload["type"] as string;
  const effective: JsonObject = {};
  const warnings: string[] = [];
  if (["reject", "cancel", "bye", "error", "notify"].includes(type) && typeof payload["reason"] === "string") {
    const e = effectiveReason(payload["reason"], type);
    effective["reason"] = e.reason;
    effective["fallback"] = e.fallback;
    // Impl: §9.3 puts `session.expired` / `policy.terminated` on a terminal `notify`, but the §15.4
    // "valid on" column never lists `notify`; the column is not applied to it (spec-gap 73).
    if (!e.validOnType && type !== "notify") warnings.push("reason-not-valid-on-type");
  }
  if (typeof payload["answered_by"] === "string") effective["answered_by"] = effectiveAnsweredBy(payload["answered_by"]);
  if (type === "progress" && typeof payload["status"] === "string") effective["status"] = effectiveStatus(payload["status"]);
  return {
    ...(Object.keys(effective).length ? { effective } : {}),
    ...(warnings.length ? { warnings } : {}),
  };
}

/** Stages 12–14 over a decoded payload. */
export function checkPayload(payload: JsonObject, ctx: SemanticContext, schemas: SchemaSet): Verdict {
  const failed =
    (ctx.supported ? checkVersion(payload, ctx.supported) : null) ??
    checkShape(payload, schemas) ??
    checkSemantics(payload, ctx);
  return failed ?? { verdict: "accept", ...interpret(payload) };
}
