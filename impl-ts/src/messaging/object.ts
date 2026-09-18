/**
 * Content objects: what the plaintext of an MLS application message may be, and how a client reads it.
 *
 * Spec: M§8.1 (objects, sender/conversation/ULID rules), M§8.2 (kind and purpose, with fallback),
 * M§10 (receipts), M§10.5 (the personal-group read watermark, spec-gap 52), M§11.1 (activity),
 * M§12 / M§13.3 (archive keys and call events live in the personal group only), §10.3 (no floats).
 */
import type { Json, JsonObject } from "../did.js";
import { ulidSeconds } from "../encoding.js";
import { reject, type Verdict } from "../verdict.js";
import { messagingSchemas } from "./schemas.js";

/** Spec: M§8.1 — object discriminator → schema; anything else is ignored. */
const OBJECTS: Record<string, string> = {
  content: "content", receipt: "receipt", activity: "activity", "archive-key": "archive-key", "call-event": "call-event",
};
/** Spec: M§12, M§13.3 — objects that would disclose the identity's own state to a peer anywhere else. */
const PERSONAL_ONLY = ["archive-key", "call-event"];

/** Spec: M§8.2 — registry `dsip-content-kind` → the body members the kind MUST carry. */
const KIND_BODY: Record<string, string[]> = {
  text: ["text"], audio: ["blob", "duration_ms"], video: ["blob", "duration_ms"], image: ["blob"],
  file: ["blob", "name"], contact: ["did"], location: ["lat_e7", "lon_e7"],
};
/** Spec: M§8.2 — registry `dsip-content-purpose`. */
const PURPOSES = ["message", "voice-message", "video-message", "voicemail", "attachment", "reaction", "callback-request"];
/** Spec: M§11.1 — registry `dsip-activity`. */
const ACTIVITIES = ["typing", "recording-audio", "recording-video", "uploading"];
/** Spec: M§8.1 / §20.6 — ULID timestamp within 300 s of `sent_at`. */
const ULID_TOLERANCE_S = 300;
/** Spec: M§8.2 — a reaction is one emoji grapheme cluster of at most 32 bytes. */
const MAX_REACTION_BYTES = 32;

function hasFloat(value: Json): boolean {
  if (typeof value === "number") return !Number.isInteger(value);
  if (Array.isArray(value)) return value.some(hasFloat);
  return value !== null && typeof value === "object" && Object.values(value).some(hasFloat);
}

/** What the receiving device knows about the group the object arrived in. */
export interface ObjectContext {
  /** The group's `dsip_conversation.conversation`. */
  conversation: string;
  conversation_kind: string;
  /** The identity of the MLS sender leaf (M§6.2). */
  leaf_identity: string;
}

/** Check one decrypted object. */
export function checkObject(object: JsonObject, ctx: ObjectContext): Verdict {
  if (hasFloat(object)) return reject("payload-float"); // §10.3 holds inside MLS plaintext too
  const schema = OBJECTS[object["object"] as string];
  // M§8.1: an unknown object is ignored — not rendered, not an error
  if (!schema) return { verdict: "accept", effective: { render: "ignore" } };
  if (!messagingSchemas.valid(schema, object)) return reject("schema-invalid");

  // M§8.1: the sender is the MLS leaf's identity, or the object is unauthenticated
  if ("sender" in object && object["sender"] !== ctx.leaf_identity) return reject("sender-mismatch");
  // M§10.5 (spec-gap 52): the one exemption — an undisclosed read watermark in the personal group
  const exempt = ctx.conversation_kind === "personal" && object["object"] === "receipt" && object["kind"] === "read";
  if ("conversation" in object && object["conversation"] !== ctx.conversation && !exempt) return reject("conversation-mismatch");
  if (typeof object["id"] === "string" && typeof object["sent_at"] === "number") {
    const at = ulidSeconds(object["id"]);
    if (at !== null && Math.abs(at - object["sent_at"]) > ULID_TOLERANCE_S) return reject("ulid-sent-at-mismatch");
  }
  if (PERSONAL_ONLY.includes(schema) && ctx.conversation_kind !== "personal") return reject("personal-group-only");

  if (schema === "content") return checkContent(object);
  if (schema === "receipt") return checkReceipt(object);
  if (schema === "activity") {
    const activity = object["activity"] as string;
    return { verdict: "accept", effective: { activity: ACTIVITIES.includes(activity) ? activity : "active" } };
  }
  return { verdict: "accept" };
}

function checkContent(o: JsonObject): Verdict {
  const kind = o["kind"] as string;
  const body = KIND_BODY[kind];
  if (body && body.some((member) => !(member in o))) return reject("content-body");
  // M§8.2: a voicemail names the unanswered session (M§13)
  if (o["purpose"] === "voicemail" && !("session" in o)) return reject("content-body");
  if (o["purpose"] === "reaction") {
    const text = o["text"];
    const graphemes = typeof text === "string" ? [...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(text)].length : 2;
    const ok = kind === "text" && typeof o["reply_to"] === "string" && typeof text === "string" &&
      Buffer.byteLength(text, "utf8") <= MAX_REACTION_BYTES && graphemes <= 1;
    if (!ok) return reject("reaction-invalid");
  }
  const purpose = o["purpose"] as string | undefined;
  return {
    verdict: "accept",
    effective: {
      // M§8.2: an unknown kind with a blob is offered as a file, otherwise an "unsupported message" placeholder
      kind: body ? kind : "blob" in o ? "file" : "unsupported",
      purpose: purpose !== undefined && PURPOSES.includes(purpose) ? purpose : "message",
    },
  };
}

function checkReceipt(o: JsonObject): Verdict {
  const kind = o["kind"] as string;
  // M§10: unknown receipt kinds are ignored, never errors
  if (!["delivered", "read", "played"].includes(kind)) return { verdict: "accept", effective: { render: "ignore" } };
  // M§10.3: read carries `through` instead of `targets`
  const shaped = kind === "read" ? "through" in o && !("targets" in o) : "targets" in o && !("through" in o);
  return shaped ? { verdict: "accept", effective: { receipt: kind } } : reject("receipt-shape");
}
