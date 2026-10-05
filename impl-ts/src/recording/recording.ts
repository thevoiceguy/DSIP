/**
 * Recording Profile (draft, `recording/0.1`): the counterparty's consent machine for calls, the
 * recorder device in conversations, and the recording party's checks on its recorder leg.
 *
 * Spec: C§4, C§5, C§6 (`v0.9/dsip-recording-profile-v0.9-draft.md`). Contract: `impl/vectors/README.md`,
 * "Kind: `recording`".
 */
import type { Json, JsonObject } from "../did.js";

/** The reason a declining client sends. Spec: C§4, C§7 (`dsip-reason`). */
export const RECORDING_DECLINED = "policy.recording-declined";

/** The delegation capability that makes a device a recorder. Spec: C§1, C§7. */
export const RECORD_CAPABILITY = "dsip.record";

/**
 * Compare two strings by Unicode code point (not UTF-16 code unit, which is what `<` does).
 *
 * Spec: none (infrastructure).
 * Impl: the README sorts `accepted` and `recorders` "by code point"; JavaScript's default string order
 * differs from it for characters outside the BMP, so this walks code points.
 */
export function byCodePoint(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

type Declaration = { state: string; recorder?: string; purpose?: string };

/**
 * One counterparty's client in one call: renders the other side's recording declaration, holds
 * answering or outbound media until acceptance, and declines with `policy.recording-declined`.
 *
 * Spec: C§4 (consent at the counterparty), C§3 (an absent declaration is `off`; a declaration
 * persists until the next one).
 * Spec: `disclosure` holds only `state`, `recorder` and `purpose` (README).
 * Spec: C§4 as pinned by the README: `local: "answer"` does nothing for a caller; received types are
 * processed alike for either role; the effective state is applied whether or not the declaration
 * changed, and a return to an accepted recorder clears `pending`.
 */
export class ConsentClient {
  private readonly role: string;
  private readonly accept: string;
  private disclosure: Declaration | null = null;
  private pending = false;
  private accepted = new Set<string>();
  private ended: string | null = null;
  private answered = false;

  /** Spec: C§4. `context` is `{role, accept}` (README). */
  constructor(context: JsonObject) {
    this.role = String(context["role"]);
    this.accept = String(context["accept"] ?? "ask");
  }

  /** Apply one event and return the step's snapshot. Spec: C§4. */
  step(event: JsonObject): JsonObject {
    const emit: Json[] = [];
    if ("received" in event) this.received(event["received"] as JsonObject, emit);
    else if (event["local"] === "accept") this.localAccept(emit);
    else if (event["local"] === "decline") {
      if (this.ended === null && this.disclosure !== null) this.decline(emit);
    } else if (event["local"] === "answer") this.localAnswer(emit);
    else throw new Error(`unknown recording event ${JSON.stringify(event)}`);
    return this.snapshot(emit);
  }

  private received(msg: JsonObject, emit: Json[]): void {
    if (this.ended !== null) return;
    if (msg["type"] === "answer") this.answered = true;
    const rec = (msg["recording"] as JsonObject | undefined) ?? { state: "off" };
    const state = String(rec["state"]);
    if (state === "off") {
      // C§4: `off` releases a hold, and the disclosure is rendered as ended
      if (this.disclosure !== null) {
        const r: JsonObject = { state: "off" };
        if (this.disclosure.recorder !== undefined) r["recorder"] = this.disclosure.recorder;
        emit.push({ render: r });
        this.disclosure = null;
      }
      this.pending = false;
      return;
    }
    const decl: Declaration = { state };
    if (typeof rec["recorder"] === "string") decl.recorder = rec["recorder"];
    if (typeof rec["purpose"] === "string") decl.purpose = rec["purpose"];
    const d = this.disclosure;
    if (d === null || d.state !== decl.state || d.recorder !== decl.recorder || d.purpose !== decl.purpose) {
      emit.push({ render: { ...decl } });
      this.disclosure = decl;
    }
    // C§4: `paused` holds nothing; `on` and any unregistered state read as `on` (the safe reading)
    if (state === "paused") {
      this.pending = false;
      return;
    }
    const recorder = decl.recorder ?? "";
    if (this.accepted.has(recorder)) {
      this.pending = false; // C§4: a return to an accepted recorder needs no new acceptance
      return;
    }
    if (this.accept === "always") {
      this.accepted.add(recorder);
      emit.push({ accepted: { recorder, by: "policy" } });
    } else if (this.accept === "never") {
      this.decline(emit); // C§2: `forbidden` means `never`
    } else {
      this.pending = true;
    }
  }

  private localAccept(emit: Json[]): void {
    if (!this.pending || this.disclosure === null) return;
    const recorder = this.disclosure.recorder ?? "";
    this.accepted.add(recorder);
    this.pending = false;
    emit.push({ accepted: { recorder, by: "user" } });
  }

  private localAnswer(emit: Json[]): void {
    if (this.ended !== null || this.role !== "callee") return;
    if (this.pending) {
      emit.push({ blocked: "awaiting-acceptance" }); // C§4: MUST NOT answer before acceptance
      return;
    }
    this.answered = true;
    emit.push({ send: { type: "answer" } });
  }

  /** C§4: a callee that has not answered rejects; otherwise the session ends with `bye`. */
  private decline(emit: Json[]): void {
    const type = this.role === "callee" && !this.answered ? "reject" : "bye";
    emit.push({ send: { type, reason: RECORDING_DECLINED } });
    this.ended = RECORDING_DECLINED;
    this.pending = false;
  }

  private snapshot(emit: Json[]): JsonObject {
    return {
      emit,
      disclosure: this.disclosure === null ? null : { ...this.disclosure },
      pending: this.pending,
      hold_media: this.ended === null && this.pending,
      accepted: [...this.accepted].sort(byCodePoint),
      ended: this.ended,
    };
  }
}

/**
 * Whether a conversation is recorded, who records it, whether this member may send, and whether a
 * sender's content is rendered.
 *
 * Spec: C§5 (a recorder leaf is receive-only; its content is treated as an unauthenticated leaf's,
 * M§6.2).
 * Spec: C§5, acceptance covers every recorder present: `may_send` is whether every recorder's device
 * is in `accepted`, so a recorder that leaves asks nothing new.
 */
export function checkConversation(input: JsonObject): JsonObject {
  const leaves = (input["leaves"] as JsonObject[] | undefined) ?? [];
  const accepted = new Set((input["accepted"] as string[] | undefined) ?? []);
  const isRecorder = (l: JsonObject): boolean =>
    Array.isArray(l["capabilities"]) && (l["capabilities"] as Json[]).includes(RECORD_CAPABILITY);
  const recorders = leaves
    .filter(isRecorder)
    .map((l) => ({ device: String(l["device"]), subject: String(l["subject"]) }))
    .sort((a, b) => byCodePoint(a.device, b.device));
  const out: JsonObject = {
    recorded: recorders.length > 0,
    recorders,
    may_send: recorders.every((r) => accepted.has(r.device)),
  };
  if (typeof input["sender"] === "string") {
    const leaf = leaves.find((l) => l["device"] === input["sender"]);
    out["render_sender"] = leaf !== undefined && !isRecorder(leaf);
  }
  return out;
}

/**
 * The recording party's checks on a recorder leg's offer, before it sends media, in the README order:
 * `not-declared`, `recorder-mismatch`, `missing-capability`, `wrong-session`, `bad-stream-map`,
 * `direction`.
 *
 * Spec: C§6 (the recorder's delegation carries `dsip.record` and its identity is the declared
 * recorder; streams map offered sections to participants; every recorded stream is `sendonly`).
 * Spec: C§6 also fixes what the README pins: no stream, or a `media` that is not an integer index, is
 * `bad-stream-map`; a section with no `direction` is not `sendonly`; an unregistered declared state
 * counts as declared. The tokens are local results (the leg is ended with `bye` `policy.blocked`).
 * Impl: a missing `participants` or `streams` array reads as empty. JSON `1.0` parses to the number 1
 * in JavaScript, so a float-spelled integer index is accepted here; a fractional one is refused.
 */
export function checkRecordingSession(input: JsonObject): JsonObject {
  const declared = (input["declared"] as JsonObject | undefined) ?? {};
  const recorder = (input["recorder"] as JsonObject | undefined) ?? {};
  const offer = (input["offer"] as JsonObject | undefined) ?? {};
  const media = (offer["media"] as JsonObject[] | undefined) ?? [];
  const rs = (offer["recording_session"] as JsonObject | undefined) ?? {};
  const refused = (token: string): JsonObject => ({ refused: token });

  if (declared["state"] === undefined || declared["state"] === "off") return refused("not-declared");
  if (recorder["identity"] !== declared["recorder"]) return refused("recorder-mismatch");
  const caps = (recorder["capabilities"] as Json[] | undefined) ?? [];
  if (!caps.includes(RECORD_CAPABILITY)) return refused("missing-capability");
  if (rs["of"] !== declared["session"]) return refused("wrong-session");

  const participants = new Set(
    ((rs["participants"] as JsonObject[] | undefined) ?? []).map((p) => p["identity"]),
  );
  const streams = (rs["streams"] as JsonObject[] | undefined) ?? [];
  if (streams.length === 0) return refused("bad-stream-map");
  const seen = new Set<number>();
  for (const s of streams) {
    const m = s["media"];
    if (typeof m !== "number" || !Number.isInteger(m) || m < 0 || m >= media.length || seen.has(m))
      return refused("bad-stream-map");
    seen.add(m);
    if (!participants.has(s["participant"] as Json)) return refused("bad-stream-map");
  }
  for (const m of seen) if (media[m]!["direction"] !== "sendonly") return refused("direction");
  return { ok: true };
}

/**
 * Runner for kind `recording`: a consent trace (`input.steps`), or `input.check` of `conversation` or
 * `recording-session`.
 *
 * Spec: C§4, C§5, C§6.
 */
export function runRecording(context: JsonObject, input: JsonObject): Json {
  if (Array.isArray(input["steps"])) {
    const client = new ConsentClient(context);
    return (input["steps"] as JsonObject[]).map((s) => client.step(s["event"] as JsonObject));
  }
  switch (input["check"]) {
    case "conversation":
      return checkConversation(input);
    case "recording-session":
      return checkRecordingSession(input);
    default:
      throw new Error(`unknown recording check ${String(input["check"])}`);
  }
}
