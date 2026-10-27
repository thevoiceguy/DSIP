/**
 * Presence Profile (draft, `presence/0.1`): the subscriber's side — combining the records of several
 * devices, and the authority's assertion, into one identity's presence.
 *
 * Spec: P§4 (the combining rule), P§5 (`dsip-presence-state`, open, unknown → `available`)
 * (`v1.0/dsip-presence-profile-v1.0-draft.md`). Contract: `impl/vectors/README.md`, "Kind: `presence`".
 * The authority's side (publishing, the body, expiry, grace) is `../broadcast-state.ts`.
 */
import type { Json, JsonObject } from "../did.js";
import { byCodePoint } from "../recording/recording.js";
import { PRESENCE_STATE_RANK, effectivePresenceState, isRegisteredPresenceState } from "../registry.js";

/** One device's record as the combining rule reads it. Spec: §9.4, P§4 */
export interface PresenceRecordView {
  state: string;
  expires_at: number;
  /** Absent in a v0.16-form record: one unnamed device (P§4). It plays no part in the rule. */
  device?: string;
}

/** An identity's presence as a subscriber shows it. Spec: P§4 */
export interface AggregatePresence {
  /** The effective state: a registered value (P§5). */
  state: string;
  /** The token that won, shown raw when unknown (P§5). */
  token: string;
  /** Where the winner came from; an `assertion` is rendered as the authority's claim (§9.3). */
  source: "record" | "assertion" | "none";
}

interface Candidate {
  token: string;
  source: "record" | "assertion";
}

/**
 * The P§4 combining rule. Candidates: the state of every record still valid (`expires_at` after now),
 * plus `available` when the body's assertion is `available`. None → `offline` from nothing. Otherwise the
 * highest rank wins (`dnd` > `busy` > `available` > `away` > `offline`, unknown as `available`); among equal
 * ranks a record before the assertion, then a registered state before an unknown one, then unknown states in
 * code-point order.
 *
 * Spec: P§4, P§5.
 */
export function aggregatePresence(records: PresenceRecordView[], asserted: string | undefined, now: number): AggregatePresence {
  const candidates: Candidate[] = records
    .filter((r) => r.expires_at > now)
    .map((r) => ({ token: r.state, source: "record" as const }));
  if (asserted === "available") candidates.push({ token: "available", source: "assertion" });
  if (candidates.length === 0) return { state: "offline", token: "offline", source: "none" };
  const rank = (t: string): number => PRESENCE_STATE_RANK[effectivePresenceState(t)]!;
  const before = (a: Candidate, b: Candidate): number => {
    if (rank(a.token) !== rank(b.token)) return rank(b.token) - rank(a.token);
    if (a.source !== b.source) return a.source === "record" ? -1 : 1;
    const ra = isRegisteredPresenceState(a.token);
    const rb = isRegisteredPresenceState(b.token);
    if (ra !== rb) return ra ? -1 : 1;
    return ra ? 0 : byCodePoint(a.token, b.token);
  };
  const winner = [...candidates].sort(before)[0]!;
  return { state: effectivePresenceState(winner.token), token: winner.token, source: winner.source };
}

/** Kind `presence`: one check per vector. A check this implementation does not cover returns `undefined`. */
export function runPresence(context: JsonObject, input: JsonObject): Json | undefined {
  switch (input["check"]) {
    case "aggregate":
      return aggregatePresence(
        (input["records"] ?? []) as unknown as PresenceRecordView[],
        input["asserted"] as string | undefined,
        context["now"] as number,
      ) as unknown as Json;
    default:
      return undefined;
  }
}
