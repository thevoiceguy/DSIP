/**
 * Using a verified number binding: the caller's own `tel` claim carrying a binding (N§4), and the warning a client
 * gives when a stored contact's number is now attested for a different identity (N§5).
 *
 * Spec: N§4 (the claim checked against the envelope, a failed claim dropped, rendering), N§5 (a number that moves to
 * another identity), §18.1 (show the basis, never a generic badge), §18.2 (an unverified claim shown marked).
 * Impl: the exact lines are the conformance suite's (`impl/vectors/README.md`, kind `tn-binding`, `check: "claim"`
 * and `check: "contact"`); the spec gives their form, not their text.
 */
import type { Json, JsonObject } from "../did.js";
import { verifyTnBinding, type TnContext } from "./binding.js";

/** Spec: N§1, N§3.1 — E.164: `+`, then 2 to 15 digits, the first not `0`. */
const E164 = /^\+[1-9][0-9]{1,14}$/;

const isObject = (v: Json | undefined): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** The outcome of checking a `tel` claim that carries a binding. */
export type ClaimOutcome =
  | { outcome: "ignored" }
  | { outcome: "attested"; line: string; issued: number; expires: number }
  | { outcome: "dropped"; reason: string; line: string | null };

/**
 * Check a `tel` claim with a `binding` from an invite's `identity.claims`, against the envelope's verified signing
 * identity, and render it.
 *
 * Spec: N§4 — "A receiver verifies the binding (N§3.4) against the DID of the envelope's signing identity, and
 * `number` must equal the binding's `tn`"; "A failed claim is dropped … it may still be shown marked
 * '(unverified)'" (§18.2); rendering per §18.1.
 * Spec: README `check: "claim"` — the order: `binding` not a string (`malformed`), then the first failing N§3.4
 * step, then `number-mismatch`.
 * Spec: README `check: "claim"` — a `binding` member of any value makes a binding claim (`binding: null` is dropped
 * as `malformed`); a claim with a string `verifier` is a gateway claim (G§5) and ignored, even with a `binding`.
 */
export function checkTelClaim(ctx: TnContext, input: JsonObject): ClaimOutcome {
  const claim = input["claim"];
  // A gateway's `tel` claim (G§5) has no binding: it is the `trust` kind's to render.
  // README `check: "claim"`: a claim with a string `verifier` is a gateway claim even when it carries a `binding`.
  if (!isObject(claim) || claim["type"] !== "tel" || !own(claim, "binding") || typeof claim["verifier"] === "string") {
    return { outcome: "ignored" };
  }

  const number = claim["number"];
  const shown = typeof number === "string" && E164.test(number) ? `${number} (unverified)` : null;
  const dropped = (reason: string): ClaimOutcome => ({ outcome: "dropped", reason, line: shown });

  const binding = claim["binding"];
  if (typeof binding !== "string") return dropped("malformed");
  const verified = verifyTnBinding(ctx, {
    binding,
    did: input["identity"] ?? null,
    did_document: input["did_document"] ?? null,
    now: input["now"] ?? null,
  });
  if (verified.outcome === "rejected") return dropped(verified.reason);
  // N§4: `number` must equal the binding's `tn`, compared exactly (no normalisation).
  if (number !== verified.tn) return dropped("number-mismatch");

  const by = verified.attested_by;
  const line = by === null
    ? `${verified.tn} · number attested for this identity`
    : `${verified.tn} · number attested by ${by} for this identity`;
  // `issued` is the binding's `iat`; verification has already checked it is an integer.
  const iat = issuedAt(binding);
  return { outcome: "attested", line, issued: iat, expires: verified.expires };
}

/**
 * The `iat` of a binding that has passed verification (so the payload segment is valid base64url I-JSON).
 *
 * Spec: N§3.1 (payload `iat`).
 */
function issuedAt(binding: string): number {
  const payload = JSON.parse(Buffer.from(binding.split(".")[1]!, "base64url").toString("utf8")) as JsonObject;
  return payload["iat"] as number;
}

/**
 * `issued` (Unix seconds) as a UTC calendar date, `YYYY-MM-DD`.
 *
 * Spec: README `check: "contact"` — "`<date>` is `issued` as a UTC calendar date".
 * Impl: the proleptic Gregorian calendar (JavaScript `Date`), the year zero-padded to 4 digits; a year outside
 * 0–9999 or an `issued` outside `Date`'s range is not pinned and is written as `Date` gives it.
 */
function utcDate(issued: number): string {
  const d = new Date(issued * 1000);
  if (Number.isNaN(d.getTime())) return String(issued);
  const y = d.getUTCFullYear();
  const pad = (n: number, w: number) => String(n).padStart(w, "0");
  return `${y >= 0 ? pad(y, 4) : `-${pad(-y, 4)}`}-${pad(d.getUTCMonth() + 1, 2)}-${pad(d.getUTCDate(), 2)}`;
}

/**
 * The identity-change warning: a verified number that a stored contact lists, now attested for another DID.
 *
 * Spec: N§5 — "A client that holds a contact's DID and number, and then verifies a binding of that number to a
 * different DID, MUST say so. It renders the new identity as new, never as the stored contact."
 * Spec: README `check: "contact"` — `null` when no contact lists `tn`, or when some contact listing `tn` has the
 * attested DID; otherwise the first listing contact, in array order, is named.
 * Impl: numbers and DIDs are compared exactly, as strings. A contact entry that is not an object, or whose `numbers`
 * is not an array, lists nothing. A non-string `name` or `did` is written as JSON would write it (not pinned).
 */
export function contactWarning(input: JsonObject): string | null {
  const attested = input["attested"];
  if (!isObject(attested)) return null;
  const tn = attested["tn"];
  const contacts = Array.isArray(input["contacts"]) ? input["contacts"] : [];
  const listing = contacts.filter(
    (c): c is JsonObject => isObject(c) && Array.isArray(c["numbers"]) && c["numbers"].some((n) => n === tn),
  );
  if (listing.length === 0) return null;
  // The stored identity, unchanged: nothing to say.
  if (listing.some((c) => c["did"] === attested["did"])) return null;

  const first = listing[0]!;
  const text = (v: Json | undefined) => (typeof v === "string" ? v : JSON.stringify(v ?? null));
  const by = attested["attested_by"];
  const date = utcDate(attested["issued"] as number);
  const since = typeof by === "string" ? `number attested by ${by} since ${date}` : `number attested since ${date}`;
  return `${text(tn)} now belongs to a different identity (${since}). Your contact "${text(first["name"])}" is ${text(first["did"])}.`;
}

/**
 * The `tn-binding` vector kind: verification when `input.check` is absent, else the claim or the contact check.
 *
 * Spec: N§3.4, N§4, N§5; README "Kind: `tn-binding`", "`check`".
 */
export function runTnBinding(ctx: TnContext, input: JsonObject): Json {
  const check = input["check"];
  if (check === "claim") return checkTelClaim(ctx, input) as unknown as Json;
  if (check === "contact") return contactWarning(input);
  return verifyTnBinding(ctx, input) as unknown as Json;
}
