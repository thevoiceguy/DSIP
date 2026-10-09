/**
 * Using a verified number binding: the caller's own `tel` claim carrying a binding (N§4), the warning a client
 * gives when a stored contact's number is now attested for a different identity (N§5), a node's verify-before-store
 * of a published binding (N§6 route 1), the reader's number → DID choice (N§6, N§7), and a client pooling what the
 * number's authorities served it (N§6 route 2).
 *
 * Spec: N§4 (the claim checked against the envelope, a failed claim dropped, rendering), N§5 (a number that moves to
 * another identity), N§6 (discovery: the DHT stays a hints tier, §8.1), N§7 (two verified bindings for one number),
 * §18.1 (show the basis, never a generic badge), §18.2 (an unverified claim shown marked).
 * Impl: the exact lines are the conformance suite's (`impl/vectors/README.md`, kind `tn-binding`, `check: "claim"`
 * and `check: "contact"`); the spec gives their form, not their text.
 */
import type { Json, JsonObject } from "../did.js";
import { readPayload, verifyAll, verifyFirstSteps, verifyTnBinding, type TnContext } from "./binding.js";
import { assertNumber, routeNumber, verifyPassport } from "./gateway.js";

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
  const verified = verifyAll(ctx, binding, input["identity"], input["did_document"], input["now"] as number);
  if ("reason" in verified) return dropped(verified.reason);
  // N§4: `number` must equal the binding's `tn`, compared exactly (no normalisation).
  if (number !== verified.tn) return dropped("number-mismatch");

  const by = verified.attestedBy;
  const line = by === null
    ? `${verified.tn} · number attested for this identity`
    : `${verified.tn} · number attested by ${by} for this identity`;
  return { outcome: "attested", line, issued: verified.iat, expires: verified.exp };
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

/** Byte order of the UTF-8 encodings (README: "binding text in byte order"). */
const byteOrder = (a: string, b: string): number => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

/** A held or new binding with the payload members the held-set rules read. */
interface Entry {
  text: string;
  did: string;
  iat: number;
  exp: number;
}

/** The held-set order: `iat` newest first, then binding text in byte order. Spec: README `check: "store"`. */
const heldOrder = (a: Entry, b: Entry): number => (b.iat - a.iat) || byteOrder(a.text, b.text);

/** Spec: README `check: "store"` — a node holds at most 4 bindings for a number. */
const MAX_HELD = 4;

/** The outcome of a node's verify-before-store. */
export type StoreOutcome =
  | { outcome: "stored"; held: string[] }
  | { outcome: "kept"; reason: string }
  | { outcome: "rejected"; reason: string };

/**
 * A `dsip-node`'s verify-before-store for `PUT /dsip/v1/tn/<tn>`: N§6 discovery route 1.
 *
 * Spec: N§6 ("The DHT stays a hints tier (§8.1). The reader verifies the binding"), §8.1; README `check: "store"` —
 * `bad-number`, then N§3.4 steps 1–5, then `tn-mismatch`, then the held-set rules (expired dropped; one per DID,
 * `same` / replace / `older`; at most 4; eviction of the smallest `iat`, the greatest text among equals).
 * Impl: a held entry's payload segment alone is read (`readPayload`); an entry whose payload does not read is dropped
 * with the expired ones, since the node could never have stored it (not pinned).
 * Impl: when several held bindings name the new binding's DID (which this check never produces), `same` if any is
 * the same text; otherwise `stored` only if the new `iat` is greater than every one of theirs, replacing them all;
 * otherwise `older` (not pinned).
 * Impl: a `held` that is not an array is read as empty (not pinned).
 */
export function storeBinding(ctx: TnContext, input: JsonObject): StoreOutcome {
  const tn = input["tn"];
  const now = input["now"] as number;
  // 1. bad-number
  if (typeof tn !== "string" || !E164.test(tn)) return { outcome: "rejected", reason: "bad-number" };
  // 2. steps 1–5: a node resolves no DIDs
  const v = verifyFirstSteps(ctx, input["binding"], now);
  if ("reason" in v) return { outcome: "rejected", reason: v.reason };
  // 3. tn-mismatch
  if (v.tn !== tn) return { outcome: "rejected", reason: "tn-mismatch" };
  const mine: Entry = { text: input["binding"] as string, did: v.did, iat: v.iat, exp: v.exp };

  // 4. against `held`: expired (and unreadable) ones dropped first
  const rawHeld = Array.isArray(input["held"]) ? input["held"] : [];
  let held: Entry[] = [];
  for (const h of rawHeld) {
    const p = readPayload(h);
    if (p && now < p.exp) held.push({ text: h as string, did: p.did, iat: p.iat, exp: p.exp });
  }
  const done = (set: Entry[]): StoreOutcome => ({ outcome: "stored", held: [...set].sort(heldOrder).map((e) => e.text) });

  const sameDid = held.filter((e) => e.did === mine.did);
  if (sameDid.length) {
    if (sameDid.some((e) => e.text === mine.text)) return { outcome: "kept", reason: "same" };
    if (sameDid.every((e) => mine.iat > e.iat)) return done([...held.filter((e) => e.did !== mine.did), mine]);
    return { outcome: "kept", reason: "older" };
  }
  if (held.length < MAX_HELD) return done([...held, mine]);
  // Eviction candidate: the smallest `iat`; among equals the greatest binding text.
  const candidate = held.reduce((c, e) => (e.iat < c.iat || (e.iat === c.iat && byteOrder(e.text, c.text) > 0) ? e : c));
  if (mine.iat > candidate.iat) {
    held = held.filter((e) => e !== candidate);
    return done([...held, mine]);
  }
  return { outcome: "kept", reason: "full" };
}

/** The outcome of a reader's number → DID choice. */
export type SelectOutcome =
  | { outcome: "none" }
  | { outcome: "found"; did: string; attested_by: string | null; issued: number; others: string[] };

/**
 * The reader's choice among the bindings a lookup returned: number → DID.
 *
 * Spec: N§6 (the reader verifies the binding, N§3.4, then resolves the DID), N§7 ("Both DIDs claim it … The binding
 * with the newer `iat` wins, and the client shows the N§5 warning"); README `check: "select"` — each binding fully
 * verified against its own payload's `did` and `documents[did]`, a wrong `tn` passed over, the greatest `iat`
 * winning, ties to the smallest text in byte order, `others` the other verified DIDs, each once, sorted.
 * Impl: `others` is sorted in UTF-8 byte order, like the binding texts (the README says only "sorted").
 * Impl: a `documents` that is not an object resolves nothing; a member is looked up as an own property only.
 */
export function selectBinding(ctx: TnContext, input: JsonObject): SelectOutcome {
  return selectAmong(ctx, input["bindings"], input).outcome;
}

/** The `select` outcome together with the winning binding's text (for `served_by`). */
interface Selection {
  outcome: SelectOutcome;
  winner: string | null;
}

/**
 * The `select` logic over `bindings`, with `tn`, `documents` and `now` from `input`.
 * Spec: README `check: "select"`; `check: "authority"` ("the `select` check over the pool").
 */
function selectAmong(ctx: TnContext, rawBindings: Json | undefined, input: JsonObject): Selection {
  const tn = input["tn"];
  const now = input["now"] as number;
  const docs = isObject(input["documents"]) ? input["documents"] : {};
  const bindings = Array.isArray(rawBindings) ? rawBindings : [];
  const found: (Entry & { attestedBy: string | null })[] = [];
  for (const b of bindings) {
    const p = readPayload(b); // only to find the DID to check; verifyAll parses the binding in full
    const did = p?.did;
    const doc = did !== undefined && own(docs, did) ? docs[did] : null;
    const v = verifyAll(ctx, b, did ?? null, doc ?? null, now);
    if ("reason" in v || v.tn !== tn) continue;
    found.push({ text: b as string, did: v.did, iat: v.iat, exp: v.exp, attestedBy: v.attestedBy });
  }
  if (found.length === 0) return { outcome: { outcome: "none" }, winner: null };
  const winner = found.reduce((w, e) => (e.iat > w.iat || (e.iat === w.iat && byteOrder(e.text, w.text) < 0) ? e : w));
  const others = [...new Set(found.map((e) => e.did).filter((d) => d !== winner.did))].sort(byteOrder);
  return {
    outcome: { outcome: "found", did: winner.did, attested_by: winner.attestedBy, issued: winner.iat, others },
    winner: winner.text,
  };
}

/** The outcome of pooling the number's authorities' answers: `select`, plus who served the winner. */
export type AuthorityOutcome =
  | { outcome: "none" }
  | { outcome: "found"; did: string; attested_by: string | null; issued: number; others: string[]; served_by: Json[] };

/**
 * A client pooling what the number's authorities served it at `/.well-known/dsip/tn/<tn>`: N§6 discovery route 2,
 * its serving half.
 *
 * Spec: N§6 route 2 — "A client asks the authorities it is configured with …, pools what they return …, verifies
 * every binding in full against its DID's document and chooses by N§7, and remembers which authorities served the
 * chosen binding: the parties accountable for the answer"; README `check: "authority"` — an answer contributes when
 * `status` is the integer 200 and `body` is an object whose `bindings` is an array; its string elements join the
 * pool once each, in first-occurrence order; the `select` check decides; `served_by` names, in `answers` order and
 * each once, the `authority` of every contributing answer whose `bindings` holds the winning binding's text.
 * Impl: an `authority` that is not a string is named as the value it is, deduplicated by its JSON text (not pinned).
 * Impl: an answer that is not an object is not an answer and contributes nothing (not pinned).
 */
export function poolAuthorities(ctx: TnContext, input: JsonObject): AuthorityOutcome {
  // README: "(A `answers` that is not an array is empty.)"
  const answers = Array.isArray(input["answers"]) ? input["answers"] : [];
  const contributing: { authority: Json; bindings: Json[] }[] = [];
  const pool: string[] = [];
  const seen = new Set<string>();
  for (const a of answers) {
    if (!isObject(a)) continue;
    const body = a["body"];
    // `status` is the HTTP status as an integer: `"200"` is not 200.
    if (a["status"] !== 200 || !isObject(body) || !Array.isArray(body["bindings"])) continue;
    contributing.push({ authority: a["authority"] ?? null, bindings: body["bindings"] });
    for (const b of body["bindings"]) {
      if (typeof b !== "string" || seen.has(b)) continue;
      seen.add(b);
      pool.push(b);
    }
  }
  const { outcome, winner } = selectAmong(ctx, pool, input);
  if (outcome.outcome === "none") return outcome;
  const served_by: Json[] = [];
  const named = new Set<string>();
  for (const c of contributing) {
    if (!c.bindings.some((b) => b === winner)) continue;
    const key = JSON.stringify(c.authority);
    if (named.has(key)) continue;
    named.add(key);
    served_by.push(c.authority);
  }
  return { ...outcome, served_by };
}

/**
 * The `tn-binding` vector kind: verification when `input.check` is absent, else the claim, contact, store, select,
 * authority or one of the gateway checks (`gateway.ts`).
 *
 * Spec: N§3.4, N§4, N§5, N§6, N§7, G§5; README "Kind: `tn-binding`", "`check`", "Gateway checks".
 */
export function runTnBinding(ctx: TnContext, input: JsonObject): Json {
  const check = input["check"];
  if (check === "claim") return checkTelClaim(ctx, input) as unknown as Json;
  if (check === "contact") return contactWarning(input);
  if (check === "store") return storeBinding(ctx, input) as unknown as Json;
  if (check === "select") return selectBinding(ctx, input) as unknown as Json;
  if (check === "authority") return poolAuthorities(ctx, input) as unknown as Json;
  if (check === "passport") return verifyPassport(ctx, input) as unknown as Json;
  if (check === "route") return routeNumber(ctx, input) as unknown as Json;
  if (check === "assert") return assertNumber(ctx, input) as unknown as Json;
  return verifyTnBinding(ctx, input) as unknown as Json;
}
