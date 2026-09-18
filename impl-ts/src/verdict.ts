/**
 * The verdict vocabulary shared by every check.
 *
 * Spec: none (infrastructure) — the codes are the conformance suite's (`impl/vectors/README.md`).
 */
import type { Json } from "./did.js";

/** A message was accepted; extra members depend on the check. */
export type Accept = { verdict: "accept" } & { [k: string]: Json };
/** A message was rejected at the first failing stage. */
export type Reject = { verdict: "reject"; code: string; reason?: string };
/** Outcome of a check. */
export type Verdict = Accept | Reject;

/** Build a rejection; `reason` is the §15 token the receiver signals, when the spec assigns one. */
export function reject(code: string, reason?: string): Reject {
  return reason ? { verdict: "reject", code, reason } : { verdict: "reject", code };
}
