/**
 * Rendering the basis of verification: what a client may say about who is calling.
 *
 * Spec: §18.1 (no generic verified badge — show the basis), §18.2 (display fields are claims),
 * §6.3 / G§6 (gateway downgrade), G§5 (PSTN caller identity as a `tel` claim).
 * Impl: the exact wording is the conformance suite's (`impl/vectors/README.md`, kind `trust`);
 * the spec gives the form of each line, not its text.
 */
import type { JsonObject } from "./did.js";

/** The name a verifier is shown by: the host of a `did:web`, otherwise the DID itself. */
function verifierName(did: string): string {
  if (!did.startsWith("did:web:")) return did;
  return decodeURIComponent(did.slice("did:web:".length).split(":")[0]!);
}

function telClaim(claims: JsonObject[]): JsonObject | undefined {
  return claims.find((c) => c["type"] === "tel");
}

/**
 * The basis line for an identity and the claims it presented.
 *
 * Spec: §18.1 — a `tel` claim is rendered with its attestation level and the gateway that asserts
 * it, never as a verified identity of the caller; it takes precedence over the carrying identity's
 * own basis (the gateway's domain says nothing about the caller).
 */
export function verificationBasis(identity: string, claims: JsonObject[]): string {
  const tel = telClaim(claims);
  if (tel) {
    const level = tel["attestation"] as string;
    const attested =
      level === "none" || level === undefined
        ? "no attestation"
        : `STIR attestation ${level} (${tel["verified"] === true ? "verified" : "unverified"})`;
    return `Gateway attested by ${verifierName(tel["verifier"] as string)} · ${attested}`;
  }
  if (identity.startsWith("did:key:")) return "Self-issued identity";
  if (identity.startsWith("did:web:")) return `Domain verified (${identity})`;
  return "Unrecognized identity method";
}

/** The caller headline for a `tel` claim; `null` for any other claim. Spec: §18.1, §18.2 (CNAM is a claim). */
export function telCallerLine(claim: JsonObject): string | null {
  if (claim["type"] !== "tel") return null;
  const cnam = claim["cnam"];
  return `PSTN caller ${String(claim["number"])}${typeof cnam === "string" ? ` · ${cnam}` : ""}`;
}

/** Spec: §6.3, G§6 — what each named loss means to the person looking at the call. */
const LOSSES: Record<string, string> = {
  "no-srtp-on-trunk": "media is not encrypted on the PSTN trunk",
  "identity-not-assertable": "your identity could not be asserted into the PSTN",
  "no-attestation": "the caller carried no verified attestation",
  "policy-unenforceable": "your media policy cannot be enforced past the gateway",
};

/** The `gateway.downgraded` summary for a list of loss tokens. Spec: §6.3 */
export function downgradeSummary(losses: string[]): string {
  const head = "Trust downgraded crossing the gateway (§6.3)";
  return losses.length ? `${head}: ${losses.map((l) => LOSSES[l] ?? l).join("; ")}` : head;
}
