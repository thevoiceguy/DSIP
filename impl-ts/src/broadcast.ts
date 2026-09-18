/**
 * Receiver-side verification of a broadcast publication and its provenance statements.
 *
 * Spec: §22.1 (publication record: publisher binding, stream-id namespace, variant selection),
 * §22.2 (integrity modes), §22.3 (provenance statements, policy violations, what is displayed).
 */
import type { Json, JsonObject } from "./did.js";
import { b64urlDecode } from "./encoding.js";
import { verifyEnvelope, type Envelope, type ReceiverContext } from "./envelope.js";
import type { SchemaSet } from "./schema.js";
import { reject, type Verdict } from "./verdict.js";

/** What the receiver can play. */
export interface Capabilities {
  codecs: string[];
  transports: string[];
}

/** Spec: §22.2 — modes Core v1.0 defines; anything else is read as the weaker `metadata-only`. */
const INTEGRITY_MODES = ["metadata-only", "derivative-bound"];

function payloadOf(envelope: Json): JsonObject {
  return JSON.parse(b64urlDecode((envelope as unknown as Envelope).payload)!.toString("utf8"));
}

function integrity(token: Json | undefined): string {
  return typeof token === "string" && INTEGRITY_MODES.includes(token) ? token : "metadata-only";
}

/** Verify a publication record and the statements that came with it. */
export function verifyPublication(
  publication: Json,
  statements: Json[],
  capabilities: Capabilities,
  ctx: ReceiverContext,
  schemas: SchemaSet,
): Verdict {
  const verdict = verifyEnvelope(publication, ctx, schemas);
  if (verdict.verdict === "reject") return verdict;
  const record = payloadOf(publication);
  const publisher = verdict["identity"] as string;
  // §22.1: `publisher` MUST equal the verified signing identity; streams live in its namespace
  if (record["publisher"] !== publisher) return reject("publisher-mismatch");
  const stream = record["stream_id"] as string;
  if (stream !== publisher && !stream.startsWith(`${publisher}:`)) return reject("stream-id-namespace");

  // §22.1: variant order is the publisher's preference; take the first one we support
  const variants = (record["variants"] ?? []) as JsonObject[];
  const selected = variants.find(
    (v) => capabilities.codecs.includes(v["codec"] as string) && capabilities.transports.includes(v["transport"] as string),
  );
  const policy = (record["policy"] ?? {}) as JsonObject;

  const deliveredBy: string[] = [];
  const transcodedBy: string[] = [];
  const provenance = statements.map((envelope): Json => {
    const v = verifyEnvelope(envelope, ctx, schemas);
    if (v.verdict === "reject") return v;
    const s = payloadOf(envelope);
    const processor = v["identity"] as string;
    // §22.3: the statement names a publication the receiver has verified — this one
    if (s["original_publication"] !== record["id"]) return reject("provenance-unknown-publication");
    if (s["original_stream"] !== stream) return reject("provenance-stream-mismatch");
    if (s["processor"] !== processor) return reject("provenance-processor-mismatch");
    const known = variants.map((x) => x["id"]);
    if (!known.includes(s["input_variant"] as string)) return reject("provenance-variant-unknown");
    const operation = s["operation"] as string;
    const transcode = operation === "transcode";
    const list = transcode ? transcodedBy : deliveredBy;
    if (!list.includes(processor)) list.push(processor);
    // §22.3: a statement the policy forbids still verifies, and is surfaced as a violation
    const violation =
      policy["redistribution"] === "forbidden" ? "redistribution"
      : transcode && policy["transcoding"] === "forbidden" ? "transcoding"
      : undefined;
    return {
      verdict: "accept", processor, operation,
      // Impl: the suite reports every verified statement as `derivative-bound` — the mode of the
      // statement itself (a processor signing a reference to the original, §22.2) — whatever the
      // operation; only a `transcode` changes the mode that is displayed (spec-gap 77).
      integrity_mode: "derivative-bound",
      ...(violation ? { policy_violation: violation } : {}),
    };
  });

  // §22.2: a verified transcode statement makes the delivered stream derivative-bound; otherwise
  // the selected variant's own `integrity` overrides the record's.
  const declared = integrity(selected && "integrity" in selected ? selected["integrity"] : record["integrity"]);
  return {
    ...verdict,
    selected_variant: selected ? (selected["id"] as string) : null,
    provenance,
    display: {
      original_publisher: publisher,
      delivered_by: deliveredBy,
      transcoded_by: transcodedBy,
      integrity_mode: transcodedBy.length ? "derivative-bound" : declared,
    },
  };
}
