/**
 * Blobs: the HTTPS upload endpoint, replication to member mailboxes, and where a device fetches from.
 *
 * Spec: M§5.6 (`blob-put`, refusal order — spec-gap 48), M§8.4 rules 6–7 (replication, rewriting,
 * fetch order — spec-gaps 65 and 67).
 */
import type { JsonObject } from "../did.js";

interface ManifestEntry {
  uri: string;
  sha256: string;
  size: number;
}

/** Spec: M§8.4 (spec-gap 67) — RECOMMENDED bound on replication attempts. */
const MAX_REPLICATION_ATTEMPTS = 5;

/**
 * Answer a `PUT {blob_endpoint}/{sha256}`. `authorization` is the verified `blob-put` envelope
 * (its payload and the delegating identity), or `null` when there was none that verified.
 *
 * Spec: M§5.6 — refusals are checked in this order so a server can refuse before reading a body.
 */
export function blobPut(i: {
  mailbox: { did: string; serves: string[]; max_blob_bytes: number };
  authorization: { identity: string; payload: JsonObject } | null;
  request: { path_sha256: string; body_size: number; body_sha256: string };
  stored: string[];
}): JsonObject {
  const refuse = (status: number, reason: string): JsonObject => ({ status, reason });
  if (i.authorization === null) return refuse(401, "policy.blocked");
  const { identity, payload } = i.authorization;
  if (payload["to"] !== i.mailbox.did) return refuse(403, "policy.blocked");
  if (!i.mailbox.serves.includes(identity)) return refuse(403, "transport.unknown-recipient");
  if (i.request.path_sha256 !== payload["sha256"]) return refuse(400, "policy.blocked");
  if ((payload["size"] as number) > i.mailbox.max_blob_bytes) return refuse(413, "mailbox.object-too-large");
  const accepted = { in_reply_to: payload["id"]! };
  // uploads are idempotent (M§9.3)
  if (i.stored.includes(i.request.path_sha256)) return { status: 200, accepted: { ...accepted, duplicate: true } };
  if (i.request.body_size !== payload["size"] || i.request.body_sha256 !== payload["sha256"]) return refuse(400, "mailbox.blob-mismatch");
  return { status: 201, accepted };
}

/** Spec: M§5.6 — the hash is the capability. */
export function blobGet(pathSha256: string, stored: string[]): JsonObject {
  return { status: stored.includes(pathSha256) ? 200 : 404 };
}

/** Spec: M§8.4 rule 6 (spec-gaps 65, 67) — whether to fetch a manifest blob, and what to do with the answer. */
export function blobReplicate(i: {
  mode: string; max_blob_bytes: number; stored: string[]; entry: ManifestEntry;
  fetched?: { status: number; sha256?: string; size?: number }; attempt?: number; max_attempts?: number;
}): JsonObject {
  if (i.mode !== "sync") return { action: "skip", reason: "mode" };
  if (i.stored.includes(i.entry.sha256)) return { action: "skip", reason: "stored" };
  if (i.entry.size > i.max_blob_bytes) return { action: "skip", reason: "too-large" };
  if (!i.entry.uri.startsWith("https://")) return { action: "skip", reason: "not-https" };
  if (i.fetched === undefined) return { action: "fetch" };
  if (i.fetched.status !== 200) {
    // nothing to serve yet: tried again, a bounded number of times
    return { action: "discard", reason: "unavailable", retry: (i.attempt ?? 1) < (i.max_attempts ?? MAX_REPLICATION_ATTEMPTS) };
  }
  if (i.fetched.sha256 !== i.entry.sha256 || i.fetched.size !== i.entry.size) {
    return { action: "discard", reason: "mismatch", retry: false }; // the origin would serve the same bytes
  }
  return { action: "store" };
}

/** Spec: M§8.4 rule 6 — in `items`, a held blob is named at this mailbox's own endpoint; the rest are unchanged. */
export function itemsBlobs(blobEndpoint: string, stored: string[], manifest: ManifestEntry[]): JsonObject {
  return { blobs: manifest.map((e) => (stored.includes(e.sha256) ? { ...e, uri: `${blobEndpoint}/${e.sha256}` } : { ...e })) };
}

/** Spec: M§8.4 rules 6–7 — the mailbox's copy first, then the content's own `uri`; every source is verified. */
export function blobSources(blob: ManifestEntry, manifest: ManifestEntry[] | null): JsonObject {
  const copies = (manifest ?? [])
    .filter((e) => e.sha256 === blob.sha256 && e.size === blob.size && e.uri !== blob.uri)
    .map((e) => e.uri);
  return { sources: [...copies, blob.uri] };
}
