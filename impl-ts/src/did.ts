/**
 * Resolving a `kid` to an Ed25519 verification key.
 *
 * Spec: §8.1 (the DID document is the top of the authority order), §7.2 (did:key, did:web), §10.2 (`kid`).
 */
import { ed25519FromMultibase } from "./encoding.js";

/** Any decoded JSON value. */
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
/** A decoded JSON object. */
export type JsonObject = { [k: string]: Json };

/** DID documents a verifier holds, keyed by DID. Vectors supply them; nothing here touches a network. */
export type DidDocuments = Record<string, JsonObject>;

/** The DID part of a DID URL (everything before `#`). */
export function didOf(didUrl: string): string {
  const i = didUrl.indexOf("#");
  return i < 0 ? didUrl : didUrl.slice(0, i);
}

/** True when `kid` is a DID URL with a non-empty fragment. Spec: §10.2 */
export function isDidUrlWithFragment(kid: string): boolean {
  return /^did:[a-z0-9]+:[^#\s]+#[^#\s]+$/.test(kid);
}

/**
 * The raw Ed25519 key `kid` names, or `null` when it cannot be resolved.
 *
 * Spec: §8.1 — `did:key` resolves from the identifier alone, and its only verification method is
 * the key itself (the fragment repeats the multibase value). `did:web` resolves through the
 * document, so a rotated-out fragment names nothing (§7.5).
 */
export function resolveKey(kid: string, documents: DidDocuments): Buffer | null {
  const did = didOf(kid);
  const fragment = kid.slice(did.length + 1);
  if (did.startsWith("did:key:")) {
    const multibase = did.slice("did:key:".length);
    return fragment === multibase ? ed25519FromMultibase(multibase) : null;
  }
  const doc = documents[did];
  const methods = doc?.["verificationMethod"];
  if (!Array.isArray(methods)) return null;
  for (const m of methods) {
    if (m && typeof m === "object" && !Array.isArray(m) && m["id"] === kid) {
      const mb = m["publicKeyMultibase"];
      return typeof mb === "string" ? ed25519FromMultibase(mb) : null;
    }
  }
  return null;
}
