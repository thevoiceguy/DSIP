**Status:** DRAFT, companion document to DSIP v0.9 (the `reachability-hint` schema is in the v0.8 schema set; the DHT is a hints tier only, §8.1). v0.8 adds `endpoints[].service` (spec-gap 37).

# Draft: DSIP Reachability Hints Profile (`dht-hints/0.1`)

**Status:** draft carried from the v0.7 spec feedback loop (plan §10.4 deliverable 4). Candidate text
for an *optional* profile under §8.5. Nothing here changes §8.1: a hint is never authoritative.

## 1. Purpose

An endpoint whose DID has no DID document (`did:key`) — or whose document does not advertise a
reachable signaling endpoint — can publish a **reachability hint**: a signed, expiring statement
of where it can currently be reached. Other endpoints use the hint only to choose which
signaling endpoint to dial; identity, delegation, and session security come entirely from the
signed envelopes of the session itself (§10.2, §12).

## 2. Record format

A hint is a DSIP-JOSE envelope (§10.2) whose payload is:

```json
{
  "dsip": {"core": "1.0", "min_core": "1.0", "profiles": [], "extensions": [], "critical": []},
  "type": "reachability-hint",
  "id": "<ULID>",
  "from": "<subject DID>",
  "subject": "<subject DID>",
  "endpoints": [{"uri": "wss://relay.example/dsip", "bindings": ["ws/1.0"]}],
  "seq": 1787262059,
  "issued_at": 1787262059,
  "expires_at": 1787265659
}
```

- `from` MUST equal `subject`. The signing key (`kid`) MUST be a key of the subject or a device
  delegated by the subject (§7.4); the delegation MAY be presented in the protected header
  `delegations` array so that nodes can verify without any external lookup.
- `endpoints[].uri` MUST be `wss://` (§13.2). `bindings` lists signaling bindings.
- `endpoints[].service` (optional, v0.8) names the DID service type the endpoint stands in for:
  `DSIPSignaling` when absent, `DSIPMailbox` for a Messaging Profile mailbox (which then carries that
  service entry's fields, M§4.2). Hints serve only identities with no document entry of that type,
  and never override one (§8.1).
- `seq` MUST be strictly increasing per subject across publications. Using `issued_at` as `seq`
  satisfies this for a single publisher clock; multi-device publishers SHOULD coordinate or
  accept that the latest clock wins.
- `expires_at − issued_at` MUST be ≤ 3,600 s (v0.8, spec-gap 96). Publishers SHOULD re-sign at ⅔ of
  the lifetime.
- Envelope rules apply, with the core §12.9 exception for hints: the age bound is the record's own
  `expires_at`, not the 300 s replay window — a node stores, replicates and returns a hint, and a
  reader accepts it, while `issued_at` is no more than 300 s in the future and `now < expires_at`.
  The 300 s window would otherwise make every hint unusable 300 s after signing, whatever its TTL,
  and no node that missed the first 300 s could ever store it (measured on the WAN testbed). Replay
  of a hint is harmless: §8.3 discards a lower `seq` and treats identical content as a no-op, so
  `id` deduplication does not apply. ULID/`issued_at` consistency and the 65,536-byte cap apply
  unchanged.

Schema: `reachability-hint.schema.json` in the v0.8 spec schema set.

## 3. Keying and transport

- DHT key = multihash `sha2-256` (`0x12 0x20` ‖ digest) of the **normalized** subject DID:
  `did:` prefix and method lower-cased, method-specific id untouched.
- Value = the envelope's text frame (compact JSON), forwarded byte-for-byte.
- Overlay: libp2p Kademlia, protocol `/dsip/hints/0.6`, server mode for nodes that accept
  storage. Bootstrap peers are configuration; implementations SHOULD accept several and SHOULD
  persist learned peers across restarts.

## 4. Verification (MUST, at every hop)

Before a node stores, forwards, or returns a record it MUST:

1. Verify the envelope (§10.2 pipeline) and that `from == subject == verified identity`.
2. Validate the payload against the hint schema.
3. Apply §8.3 against any live record it holds for the key:
   higher `seq` replaces; lower `seq` is discarded; identical content is a no-op; same `seq` with
   different content is a conflict — keep the held record, surface a warning.
4. Treat records past `expires_at` as absent.

A node MUST NOT store a record that fails 1–2 (this is the poisoning defense) and SHOULD count
rejections per remote peer for rate limiting.

## 5. Reading

A reader MUST collect **all** records returned for a key, apply §4 to each, and select the
winner by §8.3. Taking the first record returned is non-conformant. The selected hint MUST be
presented to users and logs as hint-sourced, never as an authoritative endpoint.

## 6. Privacy statement (normative)

Publishing a hint discloses, to anyone who knows the subject DID, the subject's current relay
and the fact that it published recently. It is an explicit opt-in. Presence records (§9.4) MUST
NOT be published to this overlay. Querying a key discloses interest in that DID to the nodes
closest to the key.

## 7. Known limits (informative)

Sybil and eclipse are not addressed: a hostile majority near a key can withhold records or
serve stale-but-valid ones; it cannot forge them. Bootstrap entry points are a censorship point
for newcomers. See `docs/dht-findings.md`.

## 8. Registry entries requested

- `dsip-profile`: `dht-hints/0.1` (optional).
- message type `reachability-hint` (not a session message; §12.1 unaffected).
- `dsip-info-about` unchanged.
