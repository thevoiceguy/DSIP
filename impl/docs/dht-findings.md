# Workstream D — DHT reachability hints: findings report

**Against:** spec §8.5 risk list (Sybil, eclipse, spam indexing, privacy leakage, poisoned
routing records, inconsistent availability) and plan §10.4 deliverable 3.
**Data:** `tools/dht_testnet.py` runs on a 5-node and a 12-node local testnet
(`docs/dht-testnet-report.json`, `docs/dht-testnet-report-12.json`), plus the
`demos/dht-demo.sh` end-to-end call. Localhost only — no NAT, no WAN latency, no
adversarial routing. Everything below is scoped by that.

## What was built

- `dsip-dht`: hint records are ordinary DSIP-JOSE envelopes (`type: reachability-hint`,
  schema `reachability-hint.schema.json`, in the v0.7 spec set), keyed by the SHA-256 multihash of the
  normalized subject DID, carried over libp2p Kademlia (`/dsip/hints/0.6`).
- **Verification at the storage boundary.** Every node evaluates an inbound PUT with the full
  envelope pipeline (signature over bytes, `kid` → subject key or a presented §7.4 delegation,
  replay window, schema) and the §8.3 rules against what it already holds before storing.
  Unverifiable or superseded records are counted and dropped. The same evaluation ranks the
  results of a GET, and the publishing node applies it to its own publishes.
- The authority order is unchanged: `dsip resolve` and `dsip call` print every hint as
  **HINT-SOURCED, NOT AUTHORITATIVE**, and a hint is only ever used to pick which relay to dial;
  identity and trust still come from the envelope signatures on the call itself.

## Results

| Check | 5 nodes | 12 nodes |
|---|---|---|
| publish → resolve round-trip (`did:key` subject, delegated device signer) | pass; 5 copies returned | pass; 12 copies returned |
| newer `seq` wins; stale `seq` refused by an honest publisher and superseded on peers | pass | pass |
| poisoning: mis-signed records injected raw (`put_raw`) at two nodes | 8 inbound PUTs rejected (`signer-mismatch`); honest publish refused; evil record never selected | 22 rejected; same outcome |
| expiry lapse (3 s TTL) | resolves while live; all copies `expired` after | same |
| publisher killed; late joiner | record still served by 4/4 remaining; joiner finds it | 11/11; joiner finds it |
| end-to-end call discovered via hint only | `demos/dht-demo.sh` completes invite→answer→bye | — |

Round-trip publish-to-resolve latency on localhost was sub-second; the harness's only waits
are the 1.5–2.5 s routing warm-up after a node joins.

## Findings against the §8.5 risk list

1. **Poisoned records — mitigated by construction, at a cost.** Because a node verifies before it
   stores, a mis-signed record never propagates past the first honest hop and never ranks in a
   GET. The cost is CPU: every injection triggers an Ed25519 verification (plus delegation
   verification) on every node the attacker can reach, and Kademlia's replication fan-out
   multiplied 2 injections into 8–22 verification events. **An attacker who cannot forge a
   record can still make honest nodes verify garbage.** Rate-limiting inbound PUTs per peer is
   the obvious next control; it is not implemented.
2. **Sybil / eclipse — not addressed, by design (§3.2, plan §10.5).** Nothing stops one operator
   from running many PeerIds. Because records are self-certifying, a Sybil majority cannot
   *forge* reachability; it can **withhold** it (serve no record) or serve a **stale but valid**
   older record. The seq rule defends against staleness only if the querier reaches at least one
   honest holder of the newest record; an eclipsed querier has no way to know it is eclipsed.
   This is the residual risk the spec should keep naming.
3. **Bootstrap centralization — measured, real.** Every node joined through one configured
   address (node 0; node 1 as second). If node 0 is unreachable before a node's first join, that
   node never enters the overlay; after joining, node 0's death did not matter (churn test). The
   bootstrap list is a trust-on-first-use choice of *whom you ask for peers*, not of *what you
   believe* — but it is a censorship point for newcomers. Multiple independent bootstrap
   operators, cached peer lists across restarts, and out-of-band peer exchange are the usual
   mitigations; none is in the PoC.
4. **Availability under churn — good in a small overlay, unknown at scale.** With ≤ 12 nodes and
   Kademlia's replication factor of 20, every record lived on every node, which makes the churn
   result unsurprising. At scale a record lives on the ~20 closest nodes; availability then
   depends on the re-announce interval relative to churn. The node re-announces held records
   every 60 s (5 s in tests); the *publisher* re-signs before `expires_at` (the CLI does so at ⅔
   of the TTL). Neither number is tuned by data.
5. **Privacy leakage — present and worth stating plainly.** (a) A hint is public: anyone who knows
   a DID can learn which relay its owner uses and that the owner was online recently enough to
   publish — a coarse presence signal, exactly what §9.2 says presence privacy must not leak.
   (b) A GET reveals to the ~20 closest nodes that *someone* is interested in that DID. (c) Keys
   are hashes of DIDs, so a node cannot enumerate subjects it does not already know, but it can
   confirm guesses. The profile should say that publishing a hint is an opt-in disclosure of
   reachability, and that presence records (§9.4) must not ride this overlay.
6. **Spam indexing — partially bounded.** Records must verify against their subject, so a spammer
   can only index DIDs it controls; creating DIDs is free (`did:key`), so it can index arbitrarily
   many *of its own*. Per-key record size is bounded by the envelope cap; per-node storage is
   not. A storage quota per PeerId and a minimum TTL would be the next controls.
7. **Inconsistent availability / stale reads.** A GET returns every copy the closest nodes hold;
   we observed mixed results (`older-seq` alongside the newest) immediately after a stale
   injection, and the seq rule resolved them correctly. Readers must fetch *all* copies and
   rank, not take the first — libp2p's default "first record wins" GET would have been wrong
   here.

## Things the PoC deliberately did not do

- No relay participation yet: browsers and relays are expected to query/publish on behalf of
  endpoints (plan §10.2 browser asymmetry); the relay binary does not yet embed a node.
- No NAT traversal, no QUIC transport, no WAN measurements.
- No Sybil or eclipse countermeasure, no reputation, no presence in the DHT (plan §10.5).
- `did:web` subjects work (the resolver accepts document files) but were not exercised on the
  testnet; the flagship path is `did:key`, where verification needs no external resolution at all.

## Recommendation for v0.7

Keep §8.5 "experimental" but give it a concrete, optional profile (`docs/dht-hints-profile.md`)
so that implementations that do ship hints agree on record format, keying, and ranking. Do
**not** promote hints toward authority: the data here shows they are reliably *unforgeable*
but not reliably *available* or *fresh* under adversarial peers, which is exactly the boundary
§8.1 rule 6 draws.
