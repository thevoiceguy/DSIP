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

## WAN results (2026-10-02, commit `5ff45ea`)

Four Linodes on three continents and one endpoint behind a home NAT, per `tools/wan/README.md`:
L1 Atlanta (bootstrap, relay A, Alice's mailbox + hub), L2 Seattle (DHT, relay B, Bob's mailbox),
L3 Tokyo (DHT), L4 Milan (DHT, STUN/TURN). Alice on the NAT'd endpoint (port-preserving NAT per
STUN). RTT from Alice: L1 55 ms, L2 87 ms, L3 208 ms, L4 119 ms. All DHT clocks within 1 ms
(chrony). Bob ran on L2 (no second NAT'd host yet), so **Run 3 (NAT on both ends, TURN) is still
open**. Raw records: `docs/dht-wan-results.jsonl`, one JSON object per run (`*-after` rows are the re-runs on `7d47ab0` = `4b83e55` + #58).

| Run | What | Result | Key numbers |
|---|---|---|---|
| 1 | Baseline: NAT'd Alice finds public Bob through the DHT and calls | pass | resolve 1.9 s; ICE 521 ms after `hello`; first RTP +194 ms; rhythm 0.97 / 0.98; hint stored on 2 of 4 nodes |
| 2 | Bootstrap death and rejoin | pass | via dead BOOT1: 1.6 s, 0 records, *no diagnostic*; via BOOT2: 1.95 s + call; both listed, dead first: +0 ms (RST); restarted L1: 0 peers for 95 s, then 2 of 3, 0 records recovered (replicated copies rejected `replay-window`) |
| 2b | Callee frozen / killed inside the hint TTL | pass | T-Establish (10 s) → `cancel session.timeout`; killed: relay queues the invite (§13.3), dequeued on cancel; user sees `session.timeout` at 11.8 s — indistinguishable from no answer |
| 4 | Partition, stale copies, freshness (TTL 120 s) | pass | precondition "stored on all 4" never met; one unreachable node makes every GET/publish ~10–11 s; partitioned node's copy had already expired (served as `expired`, never stale-valid); converged within 30 s of lifting; L3 accepted 0 puts all run |
| 5 | Forged-PUT flood, 50/s from L3 | pass | 3,001 sent, every one rejected `signer-mismatch`, `stored` unchanged; resolve mid-flood 2.5 s (vs 1.9); 3–6 % of one core per honest node |
| 1-after | Run 1 on the fixed build | pass | publish acknowledged by 4, stored on all 4 (Tokyo included); 4 records returned; resolve 2.0 s; ICE 547 ms, RTP +207 ms; the hint resolves 4/4 at 322 s and 380 s old (was 0/3 at 321 s) |
| 2-after | Bootstrap restart on the fixed build | partial | restarted L1 re-acquired Bob's hint in 77 s with no rejections (was: rejected `replay-window`); its routing table stayed empty > 3 min — no persisted peers, no bootstrap of its own |
| 5-after | Same flood, rate-limited nodes | pass | signature checks 3,001 → 40 per node (20 per 60 s window), 2,100–2,700 dropped unverified; resolve 2.0 s; **CPU unchanged** (3.3–5.2 %) |
| 6 | Messaging Profile across hosts | pass | delivery median 76 ms (A→B), ~80 ms (B→A); offline sync 415 ms; `kill -9` restore without replay; federation backoff 4/8/16/32 s; hub restart → held message accepted 12 s; blob 16,486 B byte-identical, sealed at rest, replicated from the public `blob_endpoint`, fetched with L1 down |

What the WAN showed that localhost could not, and what was done about it:

1. **Hints were unusable 300 s after signing** — the 300 s replay window applied to a record meant
   to live for its TTL. Spec-gap 96 (core §12.9 exception, DHT profile §2), PR #55.
2. **Hints reached only some nodes — two causes.** `Quorum::One` + libp2p-kad ending a put at
   quorum stopped at the first wave of closest peers (`Quorum::All`, PR #56). Separately, every node
   advertised `127.0.0.1` among its listen addresses; a client on a host that runs its own node
   dialed that, reached the local node, and libp2p dropped the peer (`WrongPeerId`) — which is why
   Tokyo never stored Bob's hint from L2, not distance (PR #58). The "acknowledged by N" count was
   a hard-coded 1; it now counts the nodes that stored the record.
3. **Short-lived CLI clients polluted routing tables** (7–17 entries in a 4-node overlay); they now
   join in client mode. PR #56.
4. **A dead bootstrap was silent** (`joined … via 1 bootstrap node(s)`, then "no hint"); the CLI now
   reports peers reached. PR #56.
5. **Flood cost.** A per-peer rejection budget (20 verification failures / 60 s) now drops a
   misbehaving peer's PUTs unverified (PR #56): signature checks fell from 3,001 to 40 per node. CPU
   did not fall — at 50 PUTs/s the cost is the connection, stream and Kademlia handling, not
   Ed25519. The next control is to disconnect or ban a peer once its budget is spent.
6. Messaging clients did not reconnect after a mailbox restart (core §13.2 SHOULD); fixed in the
   `dsip-msg` reconnect PR, which also stops a receipt queued behind a hub outage being reported as
   refused.

Against the §8.5 risk list above: **1** (poisoned records) — measured on WAN: 3–6 % of a core at
50 forged PUTs/s; verification is now bounded per peer, transport cost is not. **3** (bootstrap centralization) — measured: a dead first
bootstrap costs nothing when a second is listed, but a client with only the dead one is cut off and
was not told; a restarted bootstrap node with no cached peers took 95 s to see 2 of its 3 peers on the first
build and saw none for over 3 minutes on the second (it now re-acquires records regardless).
**4** (availability) — on WAN the replication assumption failed (2 of 4 nodes) until puts waited for
every closest peer and loopback addresses stopped reaching routing tables; now 4 of 4. **7** (stale reads) — with TTLs ≤ 3,600 s and re-signing at ⅔, a partitioned
node's copy expired before the partition healed; the seq rule picked the newer relay throughout.
Still not done: Run 3 (both ends behind NAT; TURN fallback), persisted peer lists and a bootstrap
list on bootstrap nodes themselves, connection-level penalties for flooding peers.

## Things the PoC deliberately did not do

- No relay participation yet: browsers and relays are expected to query/publish on behalf of
  endpoints (plan §10.2 browser asymmetry); the relay binary does not yet embed a node.
- No QUIC transport. WAN measurements: see "WAN results" above (Run 3, NAT on both ends, still open).
- No Sybil or eclipse countermeasure, no reputation, no presence in the DHT (plan §10.5).
- `did:web` subjects work (the resolver accepts document files) but were not exercised on the
  testnet; the flagship path is `did:key`, where verification needs no external resolution at all.

## Recommendation for v0.7

Keep §8.5 "experimental" but give it a concrete, optional profile (`docs/dht-hints-profile.md`)
so that implementations that do ship hints agree on record format, keying, and ranking. Do
**not** promote hints toward authority: the data here shows they are reliably *unforgeable*
but not reliably *available* or *fresh* under adversarial peers, which is exactly the boundary
§8.1 rule 6 draws.
