# DSIP Proof-of-Concept Development Plan

**Tracks:** DSIP Draft v0.6 and the v0.6 JSON Schema set (draft 2020-12)
**Implementation language:** Rust (rationale in §2)
**Status:** Draft for review
**Scope anchor:** Spec §25 "Minimal Reference Implementation," Phases 1–4

---

## 1. Purpose and Ground Rules

The PoC exists to do three things, in priority order:

1. **Prove the spec is implementable.** Every MUST in §10–§15 either gets implemented or generates a filed spec issue. Ambiguities discovered during implementation are treated as spec bugs, not implementation judgment calls.
2. **Produce a conformance contract.** The language-neutral test vector suite (§5) becomes the artifact that any second implementation is measured against. The Rust code proves the vectors; the vectors outlive the Rust code.
3. **Demo the story.** Phase milestones each end in something demonstrable: a CLI call flow, a browser call with identity display, a verified broadcast subscription.

Ground rules:

- **Vectors before code** for every stateful behavior. No state machine transition ships without a vector trace exercising it.
- **The spec's authority order is the code's authority order.** DID document > alias resolution > cache > hints (§8.1). Nothing in the PoC treats a non-authoritative source as authoritative.
- **Signature over bytes, always.** The base64url payload is carried as bytes through verification and only then decoded (§10.2). No re-serialization on the verify path, ever.
- **Spec drift is absorbed by the vector suite.** When v0.7 lands, the diff is expressed as vector changes first, code changes second.
- **Documentation is a deliverable.** Every normative behavior in code cites the spec section it implements, and every open-choice resolution is marked as such (§4). Undocumented public items fail the build.

---

## 2. Why Rust

- **The §12 state machine is the centerpiece of Phase 1**, and Rust's sum types and ownership model let invalid states and transitions be unrepresentable at compile time. A reference implementation whose session lifecycle is compiler-checked is a stronger credibility artifact than a dynamically-typed one.
- **Byte-preservation through the signature path** (§10.2 signs exact transmitted bytes; no canonicalization) is natural in Rust and error-prone in eagerly-parsing dynamic languages.
- **WASM path for Phase 2.** The envelope construction, verification, and validation core compiles to WASM via `wasm-bindgen`, so the browser demo runs the same verifier as the native endpoint. One verifier, every platform.
- **Ecosystem is sufficient** (verified August 2026): `ed25519-dalek` (signatures, audited), `ssi` (SpruceID, actively maintained, did:key + did:web), `jsonschema` (draft 2020-12, consumes the existing schema files directly), `ulid`, `tokio` + `tokio-tungstenite` / `axum` (ws/1.0 client and relay), `webrtc-rs` (Phase 2 native media).
- **Accepted cost:** slower iteration than Python/TS. Mitigated by keeping vector *generation* in the existing Python tooling (§5.1) — Python sketches fast, Rust proves rigorously, and a vector bug and an implementation bug cannot hide behind each other.

---

## 3. Repository Layout

The PoC lives in the existing DSIP spec repo, in a top-level `impl/` directory beside the version folders — **not** inside `v0.6/`. The version folders hold document snapshots (v0.5 frozen, v0.6 superseding it); the PoC is a living codebase that tracks successive spec versions rather than belonging to one. Placing it under `v0.6/` would force either a workspace move or a parallel fork when v0.7 lands. The binding between code and spec version is explicit, not positional: this plan's "Tracks" header, the `spec_ref` field on every test vector, and a git tag (`poc-v0.6`, then `poc-v0.7`, …) cut whenever the implementation is fully conformant to a spec version — giving the code the same snapshot property the version folders give the documents.

Keeping the implementation in the spec repo (rather than a separate `dsip-rs` repo) is deliberate at this stage: the spec feedback loop (§11) frequently pairs a spec edit with a vector change, and a single repo lets both land in one atomic commit so the normative sentence and the vector enforcing it cannot drift apart. Splitting implementations into their own repos is the eventual end state if third-party implementations emerge; it is easy to do later and pure overhead now. `impl/` (rather than a Cargo workspace at the literal repo root) keeps GitHub presenting the repo as a protocol project instead of a Rust codebase.

```
DSIP/                          # existing spec repo root
├── v0.5/                      # frozen spec snapshot (unchanged)
├── v0.6/                      # current spec + schema set (unchanged)
└── impl/                      # PoC Cargo workspace, crates in dependency order
    ├── vectors/               # Language-neutral JSON test vectors (Workstream 0)
    │   ├── envelope/          # Signature, replay, ULID/issued_at consistency
    │   ├── payload/           # Schema pass/fail per message type
    │   ├── semantic/          # The 11 post-schema semantic checks
    │   ├── state/             # Scripted state-machine traces
    │   ├── transport/         # hello handshake, splicing, size caps
    │   └── dht/               # Reachability hint records (§10.3, stateless)
    ├── tools/                 # Python: vector generator; imports the v0.6 schema tooling
    ├── crates/
    │   ├── dsip-core/         # Identifiers, DIDs, keys, envelope, sign/verify
    │   ├── dsip-schema/       # Embedded schemas + stateless semantic checks
    │   ├── dsip-session/      # §12 state machine, timers, races, renegotiation
    │   ├── dsip-transport/    # §13.2 ws/1.0 binding, hello, reconnection
    │   ├── dsip-dht/          # §8.5 DHT reachability hints (Workstream D, §10)
    │   ├── dsip-relay/        # Relay binary: P1 loopback → P2 forking + SnF
    │   ├── dsip-cli/          # keygen, resolve, call, answer, vector runner
    │   └── dsip-wasm/         # (Phase 2) wasm-bindgen exposure of the verifier
    └── demos/                 # (Phase 2+) browser client, broadcast UI
```

The schema files remain canonical in `v0.6/` (and successor folders); `dsip-schema` embeds them from the current spec folder at build time, and the build-script freshness check (§6, WS-2) fails the build if the embedded copies drift from the generator's output. When v0.7 lands, repointing that one path is the whole migration for the schema layer.

Crate boundaries follow verification order: `dsip-core` never depends on schema or session logic; `dsip-session` consumes verified, schema-valid payloads only. A message that reaches the state machine has already passed signature, replay, and shape checks — mirroring §10.2's verify-then-decode ordering.

---

## 4. Documentation Standard

The PoC is a *reference* implementation: its documentation is part of the deliverable, not an afterthought. The standard has one organizing principle — **spec traceability** — and it is enforced, not aspirational.

### 4.1 Spec-traceable comments

Every module, public type, and public function that implements normative behavior carries a rustdoc comment citing the v0.6 section it implements, using a consistent `Spec:` line so citations are grep-able:

```rust
/// DID method support for DSIP Core v1.0.
///
/// Spec: §7.2 DID Usage
///
/// v1.0 keeps the required method set small: `did:key` for self-certifying
/// identities, test endpoints, ephemeral users, and devices; `did:web` for
/// organizations, broadcasters, domains, gateways, and service providers.
/// Other methods are extension territory and are deliberately absent here.
pub enum DidMethod { Key, Web }
```

Inline comments do the same at the branch level wherever a line of code exists *because* the spec says so — timer bounds, reason-token choices, race resolutions:

```rust
// Spec §12.6: lexicographically smaller ULID wins glare; the loser
// rejects with `session.glare` and proceeds as responder.
if outbound_id < inbound_id { ... }
```

### 4.2 Implementation-note comments

Where the code makes a choice the spec leaves open, or resolves an ambiguity, the comment says so explicitly and distinguishes normative citation from implementation decision — `Spec:` for the former, `Impl:` for the latter:

```rust
/// Key material for a DSIP endpoint.
///
/// Spec: §7.3 Identity Keys vs Device Keys
///
/// DSIP separates the identity controller key (controls the DID), device
/// keys (sign session messages per device), recovery keys (rotation and
/// regain-control after loss), and delegation credentials (authorize
/// devices, agents, gateways, or services to act for an identity). The
/// separation exists so multi-device use never requires sharing one
/// private key across devices.
///
/// Impl: recovery keys are represented but not exercised in Phase 1 —
/// §7.6 recovery models are out of PoC scope; the type exists so the
/// delegation-verification path (§7.4) is honest about what it checks.
pub struct EndpointKeys { ... }
```

Every `Impl:` note that resolves a genuine spec ambiguity must also have a corresponding `spec-gap` issue (§11) — the comment records the local choice; the issue drives the spec fix. Neither substitutes for the other.

### 4.3 Enforcement and artifacts

- `#![deny(missing_docs)]` on every library crate: public items without doc comments fail the build.
- CI runs a trivial lint (grep-level) asserting every `crates/*/src/**` module header contains at least one `Spec:` citation; modules with none must carry `Spec: none (infrastructure)` so the exemption is deliberate and visible.
- `cargo doc` output is the API reference; the vector suite's `spec_ref` fields plus the `Spec:` comment lines together form a coverage cross-index — a small `tools/` script emits a table of spec sections → implementing modules → covering vectors, which doubles as the conformance status page and makes unimplemented sections visible rather than silently absent.
- Each crate's `lib.rs` opens with a crate-level doc comment stating which spec sections the crate owns, mirroring the layout table in §3.

---

## 5. Workstream 0 — Test Vector Suite

**This is the first deliverable and the highest-leverage artifact.** The schema README lists it as the next artifact; §25.1 requires the state machine to be "driven by the test vector suite."

### 5.1 Tooling

Vectors are generated by extending the existing Python tooling (`generate_schemas.py` sibling), which already encodes the shared definitions. Deterministic keys (fixed seeds) so signed envelopes are byte-reproducible. Every vector carries: `description`, `spec_ref` (section number), `expect` (accept/reject + reason token where applicable).

### 5.2 Coverage map

**Envelope vectors** (§10.2, §12.9): valid Ed25519 signature; tampered payload; wrong `kid`; `kid` resolving to a non-delegated key; `issued_at` outside the 300 s replay window; duplicate `id` within window; ULID timestamp component inconsistent with signed `issued_at` (glare-backdating guardrail, §20.6).

**Payload vectors**: reuse and extend the 29-case harness — every schema gets at least one accept and one reject; prose-style illustrative ids (`01HZINVITEABC`) pinned as failures.

**Semantic vectors** — one cluster per check in the schema README's list of 11: expiry ordering and replay window; delegation resolution including `on_behalf_of` on `hello`; unknown-session and invalid-state rejections; registry membership with category fallback for unknown-but-well-formed reason tokens; single outstanding `update` across both directions; relay `hello` `in_reply_to` anti-splicing; 65,536-byte encoded envelope cap; answer/reject selections as subsets of the referenced offer; wire-format rules (UTF-8, no floats, integer timestamps); `info` ACTIVE-only; introduction 4,096-byte cap and grant referencing a real introduction; per-event `expires_in` caps (presence 3,600 s).

**State traces** — scripted event sequences (`local` and `recv` events with mock-clock advances) with expected state and expected emissions after each step. Minimum trace set, each mapped to its spec section:

| Trace | Spec |
|---|---|
| Happy path: invite → progress → answer → active → bye, both roles | §12.4 |
| Cancel/answer race, all three resolutions (incl. initiator `bye` reason `session.cancelled` after own cancel) | §12.5 |
| Glare: smaller-ULID wins; pathological equal-id double-reject with 1–4 s retry | §12.6 |
| Forking: first answer wins; `cancel` reason `session.answered-elsewhere`; late answer gets `bye` reason `session.already-answered`; no missed-call on answered-elsewhere cancel | §12.7 |
| Attempt outcome: relay forwards most-informative reject when all legs terminate (`user.declined` > `user.no-answer` > `endpoint.busy` > `endpoint.unavailable`) | §12.7 rule 6 |
| Renegotiation: update/answer via `in_reply_to`; RENEGOTIATING sub-state; update glare via ULID rule; `session.update-pending` violation; rejected update preserves prior state; `bye` beats pending update | §12.8 |
| Timer expiries: T-Establish, T-Ring (with `ring_timeout` extension honored up to bound), T-Queue replace/restart, T-Ring-Local, invite `expires_at` pre-alerting vs T-Ring post-alerting | §12.9 |
| Screening: `answered_by: "service"` then escalation update | §14.3–14.4 |

**Transport vectors** (§13.2): client/relay `hello` conditional forms; `in_reply_to` mismatch (splice attack) rejection; `max_envelope_bytes` constant; oversize envelope rejection; reconnection sequence.

**DHT hint-record vectors** (§8.3, §10.3): valid reachability hint; tampered; non-delegated signer; expired; seq conflict in both orders; same-key live-conflict warn/fail case. (DHT *network* behavior is integration-tested on a local testnet, not vector-tested — see §10.3.)

### 5.3 Exit criteria

Vector runner in `dsip-cli` executes the full suite; Python harness and Rust runner agree on every verdict (parity check); every §12.4–§12.10 transition row is covered by at least one trace step.

---

## 6. Phase 1 — Core (§25.1)

### WS-1: `dsip-core`

- ULID generation/parsing with timestamp extraction (for the §12.6/§20.6 checks).
- `did:key` native (multibase Ed25519 — small enough to own outright); `did:web` resolution behind a `DidResolver` trait with the `ssi` crate as the default backend, isolated so crate churn can't leak into the API.
- Device delegation model (§7.4): identity keys vs device keys, delegation verification, `on_behalf_of`.
- DSIP-JOSE envelope: construct, sign (Ed25519), verify with `kid`→DID resolution; payload held as bytes through verification.
- Wire-format enforcement at parse (§10.3): UTF-8, integer timestamps, float rejection.
- Version block handling and §11 negotiation rules, including version error emission.

**Exit:** all envelope and wire-format vectors pass; keygen + sign + verify round-trip in CLI.

### WS-2: `dsip-schema`

- Schemas embedded at build time from the v0.6 set (`include_str!` + build-script freshness check against `generate_schemas.py` output).
- Validation via the `jsonschema` crate; `message.schema.json` dispatch handled natively (match on `type`) rather than through cross-file `$ref` resolution.
- Stateless semantic checks (expiry ordering, ULID consistency, registry shape/membership split, subset rules) as a typed check pipeline with reason-token outputs.

**Exit:** payload and stateless semantic vectors pass; Rust/Python parity on the 29-case harness.

### WS-3: `dsip-session`

- Initiator and responder state machines as typestate: states from §12.4, transitions as consuming functions returning `(NewState, Vec<Emission>)`.
- Sub-state RENEGOTIATING with the one-outstanding-update invariant enforced structurally.
- Race handling: cancel/answer (§12.5), glare by ULID comparison (§12.6), update glare (§12.8.3).
- Forked-answer handling on the initiator side (first-accept, answered-elsewhere cancel, late-answer bye) — driven entirely by vectors in P1, no relay required.
- Timer engine over `tokio::time` with pausable clock; all six §12.9 timers with their bounds and interactions (T-Queue replacing T-Ring, `ring_timeout` extension, expires_at-vs-T-Ring handoff at ALERTING).

**Exit:** every state trace passes; property test (proptest) fuzzing random event orderings never panics and never produces an emission sequence violating the §12.5 invariant ("cancel is authoritative for the initiator's intent").

### WS-4: `dsip-transport`

- `ws/1.0` client binding: wss connect, client `hello`, capability exchange, verified relay `hello` with the `in_reply_to` anti-splicing check, reconnection with session continuity.
- 65,536-byte encoded envelope cap enforced on send and receive.
- `dsip-relay` P1 form: single-connection loopback/echo relay sufficient to run two CLI endpoints against each other. (Forking, leg tracking, and store-and-forward are Phase 2 — but the relay's leg-state data model is designed now so P2 is additive.)

**Exit:** transport vectors pass; two `dsip-cli` instances complete a full invite→answer→bye flow over a live wss connection through the loopback relay.

### WS-5: `dsip-cli`

Subcommands: `keygen`, `resolve <did|alias>`, `call`, `answer` (interactive accept/decline/screen), `vectors run`. Media negotiation at this phase is structural (offer/answer of declared capabilities) — no actual media until Phase 2.

**Phase 1 demo:** two terminals, two generated `did:key` identities, a signed call placed, screened, answered, renegotiated (add a capability via `update`), and hung up — every envelope verified, every transition logged with its spec section.

---

## 7. Phase 2 — Interactive Media (§25.2)

- **`dsip-wasm`:** envelope verify + schema/semantic validation compiled to WASM; browser demo uses it directly.
- **Browser demo:** WebRTC media binding (DTLS-SRTP), ICE candidates in signed `update` envelopes per §26; identity verification display, policy display, unknown-identity warning.
- **Native endpoint:** `webrtc-rs`-based CLI/native answerer for audio, so browser↔native calls work.
- **Screening demo:** `answered_by: "service"` flow with escalation update (§14.4).
- **First contact:** introduction/grant flow (§19.4) with contact allowlist; anti-enumeration uniform rejects; 4,096-byte introduction cap.
- **`dsip-relay` full form:** forking with per-leg tracking, per-leg cancel delivery, attempt-outcome signaling with most-informative-reason selection, store-and-forward within the offline delivery boundary (§13.3).

**Phase 2 demo:** browser calls a two-device identity; both devices ring; one answers; the other silently stops (no missed call); mid-call video escalation via `update`.

**Phase 2 risk:** `webrtc-rs` maturity is the least-proven dependency in the plan. Fallback: browser↔browser demo only, with the native endpoint doing signaling + identity but delegating media to a headless browser shell.

---

## 8. Phase 3 — Verified Broadcast (§25.3, §22)

- Publication record generator and signed-publication verifier (`publish`/`unpublish`).
- Subscription flow (`subscribe`/`notify` per §9.3 semantics: mandatory events + `expires_in`, seq-ordered notifies, terminal state, presence 3,600 s cap).
- HLS/WebRTC variant advertisement; receiver selects a compatible variant.
- CDN/relay provenance PoC: `derivative-bound` signed provenance statement, receiver displays publisher + delivery path.
- Basic publisher and receiver UI.

**Phase 3 demo:** a broadcaster identity (`did:web`) publishes a signed stream record; a receiver resolves an alias, verifies publisher and policy, subscribes, and displays provenance through a transcoding relay.

---

## 9. Phase 4 — SIP/WebRTC Gateway (§25.4)

DSIP→SIP INVITE gateway, SDP mapping, RTP/SRTP bridge, §15.5 reason-code mapping, trust downgrade indicator, optional STIR/PASSporT/RCD mapping research. Scoped as a separate follow-on plan once Phases 1–2 are stable; it has the largest external-dependency surface and the least spec-proving value per unit effort.

---

## 10. Workstream D — DHT Reachability Hints (Parallel Track)

DHT discovery is in the PoC as a first-class workstream. Rationale: the protocol's decentralization claim needs demonstration, not prose — without a DHT, PoC discovery is `did:web` (DNS + Web PKI, which §8.4 concedes is not decentralized) and `did:key` (no discovery at all). The DHT track is also the only way to generate real data on the §8.5 risk list. It runs in parallel: `dsip-dht` depends only on `dsip-core` (envelope + DID), not on session or transport, so it starts once WS-1 lands and demos alongside Phase 2.

### 10.1 What it is — and is not

The §8.1/§8.3 authority rules are load-bearing and non-negotiable in this implementation:

- The DHT distributes **signed, expiring reachability hint records**. It is **never authoritative**: a DHT record can suggest where an identity is reachable; only the DID document (or its delegated keys) can prove it. Discovery resolution order remains exactly §8.1 — the DHT sits in the hints tier of the `DidResolver` trait.
- A hint record is a standard DSIP-JOSE envelope (reusing WS-1 machinery) whose payload carries: the subject DID, current relay/service endpoint hints, `seq`, `issued_at`, `expires_at`.
- DHT key: multihash of the normalized DID. Value: the signed envelope.
- Retrieval verification applies the §8.3 conflict rules mechanically: signature valid against the DID's keys (or a valid delegation) → signed beats unsigned; higher `seq` beats lower; expired records are invalid; conflicting live records from the same key trigger the profile's warn/fail behavior.
- **The `did:key` path is the flagship demo**: a self-certifying identity means the hint record verifies against the key embedded in the DID itself — zero external resolution anywhere in the discovery path. This is the fully decentralized route through the whole stack and the demo that earns the protocol's name.

### 10.2 Implementation

- `dsip-dht` crate over `rust-libp2p` Kademlia; a `dsip-dht-node` binary that any native endpoint or relay can run.
- Record publication is a signed operation by the identity's device keys under §7.4 delegation rules; republish before expiry; `seq` monotonic per key.
- Browser asymmetry, by design: browsers do not join the DHT; they query through their relay, which participates. Documented as a finding, not hidden.
- Bootstrap nodes are configuration, and are themselves a centralization point — measured and documented honestly rather than waved away.

### 10.3 Vectors and testing

- **Record vectors** (stateless, in the §5 suite): valid hint record; tampered; wrong key; non-delegated signer; expired; seq conflict resolution (both orders); same-key live-conflict case.
- **Network behavior** is not vector-testable; a `tools/` harness spins a local multi-node testnet (5–20 nodes) for integration tests: publish/resolve round-trip, expiry lapse, republish, node churn, and a basic poisoning attempt (unsigned/mis-signed record injected → verified-rejection path).

### 10.4 Deliverables

1. Working publish/resolve of verified reachability hints on a local testnet, wired into `dsip-cli resolve` as the hints tier (clearly labeled in output as hint-sourced vs authoritative).
2. **Demo:** two `did:key` endpoints on separate networks discover each other's relay endpoints via the DHT and complete a signed call — no DNS, no Web PKI, no directory.
3. **Findings report** against the §8.5 risk list: Sybil/eclipse exposure surface, poisoning behavior observed, availability under churn, bootstrap centralization measurements.
4. **Draft DHT Hints Profile** for the spec feedback loop (§11): record format, key derivation, TTL and republish rules, seq semantics, bootstrap considerations — candidate text for promoting §8.5 beyond "experimental" in v0.7 if the data supports it.

### 10.5 Scope guardrails

No global reputation, no Sybil *solution* (out of scope per §3.2 — instrumented, not solved), no DHT-stored presence beyond reachability hints (presence privacy per §9.2 stays out of the DHT), and no change to the authority order under any circumstance. If the experiment shows hints can't be made trustworthy enough to be useful, that negative result goes in the findings report and the spec keeps §8.5 conservative — a legitimate outcome, not a failure.

---

## 11. Spec Feedback Loop

Issues to file against v0.6 immediately (already flagged in the schema README):

1. §15.3 codec example uses bare strings; §14.2 defines objects. Schemas resolved in favor of §14.2 — update §15.3 prose.
2. `$id` base URI `https://dsip.org/schema/1.0/` is a placeholder pending §24 registry governance.
3. Illustrative ids in prose (`01HZINVITEABC`) are not valid ULIDs — replace with real ULIDs so examples are copy-safe.

Ongoing: every implementation-blocking ambiguity gets a repo issue tagged `spec-gap` with the section number, the choices considered, and the choice the PoC made. These become the v0.7 worklist.

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `ssi` crate API churn | Core DID resolution breaks | Pin version; isolate behind `DidResolver` trait; `did:key` implemented natively |
| `jsonschema` crate 2020-12 edge cases | Silent validation divergence | Rust/Python parity check on every vector run in CI |
| `webrtc-rs` maturity (Phase 2) | Native media endpoint slips | Browser-first media demo; native endpoint does signaling-only fallback |
| `rust-libp2p` learning curve (WS-D) | DHT track absorbs disproportionate time | Parallel track — never blocks Phases 1–3; scope guardrails in §10.5; timeboxed to a findings report if publish/resolve proves harder than planned |
| DHT hints prove untrustworthy in practice | Decentralized-discovery demo weakens | Negative result is a planned deliverable (§10.5): findings report keeps §8.5 conservative with data instead of speculation |
| Spec drift v0.6 → v0.7 | Rework | Vectors are the compatibility contract; diff lands in vectors first |
| Timer/race logic subtly wrong | Undermines the spec's core claim | Vector traces per transition row + property tests on event orderings |
| Solo-project scope creep | Phases stall | Each workstream has a hard exit criterion; nothing starts before WS-0 vectors exist for it |

---

## 13. Milestone Summary

| Milestone | Contents | Demo |
|---|---|---|
| **M0** | Vector suite v1 (envelope, payload, semantic, state, transport) + Rust/Python parity harness | `vectors run` green in both languages |
| **M1** | Phase 1 complete (WS-1…WS-5) | Two-terminal signed call over wss with screening + renegotiation |
| **M2** | Phase 2 complete | Browser↔native call, forked ringing, first-contact flow |
| **MD** | Workstream D complete (parallel; targets M2 timeframe) | Two `did:key` endpoints discover each other via DHT and complete a signed call — no DNS, no Web PKI; findings report + draft DHT Hints Profile delivered |
| **M3** | Phase 3 complete | Verified broadcast with provenance display |
| **M4** | Gateway plan drafted | — |
