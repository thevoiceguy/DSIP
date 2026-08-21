# CLAUDE.md — DSIP Repository

## What this project is

DSIP (Decentralized Session Initiation Protocol) is an identity-first signaling
and media negotiation protocol for trusted real-time sessions. This repo holds
both the **specification** (versioned document snapshots) and the **reference
implementation PoC** (a living Rust codebase that tracks spec versions).

The PoC's purpose, in priority order:
1. **Prove the spec is implementable.** Every MUST is implemented or generates a filed spec issue.
2. **Produce a conformance contract.** The language-neutral test vector suite is the artifact second implementations are measured against. The vectors outlive the Rust code.
3. **Demo the story.** Each phase ends in something demonstrable.

Full plan: `impl/docs/dsip_poc_dev_plan.md`. Read it before large changes.

## Repository map

```
v0.5/, v0.6/, v0.7/  Spec snapshots. v0.7 is current (in assembly). NEVER edit v0.5 or v0.6.
v0.7/dsip-schemas…  Canonical JSON Schemas (draft 2020-12) + generate_schemas.py
impl/               PoC Cargo workspace (living code; tracks spec versions via
                    git tags poc-v0.6, poc-v0.7, …, never via folder placement)
impl/vectors/       Language-neutral JSON test vectors (envelope/ payload/
                    semantic/ state/ transport/ dht/ broadcast/ media-binding/)
impl/tools/         Python: vector generator, parity harness, testnet harness
impl/crates/        dsip-core, dsip-schema, dsip-session, dsip-endpoint, dsip-transport,
                    dsip-media, dsip-webrtc-binding, dsip-broadcast, dsip-dht, dsip-relay,
                    dsip-cli, dsip-wasm
impl/demos/         Browser client, broadcast UI (Phase 2+)
```

Crate dependency order mirrors verification order: core → schema → session.
A message reaching `dsip-session` has already passed signature, replay, and
shape checks. Never invert this.

## Non-negotiable engineering rules

1. **Vectors before code.** No stateful behavior (state machine transition,
   timer, race resolution) ships without a vector or trace exercising it.
   When implementing new behavior: write/generate the vector first in
   `impl/tools/`, confirm the Python harness verdict, then implement in Rust
   until the runner agrees.

2. **Rust/Python parity is CI-enforced.** Every vector must produce the same
   verdict from the Python harness and the Rust runner. If they disagree,
   stop and find out why before proceeding — a divergence is either a vector
   bug or an implementation bug, and it must be identified, never papered over.

3. **Signature over bytes.** The base64url payload is carried as raw bytes
   through signature verification and only then decoded to JSON (spec §10.2).
   Never re-serialize on the verify path. Never "canonicalize."

4. **Authority order (spec §8.1) is untouchable.** DID document > alias
   resolution > cache > hints. The DHT is a hints tier ONLY — signed, expiring
   reachability records verified against the DID before use. No code path may
   treat a DHT record, cache entry, or relay claim as authoritative.

5. **Schemas are canonical in the spec folder.** Edit
   `v0.7/…/generate_schemas.py`, never the generated schema files.
   `dsip-schema` embeds schemas from the current spec folder at build time;
   the freshness check fails the build on drift. Regenerate after edits.

6. **Wire format rules at parse (spec §10.3):** UTF-8 only, integer
   timestamps, reject floats. Enforced in `dsip-core` parsing, tested by
   vectors.

7. **Spec version drift lands in vectors first.** When a new spec version
   arrives, express the diff as vector changes, then change code until green.

## Documentation standard (enforced)

- Every module, public type, and public function implementing normative
  behavior carries a rustdoc comment with a `Spec:` line citing the v0.7
  section (e.g. `Spec: §12.6`). Grep-able, consistent format.
- Where code resolves a choice the spec leaves open, add an `Impl:` line
  explaining the decision. `Spec:` = citation, `Impl:` = decision. Never mix.
- Every `Impl:` note resolving a genuine ambiguity requires a matching
  `spec-gap` issue (section number, choices considered, choice made). The
  comment records the local decision; the issue drives the spec fix.
- Branch-level inline comments cite the spec where a line exists *because*
  the spec says so (timer bounds, reason tokens, race resolutions).
- `#![deny(missing_docs)]` on all library crates — undocumented public items
  fail the build.
- Modules with no normative content must carry `Spec: none (infrastructure)`.
- Crate `lib.rs` opens with a doc comment stating which spec sections the
  crate owns.

## Common commands

```bash
# Schemas: regenerate after editing the generator, then sanity-check
python3 v0.7/dsip-schemas-v0.7-draft/dsip-schemas/generate_schemas.py v0.7/dsip-schemas-v0.7-draft/dsip-schemas/schemas
python3 v0.7/dsip-schemas-v0.7-draft/dsip-schemas/validate_samples.py

# Vectors: regenerate + Python verdicts
python3 impl/tools/generate_vectors.py
python3 impl/tools/run_vectors.py            # Python side of parity

# Rust: build, test, vector runner (Rust side of parity), docs
cargo build --workspace                       # run from impl/
cargo test --workspace
cargo run -p dsip-cli -- vectors run
cargo doc --workspace --no-deps

# DHT local testnet (integration, not vectors)
python3 impl/tools/dht_testnet.py --nodes 5
```

pip installs in this environment need `--break-system-packages`.

## Key spec sections (v0.7; numbering unchanged from v0.6) you will cite constantly

| Section | Topic |
|---|---|
| §7.3–7.5 | Identity vs device keys, delegation, rotation |
| §8.1–8.5 | Discovery authority order, conflict rules, DHT status |
| §9.3 | Presence subscription protocol (subscribe/notify) |
| §10.2–10.3 | Envelope signature semantics, payload rules |
| §12.4–12.10 | State machine, cancel/answer race, glare, forking, renegotiation, timers |
| §13.2 | ws/1.0 binding, hello, anti-splicing, 65,536-byte cap |
| §14.3–14.4 | answered_by, screening pattern |
| §15 | Reason codes: `category.condition`, category fallback |
| §19.4 | First contact: introduction/grant |
| §22 | Verified Broadcast profile |
| B§2–B§8 | WebRTC Media Binding 1.0 (`v0.7/dsip-webrtc-media-binding-v0.7.md`) — cite as `B§n` |

## Semantic checks (post-schema, must-implement)

The 11 checks in the schema README are the authoritative list. Highlights that
recur in reviews: 300 s replay window + `expires_at` > `issued_at`; ULID
timestamp consistent with `issued_at` (glare-backdating guard); one
outstanding `update` per session across both directions; relay `hello`
`in_reply_to` anti-splicing; answer/reject selections ⊆ referenced offer;
registry *shape* in schema vs *membership* in registries with category
fallback for unknown tokens.

## Things Claude should NOT do

- Do not edit generated schema files, anything in `v0.5/`, or renumber spec
  sections without an explicit request.
- Do not resolve a spec ambiguity silently — implement a choice only alongside
  an `Impl:` comment and a `spec-gap` issue.
- Do not weaken a vector to make an implementation pass. If a vector looks
  wrong, flag it; the vector suite is the contract.
- Do not introduce closed enums for registry-governed values (`answered_by`,
  `progress.status`, reason tokens) — registries grow; use shape validation
  plus membership checks with fallback.
- Do not add DHT authority, DHT-stored presence, or Sybil "solutions" —
  instrumented, not solved (§3.2, plan §10.5).
- Do not treat prose example ids like `01HZINVITEABC` as valid ULIDs; they
  fail validation by design.
- Do not begin gateway (Phase 4) work; it is a follow-on plan.

## Workflow expectations

- Section-renumbering or cross-reference edits in any document: map every
  internal reference first, then apply exact unique-string replacements
  (assert uniqueness), descending order — never blind pattern replacement.
  Internal doc §refs and spec §refs overlap numerically; verify which is which.
- Multi-stage document edits: verify intermediate state before the next stage;
  never overwrite a partially-applied edit set.
- When a task produces a spec finding (ambiguity, inconsistency, missing
  registry entry), end the task by drafting the `spec-gap` issue text.
- Conformance tagging: when the implementation fully passes the suite for a
  spec version, tag `poc-vX.Y` before any next-version changes land.
