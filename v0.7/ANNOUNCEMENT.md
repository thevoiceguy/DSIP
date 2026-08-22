# DSIP v0.7: a spec revision written from an implementation

DSIP (Decentralized Session Initiation Protocol) is an identity-first signaling and media
negotiation protocol for trusted real-time sessions: DIDs instead of phone numbers, signed
envelopes instead of trusted intermediaries, explicit media and policy negotiation before any
media flows. v0.6 was the first revision we called implementable. v0.7 is the revision that
proves it — or rather, the revision an implementation forced us to write.

## What happened between v0.6 and v0.7

We built the reference implementation against v0.6 with one rule: **every MUST is implemented,
or it becomes a filed gap.** The build went through Phase 1 (core signaling, state machine,
`ws/1.0` relay), Phase 2 (first contact, browser and native WebRTC endpoints, store-and-forward
relay), Phase 3 (Verified Broadcast with provenance), and a parallel DHT reachability-hints
track — and it hit **22 places where two careful implementers would have made different
choices.** Each one became a numbered `spec-gap` recording the conflict, the options, the choice
the implementation made, and a conformance vector pinning that choice.

v0.7 is the transcription of those 22 dispositions. Nothing on the wire changed (`core` stays
`1.0`); what changed is that the text now says what the code had to decide:

- when a crossed `cancel` is a race and when it is an error, and who withdraws the losing invite
  under glare;
- what a relay may call an unknown recipient, and how introductions stay un-enumerable;
- what "a selection is a subset of the offer" means field by field;
- how a verifier obtains a device delegation for an identity that has no DID document to host it;
- what a key rotation record *is*, who signs it, and why `did:key` identities cannot rotate;
- how broadcast integrity is declared and how provenance statements travel;
- and the document v0.6 cited but never wrote: the **WebRTC Media Binding**.

Every item is listed in the spec's Appendix A.4 and in `impl/docs/spec-gaps.md`.

## The conformance suite is the contract

The artifact we care most about is not the Rust code. It is the **language-neutral vector
suite**: 341 JSON vectors across envelope verification, payload schemas, stateless semantics,
the session state machine (every transition row, every race, every timer), the relay, DHT
hints, broadcast, and — new in v0.7 — the WebRTC Media Binding (descriptor/SDP authority rule,
DTLS roles, candidate sequencing, renegotiation, one answer per forked offer).

Two independent runners consume the suite — a Python reference harness and the Rust
implementation — and CI fails if they disagree on a single verdict. Expected outcomes are
hand-authored from the spec, never recorded from an engine. A second implementation in any
language is measured against the same files.

## What the implementation proved about media

The native endpoint runs on two independent WebRTC stacks — our own `forge-media` and
`webrtc-rs` — selectable at runtime, and the suite pairs them in both directions in CI. That
pairing found three interoperability bugs in `forge-media` that its own tests could never see,
because both ends shared the same misunderstanding of the STUN RFCs. A cross-implementation
test is worth more than any amount of self-consistency.

## Where to look

- Specification: `v0.7/dsip_v_0_7_decentralized_session_initiation_protocol.md`
- WebRTC Media Binding 1.0: `v0.7/dsip-webrtc-media-binding-v0.7.md`
- DHT Hints Profile (draft): `v0.7/dsip-dht-hints-profile-v0.7-draft.md`
- JSON Schema set: `v0.7/dsip-schemas-v0.7-draft/`
- Conformance vectors and their contract: `impl/vectors/README.md`
- Reference implementation and demos: `impl/` (tag `poc-v0.7`)

## What is not in v0.7

Not claimed: E2EE signaling confidentiality from relays, the QUIC binding, a solved Sybil
problem for the DHT tier (it is instrumented, not solved), or the SIP/PSTN gateway. Those are
named follow-ons, and the DHT findings report says plainly what the hints tier can and cannot
do.

If you are building real-time communication on identities that no carrier issues, we would
like to hear where this breaks for you. The gaps we found were found by building; the next ones
will be found by someone building something else.
