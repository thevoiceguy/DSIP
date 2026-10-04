# DSIP v0.8

v0.8 is the current revision. `dsip_v_0_8_decentralized_session_initiation_protocol.md` states what the core says
differently from v0.7 (Appendix A.5): the dispositions of the spec-gaps that touch the core (23–100), and the
companion documents below. v0.7 (`../v0.7/`, tag `poc-v0.7`) is frozen. No wire-format change: `dsip.core` stays
`1.0`; the one addition on the wire, sealed bodies, is an extension (`sealed-body/1.0`, §10.4).

| document | what | status | conformance |
|---|---|---|---|
| `dsip_v_0_8_decentralized_session_initiation_protocol.md` | DSIP core | v0.8 | the core categories of `impl/vectors/` |
| `dsip-schemas-v0.8-draft/` | Core JSON Schema set v0.8 (adds `introduction.sealed`, `delegation-revocation`, hint `endpoints[].service`) | generated from `generate_schemas.py`; 47 samples | `payload/`, `semantic/` |
| `dsip-webrtc-media-binding-v0.8.md` | WebRTC Media Binding 1.0 (`transport:webrtc`), unchanged from v0.7 | normative | `media-binding/` (42) |
| `dsip-gateway-profile-v0.8.md` | Gateway Profile 1.0 — DSIP ↔ SIP/PSTN | normative | `gateway/` (66) |
| `dsip-messaging-profile-v0.8.md` | Messaging Profile 1.0 and Mailbox 1.0 (`messaging/1.0`) — mailboxes, MLS end-to-end encryption with per-group hubs, groups, multi-device history, receipts, activity, voicemail, blobs, first contact | normative | `messaging/` (457) |
| `dsip-messaging-schemas-draft/` | The Messaging Profile's schema set (profile messages and content objects) | generated from `generate_schemas.py` | `messaging/` |
| `dsip-rtp-srtp-media-binding-v0.8-draft.md` | RTP/SRTP Media Binding (`transport:rtp`) | draft (no binding implementation yet) | SDP mapping in `gateway/` |
| `dsip-dht-hints-profile-v0.8-draft.md` | DHT Reachability Hints Profile (`dht-hints/0.1`), with `endpoints[].service` | draft | `dht/` (18) |

The spec-gap dispositions are in `../impl/docs/spec-gaps.md`: worklists for gaps 23–30 and 31–57; profile errata
58–72; 73–81 are findings of the second implementation, 82–84 of the differential fuzzer; 85–100 later findings of
the implementations, the fuzzer and the WAN testbed (96), and three design decisions: sealed bodies (97), storage
limits (99) and relay service scope (100). Each is marked in place with its number; Appendix A.5 lists the core's,
Appendix M-B the Messaging Profile's. Spec-gap 26 (DTMF carriage) is closed by spec-gap 70: `media:dtmf` in
`dsip-info-about` (§12.12, G§9).

Two companions stay drafts: the RTP/SRTP Media Binding has no binding implementation yet (only the gateway's SDP
mapping), and the DHT Reachability Hints Profile is a hints tier by design (§8.1). The two schema folders keep their
`-draft` names because the build embeds them from those paths; their contents are the v0.8 schemas.

**Conformance.** Rule 7 of `CLAUDE.md` applied: every v0.8 behavioural change landed as a vector change first, then
code. The suite is 979 vectors; the Python harness, the Rust reference implementation (`../impl/`) and the
independent TypeScript implementation (`../impl-ts/`, written from this text, the schemas and the vectors README
alone) agree on every one. Tags: `poc-v0.8` is the first v0.8 suite (737 vectors, Rust/Python); `poc-v0.8.1` is this
text.
