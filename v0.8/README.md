# DSIP v0.8 — assembled (draft)

v0.8 is the current revision. `dsip_v_0_8_decentralized_session_initiation_protocol.md` states what the core says
differently from v0.7 (Appendix A.5): the dispositions of spec-gaps 23–57 that touch the core, and the companion
documents below. v0.7 (`../v0.7/`, tag `poc-v0.7`) is frozen. The PoC is tagged `poc-v0.8` once both vector
runners are green on this revision. No wire-format change: `dsip.core` stays `1.0`.

| document | what | status | conformance |
|---|---|---|---|
| `dsip_v_0_8_decentralized_session_initiation_protocol.md` | DSIP core | draft v0.8 | the core categories of `impl/vectors/` |
| `dsip-schemas-v0.8-draft/` | Core JSON Schema set v0.8 (adds `introduction.sealed`, `delegation-revocation`, hint `endpoints[].service`) | generated from `generate_schemas.py`; 47 samples | `payload/`, `semantic/` |
| `dsip-webrtc-media-binding-v0.8.md` | WebRTC Media Binding 1.0 (`transport:webrtc`), unchanged from v0.7 | normative | `media-binding/` (42) |
| `dsip-gateway-profile-v0.8.md` | Gateway Profile 1.0 — DSIP ↔ SIP/PSTN | normative | `gateway/` (66) |
| `dsip-messaging-profile-v0.8.md` | Messaging Profile 1.0 and Mailbox 1.0 (`messaging/1.0`) — mailboxes, MLS end-to-end encryption with per-group hubs, groups, multi-device history, receipts, activity, voicemail, blobs, first contact | normative | `messaging/` (424) and the wire demos in `impl/demos/` |
| `dsip-messaging-schemas-draft/` | The Messaging Profile's schema set (profile messages and content objects) | generated from `generate_schemas.py` | `messaging/` |
| `dsip-rtp-srtp-media-binding-v0.8-draft.md` | RTP/SRTP Media Binding (`transport:rtp`) | draft (no binding implementation yet) | SDP mapping in `gateway/` |
| `dsip-dht-hints-profile-v0.8-draft.md` | DHT Reachability Hints Profile (`dht-hints/0.1`), with `endpoints[].service` | draft | `dht/` (12) |

The spec-gap dispositions are in `../impl/docs/spec-gaps.md` (worklists for gaps 23–30 and 31–57; profile errata
58–72; 73–81 are findings of the second implementation, 82–84 of the differential fuzzer). Spec-gap 26 (DTMF carriage) is closed by spec-gap 70: `media:dtmf` in `dsip-info-about` (§12.12, G§9).

Rule 7 of `CLAUDE.md` applied: every v0.8 behavioural change landed as a vector change first, then code, and
`poc-v0.8` is tagged only when both runners are green on the v0.8 suite (737 vectors).
