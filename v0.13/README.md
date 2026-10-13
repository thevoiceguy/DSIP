# DSIP v0.13 — final

v0.13 is final at tag `poc-v0.13`. It was assembled from v0.12 at tag `poc-v0.12`, and `../v0.12/` is frozen. Appendix
A.10 of `dsip_v_0_13_decentralized_session_initiation_protocol.md` lists what v0.13 changes, with its spec-gap numbers
(119–123). The companion drafts (DHT Hints, RTP/SRTP, Alias Transparency stage 1, Device Events, Recording, Number
Attestation) stay drafts within the final revision.

| document | what | status |
|---|---|---|
| `dsip_v_0_13_decentralized_session_initiation_protocol.md` | DSIP core | v0.13, final (v0.12 text + A.10; Appendix D, call detail records, informative) |
| `dsip-schemas-v0.13-draft/` | Core JSON Schema set | generated; unchanged from v0.12 |
| `dsip-webrtc-media-binding-v0.13.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.13.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.13.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative; the `call-record` object listed (M§8.1, 121); a hub's queues bounded by `mls_retention_s` (M§6.5, spec-gap 119), joining without a sibling is the device's decision (M§6.8, 120), moving to another mailbox (M§4.1, M§5.7, 122) |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; adds `call-record` (C§9) |
| `dsip-rtp-srtp-media-binding-v0.13-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.13-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.13-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft, stage 1; stage 2 waits for KEYTRANS -06 |
| `dsip-device-events-profile-v0.13-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.13-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft; C§9 call records (spec-gap 121), opened by the record-keeper (123) |
| `dsip-number-attestation-profile-v0.13-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |

No core wire-format change: `dsip.core` stays `1.0`. The messaging schema set gains one object (`call-record`), which a
receiver that does not know it ignores (M§8.1). The suite has 2,002 vectors, on which the Python harness, the Rust
reference implementation and the independent TypeScript implementation agree. What a client decides and no message
carries (when a device joins without a sibling, re-registering after a move, holding call records until the
record-keeper opens the conversation) is pinned by the browser client's headless tests (`impl/web/test/`).
