# DSIP v0.11 — in progress (draft)

v0.11 is the current revision, assembled from v0.10 at tag `poc-v0.10`; `../v0.10/` is frozen. Appendix A.8 of
`dsip_v_0_11_decentralized_session_initiation_protocol.md` lists what v0.11 changes, as each item lands.

| document | what | status |
|---|---|---|
| `dsip_v_0_11_decentralized_session_initiation_protocol.md` | DSIP core | draft v0.11 (v0.10 text + A.8) |
| `dsip-schemas-v0.11-draft/` | Core JSON Schema set | generated; unchanged from v0.10 so far |
| `dsip-webrtc-media-binding-v0.11.md` | WebRTC Media Binding 1.0 | normative |
| `dsip-gateway-profile-v0.11.md` | Gateway Profile 1.0 | normative |
| `dsip-messaging-profile-v0.11.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated |
| `dsip-rtp-srtp-media-binding-v0.11-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.11-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.11-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft, stage 1 |
| `dsip-device-events-profile-v0.11-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.11-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |

No wire-format change so far: `dsip.core` stays `1.0`. Rule 7 of `CLAUDE.md` applies: each change lands as vectors
first, then the three implementations, and `poc-v0.11` is tagged when all three agree on the v0.11 suite.
