# DSIP v0.12 — in progress (draft)

v0.12 is the current revision, assembled from v0.11 at tag `poc-v0.11`; `../v0.11/` is frozen. Appendix A.9 of
`dsip_v_0_12_decentralized_session_initiation_protocol.md` lists what v0.12 changes, as each item lands.

| document | what | status |
|---|---|---|
| `dsip_v_0_12_decentralized_session_initiation_protocol.md` | DSIP core | draft v0.12 (v0.11 text + A.9) |
| `dsip-schemas-v0.12-draft/` | Core JSON Schema set | generated; unchanged from v0.11 so far |
| `dsip-webrtc-media-binding-v0.12.md` | WebRTC Media Binding 1.0 | normative |
| `dsip-gateway-profile-v0.12.md` | Gateway Profile 1.0 | normative |
| `dsip-messaging-profile-v0.12.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated |
| `dsip-rtp-srtp-media-binding-v0.12-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.12-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.12-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft, stage 1; v0.12 adds the `tel:` label (T§3); stage 2 waits for KEYTRANS -06 |
| `dsip-device-events-profile-v0.12-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.12-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.12-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; v0.12 adds route 2's serving half (N§6, the authority's `.well-known`); stage 5 needs a pilot partner |

No wire-format change so far: `dsip.core` stays `1.0`. Rule 7 of `CLAUDE.md` applies: each change lands as vectors
first, then the three implementations, and `poc-v0.12` is tagged when all three agree on the v0.12 suite.
