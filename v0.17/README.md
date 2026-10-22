# DSIP v0.17 — in progress

v0.17 was assembled from v0.16 at tag `poc-v0.16`, and `../v0.16/` is frozen. Appendix A.14 of
`dsip_v_0_17_decentralized_session_initiation_protocol.md` lists what v0.17 changes, with its spec-gap numbers.
The companion drafts (DHT Hints, RTP/SRTP, Alias Transparency, Device Events, Recording, Number Attestation) stay
drafts, and the Presence Profile is new.

| document | what | status |
|---|---|---|
| `dsip_v_0_17_decentralized_session_initiation_protocol.md` | DSIP core | v0.16 text + A.14: the `presence` message and its record's `device` (§9.4), its age (§12.9), the `presence` reason category (§15) |
| `dsip-schemas-v0.17-draft/` | Core JSON Schema set | generated; adds `presence` |
| `dsip-webrtc-media-binding-v0.17.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.17.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.17.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative, unchanged |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v0.17-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.17-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.17-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft; stage 1 and the DSIP side of stage 2 (T§7–T§10); proof verification waits for KEYTRANS -06 (T§6) |
| `dsip-device-events-profile-v0.17-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.17-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.17-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |
| `dsip-presence-profile-v0.17-draft.md` | Presence Profile (`presence/0.1`), cited `P§n` | draft; P§3–P§5 and P§8 pinned by vectors (spec-gaps 134–137); audiences (P§6) and shares (P§7) not yet |

`dsip.core` stays `1.0`.
