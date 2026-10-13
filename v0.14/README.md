# DSIP v0.14 — final

v0.14 is final at tag `poc-v0.14`. It was assembled from v0.13 at tag `poc-v0.13`, and `../v0.13/` is frozen. Appendix
A.11 of `dsip_v_0_14_decentralized_session_initiation_protocol.md` lists what v0.14 changes, with its spec-gap numbers
(124, 125). The companion drafts (DHT Hints, RTP/SRTP, Alias Transparency, Device Events, Recording, Number
Attestation) stay drafts within the final revision.

| document | what | status |
|---|---|---|
| `dsip_v_0_14_decentralized_session_initiation_protocol.md` | DSIP core | v0.14, final (v0.13 text + A.11) |
| `dsip-schemas-v0.14-draft/` | Core JSON Schema set | generated; adds `alias-monitor` (T§8) |
| `dsip-webrtc-media-binding-v0.14.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.14.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.14.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative; leaving a conversation (M§7.3, spec-gap 125) |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v0.14-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.14-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.14-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft; stage 1 and the DSIP side of stage 2 (T§7–T§10, spec-gap 124); proof verification waits for KEYTRANS -06 (T§6) |
| `dsip-device-events-profile-v0.14-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.14-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.14-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |

No change to the core wire format: `dsip.core` stays `1.0`. The core schema set gains one message type,
`alias-monitor`, which a provider receives over HTTPS (T§8) and no session carries. A tree head between peers rides as
an `identity.claims` entry (T§9), which a receiver that does not know it ignores. Leaving uses MLS's own Remove
proposals (M§7.3). The suite has 2,079 vectors, on which the Python harness, the Rust reference implementation and the
independent TypeScript implementation agree. Proof verification for alias transparency waits for KEYTRANS -06 and
goes into a later revision.
