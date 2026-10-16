# DSIP v0.16 — final

v0.16 is final at tag `poc-v0.16`. It was assembled from v0.15 at tag `poc-v0.15`, and `../v0.15/` is frozen. Appendix A.13 of
`dsip_v_0_16_decentralized_session_initiation_protocol.md` lists what v0.16 changes, with its spec-gap numbers
(130–132). The companion drafts (DHT Hints, RTP/SRTP, Alias Transparency, Device Events, Recording, Number Attestation)
stay drafts within the final revision.

| document | what | status |
|---|---|---|
| `dsip_v_0_16_decentralized_session_initiation_protocol.md` | DSIP core | v0.16, final (v0.15 text + A.13): when a leg expires (§12.7 rule 3, spec-gap 132) and what a relay forgets (§13.3, spec-gap 131) |
| `dsip-schemas-v0.16-draft/` | Core JSON Schema set | generated; unchanged |
| `dsip-webrtc-media-binding-v0.16.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.16.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.16.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative; an enrolment can end: release, idle expiry, and `mailbox.not-served` at a full mailbox (M§4.1, M§5.7, spec-gap 130) |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; adds `mailbox-config.release` |
| `dsip-rtp-srtp-media-binding-v0.16-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.16-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.16-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft; stage 1 and the DSIP side of stage 2 (T§7–T§10); proof verification waits for KEYTRANS -06 (T§6) |
| `dsip-device-events-profile-v0.16-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.16-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.16-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |

`dsip.core` stays `1.0`. The wire changes are an optional field of a Messaging Profile message (`release`) and a
pair of reason tokens in the Messaging Profile registry. The core changes are relay behaviour only: a relay now says
when a silent leg has expired (`transport.no-response`, already registered) and may forget what nothing can still need.
The suite has 2,130 vectors, on which the Python harness, the
Rust reference implementation and the independent TypeScript implementation agree.
