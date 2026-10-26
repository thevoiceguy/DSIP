# DSIP v0.17 — final

v0.17 is final at tag `poc-v0.17`. It was assembled from v0.16 at tag `poc-v0.16`, and `../v0.16/` is frozen.
Appendix A.14 of `dsip_v_0_17_decentralized_session_initiation_protocol.md` lists what v0.17 changes, with its
spec-gap numbers (134–162 except 152–157 counted once, and 138–140 in the Messaging Profile). The companion drafts
(DHT Hints, RTP/SRTP, Alias Transparency, Device Events, Recording, Number Attestation) stay drafts within the final
revision, and the Presence Profile is new, a draft.

| document | what | status |
|---|---|---|
| `dsip_v_0_17_decentralized_session_initiation_protocol.md` | DSIP core | v0.17, final (v0.16 text + A.14): the `presence` message and its record's `device` and sealed form (§9.4), exclusive expiry (§12.9), private presence and its subscriber's binding (§9.3), grants with audiences, keys and successors, `grant-revocation`, admission by grantee (§19.4), `transport.replaced` (§13.2), the `presence` reason category (§15) |
| `dsip-schemas-v0.17-draft/` | Core JSON Schema set | generated; adds `presence` and `grant-revocation`; `grant` gains `presence_audience` and `presence_keys`; `subscribe` and `message` follow |
| `dsip-webrtc-media-binding-v0.17.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.17.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.17.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative; three clarifications in place (M§5.4, M§7.5, M§12.1; spec-gaps 138–140, Appendix M-B) |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v0.17-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.17-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.17-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft; stage 1 and the DSIP side of stage 2 (T§7–T§10); proof verification waits for KEYTRANS -06 (T§6) |
| `dsip-device-events-profile-v0.17-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.17-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.17-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |
| `dsip-presence-profile-v0.17-draft.md` | Presence Profile (`presence/0.1`), cited `P§n` | draft; records (P§3–P§5, P§8), audiences (P§6), shares (P§7) and sealed records (P§12, `presence/0.2`) pinned by vectors (spec-gaps 134–162) and run by the CLI and the browser client |

`dsip.core` stays `1.0`. The wire changes are new messages (`presence`, `grant-revocation`), optional fields of
`grant`, the reason `transport.replaced`, and the `presence` category with the tokens the Presence Profile registers. The suite
has 2,323 vectors, on which the Python harness, the Rust reference implementation and the independent TypeScript
implementation agree.
