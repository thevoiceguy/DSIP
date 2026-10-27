# DSIP 1.0 — in progress

1.0 is DSIP Core 1.0: the v0.17 text, final at tag `poc-v0.17`, declared normative 1.0. `../v0.17/` is frozen.
Appendix A.15 of `dsip_v_1_0_decentralized_session_initiation_protocol.md` lists what 1.0 changes: no message, field,
rule, schema or vector, and the stability rule for later 1.x revisions (§11.4, spec-gap 163). The companion documents
are carried unchanged, each with its own version; the drafts stay drafts.

| document | what | status |
|---|---|---|
| `dsip_v_1_0_decentralized_session_initiation_protocol.md` | DSIP Core 1.0 | normative 1.0, in progress (v0.17 text + A.15): the stability rule for 1.x (§11.4, spec-gap 163); carried from v0.17: the `presence` message and its record's `device` and sealed form (§9.4), exclusive expiry (§12.9), private presence and its subscriber's binding (§9.3), grants with audiences, keys and successors, `grant-revocation`, admission by grantee (§19.4), `transport.replaced` (§13.2), the `presence` reason category (§15) |
| `dsip-schemas-v1.0/` | Core JSON Schema set 1.0 | generated; unchanged from v0.17 (closed schemas, §11.4) |
| `dsip-webrtc-media-binding-v1.0.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v1.0.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v1.0.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative, unchanged |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v1.0-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v1.0-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v1.0-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft; stage 1 and the DSIP side of stage 2 (T§7–T§10); proof verification waits for KEYTRANS -06 (T§6) |
| `dsip-device-events-profile-v1.0-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v1.0-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v1.0-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |
| `dsip-presence-profile-v1.0-draft.md` | Presence Profile (`presence/0.1`), cited `P§n` | draft; records (P§3–P§5, P§8), audiences (P§6), shares (P§7) and sealed records (P§12, `presence/0.2`) pinned by vectors (spec-gaps 134–162) and run by the CLI and the browser client |

`dsip.core` is `1.0`, as it has been since it was introduced. The suite has 2,323 vectors, unchanged from v0.17,
on which the Python harness, the Rust reference implementation and the independent TypeScript implementation agree.
