# DSIP v0.15 — draft

v0.15 is the current revision. It was assembled from v0.14 at tag `poc-v0.14`, and `../v0.14/` is frozen. Appendix
A.12 of `dsip_v_0_15_decentralized_session_initiation_protocol.md` lists what v0.15 changes, with its spec-gap numbers
(126–129). The companion drafts (DHT Hints, RTP/SRTP, Alias Transparency, Device Events, Recording, Number
Attestation) stay drafts.

| document | what | status |
|---|---|---|
| `dsip_v_0_15_decentralized_session_initiation_protocol.md` | DSIP core | v0.15 (v0.14 text + A.12) |
| `dsip-schemas-v0.15-draft/` | Core JSON Schema set | generated; unchanged |
| `dsip-webrtc-media-binding-v0.15.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.15.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.15.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative; members enforce the roster rules (M§7.3, spec-gap 126), removal ends the join (M§8.5, 127), a group may return to a hub it left (M§7.4, 128), a member may reach the new hub first (M§7.4, 129) |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v0.15-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.15-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-alias-transparency-profile-v0.15-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft; stage 1 and the DSIP side of stage 2 (T§7–T§10); proof verification waits for KEYTRANS -06 (T§6) |
| `dsip-device-events-profile-v0.15-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.15-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.15-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; stage 5 needs a pilot partner |

No change to the wire format or to either schema set: `dsip.core` stays `1.0`. Every v0.15 change is a rule a
device or a hub applies to messages it already exchanges. The suite has 2,109 vectors, on which the Python harness,
the Rust reference implementation and the independent TypeScript implementation agree.
