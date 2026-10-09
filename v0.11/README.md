# DSIP v0.11 — final

v0.11 is final at tag `poc-v0.11`. It was assembled from v0.10 at tag `poc-v0.10`, and `../v0.10/` is frozen. Appendix
A.8 of `dsip_v_0_11_decentralized_session_initiation_protocol.md` lists what v0.11 changes. The companion drafts (DHT
Hints, RTP/SRTP, Alias Transparency stage 1, Device Events, Recording, Number Attestation) stay drafts within the
final revision.

| document | what | status |
|---|---|---|
| `dsip_v_0_11_decentralized_session_initiation_protocol.md` | DSIP core | v0.11, final (v0.10 text + A.8; §15 `detail` may be a profile-defined object; §19.1 names the tier of a verified number) |
| `dsip-schemas-v0.11-draft/` | Core JSON Schema set | generated; v0.11 adds `invite.destination` (spec-gap 111) and widens `detail` on the reason-carrying messages to string or object (spec-gap 112) |
| `dsip-webrtc-media-binding-v0.11.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.11.md` | Gateway Profile 1.0 | normative, unchanged; G§11 points at the Number Attestation draft for path (c) |
| `dsip-messaging-profile-v0.11.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative, unchanged |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated, unchanged |
| `dsip-rtp-srtp-media-binding-v0.11-draft.md` | RTP/SRTP Media Binding | draft, unchanged |
| `dsip-dht-hints-profile-v0.11-draft.md` | DHT Reachability Hints Profile | draft; v0.11 adds §10, HTTP access to hints and number bindings on a `dsip-node` (spec-gaps 105, 109) |
| `dsip-alias-transparency-profile-v0.11-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft, stage 1; stage 2 waits for KEYTRANS -06 |
| `dsip-device-events-profile-v0.11-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft; v0.11 adds signed-syslog gap detection, key blob types N, P and U, and SNMPv3 over DTLS (spec-gap 103, now closed) |
| `dsip-recording-profile-v0.11-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft, unchanged |
| `dsip-number-attestation-profile-v0.11-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, new in v0.11: stages 1–4 (binding, claim, discovery, gateway); stage 5 needs a pilot partner |

No wire-format change: `dsip.core` stays `1.0`; the suite has 1,924 vectors, on which all three implementations agree.
