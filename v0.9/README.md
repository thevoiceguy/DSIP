# DSIP v0.9 — in progress (draft)

v0.9 is the current revision, assembled from v0.8 at tag `poc-v0.8.1`; `../v0.8/` is frozen. Appendix A.6 of
`dsip_v_0_9_decentralized_session_initiation_protocol.md` lists what v0.9 changes, as each item lands. The plan is
`../impl/docs/v0.9-research.md`, section 3, decided 2026-10-04:

1. `did:webvh` as a recommended DID method beside `did:web`.
2. Reachability hints on the BitTorrent Mainline DHT (Pkarr) for `did:key` subjects, beside the hints overlay.
3. Alias transparency for `alias → DID` (§8.2), aligned with IETF KEYTRANS.
4. A Device Events Profile: device alarms and events gatewayed from SNMP and syslog, signed, durably delivered,
   acknowledged and escalated.

| document | what | status |
|---|---|---|
| `dsip_v_0_9_decentralized_session_initiation_protocol.md` | DSIP core | draft v0.9 (v0.8 text + A.6) |
| `dsip-schemas-v0.9-draft/` | Core JSON Schema set | generated; unchanged from v0.8 so far |
| `dsip-webrtc-media-binding-v0.9.md` | WebRTC Media Binding 1.0 | normative, unchanged |
| `dsip-gateway-profile-v0.9.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.9.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative, unchanged |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v0.9-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.9-draft.md` | DHT Reachability Hints Profile | draft |
| `dsip-device-events-profile-v0.9-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft; `device-events/` vectors |
| `dsip-alias-transparency-profile-v0.9-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft, stage 1; `alias-transparency/` vectors |

No wire-format change so far: `dsip.core` stays `1.0`. Rule 7 of `CLAUDE.md` applies: each change lands as vectors
first, then the three implementations, and `poc-v0.9` is tagged when all three agree on the v0.9 suite.
