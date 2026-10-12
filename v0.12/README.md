# DSIP v0.12 — final

v0.12 is final at tag `poc-v0.12`. It was assembled from v0.11 at tag `poc-v0.11`, and `../v0.11/` is frozen. Appendix
A.9 of `dsip_v_0_12_decentralized_session_initiation_protocol.md` lists what v0.12 changes. The companion drafts (DHT
Hints, RTP/SRTP, Alias Transparency stage 1, Device Events, Recording, Number Attestation) stay drafts within the
final revision.

| document | what | status |
|---|---|---|
| `dsip_v_0_12_decentralized_session_initiation_protocol.md` | DSIP core | v0.12, final (v0.11 text + A.9: a revocation handed to a relay, §7.4/§13.2; what a relay's `hello` does not carry, §13.2; `from` and the acting identity, §10.2) |
| `dsip-schemas-v0.12-draft/` | Core JSON Schema set | generated; unchanged from v0.11 |
| `dsip-webrtc-media-binding-v0.12.md` | WebRTC Media Binding 1.0 | normative; §4 names how ICE servers and TURN credentials reach a client (spec-gap 114) |
| `dsip-gateway-profile-v0.12.md` | Gateway Profile 1.0 | normative, unchanged |
| `dsip-messaging-profile-v0.12.md` | Messaging Profile 1.0 and Mailbox 1.0 | normative; M§4.1 enrolment (spec-gap 115), M§6.5 rule 5 mailbox resolution (116), M§14.2 the granter from the delegation (117) and the `origin` age bound (118) |
| `dsip-messaging-schemas-draft/` | Messaging Profile schema set | generated; unchanged |
| `dsip-rtp-srtp-media-binding-v0.12-draft.md` | RTP/SRTP Media Binding | draft |
| `dsip-dht-hints-profile-v0.12-draft.md` | DHT Reachability Hints Profile | draft; §10 adds the Pkarr refresh (spec-gap 109) and that nodes are configuration (114) |
| `dsip-alias-transparency-profile-v0.12-draft.md` | Alias Transparency Profile (`alias-transparency/0.1`), cited `T§n` | draft, stage 1; v0.12 adds the `tel:` label (T§3); stage 2 waits for KEYTRANS -06 |
| `dsip-device-events-profile-v0.12-draft.md` | Device Events Profile (`device-events/0.1`), cited `E§n` | draft |
| `dsip-recording-profile-v0.12-draft.md` | Recording Profile (`recording/0.1`), cited `C§n` | draft |
| `dsip-number-attestation-profile-v0.12-draft.md` | Number Attestation Profile (`tn-binding/0.1`), cited `N§n` | draft, stages 1–4; v0.12 adds route 2's serving half (N§6, the authority's `.well-known`); stage 5 needs a pilot partner |

No wire-format change: `dsip.core` stays `1.0`; the suite has 1,956 vectors, on which all three implementations agree.
What a host decides and no message changes (spec-gaps 113–116) is pinned by the browser client's headless tests
(`impl/web/test/`) rather than by vectors. Open against v0.12 at the tag: spec-gap 119 (a hub's fan-out queue for a
member that has gone has no bound) and the leftovers of spec-gap 103; the next revision starts from `poc-v0.12` in a
`v0.13/` folder, as rule 7 of `CLAUDE.md` says.
