# DSIP v0.8 — staging (drafts)

v0.7 (`../v0.7/`) is the current published revision (tag `poc-v0.7`). This folder stages v0.8
material as it is drafted, the same way `v0.7/` staged its companions before `poc-v0.7`. Nothing
here is released; v0.7 is frozen.

Contents:

| document | what | conformance |
|---|---|---|
| `dsip-gateway-profile-v0.8-draft.md` | DSIP↔SIP/PSTN Gateway Profile 1.0 — identity, controller state machine, reason mapping both ways, PSTN caller claims, downgrade rule, early media, DTMF | `impl/vectors/gateway/` (53 vectors, Rust/Python parity) |
| `dsip-rtp-srtp-media-binding-v0.8-draft.md` | RTP/SRTP Media Binding 1.0 (`transport:rtp`) — SDES/DTLS keying, encryption floor + plain-RTP exception, codec mapping, DTMF | G§6 SDP-mapping vectors; a `media-binding-rtp/` category follows when the binding lands in code |

Both are transcribed from the reference gateway (`impl/crates/dsip-gateway`), whose tables and
controller are already vector-pinned — the same "write the spec from the implementation" method as
the WebRTC Media Binding (v0.7).

**Core additions these companions imply for a v0.8 core revision** (filed as gateway spec-gaps
23–30 in `impl/docs/spec-gaps.md`): the Gateway Profile and RTP/SRTP binding as named conformance
pieces (§24.4), a `tel` claim-types registry entry, DTMF carriage, `gateway.downgraded` trigger
conditions, the early-media rule, the single-contact-vs-forking decision, and the
`Reason: DSIP;text=` convention on SIP crossings.
