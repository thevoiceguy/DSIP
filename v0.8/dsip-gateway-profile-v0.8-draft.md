# DSIP Gateway Profile 1.0 — DSIP ↔ SIP/PSTN

**Status:** DRAFT, companion profile to DSIP (staged for v0.8). Normative for a conformant
DSIP↔SIP gateway. **Conformance:** the `gateway/` category of the DSIP vector suite
(`impl/vectors/gateway/`, 53 vectors, Rust/Python parity) pins the reason tables (G§4), SDP
mapping (G§6), caller claims (G§5), the downgrade rule (G§7) and the controller state machine
(G§3). Resolves gateway spec-gaps 23–29 (`impl/docs/spec-gaps.md`).
**Editor's note:** written from the reference gateway (`impl/crates/dsip-gateway`,
round-one host in `impl/crates/dsip-gateway/src/host`). Where this document and the code differ,
this document wins and the code changes.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are RFC 2119 / RFC 8174.
Core sections are cited `§n`; this profile's own sections are cited `G§n`.

---

## G§1 Scope

A DSIP↔SIP gateway is a **back-to-back user agent** (B2BUA): it terminates a DSIP session on one
side and a SIP dialog on the other, anchoring and transcoding media between them. This profile
defines how the two protocols map so that a conformant gateway preserves DSIP's honesty principle
(§6.3): *crossing into the PSTN is a trust downgrade unless the gateway can preserve and assert
DSIP identity semantics through supported PSTN identity mechanisms.*

This profile defines: the gateway's identity (G§2), the controller state machine that mediates the
two legs (G§3), the reason-code mapping both directions (G§4), PSTN caller identity as DSIP claims
(G§5), SDP ↔ descriptor mapping (G§6), the trust-downgrade rule (G§7), early-media handling (G§8),
DTMF (G§9), and conformance (G§10). Media transport on the SIP side is the **RTP/SRTP Media
Binding** (companion document); on the DSIP side it is the **WebRTC Media Binding** (§v0.7).

**Out of scope** (Core §3.2, Appendix B): emergency calling, lawful intercept, number portability
and rate-center routing, billing/settlement, transfer (REFER), video, and any SIP proxy or
registrar role for DSIP identities. A gateway is a B2BUA and a SIP UA (trunk endpoint or PBX
registrant).

## G§2 Gateway identity

- The gateway is a DSIP identity, a `did:web` of the operator (§7.2), with a per-instance device
  key delegated by that identity (§7.4). Every DSIP envelope the gateway sends is signed by the
  device key; the delegation rides in the protected header as for any device.
- Toward DSIP callees the gateway is a Tier 3 (domain-bound) identity (§19.1); an operator holding
  an organization credential is Tier 4.
- Toward SIP it is a UA with trunk credentials (Digest) and, where the operator has one, an STI
  certificate (G§5, G§11).
- A gateway MUST NOT present itself to a DSIP callee as the identity of the PSTN caller. The caller
  is a claim (G§5), the gateway is the signer.

## G§3 Controller state machine

The gateway hosts the §12 DSIP state machine (it never re-implements it) and siphon-style SIP
dialog/transaction handling. The controller's own state is small: the direction, which leg is
pending, whether early media has answered the DSIP leg, and the terminal-event mapping. The two
legs are distinct sessions: **glare (§12.6) cannot cross the gateway**, and a gateway MUST follow a
single SIP contact — it MUST NOT forward SIP 3xx as DSIP forking in this version (spec-gap 29).

### G§3.1 DSIP → PSTN (the gateway is DSIP responder, SIP UAC)

| controller event | DSIP leg action | SIP leg action |
|---|---|---|
| DSIP `invite` admitted (§19 policy) | — | INVITE |
| SIP 100 | — | (already sent) |
| SIP 180/183 | `progress` (status `ringing`) | — |
| SIP 183 + SDP, early-media policy pass (G§8) | `answer` `answered_by: gateway` + bridge | — |
| SIP 2xx | `answer` `answered_by: gateway` (if not already) + bridge | ACK |
| SIP 3xx–6xx (pre-answer) | `reject` with the G§4 reason | — |
| DSIP `cancel` | — | CANCEL; a 2xx crossing the CANCEL is ACKed then `BYE session.cancelled` (§12.5) |
| DSIP `bye` | — | BYE with the G§4 cause |
| SIP BYE | `bye` with the G§4 reason | 200 OK |
| SIP final ≥ 300 after answer | `bye` `gateway.mapped` (attempt tokens become `gateway.mapped` once ACTIVE) | — |
| SIP Timer C, no final | `reject`/`bye` `gateway.unreachable` | CANCEL |

### G§3.2 PSTN → DSIP (the gateway is SIP UAS, DSIP initiator)

| controller event | DSIP leg action | SIP leg action |
|---|---|---|
| SIP INVITE | `invite` to the resolved DSIP target, `identity.claims` = the G§5 `tel` claim | 100 Trying |
| DSIP `progress ringing` | — | 180 Ringing |
| DSIP `answer` `answered_by: user` | — | 200 OK + SDP |
| DSIP `answer` `answered_by: screening` (§14.4) | — | 200 OK, `a=sendonly` toward the PSTN (caller heard, nothing played back) |
| DSIP `update` (escalation) | — | re-INVITE mirroring the direction |
| DSIP `reject` | — | mapped 4xx/6xx (G§4) with the DSIP token in `Reason` |
| SIP CANCEL | `cancel` | 200 to CANCEL + 487 to the INVITE |
| SIP BYE | `bye` | 200 OK |
| SIP REFER | — | 603 Decline (transfer is out of scope this version) |

Every crossing MUST carry the DSIP reason on the SIP message as a `Reason` header
`DSIP;text="<token>"` (RFC 3326), in addition to any `Q.850;cause=` — so a capture or a
downstream element sees the unmapped DSIP reason (spec-gap 24 makes this normative).

## G§4 Reason-code mapping (normative; §15.5)

A gateway MUST map foreign codes to DSIP reasons and MUST NOT tunnel numeric SIP/Q.850 codes to
DSIP clients. A `Reason: Q.850;cause=<n>` present on an inbound message takes precedence over the
SIP status when the cause is mapped (the cause is the more specific signal). Tokens describing a
failed *attempt* (busy, declined, unknown, moved, cancelled, blocked) that arrive **after** the
DSIP leg is ACTIVE are reported as `gateway.mapped` (the attempt already succeeded; the teardown
is a mid-call event). A BYE with no `Reason` maps to `user.hangup`.

### G§4.1 Inbound (SIP/Q.850 → DSIP)

Q.850 cause → DSIP token (checked first):

| Q.850 | DSIP | Q.850 | DSIP |
|---|---|---|---|
| 1 | `identity.unknown` | 31, 16 | `user.hangup` |
| 16 (normal) | `user.hangup` | 34, 38, 41–44 | `gateway.unreachable` |
| 17 | `endpoint.busy` | 47 | `media.failed` |
| 18–20 | `endpoint.unavailable` | 63, 65, 79 | `media.unsupported` |
| 21 | `user.declined` | 102 | `session.timeout` |
| 22 | `identity.not-in-service` | 28 | `identity.unknown` |

SIP status → DSIP token (when no mapped Q.850 cause):

| SIP | DSIP | SIP | DSIP |
|---|---|---|---|
| 403 | `policy.blocked` | 487 | `session.cancelled` |
| 404, 484, 604 | `identity.unknown` | 488, 415, 606 | `media.unsupported` |
| 408, 480 | `endpoint.unavailable` | 486, 600 | `endpoint.busy` |
| 410 | `identity.not-in-service` (`identity.moved` with a known successor) | 502, 503, 504 | `gateway.unreachable` |
| 603 | `user.declined` | other/unmappable | `gateway.mapped`, original code in `detail` |

The carrying DSIP message is `reject` (pre-answer), `bye` (ACTIVE), or `error` (transport-scoped).

### G§4.2 Outbound (DSIP → SIP)

A pre-answer refusal → SIP final response (with `Q.850;cause` and `Reason: DSIP`); an ACTIVE
teardown → BYE with the cause. Registered tokens map as below; an **unregistered** token maps by
its §15.1 category (`user`→603, `endpoint`→480, `identity`→404, `session`→500, `media`→488,
`policy`→403, `transport`→503, `gateway`→503) and still carries its literal text in `Reason`.

| DSIP | SIP (cause) | DSIP | SIP (cause) |
|---|---|---|---|
| `user.declined` / `user.blocked` | 603 (21) | `media.*` | 488 (65) |
| `user.no-answer` | 480 (19) | `policy.blocked` / `policy.trust-insufficient` / `policy.first-contact-required` | 403 (21) |
| `user.cancelled` | 487 | `policy.rate-limited` | 503 (42) + `Retry-After` |
| `endpoint.busy` | 486 (17) | `policy.terminated` | 480 (31) |
| `endpoint.unavailable` | 480 (18) | `transport.unknown-recipient` | 404 (1) |
| `endpoint.capability` | 488 (79) | `transport.*` (other) | 503 (41) |
| `identity.not-in-service` / `identity.moved` | 410 (22) | `gateway.unreachable` | 503 (38) |
| `identity.suspended` | 403 (21) | `gateway.mapped` / `session.failed` | 500 (41) |
| `identity.unknown` | 404 (1) | BYE `user.hangup` / `session.*` | cause 16 |
| `session.expired` / `session.timeout` | 480 (102) | BYE `media.failed` | cause 47 |

PSTN in-band announcements SHOULD be classified to a reason token where the gateway can (G§8);
where it cannot, the gateway answers the DSIP leg (`answered_by: gateway`) and passes audio through
— free, because a DSIP `answer` carries no billing semantics (§14.1).

## G§5 PSTN caller identity as DSIP claims (§18.1)

An inbound PSTN caller has no DID. The gateway's DSIP `invite` carries a `tel` claim in
`identity.claims[]` and the DSIP callee's client renders the **verification basis**, never a badge:

```json
{ "type": "tel", "number": "+15551234567", "attestation": "A", "verified": true,
  "verifier": "did:web:gw.example", "cnam": "ACME Corp" }
```

- `attestation` is the STIR/SHAKEN level (`A`|`B`|`C`|`none`) from a verified RFC 8224 `Identity`
  header; `none` when absent.
- `verified` is `true` only when the PASSporT signature and X.509 chain verified **and** its
  `orig` matches the SIP `From` number. A PASSporT whose `orig` names a different number MUST be
  discarded (attestation `none`) — it attests some other call.
- `verifier` is the gateway's DID.
- The client MUST render the basis as the gateway's claim: e.g. *"Gateway attested by gw.example ·
  STIR attestation A (verified)"* / *"… · no attestation"* — §18.1's "explain the trust basis"
  rule. It MUST NOT show a generic verified badge.

First contact (§19.4) applies to the **gateway identity**: a callee who has granted the gateway
`dsip.invite` admits PSTN calls through it; otherwise the invite is refused
`policy.first-contact-required` (the DSIP-native answer to unsolicited PSTN calls). A gateway MAY
send an `introduction` on a caller's behalf.

The `tel` claim type is registered in the DSIP claim-types registry (spec-gap 25).

## G§6 SDP ↔ descriptor mapping

No SDP crosses the gateway. Each side's SDP is authoritative for its own transport (the DSIP side
by the WebRTC Media Binding B§2.1, the SIP side by the RTP/SRTP binding); descriptors are
re-derived per side.

- **Trunk SDP → DSIP descriptors:** each `m=audio`/`m=video` with a known codec becomes a media
  descriptor (codec ids from `a=rtpmap`; encodings DSIP has no id for are dropped; a section with
  no known codec is omitted); the section direction (including a hold's `sendonly`/`inactive`)
  carries; SRTP mode is `none` (plain RTP), `sdes` (`a=crypto`), or `dtls` (`UDP/TLS/RTP/SAVP*`).
- **DSIP selection → trunk m= lines:** the negotiated codecs and direction become the SIP leg's
  offer/answer. The gateway transcodes when the two sides' codecs differ (Opus 48 kHz ⇄ G.711
  8 kHz / G.722 16 kHz), Opus↔Opus when the trunk offers Opus.

## G§7 Trust downgrade (§6.3)

A gateway MUST send `gateway.downgraded` (an informational `error` on the DSIP leg; the session
continues) whenever a crossing loses a guarantee the DSIP side held. The losses, each named:

| loss | condition |
|---|---|
| `no-srtp-on-trunk` | the SIP media is plain RTP (no SDES, no DTLS-SRTP) |
| `identity-not-assertable` | outbound, and the operator cannot assert the DSIP caller's identity into the PSTN (G§11) |
| `no-attestation` | inbound, and the caller carried no verifiable STIR attestation |
| `policy-unenforceable` | the DSIP caller declared a `policy` (§16.4) the gateway cannot enforce past the trunk |

The gateway echoes the DSIP caller's `policy` to the DSIP side unchanged and MUST NOT claim
PSTN-side compliance (spec-gap 27 makes these triggers normative).

## G§8 Early media (Appendix C)

Per-trunk policy `pass-early-media` ∈ {`auto`, `always`, `never`}, default `auto`:

- `never`: a 183 with SDP only rings; the DSIP leg is answered on 2xx.
- `always`: a 183 with SDP answers the DSIP leg (`answered_by: gateway`) and bridges audio.
- `auto`: if the gateway can classify the early media as an announcement it maps it to a reason
  token; otherwise it answers and passes the audio.

This is stated in §15.5/Appendix C prose in the core; G§8 is the rule with vectors (spec-gap 28).

## G§9 DTMF

DSIP has no DTMF semantics in Core v1.0. This version does **not** forward RFC 2833 DTMF events
across the gateway. Carriage is an open question (spec-gap 26): the natural vehicle is a signed
`info` (§12.12) with a gateway-defined `about` (e.g. `x-gateway:dtmf`); a future revision defines
it. A gateway MUST NOT invent a DTMF carriage silently.

## G§10 Conformance

A conformant DSIP↔SIP gateway MUST implement G§3–G§8, MUST answer DSIP legs with
`answered_by: "gateway"`, MUST map reasons per G§4 (never tunnel numerics), MUST render PSTN
callers as claims per G§5, MUST emit `gateway.downgraded` per G§7, and MUST pass the `gateway/`
vectors of the conformance suite. A gateway conforms to this profile as
`DSIP Gateway Profile 1.0` (§24.4).

## G§11 STIR/SHAKEN, RCD, CNAM (informative; the findings work is G4)

Outbound identity assertion depends on the operator's status and is written up separately (plan
G4). Three paths: (a) a service provider with an SPC token and STI certificate signs a SHAKEN
PASSporT (`attest: A` for owned numbers) — requires PASSporT **signing** in `sip-identity`, which
verifies today; (b) a non-SP presents `From`/`P-Asserted-Identity` only and crosses with
`gateway.downgraded`; (c) an RFC 9060 delegate certificate model where a carrier delegates a TN
range — the most DSIP-shaped path, because the DID document could publish the delegate certificate.
This version implements (b) and documents (a)/(c). See `impl/docs/gateway-stir-findings.md` (G4) for the full analysis and the `sip-identity` PASSporT-signing prototype (siphon-rs PR #123) behind path (a)/(c).
