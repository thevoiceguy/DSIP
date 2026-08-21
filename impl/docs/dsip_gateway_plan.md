# DSIP Phase 4 — SIP/PSTN Gateway Plan (M4)

**Status:** plan, drafted 2026-08-21 against DSIP v0.7 and the delivered PoC (Phases 1–3, WS-D).
**Scope of this document:** the design and workstream plan for the DSIP↔SIP gateway. It is the
M4 deliverable of `dsip_poc_dev_plan.md` ("gateway plan drafted"); no gateway code exists yet.
**Owner stack:** siphon-rs (SIP) + forge-media (media) + the DSIP PoC crates. All three are this
project's own code, which is what changed the calculus since the original plan called the gateway
the "least spec-proving value per unit effort" item (§1).

---

## 1. Why now, and what changed

The v0.6 plan deferred the gateway because it had "the largest external-dependency surface". That
premise no longer holds:

- **siphon-rs** is a production SIP stack with UAC/UAS helpers, dialogs, transactions, registrar,
  PRACK, session timers, REFER/Replaces, tel URIs, RFC 3263 DNS, TLS, HEP, and STIR/SHAKEN
  *verification* (RFC 8224/8225, ES256, X.509 chain to an STI-PA anchor).
- **forge-media** carries RTP/SRTP both ways (SDES and DTLS-SRTP), G.711/G.722/Opus with
  transcoding, jitter, DTMF (RFC 2833 and in-band), a PCM media bridge, and — since the DSIP forge
  sprint — an endpoint-shaped WebRTC peer connection (`forge-webrtc` 0.3).
- **siphon-ai** already composes the two into a per-call `CallController` daemon deployed against
  Twilio, FreeSWITCH and CUCM trunks. A DSIP gateway is that daemon with its WebSocket leg replaced
  by a DSIP leg.
- **The DSIP side is a library.** `dsip-endpoint::Core` is IO-free (it drives the browser and the
  native CLI today); `dsip-transport::Agent` wraps it with `ws/1.0`; `dsip-webrtc-binding` enforces
  the media binding; `dsip-media` gives a forge-backed WebRTC leg. The gateway's DSIP leg is a
  fourth host of the same core, not new protocol code.

So the gateway has turned from an integration risk into the first **cross-protocol proof** of the
spec: does DSIP's trust model survive contact with the network it proposes to replace, and does
the spec say *honestly* what is lost? §6.3's principle — "crossing into the PSTN is a trust
downgrade unless the gateway can preserve and assert DSIP identity semantics" — is the claim under
test.

## 2. Goals and non-goals

**Goals**

1. A B2BUA that terminates a DSIP session on one side and a SIP dialog on the other, in both
   directions (DSIP→PSTN outbound, PSTN→DSIP inbound), with media anchored and transcoded by forge.
2. The **Gateway Profile** and **RTP/SRTP Media Binding** as v0.8 companion documents, written the
   way the WebRTC binding was: from the implementation, with conformance vectors before code.
3. Trust semantics made explicit on every crossing: `answered_by: "gateway"`, `gateway.downgraded`,
   the §18.1 verification basis ("Gateway attested by …"), and the §15.5 reason mapping as a
   normative table with vectors.
4. A findings report on STIR/SHAKEN, RCD and CNAM: what a DSIP gateway can verify inbound, what it
   can assert outbound, and under which operator status (the honest answer is "it depends on who
   holds the SPC token").

**Non-goals (explicit, per Core §3.2 and Appendix B)**

- Emergency calling (911/112/999) — regulated profile, out of scope.
- Lawful intercept, TCPA/robocall compliance, number portability lookups, rate-center routing —
  operator obligations the plan names but does not implement.
- Billing or settlement. DSIP `answer` carries no billing semantics (§15.5); the gateway does not
  introduce any.
- Video through the gateway. Round one is audio (G.711/G.722/Opus). Video over SIP is a later step
  once the RTP/SRTP binding exists.
- A SIP *proxy* or registrar role for DSIP identities. The gateway is a B2BUA and a SIP UA
  (registering to a PBX or acting as a trunk endpoint), exactly like siphon-ai.

## 3. Architecture

```
                DSIP side                         gateway daemon                       SIP side
  ┌────────────────────────────┐      ┌──────────────────────────────────────┐      ┌──────────────────┐
  │ relay (ws/1.0, dsip-relay) │◀────▶│ DSIP leg: dsip-transport::Agent       │      │ trunk / PBX /    │
  │   or direct wss peer       │      │   over dsip-endpoint::Core            │      │ carrier SBC      │
  └────────────────────────────┘      │   + dsip-webrtc-binding (enforced)    │      └────────┬─────────┘
                                      │   + forge-webrtc PeerConnection       │               │ SIP (UDP/TCP/TLS)
  ┌────────────────────────────┐      │               ▲                       │      ┌────────▼─────────┐
  │ DSIP endpoint (browser /   │◀DTLS-SRTP (Opus)─┐   │  CallController        │◀────▶│ siphon-rs        │
  │ native)                    │                  │   │  (per-call state       │      │ sip-uas / sip-uac│
  └────────────────────────────┘                  │   │   machine: §12 ↔ RFC   │      │ sip-dialog       │
                                                  │   │   3261 mapping)        │      │ sip-identity     │
                                                  │   ▼                       │      └────────┬─────────┘
                                                  │ forge-engine MediaSession  │               │ RTP/SRTP
                                                  │  webrtc leg ⇄ transcode ⇄  │◀──────────────┘
                                                  │  sip leg (SDES/DTLS/plain) │
                                                  └────────────────────────────┘
```

**Identity of the gateway.** The gateway is a DSIP identity — `did:web` of the operator (§7.2 lists
gateways under `did:web`) — with a device key per daemon instance delegated by that identity
(§7.4). Every DSIP envelope the gateway sends is signed by the device key; the delegation rides in
the header as for any device. Toward SIP it is a UA with trunk credentials (Digest) and, where the
operator has one, an STI certificate.

**Three legs, one controller.** Mirroring siphon-ai's `CallController`, each call owns:

- a **DSIP leg** — a session in `Core` (initiator or responder role per direction), its SDP from
  the forge peer connection, its candidates through signed `info`;
- a **SIP leg** — a siphon dialog (UAC for outbound INVITE, UAS for inbound), the trunk's SDP;
- a **media session** — a forge `MediaSession` with two participants (WebRTC leg, SIP leg),
  transcoding Opus↔G.711/G.722 when needed, DTMF relayed as RFC 2833 on the SIP side and as… see
  §7 (DSIP has no DTMF semantics; round one drops it or maps it to `info` with a gateway-defined
  `about`, which is a spec gap to file).

The controller is the **only** place where the two protocols' state machines meet; it holds the
mapping table of §5 and nothing else knows about the other protocol.

**Crate layout** (in `impl/`):

```
crates/dsip-gateway/         library: CallController, leg adapters, mapping tables, trust model
  src/controller.rs          per-call state machine (§5 mapping), the spec-traceable part
  src/dsip_leg.rs            Core/Agent host (like dsip-cli console.rs, headless)
  src/sip_leg.rs             siphon UAS/UAC adapter
  src/media.rs               forge MediaSession wiring: webrtc participant ⇄ sip participant
  src/reasons.rs             §15.5 mapping, both directions (vector-pinned)
  src/sdp.rs                 DSIP descriptors ⇄ SIP SDP (vector-pinned)
  src/identity.rs            DID ⇄ SIP/tel URI, claims, attestation → trust basis
bins/dsip-gateway/           daemon: config (trunks/registrations like siphon-ai), HEP, metrics
```

`dsip-gateway` depends on `dsip-endpoint`, `dsip-transport`, `dsip-webrtc-binding`, `dsip-media`
(forge backend), and on `siphon-rs` + `forge-media` by git rev, the same way `dsip-media` already
depends on forge.

## 4. Call flows

### 4.1 DSIP → PSTN (outbound)

```
DSIP caller          gateway (DSIP leg)      controller       gateway (SIP leg)        trunk
  invite{to: gw DID, ─▶ verify sig/delegation ─▶ admit? ───▶ INVITE sip:+1555…@trunk ─▶
    identity, media,     (§19: first contact,     (policy:        SDP from forge sip leg
    transports[webrtc]}   rate limits apply)       allowed                                 ◀─ 100 Trying
                                                   callers)                                ◀─ 180 Ringing
  ◀─ progress{ringing} ◀──────────────────────────────────────── map 180 → ringing
  ◀─ progress{ringing, ring_timeout} (T-Ring, §12.9)
                                                                                           ◀─ 183 + SDP (early media)
  ◀─ answer{answered_by: "gateway"} ◀──── if early media must be heard (§15.5, App. C):
      media start (DSIP side)                answer the DSIP leg now; audio passes through
                                                                                           ◀─ 200 OK + SDP
  (already ACTIVE)  or, with no early media: ◀─────────────────── map 200 → answer{answered_by:"gateway"}
                                                          ACK ─▶
  ◀─ info{candidates} / ─▶ info{candidates}   (DSIP side only; SIP side has no ICE in round one)
  ◀─────────────────── DTLS-SRTP Opus ──▶ forge transcodes ◀── RTP G.711/SRTP (SDES or DTLS) ──▶
  bye{user.hangup} ─▶                                           BYE ─▶            ◀─ 200 OK
  ◀─ bye{reason mapped §15.5} ◀──────────────────────────────── ◀─ BYE
```

Key decisions: the DSIP answer is always `answered_by: "gateway"` — the gateway cannot assert that
a human answered (§14.1 means "a delegated endpoint commits to media", and the gateway is that
endpoint). Early media is the App. C rule: classify announcements to reasons when possible,
otherwise answer and pass audio. `cancel` ↔ `CANCEL`; a `487` back maps to `session.cancelled`.

### 4.2 PSTN → DSIP (inbound)

```
trunk                gateway (SIP leg)       controller        gateway (DSIP leg)        DSIP callee
INVITE sip:+1555…  ─▶ UAS: verify Identity ─▶ resolve target ─▶ invite{from: gw device,
  (+ Identity hdr)     (STIR) → attestation    (E.164 → DID:       identity.claims: [tel,
                        A/B/C or none          operator routing     attestation, CNAM],
                                               table / alias §8.2)  to: callee DID} ─▶ relay forks (§12.7)
◀─ 100 Trying
◀─ 180 Ringing  ◀────────────────────────────────────────────── ◀─ progress{ringing}
◀─ 200 OK + SDP ◀──────────────────────────────────────────── ◀─ answer{answered_by: user|screening}
   ACK ─▶                                                         (screening answer = recvonly: gateway
◀── RTP ──▶ forge ◀── DTLS-SRTP ──▶                               sends caller audio, plays nothing back)
◀─ BYE  ◀──────────────────────────────────────────────────── ◀─ bye
```

Key decisions: the PSTN caller has no DID, so the invite's `from` is the gateway's device and the
caller is a **claim** in `identity.claims` (tel URI, STIR attestation level and verification
result, CNAM/RCD if present), rendered by the callee's client under the §18.1 basis "Gateway
attested by <operator>" — never as a verified DSIP identity. First contact (§19.4) applies to the
*gateway identity*: a callee who has not granted the gateway sees `policy.first-contact-required`
behaviour, which is the DSIP-native answer to unsolicited PSTN calls (the gateway MAY send an
`introduction` on the caller's behalf; a grant scoped `dsip.invite` then admits calls via that
gateway). Screening (§14.4) works unchanged and is genuinely useful here: the callee's endpoint
hears the PSTN caller before committing.

### 4.3 Mid-call

| DSIP | SIP | notes |
|---|---|---|
| `update` (escalation, codec change) | re-INVITE | round one: audio-only, so updates that add video are rejected `media.unsupported` toward DSIP, never forwarded |
| — | re-INVITE for hold (a=sendonly/inactive) | map to `update` with the mirrored direction; DSIP side answers |
| — | REFER (transfer) | out of round one; respond 603 Decline on the SIP leg |
| `info` (candidates) | — | terminated at the gateway's WebRTC leg |
| — | INFO/DTMF (RFC 2833 in RTP) | §7: dropped in round one, spec gap filed |
| `bye` | BYE | both directions, reason mapped |

## 5. State-machine mapping (controller)

The DSIP side is the §12.4 machine *as implemented by `dsip-session`* — the gateway never
re-implements it, it hosts it. The SIP side is siphon's dialog/transaction layer. The controller's
own state is small: which leg is pending, whether early media answered the DSIP leg, and the
mapping of terminal events.

| controller event | DSIP leg action | SIP leg action |
|---|---|---|
| DSIP `invite` admitted | Core: `alert` (progress ringing) | UAC INVITE |
| SIP 1xx (180/183) | `progress ringing` (+ `ring_timeout` from session timers if any) | — |
| SIP 183 with SDP, policy "pass early media" | `accept` `answered_by: gateway` | — |
| SIP 2xx | `accept` `answered_by: gateway` (if not already) | ACK |
| SIP 3xx–6xx | `auto_reject` / `decline` with §15.5 reason | — |
| DSIP `cancel` | — | CANCEL (or BYE if already 2xx'd — the §12.5 race on the SIP side) |
| DSIP `answer` (inbound call) | — | 200 OK with SDP (screening → `a=sendonly` toward PSTN) |
| DSIP `reject` | — | 4xx/6xx per reverse mapping |
| either `bye`/BYE | `hangup{reason}` | BYE |
| DSIP T-Ring/T-Establish expiry | engine cancels | CANCEL |
| SIP Timer C / session-timer expiry | `hangup{gateway.unreachable}` | BYE |

Glare (§12.6) cannot cross the gateway (the two sides are distinct sessions); forking is native on
the DSIP side (relay) and is *not* forwarded from SIP 3xx in round one (the gateway follows a
single contact). These are the first rows of the `gateway/` state-trace vectors (§8).

## 6. Identity and trust

1. **Gateway as DSIP identity.** `did:web:gw.example` with per-instance device delegations;
   toward DSIP callees the gateway is a Tier 3 (domain-bound) identity by §19.1. Operators that hold
   an organization credential reach Tier 4.
2. **Inbound PSTN caller → DSIP claims.** `identity.claims` carries a `tel` claim
   (`{"type": "tel", "number": "+15551234567", "attestation": "A|B|C|none", "verified": true|false,
   "verifier": "did:web:gw.example", "cnam": "…"}`) — shape to be fixed by the Gateway Profile
   (spec gap: no claim registry entry exists for this). The client shows "Gateway attested by
   gw.example · STIR attestation A" — the §18.1 basis, never a badge.
3. **Outbound DSIP identity → PSTN.** Three options, to be decided in the findings report (§9):
   (a) the operator is a service provider with an SPC token and STI certificate: the gateway
   signs a PASSporT (`shaken` with `attest: "A"` for numbers it owns; `div`/`rcd` as applicable) —
   requires adding **PASSporT signing** to `sip-identity` (it verifies today); (b) the operator is
   not an SP: it can only present `From`/`P-Asserted-Identity` and RCD-like display data, and the
   call crosses with `gateway.downgraded`; (c) a delegate-certificate model (RFC 9060) where a
   carrier delegates a TN range to the operator — the most interesting path for DSIP, because the
   DID document could publish the delegate certificate. Round one implements (b) and documents (a)/(c).
4. **`gateway.downgraded`.** Sent as an informational `error` on the DSIP leg whenever a crossing
   loses a guarantee the DSIP side had (no SRTP on the trunk, no attestation, identity not
   assertable). Clients render it; the session continues. Vector-pinned.
5. **Policy fields** (§16.4) — `recording`, `ai_processing`, `redistribution` — cannot be enforced
   beyond the gateway. The gateway echoes the DSIP caller's policy to the DSIP side unchanged and
   logs that it is unenforceable past the trunk; it never claims PSTN-side compliance.
6. **Abuse controls.** The gateway applies §19.2 rate limits per DSIP identity (outbound) and per
   calling number (inbound), and the trunk's own admission control (siphon's ingress limiter).

## 7. Media

- **SIP side**: forge `MediaSession` SIP participant — plain RTP, SDES (`a=crypto`), or DTLS-SRTP
  per what the trunk offers; G.711 µ/A, G.722, Opus. Jitter buffer and RTCP as today.
- **DSIP side**: `forge-webrtc` peer connection as the second participant (Opus over DTLS-SRTP),
  driven by the DSIP leg exactly as `dsip-media`'s forge backend does.
- **Transcoding**: forge-transcoder between the two when codecs differ (Opus 48 kHz ⇄ G.711 8 kHz /
  G.722 16 kHz). Opus-to-Opus when the trunk offers Opus (Twilio does).
- **SDP mapping** (`sdp.rs`, vector-pinned): DSIP descriptors ⇄ SIP SDP media lines; the
  gateway's own WebRTC SDP stays on the DSIP side (B§2.1 authority rule applies there), the trunk's
  SDP stays on the SIP side. No SDP crosses; descriptors are *re-derived* from each side.
- **DTMF**: no DSIP semantics exist. Round one: RFC 2833 events from PSTN are not forwarded; DSIP
  `info` with a gateway-defined `about` (`x-gateway:dtmf`?) is the obvious carriage — file as a
  spec gap for the Gateway Profile rather than inventing it silently.
- **RTP/SRTP Media Binding** (v0.8 companion): the descriptor for `transport:rtp` (SDES/DTLS keying
  modes, plain RTP forbidden by the §17.2 floor except behind a trunk the operator vouches for),
  written from `sdp.rs` the way the WebRTC binding was written from `dsip-media`.

## 8. Conformance: vectors before code

New vector kind **`gateway/`**, language-neutral like the others, with a Python reference and the
Rust controller at parity:

| check | pins |
|---|---|
| `reason-inbound` | SIP status (+ Q.850 cause) → DSIP token (§15.5 table, normative in the profile); unmappable → `gateway.mapped` with `detail` |
| `reason-outbound` | DSIP token → SIP status (the reverse table: `user.declined`→603, `endpoint.busy`→486, `policy.blocked`→403, `media.unsupported`→488, …) |
| `sdp-map` | DSIP descriptors ⇄ SIP SDP (codec ids ⇄ rtpmap, directions, hold) |
| `claims` | Identity header → `identity.claims[tel]` (attestation levels, verification outcomes, missing header) |
| `downgrade` | which crossings emit `gateway.downgraded` |
| `trace` | controller traces: outbound with 180/200, outbound with 183 early media, outbound 486, inbound answered, inbound screened, cancel/487 race, BYE both ways, Timer C |

Exit criterion for each workstream below: its vectors exist and pass in Python before Rust lands
(CLAUDE.md rule 1), and both runners agree (rule 2).

## 9. Workstreams and milestones

| WS | Deliverable | Exit criterion |
|---|---|---|
| **G0** | `gateway/` vectors + Python reference: reason tables, SDP map, claims, controller traces | Python green; tables reviewed against §15.5 and RFC 3261/Q.850 |
| **G1** | `dsip-gateway` lib: controller + DSIP leg + SIP leg + media wiring; Rust at parity with G0 | parity green; `cargo doc` Spec: citations to §15.5/§14.1/§19 and G§ (Gateway Profile) |
| **G2** | daemon + demo: DSIP native CLI ↔ gateway ↔ siphond (siphon-rs test daemon) with forge media both ways, audio recorded on both ends; then against a real trunk (Twilio) by hand | `demos/gateway-demo.sh` self-checking like `media-demo.sh`; CI runs it against siphond |
| **G3** | trust: claims, `gateway.downgraded`, §18.1 rendering in the CLI and browser demo; first-contact via the gateway identity | vectors + demo |
| **G4** | STIR/SHAKEN / RCD / CNAM **findings report** (options (a)/(b)/(c) of §6.3 with what each needs; PASSporT signing prototype in `sip-identity` behind a feature) | report in `docs/`; prototype signs a PASSporT that siphon verifies |
| **G5** | spec artifacts: **Gateway Profile 1.0 (draft)** and **RTP/SRTP Media Binding 1.0 (draft)** companions for v0.8; spec-gaps filed (DTMF carriage, tel claim shape, early-media answer rule wording, downgrade semantics) | both drafts in `v0.8/`; every normative sentence has a vector |

**Milestone M4′ (revised):** G0–G3 delivered = "a DSIP caller reaches a PSTN number and a PSTN
caller reaches a DSIP identity, each with the trust downgrade stated on the wire". G4–G5 are the
spec-proving half and may run in parallel after G1.

Estimated shape: G0 is a few days (tables + traces are small); G1 is the bulk (the controller is
siphon-ai's, re-targeted); G2 is bounded by siphond; G4 depends on operator status.

## 10. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| siphon-rs API churn (pre-1.0) | gateway rebuilds | pin by rev (as forge is today); the adapter is one file (`sip_leg.rs`) |
| Early-media policy is wrong for some trunks | callers hear nothing, or DSIP legs answer too early | policy per trunk (`pass-early-media: auto|always|never`), default `auto` = classify, else answer; vector-pinned |
| `gateway.downgraded` noise | every PSTN call emits it | it is informational and once per crossing; clients collapse it into the §18.1 basis line |
| STIR signing needs operator status the project does not have | G4 stays a report | that is the honest outcome; (c) delegate certificates is the path to write up |
| Scope creep into PBX features (transfer, hold variants, conferencing) | G1 never ends | round one answers REFER with 603, forwards hold as `update`, nothing else |
| DTMF expectations | users expect IVR navigation to work | explicit non-goal for round one, spec gap filed; forge already detects/generates RFC 2833 so round two is cheap |

## 11. Spec gaps expected (to be filed as they are hit)

1. Gateway Profile does not exist (§15.5 says "normative table belongs to the gateway profile").
2. RTP/SRTP Media Binding does not exist (§17.2, §24.4 list it).
3. No claim-type registry entry for PSTN caller identity (`tel` + attestation).
4. DTMF has no DSIP carriage.
5. `gateway.downgraded` is registered but its trigger conditions are undefined.
6. Early-media handling is stated in §15.5/App. C prose; needs a rule with vectors.
7. Whether a gateway MAY forward SIP 3xx forking as DSIP forking, or MUST follow one contact.

---

*Relationship to the original plan:* `dsip_poc_dev_plan.md` §9 is superseded by this document;
its §13 milestone row M4 ("Gateway plan drafted") is met by it, and M4′ above defines what
"gateway delivered" means.
