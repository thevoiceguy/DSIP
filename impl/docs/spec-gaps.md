# Spec-gap issue drafts (v0.6 → v0.7 worklist)

Each entry is the text of a `spec-gap` issue, per plan §11 and the CLAUDE.md
documentation standard. Numbers match the `Impl (spec-gap N)` comments in
`impl/tools/dsipvec/` and the Rust crates, and the list in
`impl/vectors/README.md`. Vectors named here pin the PoC's choice; if the spec
resolves differently, the vector changes first, then the code.

## v0.7 worklist (dispositions)

**Status (2026-08-21):** every disposition below is transcribed into `v0.7/dsip_v_0_7_decentralized_session_initiation_protocol.md` (changelog Appendix A.4) and pinned by the 298-vector v0.7 suite.

Status of every gap as input to the v0.7 assembly. *Disposition* is what v0.7 should say;
for gaps 1–13 it is the **Suggested fix** already recorded under each entry. Gaps 14–22
carry an explicit **v0.7 disposition** paragraph (added 2026-08-21). "adopt" = make the PoC
choice normative as written; "adopt-with-change" = normative text differs from the PoC and the
vectors change first. No gap is awaiting a decision.

| # | sections | disposition | pinned by |
|---|---|---|---|
| 1 | §12.4, §12.5 | adopt (crossed vs late cancel) | `state/race-responder-*` |
| 2 | §12.6 | adopt (suggested fix) | `state/glare-*` |
| 3 | §12.8 r4 | adopt (suggested fix) | `state/update-second-outstanding` |
| 4 | §12.9 | adopt (suggested fix) | `state/t-ring-*` |
| 5 | §12.7 r3, §12.4 | adopt (suggested fix) | `state/fork-*` |
| 6 | §20.6 | adopt (300 s, reject) | `envelope/ulid-*` |
| 7 | §12.9 | adopt (symmetric window) | `envelope/replay-future` |
| 8 | §7.4 | adopt (header `delegations`) | `envelope/delegation-in-header` |
| 9 | §14.2 | adopt (suggested fix) | `semantic/selection-*` |
| 10 | §15.4 | adopt (warning, not reject) | `payload/reject-*` |
| 11 | §12.10 | adopt (suggested fix) | `state/queue-*` |
| 12 | §12.4, §12.7 | adopt (`session.failed`) | `state/answer-after-reject` |
| 13 | §12.4 | adopt (drop ENDING) | all state traces |
| 14 | §19.4, §13.2 | adopt | `state/relay-introduction-anti-enumeration` |
| 15 | §19.4 | adopt | `state/first-contact-*` |
| 16 | §12.12, §16.3, §26 | adopt → **WebRTC Media Binding** (`v0.7/dsip-webrtc-media-binding-v0.7.md`) | `payload/info-*` incl. `info-webrtc-missing-mid` (binding schema, v0.7), `state/info-active-only` |
| 17 | §13.2, §13.3, §12.7 | adopt | `state/relay-store-and-forward-*`, `state/relay-*-queued-*` |
| 18 | §22.1 | adopt | `broadcast/publication-*` |
| 19 | §9.3, §9.4 | adopt (refuse over-cap with `error policy.subscription-lifetime`; authority-asserted presence) | `state/broadcast-authority-presence`, `semantic/subscribe-presence-over-cap` (carries the token since v0.7) |
| 20 | §22.2 | **adopt-with-change** (record-level `integrity`) — done in v0.7 vectors | `broadcast/publication-integrity-*` (3, v0.7), `broadcast/publication-valid-metadata-only`, `broadcast/provenance-derivative-bound` |
| 21 | §22.3 | adopt; `provenance` is a core message with a spec schema — done in v0.7 vectors | `broadcast/provenance-*`, `payload/provenance-*` (v0.7) |
| 22 | §7.5 | adopt (c): DID document authoritative + `key-rotation` record defined — schema + checks in v0.7 | `envelope/rotated-did-web-*`, `envelope/key-rotation-signed-by-previous-key`, `payload/key-rotation-*`, `semantic/key-rotation-*` (v0.7) |
| 23 | §15.5, §6.3 | adopt → **Gateway Profile 1.0** (`v0.8/dsip-gateway-profile-v0.8-draft.md`) | `gateway/*` (53) |
| 24 | §15.5 | adopt (`Reason: DSIP;text=`) | `gateway/reason-outbound-*`, `gateway/trace-*` |
| 25 | §18.1, §24.2 | adopt; register `tel` claim type | `gateway/claims-*` |
| 26 | §12.12 | **open** (DTMF `info` binding — future revision) | — (round one does not forward DTMF) |
| 27 | §6.3 | adopt (named downgrade losses) | `gateway/downgrade-*` |
| 28 | §15.5, App. C | adopt (per-trunk early-media policy) | `gateway/trace-outbound-early-media*` |
| 29 | §12.7 | adopt (single contact; no SIP→DSIP forking in v1) | `gateway/trace-*` |
| 30 | §17.2, §24.4 | adopt → **RTP/SRTP Media Binding 1.0** (`v0.8/dsip-rtp-srtp-media-binding-v0.8-draft.md`) | G§6 (`gateway/sdp-*`) |

---

## 1. §12.4 vs §12.5 — responder in ACTIVE receiving `cancel`

**Conflict.** The §12.4 responder table says `ACTIVE` + `Recv cancel` → send
`error` (`session.invalid-state`), session continues. §12.5 rule 2 says a
responder that has already sent `answer` when `cancel` arrives MUST treat the
session as ended and MUST NOT treat the crossed cancel as an error. Both rows
fire on the same input.

**Choices considered.** (a) Always error (table wins) — breaks the race rule.
(b) Always tear down (rule wins) — lets a stale/forged-path cancel kill an
established call. (c) Distinguish "crossed" from "late" by whether the
initiator has been observed post-answer.

**PoC choice.** (c): a cancel received in ACTIVE before any initiator message
has arrived since our answer is treated as crossed (teardown, no error); after
the initiator has spoken post-answer (`info`, `update`, `bye`, an update
reply), cancel is `session.invalid-state`. Vectors:
`state/race-responder-crossed-cancel`,
`state/race-responder-cancel-after-post-answer-traffic`.

**Suggested fix.** Add the distinguishing condition to both §12.4 and §12.5,
or define that the initiator MUST NOT send `cancel` after accepting an answer
except `session.answered-elsewhere` addressed to the identity, and that
responders in ACTIVE MUST ignore `session.answered-elsewhere` silently.

## 2. §12.6 — who sends `reject session.glare`, and with which message

**Ambiguity.** "The endpoint whose invite lost MUST send `reject` with reason
`session.glare` for the losing invite." The loser cannot `reject` its own
invite (`reject` is a responder message); the winner "ignores the glare
condition", so nobody withdraws the losing invite at the winner's side.

**PoC choice.** The loser withdraws its own invite with `cancel
session.glare` (the initiator's withdrawal verb; §15.4 lists `session.glare`
as valid on `cancel`) and proceeds as responder. The winner rejects the
inbound losing invite with `reject session.glare`. Both legs of the losing
invite therefore end deterministically whichever message arrives first.
Vectors: `state/glare-we-win`, `state/glare-we-lose`, `state/glare-equal-ids`.

## 3. §12.8 rule 4 — "processes neither"

**Ambiguity.** A second `update` from the same sender while its first is
outstanding yields `error session.update-pending` "and processes neither".
Does the first update remain outstanding?

**PoC choice.** Literal reading: both are discarded; the session has no
outstanding update afterwards. Vector:
`state/renegotiation-second-update-same-direction`.

## 4. §12.9 — T-Ring restart semantics; what bounds PROCEEDING after `trying`

**Gaps.** (a) T-Ring is "started on first `progress` with status `ringing`";
the PROCEEDING row says later `progress` "adjusts timers per §12.9" without
saying how. (b) T-Establish is "stopped by first `progress`" of any status,
but nothing starts on `trying`/`forwarded`, so PROCEEDING is unbounded until
the relay signals an outcome.

**PoC choice.** A `ringing` progress carrying `ring_timeout` (re)starts T-Ring
at `clamp(ring_timeout, 30, 300)`; a `ringing` without it starts T-Ring only
if none is running. A non-ringing, non-queued progress starts T-Ring (default)
as a backstop when neither T-Ring nor T-Queue runs. Vectors:
`state/timer-t-ring-extension-honored`, `state/timer-repeat-ringing-no-restart`,
`state/timer-trying-backstop`.

## 5. §12.7 rule 3 / §12.4 — when does the initiator know an invite was forked?

**Gap.** §12.4 says "if forked, send `cancel`"; §12.7 rule 3 says the
initiator MUST send it unconditionally. The initiator cannot observe forking.

**PoC choice.** Send `cancel session.answered-elsewhere` to the invite's `to`
when the accepted answer's `from` differs from `to` (identity-addressed
delivery may have forked); do not send it when the invite addressed the
answering device directly. Vectors: `state/fork-first-answer-wins`,
`state/direct-device-call-no-fork-cancel`.

## 6. §20.6 — ULID/`issued_at` consistency tolerance

**Gap.** "SHOULD verify … MAY reject on gross mismatch" defines neither the
tolerance nor the verdict. **PoC choice.** Reject when the ULID timestamp
component differs from `issued_at` by more than the 300 s replay window.
Vectors: `envelope/ulid-backdated`, `envelope/ulid-within-tolerance`.

## 7. §12.9 — future-dated `issued_at`

**Gap.** Replay window text rejects envelopes "older than the window" only.
**PoC choice.** Symmetric window: `issued_at` more than 300 s in the future
is also rejected. Vector: `envelope/replay-window-future`.

## 8. §7.4 — conveying delegation credentials to a verifier

**Gap.** §7.4 shows the DeviceDelegation object but not how a verifier
obtains it for a `did:key` identity (which has no DID document to host it).
**PoC choice.** A delegation is a DSIP-JOSE envelope over the DeviceDelegation
object, signed directly by a key of the subject (no chains). Verifiers accept
delegations from a local store and from an optional `delegations` array in
the envelope's protected header. Vectors: `envelope/delegation-*`.

## 9. §14.2 / schema README check 9 — subset semantics

**Gap.** "Selections are subsets of the referenced offer" is not defined per
field. **PoC choice.** Match descriptors on `type`+`purpose`; codecs by `id`
⊆ offered; SDP-style direction answers; the single transport `id` ∈ offered.
Vectors: `semantic/selection-*`.

## 10. §15.4 — registered token on a message type it is not listed as valid on

**PoC choice.** Accept with a `reason-not-valid-on-type` warning rather than
reject; the registry column reads as guidance for senders. Vector:
`semantic/reason-not-valid-on-type`.

## 11. §12.10 — re-queue limit exceeded

**PoC choice.** The fourth consecutive `queued` is treated as T-Queue expiry
(`cancel session.timeout`). Vector: `state/timer-t-queue-requeue-limit`.

## 12. §12.4/§12.7 — `bye` reason for an answer after a terminal `reject`

**Gap.** `session.cancelled` covers answers crossing a cancel;
`session.already-answered` covers late legs of an established session. No
token covers an answer arriving after the attempt ended by `reject`.
**PoC choice.** `bye session.failed`. Vector:
`state/initiator-rejected-while-proceeding`.

## 13. §12.4 — ENDING

**PoC choice.** ENDING is collapsed into ENDED; the reference engine's local
teardown is synchronous. A future media-bound implementation may surface
ENDING as an observable state without changing any emission.

## 14. §19.4 vs §13.2 — relay handling of introductions to unknown recipients

**Conflict.** §13.2: "A relay MUST NOT silently drop envelopes on a live connection … it MUST
respond with a signed `error` (`transport.unknown-recipient` …)". §19.4: "an introduction to a
nonexistent identity and an ignored introduction are indistinguishable to the sender." A relay
that answers `transport.unknown-recipient` to an introduction is an enumeration oracle.

**PoC choice.** For `introduction` only, the relay queues the envelope for the addressed identity
whether or not it knows it (bounded per-inbox, until the introduction's `expires_at`) and returns
nothing; bound devices receive it immediately; a later `hello` binding flushes the queue. All
other message types keep the §13.2 error. Vector: `state/relay-introduction-anti-enumeration`.

**Suggested fix.** Add to §13.2: "except for `introduction`, where §19.4 anti-enumeration
governs: the relay MUST accept without a routing error regardless of recipient existence."

**v0.7 disposition.** Adopt. §13.2: append to the MUST-NOT-silently-drop rule — "except
`introduction`, which §19.4 governs: a relay MUST accept an introduction for any recipient
without a routing response, MAY hold it (bounded per recipient) until its `expires_at`, and
MUST deliver it on the recipient's next binding." §19.4: state the bound (PoC: 16 per inbox)
as a SHOULD with a registry-free deployment knob. No vector change.

## 15. §19.4 — grant matching, scope, and contact-token semantics

**Gaps.** (a) Whether the optional `grant` field in an invite is required for a relay/endpoint to
honor a grant, or whether holding a grant for the inviting identity suffices. (b) Whether a grant
whose `scope` lacks `dsip.invite` admits invites. (c) Whether a contact token is single-use.

**PoC choice.** A live grant admits an invite when matched by `grant` id **or** by grantee
identity; `scope` MUST contain `dsip.invite`; a token auto-grants once and is then consumed.
Vectors: `state/first-contact-responder-grant`, `state/first-contact-grant-scope`,
`state/first-contact-contact-token`.

**v0.7 disposition.** Adopt all three. §19.4 text: (a) "A live grant admits an invite when
the invite's `grant` names it **or** the inviting identity is the grantee; the `grant` field is
an optimisation for stateless relays, never a requirement." (b) "A grant admits only the
operations in `scope`; an invite requires `dsip.invite`." (c) "A contact token is single-use:
the first invite carrying it is auto-granted and the token is consumed; multi-use tokens are a
deployment extension." No vector change.

## 16. §12.12 / §16.3 — the WebRTC Media Binding document does not exist

**Gap.** §12.12 says the `info.data` structure for `transport:webrtc` "is normative in the
WebRTC Media Binding document" and §16.3 says SDP may ride as a transport binding object; no
such document is in the repository, and §26 step 8 still says candidates ride in `update`.

**PoC choice.** `transports[].sdp` on `invite`/`update`/`answer` carries the SDP offer/answer
(the descriptor keeps `id: transport:webrtc`, `ice: trickle`); trickle candidates ride in
`info.data.candidates[{candidate, sdp_mid, sdp_m_line_index}]` + `end_of_candidates`, exactly
the §12.12 example shape; `info` is ACTIVE-only so candidates gathered before the answer are
buffered by the endpoint. Implemented in `dsip-endpoint` and `demos/browser/app.js`.

**Suggested fix.** Publish the binding document (or an appendix) with these shapes, fix §26
step 8 to say `info`, and state whether a forked invite's single SDP offer may be answered by
more than one leg (the PoC accepts only the first answer; later legs get `bye`).

**v0.7 disposition.** Adopt the PoC shapes and publish them as the **WebRTC Media Binding**
companion document — drafted at `v0.7/dsip-webrtc-media-binding-v0.7.md` (binding id
`transport:webrtc`, version 1.0). Spec edits: §12.12 "normative in the WebRTC Media Binding"
→ cite the document by id; §16.3 replace the `transport_binding: {type, sdp}` example with the
`transports[].sdp` descriptor form and the authority rule (descriptors govern *what* is
negotiated, SDP governs transport parameters); §26 step 8 `update` → `info`; §17.2 name the
binding. Forking: "exactly one answer is applied per invite; a later answer is released with
`bye session.already-answered`" moves into §12.7. ICE restart is explicitly out of scope for
binding 1.0. Vectors: the binding's `info.data` schema (Appendix A of the draft) becomes a
payload vector set in the v0.7 suite.

## 17. §13.2 / §13.3 — what a store-and-forward relay may call an unknown recipient

**Gap.** §13.2 requires `transport.unknown-recipient` when the relay "has no route"; §13.3
makes reaching offline devices the relay's job. A relay with store-and-forward therefore needs
a rule for *offline* versus *unknown*, and for what happens when a held envelope expires.

**PoC choice.** A recipient is *known* if any device has bound (`hello`) for it on this relay;
known-but-offline envelopes are queued until `min(expires_at, offline_retention_s)` and flushed
in order on the next binding (queued invites become tracked legs; a device binding while an
attempt is live becomes a leg mid-attempt, §12.7 rule 3). Expiry dequeues silently — the
initiator's §12.9 timers are the backstop — and an initiator `cancel` drops a still-queued
invite. Never-seen recipients still get `transport.unknown-recipient` (introductions excepted,
gap 14). Vectors: `state/relay-store-and-forward-known-offline`,
`state/relay-queued-invite-expires`, `state/relay-cancel-drops-queued-invite`,
`state/relay-leg-added-mid-attempt`, `state/relay-bye-queued-for-reconnecting-device`,
`state/relay-retention-cap`.

**Suggested fix.** Define "known" in §13.3, state that expiry of a held envelope is not
signaled (or define an `error` for it), and add the mid-attempt leg case to §12.7 explicitly.

**v0.7 disposition.** Adopt. §13.3 defines *known*: "an identity for which a device has
completed a verified `hello` at this relay within the relay's retention window"; store-and-
forward applies only to known identities, `transport.unknown-recipient` to all others (gap 14
excepted). Expiry of a held envelope is **not** signalled — the initiator's §12.9 timers are the
backstop; a held `invite` whose `cancel` arrives is dropped with no leg ever created. §12.7 rule
3 gains the mid-attempt leg sentence: "a device that binds while an attempt is live becomes a
leg of that attempt if the invite is still unexpired." Retention cap is a SHOULD with the PoC
default (24 h). No vector change.

## 18. §22.1 — who may publish a stream, and stream_id ownership

**Gap.** The record carries `from` and `publisher`; nothing says they must agree with the
signature, nor who may update or withdraw a stream, nor how `stream_id` relates to the publisher.

**PoC choice.** `publisher` MUST equal the verified identity (signer or its delegator); `stream_id`
MUST be the publisher DID or a colon-suffixed extension of it; a record with a lower ULID than the
held one is stale; `unpublish` MUST be signed by the same identity and name the held
`publication`. Vectors: `broadcast/publication-publisher-mismatch`,
`broadcast/publication-stream-outside-namespace`, `state/broadcast-authority-publisher-binding`.

**v0.7 disposition.** Adopt as §22.1 normative text: "`publisher` MUST equal the verified
signing identity (the signer, or the delegator of a delegated device); `stream_id` MUST be the
publisher DID or a colon-suffixed extension of it; a `publish` whose `id` is ULID-older than
the held record for the same `stream_id` is stale and ignored; `unpublish` MUST be signed by
the same identity and MUST name the held `publication`." No vector change.

## 19. §9.3 — presence subscriptions: what the authority knows

**Gap.** §9.4 defines signed presence records but not how an authority learns presence.
**PoC choice.** Presence for an identity derives from whether any of its devices is bound at the
authority (`available` / `offline`); presence bodies are authority-asserted, not subject-signed;
targets the authority has never seen get the uniform `policy.blocked`. Vectors:
`state/broadcast-authority-presence`, `state/broadcast-authority-caps-renewal-terminate`.

Also: §9.3 calls the per-event lifetimes "hard caps" without saying whether an over-cap
`expires_in` is refused or clamped. The PoC refuses it at the stateless boundary
(`subscription-lifetime-exceeded`, vector `semantic/subscribe-presence-over-cap`) and the
authority additionally clamps as defense in depth.

**v0.7 disposition.** Adopt, with the two models named. §9.4 keeps subject-signed presence
records as the privacy-preserving form; §9.3 adds: "An authority that has no subject-signed
record MAY assert presence from its own device bindings (`available` when any device of the
target is bound, else `offline`); such bodies are authority-asserted and clients MUST render them
as the authority's claim." Over-cap `expires_in` is **refused** at the stateless boundary with
`error policy.subscription-lifetime` — v0.7 registers that token (PoC verdict code
`subscription-lifetime-exceeded`); clamping is not permitted because it makes the caller's view
of its own subscription wrong. Vector change: none for the refusal; the new token lands in the
`dsip-reason` registry and `semantic/subscribe-presence-over-cap` gains the `reason` field.

## 20. §22.2 — where the integrity mode is stated

**Gap.** §22.2 defines `metadata-only` / `derivative-bound` but the `publish` schema is closed and
has no field for it. **PoC choice.** Variants carry `integrity` (variants allow extra
properties); a verified transcode statement makes the receiver display `derivative-bound`.

**v0.7 disposition.** Adopt-with-change. The PoC's per-variant `integrity` is a workaround
for a closed schema; v0.7 adds a **record-level** `integrity` field to `publish` (string,
registry `dsip-integrity-mode`, initial values `metadata-only`, `derivative-bound`) with an
optional per-variant override. Vectors change first: `broadcast/publication-valid-metadata-only`
and `broadcast/provenance-derivative-bound` move the field up a level; `generate_schemas.py`
gains the property; receivers treat an absent field as `metadata-only`.

## 21. §22.3 — how provenance statements reach receivers

**Gap.** §22.3 shows the statement but not its carriage. **PoC choice.** Processors send the
statement (type `broadcast.provenance`, extension `broadcast-provenance/1.0`, impl-local schema)
to the publisher's authority, which attaches processors to the record and lists them in
`notify.body.provenance`; the CLI receiver fetches statements alongside the record. Vectors:
`broadcast/provenance-*`, `state/broadcast-authority-provenance`.

---

**v0.7 disposition.** Adopt the carriage (processor → authority → `notify.body.provenance`)
and promote the statement to a spec message: `provenance` joins §22.3 with the PoC's impl-local
schema as its normative schema (`broadcast-provenance/1.0` stops being an extension id). Direct
receiver ↔ processor fetch remains permitted as an alternative path; either way the statement is
verified against the processor's identity and the publication's `policy` (§16.4). Vector change:
the `broadcast/provenance-*` vectors drop the extension declaration from `dsip.extensions`.

## 22. §7.5 — key rotation has requirements but no wire format

**Gap.** §7.5 says the protocol "defines, at minimum" a previous key, new key, rotation
timestamp, signature by the previous key (or a recovery signature), revocation reason, device
list update, and replay protection — but no message, record, or schema carries these, and no
section says how a verifier learns of a rotation. §7.6 (recovery models) is explicitly
deployment-specific and §7.7 (transparency) is optional, so nothing else fills the hole.

**Choices considered.** (a) Define a DSIP `KeyRotation` record (DSIP-JOSE envelope signed by
the previous key when available, else by a recovery key; carries the fields §7.5 lists; ULID +
`issued_at` give replay protection) and have DID methods / transparency logs publish it.
(b) Delegate rotation entirely to the DID method: the DID document *is* the rotation state
(§8.1 rule 4), and §7.5's list becomes guidance for what a method's update must capture.
(c) Both: the DID document is authoritative for verification (as today), and the record is the
audit artifact that §7.7 logs and that clients display as trust metadata.

**PoC choice.** The verifier-observable consequences only, derived from §8.1 + §7.4: after a
`did:web` document replaces `#key-1` with `#key-2`, signatures under the new kid verify, the
retired kid is `kid-unresolvable`, a delegation re-issued by the new key admits the device, and
a delegation signed by the retired key is `delegation-invalid`. No rotation record exists in
the PoC. Vectors: `envelope/rotated-did-web-new-key-signs`,
`envelope/rotated-did-web-retired-kid-rejected`, `envelope/rotated-did-web-new-key-delegation`,
`envelope/rotated-did-web-old-key-delegation-rejected`.

**Suggested fix.** (c). Keep the DID document authoritative — the vectors above then stand
unchanged — and define the record as the §7.5 artifact with a schema, so §7.7 has something to
log and clients have something to show. State explicitly that `did:key` identities cannot rotate
(the DID is the key) and that rotation for them means a new identity plus a signed
`identity.moved` pointer.

**v0.7 disposition.** **(c), decided 2026-08-21.** The DID document stays authoritative for
verification (§8.1; the vectors above stand unchanged) and v0.7 defines the `KeyRotation` record
with a schema as the §7.5 artifact — what §7.7 logs and clients show as trust metadata. `did:key`
identities cannot rotate; v0.7 says so and points to `identity.moved`.

## 23. §15.5 / §6.3 — the Gateway Profile does not exist

**Gap.** §15.5 gives an "informative initial mapping" and says "the normative table belongs to the
gateway profile"; §6.3 states the trust-downgrade principle but no mechanism. No Gateway Profile
document exists.

**PoC choice.** `impl/crates/dsip-gateway` implements the full B2BUA rule set — reason mapping both
directions, PSTN caller claims, SDP↔descriptor mapping, the downgrade rule, early media, the
controller state machine — all pinned by the 53 `gateway/` vectors. Written up as
**DSIP Gateway Profile 1.0** (`v0.8/dsip-gateway-profile-v0.8-draft.md`).

**Suggested fix.** Adopt the profile draft as a named conformance piece (§24.4); make §15.5's table
normative there and leave §15.5 in core as the pointer.

## 24. §15.5 — the DSIP reason should stay visible across a SIP crossing

**Gap.** §15.5 says map foreign codes to DSIP reasons; it does not say the DSIP reason should be
preserved *on* the SIP message so a capture or downstream element can see the original token.

**PoC choice.** Every SIP crossing carries `Reason: DSIP;text="<token>"` (RFC 3326) in addition to
any `Q.850;cause=`. Vectors: `gateway/reason-outbound-*`, `gateway/trace-*`.

**Suggested fix.** State the `Reason: DSIP` convention in the Gateway Profile (G§3).

## 25. §18.1 — no claim type for a PSTN caller identity

**Gap.** §18.1 requires clients to display a verification *basis*; a gateway presenting a PSTN
caller has no registered claim shape to carry the number, STIR attestation, and verification
outcome.

**PoC choice.** A `tel` claim `{type, number, attestation, verified, verifier, cnam?}` in the
invite's `identity.claims`, rendered as "Gateway attested by <did> · STIR attestation <A|B|C>
(verified|unverified)" or "· no attestation"; a PASSporT whose `orig` ≠ `From` is discarded.
Vectors: `gateway/claims-*`.

**Suggested fix.** Register `tel` in a DSIP claim-types registry (§24.2) with this shape.

## 26. §12.12 — DTMF has no DSIP carriage

**Gap.** DSIP Core v1.0 has no DTMF semantics; a gateway bridging RFC 2833 telephone-event has
nowhere to put digits on the DSIP side.

**PoC choice.** Round one does not forward DTMF across the gateway. The natural vehicle is a signed
`info` (§12.12) with a gateway-defined `about` (`x-gateway:dtmf`).

**Suggested fix.** Define a DTMF `info` binding (`about` value + `data` schema) in a future
revision; register the `about` in `dsip-info-about`.

## 27. §6.3 — `gateway.downgraded` trigger conditions are undefined

**Gap.** `gateway.downgraded` is a registered reason (§15.4) but §6.3 does not say when a gateway
emits it.

**PoC choice.** One informational `error` per crossing that loses a guarantee, naming each loss:
`no-srtp-on-trunk`, `identity-not-assertable`, `no-attestation`, `policy-unenforceable`. Vectors:
`gateway/downgrade-*`.

**Suggested fix.** State the trigger set in the Gateway Profile (G§7).

## 28. §15.5 / Appendix C — early-media handling needs a rule

**Gap.** §15.5 and Appendix C describe early media in prose ("classify announcements … otherwise
answer the DSIP leg and pass audio through") without a rule.

**PoC choice.** Per-trunk `pass-early-media` ∈ {auto, always, never}, default auto (classify to a
reason if possible, else answer `answered_by: gateway` and bridge). Vectors:
`gateway/trace-outbound-early-media*`.

**Suggested fix.** Adopt the rule in the Gateway Profile (G§8).

## 29. §12.7 — may a gateway forward SIP forking as DSIP forking?

**Gap.** SIP 3xx and parallel forking have no stated mapping to DSIP forking (§12.7 is a
relay-side, identity-addressed mechanism).

**PoC choice.** A gateway follows a single SIP contact and does **not** forward SIP 3xx as DSIP
forking in round one; glare (§12.6) cannot cross (the two sides are distinct sessions).

**Suggested fix.** State single-contact behaviour in the Gateway Profile; leave multi-contact
follow as a later extension.

## 30. §17.2 / §24.4 — the RTP/SRTP Media Binding does not exist

**Gap.** §17.2 names "RTP/SRTP binding for SIP and telecom gateways" and §24.4 lists
`DSIP RTP/SRTP Media Binding 1.0` as a conformance piece; no document defined it.

**PoC choice.** `transport:rtp` with SDES/DTLS keying, the §17.2 encryption floor plus a
plain-RTP exception behind an operator-vouched trunk (with `gateway.downgraded`), and the PSTN
codec set. Written up as `v0.8/dsip-rtp-srtp-media-binding-v0.8-draft.md`.

**Suggested fix.** Adopt the binding draft; align it with the WebRTC binding's descriptor/SDP
authority rule.

## v0.8 messaging worklist (gaps 31–43)

**Status (2026-09-15):** filed with the **DSIP Messaging Profile 1.0** draft
(`v0.8/dsip-messaging-profile-v0.8-draft.md`, cited M§n). Unlike gaps 1–30, these were not found
by implementing. They are the choices the profile draft makes before implementation, per the
decisions taken 2026-09-15: companion profile, MLS plus HPKE, SYNC history by default, groups in
1.0. Every row is **open** until the profile text and its vectors agree; "draft choice" is what the profile
text says today. Tranche 1 of `messaging/` (101 vectors, 2026-09-15: message/object rules, hub
and mailbox traces) pins gaps 34–36, 38, 40 and 43 at Rust/Python parity. Tranche 2 (46 vectors: voicemail offer, conversation and successor
convergence, client receipts/watermarks/activity, seq gaps) pins 41 and 42. Tranche 3 (38 vectors: MLS extension encoding, leaf authentication, `dsip_conversation`
bytes, AES-GCM formats) pins 33 and 39, and `impl/crates/dsip-mls` runs the profile on OpenMLS end to end. Gap 31 is a v0.7 defect in its own right and does not depend on messaging.

| # | sections | draft choice | pinned by |
|---|---|---|---|
| 31 | §12.9, §13.3, §19.4 | **adopted in the PoC** (2026-09-15): type-scoped validity for held introductions + enforced 7-day cap (**v0.7 defect**) | `envelope/introduction-held-*` (3), `envelope/introduction-future-rejected`, `envelope/introduction-validity-over-cap` |
| 32 | §3.2, §6.1, §12.1, §24.4 | adopt → **Messaging Profile 1.0** + **Mailbox 1.0** conformance pieces | `messaging/*` (101, tranche 1) |
| 33 | §6.2, §20.7 | MLS for conversations, HPKE for sealed introductions; non-repudiation stated | `messaging/mls-credential-*` (13), `dsip-mls` e2e (OpenMLS) |
| 34 | (new; M§6.5) | per-group hub orders MLS commits | `messaging/hub-*` (19) |
| 35 | (new; M§12) | archive key in the personal group; `sync` default, `queue` opt-out | `messaging/mailbox-archive-*`, `messaging/mailbox-sync-mode-retains-after-ack`, `messaging/mailbox-queue-mode-*` |
| 36 | §19.4 | `dsip.message` scope; `sealed` introductions; grant-gated group adds; invite-grantee voicemail | `messaging/mailbox-welcome-*` (11), `messaging/mailbox-key-package-fetch-unauthorized` |
| 37 | §8.1, §13.2, DHT Hints | `DSIPMailbox` service type; hint `service`; priority-ordered multiple mailboxes | `messaging/mailbox-select-*` (11), `messaging/mailbox-switch-*` (3), `messaging/mailbox-service-*` (3) |
| 38 | §15.1 | new reason category `mailbox` | `messaging/deposit-unknown-class-refused`, `messaging/mailbox-*` error tokens |
| 39 | §7.4, §24.2 | delegation capability `dsip.messaging` + a delegation-capability registry | `messaging/mls-credential-signaling-only-delegation`, `dsip-mls` e2e |
| 40 | §13.2 | `MAX_MLS_BYTES` = 24,576; blobs over HTTPS | `messaging/deposit-mls-at-cap-accepted`, `messaging/deposit-mls-over-cap-refused` |
| 41 | §12, §14 | caller-recorded voicemail; trigger set; no core field | `messaging/voicemail-offer-*` (16) |
| 42 | §12.6, §20.6 | duplicate direct conversations / successor groups: lower ULID wins | `messaging/direct-select-*`, `messaging/successor-*` |
| 43 | (new; M§11) | activity keyed by the MLS exporter, not the secret tree | `messaging/deposit-ephemeral-*`, `messaging/hub-ephemeral-*`, `messaging/mailbox-ephemeral-pushed-never-stored` |

## 31. §12.9 vs §13.3 / §19.4 — the replay window rejects held envelopes

**Gap.** §12.9 requires rejecting any envelope whose `issued_at` is more than 300 s old. §19.4
gives introductions up to 7 days of validity "because the recipient may be offline for days", and
§13.2/§13.3 have relays hold them until the recipient's next binding. A held introduction delivered
more than 300 s after signing therefore fails the recipient's replay check. The PoC confirms it:
`dsip-core::envelope::verify` applies `REPLAY_WINDOW_S` to every envelope with no type exemption.
No vector exercises recipient-side verification of a held introduction, which is why the suite is
green. Held `invite`s are unaffected in practice (their validity is 30 s).

**Choices considered.** (a) Type-scoped validity: for `introduction`, replace the age bound with
`now < expires_at` (keeping the future bound) and deduplicate its `id` until `expires_at`. Memory
stays bounded by the 7-day cap and the per-recipient inbox bound of 16. (b) The relay re-wraps held
envelopes in a fresh relay-signed envelope, which changes what the recipient verifies and makes the
relay a signer of third-party content. (c) Shorten introduction validity to 300 s, which defeats
store-and-forward.

**Draft choice.** (a). The Messaging Profile sidesteps the issue by construction: mailboxes deliver
stored bytes inside fresh `items` envelopes (M§5.1) and authenticate content with MLS. It does not
fix core.

**PoC choice (2026-09-15).** (a), plus enforcing the §19.4 cap, which nothing enforced before.
Without the cap the relaxed age bound would let an introduction claiming a year of validity stay
replayable, with its id tracked, for a year. Envelope stage 9 for `introduction`:
`expires_at − issued_at > 604,800` → `introduction-validity`; `issued_at > now + 300` →
`replay-window`; `expires_at < now` → `expired`. Receivers track the id until `expires_at`
(`dsip-endpoint::verify::SeenIds`). Every other type keeps the symmetric 300 s window. Vectors:
`envelope/introduction-held-accepted` (delivered at +2 days), `introduction-held-replayed`,
`introduction-held-expired`, `introduction-future-rejected`, `introduction-validity-over-cap`.
The existing `introduction-valid-7-day` pins the cap edge and `replay-window-too-old` pins that
invites are unaffected.

**Suggested fix.** State (a) and the enforced cap in §12.9 and §19.4 for v0.8.

## 32. §3.2 / §6.1 / §12.1 / §24.4 — no Messaging Profile exists

**Gap.** §6.1 defers messaging to "a future DSIP Messaging Profile, or reuse MIMI/MLS concepts";
§3.2 lists full messaging interoperability as out of scope for Core v1.0. No profile, message
types, or conformance piece exists.

**Choices considered.** (a) A companion profile with its own message types and conformance pieces,
like the Gateway Profile. (b) Fold a mailbox into core as a fourth core service. That reverses the
v0.5 scope correction (Appendix A.1) and §5.1.

**Draft choice.** (a): `messaging/1.0`, message types `deposit`, `accepted`, `sync`, `items`,
`key-packages`, `key-package-fetch`, `blob-put`, `mailbox-config` (outside the §12.1 session set,
as `reachability-hint` is), and conformance pieces `DSIP Messaging Profile 1.0` and
`DSIP Mailbox 1.0`.

**Suggested fix.** Add both pieces to §24.4. Add a §12.1 sentence naming profile message types
alongside `reachability-hint`. Replace §6.1's deferral with a pointer to the profile.

## 33. §6.2 / §20.7 — asynchronous traffic needs end-to-end encryption

**Gap.** §20.7: payloads are signed, not encrypted; a relay can read them. That is tolerable for
call signaling but not for stored messages. §6.2 says to consider MLS before inventing group key
management.

**Choices considered.** (a) MLS (RFC 9420): devices as leaves, groups, FS/PCS, IETF standard,
permissively licensed Rust implementations (OpenMLS, mls-rs), and the choice of MIMI and RCS
Universal Profile 3.0. It needs an ordering authority (gap 34). (b) The Signal Protocol
(PQXDH + Double Ratchet, sender keys for groups): excellent pairwise and deniable, but it is
implementation-defined rather than a standard (libsignal is AGPL-3.0), and multi-device and group
membership lean on central servers. (c) HPKE to each device: simple, but no FS and no group
machinery.

**Draft choice.** (a) for all conversations (M§6), with credentials bound to §7.4 delegations and
leaf signature key = device Ed25519 key. (c) only to seal introduction text (M§6.9). Messages are
non-repudiable, and the profile says so (M§6.10).

**Suggested fix.** In §20.7, keep the signaling limitation and add that the Messaging Profile's
content is end-to-end encrypted. In §6.2, record the MLS adoption.

## 34. MLS commit ordering needs an authority

**Gap.** MLS members must apply one commit per epoch. Concurrent commits fork a group, and forks
cannot be merged. RFC 9420 leaves ordering to a Delivery Service, which DSIP does not define.

**Choices considered.** (a) One hub per group, named in an authenticated GroupContext extension,
accepting the first valid commit per epoch (MIMI's hub model). (b) Leaderless: members pick among
conflicting commits deterministically (e.g. lowest hash), which needs fork detection and rollback
and still loses messages sent on the losing branch. (c) Consensus among member mailboxes, which is
too heavy for a profile and introduces Sybil questions.

**Draft choice.** (a) (M§6.5). The creator's primary mailbox is hub by default. The hub can be moved
by commit (M§7.4). If it dies, a successor group takes over (M§7.5). Hub powers and limits are
stated in M§15.3.

**Suggested fix.** Adopt in the profile; nothing in core.

## 35. New-device history versus forward secrecy

**Gap.** With MLS a device added today cannot decrypt earlier messages. The user requirement
(2026-09-15) is SYNC: history on new devices.

**Choices considered.** (a) An identity-level archive key, distributed in a personal MLS group, used
by devices to re-encrypt decrypted content into mailbox-stored archive records. This gives up
forward secrecy of stored history. (b) Device-to-device history transfer at add time, which needs a
surviving device online and holding the full history. (c) No history (`queue`). (d) Mailbox-side
plaintext (rejected: violates the untrusted-mailbox principle).

**Draft choice.** (a) as default `sync` mode, with (c) as opt-in `queue` mode (M§4.4, M§12). The
first archive per (group, seq) wins at the mailbox. The archive key is rotated on device removal.
The trade is stated normatively (M§15.2).

**Suggested fix.** Adopt in the profile; recovery-escrow of the archive key goes into §7.6
deployment guidance.

## 36. §19.4 — first contact for messaging

**Gap.** §19.4's grant scopes are `dsip.invite` and `dsip.subscribe`; nothing authorizes messaging.
Introduction `purpose` is plaintext to relays. Nothing says who may add an identity to a group.

**Choices considered.** For authorization: (a) new scope `dsip.message`; (b) reuse `dsip.invite`
for everything. For sealing: (a) optional HPKE `sealed` replacing `purpose`, keyed to the DID
`keyAgreement` key; (b) leave introductions plaintext. For group adds: (a) the adder must hold a
`dsip.message` grant from the added identity, or the added identity's mailbox admits `open`;
(b) any member may add anyone (spam vector).

**Draft choice.** (a) in each case (M§14). A `dsip.invite`-only grantee may create a conversation
so it can leave voicemail, and the recipient client restricts rendering to `voicemail` and
`callback-request` until `dsip.message` is granted. Grants are carried in full so mailboxes verify
them statelessly, and revocation is propagated by `mailbox-config.revoked_grants`.

**Suggested fix.** Register `dsip.message` in `dsip-grant-scope`. Add optional `sealed` to
`introduction.schema.json` (mutually exclusive with `purpose`). Add a §19.4 sentence pointing to
the profile.

## 37. §8.1 / §13.2 / DHT Hints — mailbox discovery

**Gap.** Only `DSIPSignaling` service entries exist (§13.2). The hint schema's `endpoints[]` have
no service discriminator. Nothing defines several mailboxes for one identity.

**Choices considered.** Discovery: (a) a `DSIPMailbox` DID service entry (authoritative) plus a
hint `service` field for `did:key`; (b) mailbox fields on the relay's `hello` capabilities, which
are not authoritative and are only visible after connecting. Multiple mailboxes: (a) `priority`
order for deposit, owner devices sync all and archive to all; (b) exactly one mailbox;
(c) mailbox-to-mailbox replication, a new trust relationship between operators.

**Draft choice.** (a) and (a) (M§4.2). Hint-sourced mailboxes never replace an established
conversation's mailbox on their own (M§15.4). Vectors (2026-09-15) settle what the prose left open: an
entry is usable only if it satisfies the `mailbox-service` shape and advertises `messaging/1.0`;
`priority` defaults to 0 and equal priorities keep document order; the selection is the first usable
entry that accepts a connection while devices sync every usable one; and a document that lists only
unusable entries yields **no** mailbox rather than falling back to a hint.

**Suggested fix.** Register the `DSIPMailbox` service type. Add optional `endpoints[].service` to
the DHT Hints Profile (default `DSIPSignaling`).

## 38. §15.1 — no reason category fits mailbox conditions

**Gap.** The §15.1 category set is closed in the grammar. Commit conflicts, stale epochs, cursors,
and KeyPackage exhaustion are neither `session` (no session exists) nor `transport`.

**Choices considered.** (a) New core category `mailbox`, with fallback "re-sync, retry once, then
surface". (b) Extension-prefixed `x-messaging.*` (§15.6), which receivers without the profile map
to `session.failed`, and whose `x-` wrongly suggests an unofficial extension. (c) Overload
`session.*` and `policy.*`.

**Draft choice.** (a), with eight tokens (M§16).

**Suggested fix.** Add `mailbox` to the §15.1 grammar and §15.3 table; register the M§16 tokens.

## 39. §7.4 / §24.2 — delegation capabilities have no registry

**Gap.** §7.4's example uses `dsip.signaling` and `dsip.media.interactive`, and verifiers require
`dsip.signaling`, but §24.2 lists no registry for delegation capabilities. Messaging needs a
capability so that an identity can delegate a device for calls but not messages, or the reverse.

**Choices considered.** (a) Create `dsip-delegation-capability` with the two existing values plus
`dsip.messaging`, and require `dsip.messaging` for messaging leaves and mailbox operations. (b)
Treat `dsip.signaling` as covering messaging, which gives no separation.

**Draft choice.** (a) (M§6.2, M§4.3).

**Suggested fix.** Add the registry to §24.2 and cite it from §7.4.

## 40. §13.2 — 64 KiB cap versus media messages

**Gap.** Voicemail, images, and files exceed the fixed 65,536-byte `ws/1.0` envelope cap, and
payload bytes are base64url-encoded twice (inside the payload and then as the payload).

**Choices considered.** (a) Cap every MLS value at 24,576 bytes so any envelope carrying one value
plus a header delegation fits, and move larger payloads to client-encrypted blobs over HTTPS with
signed `blob-put` upload and capability-URL fetch. (b) Chunk over `ws/1.0`, adding a reassembly
layer to a binding defined as one envelope per message. (c) A new binding version with a larger cap
(§13.2 forbids negotiating the constant).

**Draft choice.** (a) (M§5.1, M§8.4). Recipient mailboxes replicate blobs so devices never contact
the sender's mailbox.

**Suggested fix.** Adopt in the profile. Add a §13.2 note that profiles carry bulk data outside the
signaling binding.

## 41. §12 / §14 — voicemail

**Gap.** Core has `answered_by: service` for voicemail systems (§14.3), but no end-to-end model, and
no rule for when a caller may leave a message.

**Choices considered.** (a) The caller records locally and sends an E2EE `voicemail` content object.
The offer is gated on the callee's `DSIPMailbox.voicemail` advertisement and a fixed set of attempt
outcomes. (b) A mailbox service answers the call (`answered_by: service`) and records, which gives
the service plaintext audio. (c) (a) plus a new `reject` field to suppress or permit voicemail per
attempt, a core schema change.

**Draft choice.** (a) (M§13). (b) remains permitted outside the profile's guarantee. (c) is not
adopted in 1.0. Vectors (2026-09-15) added the unregistered-token rule the list left open: an
unregistered `endpoint.*` rejection offers by category fallback; an unregistered condition in any other
category does not, and registered tokens outside the list (e.g. `endpoint.capability`) never do.

**Suggested fix.** Adopt in the profile; no core change.

## 42. §12.6 / §20.6 — concurrent conversation creation

**Gap.** Two identities can create a direct conversation simultaneously, and two members can create
successor groups for a dead hub simultaneously. Both are glare in a new place.

**Choices considered.** (a) Lower ULID wins (conversation ULID for direct conversations, `group_id`
ULID for successors), mirroring §12.6, with clients merging histories into one thread. (b) Both
survive and the UI merges them. That leaves two hubs and doubles metadata exposure. (c) The
lexicographically lower identity DID wins, which is deterministic but permanently favors some
identities.

**Draft choice.** (a) (M§7.2, M§7.5). Backdating wins only hub hosting (metadata visibility), and
the §20.6 tripwire is restated for any future hosting privilege. Vectors (2026-09-15) pin two details:
a candidate failing the ULID/`issued_at` check cannot win, and successor `group_id`s compare as
decoded ULIDs, because base64url text does not sort like the ULID it encodes.

**Suggested fix.** Adopt in the profile; cite §20.6.

## 43. Ephemeral activity and the MLS secret tree

**Gap.** Sending typing refreshes as MLS application messages consumes sender ratchet generations.
A long-offline member then faces generation gaps that can exceed an implementation's maximum
forward distance, breaking decryption of real content.

**Choices considered.** (a) Seal activity with a per-epoch `MLS-Exporter("dsip activity", …)` key
and a device signature: no ratchet consumption, not forward-secret within an epoch, acceptable for
content-free indicators. (b) MLS application messages with a rate cap, which mitigates but does not
eliminate the problem. (c) Unencrypted activity, which leaks conversation activity to hubs and
mailboxes.

**Draft choice.** (a) (M§11.1), never stored, ≤ 10 s envelope lifetime.

**Suggested fix.** Adopt in the profile.

## Already-flagged (schema README / plan §11)

- §15.3 codec example uses bare strings; §16.2 defines objects (schemas follow §16.2).
- `$id` base `https://dsip.org/schema/1.0/` is a placeholder pending §24.
- Prose ids like `01HZINVITEABC` are not valid ULIDs.
- §12.7 rule 6 reject preference order lists four tokens; the relay needs a rule
  for other tokens (PoC: first-seen).
- §26 step 8 says ICE candidates ride in `update` envelopes; §12.12/§16.3 say `info`.
