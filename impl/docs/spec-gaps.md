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
| 23 | §15.5, §6.3 | adopt → **Gateway Profile 1.0** (`v0.8/dsip-gateway-profile-v0.8.md`) | `gateway/*` (53) |
| 24 | §15.5 | adopt (`Reason: DSIP;text=`) | `gateway/reason-outbound-*`, `gateway/trace-*` |
| 25 | §18.1, §24.2 | adopt; register `tel` claim type | `gateway/claims-*` |
| 26 | §12.12 | adopt → `media:dtmf` in `dsip-info-about` with `dtmf-info-data` (spec-gap 70; core v0.8 §12.12 + G§9 errata, 2026-09-17) | `payload/info-dtmf-*` (7), `gateway/trace-dtmf-*` (3) |
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
`state/initiator-rejected-while-proceeding`. The third case — an answer arriving after a session that *was* established
has ended — is spec-gap 85.

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
**DSIP Gateway Profile 1.0** (`v0.8/dsip-gateway-profile-v0.8.md`).

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

**PoC choice.** Round one did not forward DTMF across the gateway. The natural vehicle is a signed
`info` (§12.12) with a registered `about`.

**Resolved by spec-gap 70:** `media:dtmf` is now a registered `dsip-info-about` value with its own
`data` schema, and G§9 maps it to and from SIP `INFO`.

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

## v0.8 messaging worklist (gaps 31–58)

**Status (2026-09-17): every gap in this worklist and in the gateway worklist (23–30) is disposed in the v0.8
core (`v0.8/dsip_v_0_8_decentralized_session_initiation_protocol.md`, Appendix A.5) or in its companion profiles.
Spec-gap 26 (DTMF carriage), open until 2026-09-17, is closed by spec-gap 70. Gaps 58–72 are profile 1.0 errata
found by running the profile; each is carried into the profile text as it lands.**

**Status (2026-09-15):** filed with the **DSIP Messaging Profile 1.0** draft
(`v0.8/dsip-messaging-profile-v0.8.md`, cited M§n). Unlike gaps 1–30, these were not found
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
| 44 | M§5.4, M§8.5 | **pinned** (2026-09-16): MLS state and delivery state (ack cursor, per-group seq positions) commit atomically per item; redelivered sequenced items collapse by seq, not content id | `messaging/resume-*` (9), `dsip-mls` `tests/persist.rs`, `demos/messaging-demo.sh` (restart + crash-before-commit) |
| 45 | M§5.2, M§6.6 | **pinned** (2026-09-16): a mailbox forwards only its owner's devices' deposits, only to the hub registered for the group (from the welcome's `hub`); hub identity from the header delegation | `messaging/mailbox-forward-*` (5), `demos/group-demo.sh` |
| 46 | M§14.2, §19.4 | **pinned** (2026-09-16): a hub-forwarded welcome's adder is proven only by `origin` (a `handshake` deposit, same group, ≤ 300 s); `policy.blocked` for a bad origin | `messaging/mailbox-welcome-hub-forwarded-*` (6), `demos/group-demo.sh` |
| 47 | M§6.5 | **pinned** (2026-09-16): a device's own fanned-back items are processed by the `accepted` seq (or recognised by their bytes), never decrypted | `messaging/resume-own-item-by-accepted-seq`, `demos/group-demo.sh` |
| 48 | M§5.6, M§16 | **pinned** (2026-09-16): blob endpoint statuses 401/403/400/413 in check order, idempotent 200 re-upload, 404 GET; new token `mailbox.blob-mismatch` | `messaging/blob-put-*` (10), `messaging/blob-get-*` (2), `demos/messaging-demo.sh` (voicemail) |
| 49 | M§5.4, M§11.2 | **pinned** (2026-09-16): pushed ephemeral item `{class, group, source, sealed, expires_at}` without cursor; originating `expires_at` carried unchanged and enforced by every hop; receivers clear at it | `messaging/items-ephemeral-*` (3), `messaging/items-stored-class-ephemeral-refused`, `messaging/mailbox-ephemeral-expired-dropped`, `messaging/client-activity-*` (4 receiver traces), `demos/receipts-demo.sh` |
| 50 | M§6.5, M§6.7 | **pinned** (2026-09-16): the hub sends a welcome to every identity that gains a device, including a member adding its own | `messaging/hub-commit-adds-own-device-sends-welcome`, `messaging/hub-commit-readds-existing-device-no-welcome`, `demos/multidevice-demo.sh` |
| 51 | M§12.1–M§12.3, M§8.5 | **pinned** (2026-09-16): held archive until its key; pre-join and unjoined-group MLS skipped; sibling welcome acknowledged, not a join; own sent content archived; current key = greatest created_at; archive items carry ref_group/ref_seq as group/seq | `messaging/history-*` (8), `messaging/resume-sibling-welcome-is-not-a-join`, `demos/multidevice-demo.sh` |
| 52 | M§10.5, M§8.1 | **pinned** (2026-09-16): a private read watermark in the personal group names the conversation it describes (exempt from the conversation match) | `messaging/receipt-read-in-personal-group-*`, `messaging/receipt-*-other-conversation-refused` (2), `demos/multidevice-demo.sh` |
| 53 | M§5.7, M§6.6, M§12.4 | **pinned** (2026-09-16): a removed device sends `left` only when no leaf of its identity remains | `messaging/registration-on-removal-*` (2), `demos/multidevice-demo.sh` |
| 54 | M§14.1, §19.4, M§5.2 | **pinned** (2026-09-17): introductions and grants as mailbox deposits (`envelope`, `recipient`, no group); §19.4 relay rules at the mailbox | `messaging/deposit-introduction-*`, `messaging/deposit-grant-valid`, `messaging/mailbox-introduction-*` (5), `messaging/mailbox-grant-stored-for-owner`, `demos/messaging-first-contact-demo.sh` |
| 55 | M§6.9, §7 | **pinned** (2026-09-17): did:key-style derivation of the X25519 key agreement key; did:web provisioning is deployment-defined | `messaging/x25519-key-agreement-from-ed25519`, `messaging/sealed-introduction-*` (10), `messaging/hpke-*` (4) |
| 56 | §7.4, §24.2 | **adopted in core v0.8** (2026-09-17), disposition (b): binding stays `dsip.signaling` for every envelope; messaging devices carry `dsip.signaling` and `dsip.messaging` | `envelope/hello-messaging-only-delegation-rejected`, `dsip-mailbox` `verify::tests` |
| 57 | §7.4, §8.1, M§4.3, M§5.7, M§12.4 | **adopted in core v0.8** (2026-09-17): `delegation-revocation` record (subject-signed, covers delegations issued ≤ `revoked_at`), found in the DID document or any verifier store; `delegation-revoked`; mailbox closes the binding | `envelope/delegation-revoked-*`, `envelope/delegation-revocation-*`, `envelope/hello-revoked-device-rejected`, `payload/delegation-revocation-*`, `semantic/delegation-revocation-*`, `messaging/mailbox-revoked-device-closed-and-forgotten`, `demos/revocation-demo.sh` |
| 58 | M§6.5, §15.3 | **pinned** (2026-09-17, profile 1.0 erratum): on commit-conflict or stale-epoch discard, sync past the winning commit, re-propose while still needed, at most 3 proposals; unknown `mailbox.*` retried once; other refusals surfaced | `messaging/commit-retry-*` (9), `demos/commit-conflict-demo.sh` |

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

## 44. M§5.4 / M§8.5 — durable processing and redelivery of MLS items

**Gap.** M§5.4 lets a device acknowledge items it has "durably processed" but does not say what must
be durable. Processing an MLS item changes two things in different places: the MLS group state
(which deletes the secret it used) and the device's ack cursor. A crash between them either (a)
acknowledges an item whose MLS state change is lost — in `queue` mode the mailbox then deletes a
message the device never kept — or (b) keeps the MLS state change but not the cursor, so the item is
redelivered and can no longer be decrypted. M§8.5 deduplicates by content id, which needs a
decryption, so (b) surfaces as an undecryptable message rather than a silent duplicate. The same
redelivery happens with no crash at all after `mailbox.cursor-invalid` (re-sync from `null`) and when
a device syncs several mailboxes.

**Choices considered.** (a) Commit MLS state and delivery state (ack cursor, per-group seq positions,
joined groups) atomically per item, and recognise redelivered sequenced items by hub `seq`, welcomes
by joined group. (b) Acknowledge only after MLS state is flushed, and treat undecryptable items as
probable duplicates: silent loss of genuinely undecryptable content is indistinguishable from a
duplicate. (c) Leave it to implementations: interop is unaffected, but the queue-mode loss in (a)
above is a protocol-visible failure.

**Draft choice.** (a) — MUST NOT acknowledge ahead of durable MLS state; SHOULD commit atomically;
MUST keep per-group seq positions durably and collapse redelivery by seq. Vectors (2026-09-16,
`messaging/resume-*`) pin: the post-restart `since`/`ack_through` equal the last committed item;
an uncommitted item is redelivered and processed; duplicates are acknowledged; seq positions are per
group and include seqs processed beyond a gap; a welcome for a joined group is a duplicate;
`group-info` is re-applied. `impl/crates/dsip-mls` (`sqlite` feature) shows (a) is directly
implementable on OpenMLS: its SQLite storage provider opens no transactions of its own, so one
transaction spans the MLS writes and the delivery state. `tests/persist.rs` and the messaging demo
(a device killed after processing but before commit) exercise it, and both fail when the transaction
is removed.

**Not yet pinned.** How a device's durable state interacts with items held across a seq gap (M§6.5):
a held item is not processed, so the ack position must stop before it, while later items for other
groups may still be processed.

**Suggested fix.** Adopt the M§5.4 and M§8.5 text now in the draft.

## 45. M§5.2 / M§6.6 — mailbox-to-hub forwarding has no rules

**Gap.** M§5.2 says a device sends every deposit to its own mailbox, "which forwards it unchanged to
`to` when `to` names another service". It does not say how the mailbox reaches that service (a hub is
named by a DID, which for a service need not resolve to an endpoint), which deposits it may forward
(otherwise any client can use a mailbox as an open relay), or how the hub learns who deposited: the
connection it arrives on is the mailbox's `hello`, so the §13.2 binding names the mailbox, not the
member. The first group over the wire needed all three; a direct conversation never did, because only
its creator's device deposits and that device is bound at the hub.

**Choices considered.** (a) Forward only an owner device's deposit and only to the hub registered for
its group, at the `hub.uri` the registering `welcome` carried; the device carries its delegation in the
header and the hub takes identity from it. (b) Resolve `to` as a DID and forward anywhere it leads: an
open relay, and a service `did:key` has no endpoint. (c) Devices always connect to hubs directly (the
MAY): exposes device addresses to every hub and multiplies connections, which M§5.2 set out to avoid.

**Draft choice.** (a), with `policy.blocked` for another identity's device and `mailbox.unknown-group`
for an unregistered group or another service. Vectors pin the mailbox decisions; the group demo shows
the hub taking identity from the header (mutation: taking it from the connection makes the hub refuse
Bob's deposit with `policy.blocked`).

**Suggested fix.** Adopt the M§5.2 text now in the draft. Hub changes (M§7.4) will need the device to
update the registration's hub when it processes the GroupContextExtensions commit.

## 46. M§14.2 — `origin` on hub-forwarded welcomes

**Gap.** M§14.2 requires a mailbox to verify a hub-forwarded welcome's `origin` but does not say that
the adder identity is *taken from* it (rather than from the hub's connection or any other field), what
kind of deposit it must be, whether it must name the same group, whether its own replay window applies
(it cannot: it is presented after delivery), or what to answer when it fails.

**Choices considered.** (a) `origin` is verified as a credential, must be a `handshake` deposit for the
same group within 300 s of the hub deposit, and alone names the adder; failures are `policy.blocked`,
while a proven adder without authorization stays `policy.first-contact-required`. (b) Trust the hub to
name the adder: gives every hub the power to impersonate adders to first-contact controls. (c) Reuse
`policy.first-contact-required` for everything: conflates "who added you is unknown" with "they may
not add you".

**Draft choice.** (a). Vectors pin the 300 s bound as inclusive, a mismatched group, a missing origin,
and that a claim beside the origin cannot override it.

**Suggested fix.** Adopt the M§14.2 text now in the draft.

## 47. M§6.5 rule 5 — a device's own items come back to it

**Gap.** The hub fans every item out to the sender's own identity "which is how a user's other devices
see sent messages". The sending device receives that copy too, and MLS does not let a member decrypt
its own messages, so a device that simply processes its mailbox fails on everything it sent. The
profile does not say how the copy is recognised; content-id deduplication (M§8.5) needs a decryption.

**Choices considered.** (a) The `seq` in the hub's `accepted` marks the item processed (it joins the
device's durable seq positions, spec-gap 44), and a copy that arrives before the `accepted` is
recognised by its MLS bytes. (b) Recognise copies only by bytes: lost on restart, so a copy redelivered
after a restart fails. (c) Hubs skip the sending device: the hub knows identities, not which device's
mailbox copy serves which device, and the identity's other devices need the copy.

**Draft choice.** (a). The demo exercises both paths: the hub owner's `accepted` arrives before its copy
(`DUP`), and a forwarded deposit's copy can beat its `accepted` (`SELF`); removing both fails the demo.

**Suggested fix.** Adopt the M§6.5 text now in the draft.

## 48. M§5.6 — the blob endpoint has no refusals

**Gap.** M§5.6 defines the success of `PUT {blob_endpoint}/{sha256}` (`201` with a signed `accepted`)
and what the mailbox must verify, but no HTTP status or reason for any failure, no answer for a hash
already stored, and nothing for `GET`. No registered token fits a body that does not match its
authorization (`mailbox.object-too-large` is about size limits, `policy.blocked` about who may act).
It also leaves open whether the URL's hash must equal the envelope's, and whether an authorization
minted for one mailbox can be replayed at another.

**Choices considered.** (a) Statuses in the order a server can decide them — `401` credential, `403`
addressee and served identity, `400` URL/authorization mismatch, `413` declared size before reading the
body, `400` body mismatch with a new `mailbox.blob-mismatch` — with a signed `error` body, idempotent
`200 duplicate` for a stored hash, `404` for an unknown `GET`. (b) One `400` for everything: clients
cannot tell a retryable upload from a forbidden one. (c) Silent `201` for a stored hash: hides that
nothing new was stored, which quota accounting will need.

**Draft choice.** (a). Vectors pin the order and each status; the PoC serves blobs on the mailbox's own
TLS port beside `ws/1.0`, and its demo checks `401` for an unauthorized `PUT`, `404` for an unknown hash
and the stored ciphertext for a known one (mutation: accepting an unauthorized upload fails it).

**Suggested fix.** Adopt the M§5.6 table and the `mailbox.blob-mismatch` registry entry now in the draft.

## 49. M§5.4 / M§11.2 — ephemeral activity cannot reach a device

**Gap.** M§11.2 says hubs and mailboxes push `ephemeral` deposits to bound devices, never store them,
drop them at `expires_at`, and that a receiver clears an indicator at the last refresh's `expires_at`.
But the only message a mailbox pushes with is `items`, whose items require `cursor` and `stored_at` and
have no `sealed` field, so a pushed activity cannot be expressed. And because carriage is fresh on every
hop (M§5.1), each hop signs a new envelope with its own `expires_at`: nothing says whose expiry the
receiver clears at, and a hop that issues a fresh 10 s lifetime extends the activity at every hop.

**Choices considered.** (a) A second item form for pushes — `{class: ephemeral, group, source, sealed,
expires_at}`, no cursor — where `expires_at` is the originating deposit's, carried unchanged, never
extended by any hop (forwarded envelopes expire no later), enforced by each hop and by the receiver.
(b) Deliver activity in a separate message type: one more type for the same carriage. (c) Receivers clear
after a fixed 10 s from arrival: stale indicators after queueing delays, and hops can still extend.

**Draft choice.** (a). The item schema is a `oneOf` of the stored and pushed forms; vectors pin the
schema, a mailbox dropping an expired push, and the receiver's indicator (shown until the refresh's
expiry, extended by a refresh, cleared by `stopped`, ignored when already expired). The receipts demo
shows typing clearing at expiry; a hub that extends the lifetime gets its forward refused downstream by
the 10 s rule and fails the demo.

**Suggested fix.** Adopt the M§5.4 and M§11.2 text now in the draft.

## 50. M§6.5 rule 5 — a new device of an existing member never gets a welcome

**Gap.** Rule 5 sends a `welcome` "to each added identity". When a member adds its own new device
(M§6.7, M§12.3 step 4), the identity is already in the roster, so a literal reading sends no welcome —
and the device, which is not in the group yet, has no other way to join.

**Choices considered.** (a) Welcome every identity that gains a device the group did not have. (b) The
adding device delivers the welcome to its own mailbox directly: a second path for one thing, and it
bypasses the hub's ordering of the welcome after its commit. (c) The new device external-joins (M§6.8):
defeats "an existing device adds it", which is what carries the archive keys.

**Draft choice.** (a). Vectors pin it, and that a commit adding no new device sends none; the
multidevice demo fails without it.

**Suggested fix.** Adopt the M§6.5 text now in the draft.

## 51. M§12.3 — what a new device meets when it syncs from null

**Gap.** "The new device syncs from `null`. It decrypts archive records for history and MLS items from its
join epoch onward" leaves out what happens on the way. Items arrive in cursor order, so the device meets
archive records before the personal-group welcome that brings their key, MLS items of groups it has not
joined yet and of epochs before its join, and its sibling's welcomes, which hold none of its KeyPackages.
Read literally, it acknowledges and loses the archive, fails on the MLS items, and — because a committed
welcome counts as a join (spec-gap 44) — drops its own later welcome for the same group as a duplicate.
M§12.2 also archives only what a device "decrypts", so no device ever archives its own sent messages, and
"newest `akid`" does not say newest by what. Archive `items` carry neither `ref_group` nor `ref_seq`, which
the AAD needs.

**Choices considered.** (a) Hold unknown-key archive durably and open it on the key; skip unjoined-group and
pre-join MLS items; acknowledge a sibling welcome without joining; archive own sent content with the
`accepted` seq; current key by `created_at` then `akid`; file archive items under `ref_group` with `seq` =
`ref_seq`. (b) Delay acknowledgement of anything unreadable: a mailbox in `queue` mode then retains
items forever for a device that can never read them. (c) Put archive keys in the new device's welcome
(group context or a custom extension): mixes identity-level secrets into every group's state.

**Draft choice.** (a). `messaging/history-*` pins hold/release, per-key release, archive/MLS collapse,
seq-order display, pre-join skip, no-key no-archive, newest-key archiving and own-content archiving;
`resume-sibling-welcome-is-not-a-join` pins the welcome rule. The multidevice demo exercises hold, release,
sibling welcomes, pre-join skipping and history in seq order; removing the archive-key re-send, counting a
sibling welcome as a join, or skipping nothing before the join each fail it. The epoch-race variant of the
pre-join rule (an old-epoch message sequenced after the add) is pinned by vector only.

**Suggested fix.** Adopt the M§12.1–M§12.3 text now in the draft.

## 52. M§10.5 vs M§8.1 — a private read watermark cannot name its conversation

**Gap.** M§10.5 sends an undisclosed `read` watermark to the personal group. A `read` names its
conversation, but M§8.1 requires every receipt's `conversation` to equal the carrying group's, so a
sibling device must reject it — or the watermark cannot say which conversation was read.

**Choices considered.** (a) Exempt `read` receipts in the personal group from the conversation match; they
name the conversation they describe. (b) A new object type for synced watermarks: one more type for the same
content. (c) Per-conversation personal subgroups: multiplies groups.

**Draft choice.** (a), only for `read` in `kind: personal`; other objects there still must match. Vectors
pin both sides; the demo shows the laptop's private read reaching the phone, which then sends nothing.

**Suggested fix.** Adopt the M§10.5 text now in the draft.

## 53. M§5.7 / M§12.4 — a removed device unregisters the group for its whole identity

**Gap.** A device that learns it was removed from a group naturally tells its mailbox `left` (M§5.7). But
the registration is the identity's (M§6.6), so when one device is removed while a sibling stays (M§12.4),
that `left` makes the mailbox refuse the hub's fan-out for the sibling (`mailbox.unknown-group`). The first
multidevice run lost the phone's next message exactly this way.

**Choices considered.** (a) A removed device sends `left` only when no leaf of its identity remains (it can
see the remaining roster in the removing commit). (b) Per-device registrations: mailboxes would track
device membership they cannot verify. (c) Never send `left` on removal: registrations linger after an
identity is removed.

**Draft choice.** (a). Vectors pin both cases; sending `left` unconditionally fails the demo.

**Suggested fix.** Adopt the M§5.7 text now in the draft.

## 54. M§14.1 / §19.4 — where a messaging introduction goes

**Gap.** M§14.1 says messaging "reuses §19.4 unchanged in structure", but §19.4 delivers introductions
through relays, and a messaging identity's DID document may list only a `DSIPMailbox`. Nothing says how an
introduction reaches such an identity, how the grant comes back, or whether the relay rules (mandatory rate
limits, anti-enumeration, a bounded inbox, holding until expiry) apply to a mailbox. The PoC's messaging demos
passed grants between identities as files until now.

**Choices considered.** (a) Two deposit classes, `introduction` and `grant`, carrying the signed envelope
(no group), with §19.4's relay rules applied by the mailbox. (b) Require messaging identities to also run a
relay binding: every messaging device would need a second connection for requests. (c) A new profile message
type: the same carriage with another type.

**Draft choice.** (a). The mailbox verifies the envelope fresh at deposit (pipeline, delegation, 4,096-byte
cap, profile introduction rules); it rate-limits per sender identity and per recipient inbox
(`policy.rate-limited`, `retry_after`); an introduction for an unserved identity or past the bounded inbox
is accepted and not held (indistinguishable from delivery); held items leave at `expires_at`. Devices
render introductions as requests and verify delivered grants as credentials (signature and signer binding),
because a grant's delivery window has passed by the time it is read. Vectors pin the deposit shapes and the
mailbox rules; `demos/messaging-first-contact-demo.sh` exercises them end to end and fails without sealing,
without anti-enumeration, or without rate limiting.

**Found alongside.** The PoC mailbox accepted a presented grant after checking only its signature, not that
its signer was delegated by the grant's `from`, so any device could forge consent. Fixed
(`dsip_mailbox::verify::grant_credential`, unit-tested with an honest, a bare and a forged grant).

**Suggested fix.** Adopt the M§5.2 rows and the M§14.1 "Carriage" text now in the draft; §19.4 in the v0.8
core should say its relay rules apply to any service that holds introductions.

## 55. M§6.9 — the key agreement key of a delegated identity

**Gap.** M§6.9 seals introductions to the identity's X25519 `keyAgreement` key. For `did:key` it is derived
from the Ed25519 key. For a `did:web` identity whose messaging is done by delegated devices, nothing says how
those devices hold the private half, and the DID document shape for it is not given.

**Choices considered.** (a) Leave provisioning deployment-defined (like the controller key), publish an
embedded `Multikey` X25519 method under `keyAgreement`, and allow the `did:key`-style derivation as one
arrangement. (b) Seal to each device key: the sender does not know the device set, and every device would
see the others' requests anyway. (c) Seal to the mailbox: the mailbox would read requests.

**Draft choice.** (a). The PoC derives the key from the identity key and publishes it; vectors pin the
derivation (`x25519-key-agreement-from-ed25519`) and HPKE itself against RFC 9180 A.1.1, and `dsip-mls`
cross-checks the profile's HPKE against `hpke-rs` in both directions.

**Suggested fix.** Adopt the M§6.9 text now in the draft.

## 56. §7.4 — a messaging-only device cannot introduce or grant

**Gap.** Core §7.4 binds a device-signed envelope to its `from` identity through a delegation carrying
`dsip.signaling`. The Messaging Profile delegates devices with `dsip.messaging` (spec-gap 39), and M§14.1
has devices sign core `introduction` and `grant` envelopes. A device delegated for messaging only is
therefore refused when it introduces or grants, by every verifier following core. The PoC's devices carry
both capabilities, which hides the problem; `dsip-mailbox`'s grant test pins today's refusal.

**Choices considered.** (a) Core §7.4 names the capability per message type, with `introduction` and `grant`
accepting `dsip.messaging` as well as `dsip.signaling`. (b) Messaging devices always also carry
`dsip.signaling`: over-grants signaling authority to devices that do not call. (c) The identity key signs
first-contact messages: puts the controller key on every device.

**Disposition (v0.8 core, 2026-09-17).** (b), decided by the editor: binding every envelope keeps requiring
`dsip.signaling`, profile capabilities are added beside it, and a Messaging Profile device carries both. §7.4
states it with the `dsip-delegation-capability` registry (spec-gap 39); `envelope/hello-messaging-only-delegation-rejected`
pins it.

## 57. §7.4 — a device delegation cannot be revoked

**Gap.** Core §7.4 verifies a delegation by signature, subject key, capability and its own
`issued_at ≤ now < expires_at`. Nothing revokes one before it expires, and a device presents its own delegation
in every envelope header. Key rotation (§7.5) invalidates delegations only by retiring the identity key that
signed them, which takes every device down with it. The Messaging Profile's M§4.3 and M§12.4 assumed that a
lost device "stops being served at its next hello because its delegation no longer verifies" — it keeps
verifying for its full lifetime (a year in the PoC). The multidevice demo showed it: a removed laptop still
connected to its identity's mailbox.

**Choices considered.** (a) A `delegation-revocation` record signed directly by a key of the subject, covering
the device's delegations issued at or before `revoked_at` (so the device can be re-enrolled with a later one),
published in the subject's DID document (authoritative, §8.1) and honored from any other source too, because
it can only remove authority. (b) Short-lived delegations renewed continually: puts the identity key online for
every renewal and still leaves a window. (c) Delegations valid only while listed in the DID document: every
verifier needs a fresh document for every device, and `did:key` identities cannot list anything. (d) Rotate the
identity key: revokes all devices at once.

**Draft choice.** (a). Verification adds `delegation-revoked` after capability and expiry. A mailbox accepts
revocations from its owner in `mailbox-config.revoked_delegations`, keeps them for every later verification,
closes the device's live binding, and forgets its registration and KeyPackages. Vectors pin revocation in the
document and in a store, the `revoked_at` boundary, re-enrollment, other devices unaffected, revocations signed
by anyone other than the subject (including the device itself) ignored, the binding every envelope passes, the
record shape, and the mailbox's reaction. The revocation demo: the laptop is disconnected at once, refused by
its own and by Alice's mailbox (which reads Bob's document), removable by Alice only after revocation (M§7.3),
and removed by Bob's phone with the archive key rotated; it fails if verifiers ignore revocations, if the mailbox
keeps the binding, or if a member may remove a leaf that still verifies.

**`did:key` identities** have no document: their revocations reach verifiers only by distribution (their own
mailbox in the PoC). The v0.8 core should say where else they are carried.

**Suggested fix.** Add `delegation-revocation` as a core message type and verification stage in the v0.8 core
(§7.4), with the `dsipDelegationRevocations` document property; adopt the M§4.3, M§5.7 and M§12.4 text now in
the draft. The record schema is staged in `v0.8/dsip-messaging-schemas-draft/` until the core schema set moves.

## 58. M§6.5 — what a member does when the hub refuses its commit

**Gap.** M§6.5 says a member that gets `mailbox.commit-conflict` "syncs, processes the winning commit, and
re-proposes if still needed". It does not say whether `mailbox.stale-epoch` (the member was more than one
epoch behind) is handled the same way, how many times a member re-proposes under contention, what "still
needed" means, or how the new core `mailbox` category fallback (§15.3: re-sync, retry once, then surface)
applies to refusals the profile does not name. A device that retries without bound can loop against a busy
hub; one that merges a refused commit forks the group.

**Choices considered.** (a) Conflict and stale epoch alike: discard, sync past the epoch committed from,
re-propose while still needed, at most three proposals; unregistered `mailbox.*` retried once per the core
fallback; everything else surfaced without retry. (b) Retry until accepted: unbounded under contention.
(c) Never re-propose automatically: every conflict becomes a user-visible failure for what is routine
concurrency.

**Draft choice.** (a), stated in M§6.5 as a 1.0 erratum (the profile was published in v0.8). The
`commit-retry-trace` vectors pin the outcomes; the reference device runs every commit (add, remove, device
changes, rekey) through the pinned machine. `demos/commit-conflict-demo.sh` makes a member commit from a stale
epoch twice — one epoch behind (`commit-conflict`) and two behind (`stale-epoch`) — and shows the hub refuse,
the member sync and re-propose, and both members still reading each other; merging regardless of the answer
or re-proposing without syncing fails it.

**Suggested fix.** Carry the M§6.5 text into the next profile revision.

## 59. M§6.5 / M§6.6 — a restarted hub or mailbox, and redelivered fan-out

**Gap.** Rule 5 of M§6.5 makes the hub retry an unacknowledged fan-out, so a member mailbox receives the
same `(group, seq)` again whenever an acknowledgement is lost — on a dropped connection, or when the hub
restarts between the mailbox storing an item and the hub hearing so. M§6.6 does not say what the mailbox
answers: storing it again gives the owner's devices a second item for one `seq` (a duplicate they must
catch), and refusing it leaves the hub's queue stuck. Nothing says which hub or mailbox state must survive a
restart, either. A hub that forgot its epoch or `seq` counter would re-number items or accept a second
commit for an epoch — a fork; one that forgot its queues would silently lose fan-out. A mailbox that forgot
its counter would re-issue cursors devices already hold; one that forgot `ack_through` would delete in
`queue` mode too early or never; one that forgot its rate window or seen ids would reset §19.4 limits or
accept a replay.

**Choices considered.** (a) A `seq` at or below the highest stored for the group is a redelivery: `accepted`
with `duplicate` (and the original `cursor` while the item is held), not stored or pushed; all ordering,
queue and answer state durable; live bindings not state; a restarted hub re-sends every queue head at once.
(b) Deduplicate only against items still held: a redelivery after `queue`-mode deletion would be stored as
new. (c) Leave duplicates to devices (M§8.5 already makes them idempotent): correct for content, but the
mailbox grows and pushes the item again, and every restart re-delivers every in-flight item to every device.

**Draft choice.** (a), stated in M§6.5 and M§6.6 as a 1.0 erratum. The `mailbox-trace` and `hub-trace`
vectors gain a `restart` event (the machine's full state round-trips through JSON; bindings are dropped):
`mailbox-restart-*` (items, cursors, acknowledgements, registrations, pending age, KeyPackages, revoked grants,
archive index, rate window), `mailbox-hub-deposit-redelivered-*` (held and deleted), `hub-restart-*` (queue
heads re-sent; epoch, digests and `seq` kept). The service saves its full state after every change —
machines, the hub's public MLS view, payloads, fan-out still queued, revocations, seen ids — and reloads it;
queue heads left unacknowledged are re-sent at start and then with doubling delay (4 s up to 60 s).
`demos/mailbox-restart-demo.sh` kills a mailbox with a message waiting and the hub with fan-out to a mailbox
that is down, and shows nothing lost, replayed or reordered and the reloaded hub validating the next commit;
skipping the reload, the retries, or the public view's reload each fail it.

**Open.** A welcome is fanned out once, outside the queues (M§6.5 rule 5 queues only sequenced items): an added
member whose mailbox is down misses it until a later welcome or an external join. Queuing welcomes is left to
the next profile revision.

**Suggested fix.** Carry the M§6.5 and M§6.6 text into the next profile revision; consider queuing welcomes.

## 60. M§7.4 — moving a group to another hub

**Gap.** M§7.4 gives the move in four sentences: a GroupContextExtensions commit changes the hub, the old hub
orders it and then refuses the group, members deposit to the new hub, which initializes from the latest
GroupInfo. Running it needs answers the text does not give. (1) Numbering: devices track per-group `seq`
(M§6.5, M§8.5) and archive records are sealed to `(group_id, seq)` (M§12.2), so a new hub starting at 1 would
make new items look like redeliveries and collide archive records — but nothing tells the new hub where the
old one stopped. (2) Member mailboxes admit fan-out only from the registered hub (M§6.6) and forward only to it
(spec-gap 45): who changes the registration, and when, without letting the new hub's items overtake the old
hub's last ones? (3) What a member that missed the move does with the old hub's `mailbox.unknown-group`.
(4) Whether a GroupContextExtensions commit may change anything else in `dsip_conversation`.

**Choices considered.** Numbering: (a) continue — the committer carries the moving commit's `seq`
(`handover_seq`) to the new hub; (b) restart per hub — breaks the archive AAD and every device's
duplicate test; (c) the old hub hands over directly — nothing binds the old hub's identity for the new
hub to check, and a dying old hub strands the move. Registration: (a) the owner's device, after processing
the MLS-verified commit, names the new hub and `handover_seq` in `mailbox-config`; (b) the mailbox follows
the old hub's word — lets a hub redirect a group it no longer orders. Missed move: (a) sync, re-send if the
sync shows a move, else final; (b) surface every `unknown-group` — a routine move becomes a user error.

**Draft choice.** (a) throughout, in M§7.4 as a 1.0 erratum: only the hub may change; the old hub orders
the move then refuses the group while its queues drain; the new hub starts at `handover_seq + 1` and hosts
a group only if `dsip_conversation` names it; a mailbox switches on its owner's `mailbox-config` (new
fields `hub_uri`, `handover_seq`), keeps admitting the old hub through `handover_seq`, holds the new hub off
(`mailbox.unknown-group`, retried) until those items are stored, and refuses the new hub's items at or below
it (`policy.blocked`, so a wrong handover fails loudly instead of being dropped as duplicates); a device that
gets `unknown-group` syncs and re-sends only if the group moved. A wrong `handover_seq` from a member is
detected, not prevented: too low is refused by every mailbox, too high is a gap (M§6.5 rejoin).

Vectors: `hub-move-*` (ordered then refused, queues drain, numbering continues), `mailbox-hub-move-*`
(switch, old-hub redelivery, waiting for the handover, renumbering refused), `commit-retry-unknown-group-*`,
`conversation-update-*` (only the hub changes), and the new wire fields. Real MLS (`dsip-mls` e2e): the
public view recognises the move and refuses a commit changing `kind`. `demos/hub-change-demo.sh` moves a
three-member group from Alice's mailbox to Bob's while Carol's device is offline; Carol posts before syncing,
is refused by the old hub, syncs and re-sends. A mailbox ignoring the switch, a new hub restarting at 1, a
device not re-sending, and an old hub that keeps ordering each fail it.

**Open.** None; an old hub that dies before delivering the move to some mailbox is spec-gap 71.

**Suggested fix.** Carry the M§7.4 text into the next profile revision; register `hub_uri` and `handover_seq`.

## 61. M§7.5 — successor groups: re-adding members, checking, converging

**Gap.** M§7.5 lets any member recreate a group whose hub is gone, and says mailboxes admit the successor's
welcome without a grant, clients check creator and roster, and concurrent successors converge on the lowest
`group_id`. Building one over the wire needs more. (1) The creator must fetch every member's KeyPackages, and
M§5.5/M§14.2 demand a grant it may not hold (in a group, members hold grants only from whoever added them).
(2) Hubs fan welcomes out; nothing says the fanned-out welcome carries `successor_of`, which is what the
mailbox admits it by. (3) "The successor's creator": MLS has no creator field. (4) What "converge" does to a
device already in a higher successor, or that created one; and whether a member should create a successor when
one exists. (5) What a device does with an invalid one its mailbox admitted only as a successor.

**Choices considered.** (1) (a) a registered predecessor authorizes the fetch, mirroring the welcome; (b)
require grants — successors fail in exactly the groups that need them; (c) re-add only identities the creator
holds grants from — silently drops members. (3) (a) leaf 0, the creating leaf; (b) the committer of the
first Add — needs the commit history, which a joiner does not have. (4) (a) keep candidates, stay only in the
lowest, leave a higher one joined or created; (b) first successor wins — not convergent under concurrency.

**Draft choice.** (a) throughout, in M§7.5 as a 1.0 erratum: `key-package-fetch.successor_of`; the hub
carries `successor_of` on successor welcomes; creator = leaf 0; candidates per predecessor, lowest kept, a
device leaving the others with `mailbox-config left`; a member already converged uses that successor instead of
creating one; the reference device leaves an invalid successor (its mailbox admitted it only as one), which is
"new conversation under first contact" with no grant behind it. When a hub counts as dead stays the member's
call (the reference device acts on an explicit `successor` command).

Vectors: `successor-trace` (valid joined, invalid and unknown-predecessor as first contact, a lower successor
arriving later switches, a higher one declined, create when one exists, own successor losing or winning against
a concurrent one, non-member refused), `mailbox-key-packages-for-successor`, `key-package-fetch-successor-valid`.
`demos/successor-demo.sh` moves a three-member group to a dedicated hub service, kills it and deletes its state;
Bob and Carol create successors at the same moment; all three devices converge on the lower `group_id` and the
conversation continues there. A device keeping a superseded successor, a mailbox refusing successor KeyPackage
fetches, welcomes fanned out without `successor_of`, and joining every successor each fail it.

**Open.** A device that left a losing successor is still a leaf in it; its members can remove it once they
converge too (nobody is left to order anything there in practice). A dead hub that comes back finds its group
superseded; members ignore it (M§7.5 says nothing about the predecessor's future).

**Suggested fix.** Carry the M§7.5 text into the next profile revision; register `key-package-fetch.successor_of`.

## 62. M§6.8 — what an external commit may do, and who the joiner is

**Gap.** M§6.8 allows an external join when "its identity already has a leaf in the group" or the group is the
identity's personal group, with the commit removing "that identity's stale leaves it replaces", and requires hub
and members to check the same condition. Checking it needs definitions the text does not give. (1) Which leaf is
"its identity"? An external commit carries no Add proposal for the joiner (MLS installs the joiner's leaf through
the update path), so a hub looking at Add proposals sees nobody and cannot apply M§7.3 at all. (2) May the commit
add anyone else, or remove another identity's leaf? (3) What "stale leaves" means given MLS permits exactly one
Remove in an external commit — the resync of the joiner's own signature key — and that a returning device's old
leaf may no longer authenticate. (4) What a member does with an external commit that fails the check, and where
a device gets "the latest group-info" for a group it is not in. (5) The hub checks "the identity's own personal
group", but a hub machine built from a GroupInfo has no owner.

**Choices considered.** (1) (a) the path leaf, authenticated like any leaf (M§6.2); (b) the envelope's delegation
alone — a device could commit a leaf for another device. (2) (a) exactly the joiner's device, removals only of the
joiner's identity; (b) the M§7.3 member rules (whole-identity or lapsed removals) — an external joiner is not yet a
member and has no business removing anyone else. (3) (a) a removed leaf naming the joiner's device counts as the
joiner's even unauthenticated; (b) require it to authenticate — a device returning after its delegation lapsed
could never replace its leaf. (4) (a) not merged, surfaced; the latest group-info item the mailbox delivered is kept
per group. (5) (a) the mailbox hosting a personal group is its owner's (M§7.1).

**Draft choice.** (a) throughout, in M§6.8 as a 1.0 erratum. Vectors: `external-join-*` (new device of a member,
returning device replacing its own leaf, removing another own stale leaf, stranger, removing another identity,
adding another device, a leaf other than the sender's, personal-group owner and non-owner) and
`hub-external-commit-*` (removing another identity, bringing in another identity's leaf); the hub uses the same
check. Real MLS (`dsip-mls` e2e): a new device joins from a GroupInfo and the public view names it; a device with a
fresh store and the same key rejoins and the commit removes its old leaf; a stranger's external commit is refused.
`demos/external-join-demo.sh`: Bob's tablet joins his personal group and his conversation with Alice while his phone
is offline; then the phone loses its MLS state and rejoins, replacing its leaf; Alice and the tablet render both.
A hub view that misses the path-leaf joiner, a device that keeps no GroupInfo, members refusing valid joins, and a
check refusing any removal each fail it.

**Open.** None; rejoining on a gap that does not fill is spec-gap 69.

**Suggested fix.** Carry the M§6.8 text into the next profile revision.

## 63. M§13.3 — which devices send call events, and what the timeline does with them

**Gap.** M§13.3 has "a callee device that alerted and was not answered" send a `call-event` so "every device of
the identity shows one missed call", never for `session.answered-elsewhere`, and asks clients to interleave calls
with content by peer. Left open: whether every alerted device sends (then several events describe one call) or
only one does (which one, if the others are offline); what `outcome` a leg the user declined on this device gets;
how duplicates collapse, given `call-event` has no `id`; whether call events reach a device added later (M§12.2
archives only content and receipts); and how calls are placed among messages when M§8.5 forbids time from
reordering history.

**Choices considered.** Senders: (a) every alerted, unanswered device, collapsed by `session`; (b) one designated
device — none exists in DSIP, and it may be the one offline. Outcome: (a) `declined` for a local `user.declined`,
`missed` otherwise; (b) always `missed` — loses the difference the user sees. History: (a) archive call events;
(b) not — a new device has no call log. Placement: (a) content in `seq` order, each call before the first content
later than it; (b) sort everything by time — lets a backdated `sent_at` reorder content.

**Draft choice.** (a) throughout, in M§13.3 as a 1.0 erratum. Vectors: `call-event-*` (7 decisions),
`peer-timeline-*` (collapse, interleave, content order kept), `history-archived-call-event-applied`.
`demos/call-history-demo.sh`: a missed call on Bob's phone reaches a laptop added later via archive; with both
devices ringing, a call answered on the laptop leaves no event anywhere, a call both miss is reported by both and
recorded once on each, a call declined on the phone is `declined` on the laptop; the laptop's timeline with Alice
interleaves calls and messages. The reference device takes leg outcomes from a `call-ended` command (its messaging
process has no signaling leg); the decision is the pinned function.

**Suggested fix.** Carry the M§13.3 text into the next profile revision; register `outcome` values (`missed`,
`declined`) in a `dsip-call-outcome` registry.

## 64. M§12.2 — which receipts are archived, and what restoring them does

**Gap.** M§12.2 archives "a `receipt` that changes rendering" without defining the phrase, and says nothing
about what a device does when it opens archived receipts (or content) while restoring history: a device that
treats them as new items sends delivered receipts for weeks-old messages and archives everything again.

**Choices considered.** (a) Changes rendering = adds a delivered/played entry not held for that content and
identity, or advances that identity's read watermark; restored items update rendering state silently (no receipts,
no re-archiving). (b) Archive every receipt — duplicates and stale watermarks fill the archive. (c) Restore by
replaying records as live items — sends receipts for history.

**Draft choice.** (a), in M§12.2 as a 1.0 erratum. The receipt machine (`client-trace`) emits `archive {seq}`
exactly when a receipt changes its state (five existing vectors gain that emission where their receipts did; new
`client-receipt-archived-when-rendering-changes`), and gains a `restore` event that applies content and receipts
without emissions (`client-restore-from-archive-sends-nothing`); `history-trace` applies an archived receipt
instead of showing it (`history-archived-receipt-applied-not-shown`). In `demos/call-history-demo.sh` Bob's phone
archives Alice's delivered and read receipts; a laptop added later restores them (its receipt state shows Alice's
watermark) and sends no receipts for history. Mutation-checked: restoring like a live sync, never archiving
receipts.

**Open.** None; a device's own read watermark is archived under spec-gap 68.

**Suggested fix.** Carry the M§12.2 text into the next profile revision.

## 65. M§8.4 rule 6 — replicating blobs to member mailboxes

**Gap.** Rule 6 has a sync-mode member mailbox replicate "every manifest blob on receipt, verifying `sha256`, and
rewrite `uri` in `items`", with devices fetching from their own mailbox and "falling back to the original `uri`".
Unstated: whether size is verified too (the manifest carries it); what happens to a blob larger than the replicating
mailbox's own `max_blob_bytes`; whether a failed or mismatching fetch changes anything; which `uri` in `items` is
rewritten, given the content object's `uri` is inside MLS and cannot be; and how a device relates the unencrypted
manifest to the encrypted content — a manifest entry must not be able to point a device at a different blob.

**Choices considered.** (a) Replicate application items' manifest blobs in sync mode unless already held,
over the local limit, or not https; store only a 200 matching both hash and size; rewrite only held entries in
`items`; devices take a manifest entry as a source only for the exact `sha256` and `size` of the content's blob, try
it first, verify every source and fall through on mismatch. (b) Verify the hash only — sufficient on its own, but the
device checks both (rule 7), and one rule for mailbox and device is simpler to state and test. (c) Trust the rewritten `uri` alone — a damaged or malicious copy would make the
blob unplayable instead of falling back.

**Draft choice.** (a), in M§8.4 as a 1.0 erratum. Vectors: `blob-replicate-*` (9: fetch, queue mode, already
stored, too large, non-https, store verified, hash mismatch, size mismatch, unavailable), `items-blobs-rewrites-
held-blobs`, `blob-sources-*` (4). `demos/blob-replication-demo.sh`: Bob's mailbox replicates a voice message while
Bob is offline; Alice's mailbox crashes and Bob plays from his own mailbox; a damaged replicated copy fails Bob's
device's check and the original serves it; a message larger than Bob's mailbox's limit is not replicated and plays
from the original. A mailbox that never replicates, `items` not rewritten, a device ignoring its mailbox's copy, a
device that never falls back, and an ignored size limit each fail it.

**Open.** Replicated blobs are kept for as long as the items that reference them (no separate retention). Retrying a
failed fetch is spec-gap 67.

**Suggested fix.** Carry the M§8.4 text into the next profile revision.

## 66. M§6.5 rule 5 — a welcome is a fan-out too

**Gap.** Rule 5 queues sequenced items per member mailbox and retries an unacknowledged one before sending later
ones, but the welcome a commit sends to an added identity is not sequenced, so nothing said it is retried at all.
An identity whose mailbox is down when it is added therefore never learns of the group: the commit's `seq` goes to
the existing members, the welcome is sent once into the void, and the added member's devices wait forever (recorded
as the open item of spec-gap 59). Two further questions follow: what the hub does with items sequenced after the
add, since the added mailbox has no registration for the group until the welcome arrives and refuses them (M§6.6);
and what a mailbox does with a welcome it has already stored, once retries make duplicates possible — it cannot
simply drop a second welcome for a registered group, since that is how an owner's new device is let in (M§6.7).

**Choices considered.** (a) The welcome is queued in the added identity's own queue at the commit's `seq` and
retried like any fan-out; its items wait behind it; a mailbox answers a welcome whose MLS bytes it already holds
`accepted` with `duplicate` and that welcome's cursor. (b) Queue the welcome in the same queue as sequenced items — a
member adding its own device needs both the commit and the welcome for one `seq`, so one queue entry cannot carry
both. (c) Leave the welcome unretried and let the added member discover the group by external join (M§6.8) — it
cannot: an external join needs a `group-info` its mailbox would also have refused.

**Draft choice.** (a), in M§6.5 as a 1.0 erratum. A welcome has no `seq` on the wire (M§5.2), so its
acknowledgement is matched by the deposit it answers. Vectors: `hub-welcome-queued-and-retried` (queued, later items
held, released on acknowledgement), `hub-welcome-resent-after-restart`, `mailbox-welcome-redelivered-duplicate` (same MLS bytes),
`mailbox-welcome-for-another-device-stored` (different bytes, a sibling's invitation),
`mailbox-welcome-after-leaving-registers-again`; the two existing welcome vectors now show the queue.
`demos/welcome-retry-demo.sh`: Alice adds Carol with Carol's mailbox down (her KeyPackage fetched beforehand — new
`prefetch`, M§5.5 allows holding one), Alice and Bob carry on, and when Carol's mailbox returns the welcome lands,
her device joins once, and the messages that waited follow in order. A hub that sends the welcome once and never
queues it fails the demo.

**Suggested fix.** Carry the M§6.5 text into the next profile revision.

## 67. M§8.4 rule 6 — a replication that could not be made

**Gap.** Rule 6 replicates "on receipt". A member mailbox that receives an item while the sending mailbox is down —
or before the blob is readable there — fetches nothing, and nothing in the profile says whether it ever tries again.
The item then keeps the origin `uri` for good, which is exactly the case rule 6 exists to avoid. Retrying
indiscriminately is no better: a body that did not match the manifest will not match on the next attempt either.

**Choices considered.** (a) Retry only `unavailable` (no 200 to work with), with rule 5's backoff, bounded and
carried across restarts; never retry `mismatch`. (b) Retry everything — a mismatching or hostile origin is refetched
forever. (c) Retry nothing (the state before this gap) — a moment's outage costs the copy permanently.

**Draft choice.** (a), in M§8.4 as a 1.0 erratum, with 5 attempts RECOMMENDED. `blob-replicate` gains `attempt` and
answers `retry` on a discard. Vectors: `blob-replicate-unavailable-retried`, `-unavailable-bounded`,
`-unavailable-attempt-below-bound`, and the mismatch vectors now show `retry: false`. The service keeps failed
replications with their attempt count and next time, persists them, and runs them from the same timer as fan-out
retries. `demos/blob-replication-demo.sh` gains a stage: the blob is made unreadable at its origin while Bob's
mailbox is down, so its first fetch finds nothing; when the blob is readable again a later attempt stores it, and
Bob plays from his own mailbox. A mailbox that never retries fails it.

**Suggested fix.** Carry the M§8.4 text into the next profile revision.

## 68. M§12.2 / M§10.5 — a device's own read watermark is history too

**Gap.** M§12.2 archives what a device "decrypts": content, and (spec-gap 64) receipts that change its rendering. A
device's own `read` watermark is neither — it does not arrive, it is sent — so nothing archived it, and a device
added later had no idea where its user had read. The gap is plain in the personal group, which exists precisely so
an identity's devices share that watermark (M§10.5): the receipt is deposited, but only devices that were in the
group at the time ever see it.

**Choices considered.** (a) A device archives the `read` receipt it sends, under the group it sent it to and the
`seq` the hub accepted, and not its own `delivered`/`played` (those describe other identities' devices, which
siblings learn from those identities directly). (b) Archive every receipt a device sends — fills the archive with
`delivered` receipts that tell a sibling nothing. (c) Leave it: a new device re-reads everything as unread until
the user reads again.

**Draft choice.** (a), in M§12.2 as a 1.0 erratum. `history-trace`'s `sent` event takes an `object`: a `receipt` or
`call-event` is archived once and is not a timeline entry (`history-own-read-receipt-archived`).
`demos/call-history-demo.sh`: Bob's phone marks the conversation read (undisclosed, so the watermark goes to his
personal group), and the laptop added later restores it — its receipt state shows Bob's own watermark as well as
Alice's, and neither device shows a receipt as a conversation entry. Not archiving the watermark, and treating it as
timeline content, each fail the demo.

**Suggested fix.** Carry the M§12.2 text into the next profile revision.

## 69. M§6.5 / M§6.8 — re-joining when a gap will not fill

**Gap.** M§6.5 tells a device to hold a handshake beyond a `seq` gap and, if the gap does not fill within
`gap_timeout`, to re-join by external commit and treat every seq it has seen as passed. The rule was pinned
(`gap-trace`) but never wired into a device, and three things it leaves open decide whether it can be: what a device
does with a held item it cannot process (the mailbox may delete an item it has acknowledged, M§5.4); whether the
device's own deposits count towards its contiguous position, since their `seq` arrives in the hub's `accepted` and
never as an item (spec-gap 47); and whether `gap_timeout` is a protocol constant or the device's own choice.

**Choices considered.** (a) A held item is kept durably by the device and MAY be acknowledged — it has taken
responsibility for it, though it has not processed it — and is dropped on re-join; own deposits advance the gap
tracker exactly as they advance the resume position; `gap_timeout` is the device's (300 s RECOMMENDED). (b) Do not
acknowledge held items: the ack cursor is a single watermark, so one held item stalls acknowledgement for every group.
(c) Leave own deposits out of the tracker: a device then sees its own items as a gap and re-joins for nothing — which
is exactly what happened when this was first wired (Alice held Bob's re-join commit). A fourth question the wiring
answered the same way: a device counts gaps from where it starts — the first sequenced item a fresh member processes,
or the position an existing one committed — since everything before its welcome is history (M§12.3 step 5), not a gap
(every group demo failed until this was right).

**Draft choice.** (a), in M§6.5 as a 1.0 erratum. `gap-trace` takes `gap_timeout` in its context
(`gap-timeout-configurable`), and `resume-trace` gains `rejoined` (`resume-rejoin-passes-every-seq-seen`): every seq
up to the highest seen is passed, so a redelivery is a duplicate. The device holds items durably, advances its
trackers on a timer, and re-joins by external commit when one times out (`--gap-timeout` for the demo's sake).
`demos/auto-rejoin-demo.sh`: Bob is away while Alice rekeys, his mailbox loses an item he never acknowledged (what
`mls_retention_s` does), and on return he holds the rekey, re-joins by himself, and carries on from the current
epoch. A tracker that never times out, a device that does not hold beyond a gap, and a re-join that does not pass the
seqs behind it each fail the demo.

**Suggested fix.** Carry the M§6.5 text into the next profile revision.

## 70. §12.12 / G§9 — the DTMF binding

**Gap.** Spec-gap 26 left DTMF with nowhere to go: core has no DTMF semantics, and the gateway profile said a future
revision would define carriage, suggesting a gateway-defined `about` such as `x-gateway:dtmf`. That is the wrong
shape — DTMF is not gateway-specific (a DSIP callee may run an IVR, with no PSTN anywhere) — and "gateway-defined"
means every gateway invents its own, which G§9 itself forbids.

**Choices considered.** (a) A core binding: `media:dtmf` in `dsip-info-about`, `data` of `{digits, duration_ms?}`,
carried by `info` (§12.12) — ACTIVE-only, never critical, no reply, changes nothing negotiated; the gateway maps it
to and from SIP `INFO`. (b) `x-gateway:dtmf` as the profile suggested: private to gateways, so two DSIP endpoints
cannot send digits to each other. (c) A new message type: `info` exists for exactly this kind of in-session,
high-frequency, nothing-negotiated data.

**Draft choice.** (a), in §12.12 and G§9 as errata. `digits` is 1–32 RFC 4733 events (`0`–`9`, `*`, `#`, `A`–`D`) in
the order pressed; `duration_ms` (40–10,000) is each digit's tone length and is optional. Vectors: `payload/info-dtmf-*`
(7, through the binding data schema the harness validates per `about`), `state/info-active-only` (a `media:dtmf` info
is delivered like any registered one), `gateway/trace-dtmf-*` (both directions, ignored outside the call, other
`about` values not carried, and a digit arriving as an RFC 4733 event — a SIP-side event with nothing to answer). Mutation-checked: a gateway carrying any `about`, carrying DTMF before answer, an
unregistered `media:dtmf`, and an unconstrained `digits` each fail vectors.

**Open.** None. Both carriages are on the wire in the reference gateway (2026-09-17). INFO: one
`application/dtmf-relay` body per digit with an increasing CSeq, 160 ms when the DSIP `info` names no `duration_ms`;
inbound dtmf-relay on a known call is answered 200 and reported, other INFO payloads 415, unknown calls 481. RFC 4733:
the gateway offers `telephone-event` (payload type 101) and, when the trunk accepts it, sends each digit as a marked
start packet, 20 ms updates and the end packet three times on one timestamp, and reports a trunk's event once, on its
end packet, as the controller event `{"sip": {"event": "dtmf", …}}` (`trace-dtmf-rtp-events`), which answers nothing
on the SIP leg. RTP events are preferred when negotiated. `tests/round_trip.rs` proves both carriages both ways
against the SIP peer. Found on the way: the host re-sent the controller's `response` emission for a request the leg
had already answered — for INFO that would have been a second 200 to the INVITE.

**Suggested fix.** Register `media:dtmf` in `dsip-info-about` and carry the §12.12 and G§9 text into the next
revision.

## 71. M§7.4 — a move whose old hub never finishes delivering

**Gap.** Spec-gap 60 has a member mailbox hold the new hub off (`mailbox.unknown-group`, retried) until the old
hub's items through `handover_seq` are stored, so that items reach the owner's devices in `seq` order. It says
nothing about an old hub that dies after ordering the move and before every mailbox has those items. The
committer's own mailbox is the usual victim: the committer processes its own commit from `accepted` (spec-gap 47)
and names the new hub at once, so if the old hub's fan-out of that commit is lost, the mailbox waits for an item
that will never come and refuses its own hub forever. The reference service had a second problem underneath: a
hub delivered its own owner's fan-out in-process and acknowledged its queue unconditionally, so a refusal there
was never retried at all. (The other members are not stranded by this: their devices learn of the move only from
the old hub's fan-out, so their mailboxes have everything through `handover_seq` by the time they switch. A hub
that dies before fanning out to anyone is the dead-hub case, spec-gap 61.)

**Choices considered.** (a) Bound the hold: the mailbox waits `handover_wait` from the `mailbox-config` that
named the new hub, then admits it and leaves the missing seqs to the owner's devices, whose gap handling
(spec-gap 69) already covers a `seq` that never arrives; what the old hub still delivers after that, at or below
`handover_seq`, is stored out of order so a merely slow old hub fills the gap. (b) The committer tells its mailbox
it holds everything through `handover_seq` (a new `mailbox-config` field): true for the committer, false for its
sibling devices, and a device asserting what its mailbox should believe. (c) The new hub carries the old hub's
tail: it has nothing before `handover_seq + 1`, and the committer's `group-info` deposit is the wrong place for
other members' content. (d) Drop the hold and let devices sort every move out by gap handling: a routine move
would then cost every sibling device a `gap_timeout` and an external re-join.

**Draft choice.** (a), in M§7.4 as a 1.0 erratum. `handover_wait` is the mailbox's own (300 s RECOMMENDED,
`handover_wait` in the `mailbox` vector context, `--handover-wait` on the service), measured from the config
naming the new hub and durable across a restart. Expiry is an internal event of the mailbox machine
(`handover_expired`, naming the seqs given up on), not a wire message. After it, the old hub's items at or below
`handover_seq` are stored unless already stored, its items above it are refused as before, and the new hub's at or
below it are still `policy.blocked`. Vectors: `mailbox-hub-move-handover-wait-expires`,
`mailbox-hub-move-handover-wait-configurable`, `mailbox-hub-move-late-previous-items-stored`,
`mailbox-hub-move-handover-wait-survives-restart`. The service delivers its own owner's fan-out through the same
queue discipline as everyone else's (acknowledged only when the mailbox stored it, retried with backoff
otherwise), which the demo depends on. `demos/handover-wait-demo.sh`: a dedicated hub orders Bob's move, delivers
it to Alice and Carol, never to Bob's mailbox (`--drop-fanout-to`, fault injection), and dies; Bob's mailbox
refuses its own hub, the wait expires, the queued fan-out is retried, and Bob receives Alice's reply. A mailbox
that never releases (`HANDOVER_WAIT=100000`) fails it, as did the service's unconditional self-acknowledgement
before it was fixed (the refused fan-out was never retried).

**Open.** A sibling device of the committer, if the missing items included a commit, pays a `gap_timeout` and an
external re-join (spec-gap 69); so does the committer itself if other members' items were lost along with its
commit (the demo lets receipts land before the move for that reason); nothing shorter is available without the
old hub. The reference service's
mailbox clock (advanced before each message and every 2 s) now drives the machine's other timers too (§19.4
held-introduction expiry, M§6.6 pending groups), which no demo exercises yet.

**Suggested fix.** Carry the M§7.4 text into the next profile revision.

## 72. M§9.4 — the hub cannot be reached

**Gap.** M§9.4 says a client keeps content pending, retries with the §13.2 backoff, never deposits into members'
mailboxes directly, and treats a hub unreachable past a client-chosen threshold (24 h RECOMMENDED) as the M§7.5
successor trigger. Nothing pinned it: the reference device sent once, waited 20 s for an answer, and reported an
error with nothing kept; the mailbox, whose dial to the hub had failed, told the device nothing at all (a forward
queued behind a failed dial was dropped, and one in flight when the connection ended was forgotten); and the only
way a successor group ever came about was a person typing `successor`. Coverage found it: M§9.4 was the one
normative section of the profile with neither a module nor a vector (`docs/coverage.md`, spec-lint since PR #29).

**Choices considered.** (a) An explicit signal: the mailbox answers `mailbox.hub-unreachable` when it cannot hand a
forward to the hub, and the device also treats silence as an outage; the device's outbox is a machine with a
pinned backoff and threshold. (b) Silence only: the device infers the outage from its own answer timeout — slow
(20 s per attempt), and a mailbox that knows the hub is down would still say nothing. (c) The mailbox retries on the
device's behalf: it would have to hold content and re-sign nothing (the envelope is the device's), and M§9.2's
"pending" state is the device's to show; a mailbox is not the place for a device's outbox. Threshold: (a) counts
from the start of the current outage, reset by any `accepted`; (b) cumulative downtime — a flapping hub would then
be abandoned for no reason.

**Draft choice.** (a) throughout, in M§9.4 as a 1.0 erratum and `mailbox.hub-unreachable` in M§16. The outbox:
new content is encrypted at once and queued behind the pending items; the head is re-deposited as the same bytes
after 1 s, doubling to 60 s (the ceiling; a host adds jitter); an `accepted` ends the outage, flushes in order and
resets the backoff; any other refusal leaves the outbox for its own handling; at `hub_timeout` the device creates
the successor, re-encrypts the pending items for it, and abandons the dead group's outbox. Pending items and the
outage's start are durable. Vectors: `hub-outage-*` (6, `hub-outage-trace`) and
`mailbox-forward-hub-unreachable-answered`. Reference: `dsip-messaging::client::HubOutage`; the mailbox service
answers every forward a failed or lost hub connection left unanswered; `dsip-msg --hub-timeout`, `PENDING` /
`OUTAGE-SUCCESSOR` / `RESENT` lines. `demos/hub-outage-demo.sh`: the hub service dies; Alice's message is pending
and retried at 1, 2, 4, 8 s; a second one queues behind it; at 12 s her device creates the successor, re-adds Bob
and Carol and re-sends both; they converge and reply. A device that never gives up (`HUB_TIMEOUT=100000`) fails it,
and exactly one successor is created.

**Open.** A member that has nothing to send never notices the dead hub and creates no successor; it converges on
one another member creates. If nobody has anything to say, the group just stays dead until someone does, which is
what M§7.5 says. Whether receipts and typing (which also go through the hub) should count as content that keeps
the outbox alive is a host choice; the reference device queues application content only.

The hand-over to the successor can itself fail, and the reference device must not lose content to that. An item
leaves the dead group's durable outbox only once the successor's outbox has it. An item whose deposit failed after it
was encrypted for the successor is treated as a deposit with no answer (it stays pending in the successor's outbox
and is retried with the backoff, the later items queueing behind it — `RESEND-PENDING`); the successor's hub being
unreachable too is the same state reached through the ordinary answer. If the successor cannot be created at all, or
an item cannot be encrypted for it, the items stay in the dead group's outbox in order and the hand-over is tried
again with the §13.2 backoff (`SUCCESSOR-RETRY`); the dead group's outage stays abandoned with its start kept, so
nothing goes to the dead hub meanwhile and a restart resumes the hand-over. Delivery into the successor is therefore
at-least-once: a crash between the successor's `accepted` and the local save re-sends that item (same content `id`).
The item-level part is host behaviour built from the pinned `no_answer` event and the restart rule above. The retry
of the hand-over itself is the outbox's, and pinned: once `abandoned`, the event `{"handover_failed": {}}` (the host
could not create or find the successor, or could not move every item into it) is counted in `handover_attempt` — a
snapshot member, 0 until the first failure — and answered `{"handover_retry_in": d}`, where d is the §13.2 series
started afresh (1 s, doubling, 60 s ceiling), independent of `attempt`; the `advance` that reaches that time emits
`{"handover": "retry"}` once, and the next failure schedules the next. Every `handover_failed` counts, whether or not
a retry is already scheduled (the later schedule replaces the earlier). In any other state `handover_failed` emits
nothing and changes nothing; deposits stay refused (`group-abandoned`) throughout. Vectors: `hub-outage-handover-*`
(2). A host that completes the hand-over simply drops the dead group's outbox.

**Suggested fix.** Carry the M§9.4 text into the next profile revision; register `mailbox.hub-unreachable`.

## 73. §9.3 / §15.1 / §15.4 — reason tokens on `notify`

**Gap.** §9.3 says a terminal `notify` SHOULD carry a `reason`, "e.g., `session.expired` for lapsed subscriptions,
`policy.terminated` for revoked authorization". §15.1 lists the reason-carrying types as `reject`, `cancel`, `bye`
and `error` — not `notify` — and the §15.4 "valid on" column gives `session.expired` to `reject` only and
`policy.terminated` to `bye` only. An implementation that applies the column as written flags the spec's own
example. Found by the second implementation (`impl-ts/`, written from the spec and the vector README alone): it
accepted `semantic/notify-terminated-reason` with `warnings: ["reason-not-valid-on-type"]`, the Python harness and the
Rust runner with none. The vector README did not say how `actual` is compared with `expect`; read as "the members
`expect` names", the extra warning passed. (The existing runners compare for deep equality; the README now says so.)

**Choices considered.** (a) The column does not apply to `notify`: any registered token is warning-free there.
(b) Apply it and extend the registry: add `notify` to the "valid on" cell of each token a terminal notify may carry
(`session.expired`, `policy.terminated`, `policy.blocked`, `identity.not-in-service`, …) — precise, but it needs a
decided list the spec does not have. (c) Apply it as written: every reasoned `notify` warns, including the spec's own
examples.

**Draft choice.** (a) now, (b) as the spec fix. `notify` is named in the README's effective-reason rule, and the
README now states the deep-equality comparison (absent `warnings` = none), which is what pins this — the existing
vector needed no change. Reference: all three implementations agree; `impl-ts/src/semantic.ts` carries the `Impl:` note.

**Suggested fix.** §15.1: add `notify` to the types that carry a `reason`. §15.4: add `notify` to the "valid on"
cells of `session.expired` and `policy.terminated` (and whichever others §9.3 means), or state that the column
governs only `reject`/`cancel`/`bye`/`error`.

**Applied to the spec (2026-09-18).** The second form, which is what the vectors pin: §15.1 names a terminal `notify`
among the reason-carrying types, and §15.4 says the "valid on" column governs the four session types and not `notify`,
where any registered token is valid. A.5 errata. No vector or code change.

## 74. §19.4 — who an introduction's outcome is addressed to

**Gap.** §19.4 gives two signed outcomes for an introduction, `grant` and `reject`, and says nothing about their `to`.
Its `grant` example is addressed to `did:key:z6MkCarolPhone` — by its name a device — for an introduction `from` the
same DID. The vectors pin an asymmetry nobody chose on the page: the endpoint sends the `grant` to the introducing
**identity** (resolved through the delegation) and the `reject` to the introducing **device** (the introduction's
`from`). Found by the second implementation, which addressed both to the identity and failed
`state/first-contact-reject-and-silence`.

**Choices considered.** (a) Both to the identity: a grant is held by an identity (any of its devices may invite
under it), and a rejection is equally the identity's to know; the relay fans out. (b) Both to the introduction's
`from`: simplest, but a grant that reaches one device leaves the identity's other devices unable to cite it.
(c) As pinned: grant to the identity, reject to the device that asked.

**Decision (2026-09-18).** (a): both outcomes are addressed to the introducing identity. Applied: §19.4 says so and
its `grant` example names the identity; `state/first-contact-reject-and-silence` changed; all three implementations.

## 75. §12.5 rule 2 / §12.7 rule 3 — `session.answered-elsewhere` at the leg that answered

**Gap.** §12.5 rule 2: a `cancel` arriving after the responder's `answer`, with no initiator message since, "crossed
the answer: the responder MUST treat the session as ended … and MUST NOT treat the crossed `cancel` as an error".
§12.7 rule 3 has the initiator send `cancel session.answered-elsewhere` to the invited identity on accepting an
answer; a conformant relay delivers it only to the legs that did not answer, but a relay without leg tracking (or a
direct fan-out) hands it to the answering leg too — where, read literally, §12.5 rule 2 tears down the call that was
just established. The vectors pin the sane outcome (`error session.invalid-state`, session stays ACTIVE); the spec
text does not. Found by the second implementation, which followed §12.5 to the letter and ended the call.

**Choices considered.** (a) `session.answered-elsewhere` is never a crossed withdrawal: at an ACTIVE responder it is
`session.invalid-state`. (b) Silently ignore it there — no error traffic for what is a relay's shortcoming.
(c) Literal §12.5: end the session.

**Draft choice.** (a), as pinned by `state/race-responder-answered-elsewhere-at-answering-leg`.

**Suggested fix.** §12.5 rule 2 and the §12.4 responder table: except reason `session.answered-elsewhere` from the
crossed-cancel rule.

**Applied to the spec (2026-09-18).** §12.5 rule 2 carries the exception and its reason (the token is sent *because*
an answer was accepted, so the answered leg receiving it is the one that answered); the §12.4 responder table has the
row. A.5 errata. No vector or code change.

## 76. §12.7 rule 6 — the attempt outcome when no leg rejected

**Gap.** Rule 6 has the relay signal attempt completion by forwarding "that leg's `reject`", choosing the most
informative reason "if legs differed". When every leg expires there is no `reject` to forward and no reason to choose.
The vectors pin `reject endpoint.unavailable`, forwarded in the name of the first leg
(`state/relay-all-legs-expired`); the spec names neither the token nor whose name it goes out in — and a `reject`
the relay composes is not a leg's signed message at all.

**Choices considered.** (a) As pinned: `endpoint.unavailable`, attributed to the first leg. (b) Signal nothing and let
the initiator's T-Ring / T-Establish run out — rule 6 already calls them the backstop. (c) A relay-signed `error`
(`transport.*` or `identity.*`), which is honest about who is speaking.

**Decision (2026-09-18).** (c), with a token of its own: the relay sends a relay-signed `error` with reason
`transport.no-response` (new in §15.4, valid on `error`) and `session` naming the invite. It keeps "no device said
anything" apart from `endpoint.unavailable`, which a device says. An initiator in INVITING or PROCEEDING ends the attempt
on it and sends no `cancel`; in any other state it is an error like any other. Applied: §12.4 (initiator table), §12.7
rule 6, §15.4; `state/relay-all-legs-expired` changed (outcome `no-response`), `state/initiator-relay-no-response-ends-attempt`
and `state/relay-no-response-after-answer-only-surfaced` added; all three implementations; `dsip-relay` signs and sends it,
also from its timer, with no inbound frame in hand. The gateway maps it like any other `transport.*` (G§4.2: 503, cause 41).

## 77. §22.2 / §22.3 — the integrity mode of a statement that is not a transcode

**Gap.** §22.3: "`transcode` makes the output `derivative-bound` …; other operations list it under 'delivered by'."
The vectors report a per-statement `integrity_mode`, and it is `derivative-bound` for every verified statement — a
plain `relay` too (`broadcast/provenance-relay-operation`, `provenance-chain-two-processors`) — while the *displayed*
mode for the same relay-only stream is `metadata-only`. Two values for one stream, and the spec defines only one notion
of integrity mode. Found by the second implementation, which reported `metadata-only` for a relay statement and
failed three vectors.

**Choices considered.** (a) The per-statement value is the mode of the *statement* — by §22.2 any processor-signed
reference to the original record is a `derivative-bound` artifact — and only the displayed mode follows the operation.
(b) The per-statement value follows the operation: `derivative-bound` for `transcode`, the record's mode otherwise;
the vectors change. (c) Drop the per-statement field: it carries nothing the operation does not.

**Decision (2026-09-18).** (c): a statement has no integrity mode of its own. Applied: §22.3 says so (and that a
receiver MUST NOT present a `relay` or `repackage` statement as `derivative-bound`); five broadcast vectors lose the
member; all three implementations. No wire change: the field was only ever in the verification result.

## 78. G§4 — which tokens are "attempt" tokens

**Gap.** G§4: "Tokens describing a failed *attempt* (busy, declined, unknown, moved, cancelled, blocked) that arrive
after the DSIP leg is ACTIVE are reported as `gateway.mapped`." Read as a list, that is six tokens. The Rust and Python
implementations also map `endpoint.unavailable` and `identity.not-in-service`; no vector said so (the only one was
`endpoint.busy`). The second implementation took the list literally and a mid-call BYE with Q.850 18 came out as
`bye endpoint.unavailable` — a token §15.4 does not even list as valid on `bye`. A real three-way divergence, found by
adding the vector; the existing implementations' set was established black-box, with probe vectors, not by reading them.

**Choices considered.** (a) The eight tokens the existing implementations use: every mapped token that says why a call
could not be *set up*. (b) The six the profile names. (c) A rule instead of a list: any token §15.4 does not list as
valid on `bye` — tidy, but it would also rewrite `gateway.unreachable`, `media.unsupported` and `session.timeout`, which
are useful mid-call and which `gateway/inbound-bye-q850-41-unreachable` already pins as kept.

**Draft choice.** (a). Vectors `inbound-active-declined-becomes-mapped`, `-unavailable-becomes-mapped`,
`-not-in-service-becomes-mapped`, `inbound-active-media-token-stays`; all three implementations agree.

**Applied to the spec (2026-09-18).** G§4 lists the eight tokens and says every other mapped token is kept mid-call.
The §15.4 point below is **not** applied: it changes which `bye` reasons warn `reason-not-valid-on-type`, so it is a
registry decision with vector changes, not wording.

**Suggested fix.** G§4: replace the parenthetical with the eight tokens. Separately, §15.4's "valid on" for
`gateway.unreachable`, `media.unsupported` and `session.timeout` should admit `bye` if a gateway may send them there.

**Decision on the §15.4 point (2026-09-20).** All three admit `bye`. Applied: the §15.4 "valid on" column
(`session.timeout`: cancel, bye; `media.unsupported`: reject, bye; `gateway.unreachable`: reject, bye, error) and the
A.5 errata list; the three registries; vectors `semantic/bye-reason-gateway-unreachable`, `-media-unsupported`,
`-session-timeout` (accepted, no `reason-not-valid-on-type`). G§4.2's BYE-cause sentence used to say "the `session.*`
tokens valid on `bye`" for the cause-16 set; it now names `session.already-answered` and `session.cancelled`, because
`session.timeout` is valid on `bye` and keeps 102 (`gateway/outbound-bye-session-timeout-keeps-its-cause`).

## 79. G§4.2 — Q.850 causes the table does not give

**Gap.** G§4.2 maps an unregistered token "by its §15.1 category (`user`→603, `endpoint`→480, …)" — statuses only — yet
G§3 requires every crossing to carry a `Q.850;cause` where one applies, and the vectors pin one
(`outbound-unknown-token-category-fallback`: 603 **with cause 21**). Likewise an ACTIVE teardown is "BYE with the
cause", but the BYE rows name only `user.hangup`/`session.*` (16) and `media.failed` (47); `outbound-bye-policy-terminated`
pins 31, taken from the token's pre-answer row.

**Choices considered.** (a) A category fallback takes the cause of the category's representative row (`user` 21,
`endpoint` 18, `identity` 1, `session` 41, `media` 65, `policy` 21, `transport` 41, `gateway` 38); a BYE takes the
token's table cause when the BYE rows do not name it, else 16. (Settled by fuzz.py, 2026-09-18: "`session.*` → 16" in the
BYE rows means `session.already-answered` and `session.cancelled` — the `session.*` tokens valid on `bye` at the time;
spec-gap 78's later decision admits `session.timeout` on `bye` without moving it into this set. Any
other registered token keeps the cause of its own row, so a BYE for `session.timeout` is cause 102, which says more than
"normal clearing"; an unregistered token has no row and is 16, category fallback being a pre-answer rule. Vectors
`outbound-bye-session-timeout-keeps-its-cause`, `outbound-bye-unregistered-token-is-cause-16`.) (b) No cause on a fallback — the `Reason: DSIP` header
already carries the literal token.

**Draft choice.** (a), as the implementations already agreed; new vector
`outbound-unknown-endpoint-token-category-fallback` (480, cause 18) pins a second category.

**Suggested fix.** G§4.2: add the cause to each category fallback, and a sentence for BYE causes.

**Applied to the spec (2026-09-18).** G§4.2 gives each category fallback its cause and has a "BYE causes" paragraph.

## 80. M§5.2 — the deposit class field table

**Gap.** M§5.1 orders a deposit's refusals "… the class (unregistered → `mailbox.unsupported-class`), the class field
table below, and the size constant", and M§5.2's table has a "carries" column: what a class is *for*. It does not say
which of the other deposit fields a class may also carry, so `deposit-fields` — a refusal every mailbox and hub must
agree on — had no complete definition outside the two existing implementations. The second implementation wrote the
table from the prose and passed every vector; a differential probe (each class × each field, 87 temporary vectors run
through all three implementations) then found **seven** disagreements no vector covered: `recipient` on `application`,
`handshake`, `archive` and `group-info` (allowed — it is addressing, not class, and a hub's fan-out to a mailbox is an
`application` deposit with `recipient` and `seq`); `ratchet_tree_blob` on `welcome` and `group-info` (allowed, M§6.4);
`blobs` on `handshake` (refused — the manifest names what *content* references).

**Choices considered.** (a) The existing implementations' table, which the prose supports on each of the seven
points once read closely. (b) A looser rule — refuse only fields that contradict the class (an `ephemeral` with `mls`)
and ignore the rest — simpler, but then two services disagree about the same deposit.

**Draft choice.** (a). The table is now written out in the vectors README; vectors `deposit-application-fanout-valid`,
`deposit-handshake-with-blobs-refused`, `deposit-welcome-ratchet-tree-blob-valid`,
`deposit-group-info-ratchet-tree-blob-valid` pin the points that had none.

**Suggested fix.** M§5.2: replace the "carries" column with MUST-carry / MAY-carry columns, and say that `recipient`
is class-independent.

**Applied to the spec (2026-09-18).** M§5.2 keeps its descriptive table and gains "The class field table" beneath the
field list — MUST-carry / MAY-carry per class, `recipient` class-independent, `welcome` with `seq` per spec-gap 83 — the
same table the vectors README carries.

## 81. M§6.5 / M§7.4 / M§14.1 — orders and scopes the traces never exercised

**Gap.** Three places where the profile gives a list of rules and the services must pick one answer. None had a vector
with two rules in play, so the second implementation passed the whole suite (867 of 867) and still disagreed with Rust
and Python once random traces were run through all three (about 3,000 generated hub and mailbox traces; Rust and Python never
disagreed with each other):

1. **A hub's refusals** (M§6.5 rules 1–3 are a list, not an order). The reference order: moved → unsupported class →
   expired ephemeral dropped → *sequenced bytes seen before are `accepted duplicate`* → membership / M§6.8 → epoch →
   commit validity. The second implementation authenticated first, as rule 1's position suggests. The notable point is
   the fourth: a re-deposit is answered before membership and epoch, so a member removed since, or a retry arriving an
   epoch late, still learns its item was ordered — and so does anyone else who holds those bytes.
2. **The handover wait** (M§7.4, spec-gap 71) says the mailbox "refuses the new hub" until the old hub's items are
   stored. The reference holds off *everything* from the new hub, a `group-info` included, and answers "retry"
   (`mailbox.unknown-group`) before judging a wrong `seq` (`policy.blocked`); the second implementation held off only
   sequenced items and judged numbering first.
3. **First-contact rate limits** (M§14.1, §19.4) are stated for introductions. The reference counts, and limits, a
   `grant` deposit the same way.

**Choices considered.** (1) (a) the reference order; (b) membership first — but then a removed member's retry is
refused `policy.blocked` though its item *was* ordered, which M§9.3's idempotence exists to prevent. (2) (a) everything
waits; (b) only sequenced items — a GroupInfo from a hub the mailbox is not yet sure of would replace the stored one.
(3) (a) both kinds; (b) introductions only — a grant answers an introduction the *owner of the other mailbox* sent, so
limiting it with the stranger's budget can delay a legitimate answer; on the other hand an unlimited `grant` class is
an unmetered way to write into someone's mailbox.

**Draft choice.** (a) in all three, as pinned now: `hub-refusal-order-*` (4), `mailbox-hub-move-wait-covers-everything-
from-the-new-hub`, `mailbox-grant-counts-toward-the-rate-limit`, `mailbox-push-in-device-order`, and
`commit-retry-unknown-mailbox-condition-after-a-conflict` (the §15.3 fallback's one retry is its own, inside the bound
of three proposals). (3) deserves a second look: a separate, more generous budget for grants would answer both worries.

**Decision on (3) (2026-09-18).** Neither (a) nor (b): a **solicited** grant bypasses the limit. The owner's device
tells its own mailbox which introductions it sent — `mailbox-config` `introductions_sent` (new schema field, ≤ 256 ids per
message, durable) — before depositing each one. A `grant` deposit whose `session` names one is the answer the owner asked
for: not counted, not limited, and it consumes the entry (one introduction, one answer). Any other grant is an
unsolicited write and takes the introduction budget. It is the core's own `grant-unknown-introduction` test (§19.4),
applied where the abuse would land. Applied: M§5.7, M§14.1, the profile schema set; `mailbox-grant-counts-toward-the-rate-
limit` became `mailbox-unsolicited-grant-takes-the-introduction-budget`, plus `mailbox-solicited-grant-bypasses-the-rate-
limit`, `-bypass-is-single-use`, `mailbox-introductions-sent-survives-restart` and two `mailbox-config-introductions-sent-*`
message vectors; all three mailbox machines; the mailbox service passes a grant's `session` through and `dsip-msg`
announces an introduction to its mailbox before sending it.

**Suggested fix.** M§6.5: state the order. M§7.4: "refuses every deposit from the new hub".

**Applied to the spec (2026-09-18).** M§6.5 has "The order of a hub's refusals" (seven steps, the duplicate answer
before membership and epoch, with why); M§7.4 says the wait covers every deposit from the new hub and that the retry
answer comes before the numbering is judged.

## 82. §12.7 / §13.3 — session traffic for a session the relay never saw

**Gap.** Found by `impl/tools/fuzz.py` (the `relay` target: the implementations differ on most random traces, all
for this one reason). A relay tracks an attempt from the invite it forked. What does it do with session traffic —
`progress`, `answer`, `reject`, `cancel`, `bye`, `info`, `update` — naming a `session` it holds no attempt for? Rust and
Python drop it (`drop unknown-attempt`). The second implementation routes it by `to`, queueing for an unbound recipient,
because the vectors README says of the relay "`{"recv": any}` to a known but unbound identity/device: queued (§13.3)".
Neither the spec nor a vector says which. It is not an edge: a relay that restarts mid-call has no attempts, and under
the first reading it then drops every `bye` of every call set up before the restart; under the second, anyone can have
a relay carry session traffic for sessions that never existed.

**Choices considered.** (a) Attempt-scoped: drop what belongs to no known attempt (as Rust and Python). (b) Routed by
`to` like any envelope — pre-answer leg traffic needs the attempt (it is forwarded to the initiator, whom only the
attempt names), but anything carrying a device `to` is store-and-forward (§13.3). (c) (b), but only while the attempt is
unknown *because the relay lost it*: indistinguishable to the relay, so not really a choice.

**Decision (2026-09-18).** (b): route by `to`. The attempt record is for three things only — forwarding a leg's
pre-answer traffic to the initiator, delivering a `cancel` per leg, and signalling the outcome; everything else is an
envelope like any other: to the bound device it names, or every device bound for the identity it names (in device
order); held for a known, offline recipient; otherwise `error` `transport.unknown-recipient` to its sender, never a
silent drop. Applying it surfaced four neighbours, settled the same way and pinned with it:

- traffic from a device that is **not a leg** of a known attempt is routed by `to`, not dropped;
- a `cancel` whose `to` is one leg's **device** cancels that leg alone (§12.11), the attempt going on with the others;
  addressed to a device that is not a leg, it is routed by `to`; and it never takes the identity's queued invite with it;
- a leg can still be added in the invite's last second (`expires_at >= now`, as §12.10 counts it);
- when several queued invites expire together, the relay reports them in recipient order.

Applied to the spec (§13.3, A.5), the vectors (`state/relay-unknown-session-*`, `state/relay-device-addressed-cancel-*`,
`state/relay-cancel-addressed-to-a-device-that-is-not-a-leg`, `state/relay-traffic-from-a-device-that-is-not-a-leg-is-routed`,
`state/relay-leg-added-at-the-invites-last-second`, `state/relay-expiry-reports-in-recipient-order`) and all three
implementations; the `relay` fuzz target is back in `--target all`.

## 83. M§6.5 / M§8.5 — where a device starts counting a group's `seq`

**Gap.** Found by `fuzz.py` (the `resume` target). Spec-gap 69 says "a device that has just joined takes the first
sequenced item it processes as its position". In the durable delivery state (`resume-trace`), Rust and Python record a
group's first item as *seen beyond a gap* (`contiguous: 0, seen: [4]`); the second implementation records it as the
position (`contiguous: 4`). Every vector starts a group at `seq` 1, where the two are the same. They differ when a lower
`seq` arrives later: the first reading processes it, the second calls it a duplicate. Lower seqs are normally pre-join
history the device cannot decrypt — but after a hub handover wait (spec-gap 71) a mailbox does store the old hub's late
items out of order, so "lower and later" can be a real item.

**Choices considered.** (a) The first item is the position (spec-gap 69's words): what came before is history.
(b) The first item is merely seen: nothing is ever wrongly called a duplicate, at the price of a `contiguous` that never
reaches the items before the join. (c) (a), except that a welcome carries the `seq` of the commit that added the device,
and the position starts there — exact, but it needs the welcome's seq in the resume state.

**Decision (2026-09-18).** (c): from the welcome's `seq`. A hub-forwarded `welcome` carries the `seq` of the commit
that added the device (M§5.2: `welcome` MAY carry `seq`; `ephemeral` still may not); the device's position for the group
starts there, so anything at or below it is a duplicate and anything above it is processed or waited for, whatever order
the mailbox delivers in. A welcome with no `seq` keeps the old rule (the first sequenced item processed is the
position). A welcome for a sibling device sets nothing; a re-join by external commit is a join, positioned at its own
`accepted`. A mailbox never sequences a welcome by that `seq` nor echoes it in the acknowledgement (M§6.5, spec-gap 66).
Applied to the profile (M§5.2, M§6.5), the vectors (`messaging/deposit-welcome-with-seq-valid` — replacing
`deposit-welcome-with-seq-refused`, a reading the decision reverses — `deposit-ephemeral-with-seq-refused`,
`resume-welcome-seq-is-the-starting-position`, `resume-late-item-after-the-join-is-processed`,
`resume-welcome-without-seq-starts-at-the-first-item`, `resume-sibling-welcome-seq-sets-no-position`,
`resume-rejoin-is-a-join`) and all three implementations; the `resume` fuzz target is back in `--target all`.

## 84. §12.6 — glare with more than one attempt of our own

**Gap.** Found by `fuzz.py` as the first disagreement between Rust and Python themselves. An endpoint may have two live
attempts to the same identity (one addressed to the identity, one to a device). §12.6 speaks of "its outbound invite",
singular. On an inbound invite from that identity each implementation picked *one* rival — Python and TypeScript the
first placed, Rust whichever its map yielded — withdrew that one, and left the other ringing.

**Decision (2026-09-18, from the text).** "The invite with the lexicographically smaller `id` wins", over *all* the
invites between the two identities: if any of ours is older than theirs, theirs is rejected and ours are left alone;
otherwise each of ours lost, and each is withdrawn, in id order. Applied in all three; vectors
`state/glare-every-losing-attempt-is-withdrawn`, `state/glare-lowest-id-of-all-decides`.

**Suggested fix.** §12.6: say "each outbound invite to that identity".

## 85. §12.4 / §12.7 rule 4 — the `bye` a late answer gets once the call has ended

**Gap.** The §12.4 initiator table gives a late answer's `bye` in two ended states: after our `cancel`
(`session.cancelled`, §12.5 rule 3) and after an attempt "ended by `reject` or timeout" (`session.failed`, spec-gap 12).
It says nothing about the third: the session reached ACTIVE, ended with a `bye` (ours or the peer's), and another leg's
answer arrives after that — with forking that is an ordinary race, not an edge. Rust and Python send
`session.already-answered`; the second implementation, reading the table's two rows as exhaustive, sent
`session.failed`. Unpinned by any vector; noticed by reading, and confirmed by the vectors below before they were fixed.

**Choices considered.** (a) `session.already-answered`: §12.7 rule 4 says "exactly one answer is ever applied per
invite; any subsequent answer from another leg" gets it — a rule about the invite, not the state, and it is the truthful
reason. (b) `session.failed`: the fallback the table names for an ended attempt. (c) `session.cancelled`: wrong — nothing
was withdrawn.

**Decision (2026-09-20).** (a). The `bye` follows what the invite was: `session.cancelled` when we withdrew it,
`session.already-answered` when an answer was applied (however the call then ended), `session.failed` when the attempt
was never answered. Applied to §12.4 (a third ENDED row) and §12.7 rule 4; vectors
`state/fork-late-answer-after-the-call-ended`, `state/fork-late-answer-after-our-hangup`; the second implementation
now tracks whether an answer was applied.

## 86. §12.7 rules 3–4 / §13.2 — the relay must not withhold an `answer`

**Gap.** A forking relay marks a leg terminated when it delivers a `cancel` to it, when the invite expires at the relay,
or when the leg rejects. All three implementations then dropped *everything* the leg sent, `answer` included
(`drop leg-terminated`, pinned by `state/relay-user-cancel-all-legs`). But an answer can cross the cancel (§12.5 rule 3
exists for exactly that), and a device alerted just before `expires_at` can answer just after it: the device is then
ACTIVE, waiting for media, and the `bye` that §12.5 rule 3 / §12.4 make the initiator send never comes, because the
initiator never saw the answer. Silent on the wire, and at odds with spec-gap 82, under which a relay that has *lost* its
attempt record forwards that same late answer (`state/relay-unknown-session-routed-by-to`): a relay that remembered
more delivered less.

**Choices considered.** (a) Forward every `answer`, whatever the leg's state; the initiator alone ends an answered leg
(`already-answered`, `cancelled` or `failed` by §12.7 rule 4, §12.5 rule 3, §12.4). (b) Route it by `to` like unknown-
session traffic: same wire effect, but it is an attempt's own leg traffic and the record should not pretend otherwise.
(c) Keep dropping, and have the relay `bye` the leg itself: the relay speaking for the initiator (§15.2 forbids composing
in another's name). (d) Forward `progress` and `reject` from terminated legs too: no — the initiator cannot see legs, so a
stale `progress` or a second `reject` would read as the attempt's own, and nobody needs them.

**Decision (2026-09-20).** (a), with the leg record moving only for a leg that was still outstanding: a cancelled,
expired or rejected leg that answers is forwarded and stays recorded as cancelled, expired or rejected, and the attempt's
outcome is unchanged. `progress` and `reject` from a terminated leg are still `drop leg-terminated` — the relay screens
them because only it can. Applied to §12.7 rule 3 and §13.3; `state/relay-user-cancel-all-legs` reversed (the crossed
answer is forwarded), `state/relay-answer-from-an-expired-leg-is-forwarded`,
`state/relay-answer-from-a-rejected-leg-is-forwarded`; all three implementations.

## 87. M§6.5 rule 5 / spec-gap 66 — whose queue the welcome holds

**Gap.** Found by `impl/tools/fuzz.py` (seed 3, the `hub` target). The M§6.5 erratum for spec-gap 66 says that until
"that mailbox" — the added identity's — acknowledges its welcome, the hub sends it nothing else for the group, "it has no
registration yet". Read literally, "the added identity" includes a member adding its own device, whose mailbox is
registered and which the same paragraph says gets the commit *and* the welcome. Rust and Python used "has an
unacknowledged welcome" as the test: at the commit they fanned it out to the member (the welcome was queued after), but
on a restart they held that member's head back, and on the welcome's acknowledgement they sent it again. The second
implementation tracked the identities with no registration and held only those. Three readings of one paragraph.

**Choices considered.** (a) Hold the queue of an identity the commit brought in, and only that: the reason the text
gives. (b) Hold any identity with an unacknowledged welcome, consistently — at the commit too: a member's other devices
would then wait for its new device's mailbox acknowledgement for no reason. (c) Hold nothing and let the mailbox refuse
and the hub retry: what spec-gap 66 rejected.

**Decision (2026-09-20).** (a). The hold is by registration, not by welcome: an identity with no registration for the
group (brought in by the commit; an external joiner joins by its own commit and has one) has its sequenced queue held
until its welcome is acknowledged — at the commit, on retry and after a restart alike; a member that gained a device is
registered and its queue moves only on its own acknowledgements. The hold covers every send: an acknowledgement from
an identity still waiting for its welcome (seed 5 found Rust and Python answering it with the next item) moves its queue
and sends nothing. Applied to M§6.5, the README, Rust and Python (a durable `unregistered` set); vectors
`messaging/hub-member-adding-its-own-device-is-not-held-behind-the-welcome`,
`messaging/hub-acknowledgement-does-not-lift-the-welcome-hold`.

## 88. M§7.4 / spec-gap 71 — announcing the handover wait's expiry on a refused deposit

**Gap.** Found by `fuzz.py` (seed 3, the `mailbox` target). The expiry of `handover_wait` is noticed lazily, at the new
hub's first deposit after it (spec-gap 71's vectors). When that deposit is itself at or below `handover_seq`, it is
refused `policy.blocked` — and Rust and Python returned the refusal alone, discarding the `handover_expired` they had
just computed while keeping the released state, so the expiry was never announced at all. The second implementation
emitted both. An implementation defect in the two, not a reading; recorded because the profile text never says the
announcement is unconditional.

**Decision (2026-09-20).** The expiry is announced once, at the first deposit from the new hub after the wait ran out,
whether that deposit is then admitted or refused. Applied to M§7.4 and the README; vector
`messaging/mailbox-hub-move-handover-wait-expiry-announced-on-a-refused-deposit`; Rust and Python fixed.

## 89. §12.7 rule 3 / §12.11 — the order a relay reaches several legs in

**Gap.** Found by `fuzz.py` (seed 3, the `relay` target): the first disagreement of Rust with Python *and* the second
implementation. Nothing in the spec orders a fan-out, and the suite's rule ("device (DID) order wherever a relay or
mailbox fans out", spec-gap 82) was applied by Python and the second implementation to routing, but not to the two
fan-outs that walk the attempt record: a `cancel` to the identity reached the live legs in the order they were
delivered, and a device binding into several live attempts got their invites in the order the attempts were made. Rust
keeps both in ordered maps and so used DID order and id order. Only visible when delivery order differs from DID order,
which the suite's fork event, listing legs in DID order, never did.

**Decision (2026-09-20).** DID order and id order everywhere, as the suite already says: a real relay forks in DID
order anyway (its binding table), so the record's insertion order is an artefact of the harness's explicit leg list.
Applied to the README, Python and the second implementation; vectors `state/relay-cancel-reaches-live-legs-in-device-order`,
`state/relay-late-binder-gets-live-invites-in-id-order`. No spec text: emission order is the suite's contract, not the
protocol's.

## 90. §12.4 / §12.9 — a local `place_call` on a session the endpoint already holds

**Gap.** Found by `fuzz.py` (seed 3, the `endpoint` target). The harness's `place_call` names its session id. All three
implementations accepted one for an id already held — a PROCEEDING session went back to INVITING with a second
`invite` on the wire and a second T-Establish, while its T-Ring ran on; they then differed on what the timers did at
expiry. §12.4 has no transition on a local call request from any session state, and §12.9 makes the id a ULID the
replay check remembers: an id is used once.

**Decision (2026-09-20).** A `place_call` naming a session this endpoint holds, live or ended, is `refused
invalid-state` and changes nothing (the timers run on). A local-API rule, so README only; vector
`state/place-call-on-a-held-session-is-refused`; all three implementations.

## 91. M§6.6 / M§12.2 — what a pending group's expiry drops

**Gap.** Found by `fuzz.py` (seed 4, the `mailbox` target). M§6.6: an unconfirmed pending group "is dropped, with its
items". An archive deposit (M§12.2) names a group by reference and needs no registration for it — history outlives
leaving, and a later welcome for the same group makes a new, pending registration. Rust and Python kept archive records
through the drop (deliberately, unpinned); the second implementation dropped every item filed under the group, archive
records included, which would erase the owner's history of a group they left and were re-invited to, if the invitation
lapsed.

**Choices considered.** (a) Drop the hub deposits the pending group admitted, keep archive records: the records are the
owner's, stored by reference whatever the registration. (b) Drop everything filed under the group: the literal reading,
and it destroys history for a registration the owner never confirmed. (c) Refuse archive deposits for a group with no
confirmed registration: a device archives what it decrypted, and its `joined` config may arrive after its first archive.

**Decision (2026-09-20).** (a). Applied to M§6.6 and the README; vector
`messaging/mailbox-pending-group-expiry-keeps-archive-records`; the second implementation fixed.

## 92. M§6.6 / spec-gap 59 — which cursor a redelivery carries

**Gap.** Found by `fuzz.py` (seed 5, the `mailbox` target). Spec-gap 59: a redelivery is acknowledged as a duplicate
"with the original cursor while the item is still retained". After the owner leaves a group and registers it again at
another hub, a redelivered `seq` the mailbox still retains from the first registration got its cursor from Rust and
Python (which look items up by group and seq) and no cursor from the second implementation (which kept the seen map per
registration and had dropped it with the `left`). Reading all three showed a shared defect underneath: the lookup by
group and seq also matches an archive record (M§12.2), whose `ref_seq` is in the same seq space, and returns its cursor
if it was stored first.

**Choices considered.** (a) By group and seq among retained hub items: the group is the same group and its numbering
is the hub's; whether the owner's registration lapsed in between is no concern of the hub retrying. (b) Per
registration: a redelivery after re-registration is a duplicate without a cursor — true but less useful, and a mailbox
would have to remember which registration stored what. (c) Treat it as new and store it again: two items for one seq.

**Decision (2026-09-20).** (a), and an archive record is never the item. Applied to M§6.6 and the README, all three
implementations; vectors `messaging/mailbox-hub-deposit-redelivered-after-re-registration-carries-the-retained-cursor`,
`messaging/mailbox-hub-deposit-redelivery-cursor-is-never-an-archive-records`.

## 93. M§7.4 / spec-gap 71 — when an old hub's item is a fill and when a redelivery

**Gap.** Found by `fuzz.py` (seed 6, the `mailbox` target). Spec-gap 71: after the handover wait expires with items
missing, what the old hub still delivers at or below `handover_seq` "is stored rather than taken for a redelivery".
The second implementation switched to that treatment as soon as the new hub was admitted — with nothing missing, no
wait and no expiry — and then stored an old-hub item below the highest stored that Rust and Python, applying spec-gap
59's redelivery rule, acknowledged as a duplicate.

**Decision (2026-09-20, from the text).** "After that" is after an expiry: only a wait that ran out with items missing
makes the old hub's later items below the highest stored fills; a move with nothing missing changes nothing about
redelivery. Applied to the README and the second implementation; vector
`messaging/mailbox-hub-move-old-hub-item-below-the-highest-stored-is-a-redelivery`.

## 94. M§6.6 / spec-gap 66 — how long a welcome is "already held"

**Gap.** Found by `fuzz.py` (seeds 9, 11 and 12, the `mailbox` target, three probes of one shape). Spec-gap 66: a
mailbox answers a welcome "whose MLS bytes it already holds" as a duplicate with the first one's cursor. The second
implementation remembered every welcome's bytes for ever, so a welcome arriving after its pending registration had
expired — and taken the stored welcome with it (M§6.6) — was still a duplicate, answered with a cursor that no longer
existed, and the group was never registered again; and it matched the bytes across groups. Rust and Python looked
among the welcomes still held, but not by group either.

**Decision (2026-09-20).** "Already holds" is literal: among the welcomes the mailbox still holds, for that group. After
an expiry the same welcome is a new invitation — stored, registered pending again, its own cursor; the same bytes for
another group are that group's welcome. Applied to M§6.5, the README and all three implementations; vectors
`messaging/mailbox-welcome-after-pending-group-expiry-is-stored-anew`,
`messaging/mailbox-welcome-same-bytes-for-another-group-is-its-own`.

## 95. M§7.4 / spec-gap 71 — what "missing" means during a hub move

**Gap.** Found by `fuzz.py` (seed 9, the `mailbox` target). During a move the new hub is held off "while the old hub's
items through `handover_seq` are missing". Rust and Python judged that by the highest `seq` stored (nothing is missing
once it reaches `handover_seq`); the second implementation kept a map of the seqs it had seen since the registration and
called every unseen one missing, so with seqs 1 and 3 stored and `handover_seq` 3 it held the new hub's GroupInfo off
while the other two admitted it. Spec-gaps 59 and 93 already reason from the high-water mark: the hub delivers in order
and retries before sending later items (M§6.5 rule 5), so a stored `seq` says every lower one was delivered before it.

**Decision (2026-09-20).** By the highest `seq` stored, as everything else about redelivery is. Applied to M§7.4, the
README and the second implementation; vector
`messaging/mailbox-hub-move-nothing-missing-once-the-highest-stored-reaches-handover-seq`. The relay probe of seed 10
was a generator artefact — the same invite id introduced twice, which the replay stage never lets through — and the
generator now introduces an id once.

## 96. §12.9 / DHT profile §2, §4 — the replay window kills reachability hints after 300 s

**Gap.** Found on the WAN testbed (2026-10-02, `impl/tools/wan/README.md` Runs 1–2), invisible on localhost and
to the suite. The DHT profile applied "envelope rules unchanged: 300 s replay window on `issued_at`", at every hop
(§4: before a node stores, forwards or returns a record), while allowing `expires_at − issued_at` up to 3,600 s and
re-signing at ⅔ of the lifetime. Read together: a hint becomes unusable 300 s after signing whatever its TTL. With
the CLI's 600 s TTL, Bob re-signs every 400 s, so he is undiscoverable for 100 s of every cycle — measured: at
`issued_at + 321 s` all three copies returned `replay-window` and `hint none verified`, ~280 s before `expires_at`,
with Bob online and bound. Replication fails the same way: a node that joins or rejoins (Run 2's restarted
bootstrap) received the record twice by Kademlia replication and rejected both copies `replay-window`, so a node
that misses a hint's first 300 s can never hold it. This is spec-gap 31 again, for the other envelope type that is
stored and forwarded by design.

**Choices considered.** (a) As gap 31: for `reachability-hint`, the age bound is the record's own `expires_at`;
the future bound stays; `expires_at − issued_at` is capped (3,600 s, the existing SHOULD made a MUST so the
relaxation stays bounded). Replay is harmless — §8.3 already discards a lower `seq` and treats identical content
as a no-op, and the record is the signer's own claim about itself — so `id` deduplication does not apply. (b) Keep
the window and require re-signing every < 300 s: 3,600 s TTLs become meaningless, publish traffic rises ~8×, and
replication to late joiners still fails. (c) Exempt hints at storage but not at read: readers would still reject
what nodes serve.

**Decision (2026-10-02, user: "option (a), gap-31 style").** (a). Written into core §12.9 (second exception and
the errata line) and DHT profile §2. New reject code `hint-validity` (vectors README). Envelope stage 9 for
`reachability-hint`: `expires_at − issued_at > 3,600` → `hint-validity`; `issued_at > now + 300` →
`replay-window`; `expires_at < now` → `expired`. `dsip --hint-ttl` refuses values over 3,600. Vectors:
`dht/hint-held-accepted`, `hint-held-expired`, `hint-future-rejected`, `hint-validity-over-cap`,
`hint-held-newer-wins`, `hint-held-duplicate`; the cap edge is `dht/valid-self-signed-did-key` (TTL exactly 3,600).

## 97. §20.7 / §10.2 / §12.7 — signaling bodies are readable by every relay that routes them

**Status: decided 2026-10-02 — (a), static key accepted, padding 256 (user).** Raised 2026-10-02 after the WAN campaign ("what stops a bad
actor's relay from stealing user data?"). §20.7 already names "payload encryption to the recipient's
key-agreement key (sealed-sender-style delivery)" as a v1.x candidate and Appendix A lists "sealed-sender signaling
confidentiality" as forward work; this entry turns that into a concrete choice.

**Gap.** Core envelopes are signed, not encrypted (§10.2, §20.7). A relay cannot forge, alter, replay or splice
them, and cannot touch media (DTLS fingerprints ride in the signed SDP) or Messaging Profile content (MLS). But
it reads every field it routes. What a hostile relay learns today, per message (schemas, v0.8):

| Field | Carried by | What it reveals | Relay needs it? |
|---|---|---|---|
| `type`, `id`, `from`, `to`, `session`, `in_reply_to`, `issued_at`, `expires_at`, `dsip` | all | who, whom, when, which call | **yes** — routing by `to` (§13.3, spec-gap 82), attempt tracking and forking (§12.7), replay window (§12.9), store-and-forward expiry |
| `reason` (registry token), `retry_after` | reject, cancel, bye | coarse outcome (`user.busy`, `user.no-answer`) | **yes** — §12.7 rule 6 picks among leg rejects by reason; the relay itself emits `transport.no-response` (spec-gap 76) |
| `status` (progress registry token) | progress | ringing / queued | no rule uses it — the relay forwards it (`dsip-session` fork tracker records it in its emissions); T-Ring/T-Queue are the endpoints' timers |
| `transports[].sdp` | invite, answer, update | every ICE candidate (host, srflx, relay addresses: **the users' IP addresses**), codecs, DTLS fingerprint | no |
| `identity` (identityInfo: display name, claims) | invite | the caller's presented name and claims | no |
| `intent`, `policy` | invite, answer, update | why the call is placed, recording/screening policy | no |
| `answered_by` | answer, update | user / screening / gateway / service | no |
| `media` | invite, answer, update | what media is offered or selected | no |
| `data`, `about` | info | DTMF digits (§12.12, spec-gap 70), WebRTC trickle candidates — **IP addresses again** | no |
| `detail` | reject, cancel, bye | free text | no |
| `grant` | invite | id of a first-contact grant (§19.4) | only a stateless relay checking first contact; otherwise no |

The bottom half is the sensitive half: IP addresses (from SDP and trickled candidates), names, DTMF digits
(PINs typed into an IVR), and policy. None of it is used by any relay rule in §12–§13.

**Not in scope — sender anonymity.** A relay binds every connection to a device DID with `hello` (§13.2), and a
caller binds to the *callee's* relay to reach them, so the relay always knows who is talking to whom. "Sealed
sender" in the Signal sense needs anonymous binding plus a delivery token, which conflicts with per-device rate
limits and with `hello` anti-splicing. This gap is about **body confidentiality**, and the name should say so
("sealed signaling bodies"), not promise metadata privacy (§20.7 stays true).

**Choices considered.**

(a) **Seal the body to the peer identity's `keyAgreement` key; keep the routing header clear; encrypt then
sign.** The payload keeps the "relay needs it" fields above in clear and replaces the rest with
`sealed: {alg, enc, ct}` — the §19.4 / M§6.9 / M§14.1 HPKE construction (X25519 `keyAgreement` key from the
recipient's DID document, §7.2), with the clear header (`type`, `id`, `from`, `to`, `session`) as HPKE `info`/AAD so
a ciphertext cannot be cut from one message into another. The outer signature covers the payload bytes including
`ct`, so §10.2 (signature over bytes, no re-serialization) is unchanged, relays still verify, and the replay
window and dedup still apply to the clear `id`/`issued_at`. Encrypted to the **identity** key, not a device key:
the caller does not know the callee's devices (the relay forks to them, §12.7), and every device acting for the
identity can open it. Responses (`answer`, `update`, `info`) are sealed to the *caller's* identity key, which the
callee already resolves to verify the invite. Schema validation of sealed fields moves after decryption at the
recipient — a new pipeline stage between signature verification and payload schema (`impl/vectors/README.md`),
with new verdicts (candidates, in the style of `introduction-purpose-and-sealed`: `body-unseal-failed`,
`body-field-and-sealed` for a field present both in clear and in the seal, `routing-field-sealed`).

(b) **Encrypt the whole payload, routing fields included.** The relay can then neither route by `to` nor run
§12.7 forking, the §13.3 queue, or spec-gaps 75/76/86 — it would degrade to a blind byte pipe plus an outer
routing envelope, i.e. a second envelope format. Rejected: it rebuilds what (a) keeps clear, at the cost of a new
layer.

(c) **Status quo: hop-by-hop TLS, "run your own relay" (§20.7).** Correct and already stated, but the callee's
relay is the *callee's* choice: a caller cannot avoid exposing its IP addresses and name to whatever relay the
callee picked.

(d) **A two-member MLS group per call** (reusing the Messaging Profile). Gives forward secrecy, but needs key
packages fetched before the first `invite` (an extra round trip and a mailbox dependency for plain calling) and
does not fit forking to devices the caller cannot see. Better as the later upgrade for long-lived sessions than as
the base mechanism.

(e) **Per-device HPKE.** Needs the device list up front — conflicts with relay forking and leaks the device
count. Rejected.

**Draft choice.** (a), as an optional extension first (`dsip.extensions`, e.g. `sealed-body/1.0`), not a core MUST:
- A sender MAY seal when the recipient's DID document carries a `keyAgreement` key; it SHOULD when the recipient
  advertises the extension. Sealing is never inferred from a hint (DHT records are not authoritative, §8.1).
- A recipient that advertises the extension MUST accept sealed and clear bodies; one that does not MUST reject a
  sealed body with a registry token (candidate: `media.unsupported`-style new `signaling.sealed-unsupported`), so the
  sender can retry in clear only if its policy allows.
- `did:key` identities: the Ed25519 → X25519 conversion gives every `did:key` a key-agreement key with no document,
  so the flagship path works unchanged.

**Costs and open questions.**
1. **No forward secrecy.** HPKE base mode to a static identity key: whoever later obtains that key reads every
   captured sealed body. Mitigation: `keyAgreement` rotation (§7.5 already rotates keys) and (d) for long sessions.
   Is a static-key mode acceptable for v1.x?
2. **Relay content screening ends** for sealed bodies (as §19.4 already accepts for sealed introductions); rate
   limits still apply. Gateways (G§) are endpoints and unseal as the identity they act for.
3. **Size leakage.** SDP size varies with candidate count; RECOMMENDED padding of `ct` to 256-byte buckets, inside the
   65,536-byte cap (§13.2).
4. **Device key custody.** Every device of the identity must hold the identity's X25519 private key (as for sealed
   introductions today). Is that acceptable, or should delegation (§7.4) carry a device-scoped key-agreement key
   that the identity key wraps?
5. **Which header fields can still move into the seal?** `reason` on `bye` and `cancel`, and `progress.status`, are
   used by no relay rule (only `reject` reasons are, §12.7 rule 6) — candidates for sealing, at the cost of relay
   vectors that record them.

**Decision (2026-10-02).** (a), with: static-key HPKE base mode accepted (no forward secrecy; rotation is the
mitigation); plaintext padded with spaces to a multiple of 256 bytes, enforced by receivers; key custody as for
sealed introductions (identity key on every device); `bye`/`cancel` reasons and `progress.status` stay clear.
Settled while implementing:
- **Extension id `sealed-body/1.0`** — identifiers are `name/major.minor` (the schema rejected `sealed-body/1`).
  Marked in `dsip.extensions` *and* `dsip.critical`, so an addressee without it rejects with the existing
  `session.unsupported-critical-extension`; no new reason token.
- **Routers route regardless** (§10.4 "Routing"): §11.2's critical rule binds the addressee. Vector context
  `router: true`.
- **Recipient key = the DID in `to`**, which on a response is the caller's *device* (`to` = the invite's `from`);
  a device `did:key` opens with its own derived key. Found wiring the CLI: sealing to the caller's identity would
  have made every sealed `answer` unopenable on the device.
- **Pipeline stage 12b** after the version check, before schema: `sealed-not-critical` → `sealed-alg-unsupported`
  → `body-unseal-failed` → `sealed-plaintext-invalid` → `sealed-field-not-sealable` → `sealed-field-in-clear`;
  stages 13–14 run on the merged payload (`effective.sealed` on accept). Schemas admit `sealed` in place of a type's
  required sealable fields (`anyOf`).
- **Three edges the second implementation found** (its author could not decide them from §10.4 and the README):
  a payload whose AAD inputs (`type`/`id`/`from`/`to`) are not strings is not opened (Python and Rust had answered
  `body-unseal-failed`, impl-ts `schema-invalid` — a real divergence no vector covered; impl-ts's reading adopted);
  a non-array `critical` lists nothing; a type with no sealable fields admits none. Each pinned by a vector.

Written into core §10.4 (new), §20.7, the errata line; schemas (`SEALABLE` in `generate_schemas.py`); vectors README
(stage 12b, six codes, `unseal_key_hex` / `router`). Python harness, Rust (`dsip-core::hpke` — moved down from
`dsip-messaging` — and `dsip-schema::sealed`), impl-ts (written from the spec and README only). 26 vectors (25 `semantic/sealed-*`, `semantic/clear-invite-without-media-rejected`) → 963, three-way parity. CLI: `dsip call|answer --seal`;
inbound sealed bodies always open. Local check through a tracing relay (`RUST_LOG=dsip_relay=trace`): a clear call
exposed 2 SDPs, 10 ICE candidates and a display name; the sealed call exposed none (invite, answer and 8 trickle
`info`s sealed) and carried media both ways.

**Test plan (as adopted).** Vectors first (envelope/: sealed body accepted, tampered `ct`, `ct` moved between
messages, sealed field also in clear, wrong recipient key, unknown `alg`; state/: forking with sealed invites and a
relay reject choice unaffected); Python harness, Rust and impl-ts to three-way parity; then a WAN check that the
relay log and a packet capture on L2 show no SDP and no IP addresses.

## 98. §13.3 — the order a binding device receives what was queued for it

**Gap.** Found by CI's differential fuzz (seed 274, the `relay` target; first seen on PR #65's run, which changed only
a comment). A relay keeps store-and-forward queues per recipient, and a recipient is either a device or its identity
(§13.3, spec-gap 82). When the device binds, both queues are flushed to it. The README said only "`bind` flushes them
in order". Python and Rust flushed the identity's queue first, then the device's (two maps, walked in turn); the
second implementation, reading the README, flushed in arrival order. They differ when a device-addressed envelope
arrived before an identity-addressed one: the probe queued a `cancel` to the device, then one to the identity.

**Choices considered.** (a) Arrival order across both queues — what a relay that keeps one log per device does, and the
plain reading of "in order". (b) Identity queue first — an artefact of keeping two maps; no rule asks for it. (c) Id
order — would reorder envelopes from different senders by their own ULID clocks.

**Decision (2026-10-03).** (a), as spec-gap 89 did for fan-outs: the suite's own wording is the contract and the
implementations that diverged from it are fixed. README states it; Python and Rust record an arrival number when
queuing; the second implementation already complied. Vector
`state/relay-bind-flushes-device-and-identity-queues-in-arrival-order` (device, identity, device queued; delivered in
that order). No spec text: emission order is the suite's contract, not the protocol's — two `cancel`s for different
sessions mean the same in either order.

## 99. M§4.3 / M§4.4 / M§5.6 / M§9 / core §13.3 — storage limits: what `accepted` promises, and how quota is counted

**Status: decided 2026-10-04 (user: "yes to all four") — written into M§4.4, M§5.6, M§9.3 and core §13.3.** Raised by the
user: "if a relay is storing users' messages until they can be sent, what happens when it runs out of space?"

**Gap.** Four places where the profile assumes storage behaviour it never states.

1. **`accepted` and durability.** Senders stop retrying on `accepted` (M§9.2–M§9.4; spec-gap 72's outbox), so a
   mailbox that acknowledges an item it has not made durable loses it at the next restart while the sender believes it
   delivered. The PoC did exactly that: `dsip-mailbox` logged `saving state failed` and carried on. Nothing in the
   profile says `accepted` means "stored durably".
2. **What `quota_bytes` counts** (M§4.3 advertises it; M§4.4 and M§14.3 say quota is `mailbox.quota-exceeded`): which
   stored things count, when the check runs relative to the other refusals, whether a redelivery can be refused, and
   whether introductions — which §19.4 requires to be indistinguishable from an ignoring recipient — are counted.
3. **Blob uploads over quota.** The M§5.6 refusal table (spec-gap 48) has no row for quota.
4. **Relay memory.** §13.3 bounds nothing globally; a per-recipient cap alone lets traffic to many recipients grow a
   relay's store-and-forward memory without bound.

**Choices made (PoC).**
1. A deposit that stored a new item is acknowledged only after the mailbox state is written; if the write fails, the
   step is rolled back and the deposit refused `mailbox.quota-exceeded` with `retry_after` (60 s), so the sender keeps it
   pending. Proposed spec text (M§9): *"A service MUST NOT answer `accepted` for an item it has not stored durably; one
   that cannot store refuses with `mailbox.quota-exceeded`."* Live check: with the mailbox's state directory unwritable
   the fan-out was refused, and after it became writable the hub's retry delivered it exactly once.
2. Quota counts the bytes of retained items (welcomes, hub fan-out, archive records) plus stored blobs. The check runs
   after the duplicate checks — a redelivery is never refused — and after every other refusal of that deposit, before
   anything is stored or registered; a `group-info` that would replace the previous one is checked with the previous one
   still counted. Introductions are never counted or refused for quota (§19.4: they stay bounded by the inbox). Vectors:
   `messaging/mailbox-quota-*` (8).
3. `507 mailbox.quota-exceeded`, decided from the authorized size before the body is read, after `413`; a hash already
   stored is never refused. Vectors: `messaging/blob-put-*quota*`, `blob-put-over-max-and-quota-413`,
   `blob-put-stored-hash-at-full-quota-200`.
4. Relays: a memory budget for queued envelopes across all recipients (`dsip-relay --queue-budget-bytes`, default 64
   MiB), refused with a signed `transport.routing-refused` like the inbox cap (§13.3 forbids silent drops);
   introductions are dropped silently at either bound (§19.4); a `cancel` for an invite still queued is never refused,
   since it only shrinks the queue.

**Hub durability (2026-10-04, closes the known non-conformance).** The reference hub saves a newly accepted item before
answering the depositor or fanning out; if the write fails it restores the group's hub state (machine, public view,
conversation, kept payload) and refuses `mailbox.quota-exceeded` with `retry_after`. To the sender a hub's storage
refusal is the hub unavailable (M§9.4): the item stays pending under the outage backoff and counts toward
`hub_timeout`. The backoff governs; `retry_after` is advisory and not an input to the outbox (a finding of the second
implementation, which asked whether it replaces or floors the backoff). Vectors
`messaging/hub-outage-storage-refusal-is-an-outage`, `-reaches-the-threshold`. Live check: the hub's state directory
unwritable → Alice's message refused and kept PENDING (retry 1, 2, 4 s), sent once after recovery, received once.

**Open (next revision).** Relay store-and-forward is in memory, so a relay restart loses queued envelopes; §13.3 does
not say whether that is acceptable. (`retry_after` was decided: SHOULD on the refusal, advisory to the sender.)

## 100. core §13 — relay service scope: may a relay serve only some identities?

**Status: decided 2026-10-04 (user: "do both, the allowlist and the spec text") — written into core §13.6.** Raised by
the user: "can someone hosting their own relay keep it private, or do we make all relays participate to grow the
network?"

**Gap.** The spec says what a relay does for the identities bound to it, but never whether a relay may choose which
identities those are. Because a sender connects to the *recipient's* relay (the one its DID document names), a relay
that simply refuses outside devices also makes its own users unreachable, and one that binds anyone becomes a free
relay between strangers. Neither is stated.

**Choice made.** §13.6 names three deployments.
- *Open*: serves every identity that binds (the PoC default).
- *Private*: serves an operator-chosen set. It still binds any verified device. It routes only to or from a served
  identity, holds envelopes only for served identities, and is authority only for them. Everything else gets a signed
  `transport.routing-refused`. Introductions are dropped silently (§19.4).
- *Closed*: also refuses `hello` from outsiders. Conformant, but unreachable from outside.

No relay is obliged to serve or forward for anyone. Participation stays voluntary: the network grows with identities,
each bringing its own relay via its DID document, not with shared relays. Rejected: mandatory participation (cost and
abuse liability on hosts, and Sybil exposure that is out of scope per §3.2).

**PoC.** `dsip-relay --serve <DID>` (repeatable) / `--serve-file`; unset = open. `demos/private-relay-demo.sh`
covers an outsider reaching a served identity live and queued, outsider-to-outsider refused, nothing held for an
outsider, and an introduction between outsiders dropped silently. No vectors: this is routing policy outside the
relay state machine (`dsip_session::Relay`), checked before it.

**Open.** A relay cannot yet *advertise* its scope; a `hello` capability (`serves: "open" | "private"`) would let a
client know before it tries. Not needed for correctness, since refusals are explicit.

## 101. §7.2 / §8.1 / §8.4 — `did:webvh` in DSIP: what a resolver must check, and rollback

**Status: decided 2026-10-04 (user: "yes to all 4"; rollback: "cache required, watchers optional") — written into
v0.9 §7.2, §8.4, A.6; pinned by `impl/vectors/did-webvh/` (67 vectors).**

**Gap.** `did:webvh` (DIF Ratified v1.0) makes a domain-hosted DID document unforgeable by its host, but a resolver
that only verifies the log as served still accepts an *older* valid log. A host can roll an identity back to a key it
rotated away from. The method leaves rollback detection to resolver caches, watchers and witnesses. DSIP must also say
which versions it supports and how strictly it reads the log, so that three implementations agree.

**Choices made.**
1. **Rollback:** a resolver MUST cache the highest verified `versionId` per DID, and reject a log that ends before it
   (`rollback`) or differs at it (`fork`). Watchers MAY be consulted. Rejected alternatives: requiring watchers (an
   extra fetch per lookup, and they must exist) and requiring witnesses (a heavy deployment burden).
2. **Fail closed:** any invalid entry rejects the whole log. The method allows a versioned query to succeed below a
   later invalid entry; DSIP resolves only the latest version.
3. **Versions:** `did:webvh:1.0` only.
4. **I-JSON:** every line, and the witness file, must be I-JSON (RFC 7493): no duplicate names, no lone surrogates,
   integers within ±(2^53−1). This was found by probing the three implementations (a third finding of the second
   implementation's notes): an integer above 2^53 hashed differently in JavaScript, a duplicate key is a
   signature-confusion risk, and a lone surrogate crashed one runner. JCS assumes I-JSON anyway.
5. **Extra entry keys** are refused (`log-malformed`). The method lists the five entry properties without saying
   "only". See spec-gap 102 for why accepting them is unsafe in practice.
6. **DID syntax:** ASCII LDH domain labels (an IDN in its `xn--` form), the port separator `%3A` in upper case only,
   percent-decoded path bytes valid UTF-8, and Unicode White_Space at either edge of a segment refused.
7. **A deactivated DID** returns no document and has no keys (the method's MUST, which its implementations diverge on).
8. **The check order and reason tokens** are the suite's contract (`impl/vectors/README.md`, kind `did-webvh`).
9. **Boundary with CLAUDE.md rule 3:** JCS is used inside the method's own hashes and proofs. No DSIP envelope is
   ever canonicalized.

**Evidence.**
- The Python reference resolves all 76 positive logs of the DIF conformance suite
  (`didwebvh-test-suite` @ `703f97f`) and rejects all its log-level negatives.
- The vector logs were also run through `didwebvh-rs` 0.8.0 (41 of 43 applicable agree) and `didwebvh-ts` 2.8.0 (37
  of 43). Every disagreement is a case where the library is laxer than the spec text (spec-gap 102).

## 102. did:webvh v1.0 (upstream) — findings to report to the DIF working group

**Status: draft, for the user to send upstream.** The texts are in `impl/docs/upstream-reports.md`, rechecked on
2026-10-05: reports 1–6. Item 2's spec half is fixed upstream (the spec now rejects unknown `method` values with its
own negative example); the library half remains. Found while implementing spec-gap 101. These are not DSIP spec
issues; DSIP's resolution is pinned either way.

1. **Unknown entry properties are dropped before hashing by both reference libraries.** An entry with an extra key
   added *after* it was hashed and signed resolves as VALID in `didwebvh-rs` 0.8.0 and `didwebvh-ts` 2.8.0, so the
   extra content is covered by no signature. The spec lists the five entry properties but never says "only these".
   Suggest: "a log entry MUST NOT contain other properties; a resolver MUST reject one that does".
2. **`didwebvh-rs` 0.8.0 accepts `method: "did:webvh:9.9"`,** contrary to §Parameters ("MUST reject any `method`
   value that is not exactly one of the acceptable values") and to the spec's own negative example `did:webvh:99.0`.
3. **`didwebvh-ts` 2.8.0 (latest on npm) predates the 2026-06-06 hardening.** It accepts:
   - an entry after deactivation;
   - a portable move without `alsoKnownAs`;
   - an empty `proof` array;
   - an omitted `nextKeyHashes` under pre-rotation;
   - unknown parameters;
   - extra entry keys.

   The repository is at 3.0.0, unpublished.
4. **I-JSON is not stated.** JCS (RFC 8785) assumes I-JSON, but the method never requires it. Large integers,
   duplicate names and lone surrogates make implementations disagree (spec-gap 101 item 4).
5. **Schema versus prose** (`schemas/v1.0/log_entry.json`):
   - `minItems: 1` on `updateKeys`, `nextKeyHashes` and `watchers`, while the prose uses `[]` to deactivate and to
     end pre-rotation;
   - `proof` may be a single object;
   - `"type": "date-time"` is not valid JSON Schema.
6. **Smaller points:**
   - "one second" monotonicity in the security section versus "strictly greater" in the normative text;
   - a legacy base32 `nextKeyHashes` example;
   - metadata `ttl` and `witness.threshold` specified as strings while implementations emit integers;
   - `portable: false` together with a move in the same entry;
   - leading zeros in the `versionId` number;
   - fractional seconds in `versionTime`.

## 103. E§3–E§6 — Device Events Profile: re-raise, the syslog table, who escalates, SNMPv3 and syslog inputs

**Status: decided 2026-10-04 (user: "yes to all 4"; "reopen the same alarm"; "default table, configurable"; "an
escalation agent member") — written into `v0.9/dsip-device-events-profile-v0.9-draft.md`; pinned by
`impl/vectors/device-events/`.**

**Gap.** The new profile had three choices with no standard to defer to:

1. When a cleared alarm is raised again:
   - **reopen** the same alarm (RFC 8632: one alarm per key, with history);
   - **or open a new incident** (PagerDuty; an OpenNMS option).
2. How syslog severities map to alarm severities. RFC 5424 has eight levels and RFC 8632 five, and no standard
   bridges them.
3. Who runs the escalation timer: the NOC's mailbox/hub, or a member.

**Choices made.**
1. **Reopen**, with `reopened: true`. The operator state returns to `none`, so the alarm gets attention again, and the
   alarm can escalate again (once per raise). A flapping link is one alarm with a count.
2. **A default table, overridable per rule:** 0–2 `critical`, 3 `major`, 4 `warning`, 5–7 no alarm. It is a
   convention, so it is an `Impl` note.
3. **A member, the escalation agent.** Mailboxes and hubs stay storage and ordering services (M§4). The trigger is
   normative; the rota and timers are local policy.

**Also fixed while implementing.** Probing the three implementations on the second implementation's notes pinned:
- strict v1 fields (generic 0–6);
- a decimal-string sysUpTime;
- varbinds carried as exactly `{oid, type, value}`;
- a missing severity or `by` as null;
- gateway-silence processing in gateway-id order, not first-heartbeat order. impl-ts had read it the other way.

**Done (2026-10-05).**
- `device-event` and `alarm-ack` are registered content kinds (M§8.2; 4 vectors).
  - The kind check tests that the body fields are present.
  - Their contents are the alarm list's to judge (E§5).
- A reference gateway: `dsip-trapd` (BER decoding of SNMPv1/v2c traps, E§3 translation, E§4 rules, heartbeats)
  feeding the gateway's `dsip-msg`.
- `dsip-msg` keeps each group's alarm list and acknowledges with `alarm-ack`. As an escalation agent
  (`--escalate-min`, `--escalate-after`, `--escalate-cmd`) it runs the escalation command.
- `demos/device-events-demo.sh`, in CI. Real traps become signed events in an MLS alarm group, and:
  - every member keeps the same alarm list;
  - a repeat pages nobody;
  - an acknowledged alarm does not escalate;
  - an unacknowledged critical alarm rings the on-call phone through `dsip call`;
  - a silent gateway raises its alarm;
  - the community never leaves the gateway.

**Informs (2026-10-05).**
- The trap receiver moved into the gateway's `dsip-msg` (`--snmp-listen`, `--snmp-rules`, `--heartbeat`), which
  sees the hub's verdict. `dsip-trapd` is retired.
- An inform is answered (RFC 3416 §4.2.7 Response-PDU, echoing request-id and varbinds) only once its event is
  `accepted`, including when the outbox delivers it after a hub outage.
- An inform tracker gives one event per inform. Pinned by `device-events/inform-*` (9 traces), with the key order
  pinned numerically after a question from the second implementation.
- The demo kills the hub mid-inform: the device's 3 retransmissions go unanswered and deposit nothing more, and the
  next one after recovery is answered. There is exactly one event.

**SNMPv3 and syslog (2026-10-05).** E§2 gains the claims an authenticated basis adds: `usm: {engine_id, user}`
and `certificate_sha256`. E§3 gains USM processing and the syslog fields; E§4 gains syslog rules. The vectors README
pins the USM pipeline (10 reason tokens, in RFC 3414 §3.2 order), BER, the RFC 5424 / RFC 3164 grammar and the
syslog mapping. That adds 86 vectors (1309 total), with three-way parity and two new fuzz targets (`syslog`,
`snmpv3`).

Choices made (Impl):
- **Refused:** `noAuthNoPriv` (it proves nothing v2c does not), DES (RFC 3414 §8), and security models other than
  USM.
- **Wildcard users:** a password user may omit its engine ID and is then localized per message.
- **Trap time cache:** a trap engine's cache entry is seeded by its first authenticated message. RFC 3414 creates it
  by discovery, which a trap receiver never does.
- **Reports:** only `unknown-engine-id` (discovery) and `not-in-time-window` (time sync) are answered; every other
  failure is silent.
- **RFC 3164** is accepted. Its tag heuristic reads Cisco's sequence number as `app_name`, and a vector pins that.
- **Unmatched syslog:** an unmatched message that the table maps to a severity raises `(source, syslog, app_name)`.

Questions the second implementation raised, now pinned by README text and vectors:
- `<00>` is malformed.
- `resource_sd` searches only the first element with its `id` (E§4's wording was aligned).
- A userName that is not UTF-8 matches no user.
- An empty OID is malformed.
- NULL must have empty content (X.690 §8.8.2).
- Integer32 is bounded to ±2^31, and Counter32, Gauge32 and TimeTicks to 2^32−1 (RFC 2578).
- A PDU's constructed bit is not checked.
- Every SEQUENCE holds exactly its listed elements.
- Encodings need not be minimal (BER, not DER).

Outside oracles:
- RFC 3414 A.3's MD5 and SHA-1 localized keys.
- pysnmp 7.1.30's RFC 7860 SHA-2 keys.
- Three traps captured from pysnmp (SHA+AES, SHA-256, MD5+AES), kept verbatim as vectors.

The gateway (`dsip-msg`):
- New flags: `--snmp-users`, `--snmp-engine-id` (a persistent ID, with boots incremented at each start),
  `--syslog-listen`, `--syslog-tls-listen` (client certificates required, RFC 5425 octet-counted frames) and
  `--syslog-table`.
- Members render the basis with its verified identity.

`demos/device-events-v3-syslog-demo.sh` (in CI) uses real senders:
- **pysnmp:**
  - an authPriv trap arrives with its engine and user;
  - a wrong password is refused with `wrong-digest`;
  - after a reboot (boots + 1), a byte-for-byte replay of the pre-reboot trap is refused with `not-in-time-window`;
  - a v3 inform runs discovery against the gateway (a Report), is answered only once stored, and is deposited once.
- **logger:** RFC 5424 matched by a rule, and RFC 3164 through the table.
- **TLS:** a client with a device certificate gets `syslog-tls` and its fingerprint; one without is refused.
- No USM password leaves the gateway.

**v0.10, decided with the user 2026-10-06 ("Delay clears").**
- **Hold-down (E§4):** optional; the gateway delays clears by `H` s (0 = off). A raise of the same alarm while its
  clear is held cancels the clear, so members count a repeat, and a fast flap stays one alarm. A second clear keeps
  the first one's time. Events, and anything from an inform (answered only once stored, E§3), pass at once. Members'
  rules are unchanged.
- **Vectors:** `device-events/holddown-*` (8 traces), three-way. The second implementation's readings pinned key
  order (code points) and that other report fields pass through (`holddown-same-due-key-order`).
- **Certificate names (E§2):** an optional `source.name`, the gateway's configured name for the verified identity.
  It is a claim, and members render it only beside that identity.
- **Gateway:** `dsip-msg --hold-down`, `--syslog-tls-names`. In `demos/device-events-v3-syslog-demo.sh`, port 7 flaps
  (down, up, down, up) and Ann sees one raise and one clear; sw1 is shown as `name="sw1-core"` beside its
  fingerprint.

**SNMPv3 over TLS (v0.10, E§3; RFC 6353 TLSTM + RFC 5591 TSM).**
- **Basis and claim:** basis `snmpv3-tls`; the claim carries `certificate_sha256` and `tsm.security_name`.
- **Transport:** TLS over TCP only (DTLS left open), with a client certificate required.
- **The name table is pinned where RFC 6353 is loose:**
  - rows are tried in ascending `id`, matching the leaf or a CA in the verified path;
  - six maps, with only the first SAN of the type tried;
  - a name of 1–32 UTF-8 bytes, otherwise the next row;
  - no name closes the connection.
- **Framing:** BER self-delimited messages of at most 65,536 bytes; an unframeable stream is closed.
- **Per message:** `malformed`, `unsupported-security-model` (USM over TLS is refused), then `not-a-notification`. Any
  `msgFlags` level is accepted.
- **RFC 5343 discovery is required:** net-snmp's `snmpinform` probes `snmpEngineID.0` in context `8000000006` and
  gives up without an answer. The answer echoes that context (RFC 3412); only the varbind carries the engine ID. The
  first draft of E§3 put the engine ID in the context, and net-snmp discarded the Response. The real client caught
  it, and a unit test now pins it.
- **Vectors:** `tsm-*`, `tls-frames-*` and `tsm-name-*` (71), three-way. Of the second implementation's fifteen
  readings, three are now pinned in the README with vectors: first SAN only, IP hex in either case, and a single
  byte waits. Three new fuzz targets (`tsm`, `tls-frames`, `tsm-name`) ran 9,000 probes with no divergence.
- **Gateway:** `dsip-msg --snmp-tls-listen/-cert/-key/-ca/-map`. The certificate's fields come from x509-parser; the
  verified path's CA is matched by issuer against the configured CAs (an `Impl:` note). Informs are remembered by
  security name.
- **Demo:** `demos/device-events-snmp-tls-demo.sh` (in CI) uses net-snmp 5.9.5.2. 5.9.4, as shipped by Debian trixie
  and Ubuntu 24.04, caps its TLS client at TLS 1.0 and cannot connect; upstream report 11 asks for the backport.

**Signed syslog (v0.10, E§3; RFC 5848). Decided with the user 2026-10-06: "Hold, then deposit once".**
- **Basis and holding:** basis `syslog-signed`, with claim `signed` {hostname, app_name, procid, rsid, sg, spri,
  message_number, key_sha256}. A configured signer's messages are held up to `H` s (default 10); unsigned in time,
  they are deposited with their transport's basis.
- **What is pinned where RFC 5848 is loose or contradicts itself:**
  - **Keys:** configured per HOSTNAME (types C and K; §5.2.2 b end-entity matching), so every block, including each
    fragment, is authenticated on arrival.
  - **Versions:** `0111` and `0121` with OpenPGP DSA; the MPI bit count is only a length.
  - **The block** is the message's only SD element, which locates the signed bytes.
  - **FRAG** is the payload text (the example, against the table).
  - **Replays:** `old-session` per (HOSTNAME, APP-NAME).
  - **RSID 0:** a different payload resets the session.
- **Vectors:** `syslog-sign-*` (51), three-way, including RFC 5848's two examples verbatim, which verify. Python
  (OpenSSL) and Rust (RustCrypto `dsa`) agreed at first run. The second implementation verifies DSA with its own
  BigInt FIPS 186 code.
- **The new `syslog-sign` fuzz target found two real divergences:**
  - an unescaped `]` inside a quoted value: Python and Rust took the first `]` as the element's end;
  - waiting hashes when a session ends: the second implementation kept them.

  Both are fixed and pinned with vectors, along with five of its other readings. Afterwards 3,000 random probes showed
  no divergence.
- **Gateway:** `dsip-msg --syslog-signers`, `--syslog-sign-hold`; the transport of a held message is remembered for
  its unsigned deposit.
- **Demo:** `demos/device-events-syslog-sign-demo.sh` (in CI). No packaged signer exists (NetBSD's syslogd is the
  one implementation), so the demo's signer is `demos/syslog_sign_send.py`.
- **Upstream reports 12 and 13** draft RFC 5848 errata: FRAG's encoding, and the example's MPI bit count.

**Gap detection from signed syslog (v0.11, E§3).**
- **Opt-in** per signer (`gaps: true`), because RFC 5848 §4.2.3 expects gaps when a signer splits its messages
  across collectors.
- **Two gap kinds, per Signature Group:**
  - numbers no verified block covered: a block's FMN past the group's `covered`;
  - numbers signed but never arrived: a waiting hash expires.
- **Reporting:** each gap is a gateway event (`syslog_gap`, E§5) raising `(<signer>, dsip-syslog-gap,
  "<app>/<sg>/<spri>")`, warning. Later gaps re-raise it, so it is one counted alarm. A session's end drops its
  `covered`, waiting hashes and numbers.
- **Vectors:** `syslog-sign-gap-*` (11), three-way. The second implementation's two open readings were pinned: a
  run's identity comes from its lowest number's block, and `covered` resets with the session. The second of these was
  a real divergence, since Python and Rust kept `covered`.
- **Fuzzing:** the `syslog-sign` target now randomizes `gaps`; 4,000 probes found no divergence.
- **Demo:** `device-events-syslog-sign-demo.sh` shows both kinds raising one alarm.

**Open.**
- DTLS for SNMP (RFC 6353 over UDP).
- Key blob types N, P and U for signed syslog.

## 104. T§2–T§5 / core §8.1–§8.2 — alias transparency: what DSIP adopts of KEYTRANS, and when

**Status: decided 2026-10-04 (user: "KEYTRANS-shaped, blinded"; "stage it") — written into
`v0.9/dsip-alias-transparency-profile-v0.9-draft.md`; stage 1 pinned by `impl/vectors/alias-transparency/`.**

**Gap.** §8.2 aliases (`alice@example.com → DID`) are the one place a provider can silently substitute someone's
identity. IETF KEYTRANS solves this, but it is a working-group draft whose lookup-proof format is changing:
- the editors' copy is not wire-compatible with -05;
- open issue #51 records an interoperability failure over `PrefixProof` contents.

**Choices made.**
1. **Shape:** KEYTRANS-shaped, with VRF-blinded labels, as a DSIP profile that tracks the draft. Rejected:
   - CT-style public log: it enumerates a provider's users;
   - adopting KEYTRANS verbatim: the draft is still moving.
2. **Staged.** Stage 1 is now: the profile choices and the building blocks, which are stable. Stage 2 follows -06:
   - lookup verification;
   - owner monitoring;
   - fork detection via `DistinguishedHead` in DSIP signalling;
   - credentials, in introductions.
3. **One suite, one mode:** `KT_128_SHA256_Ed25519` only, and `contactMonitoring` only.
4. **`validate_key = TRUE`.** KEYTRANS states no choice, and RFC 9381 §5.3 requires one.
5. **Canonical point decoding** (RFC 8032 §5.1.3) everywhere, and a one-byte encode-to-curve counter. Found by the
   second implementation's notes.
6. **Alias normalization (T§3)**, which §8.1 never defined:
   - split at the last `@`;
   - a printable-ASCII local part, case kept;
   - LDH domain labels, lowercased;
   - at most 255 bytes.

   Internationalized local parts are deferred, because Unicode normalization tables differ across implementations.
7. **Discovery:** a `DSIPAliasLog` service in the provider's `did:web` document, holding the TLS-encoded
   Configuration.
   - The Configuration's signing key must be one of that DID's verification methods.
   - The Configuration is pinned on first use; a change is a log migration.
8. **KT bytes are carried raw**, never re-wrapped in DSIP envelopes, so any KEYTRANS implementation can verify them.
9. **Configuration integers above 2^53−1 are refused**, so they survive JSON in every language.

**Evidence.**
- RFC 9381 Appendix B.3 Examples 16–18 are vectors.
- katie's commitment test vector is reproduced.
- The draft's own search-tree and ladder examples are vectors.
- Every computed hash and signature was confirmed with **katie**, the KEYTRANS editor's Go implementation (commit
  `e1640671`): indexes, commitments, prefix and log roots, the Configuration and tree heads.

**Findings for the KEYTRANS working group** (the user to send). The texts are in `impl/docs/upstream-reports.md`,
rechecked on 2026-10-05 against the editors' copy at `a214b15`:
- **Fixed upstream since:** items 1 (`leaf_public_key`), 2 (vector lengths) and 7's stray `UpdateRequest`.
- **Partly settled:** item 3 (the `nonInclusionParent` depth is now defined), sent as a question on #51.
- **Still open, sent as reports 7–9:** items 4 (empty root), 5 (`Kc`) and 6 (the VRF).

The original list:
1. **Mode-1 Configuration.** -05 §11.2 gives contactMonitoring a `leaf_public_key`. The editors' copy removed it
   (commit `b97f81d`, 2026-07-28), and katie follows the editors. Implementations of -05 and of the editors' copy
   compute different `TreeHeadTBS` bytes, so their signatures don't verify across them. DSIP follows the editors'
   copy.
2. **The -05 → editors' copy change to vector-length semantics** (element counts).
3. **`PrefixProof.elements` for `nonInclusionParent`** (#51), and the change to its depth.
4. **The empty prefix-tree root** is unspecified.
5. **`Kc`** is called a "hex-encoded string" but is used as raw bytes (katie agrees with raw bytes).
6. **The VRF `validate_key` choice** is unstated, as are canonical point decoding and the counter bound.
7. **Editorial:**
   - a stray `UpdateRequest request;` in -05 §15.1;
   - [KTA] -09 §7 cites the RMW as "[PROTO] §7.1"; in -05 it is §6.1.

**Open (stage 2).**
- Lookups, monitoring and fork detection.
- Anti-enumeration at the query endpoint: identical answers for "no such alias" and "not permitted", plus rate
  limits.
- Credentials in introductions.

## 105. §8.5 / DHT Hints Profile §9 — reachability hints on Pkarr (the Mainline DHT)

**Status: decided 2026-10-04 (user: "yes to all 4"; "compact root-signed record") — written into the DHT Hints Profile
§9 and core §8.5; pinned by `impl/vectors/pkarr/` (40 vectors).**

**Gap.** v0.9 adds Pkarr as a second carrier for hints, putting them on a DHT far larger than DSIP's own overlay.
Pkarr does not fit DSIP hints directly:
- a BEP 44 item can be signed only by the key it is stored under, so a device cannot publish;
- values are capped at 1000 bytes, and a DSIP-JOSE hint with delegations does not fit;
- Pkarr has no signed expiry.

**Choices considered.**
- **(a) Compact `_dsip` TXT records signed by the identity key.** Chosen.
- **(b) A pointer to device-signed hints.** Deferred: it needs a new delegation conveyance (§7.4) and a freshness
  rule, because a withholding node can keep serving a pointer that still lists a revoked device.
- **(c) The whole JOSE hint in TXT.** Rejected: only an identity-signed, single-endpoint hint fits.

**What DSIP adds over Pkarr.** The pkarr crate accepts all of the following, which DSIP refuses or rejects:
- a timestamp in the future (DSIP allows at most 300 s ahead);
- a record outside the key's zone (DSIP ignores it);
- non-canonical z-base-32 (Pkarr accepts 16 encodings per key; DSIP requires the canonical one);
- any TXT content (DSIP requires exactly one `wss://` `uri=` and at least one `b=`).

DSIP also adds:
- a signed expiry of the timestamp plus the smallest TTL, each TTL at most 3600 s;
- §8.3 conflicts in place of "larger packet wins";
- owner names compared label by label without case (the crate's lookup is case-sensitive);
- `seq` at most 2^53−1, so it is exact as a JSON number.

**Evidence.**
- BEP 44's published test vectors are vectors.
- An independent Python codec produces packets byte-identical to the pkarr crate's.
- Every vector's payload was run through the crate (`SignedPacket::from_relay_payload`, v8.1.0). It agrees on every
  value and must-agree case, and every difference is one of DSIP's additions listed above.
- Probing the second implementation's notes pinned: label-by-label name matching, framing checked before content,
  the 2^53 bound, and non-hex payloads as `malformed`.

**Network (2026-10-05).**
- `dsip answer --publish-pkarr --pkarr-relay <url>` builds and signs the `_dsip` packet
  (`dsip_core::pkarr::build_payload`, with a round-trip unit test through the reader) and re-signs at 2/3 of the
  TTL. `dsip call --pkarr-relay <url>` asks every relay, reads each answer offline and takes the highest seq (§8.3).
- Relays only (Pkarr's HTTP `PUT/GET /<z32>`), since a relay writes to the Mainline DHT itself. Direct DHT access
  (the mainline crate) is not done.
- **Interoperability:** the real `pkarr-relay` (v8.1.0 source, `--testnet`: a 10-node Mainline DHT on localhost,
  nothing public) accepted 4 successive publishes, with its own signature and packet parsing. It served them back,
  the Python reader accepted the bytes, and a call was completed through it.
- **Demo** (`demos/pkarr-demo.sh`, in CI, against local stand-ins of the HTTP API): a hostile relay's forged newer
  packet is rejected (`signature`), the call reaches the real relay, the seq rises across re-publishes, and another
  application's record in the zone survives.
- **Decided (with the user, 2026-10-05): re-encode, never drop.** The publisher used to keep only TXT, A and AAAA.
  Now every IN record outside `_dsip` is carried:
  - names inside the rdata of the RFC 1035 types that RFC 3597 §4 lets compress are expanded;
  - every other type is copied as is, since RFC 3597 forbids compression in it, so SVCB and SRV are verbatim.

  It still ignores a previous packet that does not verify under its own key, so a hostile relay cannot push its
  seq. Pinned by `pkarr/carry-*` (12 vectors).
- **Decided (with the user, 2026-10-05): previous + 1, stated.** The timestamp is max(clock, previous + 1), and the
  profile names a clock stepped back as the one case signed ahead of the clock. A result above 2^53−1 (which readers
  reject) is not signed. Pinned by `pkarr/next-ts-*` (5 vectors).
- **The second implementation's questions,** settled in the README:
  - an excluded record's rdata is not examined;
  - which bytes of a name in rdata count as "in place";
  - the pointer rule inside rdata;
  - names keep their case;
  - the `_dsip` exclusion covers any type and exactly two labels, with class exactly IN;
  - only answer records are carried;
  - `dns` that is not hex is `malformed` (a vector), and the exhaustion case above.

**Mainline directly (2026-10-05).**
- `--mainline [--mainline-bootstrap host:port,…]` on `dsip answer`, `dsip call` and `dsip resolve` runs a Mainline
  node (the mainline crate, v8.0.1). It puts the same signed bytes as a BEP 44 mutable item (`seq` = ts, `v` = the
  DNS message, no salt), and gets every item a lookup returns.
- Relays and the DHT are sources of one candidate set. Every candidate is read offline by the DSIP reader, and the
  highest valid seq wins; the crate's own checks and "most recent" choice are not relied on. The put carries no
  CAS, since the seq order settles concurrent publishers.
- **Interoperability:** Pkarr's own client (v8.1.0 source, DHT only, `ResolvePolicy::NetworkOnly`) resolved the item
  DSIP put on a local testnet and parsed the `_dsip` TXT record intact.
- **Demo** (`demos/pkarr-mainline-demo.sh`, in CI): `dsip mainline-testnet` runs 10 nodes on 127.0.0.1. Bob puts to
  the DHT with no relay in his path, and Alice gets it from the DHT while a hostile relay's forgery is rejected. The
  seq rises over 3 puts, and a fresh node finds the newest packet after Bob left.

**Option (b), multi-device identities (v0.10, decided with the user 2026-10-06).**
- **Pointer:** the identity key signs `_dsip-devices` records (`dev=<did:key>`, TTL up to 604,800 s).
- **Device zone:** each device signs its own zone: the `_dsip` endpoint records (3,600 s cap) and one
  `_dsip-delegation` record holding the compact delegation. Readers resolve pointer → devices, in order, and verify
  each delegation as §7.4 does (§9.1).
- **Revocation is bounded, not immediate,** and the profile says so: by the delegation's expiry, the hourly hint, or
  the pointer's re-signing (7 days at most).
- **Vectors:** `pkarr/devices-*` (20) and `pkarr/carry-dsip-devices-and-delegation-replaced`, three-way.
- **The second implementation's twelve readings** were checked against Python and Rust. Ten matched and are now
  pinned in the README. Two were real divergences: a `null` payload (Rust) and an unsplittable delegation record
  (Python), now fixed and vectored.
- **Code:** `dsip_core::pkarr::{build_pointer_payload, build_device_payload, read_pointer, read_device}`; `dsip
  pkarr-pointer`; `dsip answer --publish-pkarr --pkarr-device`. Discovery falls back to the pointer when the identity
  zone has no `_dsip` hint.
- **Demo:** `demos/pkarr-multidevice-demo.sh` (in CI): one identity-signed pointer; the phone reached on R1; then, with
  the phone gone, the laptop on R2. Devices publish with their own keys only.

**HTTP access (v0.11, DHT Hints Profile §10; `dsip-node` stage 1, decided with the user 2026-10-06).**
- **Browsers** still join no DHT, but any `dsip-node` now serves them hints over HTTP, which they verify offline.
- **The routes:**
  - Pkarr's relay interface (`GET`/`PUT /<z32>`);
  - the overlay's `GET /dsip/v1/hints/<did>` and `POST /dsip/v1/hints`;
  - CORS on every answer.
- **A node serves every application's packets,** so a `PUT` passes only what every Pkarr packet must pass, then
  §8.3's `ts` rule (`check: "store"`, 16 vectors, three-way). `_dsip` content is judged by readers.
- **The second implementation's three open readings were pinned:**
  - a held packet is not re-verified;
  - "the same bytes" compares decoded bytes;
  - the path key is case-sensitive.
- **Demo:** `demos/dsip-node-demo.sh` (in CI). DSIP's unchanged clients publish through node A, and a call resolves
  through node C via the Mainline DHT. A browser (curl) reads the overlay hint from C, and forged and older packets
  are refused.

**Open.** None. Browsers stay off the DHT by design; HTTP access is their path.

## 106. M§8.4 "Fetching" — a device whose blob fetch finds nothing

**Status: fixed 2026-10-05 — M§8.4 text; vectors `messaging/blob-fetch-*` (7).** Found when #82 changed the
blob-replication demo.

**Gap.** M§8.4 says how a device orders a content's blob sources and verifies what it gets (rule 7). It says nothing
about a device for which **no** source served the blob, for example when the item arrives before its own mailbox has
replicated the blob and the origin is down. The reference device sent its "delivered" receipt, printed an error and
never fetched again, so a voice message could stay unplayable for good. That is the device-side twin of spec-gap 67.

**Choices considered.**
- **(a)** Retry like a mailbox's replication: only when some source had nothing to serve, with the same backoff and
  bound, across restarts; never when every source served other bytes.
- **(b)** Retry until success: a hostile or broken origin is refetched forever.
- **(c)** Hold back the "delivered" receipt until the media plays. That conflates delivery of the message with
  downloading its attachment, which M§10.2 does not do.

**Choice made.** (a). The receipt is unchanged: the message was delivered, and its media is fetched separately.

**PoC.**
- `dsip-msg` records each source's result, decides with `client::blob_fetch`, and keeps pending fetches persisted.
- It retries them from its ticker: 4 s, doubling, at most 60 s, for 5 attempts.
- It prints `AUDIO-PENDING`, then `RECV-AUDIO` on success.
- `demos/blob-replication-demo.sh` gains a stage where the device's only source has nothing to serve, then does.

## Already-flagged (schema README / plan §11)

- §15.3 codec example uses bare strings; §16.2 defines objects (schemas follow §16.2).
- `$id` base `https://dsip.org/schema/1.0/` is a placeholder pending §24.
- Prose ids like `01HZINVITEABC` are not valid ULIDs.
- §12.7 rule 6 reject preference order lists four tokens; the relay needs a rule
  for other tokens (PoC: first-seen).
- §26 step 8 says ICE candidates ride in `update` envelopes; §12.12/§16.3 say `info`.

## 107. §16.4 / Recording Profile C§1–C§7 (draft) — compliance recording under end-to-end encryption

**Gap.** §16.4's `policy.recording` says what a party accepts, but nothing says that a party **is** recording, who
records, or what a counterparty's client must do. Under end-to-end encryption, compliance recording can only happen
at an endpoint the organisation controls (research track C). Without a disclosure, it happens unannounced.

**Prior art (2026-10-05).**
- **SIPREC** (RFC 7866, RFC 7865): the recording client declares `a=record:on|off|paused`. A participant states
  `a=recordpref`, which the recorder may ignore, and refusing means leaving. The recorder is not a participant: the
  client forks media to it, at least as secure as the recorded session.
- **Wire legal hold** (MLS): a disclosed device on the subject's account, with an indicator in every conversation.
  Users who have not consented are kept out of conversations a legal-hold device is in (per team).

**Decided (with the user, 2026-10-05).**
- **Scope:** all three — disclosure, a recorder role, and a recorder leg for calls.
- **Consent:** render plus local acceptance. A callee does not answer, and a caller holds its media, until the user
  or a standing policy accepts. Declining is `reject` or `bye` with the new reason `policy.recording-declined`.
- **Recorder devices are receive-only:** members do not render their content.

**Choices made (Impl).**
- **The declaration** is a top-level `recording` member on `invite`, `answer` and `update`, signed with the
  envelope: `{state, recorder, purpose?}`. A mid-call change is an `update`, as SIPREC uses a re-INVITE or UPDATE.
- **Acceptance** is per session and per recorder. A resume with the same recorder needs none; a new recorder needs
  it again. A `paused` declaration holds nothing.
- **An unregistered state** reads as `on`, the safe reading.
- **The messaging recorder** is a device of the recorded identity carrying `dsip.record` (the Wire model), visible
  through its leaf's delegation (M§6.2). Acceptance is per conversation and per set of recorder devices.
- **The recorder leg** is an ordinary DSIP session to the declared recorder, carrying RFC 7865-shaped
  `recording_session` metadata and `sendonly` streams. The recording party checks the recorder's identity and
  capability first.

**Spec.**
- `v0.9/dsip-recording-profile-v0.9-draft.md`.
- Core: §15.4 adds `policy.recording-declined`; §16.4 separates the preference from the declaration; §24.2 adds
  `dsip.record` and the recording registries.
- Schemas: `recording` on invite/answer/update, and `recording_session` on invite, with samples.

**Vectors.**
- `recording/` (39): consent traces, recorded conversations, recorder-leg checks.
- `semantic/` (4): the reason token, and declarations with and without a recorder.

**The second implementation's questions, decided and pinned.**
- **Returning to an accepted recorder** while a new one is pending releases the hold. C§4's intent; the README had
  said "nothing more". Vector: return-to-accepted-recorder-releases-hold.
- **A caller's local `answer`** does nothing.
- **Any message type is processed for either role.**
- **The disclosure** holds only `state`, `recorder` and `purpose`.
- **Conversation acceptance** covers every recorder present: a new one asks again, one that leaves asks nothing.
  C§5's "set of recorder devices" wording was aligned with the README's subset test.
- **The recording-session check:**
  - at least one stream, each with an integer `media`;
  - a missing `direction` is not `sendonly`;
  - an unregistered state counts as declared;
  - the six refusal tokens are local results, and the leg is ended with `bye` and `policy.blocked`.

**On the wire (2026-10-05).**
- **New flags:** `dsip call/answer --recorded-by <recorder> [--record-purpose] [--record-later]`, and
  `--recording-accept ask|always|never`.
- **New commands:** `accept-recording`, `decline-recording`, `record on|pause|off`.
- The endpoint signs the declaration into every invite, answer and update.
- The console runs `dsip_recording::Consent`. It never auto-answers before acceptance, and holds the media leg
  (`hold_sending`) while acceptance is pending.
- A local decline may now carry a reason: `state/responder-declines-with-reason` (all three implementations).
- `demos/recording-consent-demo.sh` (in CI) runs four calls:
  - a caller holds all audio (0 frames) until acceptance;
  - a callee will not answer before acceptance, and its decline is `reject policy.recording-declined`;
  - a standing `never` policy declines at once;
  - recording begun mid-call by `update` and declined ends with `bye policy.recording-declined`.

**The recorder leg (2026-10-05).**
- `dsip recorder` is a recorder service. It answers only invites carrying `recording_session` (otherwise `reject
  policy.blocked`), records each stream to Ogg/Opus, and keeps the metadata.
- The recording party's console, with `--record-device <second device>`, forks the call from that device once media
  flows:
  - one `sendonly` recording session per voice;
  - the Opus is forwarded unchanged through taps on the call leg and a `Feed` source;
  - before any media, it runs `dsip_recording::recording_session` with the recorder's verified delegation
    (`peer_has_capability`).
- Supporting changes:
  - `identity init --capability` for extra delegated capabilities;
  - an invite patch for direction and metadata;
  - the answer selection maps an offered `sendonly` to `recvonly` and vice versa (§14.2 subset rule; it used to copy
    the direction).
- **Choices made (Impl), now in C§6:**
  - one recording session per stream (C§6 now says "one or more");
  - `paused` holds the legs' media rather than renegotiating them to `inactive` (C§6 now allows either).
- `demos/recorder-leg-demo.sh` (in CI; forge and webrtc-rs both pass):
  - a call yields two files, one per voice, plus metadata;
  - a counterparty who never accepted contributes 0 frames;
  - a "recorder" without `dsip.record` is refused before any media (`bye policy.blocked`).

**Recorder devices in messaging (2026-10-05).**
- A leaf's delegated capabilities are now part of `LeafIdentity` (`is_recorder`).
- `dsip-msg --recorder` delegates `dsip.record`. It sends no content or receipts, discloses nothing, and archives
  what it receives to `recorder-archive.jsonl`.
- Members run `dsip_recording::conversation` over the authenticated leaves:
  - they render a conversation becoming recorded, or no longer recorded;
  - they refuse to send content or receipts before `accept-recording` (`decline-recording` leaves);
  - they drop anything a recorder leaf sends.
- **Choice made (Impl, now in C§5):** a recorder of a member's own identity needs no acceptance from that member.
- **Choice made (Impl, now in C§5):** a recorder device joins conversations, never its identity's personal group.
  So it gets no archive key and records only what was sent while it was disclosed. Without this, the multi-device
  path would have handed it the whole history, including messages sent before anyone was told.
- `demos/recorder-device-demo.sh` (in CI) covers all of this, including a misbehaving recorder whose message both
  members drop.

**Acceptance across devices (v0.10, 2026-10-06).**
- Acceptance is now the person's, not one device's. The device on which the user accepts sends a
  `recording-acceptance` object (`{conversation, recorders, accepted_at}`) to the identity's personal group. Every
  device of the identity applies the union with its own acceptances (C§5, M§8.1 table).
- Vectors: `messaging/recording-acceptance-*` (3), three-way.
- **The second implementation's agent found a text contradiction.** M§10.5 called the private read watermark "the
  one object exempt" from M§8.1's `conversation` rule, yet the new object names the recorded conversation too. M§10.5
  now names both, and the vectors README states that `sender-mismatch` and `conversation-mismatch` apply to `content`,
  `receipt` and `activity` only, as all three implementations already did.
- `dsip-msg`: `accept-recording` shares the acceptance, and a sibling's acceptance is applied on receipt.
- The recorder-device demo now adds a laptop for Alice. Told of the recording, the laptop can't send until Alice
  accepts on her phone; the acceptance then reaches the laptop through her personal group, and it sends.
- Whether a party's `policy.recording: forbidden` should also be enforced by its relay. It is not: a relay never
  sees media and cannot know.

## 108. M§7.2 / Recording Profile C§5 — every device of an identity in a new conversation; a recorder never stands in

**Found (2026-10-05)** by testing whether conversations created after a recorder device exists pick it up. Neither
direction did:
- **Alice creates a conversation with Bob.** Bob's mailbox happened to hand out his **recorder's** KeyPackage. The
  conversation was Alice plus Bob's recorder; Bob's phone never joined.
- **Bob creates one.** Only his phone and Alice joined, so the conversation was not recorded at all.

**Cause: an implementation bug, not the spec.** M§5.5 has a fetch return one KeyPackage per device, and M§7.2 has the
creator add "its own other devices and the peer's devices in one commit". `dsip-msg` added only the first KeyPackage
it was given, and never its own other devices. A second ordinary device, such as a laptop, missed new conversations
the same way.

**Spec gap (recording-specific).** With every device added, a recorder joins every new conversation of its identity,
as it should. But if only the recorder had KeyPackages left, a conversation could hold the person's recorder without
the person.

**Decided (with the user).** C§5 now says:
- an adder adds a recorder device only together with at least one other device of that identity, unless that
  identity is the adder's own (the person is then present through the adding device);
- otherwise the identity is not added (`recorder-only`);
- the personal group never takes a recorder.

The rule is pinned by `recording/add-devices-*` (9 vectors, three-way parity). The second implementation's agent
found an ambiguity in the first wording (the adder's own identity), and the `self_identity` input settled it.

**Implemented.**
- `CommitOp::Add` carries every selected KeyPackage in one commit.
- `create` adds the peer's devices and the creator's own other devices.
- `add` and the successor re-add take every device of the peer.
- All of these go through `dsip_recording::add_devices`.

**Demo.** `demos/recorder-device-demo.sh` now creates a conversation from each side after the recorder exists:
- both include the recorder, and Alice is told each is recorded;
- 19 messaging demos pass with every-device adds.


## 109. DHT Hints Profile §10 — when a node holding a Pkarr packet looks for a newer one

**Found (2026-10-08, `dsip-node` stage 5, on the WAN).** §10 says a node serves "the Pkarr relay payload" for
`GET /<z32>`, and that serving an older packet is its only power. It does not say when a node holding a packet
should look on Mainline again. `dsip-node` never did. After Bob re-signed, Milan and Tokyo kept serving his first
packet, and once it expired Alice's call through Milan failed with `rejected (expired)`, while Mainline held the new
one. This was conformant, and useless.

**Choices considered.**
1. Leave it to implementations. The cost is honest nodes that look like withholding ones.
2. Re-read Mainline on every `GET`. Always current, but every lookup pays a DHT query: 2.8–3.3 s on the WAN, against
   0.25 s from what is held.
3. Serve a fresh held packet at once and re-read in the background, rate-limited; re-read before serving a packet
   past its TTL (its `ts` plus its shortest record TTL — a node can compute that for any application's packet).

**Implemented: 3** (`Impl:` on `pkarr_get`, `crates/dsip-node/src/lib.rs`). The background re-read runs at most once
a minute per key. Measured (`dht-findings.md`, "dsip-node on the WAN", finding 2): with a 120 s TTL, nodes followed
each re-sign 20–60 s behind and never served an expired packet.

**Proposed text (§10, under `/<z32>`), as first drafted:** "A node holding a packet SHOULD look for a newer one on Mainline before
serving it after its TTL has passed (its `ts` plus its shortest record TTL), and MAY look again while it is fresh. A
held packet is a cache, not a store of record." No vector change: freshness is node behaviour, outside `check:
"store"`.

**Decided (with the user, 2026-10-08): adopted in v0.11.** DHT Hints Profile §10 now says, under `/<z32>`, that a
held packet is a cache: a node SHOULD look for a newer packet on Mainline before serving one past its freshness
(`ts` plus its shortest record TTL), and MAY look while it is fresh without delaying the answer. Core A.8 notes it.
`dsip-node` already does both.

## 110. N§1–N§7 (draft) / G§11 / §19.1 — number-to-DID attestation

**Found (2026-10-08).** G4 recommendation 3 (`gateway-stir-findings.md` §5) and G§11 path (c) need a way for a DSIP
identity to be entitled to a phone number. The design study `impl/docs/number-attestation-design.md` proposed a
STIR-signed binding. It is now the draft Number Attestation Profile (`N§n`), and stage 1 (N§3, the binding and its
checks) is pinned by `impl/vectors/tn-binding/`. The design left five choices open. The user decided on 2026-10-08
to adopt it and start stage 1, with E.164 numbers only. Items B–E take the design's proposals; A and D still need a
decision outside the PoC.

**A. G§11 / SHAKEN: may a gateway attest `A` on a carrier's binding?**
- Choices:
  - (a) yes, with the binding standing in for the subscriber relationship;
  - (b) `B`;
  - (c) only under an RFC 9060 delegate certificate for the number.
- Draft text (N§4): (c) is normative, and (a) is a question for SHAKEN governance, not for DSIP.
- Not vectored. It lands with stage 4, the gateway.

**B. N§3 / N§7: lifetime, certificate time, conflicts.**
- **Lifetime.** Choices: a 24 h, 7 d or 30 d cap. **Chosen: 7 d**, as `exp − iat` ≤ 604800, giving
  `lifetime-too-long`.
- **Clock skew.** `iat` may be up to 300 s ahead (the §12.9 tolerance), giving `not-yet-valid`. The design had no
  future rule.
- **Certificate time.** The design said "the certificate valid at `iat`". **Changed:** every certificate on the path
  is checked at the verification time, which is RFC 5280's practice. `iat` is the signer's own claim, so checking
  the certificate at `iat` proves nothing a signer could not choose.
- **Two verified bindings for one number.** The two-way rule decides first. When both DIDs claim the number, the
  newer `iat` wins, with the N§5 warning. Not vectored yet; it lands with stage 2.
- **Vectors:**
  - `tn-binding/lifetime-*`, `verified-lifetime-exactly-7-days`;
  - `not-yet-valid`, `verified-iat-at-tolerance`;
  - `cert-leaf-expired`, `cert-anchor-expired`.

**C. N§6: whether a number is discoverable by default.**
- Choices: opt-in, opt-out, or never published keyed by the number.
- **Chosen: opt-in.** Enumeration is a stated limitation, instrumented and not solved, like Sybil resistance
  (§3.2).
- Not vectored. It lands with stage 3, discovery.

**D. §19.1: the trust tier of a verified number.**
- Choices: Tier 1, Tier 3, or deployment policy.
- Draft text: **deployment policy**, with Tier 3 given as an example for business use. Needs a decision when §19.1
  next changes.

**E. N§1: short codes and toll-free numbers.**
- **Decided by the user: E.164 only for now.** `tn` matches `^\+[1-9][0-9]{1,14}$`.
- Short codes are not E.164 and are out of scope.
- Toll-free numbers written in E.164 pass the syntax checks. Their issuers (RespOrgs) and their STIR treatment
  are open.

**Decisions the vectors pin that the design did not discuss** (`Impl:` in `crates/dsip-number`):
- **Every TNAuthList on the path must cover the number,** not only the leaf's. A delegate certificate (RFC 9060)
  therefore cannot exceed its issuer's scope. Vectors: `delegate-beyond-issuer-range`,
  `tn-intermediate-list-does-not-cover`.
- **Recognized critical extensions.** Only basicConstraints, keyUsage and TNAuthList; any other critical extension
  is `untrusted-certificate`. SHAKEN's JWTClaimConstraints (RFC 8226 §8) is therefore refused when it is critical,
  until a later stage implements it.
- **An SPC entry covers a number** only through the relying party's SPC lookup (`spc_numbers`): the number
  portability data in SHAKEN.
- **Step 8 status** is a policy switch. `status-unavailable` covers both a missing URL and no answer; that token is
  new against the design.

**F. N§3.2 / README step 2: certificate parsing.** The impl-ts implementation, written from the text alone, probed
it with 41 temporary vectors and found 16 places where the three implementations disagreed. Each was decided and is
pinned with a hand-authored vector.
- **PEM.** Marker lines are whole lines, and lines end in LF or CRLF. A block left open fails the text. Only SP, HT,
  CR and LF are removed from a body. Non-zero unused bits are accepted. Vectors: `cert-pem-*`.
- **Every block parses, even after an anchor.** That means:
  - the tbs `signature` field equals `signatureAlgorithm` (RFC 5280 §4.1.1.2);
  - no extension appears twice (§4.2);
  - there is no pathLen without cA (§4.2.1.9);
  - basicConstraints and keyUsage decode, and any TNAuthList is well-formed.

  Vectors: `cert-duplicate-*`, `cert-pathlen-without-ca`, `cert-tbs-algorithm-differs`,
  `cert-unparseable-after-anchor`.
- **Trust anchors.** An entry that is not padded base64 of a certificate is ignored. Every qualifying issuing
  anchor is tried, in list order. Vectors: `anchor-*`.
- **Status.** A required check fails closed on an answer that is neither `good` nor `revoked` (`status-unknown-answer`).
- **`attested_by`.** A value whose bytes are not UTF-8 is passed over, never shown lossily
  (`attested-by-invalid-utf8-passed-over`).
- **Left unpinned, stated in the README.** Other DER and RFC 5280 encoding faults inside a CA-signed certificate:
  - a BOOLEAN `01`;
  - an encoded DEFAULT;
  - a non-minimal BIT STRING;
  - an empty `extensions` SEQUENCE;
  - GeneralizedTime before 2050;
  - an odd serial number;
  - a PrintableString outside its character set.

  The implementations differ here: `cryptography` and impl-ts are strict, and `x509-parser` is lenient. A CA signed
  those bytes, so leniency never admits an unsigned claim. Pinning them would mean writing a full strict-DER
  validator into every implementation. Vectors and fuzz avoid them. **Proposed text (N§3.2):** "Certificates are DER
  as RFC 5280 requires; a verifier SHOULD refuse one that is not."

**G. Stage 2 (N§4, N§5): the claim and the identity-change warning.** Pinned by `tn-binding/claim-*`,
`tn-binding/contact-*` and `trust/basis-tel-binding-*`. Exact rendered lines are the suite's.
- **A latent `trust` divergence, found and fixed.** Two `tel` claims, the first with no `verifier` (a binding claim)
  and the second a gateway's, were rendered differently:
  - Rust took the first `tel` claim and fell back to the identity's own basis;
  - Python took the first claim with a `verifier`;
  - impl-ts would have printed "undefined".

  **Decided:** the basis comes from the first `tel` claim whose `verifier` is a string, and `tel-caller` needs one
  too.
- **A claim with both a string `verifier` and a `binding`** is a gateway claim. The `claim` check ignores it.
- **A failed binding claim** is shown as `<number> (unverified)` (§18.2), and only when `number` is E.164.
- **The N§5 warning** is said only when no stored contact listing the number has the attested DID. It names the first
  contact that lists it, and dates the binding by its `iat` (UTC).
- **Left open** (client-local data; impl-ts's choices stand, no parity exposure on well-formed input):
  - dates outside the years 0000–9999;
  - malformed address-book entries;
  - an `attested_by` that is neither a string nor `null`.
