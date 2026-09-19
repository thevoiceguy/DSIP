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

A re-send into the successor can itself fail. The items have left the dead group's outbox by then, so the reference
device must not lose them: an item whose deposit failed after it was encrypted for the successor is treated as a
deposit with no answer (it stays pending in the successor's outbox and is retried with the backoff, the later items
queueing behind it — `RESEND-PENDING`), and the successor's hub being unreachable too is the same state reached
through the ordinary answer. This is host behaviour built from the pinned `no_answer` event, not a new machine rule.
Still open: a failure to create the successor at all (no group to keep the items pending in) loses them.

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

## 79. G§4.2 — Q.850 causes the table does not give

**Gap.** G§4.2 maps an unregistered token "by its §15.1 category (`user`→603, `endpoint`→480, …)" — statuses only — yet
G§3 requires every crossing to carry a `Q.850;cause` where one applies, and the vectors pin one
(`outbound-unknown-token-category-fallback`: 603 **with cause 21**). Likewise an ACTIVE teardown is "BYE with the
cause", but the BYE rows name only `user.hangup`/`session.*` (16) and `media.failed` (47); `outbound-bye-policy-terminated`
pins 31, taken from the token's pre-answer row.

**Choices considered.** (a) A category fallback takes the cause of the category's representative row (`user` 21,
`endpoint` 18, `identity` 1, `session` 41, `media` 65, `policy` 21, `transport` 41, `gateway` 38); a BYE takes the
token's table cause when the BYE rows do not name it, else 16. (Settled by fuzz.py, 2026-09-18: "`session.*` → 16" in the
BYE rows means the `session.*` tokens that are *valid on* `bye` — `session.already-answered`, `session.cancelled`. Any
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

## Already-flagged (schema README / plan §11)

- §15.3 codec example uses bare strings; §16.2 defines objects (schemas follow §16.2).
- `$id` base `https://dsip.org/schema/1.0/` is a placeholder pending §24.
- Prose ids like `01HZINVITEABC` are not valid ULIDs.
- §12.7 rule 6 reject preference order lists four tokens; the relay needs a rule
  for other tokens (PoC: first-seen).
- §26 step 8 says ICE candidates ride in `update` envelopes; §12.12/§16.3 say `info`.
