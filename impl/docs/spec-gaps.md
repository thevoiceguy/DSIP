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

## Already-flagged (schema README / plan §11)

- §15.3 codec example uses bare strings; §16.2 defines objects (schemas follow §16.2).
- `$id` base `https://dsip.org/schema/1.0/` is a placeholder pending §24.
- Prose ids like `01HZINVITEABC` are not valid ULIDs.
- §12.7 rule 6 reject preference order lists four tokens; the relay needs a rule
  for other tokens (PoC: first-seen).
- §26 step 8 says ICE candidates ride in `update` envelopes; §12.12/§16.3 say `info`.
