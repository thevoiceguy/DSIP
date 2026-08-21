# Spec-gap issue drafts (v0.6 → v0.7 worklist)

Each entry is the text of a `spec-gap` issue, per plan §11 and the CLAUDE.md
documentation standard. Numbers match the `Impl (spec-gap N)` comments in
`impl/tools/dsipvec/` and the Rust crates, and the list in
`impl/vectors/README.md`. Vectors named here pin the PoC's choice; if the spec
resolves differently, the vector changes first, then the code.

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

## 15. §19.4 — grant matching, scope, and contact-token semantics

**Gaps.** (a) Whether the optional `grant` field in an invite is required for a relay/endpoint to
honor a grant, or whether holding a grant for the inviting identity suffices. (b) Whether a grant
whose `scope` lacks `dsip.invite` admits invites. (c) Whether a contact token is single-use.

**PoC choice.** A live grant admits an invite when matched by `grant` id **or** by grantee
identity; `scope` MUST contain `dsip.invite`; a token auto-grants once and is then consumed.
Vectors: `state/first-contact-responder-grant`, `state/first-contact-grant-scope`,
`state/first-contact-contact-token`.

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

## 18. §22.1 — who may publish a stream, and stream_id ownership

**Gap.** The record carries `from` and `publisher`; nothing says they must agree with the
signature, nor who may update or withdraw a stream, nor how `stream_id` relates to the publisher.

**PoC choice.** `publisher` MUST equal the verified identity (signer or its delegator); `stream_id`
MUST be the publisher DID or a colon-suffixed extension of it; a record with a lower ULID than the
held one is stale; `unpublish` MUST be signed by the same identity and name the held
`publication`. Vectors: `broadcast/publication-publisher-mismatch`,
`broadcast/publication-stream-outside-namespace`, `state/broadcast-authority-publisher-binding`.

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

## 20. §22.2 — where the integrity mode is stated

**Gap.** §22.2 defines `metadata-only` / `derivative-bound` but the `publish` schema is closed and
has no field for it. **PoC choice.** Variants carry `integrity` (variants allow extra
properties); a verified transcode statement makes the receiver display `derivative-bound`.

## 21. §22.3 — how provenance statements reach receivers

**Gap.** §22.3 shows the statement but not its carriage. **PoC choice.** Processors send the
statement (type `broadcast.provenance`, extension `broadcast-provenance/1.0`, impl-local schema)
to the publisher's authority, which attaches processors to the record and lists them in
`notify.body.provenance`; the CLI receiver fetches statements alongside the record. Vectors:
`broadcast/provenance-*`, `state/broadcast-authority-provenance`.

---

## Already-flagged (schema README / plan §11)

- §15.3 codec example uses bare strings; §16.2 defines objects (schemas follow §16.2).
- `$id` base `https://dsip.org/schema/1.0/` is a placeholder pending §24.
- Prose ids like `01HZINVITEABC` are not valid ULIDs.
- §12.7 rule 6 reject preference order lists four tokens; the relay needs a rule
  for other tokens (PoC: first-seen).
- §26 step 8 says ICE candidates ride in `update` envelopes; §12.12/§16.3 say `info`.
