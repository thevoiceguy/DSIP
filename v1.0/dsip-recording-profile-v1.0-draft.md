# Draft: DSIP Recording Profile (`recording/0.1`)

**Status:** DRAFT, companion profile to DSIP 1.0. Cite as `C§n`. Decided 2026-10-05 from `impl/docs/v0.9-research.md`
track C (spec-gaps 107, 108).

Compliance recording under end-to-end encryption happens **at endpoints the organisation controls, and it is
disclosed**. It never happens by decrypting at relays, by key escrow, or through a lawful-intercept interface (§3).
This profile defines five things:

- a signed **recording declaration** for calls (C§3), shaped like SIPREC's `a=record` (RFC 7866 §7.1.2);
- what a **counterparty's client** must do about it: render it, and act only after acceptance (C§4);
- a **recorder device** role for messaging, which is disclosed and receive-only (C§5);
- a **recorder leg** for calls: a DSIP session from the recording party to its recorder, carrying the media and
  RFC 7865-shaped metadata (C§6);
- a **call record** each device sends its organisation's record-keeper after every call, carrying metadata only
  (C§9, v0.13).

**What disclosure can and cannot do.** A declaration binds the party that makes it. Nothing stops a participant from
recording their own screen or speaker in secret, and no protocol can. The profile gives honest recorders a way to
be honest, gives counterparties a signed statement to rely on and refuse, and makes a recorder that the organisation
runs visible and revocable. It does not make secret recording impossible (§4: DSIP does not solve social or
regulatory problems through message formats).

## C§1 Roles

- **Recording party.** A participant whose side of a session or conversation is recorded, usually because its
  organisation requires it. For calls it is SIPREC's Session Recording Client (SRC).
- **Recorder.** A DSIP device whose delegation (§7.4) carries the capability `dsip.record`. It is SIPREC's Session
  Recording Server (SRS). It may be a device of the recording party's own identity (messaging, C§5) or of a separate
  service identity run by the organisation (calls, C§6).
- **Counterparty.** Any other participant. Its client renders the disclosure and asks for acceptance (C§4).

A delegation carrying `dsip.record` grants nothing else on its own. A recorder that signs calls also carries
`dsip.signaling` and `dsip.media.interactive`, and one in conversations carries `dsip.messaging`.

## C§2 Policy: what a party will accept

A party's existing `policy.recording` (§16.4) states what it accepts **from the other side**, as SIPREC's
`a=recordpref` does. The values are registered:

| value | meaning |
|---|---|
| `allowed` | the other side may record, after the usual acceptance (C§4) |
| `consent-required` | the default: the other side may record only after this party's acceptance (C§4) |
| `forbidden` | this party declines any recording; its client declines automatically (C§4) |

As §16.4 says, a policy is a declaration, not enforcement. A recording party that sees `forbidden` MUST NOT record
that party. It either declares `off` or ends the session with `policy.recording-declined`.

## C§3 The recording declaration (calls)

An `invite`, `answer` or `update` MAY carry a top-level `recording` member, signed with the envelope, stating the
**sender's** side:

```json
"recording": {"state": "on", "recorder": "did:web:rec.acme.example", "purpose": "compliance"}
```

- `state` is `on`, `paused` or `off`. An absent member means `off`.
- `recorder` is the recorder's identity (C§6), a claim rendered with the disclosure. It is required when `state` is
  not `off`.
- `purpose` is a registry-governed token (`compliance`, `quality`, `personal`), rendered with the disclosure. An
  unknown token renders as given.
- A party's declaration persists until its next `update` or `answer` carries another. A change mid-call is an
  `update` (§12.8), so that the counterparty sees it in order with renegotiation, as SIPREC requires a re-INVITE or
  UPDATE (RFC 7866 §7.1.2).
- The declaration covers **all** of the sender's recording of the session: by its own client, by its recorder leg,
  or by anything else it does on purpose.

## C§4 Consent at the counterparty

A counterparty's client MUST render a declaration that is not `off`: the recording party, the `recorder` and the
`purpose`, attributed as claims (§18.2). Its acceptance is a local decision: the user's, or a standing local policy
(`ask`, `always`, `never`), where `forbidden` (C§2) means `never`. The states and events are the `recording/`
traces in `impl/vectors/README.md`.

- **Inbound `invite` declaring recording.** The callee's client MUST NOT `answer` before acceptance. Declining is a
  `reject` with `policy.recording-declined`.
- **An `answer` declaring recording.** The caller's client MUST hold its outbound media (send none) until acceptance.
  Declining is a `bye` with `policy.recording-declined`.
- **An `update` turning recording on, or naming a different recorder.** The client answers the `update` as
  renegotiation requires, and MUST hold its outbound media until acceptance. Declining is a `bye` with
  `policy.recording-declined`.
- **`paused`** is rendered as paused, and holds nothing. A resume to `on` with the **same recorder** needs no new
  acceptance; a different recorder does.
- **`off`** releases a hold, and the disclosure is rendered as ended.
- Acceptance is per session and per recorder. It is never inferred from silence, and it is not carried on the wire:
  only a decline is, as a reason.

## C§5 The recorder device (messaging)

A conversation is **recorded** while any member leaf's delegation (M§6.2) carries `dsip.record`. A member's client:

- MUST render the conversation as recorded, naming the identity whose device records (the delegation's `subject`)
  and the recorder device;
- MUST NOT send content or receipts into it until the user has accepted, for this conversation, every recorder
  device present. A new recorder asks again; one that leaves asks nothing. Declining is leaving the conversation
  (M§7). A recorder device of the member's **own** identity needs no acceptance from that member: it is that
  identity's own recording, which its owner already knows of;
- MUST treat **content** from a recorder leaf as it treats content from an unauthenticated leaf (M§6.2): not
  rendered, not archived. A recorder is receive-only, and can never speak for the person whose device it is. Its
  handshake messages (Update commits renewing its delegation, M§6.2) are processed as usual.

**Acceptance is the person's, not one device's (v0.10).** A device on which the user accepts tells the identity's
other devices. It sends a `recording-acceptance` object to the identity's personal group (M§8.1):

```json
{"object": "recording-acceptance", "conversation": "01J…", "recorders": ["did:key:…"], "accepted_at": 1790000000}
```

- `conversation` names the recorded conversation, and `recorders` lists the recorder devices accepted (at least one).
- The object travels only in the personal group, like `archive-key`: it would tell the conversation's other members
  nothing they may know.
- Each device of the identity accepts the union of its own acceptances and those in its personal group for that
  conversation.
- An acceptance is never withdrawn by this object; declining is still leaving the conversation (M§7).

**A recorder never stands in for the person.** When a device adds an identity to a conversation, it adds every device
that the identity's KeyPackage directory returns (M§5.5, M§7.2), recorder devices included. So a conversation created
after a recorder exists is recorded too, whichever side creates it. It adds a recorder device only together with at
least one of that identity's other devices, unless that identity is the adder's own (the person is then present
through the adding device). If only recorder devices are available, the identity is not added (`recorder-only`). Otherwise a conversation could hold the person's recorder without the person. The rule is pinned by
`check: "add-devices"` in `impl/vectors/README.md`.

A recorder device is added like any device (M§12.3), with one difference: it joins the identity's conversations,
**never its personal group**. It therefore receives no archive key (M§12.1) and records only what is sent while it is
a visible member, which is exactly what was disclosed. Earlier history stays out of its reach. It is removed or
revoked like any delegation (§7.4–§7.5). When it leaves, the conversation stops being recorded and the client renders
that.

## C§6 The recorder leg (calls)

The recording party records a call by opening one or more **recording sessions** to its recorder. Each is an ordinary
DSIP session (§12) whose `invite` carries `recording_session` metadata, shaped like RFC 7865's. A session may carry
every stream, or one each; the recorder correlates them by `of`, as a SIPREC recorder correlates recording sessions
of one communication session. It may open them from any of its devices.

```json
"recording_session": {
  "of": "01J…",
  "participants": [{"identity": "did:web:acme.example:bob", "role": "self"},
                   {"identity": "did:web:carol.example", "role": "peer"}],
  "streams": [{"media": 0, "participant": "did:web:acme.example:bob"},
              {"media": 1, "participant": "did:web:carol.example"}]
}
```

- `of` is the recorded session's id. `participants` and `streams` map each offered media section to whose voice it
  carries. The recording party offers every recorded stream `sendonly`, and the recorder answers `recvonly`.
- The recorder's delegation MUST carry `dsip.record`, and its identity MUST be the `recorder` the recording party
  declared in the recorded session (C§3). The recording party verifies both before sending media. If either check,
  or the metadata, fails, it sends nothing and ends the recording session with `bye` and `policy.blocked`. At least one
  stream is required.
- The recording party sends a counterparty's media to the recorder only after that counterparty's acceptance is
  evident: the callee answered an `invite` that declared recording, or the caller did not end the session on seeing
  the declaration (C§4). It sends its own media from the moment it declares `on`.
- During `paused` the recording party sends no media on the recording sessions. It MAY also renegotiate them to
  `inactive` through `update`. `off`, or the recorded session's end, ends them with `bye` (`user.hangup`).
- The recording leg is end-to-end between the recording party and the recorder (DTLS-SRTP, B§). It is at least as
  strong as the recorded session, as RFC 7866 §12 requires. No relay and no third party sees media.

## C§7 Registries

- `dsip-delegation-capability`: `dsip.record`.
- `dsip-reason`: `policy.recording-declined`, "a party declined to be recorded", valid on `reject` and `bye`.
- `dsip-policy-value` for the key `recording`: `allowed`, `consent-required`, `forbidden`.
- `dsip-recording-state`: `on`, `paused`, `off`.
- `dsip-recording-purpose`: `compliance`, `quality`, `personal`. Open, with shape `[a-z][a-z0-9-]*`.
- `dsip-call-record-outcome` (C§9, v0.13): `answered`, `answered-elsewhere`, `failed`, `declined`, `missed`,
  `cancelled`, `rejected`. Open, with shape `[a-z][a-z0-9-]*`; a record-keeper keeps an unknown outcome as given.

## C§8 Prior art

- **SIPREC** (RFC 7866, RFC 7865): "active recording", where every participant is notified (`a=record`),
  participants may state a preference (`a=recordpref`) that the recorder may ignore, and refusing means leaving. The
  recorder is not a participant: the SRC forks media to it. This profile keeps the shape, and makes acceptance a
  MUST at the counterparty's client.
- **Wire legal hold** (MLS): a disclosed recording device on the subject's account, with an indicator in every
  conversation and next to the user. Non-consenting users are kept out of conversations a legal-hold device is in.
  This profile keeps the disclosed device and makes consent per user and per conversation, not per team.

## C§9 Call records (v0.13, spec-gap 121)

An organisation that must keep a record of its people's calls (who, when, for how long, how each ended) gets one
from the infrastructure it runs: its relay, its gateway, its mailboxes (core Appendix D). A device can also bind to
relays the organisation does not run (§13.2), so the infrastructure records can miss calls. This section adds an
endpoint-side record that covers every call, on any relay. It carries metadata, never media or content.

- **The recorder.** The organisation names a **record-keeper** for a recording party: a service identity whose
  devices carry `dsip.record` (C§1). The party's devices keep a direct conversation with it (M§7.2). Like every
  recorder, the record-keeper is a member the party's own client shows (C§5), and its devices never speak in the
  conversation; a party's records are the only thing sent there.
- **Who opens the conversation (v0.13, spec-gap 123).** The record-keeper does. A party cannot: every device of the
  record-keeper is a recorder, and a recorder is never added without one of its identity's other devices
  (`recorder-only`, C§5). The record-keeper's device creates the direct conversation at its own mailbox, adding every
  device of the party (M§7.2), and asks for the party's grant (M§14.2) like any first contact. A party's client sends
  records only to the conversation with the record-keeper its organisation names, and holds them until that
  conversation exists. A `call-record` is not content: a party sends it without the acceptance C§5 asks before
  content, and sends no content there unless the user accepts the recorder.
- **One record per leg.** After every session leg a device took part in, it sends a `call-record` object to that
  conversation. Every call is covered, whether recorded or not, and whatever relay carried it. A forked call
  (§12.7) yields one record per leg of the party's own devices; the record-keeper correlates them by `session`.
  Records travel through the mailboxes (M§9), so a record-keeper that is offline loses nothing.
- **Disclosure.** A record holds what the party's own relay already sees of the call (§20.7). It needs no per-call
  declaration (C§3), as an operator's records of calls it routes do not; the organisation discloses the practice as
  a standing policy. Recording content still needs the declaration and acceptance of C§3–C§6.
- **Trust.** Like all endpoint-side recording, a record is as complete as the client that sends it: a modified
  client can omit one. The infrastructure's records (Appendix D) are the cross-check, and `evidence` lets each
  record be matched against the signed messages they kept.

```json
{"object": "call-record", "session": "01J…", "device": "did:key:z6Mk…", "direction": "outbound",
 "peer": "did:web:carol.example", "relay": "did:web:relay.acme.example",
 "invited_at": 1790000000, "answered_at": 1790000004, "ended_at": 1790000310,
 "outcome": "answered", "ended_by": "remote", "reason": "user.hangup", "media": ["audio"],
 "recording": {"state": "off"}, "evidence": ["<SHA-256 of each signed envelope, lowercase hex>"]}
```

- `session` is the session's id; `device` the sending device, which MUST be the MLS sender leaf's device (M§6.2);
  `direction` is `inbound` or `outbound`; `peer` the other party's identity; `relay` the relay the leg used, when
  known.
- `invited_at` is the invite's `issued_at`; `answered_at`, present exactly when `outcome` is `answered`, the
  applied answer's; `ended_at` when the leg ended. They never decrease in that order.
- `ended_by` is `local`, `remote`, or `transport` when the leg ended without a message (§13.2); `reason` is the
  token that ended it (§15), as received.
- `media` lists the media types of the applied answer; `recording` is the party's last declaration (C§3) in the
  session.
- `evidence` lists the SHA-256 of signed envelopes of the session, over the bytes of each text frame exactly as sent
  or received (§10.2: never re-serialised). A record-keeper matches a record against envelopes kept by a relay, a
  gateway or the peer: an entry matches an envelope whose bytes hash to it.

**Outcome.** A device derives its leg's `outcome`, in this order:

1. `answered`: the leg was answered (this device was in the session when it became active).
2. `answered-elsewhere`: the leg ended with `session.answered-elsewhere` (§12.7).
3. `failed`: `ended_by` is `transport`, or the reason's category is `transport`.
4. `declined`: the reason is `user.declined`, and the leg is inbound and ended locally (this device's user) or
   outbound and ended remotely (the callee's).
5. `missed`: any other inbound leg.
6. `cancelled`: an outbound leg ended locally.
7. `rejected`: any other outbound leg.

**At the record-keeper.** A `call-record` is accepted only in a direct conversation (`recorder-conversation-only`);
its `device` must be the sender leaf's (`sender-mismatch`) and its times must agree with the rules above
(`call-record-invalid`). It is never rendered as content. The checks and their order are `check: "object"`,
`check: "call-record-outcome"` and `check: "call-record-evidence"` in `impl/vectors/README.md`.
