# DSIP Conformance Test Vectors

**Tracks:** DSIP Draft v0.8 + JSON Schema set v0.8 (draft 2020-12); the Messaging Profile schema set for `messaging/`
**Format version:** 1

These vectors are the language-neutral conformance contract for DSIP Core v1.0.
They are *generated* by `impl/tools/generate_vectors.py` (deterministic keys,
deterministic ULIDs, byte-reproducible signatures) and *verified* independently
by the Python harness (`impl/tools/run_vectors.py`), the Rust runner
(`cargo run -p dsip-cli -- vectors run`), and a second implementation written from this
document and the spec alone (`impl-ts/`, TypeScript; `impl/tools/parity_ts.py`). A vector is
only trusted when the runners agree with its `expect` block.

Expected outcomes are authored by hand from the spec text in the generator
modules — they are never derived from either implementation's output.

## File layout

```
vectors/
  envelope/    Signature, header, kid→DID resolution, delegation, replay, ULID/issued_at
  media-binding/ WebRTC Media Binding 1.0 conformance (descriptor/SDP authority, roles, candidates, renegotiation, one answer)
  gateway/     SIP/PSTN gateway (Phase 4): §15.5 reason mapping both ways, SDP ⇄ descriptors, PSTN caller claims, downgrade rule, B2BUA controller traces
  messaging/   Messaging Profile 1.0 (M§n): profile messages, content objects, hub/mailbox/client/history traces, MLS layer, HPKE, blobs, first contact
  payload/     JSON Schema pass/fail per message type (shape only)
  semantic/    Stateless post-schema checks (schema README list of 11)
  state/       Scripted endpoint and relay state-machine traces (§12)
  transport/   ws/1.0 hello binding, anti-splicing, size cap (§13.2)
  dht/         Reachability hint records and §8.3 conflict rules
  broadcast/   Receiver-side verification of a publication record and its provenance (§22)
  trust/       The basis-of-verification lines a client shows (§18.1, §6.3) — exact text
```

One vector per file. The vector id is its path relative to `vectors/` without
the `.json` suffix (e.g. `envelope/valid-ed25519`).

## Common envelope

```json
{
  "vector": "envelope/valid-ed25519",
  "format": 1,
  "kind": "envelope",
  "description": "Human-readable statement of what is being tested",
  "spec_ref": ["§10.2"],
  "context": { ... kind-specific receiver context ... },
  "input":   { ... kind-specific input ... },
  "expect":  { ... kind-specific expectation ... }
}
```

`spec_ref` entries cite v0.8 section numbers (unchanged from v0.6 and v0.7 for every section the vectors cite); `B§n` cites a section of the WebRTC Media Binding 1.0 companion document. Every vector has at least one.

## Runner results

A runner compares what it computed (`actual`) with `expect` for **deep equality** — arrays in
order, objects member by member, nothing extra. A member absent from `expect` is therefore a claim:
no `warnings` means the implementation raised none, no `effective` means nothing registry-governed
was read, no `reason` means the spec assigns no token. Trace kinds compare each step's `emit`
exactly and, of the snapshot, the members (sessions, attempts, …) the step names.

With `--json FILE` a runner writes `{ "<vector id>": {"ok": bool, "actual": …} }` (`"steps": […]`
in place of `actual` for traces). Parity tools diff these files, so two implementations that both
satisfy `expect` but disagree on something it leaves unsaid are still caught. A runner that does
not implement a kind reports `{"ok": false, "skipped": true}`; a skipped vector never counts as agreeing.

## Beyond the vectors: differential fuzzing

A vector exercises one rule; implementations can pass every vector and still disagree when two rules meet.
`impl/tools/fuzz.py` generates random well-formed traces and table rows, runs them through all three runners
(`--dir`, `--json`) and compares actual with actual. CI runs it with a fixed seed; a weekly workflow uses a fresh one.
A disagreement never becomes a recorded expectation: it becomes a hand-authored vector here, or a spec-gap.

## Fixed fixtures

All vectors share the fixture set in `fixtures.json` (also generated):

- **Keys** are Ed25519, seeded with `sha256("dsip-vector:" + name)`; the
  vectors carry only public material. `did:key` identifiers are the multicodec
  `ed25519-pub` (0xed01) form, base58btc, `z6Mk…`.
- **Identities:** `alice` and `bob` are identity controllers with delegated
  devices `alice-phone`, `alice-laptop`, `bob-phone`, `bob-laptop`. `bob-next` is
  the key bob's `did:web` identity rotates to (§7.5 vectors). `relay` is
  a relay identity. `carol` is an unknown first-contact identity. `mallory`
  holds a key with no delegation from anyone.
- **`did:web` documents** for `did:web:example.com:users:bob` and
  `did:web:relay.example.com` are supplied under `context.did_documents`
  wherever a vector needs them; resolvers under test MUST consult that map
  instead of the network.
- **Delegations** (§7.4) are DSIP-JOSE envelopes whose payload is the
  `DeviceDelegation` object, signed by the subject identity's controller key.
  They are supplied under `context.delegations` (and MAY also appear in the
  protected header `delegations` array — see `Impl` note in the envelope
  pipeline below).
- **Revocations** (§7.4, v0.8) are `delegation-revocation` envelopes the receiver holds, under
  `context.revocations`; a `did:web` document may also publish them (`dsipDelegationRevocations`, compact form).
- **Clock:** `context.now` is the receiver's clock at receipt, integer seconds.

## Verdict codes

Rejections are classified by an implementation-neutral `code`. Where the spec
assigns a reason token to the condition, `reason` is also given and the
implementation under test MUST emit that token when it signals the failure.

| code | meaning | reason (when defined) |
|---|---|---|
| `frame-too-large` | text frame exceeds 65,536 bytes (§13.2) | `transport.envelope-too-large` |
| `envelope-shape` | not a JSON object with exactly `protected`,`payload`,`signature` base64url strings | |
| `header-invalid` | protected header not a JSON object, or missing `alg`/`kid` | |
| `alg-unsupported` | `alg` is not `EdDSA` (ES256 is MAY; this PoC rejects it) (§10.2) | |
| `kid-invalid` | `kid` is not a DID URL with a fragment (§10.2) | |
| `kid-unresolvable` | `kid` DID cannot be resolved, or fragment names no Ed25519 verification method (§8.1) | |
| `signature-invalid` | Ed25519 verification over `protected.payload` failed (§10.2) | |
| `payload-not-utf8` | decoded payload is not valid UTF-8 (§10.3) | |
| `payload-not-json` | payload is not a JSON object (§10.3) | |
| `payload-float` | any number in the payload is non-integer (§10.3) | |
| `payload-shape` | core fields (`dsip`,`type`,`id`,`from`,`issued_at`,`expires_at`) missing or wrong primitive type, or `id` not a ULID (§10.3; every later stage that reads the id depends on it) | |
| `signer-mismatch` | `kid` DID ≠ `from` DID and no delegation presented linking them (§7.4, check 3) | `transport.hello-rejected` on `hello` |
| `delegation-invalid` | presented delegation fails: bad signature, wrong subject/device, not signed by subject controller | `transport.hello-rejected` on `hello` |
| `delegation-expired` | delegation not valid at `now` (`issued_at ≤ now < expires_at` required) | `transport.hello-rejected` on `hello` |
| `delegation-capability` | delegation lacks `dsip.signaling` (every envelope binds under it; spec-gap 56) | `transport.hello-rejected` on `hello` |
| `delegation-revoked` | a `delegation-revocation` signed by the subject covers the delegation (held, or in the subject's document) (§7.4, v0.8) | `transport.hello-rejected` on `hello` |
| `expiry-order` | `expires_at ≤ issued_at` (check 1) | |
| `replay-window` | `issued_at` outside `[now − 300, now + 300]` (§12.9, check 1); for `introduction` only the future bound applies (§12.9, v0.8; spec-gap 31) | |
| `introduction-validity` | `introduction` with `expires_at − issued_at` > 604,800 s (§12.9, §19.4; spec-gap 31) | |
| `introduction-purpose-and-sealed` | an `introduction` carries both `purpose` and `sealed` (§19.4, v0.8) | |
| `revocation-subject-mismatch` / `revocation-signer-not-subject` | `delegation-revocation.from` ≠ `subject`; signed by a key other than the subject's (§7.4, v0.8; `context.signer_kid`) | |
| `lifetime-exceeded` / `deposit-class-unsupported` / `deposit-fields` / `object-too-large` / `mailbox-mode-unsupported` / `key-packages-empty` | Messaging Profile message rules (M§5; kind `messaging`) | `mailbox.unsupported-class` / — / — / `mailbox.object-too-large` / `mailbox.unsupported-mode` / — |
| `sender-mismatch` / `conversation-mismatch` / `ulid-sent-at-mismatch` / `personal-group-only` / `content-body` / `reaction-invalid` / `receipt-shape` | Messaging Profile content-object rules (M§8, M§10, M§12; kind `messaging`) | |
| `successor-invalid` | successor group not created by a predecessor member, or adding outsiders (M§7.5; kind `messaging`) | |
| `mls-truncated` / `mls-length-invalid` / `mls-length-non-minimal` / `mls-trailing-bytes` | MLS extension wire encoding (RFC 9420 §2.1.2; kind `messaging`) | |
| `credential-type` / `credential-identity` / `delegation-missing` / `credential-key-mismatch` | MLS leaf authentication (M§6.2; kind `messaging`; also uses `delegation-invalid`/`-capability`/`-expired`) | |
| `blob-size-mismatch` / `blob-hash-mismatch` / `sealed-too-short` / `aead-open-failed` | AES-GCM formats (M§8.4, M§11.1, M§12.2; kind `messaging`) | |
| `expired` | `expires_at < now` (§12.9) | `session.expired` on `invite` |
| `duplicate-id` | `id` already seen within the replay window (§12.9) | |
| `ulid-issued-at-mismatch` | ULID timestamp component differs from `issued_at` by more than 300 s (§20.6, check 2) | |
| `version-unsupported` | §11 negotiation failed | one of the `session.unsupported-*` tokens |
| `schema-invalid` | payload fails its JSON Schema | |
| `unknown-type` | `type` is not a known message type | |
| `selection-not-subset` | `answer`/`reject` selection not ⊆ referenced offer (check 9) | |
| `subscription-lifetime-exceeded` | `expires_in` above the per-event cap (presence 3,600) (§9.3) | `policy.subscription-lifetime` on `error` (v0.7) |
| `rotation-subject-mismatch` | `key-rotation.from` ≠ `subject` (§7.5) | |
| `rotation-next-same-as-previous` | `key-rotation.next` = `previous` (§7.5) | |
| `rotation-signer-not-previous` | `key-rotation` signed by a method other than `previous` without `recovery: true` (§7.5; `context.signer_kid`) | |
| `introduction-too-large` | encoded introduction envelope > 4,096 bytes (§19.4) | |
| `grant-unknown-introduction` | `grant.session` references no known introduction (§19.4) | |
| `hello-in-reply-to-mismatch` | relay `hello.in_reply_to` ≠ the client hello id actually sent (§13.2, §20.5) | |
| `hello-required` | session traffic before a verified `hello` (§13.2) | `transport.hello-required` |
| `hint-subject-mismatch` | DHT hint whose verified identity is not its `subject` (§8.3) | |
| `binding-ice-mode` | `transports[].ice` absent or not `trickle` (B§2) | `media.unsupported` |
| `binding-sdp-missing` | webrtc descriptor without `sdp` (B§2) | `media.offer-required` on offers, `media.failed` on answers |
| `binding-sdp-invalid` | `sdp` is not SDP (B§2) | `media.unsupported` / `media.failed` |
| `binding-section-count` | live `m=` sections ≠ media descriptors; answer section count ≠ offer's (B§2.1) | `media.unsupported` / `media.failed` |
| `binding-extra-section` | an `m=application` section (B§2.1) | `media.unsupported` |
| `binding-kind-mismatch` / `binding-direction-mismatch` / `binding-codec-missing` | descriptor i and `m=` section i disagree (B§2.1) | `media.unsupported` / `media.failed` |
| `binding-encryption` | plain RTP profile (B§7) | `media.encryption-required` |
| `binding-rtcp-mux-missing` / `binding-fingerprint-missing` / `binding-ice-credentials-missing` | SDP profile violations (B§2.2) | `media.unsupported` / `media.failed` |
| `binding-setup-invalid` | offer not `actpass`, or answer not `active`/`passive` (B§3.3) | `media.unsupported` / `media.failed` |
| `binding-ice-restart` | a local re-offer changed the ICE credentials (B§5.4); a remote one is `reject media.unsupported` | |

## Pipeline order (normative for parity)

When several conditions hold at once, the verdict is the **first** failing
stage below. Stages 1–11 are the envelope pipeline (`kind: envelope`,
`transport`, `dht`); stages 12–14 run on decoded payloads (`kind: payload`
runs 13 only; `kind: semantic` runs 12–14).

1. `frame-too-large` (only when `input.frame` is present)
2. `envelope-shape`
3. `header-invalid` → `alg-unsupported` → `kid-invalid`
4. `kid-unresolvable`
5. `signature-invalid` — computed over the exact ASCII bytes `protected + "." + payload`
6. `payload-not-utf8` → `payload-not-json` → `payload-float` → `payload-shape`
7. `signer-mismatch` / `delegation-*` (binding `kid` to `from`; on `hello` with `on_behalf_of`, additionally binding `from` to `on_behalf_of`)
8. `expiry-order`
9. `introduction-validity` (introductions only) → `replay-window` → `expired`
10. `duplicate-id`
11. `ulid-issued-at-mismatch`
11b. `hello-required` (transport binding state: `context.hello_verified` is `false` and the type is not `hello`)
12. `version-unsupported`
13. `unknown-type` → `schema-invalid`
14. Stateless semantic checks (`selection-not-subset`, `subscription-lifetime-exceeded`, `introduction-too-large`, `grant-unknown-introduction`, `hello-in-reply-to-mismatch`, `rotation-*`)

Stage 13 also validates `info.data` against the binding schema named by `about` when the
receiver implements that binding (`transport:webrtc` → `webrtc-info-data.schema.json`); an
unimplemented `about` leaves `data` unchecked (§12.12: ignored, never rejected).

Registry membership (check 5) never rejects a well-formed token. It yields an
*effective* interpretation, reported on accept:

```json
"expect": {
  "verdict": "accept",
  "effective": { "reason": "session.failed", "fallback": "unknown-category" }
}
```

`fallback` ∈ `none` (registered), `category` (unregistered condition in a
known category), `unknown-category` (→ `session.failed`). For `answered_by`,
`effective.answered_by` is `service` for unknown values; for `progress`,
`effective.status` is `trying` for unknown values. A registered token that the
registry does not list as valid on the carrying message type is accepted with
`warnings: ["reason-not-valid-on-type"]` (Impl decision; see spec-gap list). `effective.reason` is
reported for `reject`, `cancel`, `bye`, `error` and a `notify` that carries a `reason`; the "valid on"
column is not applied to `notify`, which §15.4 never lists (spec-gap 73).

## Kind: `envelope`

```json
"context": { "now": 1760000000, "did_documents": {}, "delegations": [], "seen_ids": [],
             "supported": {"core": "1.0", "profiles": ["interactive-media/1.0"], "extensions": []} },
"input":   { "envelope": {"protected": "...", "payload": "...", "signature": "..."} },
"expect":  { "verdict": "accept", "type": "invite", "signer": "did:key:z6Mk…", "identity": "did:key:z6Mk…" }
```

or `{"verdict": "reject", "code": "…", "reason": "…"}`. `signer` is the DID
of the `kid`; `identity` is the DID the signer acts for (`from`, or
`on_behalf_of` on `hello`).

## Kind: `payload`

```json
"input":  { "schema": "invite", "payload": { ... } },
"expect": { "verdict": "accept" } | { "verdict": "reject", "code": "schema-invalid" }
```

## Kind: `semantic`

Input is a decoded payload plus whatever receiver context the check needs:

```json
"context": { "now": …, "supported": {…}, "offer": {"media": [...], "transports": [...]},
             "known_introductions": [], "sent_hello_id": "…", "encoded_size": 4200, "signer_kid": "did:…#key-1" },
"input":   { "payload": { ... } },
"expect":  { "verdict": "accept", "effective": {...}, "warnings": [...] } | { "verdict": "reject", "code": "…", "reason": "…" }
```

Subset rule detail (check 9, Impl decision, spec-gap filed): each selected
media descriptor must match an offered descriptor on `type` (+ `purpose` when
present); every selected codec `id` must appear in that descriptor's offered
codecs; the selected direction must be an SDP-style answer to the offered
direction (`sendrecv`→any, `sendonly`→`recvonly|inactive`,
`recvonly`→`sendonly|inactive`, `inactive`→`inactive`); the single selected
transport `id` must be among the offered transports.

## Kind: `transport`

Same as `envelope`, with optional `input.frame` (the exact text frame, for the
size cap) and `context.sent_hello_id` / `context.hello_verified` for the
binding checks.

## Kind: `state`

A trace drives one **component** — an `endpoint` (holding any number of
sessions, each in initiator or responder role) or a forking `relay`
attempt — through a scripted event sequence with a mock clock.

```json
"context": {
  "component": "endpoint",
  "self": {"device": "did:key:…alice-phone", "identity": "did:key:…alice"},
  "identities": {"did:key:…bob-phone": "did:key:…bob", …},
  "start": 1760000000,
  "timers": {"t_establish": 15, "t_ring": 120, "t_ring_local": 120}
},
"input": { "steps": [ {"event": {...}, "expect": {...}}, … ] }
```

### Endpoint events

| event | meaning |
|---|---|
| `{"local":"place_call","session":ID,"to":DID}` | send `invite` (id = session), start T-Establish; when the endpoint holds a grant issued by `to`'s identity, the `send` carries `grant` (its id, §19.4) |
| `{"local":"cancel","session":ID}` | user abandons → `cancel user.cancelled` |
| `{"local":"hangup","session":ID,"reason":TOKEN?}` | `bye` with `reason` (default `user.hangup`; the media layer uses `media.failed`, B§8) |
| `{"local":"alert","session":ID,"ring_timeout":N?}` | policy admits invite → `progress ringing`, start T-Ring-Local |
| `{"local":"auto_reject","session":ID,"reason":TOKEN}` | policy rejects at OFFERED |
| `{"local":"accept","session":ID,"answered_by":V}` | user/service answers → `answer` |
| `{"local":"decline","session":ID}` | `reject user.declined` |
| `{"local":"update","session":ID,"id":ULID,"answered_by":V?}` | send `update` |
| `{"local":"answer_update","session":ID,"in_reply_to":ULID}` | answer the inbound outstanding update; the `send` carries `answered_by: "user"` (the schema requires it on every `answer`); with no matching inbound update → `refused no-pending-update` |
| `{"local":"reject_update","session":ID,"in_reply_to":ULID,"reason":TOKEN}` | reject it |
| `{"local":"info","session":ID}` | send `info` |
| `{"local":"introduce","id":ULID,"to":DID,"purpose":S,"contact_token":S?}` | send `introduction` (§19.4) |
| `{"local":"grant","introduction":ID,"id":ULID,"scope":[…],"valid_until":T}` | issue a contact grant for a pending request: `send grant {to: the introducing IDENTITY, session: introduction id, id, scope, valid_until}`; unknown request → `refused unknown-introduction` |
| `{"local":"reject_introduction","introduction":ID,"reason":TOKEN}` | decline a pending request (a policy choice): `send reject {to: the introducing IDENTITY, session, reason}` — the same addressee as a grant (§19.4, spec-gap 74) |
| `{"local":"revoke","grant":ID}` | revoke an issued grant (local policy); unknown grant → `refused unknown-grant` |
| `{"local":"issue_token","token":S,"grant_id":ULID}` | pre-authorize an out-of-band contact token: the first introduction carrying it surfaces `introduction_received {token: true}` and is auto-granted at once — id `grant_id`, scope `["dsip.invite"]`, `valid_until` = now + 31,536,000 (Impl) — and the token is consumed |

`context.policy` = `{"first_contact_required": bool, "allow": [identity DIDs]}` (default: off).
With the policy on, an invite from an identity holding no live `dsip.invite` grant (matched by
the invite's `grant` reference or by grantee) and not in `allow` is auto-rejected
`policy.first-contact-required` without alerting. Introductions never create a session.
| `{"recv": MSG}` | a **verified** message arrives (signature, replay, schema already passed) |
| `{"advance": SECONDS}` | advance the mock clock; expired timers fire in deadline order, ties by start order |

`MSG` is an abbreviated payload: `type`, `id`, `from`, `session` (except
`invite`, whose `id` is the session), and the type-specific fields the
transition depends on (`status`, `ring_timeout`, `queue_timeout`, `reason`,
`answered_by`, `in_reply_to`, `about`, `expires_at` on `invite`, `to`).

### Relay events

| event | meaning |
|---|---|
| `{"relay":"invite","session":ID,"from":DID,"to":IDENTITY,"legs":[DEVICE,…]}` | fork an invite to the listed legs |
| `{"recv": MSG}` | message from a leg (`progress`/`answer`/`reject`) or the initiator (`cancel`) |
| `{"relay":"leg_expired","session":ID,"leg":DEVICE}` | relay's own per-leg delivery expiry |
| `{"relay":"bind"|"unbind","device":DEVICE,"identity":IDENTITY}` | a device (un)binds via `hello` (§13.2); binding flushes queued introductions |
| `{"recv": introduction}` / `{"recv": invite}` (without `legs`) | routed by the relay's bindings; introductions to unknown/offline identities are queued with no error (§19.4 anti-enumeration) |
| `{"recv": any}` to a *known* but unbound identity/device | queued (§13.3 store-and-forward) until `min(expires_at, context.offline_retention_s)`; `advance` expires queues; `bind` flushes them in order, turning queued invites into tracked legs |
| `{"advance": SECONDS}` | clock |

### Expectation after each step

```json
"expect": {
  "emit": [ ...ordered emissions... ],
  "sessions": { ID: {"role":"initiator","state":"PROCEEDING","renegotiating":false,"outstanding_update":null} }
}
```

For the relay: `"attempts": { ID: {"legs": {DEVICE: "delivered|answered|rejected|expired|cancelled"}, "outcome": null|"answered"|"rejected"|"cancelled"|"no-response"} }`
(`cancelled`: the initiator withdrew and no leg is left outstanding; `no-response`: every leg expired and none rejected), optionally `"inbox": {RECIPIENT: count}` — every
envelope queued for an identity or device, of any type; recipients with nothing queued are absent.
When every leg ends without any leg having rejected there is nothing to forward: the relay speaks for itself,
`send error {to: the initiator, session, reason: transport.no-response, in_reply_to: the invite id}` (§12.7 rule 6, spec-gap 76).
An endpoint in INVITING or PROCEEDING that receives it ends the attempt (`timer stop` → `ui ended transport.no-response`,
no `cancel`); in any other state it is `ui error` like any other error. A forwarded `progress` carries its `status`. An `answer` is **never withheld**, whatever the leg's state: only the
initiator ends a leg that has answered (`bye session.already-answered` / `session.cancelled` / `session.failed`, below),
and the leg record moves only for a leg that was still outstanding — a cancelled, expired or rejected leg that answers stays
recorded as such, and the outcome is unchanged (spec-gap 86). A `progress` or `reject` from a leg that has already
terminated is `drop leg-terminated`: at an initiator that cannot see legs it would read as the attempt's own, and nobody
needs it.

The attempt record is used only for a leg's pre-answer traffic, a `cancel`, and the outcome. **Everything else is routed
by `to`** (§13.3, spec-gap 82) — post-answer traffic, traffic from a device that is not a leg, a `cancel` addressed to a
device that is not a leg, and any traffic for a session the relay holds no attempt for: `deliver` to the bound device
named, or to every device bound for the identity named, in device order; queued when the recipient is known and
offline; otherwise `send error transport.unknown-recipient` to the sender (`in_reply_to` the message's id). Nothing is
dropped for naming a session the relay does not know. A `cancel` whose `to` is one leg's device cancels that leg alone
(§12.11): the attempt goes on, and the identity's queued invite stays queued. A leg can be added while
`expires_at >= now`. Queued envelopes that expire in the same step are reported in recipient order. An invite to an identity that has never bound here is answered `send error transport.unknown-recipient`.
For an endpoint, optionally `"contacts": {"allow": […], "grants_issued": […], "grants_held": […], "requests": […], "pending_sent": […]}` (sorted ids).

Only the sessions / attempts named in `expect` are compared (`{}` names none); `contacts`, `inbox`,
`publications` and `subscriptions` are compared in full when present. `emit` is compared exactly, in order.

### Emission vocabulary

| emission | fields |
|---|---|
| `{"send": {...}}` | `type`, `to`, `session`; plus `reason` (cancel/reject/bye/error), `status` (progress), `answered_by` (answer/update when set), `in_reply_to` (answer/reject/error when set), `id` only when the event supplied it |
| `{"deliver": {"leg": DEVICE, "type": …, "reason": …, "id": …}}` | relay forwards to a specific leg (`id` present when delivering a queued envelope or a leg added mid-attempt) |
| `{"dequeue": {"to": …, "type": …, "why": "expired"\|"cancelled"}}` | relay dropped a queued envelope (§13.3 boundary; the initiator's timers are the backstop) |
| `{"forward": {"type": …, "reason": …, "from": DEVICE}}` | relay forwards a leg message to the initiator |
| `{"timer": "start", "name": "T-Ring", "seconds": 120}` / `{"timer":"stop","name":…}` / `{"timer":"fire","name":…}` | timer lifecycle (`T-Establish`, `T-Ring`, `T-Queue`, `T-Ring-Local`); `stop` is emitted only for a running timer; a restart emits only `start` |
| `{"media": "start" \| "stop" \| "apply_update"}` | media-layer instruction |
| `{"ui": "progress", "status": …}` | caller-side ringing/queued/etc. |
| `{"ui": "answered", "answered_by": …}` | caller-side, including `screening` |
| `{"ui": "offered"}` | responder-side invite admitted to OFFERED |
| `{"ui": "update_offered"}` / `{"ui": "update_rejected", "reason": …}` | renegotiation surfaces |
| `{"ui": "missed_call"}` | responder surfaces a missed call (never on `session.answered-elsewhere`) |
| `{"ui": "ended", "reason": …}` | session reached ENDED because of a remote message or timer |
| `{"ui": "glare_retry"}` | equal-id glare; MAY retry after 1–4 s |
| `{"ui": "introduction_received", "from": IDENTITY, "token": true?}` | requests surface (§19.4) — never a ring |
| `{"ui": "granted", "by": IDENTITY}` / `{"ui": "introduction_rejected", "reason": …}` | sender-side outcomes |
| `{"queue": {"to": IDENTITY, "type": "introduction"}}` | relay queued an introduction for an unbound identity |
| `{"ui": "error", "reason": …}` | a received `error` is surfaced; no state change |
| `{"info": {"about": …}}` | an `info` with a recognized `about` is handed to the binding |
| `{"refused": REASON}` | a local request was refused by the engine (`unknown-session` for any request about a session the endpoint does not hold, `update-pending`, `no-pending-update`, `unknown-introduction`, `unknown-grant`) |
| `{"drop": REASON}` | message silently ignored (`ended-session`, `unknown-about`, `stale-update-reply`, `duplicate-introduction`, `unknown-introduction`) |

## Kind: `broadcast`

Receiver-side verification of a publication record and its provenance (§22).

```json
"input":  { "publication": ENVELOPE, "provenance": [ENVELOPE, …], "capabilities": {"codecs": […], "transports": […]} },
"expect": { "verdict": "accept", "type": "publish", "signer": …, "identity": …,
            "selected_variant": "main-opus" | null,
            "provenance": [ {"verdict":"accept","processor":…,"operation":…,"policy_violation"?:…} | {"verdict":"reject","code":…} ],
            "display": {"original_publisher": …, "delivered_by": […], "transcoded_by": […], "integrity_mode": "metadata-only"|"derivative-bound"} }
```

Extra codes: `publisher-mismatch` (record `publisher` ≠ verified identity), `stream-id-namespace`
(`stream_id` not under the publisher DID), and per-statement `provenance-unknown-publication`,
`provenance-stream-mismatch`, `provenance-processor-mismatch`, `provenance-variant-unknown`.
Provenance statements are the core `provenance` message (v0.7, §22.3; schema `provenance.schema.json`),
no extension declaration. The record's `integrity` (§22.2) is shown unless a verified transcode statement makes the
delivered stream `derivative-bound`; a selected variant's own `integrity` overrides the record's; unknown tokens fall back to `metadata-only`.

A verified statement's `policy_violation` is `redistribution` when the record's policy says `redistribution: "forbidden"`
(any operation), else `transcoding` for a `transcode` under `transcoding: "forbidden"`; absent otherwise. Its
A statement has no `integrity_mode` of its own (§22.3, spec-gap 77): the one integrity mode is `display.integrity_mode`. Statement checks run in this order after the envelope pipeline:
`provenance-unknown-publication` → `provenance-stream-mismatch` → `provenance-processor-mismatch` → `provenance-variant-unknown`
(`input_variant` only; the output variant is the processor's own).

### State components `authority` and `subscriber`

`authority` (a target's relay/domain endpoint, §9.3/§22): events `{"recv": publish|unpublish|subscribe|provenance}`,
`{"local":"policy","target":T,"mode":"public"|"allow","allow":[…]}`, `{"local":"issue_capability","token":S,"target":T}`,
`{"relay":"bind"|"unbind",…}` (presence source), `advance`. Emissions: `send notify {to, subscription, seq, state, reason?, body}`,
`send reject {to, session, reason}`, `{"publication": {"stream", "state"}}`, `{"provenance": {"stream","processor"}}`,
`{"subscription": {"id","state": "replaced"|"terminated"}}`, `drop` reasons. Snapshots `publications` and `subscriptions`.

`subscriber`: `{"local":"subscribe","id","to","target","events","expires_in"}`, `{"recv": notify|reject}`, `advance`.
Emissions: `send subscribe`, `{"ui":"notify","event","state"}`, `{"ui":"subscription_terminated","reason"}`,
`{"ui":"subscription_rejected","reason"}`, `{"ui":"subscription_lapsed","subscription"}`, `drop` (`stale-seq`,
`terminated-subscription`, `unknown-subscription`). Snapshot `subscriptions: {id: {target, state, seq}}`.

## Kind: `media-binding`

WebRTC Media Binding 1.0 (`v0.8/dsip-webrtc-media-binding-v0.8.md`) conformance, below the
envelope pipeline: inputs are decoded payloads or event traces. `input.check` selects:

| check | input | expect |
|---|---|---|
| `offer` | `payload` = an `invite`/`update` body (`media`, `transports`) | verdict (B§2, B§2.1, B§2.2) |
| `answer` | `offer` + `payload` (an `answer` body with `from`) | verdict (B§2.1, B§3.1, B§3.3) |
| `role` | `offer_setup`, `answer_setup` | `{"verdict":"accept","offerer":"server\|client","answerer":…}` or verdict (B§3.3) |
| `candidates` | `steps` of `local_candidate` / `gathering_complete` / `active` / `remote_description` / `remote_info{from,candidates,end_of_candidates}` / `session_end`; `context.peer` | per-step `emit`: `buffer{local\|remote,n}`, `send_info{candidates,end_of_candidates}`, `apply n`, `remote_end`, `ignore{after-end\|not-party\|ended}`, `drop_buffered n` (B§4.2–B§4.4) |
| `renegotiation` | `steps` of `local_reoffer{ufrag}` / `remote_answer` / `remote_reject` / `remote_reoffer{ufrag}` / `answer_update`; `context.ufrag` | per-step `emit`: `local_description{pending\|current}`, `apply`, `rollback`, `reject{reason,detail}`, `error binding-ice-restart` (B§5) |
| `one-answer` | `offer` + `answers[]` | `{"applied": DID, "legs": [{from, applied\|bye[,code]}]}` — first valid answer applied, earlier invalid legs `bye media.failed`, later legs `bye session.already-answered` (B§6.1) |

Offer/answer checks run in this order, first failure wins: `binding-ice-mode` → `binding-sdp-missing` →
`binding-sdp-invalid` → `binding-extra-section` → `binding-section-count` → per live section in order
`binding-kind-mismatch` → `binding-direction-mismatch` → `binding-codec-missing` → then per live section
`binding-encryption` → `binding-rtcp-mux-missing` → `binding-fingerprint-missing` → `binding-ice-credentials-missing` →
`binding-setup-invalid`. Almost every vector breaks exactly one rule, so of this order the suite itself pins only `binding-extra-section`
before `binding-section-count`; the rest is the order the implementations share. A live section is an `m=` line whose port is not 0; attributes fall back to the session level.
An offer or answer that does not select `transport:webrtc` is `{"verdict":"accept","binding":"not-webrtc"}`.
Trace checks (`candidates`, `renegotiation`) put their expectations in `expect.steps[i].emit`, parallel to
`input.steps[i].event` — unlike kind `state`, where each step carries its own `expect`.

## Kind: `trust`

The lines a client shows for who is on the other side (§18.1: the basis of verification, never a generic badge).
The spec gives the *form* of each line; the exact text below is this suite's and is compared as a string.
`expect` is the string itself (or `null`), not an object. `input.check` selects:

| check | input | expect |
|---|---|---|
| `basis` | `identity` (DID), `claims` | with a `tel` claim (first one; it outranks the carrying identity's own basis): `Gateway attested by <verifier> · STIR attestation <A\|B\|C> (verified\|unverified)`, or `… · no attestation` when `attestation` is `none`; `<verifier>` is the host of the claim's `did:web` verifier. Otherwise `Self-issued identity` (`did:key`), `Domain verified (<did>)` (`did:web`), `Unrecognized identity method` |
| `tel-caller` | `claim` | `PSTN caller <number>`, plus ` · <cnam>` when the claim has one; `null` for a claim that is not `tel` |
| `downgrade` | `losses` (tokens of the gateway `downgrade` check) | `Trust downgraded crossing the gateway (§6.3)`, then `: ` and the losses joined by `; ` — `no-srtp-on-trunk` → `media is not encrypted on the PSTN trunk`, `identity-not-assertable` → `your identity could not be asserted into the PSTN`, `no-attestation` → `the caller carried no verified attestation`, `policy-unenforceable` → `your media policy cannot be enforced past the gateway` |

## Kind: `gateway`

Phase 4 (`impl/docs/dsip_gateway_plan.md` §8): the normative tables the Gateway Profile will
carry, pinned before the gateway exists. `input.check` selects:

| check | input | expect |
|---|---|---|
| `reason-inbound` | `sip_status`?, `q850`?, `phase` (`pre-answer`\|`active`\|`transport`), `moved_to`? | `{reason, carry: reject\|bye\|error, detail?}` — Q.850 cause wins over the status; unmappable → `gateway.mapped`; BYE without Reason → `user.hangup`; attempt-phase tokens arriving while ACTIVE become `gateway.mapped` (§15.5) |
| `reason-outbound` | `reason`, `phase` | pre-answer: `{status, q850?, reason_header: {protocol: "DSIP", text}, retry_after?}`; active: `{method: "BYE", q850, reason_header}` — every crossing carries `Reason: DSIP;text=<token>`; unregistered tokens fall back by category (§15.1) |
| `sdp-to-descriptors` | trunk `sdp` | `{media: [descriptors], srtp: none\|sdes\|dtls}` or `{error}` |
| `descriptors-to-sdp` | DSIP `media` | `{m_lines: [{kind, encodings, direction}]}` |
| `claims` | `from_tn`, `identity` (`attest`, `verified`, `orig_tn`)?, `cnam`? | `{claim: {type: tel, number, attestation, verified, verifier, cnam?}, trust_basis}` (§18.1: a basis line, never a badge; `orig` mismatch discards the attestation) |
| `downgrade` | `facts` (`direction`, `trunk_srtp`, `identity_assertable`, `attestation`, `policy_present`) | `{downgraded, lost: [no-srtp-on-trunk \| identity-not-assertable \| no-attestation \| policy-unenforceable]}` (§6.3) |
| `trace` | `steps` of `{dsip: MSG}` / `{sip: {status}\|{request, …}}` / `{timer: "C"}`; `context.direction`, `context.early_media` | per-step `emit` (what each leg is told: `{sip: "INVITE"\|"ACK"\|"CANCEL"\|{response, direction?, q850?, reason_header?}\|{request, …}}`, `{dsip: {local: …}}`, `{media: bridge\|release}`) and `state: {dsip, sip}` |

Details the table leaves out, all part of the contract:

- **The gateway's identity is fixed**: `did:web:gw.example` is the `verifier` of every `tel` claim, and `trust_basis` is the
  kind-`trust` `basis` line for that claim. `cnam` is carried only when given. A `moved_to` turns `identity.not-in-service`
  into `identity.moved` with `detail` = the target; otherwise `detail` is `Q.850 <n>` when a cause was given and mapped (or
  when there is no status), else `SIP <status>`. `phase` defaults to `pre-answer`.
- **Attempt tokens** that become `gateway.mapped` once ACTIVE: `endpoint.busy`, `endpoint.unavailable`, `user.declined`,
  `identity.unknown`, `identity.not-in-service`, `identity.moved`, `session.cancelled`, `policy.blocked` (spec-gap 78).
  `user.hangup`, `media.*`, `gateway.*` and `session.timeout` are reported as they map.
- **Outbound causes**: an unregistered token takes its category's status *and* the cause of that category's
  representative row — `user` 603/21, `endpoint` 480/18, `identity` 404/1, `session` 500/41, `media` 488/65, `policy` 403/21,
  `transport` 503/41, `gateway` 503/38; an unrecognized category is `session.failed`, 500/41 (spec-gap 79). A BYE carries
  cause 16 for `user.hangup`, `session.already-answered` and `session.cancelled`, 47 for `media.failed`, 31 for
  `policy.terminated`; any other registered token keeps its own row's cause (`session.timeout` → 102), and an
  unregistered token is 16 — category fallback is a pre-answer rule.
  `retry_after: true` appears only for `policy.rate-limited`.
- `downgrade-error` (input `facts`) is the `detail` of the informational `error gateway.downgraded`: `{losses: […]}`, or
  `null` when nothing was lost. Losses are listed in G§7 table order; `no-attestation` is inbound-only,
  `identity-not-assertable` outbound-only.
- `trace` keeps expectations in `expect.steps[i]` = `{emit, state}`, parallel to `input.steps[i].event`. States — DSIP leg:
  `inviting`/`proceeding` (outbound), `offered`/`alerting` (inbound), `active`, `ended`; SIP leg: `calling`, `early`,
  `confirmed`, `terminated`. The DSIP leg is told things as the endpoint engine's own local events: `place_call {claims,
  trust_basis}`, `alert`, `accept {answered_by: gateway}`, `auto_reject {reason, detail}`, `cancel`, `hangup {reason}`,
  `update {direction}`, `info {about, data}`. What is not carried is `{"ignore": TEXT}` with exactly: `dsip info <about>`,
  `dsip dtmf outside the established call`, `sip dtmf outside the established call`. A SIP request is answered before the
  DSIP leg is told (`200` then `hangup`; `200`, `cancel`, then `487`); a 2xx is ACKed before anything else.

## Kind: `messaging`

DSIP Messaging Profile 1.0 (`v0.8/dsip-messaging-profile-v0.8.md`, cited `M§n`), tranche 1.
Written **before** any implementation. The profile schema set is staged at
`v0.8/dsip-messaging-schemas-draft/` (generated, freshness-checked like the core set). MLS is
abstracted: traces carry what a hub or mailbox observes (epoch, commit adds/removes, validity, a
digest of the MLS bytes), just as relay traces abstract signatures. `input.check` selects:

| check | input | expect |
|---|---|---|
| `payload` | `schema`, `payload` | `accept` / `schema-invalid` |
| `message` | a profile message `payload` | `accept`, or the first failing rule: `unknown-type` → `schema-invalid` → `lifetime-exceeded` (> 60 s; ephemeral > 10 s) → `deposit-class-unsupported` (`mailbox.unsupported-class`) → `deposit-fields` (M§5.2 class table) → `object-too-large` (`mailbox.object-too-large`, decoded length > 24,576 computed as `len·3/4`); `mailbox-mode-unsupported` (`mailbox.unsupported-mode`); `key-packages-empty` |
| `object` | a decrypted content `object`; `context.conversation`, `conversation_kind`, `leaf_identity` | `payload-float` → unknown object `accept {effective: {render: ignore}}` → `schema-invalid` → `sender-mismatch` → `conversation-mismatch` → `ulid-sent-at-mismatch` (> 300 s) → `personal-group-only`; content: `content-body`, `reaction-invalid`, `accept {effective: {kind, purpose}}` (unknown kind → `file` with a blob, else `unsupported`; unknown purpose → `message`); receipt: `receipt-shape`, `effective.receipt` or `render: ignore`; activity: `effective.activity` (unknown → `active`) |
| `conversation-ext` | `extension` | `schema-invalid` or `effective.kind` (unknown → `group`) |
| `blob-replicate` | `mode`, `max_blob_bytes`, `stored`, `entry {uri, sha256, size}`, `fetched? {status, sha256, size}`, `attempt?`, `max_attempts?` | `{action: fetch\|skip\|store\|discard, reason?, retry?}` (M§8.4 rule 6, spec-gaps 65 and 67) |
| `items-blobs` | `blob_endpoint`, `stored`, `manifest` | `{blobs}` with held entries at the mailbox's endpoint (spec-gap 65) |
| `blob-sources` | `blob` (content), `manifest` | `{sources: [uri]}` in fetch order (M§8.4 rules 6–7, spec-gap 65) |
| `call-event` | `alerted`, `answered_here`, `ended_by` (`local`\|`remote`), `reason` | `{send, outcome?}` (M§13.3, spec-gap 63) |
| `peer-timeline` | `content: [{id, at}]` (seq order), `calls: [{session, at, outcome}]` (seq order) | `{timeline: [content:id\|call:session], collapsed}` (M§13.3, spec-gap 63) |
| `external-join` | `kind`, `owner?`, `roster` (identities), `joiner {identity, device}`, `adds`, `removes` | `accept`, or `external-join-adds` / `external-join-not-member` / `external-join-removes-other` (M§6.8, spec-gap 62) |
| `conversation-update` | `before`, `after` (`dsip_conversation` values) | `schema-invalid`, `conversation-immutable` (conversation, kind or successor_of changed), or `effective {moves_to: did\|null, hub}` (M§7.4, spec-gap 60) |
| `mailbox-select` | `document_entries`, `hint_entries`, optional `reachable` (mailbox DIDs that accept a connection) | `{source: did-document\|hint\|null, selected, order, sync_targets, discarded}` (M§4.2, §8.1) |
| `mailbox-switch` | `established {mailbox, source}`, `candidate {mailbox, source}` | `{switch, reason: unchanged\|hint-sourced\|did-document}` (M§4.2, M§15.4) |
| `mls-extension-encode` | `extension_type`, `data_hex` | `{hex}` — `uint16 type ‖ minimal RFC 9420 §2.1.2 length ‖ data` (M§17 codepoints `0xF0D1`, `0xF0D2`) |
| `mls-extension-decode` | `hex` | `accept {extension_type, data_hex}` or `mls-truncated` / `mls-length-invalid` (0b11 prefix) / `mls-length-non-minimal` / `mls-trailing-bytes` |
| `mls-credential` | `credential {credential_type, identity_hex}`, `signature_key_hex`, `extensions [{extension_type, data_hex}]`; standard `context` | `accept {identity, device}` or, in order, `credential-type` → `credential-identity` → `delegation-missing` → `delegation-invalid` → `delegation-capability` (needs `dsip.messaging`) → `delegation-expired` → `credential-key-mismatch` (M§6.2) |
| `mls-conversation-bytes` | `data_hex` | `payload-not-utf8` → `payload-not-json` → `payload-float` → `schema-invalid`, or `effective.kind` (M§6.3) |
| `seal` | `use` (`blob`\|`activity`\|`archive`), `key_hex`, `nonce_hex`, `plaintext_hex`, `group_hex` + `epoch`/`seq` | `{sealed_hex}` = nonce ‖ AES-256-GCM ciphertext ‖ tag; AAD none / `group ‖ u64be(epoch)` / `group ‖ u64be(seq)` (M§8.4, M§11.1, M§12.2) |
| `open` | as `seal` with `sealed_hex`; blobs add `size`, `sha256` | `accept {plaintext_hex}` or `blob-size-mismatch` → `blob-hash-mismatch` (blobs) → `sealed-too-short` → `aead-open-failed` |
| `voicemail-offer` | `voicemail` (the callee's advertisement or null), `can_send`, `outcome {type: reject\|cancel, reason}` | `{offer, max_duration_s?}` — reject `user.no-answer`/`user.declined`/`endpoint.busy`/`endpoint.unavailable`, the caller's `cancel session.timeout`, or an **unregistered** `endpoint.*` token (M§13.2) |
| `direct-select` | `candidates [{conversation, issued_at}]` | `{winner, discarded}` — lowest ULID among candidates passing the 300 s ULID/`issued_at` check (M§7.2) |
| `successor-check` | `predecessor_roster`, `creator`, `roster` | `accept` or `successor-invalid` (M§7.5) |
| `successor-select` | `candidates [group_id base64url]` | `{winner, discarded}` — lowest decoded ULID; non-ULID ids discarded (M§7.5) |
| `client-trace` | `steps` of `{sync: {items: [{seq, object}]}}` / `{restore: {items}}` (spec-gap 64: rendering state only) / `{read: {through}}` / `{play: {id}}` / `{activity: {activity, state}}` / `{advance: s}`; `context.me`, `policy {delivered, read, played, activity}`, `member_identities` | per step `emit` (`archive {seq}` for a receipt that changed rendering (spec-gap 64), `send {to: conversation\|personal, receipt, targets\|through}` / `send {to, activity, state}`) and `state {timeline, delivered, played, read_through}` (M§10, M§11.2, M§8.5) |
| `gap-trace` | `steps` of `{item: {seq, class}}` / `{advance: s}`; `context.contiguous`, `gap_timeout?` (spec-gap 69) | per step `emit` (`process`, `hold`, `duplicate`, `rejoin {held}`) and `state {contiguous, held}` (M§6.5) |
| `resume-trace` | `steps` of `{items: {items: [{cursor, class, group, seq?, sibling?}], crash_at?}}` / `{sent: {group, seq}}` / `{rejoined: {group, seq}}` (spec-gap 69; a join: the group is joined from then on, at that `seq`) / `{sync: {}}` / `{restart: {}}` / `{cursor_invalid: {}}`; `context.cursor`, `groups`, `joined`; a non-sibling `welcome` with `seq` sets the group's position to it, one without leaves the first sequenced item processed to set it (spec-gap 83) | per step `emit` (`process`, `duplicate`, `sibling`, `crash`, `sync {since, ack_through?}`) and `state {cursor, groups: {group: {contiguous, seen}}, joined}` (M§5.4, M§8.5; spec-gap 44) |
| `commit-retry-trace` | `steps` of `{answer: {reason?}}` / `{synced: {still_needed, hub_moved?}}`; `context.max_attempts` | per step `emit` (`merge`, `discard`, `sync`, `repropose {attempt}`, `done`, `surface`) and `state {attempt, state}` (M§6.5, spec-gap 58; `mailbox.unknown-group` retried only when `hub_moved`, spec-gap 60) |
| `successor-trace` | `steps` of `{welcome: {group, successor_of, creator, roster}}` / `{create: {predecessor}}` / `{created: {group, successor_of}}`; `context.groups` (group → roster by identity) | per step `emit` (`join`, `decline`, `leave`, `first_contact`, `create {successor_of, roster}`, `use`, `refuse`) and `state {predecessor: {successor, candidates}}` (M§7.5, spec-gap 61) |
| `history-trace` | `steps` of `{archive: {cursor, akid, group, seq, id, object?}}` / `{archive_key: {akid, created_at}}` / `{mls: {group, seq, epoch, id}}` / `{sent: {group, seq, id, object?}}` / `{joined: {group, epoch}}`; `context.keys`, `joined` | per step `emit` (`hold`, `show`, `apply` (a receipt or call event, spec-gaps 63–64, 68), `duplicate`, `prejoin`, `archive {group, seq, akid}`) and `state {timeline, held, current_akid}` (M§12.2, M§12.3, M§8.5) |
| `hub-trace` | `steps` of `{deposit: {id, device, identity, class, epoch?, digest, commit?: {adds, removes, valid?, external?}, expires_at?}}` / `{ack: {identity, seq, class?}}` (`class: welcome` acknowledges the welcome queue, spec-gap 66) / `{advance: s}` / `{restart: {}}` (spec-gap 59: full state survives; every unacknowledged queue head is re-sent); a commit with `moves_to` leaves the hub refusing the group (spec-gap 60); `context.epoch`, `roster`, `kind`, `owner?` | per step `emit` (`accepted {to, in_reply_to, seq, duplicate?}`, `error {to, in_reply_to, reason}`, `fanout {to, seq, class}` (a welcome carries the commit's seq, spec-gap 66), `forward {to, class: ephemeral}`) and `state {epoch, next_seq, roster, pending, welcomes}` |
| `mailbox-trace` | `steps` of `welcome`, `hub_deposit`, `sync`, `unbind`, `config`, `archive`, `kp_upload`, `kp_fetch`, `advance`, `restart` (spec-gap 59: durable state survives, live bindings do not); a `hub_deposit` whose `seq` is at or below the group's highest stored is a redelivery (`accepted` with `duplicate`); a `config` group naming another `hub` with `handover_seq` moves the registration (spec-gap 60); a `kp_fetch` with `successor_of` naming a registered group needs no grant (spec-gap 61); `context.owner`, `serves`, `devices`, `mode`, `admit`, `groups`, `key_packages`, `pending_group_ttl`, `pending_group_max_items` | per step `emit` (`accepted {to, in_reply_to, cursor?, duplicate?}`, `error`, `items {to, in_reply_to, cursors, next}`, `push {to, cursor}` / `push {to, class: ephemeral}`, `key_packages {to, in_reply_to, devices}`) and `state {items: [cursor], groups: {group: pending\|joined}, key_packages}` |

Checks the table above did not list (found by the second implementation; all are in the suite):

| check | input | expect |
|---|---|---|
| `introduction` | a core `introduction` `payload` as the profile uses it | core stage 13 then 14 (`schema-invalid`, `introduction-purpose-and-sealed`), or `accept {effective: {sealed: bool}}` (M§14.1) |
| `sealed-introduction-open` | `payload`, `recipient_ed25519_seed_hex` (the recipient's X25519 key is derived from it as in `x25519-key-agreement`) | `accept {purpose}` (a plain `purpose` passes through; `null` when there is neither), or in order `sealed-alg-unsupported` → `sealed-open-failed` → `sealed-plaintext-invalid` (not exactly `{"purpose": string}`) → `purpose-too-long` (> 280 characters). HPKE `info` = `dsip sealed introduction v1`, AAD = `id ‖ 0x00 ‖ from ‖ 0x00 ‖ to` (M§14.1) |
| `hpke-open` | `enc_hex`, `sk_r_hex`, `info_hex`, `aad_hex`, `ct_hex` | `accept {plaintext_hex}` or `hpke-open-failed` — RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, sequence 0 (M§6.9) |
| `hpke-derive-key-pair` | `ikm_hex` | `{sk_hex, pk_hex}` (RFC 9180 §7.1.3) |
| `x25519-key-agreement` | `ed25519_seed_hex` | `{x25519_pk_hex}` — secret = SHA-512(seed)[0..32] clamped, as `did:key` derives it (M§6.9, spec-gap 55) |
| `blob-put` | `mailbox {did, serves, max_blob_bytes}`, `authorization` (`{identity, payload}` already verified, or `null`), `request {path_sha256, body_size, body_sha256}`, `stored` | `{status, reason}` in M§5.6 order — 401 `policy.blocked` → 403 `policy.blocked` (`to`) → 403 `transport.unknown-recipient` → 400 `policy.blocked` (path) → 413 `mailbox.object-too-large` → (a stored hash: `{status: 200, accepted: {in_reply_to, duplicate: true}}`) → 400 `mailbox.blob-mismatch` → `{status: 201, accepted: {in_reply_to}}` (spec-gap 48) |
| `blob-get` | `path_sha256`, `stored` | `{status: 200\|404}` |
| `registration-on-removal` | `me`, `remaining_identities` | `{left}` — true only when no leaf of the identity remains (M§5.7, spec-gap 53) |
| `hub-outage-trace` | see spec-gap 72 (events `deposit`, `answer`, `no_answer`, `advance`, `handover_failed`) | per step `emit` and `state` `{state, pending, attempt, down_for, handover_attempt}` |

**The deposit class table** behind `deposit-fields` (M§5.2 "The class field table" is the same table, spec-gap 80).
Every deposit may carry `recipient` — it is addressing, not class. Beyond the envelope fields, `class` and `recipient`:

| class | MUST carry | MAY carry |
|---|---|---|
| `handshake` | `group`, `mls` | `welcome`, `group_info`, `ratchet_tree_blob`, `grants`, `seq` |
| `application` | `group`, `mls` | `seq`, `blobs` |
| `welcome` | `group`, `mls`, `hub` | `ratchet_tree_blob`, `grants`, `origin`, `successor_of`, `seq` (the adding commit's: spec-gap 83) |
| `group-info` | `group`, `mls` | `ratchet_tree_blob`, `handover_seq` |
| `ephemeral` | `group`, `sealed` | — |
| `archive` | `group`, `archive`, `akid`, `ref_group`, `ref_seq` | — |
| `introduction`, `grant` | `recipient`, `envelope` (and no `group`: a schema rule) | — |

Anything else is `deposit-fields`. After it: `object-too-large` for `mls`, `welcome`, `group_info`, `sealed`, `archive`; then
`introduction-too-large` (`transport.envelope-too-large`) for a carried introduction `envelope` over 4,096 bytes.
`external-join` checks run `external-join-adds` → `external-join-not-member` → `external-join-removes-other`;
`blob-replicate` skips run `mode` → `stored` → `too-large` → `not-https`, and `attempt` defaults to 1 of `max_attempts` 5.

**All messaging traces** keep expectations in `expect.steps[i]` = `{emit, state}`, parallel to `input.steps[i].event`;
`state` is compared in full.

**Hub refusals, in order** (spec-gap 81): moved (`mailbox.unknown-group`, whatever the deposit) → class not one of
`handshake`/`application`/`ephemeral`/`group-info` (`mailbox.unsupported-class`) → an expired `ephemeral` is dropped with no
answer → a `handshake`/`application` whose `digest` was already sequenced is `accepted {seq, duplicate}` — before membership
and epoch → membership, or for an external commit the M§6.8 check (`policy.blocked`) → epoch (`mailbox.commit-conflict`
for a commit one epoch late, else `mailbox.stale-epoch`; an application is good for the current or previous epoch) →
the commit's validity and M§7.3 (`policy.blocked`). Device lists in `roster` are sorted. An `ack` is taken only for the
head of that identity's queue (a welcome's with `class: welcome`); anything else changes nothing. Fan-out to an identity
the commit brought in waits for its welcome's acknowledgement; a member gaining a device gets the commit *and* a welcome.
An external joiner's identity is not sent its own commit unless it was already a member.

**Mailbox events the table leaves out**: `first_contact {id, from, sender_identity, recipient, kind: introduction|grant,
expires_at}` (spec-gap 54) — rate-limited per sender identity and per recipient inbox at `context.intro_limit` per
`intro_window` (`error policy.rate-limited {retry_after}`, the seconds until the oldest counted deposit leaves the window;
both kinds count and both are limited, except a solicited grant — below), then accepted **without a cursor** for an unserved recipient or an inbox already
holding `inbox_cap` introductions, else stored until `expires_at` (kept at it, dropped after); `forward {id, device,
identity, group, to}` (spec-gap 45) → `{"forward": {to, id}}`, or `policy.blocked` (not the owner's device) /
`mailbox.unknown-group` (unregistered group, or `to` is not its hub); `forward_failed {id, device, to}` → `error
mailbox.hub-unreachable` (spec-gap 72). Other emissions: `{"handover_expired": {group, hub: the OLD hub, missing}}`
(spec-gap 71) and `{"close": {device, reason: "delegation-revoked"}}` after the `accepted` of a config with
`revoked_devices` (spec-gap 57). `key_packages.devices` is a map `device → "one-time"|"last-resort"`; an upload is bounded
at 100 one-time packages per device. A pending group is dropped when its age **exceeds** `pending_group_ttl`.
During a hub move the new hub is held off — whatever it sends, a GroupInfo included — while the old hub's items through
`handover_seq` are missing and `handover_wait` has not run out; only then is a `seq` at or below `handover_seq` judged
(`policy.blocked`). A `first_contact` of kind `grant` may carry `session`, the introduction it answers: when that id is
one the owner's device listed in a `config` `introductions_sent`, the grant is solicited — not counted, not limited, and
the entry is consumed (one introduction, one answer; the list survives a restart). Pushes go to the bound devices in device (DID) order, never to the device that made the deposit.

Trace emission order: `accepted`/`error` first, then fan-out or pushes in identity/device order,
then welcomes. Cursors are `c:` + 16 lowercase hex digits (Impl). Grants in mailbox traces are
presented already verified; their signatures are the envelope pipeline's concern.

## Kind: `dht`

Reachability hint records (§8.3, §8.5; plan §10). Input is a hint envelope,
optionally with `context.existing` (a previously accepted record for the same
subject). Expect: envelope verdict plus, on accept, `"winner": "input" |
"existing"` and `"conflict": "none" | "newer-seq" | "older-seq" |
"same-seq-live"` per the §8.3 rules (higher `seq` wins; expired records are
invalid; same key + same `seq` + differing content → `same-seq-live`, which
the profile treats as a warning — the existing record is kept).

## Spec-gap list (Impl decisions these vectors encode)

Each item has a matching `spec-gap` issue draft in `impl/docs/spec-gaps.md`.

1. §12.4 vs §12.5: responder in ACTIVE receiving `cancel` — error vs crossed-cancel teardown.
2. §12.6: which party sends `reject session.glare` vs `cancel session.glare`.
3. §12.8 rule 4: "processes neither" — both updates discarded.
4. §12.9: T-Ring restart semantics on repeated `ringing`, and what bounds PROCEEDING after a non-ringing `progress`.
5. §12.7 rule 3 / §12.4: when the initiator knows an invite was forked.
6. §20.6: ULID/`issued_at` mismatch tolerance (300 s) and rejection (not just MAY).
7. §12.9: future-dated `issued_at` (symmetric replay window).
8. §7.4: how delegation credentials are conveyed to a verifier.
9. §14.2 / check 9: precise subset semantics for media selections.
10. §15.4: registered token on a message type it is not listed as valid on.
11. §12.10: consecutive re-queue limit exceeded → treated as T-Queue expiry.
12. §12.4/§12.7: `bye` reason for an answer arriving after a terminal `reject` (`session.failed`).
13. §12.4: ENDING collapsed into ENDED (local teardown is synchronous in the reference engine).
14. §19.4 vs §13.2: relay treatment of introductions to unknown recipients (queued silently; no `transport.unknown-recipient`).
15. §19.4: grant matching (by `grant` reference or by grantee identity), scope check, single-use contact tokens.
16. §12.12/§16.3: WebRTC binding shapes (SDP in `transports[].sdp`, candidates in `info.data`).
17. §13.2/§13.3: "unknown recipient" at a store-and-forward relay = never bound here; queued envelopes expire silently.
18. §22.1: `publisher` MUST equal the verified identity; `stream_id` is namespaced under the publisher; newer ULID replaces.
19. §9.3: presence derives from device bindings at the authority; targets never seen get the uniform reject.
20. §22.2: integrity mode is advertised per variant (`integrity`), the closed `publish` schema has no record-level field.
21. §22.3: provenance statements reach subscribers in `notify.body.provenance`; carriage is otherwise unspecified.
22. §7.5: rotation has no wire record; vectors pin only what a verifier observes through the rotated DID document (`envelope/rotated-did-web-*`).
31. §12.9 vs §19.4: held introductions — no 300 s age bound, 604,800 s validity cap enforced, id tracked until `expires_at` (`envelope/introduction-*`).
74. §19.4: **decided** — `grant` and `reject` of an introduction are both addressed to the introducing identity (`state/first-contact-*`).
75. §12.5 rule 2 vs §12.7 rule 3: `cancel session.answered-elsewhere` reaching the leg that answered is `session.invalid-state`, not a crossed cancel (`state/race-responder-answered-elsewhere-at-answering-leg`).
78. G§4: which tokens are "attempt" tokens once ACTIVE — the profile's list omits `endpoint.unavailable` and `identity.not-in-service` (`gateway/inbound-active-*`).
81. M§6.5 / M§7.4 / M§14.1: the order of a hub's refusals when several apply, what the new hub may send during a handover wait, and whether a grant deposit is rate-limited (`messaging/hub-refusal-order-*`, `mailbox-hub-move-wait-covers-*`, `mailbox-grant-counts-*`).
80. M§5.2: the deposit class table says what each class "carries", not which other fields it may or may not carry; the rule is in this README (`messaging/deposit-*`).
79. G§4.2: the Q.850 cause of a category-fallback response, and of a BYE for a token the BYE rows do not name (`gateway/outbound-unknown-*`, `outbound-bye-policy-terminated`).
77. §22.2/§22.3: **decided** — a statement has no integrity mode of its own; the per-statement field is gone.
76. §12.7 rule 6: **decided** — when every leg expired and none rejected the relay sends its own `error transport.no-response`, which ends the attempt at the initiator (`state/relay-all-legs-expired`, `initiator-relay-no-response-ends-attempt`).
85. §12.4 / §12.7 rule 4: **decided** — the `bye` a late answer gets after the session has *ended* follows what the invite
    was, not how the call finished: `session.cancelled` when we withdrew it (§12.5 rule 3), `session.already-answered`
    when an answer was applied (however the call then ended), `session.failed` when the attempt was never answered
    (`state/fork-late-answer-after-the-call-ended`, `fork-late-answer-after-our-hangup`).
86. §12.7 rule 3/4 vs §13.2: **decided** — a forking relay never withholds an `answer`, even from a leg it has cancelled,
    expired or seen reject; only the initiator ends an answered leg. Stale `progress` and second `reject`s are still
    screened (`state/relay-user-cancel-all-legs`, `relay-answer-from-an-expired-leg-is-forwarded`,
    `relay-answer-from-a-rejected-leg-is-forwarded`).
73. §9.3 vs §15.4: a terminal `notify` carries `session.expired` / `policy.terminated`, tokens the registry lists as valid on other types only; no warning on `notify` (`semantic/notify-terminated-reason`, by the deep-equality rule above).
34–43. Messaging Profile draft choices (hub ordering, archive first-wins, first-contact authorization, `mailbox` tokens, `MAX_MLS_BYTES`, ephemeral lifetime) pinned by `messaging/*`; see the v0.8 messaging worklist in `impl/docs/spec-gaps.md`.

Emission ordering convention for state traces: timer stops → sends → media →
ui → timer starts. A session ending emits `media stop` (when media was running)
before `ui ended`. The places the suite departs from that order, so they are part of the contract:

- accepting an answer: `timer stop` → `media start` → `ui answered` → **then** `send cancel session.answered-elsewhere`;
- a `progress`: `timer stop T-Establish` → `ui progress` → **then** the T-Ring / T-Queue adjustment (`stop`, `start`);
  a `queued` beyond the re-queue limit is `ui progress` → `timer stop T-Queue` → `send cancel` → `ui ended`;
- a `cancel` at ALERTING: `timer stop` → `ui missed_call` → `ui ended`; T-Ring-Local expiry is `timer fire` →
  `send reject user.no-answer` → `ui ended user.no-answer`, with no `missed_call`;
- equal-id glare: our invite is withdrawn first (`send cancel session.glare` → `ui ended`), then theirs is rejected
  (`send reject session.glare`), then `ui glare_retry`; one session entry (ours) remains under the shared id;
- an inbound `update` carrying `answered_by` (screening escalation, §14.4): `ui update_offered` → `ui answered`.

Found by `impl/tools/fuzz.py` and part of the contract since: a reason is surfaced as its **effective** token (§15.1: an
unrecognized category is `ui ended session.failed`); an `answer` or `reject` carrying `in_reply_to` is an update reply and
never the attempt's outcome (before ACTIVE: `error session.invalid-state`); an `invite` for a session already held is
`error session.invalid-state`, or `drop ended-session` once it has ended; with several live attempts of ours to one
identity, the smallest id of all the invites wins and every losing attempt of ours is withdrawn, in id order (spec-gap 84).
A `recv` is a message that passed the envelope pipeline: its id is new and an `invite` is not yet expired.

A responder in ACTIVE that receives `cancel session.answered-elsewhere` answers `error session.invalid-state` even when
the initiator has not spoken since the answer: that reason is never a crossed withdrawal (spec-gap 75).
