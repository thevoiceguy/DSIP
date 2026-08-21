# DSIP Conformance Test Vectors

**Tracks:** DSIP Draft v0.6 + JSON Schema set v0.6 (draft 2020-12)
**Format version:** 1

These vectors are the language-neutral conformance contract for DSIP Core v1.0.
They are *generated* by `impl/tools/generate_vectors.py` (deterministic keys,
deterministic ULIDs, byte-reproducible signatures) and *verified* independently
by the Python harness (`impl/tools/run_vectors.py`) and the Rust runner
(`cargo run -p dsip-cli -- vectors run`). A vector is only trusted when both
agree with its `expect` block.

Expected outcomes are authored by hand from the spec text in the generator
modules — they are never derived from either implementation's output.

## File layout

```
vectors/
  envelope/    Signature, header, kid→DID resolution, delegation, replay, ULID/issued_at
  payload/     JSON Schema pass/fail per message type (shape only)
  semantic/    Stateless post-schema checks (schema README list of 11)
  state/       Scripted endpoint and relay state-machine traces (§12)
  transport/   ws/1.0 hello binding, anti-splicing, size cap (§13.2)
  dht/         Reachability hint records and §8.3 conflict rules
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

`spec_ref` entries cite v0.6 section numbers. Every vector has at least one.

## Fixed fixtures

All vectors share the fixture set in `fixtures.json` (also generated):

- **Keys** are Ed25519, seeded with `sha256("dsip-vector:" + name)`; the
  vectors carry only public material. `did:key` identifiers are the multicodec
  `ed25519-pub` (0xed01) form, base58btc, `z6Mk…`.
- **Identities:** `alice` and `bob` are identity controllers with delegated
  devices `alice-phone`, `alice-laptop`, `bob-phone`, `bob-laptop`. `relay` is
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
| `payload-shape` | core fields (`dsip`,`type`,`id`,`from`,`issued_at`,`expires_at`) missing or wrong primitive type | |
| `signer-mismatch` | `kid` DID ≠ `from` DID and no delegation presented linking them (§7.4, check 3) | `transport.hello-rejected` on `hello` |
| `delegation-invalid` | presented delegation fails: bad signature, wrong subject/device, not signed by subject controller | `transport.hello-rejected` on `hello` |
| `delegation-expired` | delegation not valid at `now` (`issued_at ≤ now < expires_at` required) | `transport.hello-rejected` on `hello` |
| `delegation-capability` | delegation lacks `dsip.signaling` | `transport.hello-rejected` on `hello` |
| `expiry-order` | `expires_at ≤ issued_at` (check 1) | |
| `replay-window` | `issued_at` outside `[now − 300, now + 300]` (§12.9, check 1) | |
| `expired` | `expires_at < now` (§12.9) | `session.expired` on `invite` |
| `duplicate-id` | `id` already seen within the replay window (§12.9) | |
| `ulid-issued-at-mismatch` | ULID timestamp component differs from `issued_at` by more than 300 s (§20.6, check 2) | |
| `version-unsupported` | §11 negotiation failed | one of the `session.unsupported-*` tokens |
| `schema-invalid` | payload fails its JSON Schema | |
| `unknown-type` | `type` is not a known message type | |
| `selection-not-subset` | `answer`/`reject` selection not ⊆ referenced offer (check 9) | |
| `subscription-lifetime-exceeded` | `expires_in` above the per-event cap (presence 3,600) (§9.3) | |
| `introduction-too-large` | encoded introduction envelope > 4,096 bytes (§19.4) | |
| `grant-unknown-introduction` | `grant.session` references no known introduction (§19.4) | |
| `hello-in-reply-to-mismatch` | relay `hello.in_reply_to` ≠ the client hello id actually sent (§13.2, §20.5) | |
| `hello-required` | session traffic before a verified `hello` (§13.2) | `transport.hello-required` |
| `hint-subject-mismatch` | DHT hint whose verified identity is not its `subject` (§8.3) | |

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
9. `replay-window` → `expired`
10. `duplicate-id`
11. `ulid-issued-at-mismatch`
11b. `hello-required` (transport binding state: `context.hello_verified` is `false` and the type is not `hello`)
12. `version-unsupported`
13. `unknown-type` → `schema-invalid`
14. Stateless semantic checks (`selection-not-subset`, `subscription-lifetime-exceeded`, `introduction-too-large`, `grant-unknown-introduction`, `hello-in-reply-to-mismatch`)

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
`warnings: ["reason-not-valid-on-type"]` (Impl decision; see spec-gap list).

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
             "known_introductions": [], "sent_hello_id": "…", "encoded_size": 4200 },
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
| `{"local":"place_call","session":ID,"to":DID}` | send `invite` (id = session), start T-Establish |
| `{"local":"cancel","session":ID}` | user abandons → `cancel user.cancelled` |
| `{"local":"hangup","session":ID}` | `bye user.hangup` |
| `{"local":"alert","session":ID,"ring_timeout":N?}` | policy admits invite → `progress ringing`, start T-Ring-Local |
| `{"local":"auto_reject","session":ID,"reason":TOKEN}` | policy rejects at OFFERED |
| `{"local":"accept","session":ID,"answered_by":V}` | user/service answers → `answer` |
| `{"local":"decline","session":ID}` | `reject user.declined` |
| `{"local":"update","session":ID,"id":ULID,"answered_by":V?}` | send `update` |
| `{"local":"answer_update","session":ID,"in_reply_to":ULID}` | answer the inbound outstanding update |
| `{"local":"reject_update","session":ID,"in_reply_to":ULID,"reason":TOKEN}` | reject it |
| `{"local":"info","session":ID}` | send `info` |
| `{"local":"introduce","id":ULID,"to":DID,"purpose":S,"contact_token":S?}` | send `introduction` (§19.4) |
| `{"local":"grant","introduction":ID,"id":ULID,"scope":[…],"valid_until":T}` | issue a contact grant for a pending request |
| `{"local":"reject_introduction","introduction":ID,"reason":TOKEN}` | decline a pending request (a policy choice) |
| `{"local":"revoke","grant":ID}` | revoke an issued grant (local policy) |
| `{"local":"issue_token","token":S,"grant_id":ULID}` | pre-authorize an out-of-band contact token (auto-grant on match) |

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
| `{"advance": SECONDS}` | clock |

### Expectation after each step

```json
"expect": {
  "emit": [ ...ordered emissions... ],
  "sessions": { ID: {"role":"initiator","state":"PROCEEDING","renegotiating":false,"outstanding_update":null} }
}
```

For the relay: `"attempts": { ID: {"legs": {DEVICE: "alerting|answered|rejected|expired|cancelled"}, "outcome": null|"answered"|"rejected"} }`,
optionally `"inbox": {IDENTITY: queued-introduction-count}`.
For an endpoint, optionally `"contacts": {"allow": […], "grants_issued": […], "grants_held": […], "requests": […], "pending_sent": […]}` (sorted ids).

Only the sessions / attempts named in `expect` are compared. `emit` is compared
exactly, in order.

### Emission vocabulary

| emission | fields |
|---|---|
| `{"send": {...}}` | `type`, `to`, `session`; plus `reason` (cancel/reject/bye/error), `status` (progress), `answered_by` (answer/update when set), `in_reply_to` (answer/reject/error when set), `id` only when the event supplied it |
| `{"deliver": {"leg": DEVICE, "type": …, "reason": …}}` | relay forwards to a specific leg |
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
| `{"refused": "update-pending"}` | a local request was refused by the engine |
| `{"drop": REASON}` | message silently ignored (`ended-session`, `unknown-about`, `stale-update-reply`, `duplicate-introduction`, `unknown-introduction`) |

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

Emission ordering convention for state traces: timer stops → sends → media →
ui → timer starts. A session ending emits `media stop` (when media was running)
before `ui ended`.
