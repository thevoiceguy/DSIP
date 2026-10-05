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
  did-webvh/   Resolving a did:webvh v1.0 log for DSIP (§7.2, §8.1, §8.4; v0.9, spec-gap 101)
  device-events/ Device Events Profile draft (E§3–E§6): traps → events → alarms, the alarm list, escalation
  alias-transparency/ Alias Transparency Profile draft (T§2–T§5): KEYTRANS building blocks, alias normalization
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
(`--dir`, `--json`) and compares actual with actual. CI runs it with a fixed seed and then with the run's own number as a second seed (printed, reproducible); a weekly
workflow uses a fresh one at a larger count.
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
| `replay-window` | `issued_at` outside `[now − 300, now + 300]` (§12.9, check 1); for `introduction` (spec-gap 31) and `reachability-hint` (spec-gap 96) only the future bound applies — their age is bounded by `expires_at` (§12.9, v0.8) | |
| `introduction-validity` | `introduction` with `expires_at − issued_at` > 604,800 s (§12.9, §19.4; spec-gap 31) | |
| `hint-validity` | `reachability-hint` with `expires_at − issued_at` > 3,600 s (§12.9, DHT profile §2; spec-gap 96) | |
| `sealed-not-critical` | a payload carries `sealed` but `dsip.critical` does not list `sealed-body/1.0` (§10.4; spec-gap 97) | |
| `sealed-alg-unsupported` | `sealed.alg` is not `hpke-base-x25519-sha256-aes128gcm` (§10.4; also sealed introductions, kind `messaging`) | |
| `body-unseal-failed` | `enc`/`ct` not base64url, or the HPKE open fails — wrong key, tampered, or AAD of another message (§10.4) | |
| `sealed-plaintext-invalid` | the opened plaintext is not a §10.3 JSON object with at least one key, or its byte length is not a positive multiple of 256 (§10.4) | |
| `sealed-field-not-sealable` | the plaintext holds a key outside the type's sealable fields (§10.4 table) | |
| `sealed-field-in-clear` | a key is present both inside the seal and in clear (§10.4) | |
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
9. `introduction-validity` (introductions only) / `hint-validity` (reachability hints only) → `replay-window` → `expired`
10. `duplicate-id`
11. `ulid-issued-at-mismatch`
11b. `hello-required` (transport binding state: `context.hello_verified` is `false` and the type is not `hello`)
12. `version-unsupported`
12b. Sealed body (§10.4, only when the payload has `sealed` and `context.unseal_key_hex` is present):
    `sealed-not-critical` → `sealed-alg-unsupported` → `body-unseal-failed` → `sealed-plaintext-invalid` →
    `sealed-field-not-sealable` → `sealed-field-in-clear`. A `sealed` that is not an object of three strings
    `alg`, `enc`, `ct`, or a payload whose `type`, `id`, `from` or `to` is not a string (the AAD inputs), is
    left for stage 13. A `dsip.critical` that is not an array lists nothing (`sealed-not-critical`). A type with
    no sealable fields admits none (`sealed-field-not-sealable` for any opened key). On success the opened fields replace `sealed` and stages 13–14
    run on the merged payload.
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

**Sealed bodies (§10.4, spec-gap 97).** `context.unseal_key_hex` is the X25519 private key of the DID in `to`
(32 bytes, hex; an identity's key agreement key, or a device `did:key`'s derived one): with it the receiver is the addressee and runs stage 12b. `context.router: true` makes the
receiver a router instead: it never opens a seal, and for a payload carrying `sealed` the critical-extension
rule of stage 12 does not apply to `sealed-body/1.0` (it binds the addressee); the clear part goes to stage 13
as it stands. With neither, a sealed payload is validated as it stands (the schemas admit `sealed` in place of
the type's sealable fields). Opening: HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM; `info` = `dsip sealed body v1`; AAD = `type ‖ 0x00 ‖ id ‖ 0x00 ‖ from ‖ 0x00 ‖ to` (UTF-8,
from the clear payload); `enc` and `ct` are base64url. Sealable fields: `invite` — `identity`, `intent`,
`policy`, `media`, `transports`; `answer`, `update` — `answered_by`, `media`, `policy`, `transports`; `info` —
`about`, `data`; `reject`, `cancel`, `bye` — `detail`. On accept, `effective.sealed` lists the opened keys,
sorted, beside whatever stage 14 reports.

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
| `{"local":"place_call","session":ID,"to":DID}` | send `invite` (id = session), start T-Establish; when the endpoint holds a grant issued by `to`'s identity, the `send` carries `grant` (its id, §19.4); a session this endpoint already holds, live or ended, is `refused invalid-state` — an id is used once (§12.9; spec-gap 90) |
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
| `{"recv": any}` to a *known* but unbound identity/device | queued (§13.3 store-and-forward) until `min(expires_at, context.offline_retention_s)`; `advance` expires queues; `bind` flushes the identity's and the device's queues together in arrival order — the order the relay received them, whichever of the two each was addressed to (spec-gap 98) — turning queued invites into tracked legs |
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
`expires_at >= now`. Queued envelopes that expire in the same step are reported in recipient order. Wherever one step
reaches several legs or attempts, it goes in device (DID) order and id order — the suite's order wherever a relay or
mailbox fans out: a `cancel` to the identity reaches its live legs in DID order, whatever order they were delivered
in, and a device that binds into several live attempts gets their invites in id order (spec-gap 89). An invite to an identity that has never bound here is answered `send error transport.unknown-recipient`.
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

WebRTC Media Binding 1.0 (`v0.9/dsip-webrtc-media-binding-v0.9.md`) conformance, below the
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

DSIP Messaging Profile 1.0 (`v0.9/dsip-messaging-profile-v0.9.md`, cited `M§n`), tranche 1.
Written **before** any implementation. The profile schema set is staged at
`v0.9/dsip-messaging-schemas-draft/` (generated, freshness-checked like the core set). MLS is
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
| `mailbox-trace` | `steps` of `welcome`, `hub_deposit`, `sync`, `unbind`, `config`, `archive`, `kp_upload`, `kp_fetch`, `advance`, `restart` (spec-gap 59: durable state survives, live bindings do not); a `hub_deposit` whose `seq` is at or below the group's highest stored is a redelivery (`accepted` with `duplicate`, and the retained item's cursor — found by group and seq, across a registration the owner left and made again, never an archive record's: spec-gap 92); a `config` group naming another `hub` with `handover_seq` moves the registration (spec-gap 60); a `kp_fetch` with `successor_of` naming a registered group needs no grant (spec-gap 61); `context.owner`, `serves`, `devices`, `mode`, `admit`, `groups`, `key_packages`, `pending_group_ttl`, `pending_group_max_items`, optional `quota_bytes` (spec-gap 99: a `welcome`, a stored `hub_deposit` or an `archive` may carry `size`; when the bytes of the retained items plus `size` would exceed `quota_bytes`, the deposit is refused `mailbox.quota-exceeded` — after the duplicate checks, so a redelivery is never refused, and before anything is stored or registered — a `group-info` that would replace the group's previous one is checked with the previous one still counted; every other refusal of that deposit (pending-group bound, hub move, queue-mode archive) comes first; `first_contact` items are never counted or refused for quota; the quota survives `restart`) | per step `emit` (`accepted {to, in_reply_to, cursor?, duplicate?}`, `error`, `items {to, in_reply_to, cursors, next}`, `push {to, cursor}` / `push {to, class: ephemeral}`, `key_packages {to, in_reply_to, devices}`) and `state {items: [cursor], groups: {group: pending\|joined}, key_packages}` (plus `used_bytes`, the sum of the retained items' `size`, when `quota_bytes` is set) |

Checks the table above did not list (found by the second implementation; all are in the suite):

| check | input | expect |
|---|---|---|
| `introduction` | a core `introduction` `payload` as the profile uses it | core stage 13 then 14 (`schema-invalid`, `introduction-purpose-and-sealed`), or `accept {effective: {sealed: bool}}` (M§14.1) |
| `sealed-introduction-open` | `payload`, `recipient_ed25519_seed_hex` (the recipient's X25519 key is derived from it as in `x25519-key-agreement`) | `accept {purpose}` (a plain `purpose` passes through; `null` when there is neither), or in order `sealed-alg-unsupported` → `sealed-open-failed` → `sealed-plaintext-invalid` (not exactly `{"purpose": string}`) → `purpose-too-long` (> 280 characters). HPKE `info` = `dsip sealed introduction v1`, AAD = `id ‖ 0x00 ‖ from ‖ 0x00 ‖ to` (M§14.1) |
| `hpke-open` | `enc_hex`, `sk_r_hex`, `info_hex`, `aad_hex`, `ct_hex` | `accept {plaintext_hex}` or `hpke-open-failed` — RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, sequence 0 (M§6.9) |
| `hpke-derive-key-pair` | `ikm_hex` | `{sk_hex, pk_hex}` (RFC 9180 §7.1.3) |
| `x25519-key-agreement` | `ed25519_seed_hex` | `{x25519_pk_hex}` — secret = SHA-512(seed)[0..32] clamped, as `did:key` derives it (M§6.9, spec-gap 55) |
| `blob-put` | `mailbox {did, serves, max_blob_bytes, quota_bytes?, used_bytes?}`, `authorization` (`{identity, payload}` already verified, or `null`), `request {path_sha256, body_size, body_sha256}`, `stored` | `{status, reason}` in M§5.6 order — 401 `policy.blocked` → 403 `policy.blocked` (`to`) → 403 `transport.unknown-recipient` → 400 `policy.blocked` (path) → 413 `mailbox.object-too-large` → 507 `mailbox.quota-exceeded` (spec-gap 99: `quota_bytes` set, the hash not already stored, and `used_bytes + size > quota_bytes` — decided from the authorized size, before the body) → (a stored hash: `{status: 200, accepted: {in_reply_to, duplicate: true}}`) → 400 `mailbox.blob-mismatch` → `{status: 201, accepted: {in_reply_to}}` (spec-gap 48) |
| `blob-get` | `path_sha256`, `stored` | `{status: 200\|404}` |
| `registration-on-removal` | `me`, `remaining_identities` | `{left}` — true only when no leaf of the identity remains (M§5.7, spec-gap 53) |
| `hub-outage-trace` | see spec-gap 72 (events `deposit`, `answer`, `no_answer`, `advance`, `handover_failed`). An `answer` whose `reason` is `mailbox.hub-unreachable` or `mailbox.quota-exceeded` (the hub could not store it, M§9.3; spec-gap 99) is an outage exactly like `no_answer` — a `retry_after` on it is not an input, the outage backoff governs; any other reason is a refusal | per step `emit` and `state` `{state, pending, attempt, down_for, handover_attempt}` |

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
the commit brought in waits for its welcome's acknowledgement; a member gaining a device gets the commit *and* a welcome —
its queue is not held, on a retry or after a restart either, and its welcome's acknowledgement re-sends nothing: only an
identity with no registration yet was waiting — and an acknowledgement from one still waiting moves its queue but sends
nothing (spec-gap 87).
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
at 100 one-time packages per device. A pending group is dropped when its age **exceeds** `pending_group_ttl`, with the hub deposits it admitted; an
archive record that references it is the owner's history and stays (spec-gap 91). A `welcome` is a redelivery
(`duplicate`, the first one's cursor) only while the mailbox still holds a welcome with those MLS bytes (`digest`) for
that group — not after the pending registration expired and took it, and not for another group (spec-gap 94).
During a hub move the new hub is held off — whatever it sends, a GroupInfo included — while the old hub's items through
`handover_seq` are missing (judged by the highest `seq` stored: the hub delivers in order, so a stored `seq` says every
lower one came before it, spec-gap 95) and `handover_wait` has not run out; only then is a `seq` at or below `handover_seq` judged
(`policy.blocked`). The expiry is announced (`handover_expired`) once, at the new hub's first deposit after the wait ran
out, whether that deposit is then admitted or refused (spec-gap 88). Only that expiry makes the old hub's later items at or
below `handover_seq` fills to store; when nothing was missing, an old hub's item at or below the highest stored stays a
redelivery (spec-gap 93). A `first_contact` of kind `grant` may carry `session`, the introduction it answers: when that id is
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

## Kind: `did-webvh`

Resolving a `did:webvh` DID from its log (v0.9 §7.2, §8.4; spec-gap 101), per the did:webvh v1.0
method specification (https://identity.foundation/didwebvh/v1.0/, DIF Ratified). Offline: the
vector supplies the log text, so no HTTPS fetch takes place.

**Input:** `{did, log, witness, cache, now}`.

- `did`: the requested DID.
- `log`: the `did.jsonl` text, one JSON entry per line. A single trailing `\n` is ignored.
- `witness`: the `did-witness.json` text, or `null`.
- `cache`: `{"versionId": "<n>-<hash>"}`, the highest versionId this resolver verified before for the
  DID, or `null`.
- `now`: integer Unix seconds, the resolver's clock.

**Expect**, exactly one of:

- `{"outcome": "resolved", "versionId", "versionTime", "document", "ttl", "cache"}`.
  - `versionId` and `versionTime` are the last entry's.
  - `document` is the last entry's `state`, byte-for-byte as JSON values.
  - `ttl` is the active `ttl` parameter, an integer (default 3600).
  - `cache` is the versionId to remember: the last entry's.
- `{"outcome": "deactivated", "versionId", "cache"}`. The active parameters have `deactivated: true`,
  so no document is returned (did:webvh §Deactivate). DSIP treats the DID as having no keys.
- `{"outcome": "rejected", "reason"}`, with `reason` one of the tokens below.

**Check order (normative for parity).** The first failing check gives the reason.

1. **The requested DID** (`invalid-did`). It must:
   - start `did:webvh:`;
   - have at least a SCID and a domain;
   - have a SCID of exactly 46 base58btc characters.

   The domain is `host[%3Aport]`:
   - `host` has at least two labels, each 1–63 characters of `[A-Za-z0-9-]`, and the labels are not
     all digits (an IP address);
   - `port` is 1–5 digits, 1–65535.

   Each further segment matches `([A-Za-z0-9._~-]|%XX)+`, with either hex case. Its percent-decoded
   bytes must be valid UTF-8. Once decoded, a segment must not be `.` or `..`, must not contain `/`,
   `\` or NUL, and must not begin or end with a Unicode `White_Space` character: U+0009–U+000D,
   U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F or U+3000.
   U+FEFF is not whitespace.
2. **The log is not empty** (`log-malformed`). Then, for each line *n* in order, steps 3–11:
3. **Structure** (`log-malformed`):
   - the line is **I-JSON** (RFC 7493), as JCS requires:
     - it parses as JSON;
     - no object has a member name twice;
     - no string or name contains a lone surrogate, escaped or not;
     - every number is an integer from −(2^53−1) to 2^53−1, written without a fraction or exponent
       (`-0` is allowed, and JCS writes it `0`);
   - it is an object with **exactly** the keys `versionId`, `versionTime`, `parameters`, `state`,
     `proof`;
   - `state` is an object;
   - `proof` is a non-empty array;
   - `versionId` is a string.
4. **versionId** matches `^[1-9][0-9]*-<base58btc>$`, and its number is *n* (`version-number`). The
   part after the dash is a sha2-256 multihash, `0x12 0x20` plus 32 bytes (`entry-hash`).
5. **versionTime** (`version-time`):
   - matches `YYYY-MM-DDTHH:MM:SS[.1–9 digits](Z|+00:00)`;
   - is strictly greater than the previous entry's;
   - is not later than `now + 300` seconds.
6. **Parameters** (`after-deactivation`, then `parameters`):
   - An entry after one whose active parameters have `deactivated: true` gives
     `after-deactivation`.
   - Otherwise `parameters` must be an object holding only `method`, `scid`, `updateKeys`,
     `nextKeyHashes`, `witness`, `watchers`, `portable`, `deactivated` and `ttl`.
   - Entry 1 has `method`, `scid` and `updateKeys`. Later entries have no `scid`.
   - `method` is exactly `did:webvh:1.0`. DSIP supports v1.0 only.
   - `scid` is a sha2-256 multihash.
   - The three lists are lists of strings, and every `updateKeys` member is an Ed25519 multikey.
   - `portable` and `deactivated` are booleans. `ttl` is an integer from 0 to 2^31.
   - There is no `portable: true` after entry 1.
   - `witness` is `{}`, or exactly `{threshold, witnesses}`, where:
     - `witnesses` is non-empty, and each element is an object whose `id` is a `did:key:` +
       Ed25519 multikey;
     - the ids are unique;
     - `threshold` is an integer from 1 to the number of witnesses.

   The active parameters then become the previous ones updated by this entry's. The defaults are
   `nextKeyHashes []`, `witness {}`, `watchers []`, `portable false`, `deactivated false` and
   `ttl 3600`.
7. **SCID, entry 1 only** (`scid`).
   - Take the entry without `proof` and set `versionId` to the string `{SCID}`.
   - Serialise it to JSON text and replace every occurrence of the `scid` value with `{SCID}`.
   - Parse it again and JCS-canonicalise it.
   - `base58btc(0x12 0x20 ‖ sha256(bytes))` must equal `scid`. There is no multibase `z` prefix.
8. **entryHash** (`entry-hash`). Take the entry without `proof`, with `versionId` replaced by the
   predecessor: the SCID for entry 1, otherwise the previous entry's full versionId. Its JCS
   canonicalisation must hash, as in step 7, to the part after the dash.
9. **Pre-rotation** (`pre-rotation`). It applies when *n* > 1 and the previous active
   `nextKeyHashes` is non-empty. The entry must then itself carry both `updateKeys` and
   `nextKeyHashes`. For every one of its `updateKeys`, `base58btc(0x12 0x20 ‖ sha256(utf8(key)))`
   must be in the previous `nextKeyHashes`.
10. **Proofs** (`proof`, then `unauthorized-key`).
    - The authorised keys are this entry's `updateKeys` for entry 1 or under pre-rotation, and
      otherwise the previous active `updateKeys`.
    - For each proof in order:
      - Its `verificationMethod` must be `did:key:<mk>#<mk>` with identical parts; otherwise
        `proof`.
      - If `<mk>` is not authorised, skip the proof.
      - Otherwise it must have `type: DataIntegrityProof`, `cryptosuite: eddsa-jcs-2022`,
        `proofPurpose: assertionMethod` and a `z`+base58btc `proofValue`, and its Ed25519 signature
        must verify (else `proof`). The signature is over
        `sha256(JCS(proof without proofValue)) ‖ sha256(JCS(entry without proof))`.
    - If no proof was by an authorised key, the reason is `unauthorized-key`.
11. **state.id** (`identity`).
    - It passes step 1, and its SCID equals entry 1's `scid`.
    - If it differs from the previous entry's `state.id`, the active `portable` must be `true` and
      `state.alsoKnownAs` must be a list containing the previous id.
12. **The requested DID** has the log's SCID, and some entry's `state.id` equals it (`identity`).
13. **Witnesses** (`witness`).
    - The witness configuration for entry *n*:
      - entry 1's active witness;
      - an entry whose previous witness was `{}` takes its own active witness;
      - otherwise the previous active witness.
    - Every entry with a non-empty configuration needs `witness` to be non-null I-JSON. A text that is
      not I-JSON counts as absent. Its records
      are `[{versionId, proof: [...]}]`; records whose `versionId` is not in the log are ignored.
    - A witness proof counts when its `verificationMethod` is `did:key:<mk>#<mk>` and its
      eddsa-jcs-2022 proof verifies over the document `{"versionId": …}`.
    - An entry is approved by the distinct witness ids, among its configuration's `witnesses`, that
      have a valid proof for that entry or any later one. There must be at least `threshold`.
14. **Cache** (`rollback`, then `fork`). Applies if `cache` is set and its `versionId` is a decimal number
    without a leading zero, a `-`, then a non-empty remainder of any characters (line terminators
    included), giving number *k*. Any other cache value is treated as absent:
    - fewer than *k* entries gives `rollback`;
    - an entry *k* whose versionId differs from the cached one gives `fork`.

**JCS** is RFC 8785 restricted to the values these logs hold: objects, arrays, strings, integers,
booleans and null. Object keys are sorted by their UTF-16 code units. There is no whitespace. A string escapes only `"`, `\\` and the
control characters U+0000–U+001F: `\b \f \n \r \t` where they exist, otherwise `\u00xx` with
lowercase hex. Everything else, non-ASCII included, is written as UTF-8.

## Kind: `device-events`

Device Events Profile draft (`v0.9/dsip-device-events-profile-v0.9-draft.md`, cited `E§n`; spec-gap 103). There are two
shapes: stateless checks (`input.check`) and alarm-list traces (`input.steps`).

**`check: "trap"`** (E§3), with `input.trap`, outputs `{"snmp": {version, uptime, trap_oid, varbinds}}` or
`{"error": "malformed-trap"}`. `varbinds` must be an array, and each element an object with string `oid` and
`type` and a `value` (any JSON). Anything else is `malformed-trap`. The output copies exactly those three members of
each, in order, and drops any other member.

- **`version: "v1"`**, with `enterprise` and `agent_addr` (strings), `generic` (an integer from 0 to 6), `specific`
  and `timestamp` (integers) and `varbinds`. Anything missing or of another type is `malformed-trap`.
  - `uptime` is `timestamp`.
  - `trap_oid` is `enterprise + ".0." + specific` when `generic` is 6, and otherwise
    `"1.3.6.1.6.3.1.1.5." + (generic + 1)`.
  - Two varbinds are appended in this order, each only if no varbind already has that OID:
    - `{oid: "1.3.6.1.6.3.18.1.3.0", type: "IpAddress", value: agent_addr}`;
    - `{oid: "1.3.6.1.6.3.1.1.4.3.0", type: "OBJECT IDENTIFIER", value: enterprise}`.
- **`version: "v2c"` or `"v3"`.**
  - Varbind 0 must have OID `1.3.6.1.2.1.1.3.0` and varbind 1 OID `1.3.6.1.6.3.1.1.4.1.0`; otherwise
    `malformed-trap`.
  - `uptime` is varbind 0's value, which must be a string of decimal digits not exceeding 2^53−1 (else
    `malformed-trap`), read as an integer. `trap_oid` is varbind 1's value, which must be a string (else
    `malformed-trap`).
  - The remaining varbinds are kept in order.
- Any other version is `malformed-trap`.
- Finally, in every case, varbinds with OID `1.3.6.1.6.3.18.1.4.0` (`snmpTrapCommunity.0`) are removed. Any
  `community` field in the input is never output.

**`check: "syslog-severity"`**, with `severity` 0–7 and an optional `table` (string keys "0"–"7" overriding the
default), outputs `{"severity": <token or null>}`. The default is 0–2 → `critical`, 3 → `major`, 4 → `warning`,
5–7 → `null`.

**`check: "map"`**, with `raw` (a `check: "trap"` output), `rules` and `source`:

- Rules are tried in order. A rule matches when its `trap_oid` equals the raw `trap_oid` and, if it has
  `varbind: {oid, value}`, some varbind has that OID and the same value compared as strings. The first match wins.
- A `notify` rule, or no match, outputs `{"notify": true}`.
- Otherwise the output is `{"alarm": {resource, type, qualifier: "", severity, cleared}}`:
  - `cleared` is true for `clear`;
  - `severity` is the rule's for `raise` (`null` if the rule has none), and `null` for `clear`;
  - `resource` is `source`, or `source + "/" + value` of the first varbind whose OID equals the rule's
    `resource_varbind` or starts with it plus `.`.

**Traces** have context `{now, escalation?: {min_severity, after_s}}`. Each step has an `event` and an expect of
`{"emit": [...], "alarms": [...]}`.

`alarms` is sorted by key, the array `[resource, type, qualifier]` compared element by element. Each entry is
`{key, severity, cleared, operator, count, escalation_due}`.

Severity order is `indeterminate < warning < minor < major < critical`, and any other token orders as `indeterminate`.

An alarm is **eligible** when all of these hold: the policy is set, it is not cleared, its operator state is `none`,
it has not escalated since its last raise, and its severity ≥ `min_severity`. After every change, an eligible alarm
with no timer gets `escalation_due = now + after_s`. An ineligible alarm has `null`. A running timer is kept while the
alarm stays eligible.

Events:

- **`report: {resource, type, qualifier, severity, cleared}`.** Every report on an existing alarm adds 1 to `count`,
  clears included.
  - **Unknown key, not cleared:** create the alarm (count 1, operator `none`) and emit
    `{"raised": {key, severity, reopened: false}}`.
  - **Unknown key, cleared:** nothing.
  - **Active, cleared report:** set cleared and emit `{"cleared": {key}}`.
  - **Cleared alarm, cleared report:** nothing.
  - **Cleared alarm, not-cleared report:** reopen it. Set the severity, operator `none` and not escalated, and emit
    `{"raised": {key, severity, reopened: true}}`.
  - **Active, same severity:** nothing.
  - **Active, different severity:** emit `{"changed": {key, severity}}`.
- **`ack: {alarm: {resource, type, qualifier}, state: "ack"|"closed", by}`.** A missing `qualifier` (here and in
  reports) is `""`, and a missing `by` is emitted as `null`. Ignored for an unknown key, when the
  operator state is already `closed`, or when it equals `state`. Otherwise set the operator state and emit
  `{"operator": {key, state, by}}`.
- **`heartbeat: {gateway, interval_s}`.** Records the gateway's interval and `last = now`. If the alarm
  `[gateway, "dsip-gateway-silent", ""]` is active, apply a cleared report to it.
- **`advance: n`.** Sets `now += n`. Then:
  1. For each gateway, in order of gateway id (compared as strings), whose silence alarm is not active and where `now − last > 2 × interval_s`, apply the
     report `{gateway, "dsip-gateway-silent", "", "major", not cleared}`.
  2. For each alarm with `escalation_due ≤ now`, ordered by due time then key, emit `{"escalate": {key, severity}}`,
     mark it escalated, and set `escalation_due` to `null`.

## Kind: `alias-transparency`

Alias Transparency Profile draft, stage 1 (`v0.9/dsip-alias-transparency-profile-v0.9-draft.md`, cited `T§n`;
spec-gap 104). These are the KEYTRANS building blocks, following the editors' copy of draft-ietf-keytrans-protocol
(2026-09-16) and the editor's implementation katie (commit `e1640671`), plus the profile's own rules. Every computed
value here was confirmed with katie. The editors' copy differs from -05 only in the mode-1 Configuration.

- All binary values are lowercase hex strings, with no prefix.
- `label` and `value` are strings, used as their UTF-8 bytes.
- Integers are big-endian in every encoding.
- `SHA-256` is written `H`, and `‖` is concatenation.

Each vector has `input.check`. The checks and their outputs:

- **`alias`** (`{alias}`, T§3) → `{"label": <normalized>}` or `{"error": "not-an-alias"}`.
  - Split at the **last** `@` into `local` and `domain`.
  - `local` is one or more characters, each U+0021–U+007E and not `@`.
  - `domain` is at least two `.`-separated labels. Each is 1–63 characters of `[A-Za-z0-9-]` and neither begins nor
    ends with `-`.
  - The result is `local + "@" + lowercase(domain)`, and must be at most 255 bytes.
- **`vrf-input`** (`{label, version}`) → `{"bytes"}` = `u8(len(label)) ‖ label ‖ u32(version)`. A label over 255
  bytes, or a version outside 0–2^32−1, gives `{"error": "vrf-input"}`.
- **`vrf-verify`** (`{public_key, alpha, proof}`) → `{"valid": true, "beta": <64-byte hex>}` or
  `{"valid": false, "beta": null}`.
  - The VRF is ECVRF-EDWARDS25519-SHA512-TAI, RFC 9381 §5.3, with `validate_key = TRUE` (§5.4.5).
  - Every point (the public key, Gamma, each encode-to-curve candidate) is decoded per RFC 8032 §5.1.3 and must be
    canonical: `y < p`, and not `x = 0` with the sign bit set. A non-canonical encoding does not decode.
  - `validate_key` refuses a key whose y-coordinate encoding, with its sign bit cleared, is one of
    `0, 1, bad_y2, p − bad_y2, p − 1, p, p + 1` (RFC 9381 §5.4.5). For decodable keys this is exactly the low-order
    points.
  - encode_to_curve's counter is one byte (0–255). Exhausting it gives no point, and the proof is invalid.
  - It is invalid when:
    - the public key does not decode;
    - the public key is one of the §5.4.5 low-order encodings;
    - the proof is not 80 bytes;
    - Gamma does not decode;
    - `s ≥ q`;
    - the challenge does not match.
- **`index`** (`{public_key, label, version, proof}`) → `{"index": beta[0..32]}`, where `beta` is `vrf-verify` over
  `alpha = VrfInput(label, version)`. A label over 255 bytes, or a version that is not an integer in 0–2^32−1, gives
  `{"error": "vrf-input"}`. A proof that does not verify gives `{"error": "vrf-invalid"}`.
- **`commitment`** (`{opening, label, version, value}`) → `{"commitment"}`, computed as:
  - `HMAC-SHA256(Kc, opening ‖ u8(len(label)) ‖ label ‖ u32(version) ‖ u32(len(value)) ‖ value)`;
  - `Kc` is the 16 bytes `d821f8790d97709796b4d7903357c3f5`;
  - `opening` must be 16 bytes, else `{"error": "opening"}`. Otherwise, a label over 255 bytes or a version outside
    0–2^32−1 gives `{"error": "label"}`.
- **`commitment-raw`** (`{opening, body}`, any lengths) → `{"commitment": HMAC-SHA256(Kc, opening ‖ body)}`.
- **`prefix-root`** (`{leaves: [{index, commitment}]}`) → `{"root"}`. The leaves have 32-byte, distinct indexes.
  - Bit *i* of an index is bit `7 − i mod 8` of byte `⌊i/8⌋`, so the most significant bit comes first.
  - The tree is the binary trie on these bits, with each leaf only as deep as needed to separate it from all others.
  - A leaf is `H(0x02 ‖ index ‖ commitment)`.
  - An internal node at depth *d* is `H(0x03 ‖ left ‖ right)`, where `left` and `right` are the subtrees of leaves
    whose bit *d* is 0 and 1. An empty side is 32 zero bytes.
  - With one leaf, the root is that leaf.
  - An empty list, an index or commitment that is not 32 bytes, or duplicate indexes, gives
    `{"error": "malformed"}`.
- **`prefix-parent`** (`{left, right}`, each hex or `null`) → `{"hash": H(0x03 ‖ left ‖ right)}`, where `null` is
  32 zero bytes.
- **`log-root`** (`{entries: [{timestamp, prefix_root}]}`, one or more) → `{"root"}`.
  - Leaf *j*'s value is `H(u64(timestamp) ‖ prefix_root)`.
  - For entries `[lo, hi)` with more than one entry, let *k* be the largest power of two less than `hi − lo`. The
    value is `H(tag(L) ‖ L ‖ tag(R) ‖ R)` over `[lo, lo+k)` and `[lo+k, hi)`, where `tag` is `0x00` for a single
    leaf and `0x01` for a computed parent.
  - With one entry, the root is that leaf's value. No entries gives `{"error": "malformed"}`.
- **`configuration`** (`{config}`; members other than those named below are ignored) → `{"bytes"}`, encoded in
  this order:
  1. `u16(ciphersuite)`;
  2. `u8(mode)`;
  3. twice `u16(len(key)) ‖ key`, for `signature_public_key` and `vrf_public_key`. This is the editors' copy: mode 1
     has no `leaf_public_key`, unlike -05;
  4. `u64` each of `max_ahead`, `max_behind` and `reasonable_monitoring_window`;
  5. `maximum_lifetime` as `0x00` when null, otherwise `0x01 ‖ u64(value)`.
- **`configuration-accept`** (`{bytes}`) parses that layout and applies T§2. Checks run in this order:
  1. a ciphersuite other than 2 → `{"error": "unsupported-suite"}`;
  2. a mode other than 1 → `{"error": "unsupported-mode"}`;
  3. any of these → `{"error": "malformed"}`:
     - the input runs out;
     - the presence byte is not 0 or 1;
     - there are trailing bytes;
     - a key is not 32 bytes;
     - a `u64` above 2^53−1.

  On success the output is `{"config": {signature_public_key, vrf_public_key, max_ahead, max_behind,
  reasonable_monitoring_window, maximum_lifetime}}`, with keys as hex and `maximum_lifetime` an integer or null.
- **`tree-head`** (`{configuration, tree_size, root, signature}`) → `{"valid"}`. It is true iff the configuration is
  accepted as above and the signature is a valid Ed25519 signature by its `signature_public_key` over
  `configuration ‖ u64(tree_size) ‖ root`. A configuration that is not accepted gives that error object instead.
- **`search-tree`** (`{n}`, n ≥ 1) → `{"root", "frontier"}`.
  - `root = 2^⌊log2 n⌋ − 1`.
  - `level(x)` is the number of trailing 1 bits of *x*.
  - `left(x) = x XOR 2^(level(x)−1)`.
  - `right(x)` is computed by setting `x ← x XOR (3 · 2^(level(x)−1))`, then replacing *x* with `left(x)` while
    `x ≥ n`.
  - The frontier is `[root]`, extended by `right(last)` until it reaches `n − 1`.
- **`ladder`** (`{version}`) → `{"ladder"}`, the base binary ladder.
  - Append `2^i − 1` for `i = 0, 1, …` until a value exceeds `version`.
  - Then binary-search between the last two: repeatedly append `mid = ⌊(lo + hi)/2⌋` while `lo + 1 < hi`, setting
    `lo = mid` if `mid ≤ version` and `hi = mid` otherwise.

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
87. M§6.5 / spec-gap 66: **decided** — the hold behind an unacknowledged welcome is for an identity the commit brought in;
    a member adding its own device gets the commit at once, again after a restart, and its welcome's acknowledgement
    re-sends nothing (`messaging/hub-member-adding-its-own-device-is-not-held-behind-the-welcome`).
88. M§7.4 / spec-gap 71: **decided** — the handover wait's expiry is announced at the new hub's first deposit after it,
    even when that deposit is itself refused `policy.blocked`
    (`messaging/mailbox-hub-move-handover-wait-expiry-announced-on-a-refused-deposit`).
89. §12.7 rule 3 / §12.11: **decided** — per-leg cancels go in device (DID) order and a late binder's invites in id order
    (`state/relay-cancel-reaches-live-legs-in-device-order`, `state/relay-late-binder-gets-live-invites-in-id-order`).
94. M§6.6 / spec-gap 66: **decided** — a welcome is a redelivery only while one with those bytes is still held for that
    group (`messaging/mailbox-welcome-after-pending-group-expiry-is-stored-anew`,
    `mailbox-welcome-same-bytes-for-another-group-is-its-own`).
95. M§7.4 / spec-gap 71: **decided** — what the old hub still owes is judged by the highest `seq` stored
    (`messaging/mailbox-hub-move-nothing-missing-once-the-highest-stored-reaches-handover-seq`).
93. M§7.4 / spec-gap 71: **decided** — an old hub's item at or below the highest stored is a fill only after the wait
    expired with items missing; otherwise it is a redelivery
    (`messaging/mailbox-hub-move-old-hub-item-below-the-highest-stored-is-a-redelivery`).
92. M§6.6 / spec-gap 59: **decided** — a redelivery's cursor is the retained hub item's, by group and seq, across a
    registration the owner left and made again, and never an archive record's
    (`messaging/mailbox-hub-deposit-redelivered-after-re-registration-carries-the-retained-cursor`,
    `mailbox-hub-deposit-redelivery-cursor-is-never-an-archive-records`).
91. M§6.6 / M§12.2: **decided** — a pending group's expiry drops the hub deposits it admitted, not archive records
    that reference the group (`messaging/mailbox-pending-group-expiry-keeps-archive-records`).
90. §12.4 / §12.9: **decided** — a local `place_call` naming a session the endpoint already holds is `refused invalid-state`
    (`state/place-call-on-a-held-session-is-refused`).
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
