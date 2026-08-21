# DSIP Core v1.0 — JSON Schema Set (spec revision v0.7, draft)

Changes from the v0.6 set: `provenance` (§22.3) and `key-rotation` (§7.5) are message types; `reachability-hint` (DHT Hints Profile) joins the set; `publish` carries a record-level `integrity` (§22.2); `webrtc-info-data.schema.json` is the WebRTC Media Binding's `info.data` shape and is validated when `info.about` is `transport:webrtc` (check 11).

**Status:** Draft, tracks DSIP v0.6 working documents (state machine 13A, transport 13B, answer semantics & reason codes 13C)
**Dialect:** JSON Schema draft 2020-12

## Contents

```
schemas/                    18 schema files
  invite | progress | answer | reject | cancel | update | info | bye | error
                            Interactive session payloads
  introduction | grant      First-contact exchange (19.4)
  hello                     Transport connection binding (13.2)
  publish | subscribe | notify | unpublish
                            Broadcast and subscription payloads (9.3, 22)
  envelope.schema.json      DSIP-JOSE signed envelope (10.2)
  message.schema.json       oneOf dispatcher over all payload types
generate_schemas.py         Single source of truth; regenerates schemas/
validate_samples.py         Sanity harness: 29 positive/negative cases, all passing
```

## How to validate

Each payload schema is **standalone**: shared definitions (`ulid`, `did`, `versionBlock`, `reasonToken`, media/codec/transport/policy structures) are embedded into every file by the generator, so any conforming 2020-12 validator works with no `$ref` resolver setup. Only `message.schema.json` uses relative cross-file refs and needs a base-URI-aware resolver.

```bash
# Python
python3 validate_samples.py

# Node (ajv)
npx ajv-cli validate --spec=draft2020 -s schemas/invite.schema.json -d my_invite.json
```

Edit `generate_schemas.py`, never the schema files directly; regenerate with
`python3 generate_schemas.py schemas`.

## What these schemas validate — and what they cannot

Schemas validate the **decoded JSON payload** (the base64url `payload` member of the
envelope). Signature verification happens against the exact transmitted payload
bytes (11.2) *before* schema validation of the decoded object.

JSON Schema cannot express cross-field, cross-message, or stateful rules. The
following are **semantic checks** that conformant implementations MUST apply after
schema validation — and that the test-vector suite (next artifact) exercises:

1. `expires_at` > `issued_at`; both within the 300 s replay window of receipt (13A.5)
2. `id` ULID timestamp component consistent with signed `issued_at` (glare-backdating guardrail, 13A threat model)
3. Envelope signature valid; signing key resolves to the `from` DID or a valid device delegation (8.4), including `on_behalf_of` delegation on `hello`
4. `session` references a known session; message type valid in current state, else `session.invalid-state` / `session.unknown-session` (13A.4)
5. Registry membership: reason tokens, progress statuses, `answered_by`, policy keys/values, codec/transport/profile identifiers. Schemas validate **shape** (e.g. `category.condition`), registries validate **membership**, and category fallback governs unknown conditions (13C.3.1)
6. One outstanding `update` per session across both directions (13A.4.8)
7. Relay `hello` `in_reply_to` equals the `id` the client actually sent — the anti-splicing check (13B.2.4)
8. Encoded envelope ≤ 65,536 bytes on `ws/1.0` (schema sees decoded JSON and cannot measure this)
9. `answer`/`reject` media selections are subsets of the referenced offer
10. Wire-format payload rules: UTF-8, no floats, integer timestamps (10.3) — partially schema-enforced, fully enforced at parse
11. `info` only in ACTIVE, and `info.data` validated against the binding schema named by `about` (`transport:webrtc` → `webrtc-info-data.schema.json`; unknown `about` → ignored, not rejected); introduction encoded-size cap 4,096 bytes; per-event `expires_in` caps (presence 3,600) answered with `error policy.subscription-lifetime`; grant `session` references a real introduction; anti-enumeration uniform rejects (9.3)
12. `key-rotation`: `from` = `subject`; the signing `kid` = `previous` unless `recovery` is true; `next` ≠ `previous` (7.5). Registry membership with fallback for `publish.integrity` (unknown → `metadata-only`), `provenance.operation`, `key-rotation.reason`

## Design decisions embedded here (flag any you want reversed)

- **Codec entries are objects**, `{"id": "codec:audio/opus", ...params}` — resolving the
  spec's 14.2 (objects) vs 15.3 (bare strings) inconsistency in favor of 14.2. The 15.3
  example in the main document should be updated to match.
- **Open string sets for `answered_by` and `progress.status`** (pattern-validated, not
  closed enums), because both registries define receiver fallback for unknown values
  (`service` / `trying`). Closed enums would make registry growth a breaking schema change.
- **Reason tokens are shape-validated** (`^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$`): legacy
  flat tokens like `timeout` fail at the schema layer; unknown-but-well-formed tokens
  pass and hit category fallback, exactly matching 13C semantics. Extension namespaces
  (e.g. `x-contactcenter.queue-full`) pass the same pattern.
- **`answer` doubles as the renegotiation response** (13A.4.8) via optional
  `in_reply_to` naming the `update` it answers; same on `reject`. Initial
  answer/reject omit it.
- **`answer.transports` requires exactly one entry** — an answer is a selection, not a
  second offer.
- **Illustrative ids in spec prose (`01HZINVITEABC`) are not valid ULIDs** and fail
  validation by design; the harness pins this so prose examples get corrected rather
  than copy-pasted into implementations.
- **`hello` client/relay forms** are enforced conditionally: `in_reply_to` ⇔
  `capabilities` (relay form), otherwise `bindings` required (client form);
  `max_envelope_bytes` is `const: 65536` per the fixed binding constant.
- **`subscribe`/`notify` implement the 9.3 subscription protocol**: mandatory
  `events` + `expires_in` (0 terminates; schema ceiling 86,400 with the tighter
  3,600 presence cap as a semantic check), seq-ordered notifies with a terminal
  state, and optional claims/capability authorization evidence.
- **`info` is ACTIVE-only transport chatter** (semantic check), never critical;
  unknown `about` values pass the schema and are ignored by receivers.
- **`introduction` size cap (4,096 encoded bytes) is a semantic check** — the schema
  enforces the 280-char purpose but cannot measure the encoded envelope.
- **`$id` base `https://dsip.org/schema/1.0/` is a placeholder** pending registry
  governance decisions (spec 24).
