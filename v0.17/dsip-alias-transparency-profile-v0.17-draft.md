# Draft: DSIP Alias Transparency Profile (`alias-transparency/0.1`)

**Status:** DRAFT, companion profile to DSIP v0.17. Cite as `T§n`. Decided 2026-10-04 (`impl/docs/v0.9-research.md`
track A, item 3): a KEYTRANS-shaped log with VRF-blinded labels, written as a DSIP profile that tracks the IETF draft.
**Staged:** KEYTRANS's lookup-proof format is changing between draft-ietf-keytrans-protocol-05 and its successor.
This revision therefore makes normative the profile choices and the cryptographic building blocks, following the
editors' copy of 2026-09-16 (what -06 is expected to publish). They match -05 except the mode-1 Configuration, which
no longer carries a `leaf_public_key`; the editors removed it on 2026-07-28 (spec-gap 104). They also match the
editor's reference implementation, katie (commit `e1640671`). v0.14 adds the DSIP side of lookup, monitoring and fork
detection, which does not depend on KEYTRANS's proof bytes (T§7–T§10, spec-gap 124): the query endpoint, how an owner
authenticates to monitor, tree heads exchanged between peers, and what a lookup result counts as. Verifying the
proofs themselves (T§6) follows when -06 is published. Conformance: the `alias-transparency/` vectors.

## T§1 Purpose

An alias (§8.2) such as `alice@example.com` resolves to a DID through the alias provider, `example.com`. The provider
is trusted for availability. Without this profile it is also trusted for *correctness*: it could answer a different
DID for Alice, to everyone or only to one caller, and neither Alice nor the caller would know.

This profile makes those answers **auditable**. The provider keeps an append-only log. A client accepts an alias only
with a proof that the answer is the one in the log everyone sees. The alias owner monitors its own entry. Aliases in
the log are blinded, so the log cannot be used to enumerate the provider's users.

## T§2 Relationship to KEYTRANS

The profile uses the KEYTRANS protocol's structures and computations byte for byte
(draft-ietf-keytrans-protocol, `[KT]`; architecture, `[KTA]`). Where a KEYTRANS structure appears, its TLS
presentation-language encoding (`[KT]` §2.1) is the encoding, and KEYTRANS messages are carried as those raw bytes.
They are never re-wrapped in a DSIP envelope, so any KEYTRANS implementation can verify them. DSIP adds only the
choices below.

- **Cipher suite:** `KT_128_SHA256_Ed25519` (`0x0002`) only. That means SHA-256, Ed25519 signatures, and
  ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) with its output truncated to 32 bytes. VRF verification uses
  `validate_key = TRUE` (RFC 9381 §5.3). Impl (spec-gap 104): KEYTRANS states no `validate_key` choice.
- **Deployment mode:** `contactMonitoring` (`1`) only. A configuration with another mode is refused.
- **Label:** the alias, normalized (T§3), as UTF-8 bytes, at most 255 of them.
- **Value:** the DID, as UTF-8 bytes. A future revision may wrap it in a DSIP-typed structure.

## T§3 Alias normalization

An alias is `local@domain`, split at its last `@`. It normalizes as follows:

- **local:** one or more printable ASCII characters (U+0021–U+007E), with no `@`. Case is preserved, as in e-mail
  (RFC 5321 §2.4).
- **domain:** at least two labels, each 1–63 characters of `[A-Za-z0-9-]` that neither begin nor end with `-`,
  joined by `.`, then lowercased. An IDN
  must be given in its A-label (`xn--`) form. A client converts a U-label domain before normalizing; implementations
  differ in how (IDNA2003 versus UTS 46), so the conversion is outside this profile.
- The result is `local@domain`, and must be at most 255 bytes.

**A `tel:` alias** (v0.12; the Number Attestation Profile's route 2, N§6) is a tel URI (RFC 3966) of a global number
with no parameters: the scheme `tel:` in any case, `+`, then digits with the visual separators `-`, `.`, `(` and `)`
removed. The digits are E.164 (2 to 15, the first not `0`). The label is `tel:+<digits>`, in lowercase; a local
number, a parameter (`;ext=`, `;phone-context=`) or anything else is not an alias in this draft.

Anything else is not an alias.

Impl (spec-gap 104): §8.1 step 1 says identifiers are normalized but not how; this is the normalization for aliases.
Internationalized local parts (RFC 6531) are deferred, because Unicode normalization tables differ across
implementations.

## T§4 Discovery and trust of a provider's log

KEYTRANS requires the log's `Configuration` (`[KT]` §11.2), which holds the cipher suite, mode, public keys and timing
parameters, to reach users "through a trustworthy channel" (`[KTA]` §2), without saying which. In DSIP it comes from
the provider's DID document. The provider of `alice@example.com` is `did:web:example.com`, and its document carries:

```json
{"id": "#alias-log", "type": "DSIPAliasLog",
 "serviceEndpoint": {"uri": "https://example.com/.well-known/dsip-alias-log", "configuration": "<base64url of the TLS-encoded Configuration>"}}
```

- The Configuration's `signature_public_key` MUST be the raw Ed25519 public key of one of that DID document's
  verification methods. Tree heads are therefore signed by the provider's own identity key, under KEYTRANS's
  signature (`TreeHeadTBS`), not a second, DSIP one.
- A client pins the Configuration on first use. A different Configuration later is a different log, handled as
  `[KTA]` §5.2 log migration, never a silent replacement.
- This rests on `did:web`, which rests on the Web PKI (§8.4): a provider who can rewrite its DID document can point
  clients at a new log. Pinning and owner monitoring (T§8, with its proofs in T§6) make that detectable.

## T§5 The building blocks (normative now)

All values are as `[KT]` defines them. Their exact byte layouts are in the vectors README, kind `alias-transparency`.

1. **VRF input:** `VrfInput { opaque label<0..2^8-1>; uint32 version; }`.
2. **Index:** the first 32 bytes of `ECVRF_proof_to_hash` of a proof that verifies under the log's VRF key for that
   input. A proof that does not verify gives no index.
3. **Commitment:** `HMAC-SHA256(Kc, CommitmentValue)`, where:
   - `CommitmentValue = { opaque opening[16]; opaque label<0..2^8-1>; uint32 version; UpdateValue update; }`;
   - `UpdateValue = { opaque value<0..2^32-1>; }`, with an empty suffix in mode 1;
   - `Kc` is the 16 bytes `d821f8790d97709796b4d7903357c3f5`.
4. **Prefix tree:** a leaf is `SHA-256(0x02 ‖ index ‖ commitment)`, and a parent is
   `SHA-256(0x03 ‖ left ‖ right)`, with an absent child as 32 zero bytes.
5. **Log tree:** a left-balanced binary tree of SHA-256.
   - A leaf's value is `SHA-256(LogEntry)`, where `LogEntry = { uint64 timestamp; opaque prefix_tree[32]; }` and
     the timestamp is in milliseconds.
   - A parent's value is `SHA-256(hashContent(left) ‖ hashContent(right))`, where `hashContent` is `0x00 ‖ value`
     for a leaf and `0x01 ‖ value` for a parent.
6. **Configuration** (`[KT]` §11.2, editors' copy), for mode 1. Its fields, in order:
   - `uint16 ciphersuite`;
   - `uint8 mode`;
   - `opaque signature_public_key<0..2^16-1>`;
   - `opaque vrf_public_key<0..2^16-1>`;
   - `uint64 max_ahead`, `uint64 max_behind`, `uint64 reasonable_monitoring_window`;
   - `optional<uint64> maximum_lifetime`.
7. **Tree head:** `TreeHead { uint64 tree_size; opaque signature<0..2^16-1>; }`, an Ed25519 signature over
   `TreeHeadTBS { Configuration config; uint64 tree_size; opaque root[32]; }`.
8. **The implicit binary search tree and the binary ladder** (`[KT]` Appendix A, B): `root(n)`, the frontier, and the
   base ladder for a version.

## T§6 Staged for the next revision (after KEYTRANS -06)

What still waits for KEYTRANS's proof format. Each item is verified offline from KEYTRANS bytes:

- **Lookup proof:** greatest-version search (`[KT]` §6, §13.1), verified from a `SearchResponse`. Its result feeds
  T§10: whether the proof verified, the version's terminal entry and the rightmost distinguished entry.
- **Monitoring proof:** the owner's `MonitorResponse` (`[KT]` §8.3, §9.1), sent once T§8 admits the owner.
- **Consistency between tree heads of different sizes** (`[KT]` §10), so a head received from a peer (T§9) is checked
  against the client's own heads of other sizes, not only one of the same size.
- **Credentials** (`[KT]` §14) in introductions, so a callee need not query the caller's provider. Planned for
  v1.0.

## T§7 The query endpoint (v0.14, spec-gap 124)

The `DSIPAliasLog` endpoint's `uri` (T§4) takes KEYTRANS requests by HTTPS `POST`, the request's TLS bytes as the body
(T§2). A provider answers in this order, pinned by `check: "alias-query"`:

1. **Rate limit.** Every query counts against the requester's budget, whether the alias exists or not. Over budget,
   the answer is `429` (`rate-limited`). The budget is the provider's choice, in the spirit of §19.4's introduction
   budget. Counting before anything else means the limit reveals nothing about which aliases exist.
2. **A request that is neither a search nor a monitor** is answered `400` (`bad-request`).
3. **An alias that does not normalize** (T§3) is answered `400` (`alias-invalid`). Syntax reveals nothing about
   existence.
4. **A search** for an alias that is in the log and that the provider lets this requester see is answered `200` with
   the search response. Any other search is answered `404` (`not-found`).
5. **A monitor request** for an alias in the log, authorized by T§8, is answered `200` with the monitor response. Any
   other monitor request, whatever T§8 refused, is answered `404` (`not-found`).

**One not-found.** An absent alias, one the requester may not see, and a monitor request from someone who is not its
owner get the same answer: status `404`, the same headers, an empty body. A provider MUST NOT answer a search with
KEYTRANS's proof of absence, since that would tell an absent alias from a hidden one. It SHOULD take the same time
for each. The VRF hides aliases in the log (T§2); this rule hides them at the endpoint.

## T§8 Owner monitoring (v0.14, spec-gap 124)

An alias's owner proves who it is with an `alias-monitor` message, sent as `Authorization: DSIP <compact envelope>` on
the monitor `POST`, as `blob-put` is (M§5.6). The body stays the raw KEYTRANS request: the DSIP message authorizes it,
and never wraps it (T§2).

```json
{"dsip": {…}, "type": "alias-monitor", "id": "01J…", "from": "did:web:alice.example", "to": "did:web:example.com",
 "issued_at": 1790000000, "expires_at": 1790000060, "alias": "alice@example.com"}
```

- The envelope is verified like any DSIP message (§10.2): the signature over the bytes, the delegation when a device
  signs, the replay window, the schema (`alias-monitor.schema.json`). `from` is the identity (§10.2).
- **Who may monitor:** an identity that is, or was, the value of some version of the alias. A former owner keeps the
  right, so an owner whose alias was rebound to another DID can still see the rebinding, which is the case
  monitoring exists for.
- The provider's checks after verification, in order, pinned by `check: "alias-monitor"`: `to` is not the provider
  (`wrong-audience`); the alias does not normalize (`alias-invalid`); `from` has never been the alias's value
  (`not-owner`). Every refusal is answered `not-found` (T§7).

## T§9 Fork detection: tree heads between peers (v0.14, spec-gap 124)

A provider that shows different logs to different users is caught when two of them compare signed tree heads. DSIP
carries a head as a claim in `identity.claims` of an `invite` or `introduction` (§17, the claims list where N§4's
number claims ride), so no core schema changes:

```json
{"type": "alias-log-head", "provider": "did:web:example.com", "tree_head": "<base64url of the TLS-encoded TreeHead>",
 "root": "<base64url of the 32-byte root>"}
```

- A sender MAY include heads of logs it holds, its own provider's at least. `tree_head` is KEYTRANS's `TreeHead`, raw
  (T§2); `root` is the log root it was signed over, which a `TreeHead` does not carry.
- A receiver that does not know the claim type ignores it, like any unknown claim. One that does checks it, in order,
  pinned by `check: "alias-head"`:
  1. a claim that does not parse (a field missing or not base64url, a `TreeHead` with trailing bytes, a root that is
     not 32 bytes) is `invalid` (`malformed`);
  2. a log whose Configuration the receiver has not pinned (T§4) is `ignored` (`unknown-log`): it has nothing to check
     against;
  3. a signature that does not verify over `TreeHeadTBS` (T§5 item 7) is `invalid` (`bad-signature`);
  4. a head of a size the receiver holds, with a different root, is a **`fork`**;
  5. the same size and root is `consistent`;
  6. any other size is `new`: the receiver keeps it. Checking it against heads of other sizes needs KEYTRANS's
     consistency proofs (T§6).
- **A fork is proof.** Two heads of one size with different roots, both signed by the provider's own key, show that
  it served different logs. The receiver keeps both, treats every answer from that log as unaudited (T§10), and
  SHOULD show the user the evidence.

## T§10 What a lookup result counts as (v0.14, spec-gap 124)

A client resolving an alias (§8.1 step 3) classifies the result, pinned by `check: "alias-lookup-result"`:

1. **`not-found`:** the endpoint answered `not-found` (T§7). The alias resolves to nothing.
2. **`unaudited` (`fork`):** a fork is known for that log (T§9).
3. **`unaudited` (`unverifiable`):** the lookup proof did not verify (T§6).
4. **`unaudited` (`pending`):** the version's terminal entry lies right of the rightmost distinguished entry, or no
   entry is distinguished yet. `[KTA]` §7.1 permits this restriction, and it spares callers from contact monitoring.
5. **`audited`:** otherwise.

- An `audited` alias is the alias tier of §8.1 with this profile's assurance: the answer is the one in the log
  everyone sees.
- An `unaudited` one is what an alias is without this profile: the provider's word. A client MUST NOT present it as
  verified, and SHOULD look it up again once a distinguished entry covers it.
- Either way the DID is what the alias resolves to. The DID document stays authoritative for keys and endpoints
  (§8.1 step 4), and this profile never overrides it.
