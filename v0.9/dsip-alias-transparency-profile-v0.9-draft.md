# Draft: DSIP Alias Transparency Profile (`alias-transparency/0.1`)

**Status:** DRAFT, companion profile to DSIP v0.9. Cite as `T§n`. Decided 2026-10-04 (`impl/docs/v0.9-research.md`
track A, item 3): a KEYTRANS-shaped log with VRF-blinded labels, written as a DSIP profile that tracks the IETF draft.
**Staged:** KEYTRANS's lookup-proof format is changing between draft-ietf-keytrans-protocol-05 and its successor.
This revision therefore makes normative the profile choices and the cryptographic building blocks, following the
editors' copy of 2026-09-16 (what -06 is expected to publish). They match -05 except the mode-1 Configuration, which
no longer carries a `leaf_public_key`; the editors removed it on 2026-07-28 (spec-gap 104). They also match the
editor's reference implementation, katie (commit `e1640671`). Lookup verification, owner monitoring and fork detection (T§6) follow when
-06 is published. Conformance: the `alias-transparency/` vectors.

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
  clients at a new log. Pinning and owner monitoring (T§6) make that detectable.

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

- **Lookup:** greatest-version search (`[KT]` §6, §13.1), verified offline from a `SearchResponse`.
  - An alias version whose terminal entry lies right of the rightmost distinguished entry is **pending**. It MUST NOT
    be used as authority until a distinguished entry covers it. `[KTA]` §7.1 permits this restriction, and it spares
    callers from contact monitoring.
  - A verified result is the alias tier of §8.1. A pending or unverifiable one gets the unverified-alias treatment.
    The DID document stays authoritative for keys and endpoints.
- **Owner monitoring:** the DID holder's endpoint (`[KT]` §8.3, §9.1). It authenticates to the provider with a DSIP
  envelope signed by the bound DID.
- **Fork detection:** distinguished tree heads (`[KT]` §10) exchanged peer-to-peer in DSIP signaling, as an optional
  field, so a provider showing different logs to different users is caught.
- **Anti-enumeration at the query endpoint:** the VRF hides aliases in the log, not at the provider's search
  endpoint. A provider MUST answer "no such alias" and "not permitted" identically and rate-limit queries, in the
  spirit of §19.4.
- **Credentials** (`[KT]` §14) in introductions, so a callee need not query the caller's provider. Planned for
  v1.0.
