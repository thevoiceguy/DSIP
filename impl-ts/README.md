# dsip-ts — the second implementation

A TypeScript implementation of DSIP, measured against the conformance vectors in `../impl/vectors`.
It exists to test the project's second purpose: that the vector suite, not the Rust code, is the
contract (`../impl/docs/dsip_poc_dev_plan.md`).

**Tracks:** DSIP v0.11. Node ≥ 20. One runtime dependency (`ajv`, JSON Schema 2020-12); Ed25519 is `node:crypto`.

## The independence rule

This code is written from three sources only:

1. the spec text in `../v0.11/`,
2. the JSON Schemas in `../v0.11/` (loaded in place at start-up, never copied),
3. `../impl/vectors/README.md` and the vectors themselves.

It is **never** written by reading `../impl/crates/` or the verdict logic in `../impl/tools/dsipvec/`.
When a vector cannot be passed from those three sources, that is a finding: the README or the spec is
fixed (a `spec-gap` entry when the spec is at fault), not the ignorance. The generator modules
(`dsipvec/gen/`) may be edited to add vectors, since they author expectations by hand from the spec.

`Spec:` / `Impl:` doc-comment lines follow the repository standard (`../CLAUDE.md`).

## Running

```bash
npm ci && npm run build
npm run vectors                          # every vector; unimplemented kinds are reported as skipped
node dist/run-vectors.js --json out.json # results in the parity format (vectors README, "Runner results")
python3 ../impl/tools/parity_ts.py       # Python harness vs this implementation, actual against actual
```

## Coverage

**Every vector: 1924 of 1924**, no kind skipped. Python/TypeScript parity compares actual with actual on all of them.

| Kind | Vectors | Modules |
|---|---|---|
| `envelope`, `transport`, `dht` | 65, 13, 18 | `envelope.ts`, `did.ts`, `encoding.ts`, `dht.ts` |
| `payload`, `semantic` | 104, 83 | `schema.ts`, `semantic.ts`, `registry.ts` |
| `state` | 109 | `endpoint.ts`, `relay.ts`, `broadcast-state.ts`, `timers.ts` |
| `broadcast`, `trust`, `media-binding` | 21, 16, 42 | `broadcast.ts`, `trust.ts`, `binding.ts` |
| `gateway` | 66 | `gateway.ts` |
| `messaging` | 471 | `messaging/`: `message`, `object`, `rules`, `blobs`, `crypto` (stateless); `device`, `sync`, `client`, `hub`, `mailbox` (the nine trace machines) |
| `did-webvh` | 67 | `did/webvh.ts` (log verification, restricted JCS, I-JSON), `encoding.ts` |
| `device-events` | 313 | `events/device-events.ts` (trap translation, syslog table, rule mapping; the alarm-list and escalation machine; inform deduplication; the clear hold-down), `events/syslog.ts` (RFC 5424 / RFC 3164 datagram parsing, syslog rules), `events/usm.ts` (SNMPv3 USM: key localization, BER, the RFC 3414 §3.2 receiver with HMAC-SHA-2 and AES-128-CFB, the engine cache), `events/tsm.ts` (SNMPv3 over TLS: the certificate-to-security-name table, TLS stream framing, the v0.11 DTLS record check — one record is exactly one message, else dropped — and the TSM receiver with RFC 5343 discovery), `events/syslog-sign.ts` (RFC 5848 signed syslog: the collector's held messages and waiting hashes, Certificate Block assembly and reboot sessions, Signature Block groups, v0.11 gap detection; OpenPGP MPIs, DSA verification on BigInt with FIPS 186 digest truncation, the DSA key of a `C` signer's certificate; the key blob types of a Certificate Block payload — `C`, `K`, the OpenPGP `P` key (v0.11: the KeyID and an OpenPGP certificate framed as RFC 4880 packets, its first a v4 DSA Public-Key packet, the KeyID checked against the SHA-1 V4 fingerprint), `N` (no key sent: the configured key) and `U` (refused `unsupported-key-blob`)) |
| `alias-transparency` | 70 | `kt/alias-transparency.ts` (alias normalization, VrfInput, commitments, prefix and log trees, Configuration, tree head, search tree, ladder), `kt/vrf.ts` (ECVRF-EDWARDS25519-SHA512-TAI verify on BigInt Edwards25519 arithmetic; RFC 9381 Examples 16–18 are vectors) |
| `pkarr` | 95 | `dht/pkarr.ts` (Pkarr relay payloads for `did:key` hints: BEP 44 signed buffer, RFC 1035 parsing with backward-only compression pointers, `_dsip` TXT endpoints, z-base-32, §8.3 selection; a node's verify-before-store for `PUT /<z32>` (profile §10); publishing: the records carried over with rdata names expanded per RFC 3597 §4, the next `ts`; §9.1 multi-device identities: the identity-signed `_dsip-devices` pointer, each device's own hint and its `_dsip-delegation` record), `envelope.ts` (Ed25519; the §7.4 delegation verifier with revocations) |
| `recording` | 53 | `recording/recording.ts` (the counterparty's consent machine for calls: disclosure, acceptance per session and recorder, held answer and media, decline by `reject` or `bye`; the recorder device in conversations; the recording party's checks on its recorder leg) |
| `tn-binding` | 318 | `tn/binding.ts`, `tn/x509.ts`, `tn/der.ts` (Number Attestation N§3: compact-JWS ES256 binding, I-JSON, PEM chain, X.509 path to the STI-CA list with the pinned parse rules, strict-DER TNAuthList (RFC 8226, EXPLICIT tags) and coverage, time, DID back-reference, status policy, `attested_by`), `tn/claim.ts` (N§4: a caller's `tel` claim carrying a binding, verified against the envelope's signing identity, the number matched, the attested or `(unverified)` line; N§5: the identity-change warning against the address book, with a UTC date; N§6 route 1: a node's verify-before-store, steps 1–5 then the held set of at most 4, one per DID, with eviction; N§6–N§7: the reader's number → DID choice, newest `iat` winning, and the `others` that signal a port or hijack), `tn/gateway.ts` (the gateway as a relying party: G§5 verification of an inbound `Identity` header, RFC 8224 §8.3 canonical numbers, the SHAKEN PASSporT's shape, `orig` against `From`, `dest`, freshness, `x5u` against `info`, then N§3.4 steps 2–4 with coverage for `A` only; G§3.2/N§6.1 routing of a dialled number, the operator's table before any binding; N§4.1 assertion toward the PSTN: the first attested claim, the gateway's own chain and coverage, the key against the leaf, and an ES256-signed PASSporT at level `A` with RFC 8225 §9 serialization) |

What this is not: a product. It has no transport, no MLS library and no storage — it is the protocol's *decisions*,
which is what the vectors measure. The wire demos in `../impl/demos` remain the Rust implementation's.

## Findings so far

What writing this from the contract alone turned up (stage 1: the verification pipeline).

| # | Finding | Disposition |
|---|---|---|
| 1 | The README never said how `actual` is compared with `expect`. Read as "the members `expect` names", an implementation that raised an extra warning passed. | README "Runner results": deep equality, and the `--json` result format parity tools diff. |
| 2 | §9.3 puts `session.expired` / `policy.terminated` on a terminal `notify`; §15.1 and the §15.4 "valid on" column never mention `notify`. First real three-way divergence. | spec-gap 73. |
| 3 | `payload-shape` was documented as "missing or wrong primitive type"; the suite also expects it for an `id` that is not a ULID (`envelope/payload-prose-ulid`). | README verdict table. |
| 4 | §11.2 does not say what a profile list with one mutual and one unknown profile means; no vector had one. All three implementations turned out to agree (accept). | New vector `semantic/version-known-profile-among-unknown`. |
| 5 | The README has no section for kind `trust` (13 vectors). | Written in stage 3. |

Stage 2 (the state traces):

| # | Finding | Disposition |
|---|---|---|
| 6 | The README's emission-order convention (timer stops → sends → media → ui → timer starts) is not what the suite does in five places (answered-elsewhere cancel after `ui answered`, `ui progress` before the T-Ring/T-Queue adjustment, `missed_call` before `ended`, equal-id glare, screening escalation). | README: the departures are listed as part of the contract. |
| 7 | Undocumented engine behavior the traces expect: `place_call` cites a held grant; `answer_update` sends `answered_by: user`; the token auto-grant's scope and one-year `valid_until`; `refused` and `drop` reasons; relay leg state is `delivered` (README said `alerting`), outcome `cancelled`, `inbox` counts every queued envelope; which snapshots are compared in full. | README event, snapshot and vocabulary tables. |
| 8 | A `grant` goes to the introducing identity, the `reject` of the same introduction to the device. | spec-gap 74 — decided: both to the identity. |
| 9 | §12.5 rule 2 read literally ends a just-answered call when `cancel session.answered-elsewhere` reaches the answering leg. | spec-gap 75. |
| 10 | §12.7 rule 6 has nothing to forward when every leg expired; the suite pinned `endpoint.unavailable` in the first leg's name. | spec-gap 76 — decided: the relay's own `error transport.no-response`. |

Stage 3 (`trust`, `broadcast`, `media-binding`):

| # | Finding | Disposition |
|---|---|---|
| 11 | Kind `trust` compares exact display strings that exist nowhere but in the vectors — §18.1 gives "Domain verified by did:web", the suite expects `Domain verified (<did>)`. | README "Kind: `trust`" now carries every template. |
| 12 | Every verified provenance statement is `integrity_mode: derivative-bound`, a plain `relay` too, while the displayed mode for the same stream is `metadata-only`. | spec-gap 77 — decided: the per-statement field is gone. |
| 13 | §22.3's "any statement where [policy] forbids redistribution" had no vector, and the `policy_violation` tokens were undocumented. | New vector `broadcast/provenance-policy-redistribution-forbidden` (all three agree); README. |
| 14 | The order of the 13 media-binding checks, and that binding traces keep expectations in `expect.steps` (unlike `state`), were unstated. | README. |
| 15 | This implementation first also required a statement's `output_variant` to be advertised — the `state` authority traces pass either way. §22.3 requires only `input_variant`; followed the spec. | Noted as unpinned below. |

Stage 4 (`gateway`):

| # | Finding | Disposition |
|---|---|---|
| 16 | G§4's list of "attempt" tokens names six; Rust and Python use eight. A literal reading sent `bye endpoint.unavailable` mid-call. The second real divergence — found by adding a vector, and the existing set established with probe vectors, not by reading the code. | spec-gap 78; four new vectors. |
| 17 | G§4.2 gives category fallbacks a status but no Q.850 cause, and BYE causes for two rows only; the suite pins both. | spec-gap 79; one new vector. |
| 18 | The gateway's DID (`did:web:gw.example`) is fixed by the suite, not an input; the `downgrade-error` check, the trace states, the local-event vocabulary and the exact `ignore` strings were undocumented. | README, kind `gateway`. |

Stage 5 (`messaging`, the stateless checks):

| # | Finding | Disposition |
|---|---|---|
| 19 | The deposit class field table behind `deposit-fields` is written nowhere. This implementation's table, built from M§5.2's prose, passed every vector and still disagreed with Rust and Python on 7 of 87 class × field combinations — found by a differential probe with temporary vectors. | spec-gap 80; README table; 4 new vectors. |
| 20 | Nine `messaging` checks were missing from the README table (`introduction`, `sealed-introduction-open`, `hpke-open`, `hpke-derive-key-pair`, `x25519-key-agreement`, `blob-put`, `blob-get`, `registration-on-removal`, `hub-outage-trace`), with their codes and check orders. | README. |

**Differential probing** is now a tool: `python3 ../impl/tools/fuzz.py` (random traces and table rows through all three
implementations; CI runs it with a fixed seed and the run's number as a second, a weekly workflow with a fresh one). Its first run found a real bug in
Rust *and* Python (the commit-retry fallback escaped M§6.5's bound of three proposals), the first disagreement between
Rust and Python themselves (glare with two attempts of ours, spec-gap 84), seven wrong readings in this implementation,
and two open protocol questions (spec-gaps 82, 83). When a rule is a table (class × field, token × phase), passing the vectors proves little: generate
every combination as temporary vectors, run all three implementations, and compare `actual` with `actual`. It respects the
independence rule — nothing is read, only observed — and it is how findings 16 and 19 were made. Probes are deleted
afterwards; the disagreements become real vectors.

Stage 6 (`messaging`, the nine trace machines):

| # | Finding | Disposition |
|---|---|---|
| 21 | Passing all 867 vectors was not agreement. Random traces run through all three implementations (180 for the device machines, about 700 for the hub, about 2,400 for the mailbox; Rust and Python never differed from each other) found: the order of a hub's refusals — notably that a re-deposit is answered `duplicate` *before* membership and epoch; that a handover wait holds off everything from the new hub and is judged before numbering; that grant deposits are rate-limited like introductions; push order; and that the §15.3 fallback's one retry is its own. | spec-gap 81; 8 new vectors (874). |
| 22 | The README's mailbox table left out three events (`first_contact`, `forward`, `forward_failed`), two emissions (`handover_expired`, `close`), the `key_packages.devices` map, and the hub's ack-the-head rule. | README. |
| 23 | Deciding spec-gap 82 (a relay routes by `to`) took the relay fuzz target out of quarantine, and its first clean-rules runs split the implementations four more ways: traffic from a device that is not a leg, a `cancel` addressed to one leg's device (this implementation cancelled every leg; §12.11 says one), a leg added in the invite's last second, and the order of simultaneous expiries. | Spec §13.3; ten `state/relay-*` vectors; all three implementations. |
| 24 | Spec-gap 83 (a device starts counting at its welcome's `seq`) reversed a vector: `deposit-welcome-with-seq-refused` pinned the reading the decision rejects, and became `deposit-welcome-with-seq-valid`. This implementation also did not treat an external-commit re-join as a join, so a late welcome for the group was processed twice. | M§5.2, M§6.5; `resume-*` vectors incl. `resume-rejoin-is-a-join`. |
| 25 | The gateway checks (`passport`, `route`, `assert`), written from the README alone, passed every vector and still left five readings to the implementer: where a parameter value starts when it holds `=`, a trailing `;`, the case of `alg`/`ppt` values, an empty `info` URI, and whether a SEC1 `EC PRIVATE KEY` PEM is "a PKCS#8 PEM" (the Python reference would have read it). | README text; five `passport-*`/`assert-*` vectors; the Python reference fixed (spec-gap 110 I). |

Readings this implementation makes that no vector pins yet (found by mutating the code and seeing the suite stay green):

- A delegation *presented* in the protected header that links a different device/identity pair is
  `delegation-invalid`; one merely held in the verifier's store is ignored (`src/envelope.ts`, `bind`).
- Order of version failures when several hold at once: core → profile → critical extension.
- A provenance statement whose `output_variant` the publication does not advertise is accepted (§22.3 constrains only `input_variant`).
- Category-fallback causes for `identity`, `session`, `media`, `policy`, `transport`, `gateway` (only `user` and `endpoint` are pinned).
- In a handover wait, the seqs reported `missing` are counted from the lowest seq the mailbox has stored (from 1 when it
  has none); the random mailbox traces never told this apart from any other baseline.
- The `trust` basis for a `tel` claim whose verifier is not a `did:web` shows the verifier DID as is.
- Signed syslog (`src/events/syslog-sign.ts`): a Certificate Block repeats the established payload only with the same
  TPBL; FLEN counts the unescaped value bytes; the payload's timestamp is any non-empty field. A `P` key's OpenPGP
  certificate is framed as a whole (every packet header read and fitting the bytes, an indeterminate or partial
  length anywhere failing it) while only the first packet's contents are examined; a Public-Key body over 65,535
  bytes does not read.
