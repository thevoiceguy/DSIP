# dsip-ts — the second implementation

A TypeScript implementation of DSIP, measured against the conformance vectors in `../impl/vectors`.
It exists to test the project's second purpose: that the vector suite, not the Rust code, is the
contract (`../impl/docs/dsip_poc_dev_plan.md`).

**Tracks:** DSIP v0.8. Node ≥ 20. One runtime dependency (`ajv`, JSON Schema 2020-12); Ed25519 is `node:crypto`.

## The independence rule

This code is written from three sources only:

1. the spec text in `../v0.8/`,
2. the JSON Schemas in `../v0.8/` (loaded in place at start-up, never copied),
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

| Kind | Vectors | Status |
|---|---|---|
| `envelope` | 65 | pass |
| `transport` | 13 | pass |
| `dht` | 12 | pass |
| `payload` | 97 | pass |
| `semantic` | 50 | pass |
| `state` | 82 | pass — `endpoint` 59, `relay` 14, `authority` 7, `subscriber` 2 |
| `broadcast` | 21 | pass |
| `media-binding` | 42 | pass |
| `trust` | 13 | pass |
| `gateway` | 64 | pass |
| `messaging`, stateless checks | 226 | pass — messages, objects, client rules, blobs, MLS encoding and credentials, AES-GCM sealing, HPKE |
| `messaging`, traces | 181 | not yet implemented — mailbox 71, hub 32, client 23, resume 12, commit-retry 11, history 11, successor 9, hub-outage 6, gap 6 |

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
| 8 | A `grant` goes to the introducing identity, the `reject` of the same introduction to the device. | spec-gap 74. |
| 9 | §12.5 rule 2 read literally ends a just-answered call when `cancel session.answered-elsewhere` reaches the answering leg. | spec-gap 75. |
| 10 | §12.7 rule 6 has nothing to forward when every leg expired; the suite pins `endpoint.unavailable` in the first leg's name. | spec-gap 76. |

Stage 3 (`trust`, `broadcast`, `media-binding`):

| # | Finding | Disposition |
|---|---|---|
| 11 | Kind `trust` compares exact display strings that exist nowhere but in the vectors — §18.1 gives "Domain verified by did:web", the suite expects `Domain verified (<did>)`. | README "Kind: `trust`" now carries every template. |
| 12 | Every verified provenance statement is `integrity_mode: derivative-bound`, a plain `relay` too, while the displayed mode for the same stream is `metadata-only`. | spec-gap 77. |
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

**Differential probing.** When a rule is a table (class × field, token × phase), passing the vectors proves little: generate
every combination as temporary vectors, run all three implementations, and compare `actual` with `actual`. It respects the
independence rule — nothing is read, only observed — and it is how findings 16 and 19 were made. Probes are deleted
afterwards; the disagreements become real vectors.

Readings this implementation makes that no vector pins yet (found by mutating the code and seeing the suite stay green):

- A delegation *presented* in the protected header that links a different device/identity pair is
  `delegation-invalid`; one merely held in the verifier's store is ignored (`src/envelope.ts`, `bind`).
- Order of version failures when several hold at once: core → profile → critical extension.
- A provenance statement whose `output_variant` the publication does not advertise is accepted (§22.3 constrains only `input_variant`).
- Category-fallback causes for `identity`, `session`, `media`, `policy`, `transport`, `gateway` (only `user` and `endpoint` are pinned).
- The `trust` basis for a `tel` claim whose verifier is not a `did:web` shows the verifier DID as is.
