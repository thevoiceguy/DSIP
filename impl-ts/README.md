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
| `state`, `broadcast`, `media-binding`, `gateway`, `trust`, `messaging` | 619 | not yet implemented |

## Findings so far

What writing this from the contract alone turned up (stage 1: the verification pipeline).

| # | Finding | Disposition |
|---|---|---|
| 1 | The README never said how `actual` is compared with `expect`. Read as "the members `expect` names", an implementation that raised an extra warning passed. | README "Runner results": deep equality, and the `--json` result format parity tools diff. |
| 2 | §9.3 puts `session.expired` / `policy.terminated` on a terminal `notify`; §15.1 and the §15.4 "valid on" column never mention `notify`. First real three-way divergence. | spec-gap 73. |
| 3 | `payload-shape` was documented as "missing or wrong primitive type"; the suite also expects it for an `id` that is not a ULID (`envelope/payload-prose-ulid`). | README verdict table. |
| 4 | §11.2 does not say what a profile list with one mutual and one unknown profile means; no vector had one. All three implementations turned out to agree (accept). | New vector `semantic/version-known-profile-among-unknown`. |
| 5 | The README has no section for kind `trust` (13 vectors). | Open — to be written when `trust` is implemented here. |

Readings this implementation makes that no vector pins yet (found by mutating the code and seeing the suite stay green):

- A delegation *presented* in the protected header that links a different device/identity pair is
  `delegation-invalid`; one merely held in the verifier's store is ignored (`src/envelope.ts`, `bind`).
- Order of version failures when several hold at once: core → profile → critical extension.
