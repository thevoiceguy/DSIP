# DSIP reference implementation (PoC)

**Tracks:** DSIP Draft v0.6 + JSON Schema set v0.6. Plan: `docs/dsip_poc_dev_plan.md`.
**Conformance contract:** `vectors/` (see `vectors/README.md`). Spec-gap issue drafts: `docs/spec-gaps.md`.

## Layout

```
vectors/        Language-neutral conformance vectors (generated; committed)
tools/          Python: vector generator, reference harness, parity, spec lint
schemas/        Implementation-local schemas (DHT reachability hint)
crates/
  dsip-core     ULIDs, did:key, DID documents, Ed25519, DSIP-JOSE envelope pipeline
  dsip-schema   v0.6 schemas embedded at build time + stateless semantic checks
  dsip-session  §12 endpoint state engine, timers, races, renegotiation; §12.7 relay leg tracker
  dsip-cli      `dsip` binary: keygen, sign, verify, vectors run
docs/           Plan, spec gaps, generated coverage cross-index
```

Verification order is crate order: a payload reaching `dsip-session` has
already passed `dsip-core` (signature, binding, replay, wire format) and
`dsip-schema` (shape, version, stateless semantics).

## Quick start

```bash
# Python side (needs: jsonschema, pynacl)
python3 tools/generate_vectors.py          # regenerate vectors (deterministic)
python3 tools/run_vectors.py               # Python verdicts vs expect

# Rust side (run from impl/)
cargo build --workspace
cargo test --workspace
cargo run -q -p dsip-cli -- vectors run    # Rust verdicts vs expect
python3 tools/parity.py                    # diff Rust vs Python verdict by verdict

# Traceability
python3 tools/spec_lint.py                 # Spec: lint + docs/coverage.md
cargo doc --workspace --no-deps --open
```

## CLI

```bash
dsip keygen --out alice.key                # new did:key device key
dsip keygen --fixture alice-phone          # vector fixture key (deterministic)
dsip sign --key alice.key payload.json > env.json
dsip verify env.json [--now T] [--delegation d.json]... [--did-documents docs.json]
dsip vectors run [--only state/] [--json out.json] [-v]
```

## Status

| Milestone | Status |
|---|---|
| M0 vector suite + Rust/Python parity | ✅ 232 vectors, both runners green |
| WS-1 `dsip-core` | ✅ |
| WS-2 `dsip-schema` | ✅ (build-time freshness check vs `generate_schemas.py`) |
| WS-3 `dsip-session` | ✅ every §12.4–§12.10 transition row covered by a trace |
| WS-4 `dsip-transport` + loopback relay | in progress |
| WS-5 CLI `call`/`answer` demo | in progress |
