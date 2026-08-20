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
  dsip-transport ws/1.0 client binding (wss, hello, caps, reconnect), identity dirs, did:web fetch, the Agent
  dsip-relay    `dsip-relay` binary: wss listener, hello binding, routing, per-leg forking
  dsip-cli      `dsip` binary: keygen, sign, verify, vectors run, identity, resolve, call, answer
demos/          phase1-demo.sh
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

# Phase 1 demo (relay + two identities + scripted call; or run the pieces by hand)
demos/phase1-demo.sh
dsip-relay --listen 127.0.0.1:8443 --state .relay          # prints the self-signed cert path
dsip identity init --dir ./alice --name Alice
dsip identity init --dir ./bob --name Bob
dsip identity init --dir ./bob-laptop --controller-from ./bob   # second device, same identity
dsip answer --identity ./bob --ca .relay/cert.pem              # interactive: accept | screen | decline | escalate …
dsip call   --identity ./alice --ca .relay/cert.pem --to <bob identity did>   # interactive: update | info | hangup …
dsip resolve did:web:example.com
```

## Status

| Milestone | Status |
|---|---|
| M0 vector suite + Rust/Python parity | ✅ 232 vectors, both runners green |
| WS-1 `dsip-core` | ✅ |
| WS-2 `dsip-schema` | ✅ (build-time freshness check vs `generate_schemas.py`) |
| WS-3 `dsip-session` | ✅ every §12.4–§12.10 transition row covered by a trace |
| WS-4 `dsip-transport` + `dsip-relay` | ✅ wss-only `ws/1.0`, `hello` binding, size cap, reconnection; relay forks per-leg with attempt outcomes |
| WS-5 CLI `call`/`answer` demo | ✅ `demos/phase1-demo.sh` — screened + escalated call, forked call with no missed call |
| M1 Phase 1 | ✅ |
| Phase 2 (WASM, browser, media, first contact), WS-D (DHT hints), Phase 3 | not started |
