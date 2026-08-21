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
  dsip-endpoint IO-free endpoint core: verify → §12 engine → build/sign (shared by native agent and WASM)
  dsip-transport ws/1.0 client binding (wss, hello, caps, reconnect), identity dirs, did:web fetch, the Agent
  dsip-wasm     the same verifier/engine/builder for the browser (wasm-bindgen); built into demos/browser/pkg
  dsip-dht      reachability hints over libp2p Kademlia (experimental §8.5); `dsip-dht-node` binary
  dsip-relay    `dsip-relay` binary: wss listener, hello binding, routing, per-leg forking
  dsip-cli      `dsip` binary: keygen, sign, verify, vectors run, identity, resolve, call, answer
demos/          phase1-demo.sh, dht-demo.sh, first-contact-demo.sh, browser-demo.sh + browser/ (page, WASM pkg, Node test)
docs/           Plan, spec gaps, coverage cross-index, DHT findings + draft hints profile
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

# Workstream D: hints tier (never authoritative)
demos/dht-demo.sh                                          # 3 DHT nodes + relay; call discovered via hint only
dsip-dht-node --listen /ip4/127.0.0.1/tcp/4001 --control 127.0.0.1:4101       # prints listening: /ip4/…/p2p/<PeerId>
dsip answer --identity ./bob --ca .relay/cert.pem --dht <bootstrap> --publish-hint
dsip resolve <bob did:key> --dht <bootstrap>
dsip call --identity ./alice --ca .relay/cert.pem --dht <bootstrap> --to <bob did:key>   # no --relay: taken from the hint
python3 tools/dht_testnet.py --nodes 12                    # integration harness → docs/dht-testnet-report*.json

# Phase 2: first contact (§19.4)
demos/first-contact-demo.sh
dsip answer --identity ./bob --ca .relay/cert.pem --first-contact [--token T]   # ungranted invites → policy.first-contact-required
#   commands: requests | grant [intro-id] | reject-intro [intro-id] | revoke <grant-id> | token <t>
dsip introduce --identity ./carol --ca .relay/cert.pem --to <bob did> --purpose "…" [--token T] [--wait 30]
dsip call --identity ./carol --ca .relay/cert.pem --to <bob did>     # a held grant is attached automatically (contacts.json)
dsip-relay --intro-limit 5 --intro-window 3600 --inbox-cap 100       # §19.4 rate limits; introductions to unknown/offline identities are queued, never errored

# Phase 2: browser endpoint (needs `rustup target add wasm32-unknown-unknown` + `cargo install wasm-pack`)
demos/browser/build.sh          # wasm-pack → demos/browser/pkg
node demos/browser/test.mjs     # two WASM endpoints run a full call + first contact in memory
demos/browser-demo.sh           # relay serves https://127.0.0.1:8443/?as=alice and ?as=bob (accept the self-signed cert once)
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
| WS-D `dsip-dht` + testnet harness + no-DNS call demo | ✅ `docs/dht-findings.md`, `docs/dht-hints-profile.md` |
| Phase 2 — first contact (introduction/grant, allowlist, tokens, relay rate limit + anti-enumeration inbox) | ✅ 9 new traces, `demos/first-contact-demo.sh` |
| Phase 2 — `dsip-endpoint` + `dsip-wasm` + browser demo (WebRTC audio/video, screening, update, first contact, identity display) | ✅ WASM engine tested under Node; media path needs a real browser (`demos/browser-demo.sh`) |
| Phase 2 — `webrtc-rs` native media endpoint, full relay store-and-forward; Phase 3 | not started |
