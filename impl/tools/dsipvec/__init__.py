"""dsipvec — Python reference semantics for the DSIP v0.6 conformance vectors.

This package is the *Python side* of the Rust/Python parity contract described
in `impl/docs/dsip_poc_dev_plan.md` §5. It contains:

- deterministic fixtures (keys, DIDs, delegations),
- the envelope verification pipeline (`envelope.py`),
- schema validation and stateless semantic checks (`schema.py`, `semantic.py`),
- the §12 endpoint state engine and §12.7 relay attempt tracker (`session.py`, `relay.py`),
- vector generators (`gen/`), and the harness (`harness.py`).

Nothing here is the implementation of record; the Rust crates are. This code
exists so a vector bug and an implementation bug cannot hide behind each other.
"""

FORMAT_VERSION = 1
SPEC_VERSION = "0.6"
