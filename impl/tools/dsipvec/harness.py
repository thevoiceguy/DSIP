"""Run vectors through the Python reference semantics and compare with `expect`."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from jsonschema import Draft202012Validator

from . import envelope as E
from . import semantic as SEM
from .crypto import b64url_decode
from .session import Endpoint
from .relay import Relay
from .verdict import Verdict

IMPL_ROOT = Path(__file__).resolve().parents[2]
VECTOR_DIR = IMPL_ROOT / "vectors"
HINT_SCHEMA = IMPL_ROOT / "schemas" / "reachability-hint.schema.json"


@dataclass
class Result:
    vector: str
    ok: bool
    expected: object
    actual: object
    note: str = ""
    steps: list = field(default_factory=list)


def load_vectors(root: Path = VECTOR_DIR, only: str | None = None) -> list[dict]:
    out = []
    for p in sorted(root.rglob("*.json")):
        if p.name == "fixtures.json":
            continue
        v = json.loads(p.read_text())
        if only and not v["vector"].startswith(only):
            continue
        out.append(v)
    return out


# ---------------------------------------------------------------- per-kind runners

def run_envelope_like(v: dict) -> dict:
    ctx = E.Context.from_vector(v["context"])
    frame_text = v["input"].get("frame")
    verdict, ver = E.verify(v["input"]["envelope"], ctx, frame_text)
    if not verdict.ok:
        return verdict.to_expect()
    p = ver.payload
    # ws/1.0 binding state (§13.2): nothing but hello before a verified hello
    if v["context"].get("hello_verified") is False and p["type"] != "hello":
        return Verdict.reject("hello-required", "transport.hello-required").to_expect()
    size = len((frame_text or E.frame(v["input"]["envelope"])).encode("utf-8"))
    if v["kind"] == "dht":
        return run_dht_tail(v, verdict, ver)
    pv = SEM.check_payload(p, v["context"], encoded_size=size)
    if not pv.ok:
        return pv.to_expect()
    out = verdict.to_expect()
    out.update(pv.extra)
    return out


def run_payload(v: dict) -> dict:
    from .schema import schema_errors
    errs = schema_errors(v["input"]["schema"], v["input"]["payload"])
    return Verdict.reject("schema-invalid", detail=errs[0] if errs else None).to_expect() if errs else Verdict.accept().to_expect()


def run_semantic(v: dict) -> dict:
    return SEM.check_payload(v["input"]["payload"], v["context"]).to_expect()


_hint_validator = None


def hint_validator() -> Draft202012Validator:
    global _hint_validator
    if _hint_validator is None:
        _hint_validator = Draft202012Validator(json.loads(HINT_SCHEMA.read_text()))
    return _hint_validator


def run_dht_tail(v: dict, verdict: Verdict, ver) -> dict:
    p = ver.payload
    ctx = v["context"]
    # A hint binds to its subject: whoever signed must be (or be delegated by) the subject.
    if verdict.extra.get("identity") != p.get("subject"):
        return Verdict.reject("hint-subject-mismatch").to_expect()
    vv = SEM.check_version(p, ctx.get("supported") or {})
    if not vv.ok:
        return vv.to_expect()
    if list(hint_validator().iter_errors(p)):
        return Verdict.reject("schema-invalid").to_expect()
    out = verdict.to_expect()
    existing = ctx.get("existing")
    winner, conflict = "input", "none"
    if existing is not None:
        ex = json.loads(b64url_decode(existing["payload"]).decode("utf-8"))
        if ex.get("expires_at", 0) < ctx["now"]:
            winner, conflict = "input", "none"          # §8.3: expired records are invalid
        elif p["seq"] > ex["seq"]:
            winner, conflict = "input", "newer-seq"      # §8.3: newer sequence wins
        elif p["seq"] < ex["seq"]:
            winner, conflict = "existing", "older-seq"
        elif existing["payload"] == v["input"]["envelope"]["payload"]:
            winner, conflict = "existing", "none"        # identical record
        else:
            winner, conflict = "existing", "same-seq-live"  # §8.3: conflicting live records → warn
    out.update(winner=winner, conflict=conflict)
    return out


def run_state(v: dict) -> tuple[bool, list]:
    ctx = v["context"]
    comp = Relay(ctx) if ctx.get("component") == "relay" else Endpoint(ctx)
    key = "attempts" if ctx.get("component") == "relay" else "sessions"
    results, ok = [], True
    for i, st in enumerate(v["input"]["steps"]):
        emit = comp.step(st["event"])
        exp = st["expect"]
        snap = comp.snapshot(exp.get(key, {}).keys())
        actual = {"emit": emit, key: snap}
        if "contacts" in exp:
            actual["contacts"] = comp.contacts_snapshot()
        if "inbox" in exp:
            actual["inbox"] = comp.inbox_snapshot()
        step_ok = all(actual.get(k) == exp.get(k) for k in ("emit", key, "contacts", "inbox") if k in exp or k == "emit")
        ok = ok and step_ok
        results.append({"step": i, "ok": step_ok, "expected": exp, "actual": actual})
    return ok, results


def run_vector(v: dict) -> Result:
    kind = v["kind"]
    try:
        if kind == "state":
            ok, steps = run_state(v)
            return Result(v["vector"], ok, None, None, steps=steps)
        if kind in ("envelope", "transport", "dht"):
            actual = run_envelope_like(v)
        elif kind == "payload":
            actual = run_payload(v)
        elif kind == "semantic":
            actual = run_semantic(v)
        else:
            return Result(v["vector"], False, v["expect"], None, note=f"unknown kind {kind}")
    except Exception as e:  # a crash is a failure, never a pass
        return Result(v["vector"], False, v["expect"], None, note=f"exception: {type(e).__name__}: {e}")
    return Result(v["vector"], actual == v["expect"], v["expect"], actual)
