#!/usr/bin/env python3
"""Rust/Python parity check: run both vector runners and diff their verdicts vector by vector.

Both runners already compare against `expect`; this script compares them against
*each other*, so a divergence shows up even on vectors where both fail.
Exit status 1 on any divergence or any failure on either side.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        py_out, rs_out = Path(td) / "py.json", Path(td) / "rs.json"
        py = subprocess.run([sys.executable, str(IMPL / "tools" / "run_vectors.py"), "--json", str(py_out)],
                            capture_output=True, text=True)
        rs = subprocess.run(["cargo", "run", "-q", "-p", "dsip-cli", "--", "vectors", "run", "--json", str(rs_out)],
                            cwd=IMPL, capture_output=True, text=True)
        print(py.stdout.strip().splitlines()[-1] if py.stdout.strip() else py.stderr)
        print(rs.stdout.strip().splitlines()[-1] if rs.stdout.strip() else rs.stderr)
        if not py_out.exists() or not rs_out.exists():
            print("one runner produced no output", file=sys.stderr)
            return 1
        a, b = json.loads(py_out.read_text()), json.loads(rs_out.read_text())
    ids = sorted(set(a) | set(b))
    diverged = 0
    for vid in ids:
        pa, pb = a.get(vid), b.get(vid)
        if pa is None or pb is None:
            print(f"[ONLY-{'PY' if pb is None else 'RS'}] {vid}")
            diverged += 1
            continue
        same = pa["ok"] == pb["ok"] and _actual(pa) == _actual(pb)
        if not same:
            diverged += 1
            print(f"[DIVERGE] {vid}")
            print(f"   python: ok={pa['ok']} {json.dumps(_actual(pa))[:300]}")
            print(f"   rust:   ok={pb['ok']} {json.dumps(_actual(pb))[:300]}")
    failing = sum(1 for v in ids if not (a.get(v, {}).get("ok") and b.get(v, {}).get("ok")))
    print(f"\n{len(ids)} vectors compared, {diverged} divergences, {failing} failing on at least one side")
    return 1 if (diverged or failing) else 0


def _actual(r: dict):
    if "steps" in r:
        return r["steps"]
    return r.get("actual")


if __name__ == "__main__":
    sys.exit(main())
