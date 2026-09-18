#!/usr/bin/env python3
"""Python/TypeScript parity check: the second implementation (`impl-ts/`) against the Python harness.

Same contract as `parity.py`: both runners already compare against `expect`; this compares their
*actual* results with each other, so a disagreement on anything `expect` leaves unsaid still shows.
Vector kinds `impl-ts` does not implement yet are reported as skipped and excluded — never counted
as agreeing. Exit status 1 on any divergence or any failure on either side.

`--require-all` also fails when impl-ts skips anything: it implements every kind, and CI keeps it so.

Build first: `npm ci && npm run build` in `impl-ts/`.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        py_out, ts_out = Path(td) / "py.json", Path(td) / "ts.json"
        py = subprocess.run([sys.executable, str(REPO / "impl" / "tools" / "run_vectors.py"), "--json", str(py_out)],
                            capture_output=True, text=True)
        ts = subprocess.run(["node", str(REPO / "impl-ts" / "dist" / "run-vectors.js"), "--json", str(ts_out)],
                            capture_output=True, text=True)
        print(py.stdout.strip().splitlines()[-1] if py.stdout.strip() else py.stderr)
        print(ts.stdout.strip().splitlines()[-1] if ts.stdout.strip() else ts.stderr)
        if not py_out.exists() or not ts_out.exists():
            print("one runner produced no output", file=sys.stderr)
            return 1
        a, b = json.loads(py_out.read_text()), json.loads(ts_out.read_text())
    if set(a) != set(b):
        print(f"runners saw different vector sets: {sorted(set(a) ^ set(b))[:10]}", file=sys.stderr)
        return 1
    compared = [v for v in sorted(b) if not b[v].get("skipped")]
    diverged = failing = 0
    for vid in compared:
        pa, pb = a[vid], b[vid]
        if not (pa["ok"] and pb["ok"]):
            failing += 1
        if pa["ok"] != pb["ok"] or _actual(pa) != _actual(pb):
            diverged += 1
            print(f"[DIVERGE] {vid}")
            print(f"   python:     ok={pa['ok']} {json.dumps(_actual(pa))[:300]}")
            print(f"   typescript: ok={pb['ok']} {json.dumps(_actual(pb))[:300]}")
    print(f"\n{len(compared)} vectors compared ({len(b) - len(compared)} skipped by impl-ts), "
          f"{diverged} divergences, {failing} failing on at least one side")
    if "--require-all" in sys.argv and len(compared) != len(b):
        print("impl-ts skipped vectors and --require-all was given", file=sys.stderr)
        return 1
    return 1 if (diverged or failing) else 0


def _actual(r: dict):
    return r["steps"] if "steps" in r else r.get("actual")


if __name__ == "__main__":
    sys.exit(main())
