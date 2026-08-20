#!/usr/bin/env python3
"""Python side of the Rust/Python parity contract: run every vector, compare with `expect`.

Usage: run_vectors.py [--only PREFIX] [--json OUT] [-v]
Exit status 1 on any failure.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dsipvec.harness import load_vectors, run_vector  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="vector id prefix, e.g. state/ or envelope/valid")
    ap.add_argument("--json", help="write machine-readable results (for parity diffing)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    results = [run_vector(v) for v in load_vectors(only=args.only)]
    failures = [r for r in results if not r.ok]
    for r in results:
        if r.ok and not args.verbose:
            continue
        print(f"[{'PASS' if r.ok else 'FAIL'}] {r.vector}")
        if not r.ok:
            if r.note:
                print(f"       {r.note}")
            if r.steps:
                for s in r.steps:
                    if not s["ok"]:
                        print(f"       step {s['step']}:")
                        print(f"         expected: {json.dumps(s['expected'])}")
                        print(f"         actual:   {json.dumps(s['actual'])}")
                        break
            elif r.actual is not None:
                print(f"       expected: {json.dumps(r.expected)}")
                print(f"       actual:   {json.dumps(r.actual)}")
    by_kind: dict[str, list] = {}
    for r in results:
        by_kind.setdefault(r.vector.split("/")[0], []).append(r)
    for k, rs in sorted(by_kind.items()):
        print(f"{k:10s} {sum(1 for r in rs if r.ok):3d}/{len(rs):<3d}")
    print(f"\n{len(results)} vectors, {len(failures)} failures")
    if args.json:
        Path(args.json).write_text(json.dumps({
            r.vector: ({"ok": r.ok, "steps": [{"emit": s["actual"]["emit"], **{k: v for k, v in s["actual"].items() if k != "emit"}}
                                               for s in r.steps]} if r.steps else {"ok": r.ok, "actual": r.actual})
            for r in results}, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
