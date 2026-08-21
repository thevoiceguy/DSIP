#!/usr/bin/env python3
"""Local DHT testnet harness (plan §10.3): integration tests the vector suite cannot express.

Spins up N `dsip-dht-node` processes, drives them over their JSON-lines control
ports, and runs: publish/resolve round-trip, seq conflict resolution, expiry
lapse, publisher churn + late-joining node, a poisoning attempt (unsigned /
mis-signed records injected with the test-only `put_raw`), and a bootstrap
centralization measurement. Writes a JSON report for `docs/dht-findings.md`.

Usage: dht_testnet.py [--nodes 5] [--report out.json] [--keep]
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMPL / "tools"))

from dsipvec import fixtures as F, envelope as E, ulid as U  # noqa: E402

BIN = IMPL / "target" / "debug" / "dsip-dht-node"


class Node:
    def __init__(self, idx: int, bootstrap: list[str], republish: int = 5):
        args = [str(BIN), "--listen", "/ip4/127.0.0.1/tcp/0", "--control", "127.0.0.1:0", "--republish", str(republish)]
        for b in bootstrap:
            args += ["--bootstrap", b]
        self.idx = idx
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.peer = self.control = None
        self.addrs: list[str] = []
        deadline = time.time() + 15
        while time.time() < deadline and (self.control is None or not self.addrs):
            line = self.proc.stdout.readline().strip()
            if line.startswith("peer: "):
                self.peer = line[6:]
            elif line.startswith("control: "):
                self.control = line[9:]
            elif line.startswith("listening: "):
                self.addrs.append(line[11:])
                break
        if not self.addrs:
            raise RuntimeError(f"node {idx} did not start")

    def rpc(self, **req) -> dict:
        host, port = self.control.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=30) as s:
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.decode())

    def kill(self):
        self.proc.kill()
        self.proc.wait()


def hint_frame(signer: str, subject: str, seq: int, ttl: int = 3600, uri: str = "wss://relay-a.example/dsip",
               delegation: dict | None = None) -> str:
    """A hint claims `from = subject`; the signing device sits in `kid` and the header delegation proves
    the device acts for the subject (vectors dht/valid-delegated-device). Without a valid delegation the
    binding check fails (signer-mismatch) — which is exactly what the poisoning attempts below rely on."""
    now = int(time.time())
    payload = {"dsip": F.VERSION_TRANSPORT, "type": "reachability-hint", "id": U.deterministic(now * 1000, f"{signer}{seq}{time.time()}"),
               "from": subject, "subject": subject,
               "endpoints": [{"uri": uri, "bindings": ["ws/1.0"]}], "seq": seq, "issued_at": now, "expires_at": now + ttl}
    k = F.KEYS[signer]
    env = E.sign(payload, k, k.kid, header_extra={"delegations": [delegation]} if delegation else None)
    return E.frame(env)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=5)
    ap.add_argument("--report", default=str(IMPL / "docs" / "dht-testnet-report.json"))
    ap.add_argument("--keep", action="store_true", help="leave nodes running (prints control ports)")
    args = ap.parse_args()
    if not BIN.exists():
        print("build first: cargo build -p dsip-dht", file=sys.stderr)
        return 2

    # Live-dated delegations (the vector fixtures are anchored at the fixed fixture clock and have expired).
    now = int(time.time())
    alice = F.did("alice")
    alice_deleg = F.make_delegation(F.KEYS["alice"], alice, F.did("alice-phone"), issued_at=now - 60, expires_at=now + 86400)
    results: dict[str, dict] = {}
    nodes: list[Node] = []
    t0 = time.time()

    def check(name: str, ok: bool, **detail):
        results[name] = {"ok": bool(ok), **detail}
        print(f"[{'PASS' if ok else 'FAIL'}] {name}  {json.dumps(detail)[:160]}")

    try:
        nodes.append(Node(0, []))
        for i in range(1, args.nodes):
            nodes.append(Node(i, [nodes[0].addrs[0], nodes[min(1, i - 1)].addrs[0]]))
        time.sleep(2.5)  # let identify/bootstrap populate routing tables
        print(f"{len(nodes)} nodes up in {time.time() - t0:.1f}s")

        # 1. publish/resolve round-trip (did:key — zero external resolution)
        f1 = hint_frame("alice-phone", alice, 1, delegation=alice_deleg)
        pub = nodes[1].rpc(op="publish", frame=f1)
        got = nodes[-1].rpc(op="get", did=alice)
        check("round_trip", pub.get("ok") and got.get("winner") and got["winner"]["seq"] == 1
              and got["winner"]["endpoints"][0]["uri"] == "wss://relay-a.example/dsip",
              acknowledged=pub.get("acknowledged"), returned=got.get("returned"), publish_error=pub.get("error"))

        # 2. seq conflict: newer wins; older is superseded everywhere
        f2 = hint_frame("alice-phone", alice, 2, uri="wss://relay-b.example/dsip", delegation=alice_deleg)
        nodes[2].rpc(op="publish", frame=f2)
        got = nodes[3].rpc(op="get", did=alice)
        newer_wins = got.get("winner") and got["winner"]["seq"] == 2
        f0 = hint_frame("alice-phone", alice, 1, uri="wss://stale.example/dsip", delegation=alice_deleg)
        stale_pub = nodes[4 % len(nodes)].rpc(op="publish", frame=f0)      # honest node refuses (it already holds seq 2)
        nodes[4 % len(nodes)].rpc(op="put_raw", did=alice, frame=f0)        # so force it in raw; peers must supersede it
        time.sleep(1)
        got = nodes[0].rpc(op="get", did=alice)
        check("seq_conflict", newer_wins and got.get("winner") and got["winner"]["seq"] == 2 and not stale_pub.get("ok"),
              winner_seq=got.get("winner", {}).get("seq") if got.get("winner") else None,
              stale_publish_refused=not stale_pub.get("ok"),
              conflicts=[c["verdict"].get("conflict") for c in got.get("candidates", [])])

        # 3. poisoning: unsigned-by-subject records injected raw must be rejected by honest nodes
        before = {n.idx: n.rpc(op="stats")["stats"] for n in nodes}
        fm = hint_frame("mallory", alice, 99, uri="wss://evil.example/dsip")          # mallory signs for alice
        fc = hint_frame("carol-phone", alice, 99, uri="wss://evil.example/dsip")      # carol's device, no delegation from alice
        honest_refusal = nodes[1].rpc(op="publish", frame=fm)
        nodes[1].rpc(op="put_raw", did=alice, frame=fm)
        nodes[2].rpc(op="put_raw", did=alice, frame=fc)
        time.sleep(1.5)
        got = nodes[3].rpc(op="get", did=alice)
        after = {n.idx: n.rpc(op="stats")["stats"] for n in nodes}
        rejected = sum(sum(a["puts_rejected"].values()) - sum(before[i]["puts_rejected"].values()) for i, a in after.items())
        evil_won = bool(got.get("winner")) and "evil" in got["winner"]["endpoints"][0]["uri"]
        check("poisoning_rejected", (not honest_refusal.get("ok")) and not evil_won and rejected > 0,
              honest_publish_refused=not honest_refusal.get("ok"), inbound_rejections=rejected,
              winner_uri=got["winner"]["endpoints"][0]["uri"] if got.get("winner") else None,
              rejection_codes=sorted({k for a in after.values() for k in a["puts_rejected"]}))

        # 4. expiry lapse: a short-lived hint for bob stops resolving
        bob = F.did("bob")
        bob_deleg = F.make_delegation(F.KEYS["bob"], bob, F.did("bob-phone"), issued_at=now - 60, expires_at=now + 86400)
        fe = hint_frame("bob-phone", bob, 1, ttl=3, delegation=bob_deleg)
        nodes[1].rpc(op="publish", frame=fe)
        live = nodes[2].rpc(op="get", did=bob)
        time.sleep(4)
        lapsed = nodes[2].rpc(op="get", did=bob)
        check("expiry_lapse", live.get("winner") is not None and lapsed.get("winner") is None,
              live_returned=live.get("returned"), lapsed_returned=lapsed.get("returned"),
              lapsed_codes=[c["verdict"].get("code") for c in lapsed.get("candidates", [])])

        # 5. churn: kill the publisher of alice's record; record must survive; a late joiner must find it
        nodes[2].kill()
        time.sleep(1)
        survived = nodes[0].rpc(op="get", did=alice)
        late = Node(len(nodes), [nodes[0].addrs[0]])
        nodes.append(late)
        time.sleep(2)
        found_late = late.rpc(op="get", did=alice)
        check("churn_survival", survived.get("winner") and survived["winner"]["seq"] == 2
              and found_late.get("winner") and found_late["winner"]["seq"] == 2,
              after_kill_returned=survived.get("returned"), late_joiner_returned=found_late.get("returned"))

        # 6. bootstrap centralization + routing health (measurement, not a pass/fail)
        stats = {n.idx: n.rpc(op="stats")["stats"] for n in nodes if n.proc.poll() is None}
        results["routing"] = {"ok": True, "routing_peers": {i: s["routing_peers"] for i, s in stats.items()},
                              "stored": {i: s["stored"] for i, s in stats.items()},
                              "note": "every node bootstrapped via node 0 (and node 1): a static, configured entry point (plan §10.2)"}
        print(f"[INFO] routing_peers per node: {results['routing']['routing_peers']}  stored: {results['routing']['stored']}")
    finally:
        if args.keep:
            for n in nodes:
                print(f"node {n.idx}: control {n.control} addr {n.addrs[0]}")
        else:
            for n in nodes:
                n.kill()
    Path(args.report).write_text(json.dumps({"nodes": args.nodes, "elapsed_s": round(time.time() - t0, 1), "results": results}, indent=2) + "\n")
    failed = [k for k, v in results.items() if not v["ok"]]
    print(f"\n{len(results)} checks, {len(failed)} failed → {args.report}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
