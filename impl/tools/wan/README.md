# DSIP WAN test plan — `real-call-dht` across real hosts

These are the provisioning + validation scripts for reproducing the localhost proof in
`impl/demos/real-call-dht.sh` on separate internet hosts. Two files, copied to each host:

- **`node-setup.sh`** — idempotent per-host provisioning, keyed by `ROLE`.
- **`dsipctl`** — validation helpers (DHT counters, addresses, GETs, captures) used by every run.

**Goal.** Take the localhost proof and reproduce each of its six stages on separate internet hosts,
with at least one endpoint behind NAT, then extend it with the partition / churn / adversarial
cases that `docs/dht-findings.md` lists as "not done." Every run produces a JSON record so
`dht-findings.md` can get a localhost-vs-WAN table.

**Scope note before starting.** `forge-ice` does STUN only — there is no TURN client. Run 3 (NAT on
both ends) is therefore a *measurement*, not a guaranteed pass: if both NATs are symmetric it will
fail, and that failure is a legitimate finding that motivates TURN in forge-ice. Don't paper over it.

---

## 0. Topology

| ID | Linode (suggested region) | ROLE | Ports open (cloud firewall) |
|---|---|---|---|
| **L1** | Newark, 2 GB | `bootstrap,relay` | 22/tcp, 4001/tcp, 8443/tcp |
| **L2** | Fremont, 2 GB | `dht,relay` | 22/tcp, 4001/tcp, 8443/tcp |
| **L3** | Frankfurt, Nanode | `dht` | 22/tcp, 4001/tcp |
| **L4** | Atlanta, Nanode | `dht,stun` | 22/tcp, 4001/tcp, 3478/udp |
| **E-A** | Your Debian 13 box (home NAT) | `endpoint` (Alice) | outbound only |
| **E-B** | Laptop / second NAT'd machine, or L2 for Run 1 | `endpoint` (Bob) | outbound only |

Endpoints do not need inbound ports: signaling is outbound `wss`, the DHT client dials out over TCP,
and ICE hole-punches UDP. Relay hosts must allow the ICE/UDP **egress** they already have; no RTP
ports are needed on L1–L4 because media is endpoint↔endpoint (the relay only carries signaling).

Create one Linode cloud firewall per role so Run 4's partition is a single rule toggle. All hosts:
Debian 13, root SSH, and **chrony running** — the envelope replay window is 300 s and a drifting
clock is the most likely "nothing works and every log looks fine" failure.

---

## 1. Provisioning (all hosts)

Copy `node-setup.sh` and `dsipctl` to each host, then run in this order — L1 first because everyone
else bootstraps from it.

### L1 — bootstrap + relay A
```bash
ROLE=bootstrap,relay DHT_SEED=$(openssl rand -hex 32) ./node-setup.sh
cat /var/lib/dsip/my-multiaddr      # → /ip4/<L1>/tcp/4001/p2p/12D3Koo…   ← BOOT1
cat /var/lib/dsip/relay/cert.pem    # → distribute as ca-L1.pem
```
The seed pins the PeerId so `BOOT1` survives restarts (Run 2 restarts it cold).

### L2 — dht + relay B
```bash
ROLE=dht,relay BOOTSTRAP=<BOOT1> ./node-setup.sh
cat /var/lib/dsip/relay/cert.pem    # → ca-L2.pem
```

### L3 — dht only
```bash
ROLE=dht BOOTSTRAP=<BOOT1> ./node-setup.sh
```

### L4 — dht + STUN (also second bootstrap later)
```bash
ROLE=dht,stun DHT_SEED=$(openssl rand -hex 32) BOOTSTRAP=<BOOT1> ./node-setup.sh
cat /var/lib/dsip/my-multiaddr      # ← BOOT2 (used in Run 2)
```

### E-A / E-B — endpoints
```bash
ROLE=endpoint ./node-setup.sh       # builds CLI, creates Alice + Bob identity dirs, prints their DIDs
mkdir -p ~/dsip-wan && scp root@L1:/var/lib/dsip/relay/cert.pem ~/dsip-wan/ca-L1.pem
scp root@L2:/var/lib/dsip/relay/cert.pem ~/dsip-wan/ca-L2.pem
```
Endpoints only need a CA for the relay they *bind* to. Alice will discover Bob's relay from the
hint, so she needs the CA of whichever relay Bob uses; for Run 1 that's `ca-L2.pem`.

### Shared env file — `~/dsip-wan/HOSTS.env` on every endpoint
```bash
BOOT1=/ip4/<L1>/tcp/4001/p2p/<peer>
BOOT2=/ip4/<L4>/tcp/4001/p2p/<peer>
RELAY_A=wss://<L1>:8443/dsip
RELAY_B=wss://<L2>:8443/dsip
STUN=<L4>:3478
CA_A=$HOME/dsip-wan/ca-L1.pem
CA_B=$HOME/dsip-wan/ca-L2.pem
ALICE=$HOME/dsip-wan/ids/alice     # copy from /var/lib/dsip/ids or init fresh
BOB=$HOME/dsip-wan/ids/bob
ALICE_DID=$(jq -r .identity $ALICE/identity.json)
BOB_DID=$(jq -r .identity $BOB/identity.json)
```

### Provisioning validation (do all of these before any run)

| Check | Where | Command | Expect |
|---|---|---|---|
| clocks | all | `dsipctl drift` | offset < 1 s |
| listeners | L1–L4 | `dsipctl ports` | 4001/tcp on dht hosts, 8443/tcp on relays, 3478/udp on L4 |
| bootstrap reachable | L2, L3, L4 | `nc -zv <L1> 4001` | `succeeded` |
| overlay formed | L1 | `dsipctl stats` | `routing_peers` = 3 (L2, L3, L4) within ~5 s of the last join |
| overlay formed | L3 | `dsipctl stats` | `routing_peers` ≥ 1; `dsipctl addrs` shows its public ip, not 0.0.0.0 |
| relay TLS | E-A | `openssl s_client -connect <L2>:8443 -CAfile ~/dsip-wan/ca-L2.pem </dev/null 2>&1 \| grep 'Verify return'` | `Verify return code: 0` |
| relay hello | E-A | `dsip answer --identity $BOB --relay $RELAY_B --ca $CA_B --script "sleep 3; quit"` | log contains `relay … §13.2 hello bound` |
| STUN | E-A | `stunclient <L4> 3478` (package `stun-client`) or `nc -u -zv <L4> 3478` | mapped address = your public IP |
| DHT from NAT | E-A | `dsip resolve $BOB_DID --dht $BOOT1` | `dht joined as … via 1 bootstrap node(s)` then `hint none verified` (nothing published yet) — proves the outbound dial and routing warm-up work through NAT |
| RTT baseline | E-A | `for h in L1 L2 L3 L4; do ping -c5 $h \| tail -1; done` | record — goes in the results JSON |

If `routing_peers` stays at 0 on L2–L4, first check `BOOT1` is reachable and correct: run
`cat /var/lib/dsip/my-multiaddr` on L1 and confirm it shows L1's **public** IP (not `127.0.0.1`, not
a private/docker `172.x`/`10.x` address) and ends in `/p2p/12D3Koo…`. `node-setup.sh` composes this
addr from the auto-detected `PUBLIC_IP` plus the pinned PeerId; if `PUBLIC_IP` picked the wrong
interface, re-run with `PUBLIC_IP=<correct v4>` set explicitly.

---

## 2. The WAN call script

Rather than fork `real-call-dht.sh`, drive the same stages by hand the first time so each one can be
validated, then wrap them. Stages map 1:1 to the localhost script.

### Stage 1 — overlay up
Already done by provisioning. Validate: `dsipctl stats` on L1 shows 3 peers, `stored: 0`.

### Stage 2 — identities
Already created. Print and share:
```bash
echo "Alice $ALICE_DID"; echo "Bob $BOB_DID"
```

### Stage 3 — Bob binds to relay B and publishes a hint (on E-B)
```bash
source ~/dsip-wan/HOSTS.env
espeak-ng -v en-us+f3 -s 150 -w /tmp/bob-src.wav "Hi Alice, I hear you clearly. We found each other through the hash table, no phone company."
ffmpeg -y -loglevel error -i /tmp/bob-src.wav -ar 48000 -ac 1 -c:a libopus -b:a 24k /tmp/bob.ogg

dsip answer --identity $BOB --relay $RELAY_B --ca $CA_B \
  --dht $BOOT1 --publish-hint --hint-ttl 600 --auto accept \
  --media file:/tmp/bob.ogg --record /tmp/bob-heard.ogg \
  --stun $STUN --script "sleep 60; quit" 2>&1 | tee /tmp/bob.log
```
**Validate while it runs:**

| Where | Command | Expect |
|---|---|---|
| E-B log | `grep -E '^(dht\|hint)' /tmp/bob.log` | `dht joined as …` then `hint published <BOB_DID> → wss://<L2>… seq N ttl 600 s acknowledged by K peer(s)` — K should be ≥ 3 |
| L2 relay | `dsipctl relay-tail` | a `hello` bound for Bob's identity |
| L1, L3, L4 | `dsipctl stats` | `stored: 1`, `puts_accepted: 1` on each; `puts_rejected: {}` |
| any DHT host | `dsipctl get $BOB_DID` | one verified record, `endpoints[0].uri` = `RELAY_B`, `seq` = publish time, `expires_at` ≈ now+600 |
| L1 | `dsipctl cap-sig` during publish | TCP/4001 traffic from E-B's public IP and from L2/L3/L4 (replication fan-out) |

Note K (the ack count) — it's the first number that differs from localhost, where it was always every node.

### Stage 4 — Alice resolves via DHT only (on E-A)
```bash
source ~/dsip-wan/HOSTS.env
time dsip resolve $BOB_DID --dht $BOOT1 | tee /tmp/resolve.log
```
**Validate:**

| Command | Expect |
|---|---|
| `grep -E '^(method\|authority\|hints\|hint)' /tmp/resolve.log` | `hints 1 record(s) returned` (or more copies), `hint wss://<L2>… seq N expires in … s signed by <device>` marked HINT-SOURCED, NOT AUTHORITATIVE |
| `time` output | record as `resolve_ms`; localhost was sub-second |
| `grep -c reachability-hint /tmp/resolve.log` | ≥ 1 |

Alice has never been told `RELAY_B`. If this prints L2's URL, DHT discovery over the WAN works.

### Stage 5 — Alice calls over the discovered relay (on E-A)
```bash
espeak-ng -v en-us -s 150 -w /tmp/alice-src.wav "Hi Bob, this is Alice, calling you over the DSIP decentralized network."
ffmpeg -y -loglevel error -i /tmp/alice-src.wav -ar 48000 -ac 1 -c:a libopus -b:a 24k /tmp/alice.ogg

# no --relay: it comes from the hint. --ca must trust the *discovered* relay (L2).
dsip call --identity $ALICE --ca $CA_B --dht $BOOT1 --to $BOB_DID \
  --media file:/tmp/alice.ogg --record /tmp/alice-heard.ogg \
  --stun $STUN --script "sleep 12; hangup; sleep 1; quit" 2>&1 | tee /tmp/alice.log
```
**Validate:**

| Where | Command | Expect |
|---|---|---|
| E-A log | `grep -E 'hello bound\|ice connected\|first inbound RTP\|closed —' /tmp/alice.log` | all four lines, in that order |
| E-A log | `grep 'ice connected'` | the pair shown — record candidate types; `srflx ↔ srflx` means STUN hole-punch worked, a `host` pair on WAN means something's wrong |
| E-A | `dsipctl cap-rtp` in a second terminal | STUN binding requests to L4:3478 then UDP both ways to E-B's public IP (not to L2 — the relay never sees media) |
| L2 | `dsipctl relay-tail` | invite forked to Bob's leg, answer forwarded, bye |
| L2 | `dsipctl cap-rtp` | **no** UDP media — confirms the relay is signaling-only |
| E-B log | `grep 'first inbound RTP' /tmp/bob.log` | present |

Record timestamps between `hello bound` → `ice connected` → `first inbound RTP` from the log lines
(they carry monotonic ms) as `ice_ms` and `first_rtp_ms`.

### Stage 6 — verify the audio (either endpoint, after copying the other side's recording)
```bash
scp E-B:/tmp/bob-heard.ogg /tmp/; scp E-B:/tmp/bob.ogg /tmp/
D=/tmp SPEECH=1 python3 - <<'PY'
# paste the verifier from demos/real-call-dht.sh stage 6 here, unchanged
PY
```
Expect `✓ words crossed intact` both directions with rhythm ≥ 0.6 (localhost scored 0.97+). Record
the two scores. If Bob→Alice scores well and Alice→Bob doesn't, check that Bob's `--script` sleep was
long enough to cover Alice's full clip plus ICE time.

### Wrap it
Once stages 3–6 pass by hand, add a `wan` mode to `real-call-dht.sh` that sources `HOSTS.env` and
runs only the local side (`SIDE=alice|bob`), writing `/tmp/dsip-wan-<run>-<side>.json`. Keep one
script; localhost and WAN are the same proof with different inputs.

---

## 3. Runs

Each run: execute, validate with the commands above, and append a line to `docs/dht-wan-results.jsonl`:
```json
{"run":1,"date":"…","alice":"home-nat","bob":"L2","bootstrap":["L1"],"rtt_ms":{"L1":0,"L2":0,"L3":0,"L4":0},
 "publish_acks":3,"resolve_ms":0,"ice_pair":"srflx-srflx","ice_ms":0,"first_rtp_ms":0,
 "rhythm":{"a2b":0.0,"b2a":0.0},"stats":{"L1":{},"L3":{}},"pass":true}
```

### Run 1 — baseline across hosts
Alice on E-A (NAT), Bob on **L2** itself (public IP, relay local). Exactly stages 3–6. This is the
minimum claim: "a NAT'd endpoint found a public endpoint through the DHT and talked to it."

### Run 2 — bootstrap death and rejoin (finding 3)
1. With Run 1's overlay still up, on L1: `systemctl stop dsip-dht`.
2. On L3: `dsipctl peers` — `routing_peers` should drop by one and stay ≥ 2. `dsipctl get $BOB_DID`
   must still return the record (held by L2/L3/L4).
3. Repeat stages 4–5 from E-A **with `--dht $BOOT1` still pointed at the dead L1**. Expect: resolve
   fails / times out. Record the timeout. This is the censorship point, measured.
4. Repeat with `--dht $BOOT2` (L4). Expect: succeeds. Record.
5. Restart L1: `systemctl start dsip-dht`. On L1: `dsipctl stats` — it rejoins via… nothing (it has
   no `--bootstrap`). `routing_peers` stays 0 until another node dials it. Record how long (if ever)
   it takes L2–L4's re-announce to repopulate it; this is the "cached peer list across restarts" gap.
6. Follow-up work item: multi-`--bootstrap` on every node (the flag already takes a Vec) + persist
   `addrs` on shutdown.

### Run 3 — NAT on both ends
Bob moves to E-B behind a *different* NAT (laptop on phone hotspot is the easiest second NAT). Stage 3
with `--relay $RELAY_B` from E-B, stages 4–6 from E-A.
- **Validate the NAT types first:** from each endpoint, `stunclient <L4> 3478 --mode full` (or
  pystun3). Record: full-cone / restricted / port-restricted / symmetric.
- Expect `ice connected srflx ↔ srflx`.
- If `first inbound RTP` never appears and both sides show symmetric NAT, that is the expected
  STUN-only failure. Capture `dsipctl cap-rtp` on both sides showing binding requests leaving and
  nothing arriving, and file it as the TURN-in-forge-ice work item. Don't retry with Bob on a public
  host and call it a pass.

### Run 4 — partition, stale copies, freshness (finding 7)
1. Bob publishes with `--hint-ttl 120` from E-B via `RELAY_B`. Confirm `stored:1` on L1–L4.
2. Partition L3: in the Linode firewall for L3, drop inbound+outbound 4001/tcp (or on L3:
   `iptables -A INPUT -p tcp --dport 4001 -j DROP; iptables -A OUTPUT -p tcp --dport 4001 -j DROP`).
3. Bob quits and re-answers bound to **`RELAY_A`** with `--publish-hint`. New record has a newer `seq`
   and a different relay URI. L1/L2/L4 should show `puts_accepted:2`; L3 still holds the old one.
4. Lift the partition. Within one re-announce interval (60 s) L3 re-announces its *stale* record outward.
5. On L1: `dsipctl stats` — expect `puts_superseded` to increment (L3's stale copy lost to the newer
   seq). On L3: `dsipctl get $BOB_DID` — expect it now ranks the newer record first, the old one
   flagged `older-seq`.
6. Stage 4 from E-A during the mixed window: resolve must print `RELAY_A`, not `RELAY_B`. Stage 5 with
   `--ca $CA_A`: call lands.
7. Wait past 120 s with Bob still up: hint should have been re-signed at ⅔ TTL (80 s) — `dsipctl get`
   shows a fresh `expires_at`. Then kill Bob and wait 120 s: all copies report `expired`, resolve
   returns `hint none verified`.

### Run 5 — adversarial PUT flood (finding 1)
1. On L3, stop the honest node and run a second node with a throwaway seed that joins via `BOOT1`.
   Using its control port, loop the test-only `put_raw` with a mis-signed frame (reuse the vector from
   `tools/dht_testnet.py`'s poisoning test) at, say, 50/s for 60 s.
2. On L1, L2, L4: `dsipctl stats` every 10 s — `puts_rejected["signer-mismatch"]` climbing, `stored`
   unchanged, `top -p $(pidof dsip-dht-node)` for CPU. Record peak CPU% per honest node.
3. From E-A, stage 4 during the flood: resolve must still return Bob's real hint. Record `resolve_ms`
   under load vs Run 1.
4. Implement per-peer inbound PUT rate limiting in `dsip-dht`, redeploy, rerun, record the delta. That
   before/after pair is the headline for the findings update.

---

## 4. Teardown / reset between runs
```bash
# any DHT host: drop all held records without restarting
printf '{"op":"shutdown"}\n' | nc -q1 127.0.0.1 4101; systemctl restart dsip-dht
# relays: state dir holds the cert + key; don't delete it or every endpoint's --ca goes stale
# endpoints: identities persist; recordings in /tmp
```

---

## 5. What to write up
A table in `docs/dht-findings.md`, "WAN results," with one row per run: hosts, NAT types, RTT,
`publish_acks`, `resolve_ms`, ICE pair + `ice_ms`, `first_rtp_ms`, rhythm scores, and the stats deltas
for Runs 2/4/5. Then update the §8.5 risk list entries 1, 3, and 7 from "not measured on WAN" to the
measured numbers, and add a line under "deliberately did not do" for whatever Run 3 shows about TURN.
