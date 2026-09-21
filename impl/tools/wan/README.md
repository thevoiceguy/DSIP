# DSIP WAN test plan — `real-call-dht` across real hosts

These are the provisioning + validation scripts for reproducing the localhost proof in
`impl/demos/real-call-dht.sh` on separate internet hosts. Two files, copied to each host:

- **`node-setup.sh`** — idempotent per-host provisioning, keyed by `ROLE`.
- **`dsipctl`** — validation helpers (DHT counters, addresses, GETs, captures) used by every run.

**Goal.** Take the localhost proof and reproduce each of its six stages on separate internet hosts,
with at least one endpoint behind NAT, then extend it with the partition / churn / adversarial
cases that `docs/dht-findings.md` lists as "not done", and with the Messaging Profile across two
hosts (Run 6). Every run produces a JSON record so `dht-findings.md` can get a localhost-vs-WAN table.

**Reviewed 2026-09-20 against main (931 vectors).** Every flag, log line and control-port op below was
checked against the binaries. What changed since the plan was written (2026-08-22):

- **TURN exists.** forge-media `b674552` has a relay-capable ICE agent; `dsip call|answer` take
  `--turn`, `--turn-user`, `--turn-pass`, `--relay-only`, and `demos/real-call-dht.sh RUN3=1` proves
  the relay path on one host. Run 3 is now two runs: 3a measures STUN alone (may legitimately fail),
  3b is the TURN fallback and **must pass**. L4's coturn is a TURN server, not `stun-only`.
- **Messaging Profile 1.0** (`dsip-mailbox`, `dsip-msg`) did not exist. Run 6 is new. It needed two
  fixes to `dsip-mailbox`, made with this revision: `--host` (its certificate named only
  `localhost`/`127.0.0.1`) and an advertised `blob_endpoint` on that host (it advertised the
  `--listen` address, i.e. `https://0.0.0.0:9443/blobs`).
- **Relay behaviour** decided since: an attempt no leg answers ends in a relay-signed
  `error transport.no-response` (spec-gap 76); session traffic is routed by `to` with or without an
  attempt (82); an answer from a cancelled leg is forwarded so the initiator can `bye` it (86). Run 2b
  observes the first on a real network.
- **One commit for a campaign.** `DSIP_REF` pins it, `dsipctl commit` reports it, the results record
  carries it. The toolchain is pinned by `impl/rust-toolchain.toml` (rustup installs it on first build).
- **Build once.** A release build of the set is too big for a Nanode; build on one host and install
  the rest with `PREBUILT`.
- **CLI log lines carry no timestamps** (the old plan said they did): pipe through `ts '%.s'`.
- **One CA bundle.** `--ca` takes a PEM bundle everywhere, so endpoints carry one `ca-all.pem`.

**Scope notes.** Run 3a (STUN only, NAT on both ends) is a *measurement*: if both NATs are symmetric
it fails, and that is the finding. Don't paper over it — but don't stop there either: 3b shows what a
deployment does about it. The gateway (Gateway Profile 1.0) is out of scope here: it needs a SIP
peer, and its round trip is proven in-process in CI. DID documents for Run 6 are distributed as files
(`--resolver-file`); live `did:web` resolution over HTTPS with a public certificate is not part of
this plan.

---

## 0. Topology

| ID | Linode (suggested region) | ROLE | Ports open (cloud firewall) |
|---|---|---|---|
| **L1** | Newark, 4 GB (the build host; resize down after) | `bootstrap,relay,mailbox` | 22/tcp, 4001/tcp, 8443/tcp, 9443/tcp |
| **L2** | Fremont, 2 GB | `dht,relay,mailbox` | 22/tcp, 4001/tcp, 8443/tcp, 9443/tcp |
| **L3** | Frankfurt, Nanode | `dht` | 22/tcp, 4001/tcp |
| **L4** | Atlanta, Nanode | `dht,turn` | 22/tcp, 4001/tcp, 3478/udp, 49160–49200/udp |
| **E-A** | Your Debian 13 box (home NAT) | `endpoint` (Alice) | outbound only |
| **E-B** | Laptop / second NAT'd machine, or L2 for Run 1 | `endpoint` (Bob) | outbound only |

Endpoints do not need inbound ports: signaling is outbound `wss`, the DHT client dials out over TCP,
and ICE hole-punches UDP. No RTP ports are needed on L1–L3 because media is endpoint↔endpoint (the
DSIP relay only carries signaling). L4 is the exception from Run 3b on: a TURN allocation relays
media through 49160–49200/udp. The mailbox port (9443) carries both `wss` and the HTTPS blob endpoint.

Create one Linode cloud firewall per role so Run 4's partition is a single rule toggle. All hosts:
Debian 13, root SSH, and **chrony running** — the envelope replay window is 300 s and a drifting
clock is the most likely "nothing works and every log looks fine" failure.

---

## 1. Provisioning (all hosts)

Copy `node-setup.sh` and `dsipctl` to each host, then run in this order — L1 first because everyone
else bootstraps from it, and because it builds the binaries the others install.

Pick the commit first and use it everywhere: `export DSIP_REF=<commit or tag>` (a moving `main` on
four hosts provisioned an hour apart is four different programs). `dsipctl commit` must print the
same hash on every host before any run.

### L1 — bootstrap + relay A + Alice's mailbox (builds)
```bash
ROLE=bootstrap,relay,mailbox MAILBOX_OWNER=did:web:alice.example DHT_SEED=$(openssl rand -hex 32) ./node-setup.sh
cat /var/lib/dsip/my-multiaddr      # → /ip4/<L1>/tcp/4001/p2p/12D3Koo…   ← BOOT1
ls /var/lib/dsip/prebuilt           # dsip dsip-relay dsip-dht-node dsip-mailbox dsip-msg COMMIT
```
The seed pins the PeerId so `BOOT1` survives restarts (Run 2 restarts it cold). The build wants about
3 GB of RAM and 6 GB of disk, and takes 15–25 min on a shared 4 GB Linode. Copy the result to the
others (all Debian 13 x86-64): `scp -r root@L1:/var/lib/dsip/prebuilt /root/prebuilt` on each.

### L2 — dht + relay B + Bob's mailbox
```bash
PREBUILT=/root/prebuilt ROLE=dht,relay,mailbox MAILBOX_OWNER=did:web:bob.example BOOTSTRAP=<BOOT1> ./node-setup.sh
```

### L3 — dht only
```bash
PREBUILT=/root/prebuilt ROLE=dht BOOTSTRAP=<BOOT1> ./node-setup.sh
```

### L4 — dht + STUN/TURN (also second bootstrap later)
```bash
PREBUILT=/root/prebuilt ROLE=dht,turn DHT_SEED=$(openssl rand -hex 32) BOOTSTRAP=<BOOT1> ./node-setup.sh
cat /var/lib/dsip/my-multiaddr      # ← BOOT2 (used in Run 2)
cat /var/lib/dsip/turn.pass         # ← TURN_PASS (user `dsip`)
```

### E-A / E-B — endpoints
```bash
PREBUILT=$HOME/prebuilt ROLE=endpoint ./node-setup.sh   # Alice + Bob identity dirs, prints their DIDs
mkdir -p ~/dsip-wan
for h in L1 L2; do ssh root@$h 'cat /var/lib/dsip/relay/cert.pem /var/lib/dsip/mailbox/cert.pem'; done > ~/dsip-wan/ca-all.pem
for h in L1 L2; do scp ~/dsip-wan/ca-all.pem root@$h:/var/lib/dsip/ca-all.pem; done   # the mailboxes dial each other
```
(An endpoint that is not x86-64 Debian 13 builds for itself: drop `PREBUILT`, keep `DSIP_REF`.)
`--ca` takes a PEM bundle, so one file covers both relays and both mailboxes: Alice discovers Bob's
relay from the hint and must already trust whichever one that turns out to be.

### Shared env file — `~/dsip-wan/HOSTS.env` on every endpoint
```bash
BOOT1=/ip4/<L1>/tcp/4001/p2p/<peer>
BOOT2=/ip4/<L4>/tcp/4001/p2p/<peer>
RELAY_A=wss://<L1>:8443/dsip
RELAY_B=wss://<L2>:8443/dsip
STUN=<L4>:3478
TURN=turn:<L4>:3478
TURN_USER=dsip
TURN_PASS=<L4:/var/lib/dsip/turn.pass>
CA=$HOME/dsip-wan/ca-all.pem
MBX_A=wss://<L1>:9443/dsip
MBX_B=wss://<L2>:9443/dsip
COMMIT=<dsipctl commit>
ALICE=$HOME/dsip-wan/ids/alice     # copy from /var/lib/dsip/ids or init fresh
BOB=$HOME/dsip-wan/ids/bob
ALICE_DID=$(jq -r .identity $ALICE/identity.json)
BOB_DID=$(jq -r .identity $BOB/identity.json)
```

### Provisioning validation (do all of these before any run)

| Check | Where | Command | Expect |
|---|---|---|---|
| same code | all | `dsipctl commit` | one hash, equal to `$COMMIT` |
| clocks | all | `dsipctl drift` | offset < 1 s |
| listeners | L1–L4 | `dsipctl ports` | 4001/tcp on dht hosts, 8443/tcp + 9443/tcp on L1/L2, 3478/udp on L4 |
| bootstrap reachable | L2, L3, L4 | `nc -zv <L1> 4001` | `succeeded` |
| overlay formed | L1 | `dsipctl stats` | `routing_peers` = 3 (L2, L3, L4) within ~5 s of the last join |
| overlay formed | L3 | `dsipctl stats` | `routing_peers` ≥ 1; `dsipctl addrs` shows its public ip, not 0.0.0.0 |
| relay TLS | E-A | `openssl s_client -connect <L2>:8443 -CAfile $CA </dev/null 2>&1 \| grep 'Verify return'` | `Verify return code: 0` |
| mailbox TLS | E-A | same against `<L1>:9443` and `<L2>:9443` | `Verify return code: 0` — the certificate names the public IP (`--host`) |
| relay hello | E-A | `dsip answer --identity $BOB --relay $RELAY_B --ca $CA --script "sleep 3; quit"` | log contains `relay … §13.2 hello bound` |
| STUN | E-A | `stunclient <L4> 3478` (package `stun-client`) or `nc -u -zv <L4> 3478` | mapped address = your public IP |
| TURN | E-A | `turnutils_uclient -u $TURN_USER -w $TURN_PASS -y <L4>` (package `coturn-utils`) | allocations succeed, packets echo; `dsipctl turn-tail` on L4 shows the session |
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

dsip answer --identity $BOB --relay $RELAY_B --ca $CA \
  --dht $BOOT1 --publish-hint --hint-ttl 600 --auto accept \
  --media file:/tmp/bob.ogg --record /tmp/bob-heard.ogg \
  --stun $STUN --script "sleep 60; quit" 2>&1 | ts '%.s' | tee /tmp/bob.log
```
`ts '%.s'` (moreutils) stamps each line with epoch seconds: the CLI prints none, and the timings in
the results record come from these.
**Validate while it runs:**

| Where | Command | Expect |
|---|---|---|
| E-B log | `grep -E ' (dht\|hint) ' /tmp/bob.log` | `dht joined as …` then `hint published <BOB_DID> → wss://<L2>… seq N ttl 600 s acknowledged by K peer(s)` — K should be ≥ 3 |
| L2 relay | `dsipctl relay-tail` | `<peer>: bound device <Bob's device> for identity <BOB_DID>` |
| L1, L3, L4 | `dsipctl stats` | `stored: 1`, `puts_accepted: 1` on each; `puts_rejected: {}` |
| any DHT host | `dsipctl get $BOB_DID` | one verified record, `endpoints[0].uri` = `RELAY_B`, `seq` = publish time, `expires_at` ≈ now+600 |
| L1 | `dsipctl cap-sig` during publish | TCP/4001 traffic from E-B's public IP and from L2/L3/L4 (replication fan-out) |

Note K (the ack count) — it's the first number that differs from localhost, where it was always every node.

### Stage 4 — Alice resolves via DHT only (on E-A)
```bash
source ~/dsip-wan/HOSTS.env
time dsip resolve $BOB_DID --dht $BOOT1 | tee /tmp/resolve.log     # no ts here: the greps below anchor on ^
```
**Validate:**

| Command | Expect |
|---|---|
| `grep -E '^(method\|authority\|hints\|hint)' /tmp/resolve.log` | `hints 1 record(s) returned` (or more copies), `hint wss://<L2>… seq N expires in … s signed by <device>` marked HINT-SOURCED, NOT AUTHORITATIVE |
| `time` output | record as `resolve_ms`; localhost was sub-second |
| `grep -c 'verified against the subject DID' /tmp/resolve.log` | 1 — the hint was checked against Bob's DID before use (§8.1 rule 6) |

Alice has never been told `RELAY_B`. If this prints L2's URL, DHT discovery over the WAN works.

### Stage 5 — Alice calls over the discovered relay (on E-A)
```bash
espeak-ng -v en-us -s 150 -w /tmp/alice-src.wav "Hi Bob, this is Alice, calling you over the DSIP decentralized network."
ffmpeg -y -loglevel error -i /tmp/alice-src.wav -ar 48000 -ac 1 -c:a libopus -b:a 24k /tmp/alice.ogg

# no --relay: it comes from the hint. The CA bundle already trusts whichever relay that is.
RUST_LOG=warn,forge_webrtc=info dsip call --identity $ALICE --ca $CA --dht $BOOT1 --to $BOB_DID \
  --media file:/tmp/alice.ogg --record /tmp/alice-heard.ogg \
  --stun $STUN --script "sleep 12; hangup; sleep 1; quit" 2>&1 | ts '%.s' | tee /tmp/alice.log
```
`forge_webrtc=info` adds the `ICE nominated <local> ↔ <remote>` line: the addresses of the pair that
won, which is what tells a hole-punched path from a relayed one. Run Bob's side with it too.
**Validate:**

| Where | Command | Expect |
|---|---|---|
| E-A log | `grep -E 'hello bound\|ice connected\|first inbound RTP\|closed —' /tmp/alice.log` | all four lines, in that order |
| E-A log | `grep -E 'ice connected\|ICE nominated'` | the pair shown — the remote address is Bob's public IP (hole-punched, `srflx`); a private address on WAN means something's wrong; L4's address with a 49160–49200 port means TURN (Run 3b only) |
| E-A | `dsipctl cap-rtp` in a second terminal | STUN binding requests to L4:3478 then UDP both ways to E-B's public IP (not to L2 — the relay never sees media) |
| L2 | `dsipctl relay-tail` | `invite <session> → leg <Bob's device>`, then `answer` and `bye` lines for the same session; no `dropped on` line |
| L2 | `dsipctl cap-rtp` | **no** UDP media — confirms the relay is signaling-only |
| E-B log | `grep 'first inbound RTP' /tmp/bob.log` | present |

Record the differences between the `ts` stamps of `hello bound` → `ice connected` →
`first inbound RTP` as `ice_ms` and `first_rtp_ms`.

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
{"run":"1","date":"…","commit":"<dsipctl commit>","alice":"home-nat","bob":"L2","bootstrap":["L1"],
 "rtt_ms":{"L1":0,"L2":0,"L3":0,"L4":0},"nat":{"alice":"…","bob":"…"},
 "publish_acks":3,"resolve_ms":0,"ice_pair":"srflx-srflx","turn":false,"ice_ms":0,"first_rtp_ms":0,
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
6. Repeat step 3 with **both**: `--dht $BOOT1 --dht $BOOT2` (the flag repeats) while L1 is down.
   Expect: succeeds, `via 2 bootstrap node(s)` in the join line. Record the added latency of the dead
   first entry. This is what an endpoint should ship with.
7. Follow-up work item: multi-`--bootstrap` on every node (the flag already takes a Vec) + persist
   `addrs` on shutdown.

### Run 2b — a callee that stops answering (spec-gap 76)
The hint outlives the endpoint by up to its TTL, so a caller can discover a relay where nobody is
listening any more. On a real network that is a routine case, not a fault.
1. Bob answers as in stage 3 with `--hint-ttl 600`, **without** `--auto accept`. Freeze him rather
   than quit him: `kill -STOP $(pgrep -f 'dsip answer')` — his relay binding stays up, he says nothing.
2. Stage 5 from E-A with `--t-establish 10`.
3. Expect on E-A: no `progress`; T-Establish expires and Alice sends `cancel session.timeout`. If the
   invite's `expires_at` passes first, the relay ends the attempt itself: `attempt <session> outcome:
   no leg responded` on L2 and a relay-signed `error transport.no-response` at Alice. Record which
   came first and the elapsed time. `kill -CONT` Bob afterwards: a late `answer` from him must get a
   `bye`, not silence (spec-gap 86; `relay-tail` shows the answer forwarded, not `dropped`).
4. Now `kill -9` Bob and call again inside the TTL: Alice resolves the stale hint, binds, and the
   invite is queued (`queued invite for … (§13.3)`: the relay has seen Bob, so he is known-but-unbound;
   after a relay restart he would be unknown and Alice would get `transport.unknown-recipient`). Record what Alice's user sees and after how long —
   this is the number that says whether 600 s is a sensible hint TTL.

### Run 3a — NAT on both ends, STUN only
Bob moves to E-B behind a *different* NAT (laptop on phone hotspot is the easiest second NAT, and
carrier NAT is usually symmetric — the hard case, which is the point). Stage 3 with
`--relay $RELAY_B` from E-B, stages 4–6 from E-A.
- **Validate the NAT types first:** from each endpoint, `stunclient <L4> 3478 --mode full` (or
  pystun3). Record: full-cone / restricted / port-restricted / symmetric → the record's `nat`.
- Expect `ice connected` with both addresses public (`srflx ↔ srflx`).
- If `first inbound RTP` never appears and both sides show symmetric NAT, that is the expected
  STUN-only failure. Capture `dsipctl cap-rtp` on both sides showing binding requests leaving and
  nothing arriving, record `"pass": false, "ice_pair": "none"`, and go to 3b. Don't retry with Bob on
  a public host and call it a pass.

### Run 3b — the same two NATs with a TURN fallback (must pass)
Both endpoints add `--turn $TURN --turn-user $TURN_USER --turn-pass $TURN_PASS` next to `--stun $STUN`.
ICE still prefers a direct pair; the relay candidate is there for when none works.
- If 3a passed: expect the same direct pair (`"turn": false`) — TURN offered, not used. Record that
  the allocation alone added nothing to `ice_ms` worth noting, or what it added.
- If 3a failed: expect `ICE nominated … <L4>:491xx`, `first inbound RTP` on both sides, stage 6
  passes. On L4 `dsipctl turn-tail` shows both allocations and `dsipctl cap-rtp` shows the media —
  the one host in the testbed that ever carries any. Record `"turn": true` and the rhythm scores: media
  now crosses Atlanta, so compare `first_rtp_ms` and the scores with Run 1.
- **3c, forced:** whatever 3a did, run once more with `--relay-only` on both ends (the localhost
  `RUN3=1` case, now across hosts) so the relayed path is measured even when the NATs were kind.
- A failure here is a bug, not a finding: check 49160–49200/udp on L4's firewall first, then the
  credentials, then `RUST_LOG=warn,forge_webrtc=debug,forge_ice=debug`.

### Run 4 — partition, stale copies, freshness (finding 7)
1. Bob publishes with `--hint-ttl 120` from E-B via `RELAY_B`. Confirm `stored:1` on L1–L4.
2. Partition L3: in the Linode firewall for L3, drop inbound+outbound 4001/tcp (or on L3:
   `iptables -A INPUT -p tcp --dport 4001 -j DROP; iptables -A OUTPUT -p tcp --dport 4001 -j DROP`).
3. Bob quits and re-answers bound to **`RELAY_A`** with `--publish-hint`. New record has a newer `seq`
   and a different relay URI. L1/L2/L4 should show `puts_accepted:2`; L3 still holds the old one.
4. Lift the partition. Within one re-announce interval (60 s) L3 re-announces its *stale* record outward.
5. On L1: `dsipctl stats` — expect `puts_superseded` to increment (L3's stale copy lost to the newer
   seq). On L3: `dsipctl get $BOB_DID` — expect `.winner` to be the newer record (`RELAY_A`), and any
   old copy still returned to carry a `verdict` that lost on `seq`.
6. Stage 4 from E-A during the mixed window: resolve must print `RELAY_A`, not `RELAY_B`. Stage 5
   unchanged (the CA bundle covers both relays): call lands.
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
4. Implement per-peer inbound PUT rate limiting in `dsip-dht` (still not there as of this review),
   redeploy with a new `DSIP_REF` on every host, rerun, record the delta. That before/after pair is
   the headline for the findings update.

### Run 6 — the Messaging Profile across hosts
`demos/messaging-demo.sh` on two continents' worth of latency: Alice's mailbox on L1, Bob's on L2,
federation between them over the WAN, devices on E-A and E-B behind NAT. Identities are
`did:web:alice.example` / `did:web:bob.example`, resolved from files (see the scope notes).

1. **Documents.** On E-A, then the same for Bob on E-B with `$MBX_B` and L2's DID:
   ```bash
   source ~/dsip-wan/HOSTS.env; mkdir -p ~/dsip-wan/docs
   dsip-msg --state ~/dsip-wan/dev-a --identity did:web:alice.example --write-doc ~/dsip-wan/docs/alice.json \
     --mailbox-did "$(ssh root@L1 cat /var/lib/dsip/mailbox/service.did)" --mailbox-uri $MBX_A
   ```
   Copy **both** documents to `/var/lib/dsip/docs/` on L1 and L2 and to `~/dsip-wan/docs/` on both
   endpoints. The mailboxes read them when resolving; no restart.
2. **Devices.** On each endpoint (interactive; commands on stdin, one per line):
   ```bash
   dsip-msg --state ~/dsip-wan/dev-a --identity did:web:alice.example --ca $CA \
     --resolver-file ~/dsip-wan/docs/alice.json --resolver-file ~/dsip-wan/docs/bob.json 2>&1 | ts '%.s' | tee -a /tmp/msg-a.log
   ```
   Expect `OK connected`; on the mailbox, `dsipctl mailbox-tail` shows the device bound.
3. **First contact and a conversation.** Bob: `kp 3`, `grant did:web:alice.example` → a `GRANT <compact
   envelope>` line; put its second field in a file on E-A (`grep -m1 '^GRANT ' | cut -d' ' -f2`, after
   stripping the `ts` stamp); Bob: `live`. Alice: `kp 2`, `create direct did:web:bob.example <grant file>`
   → `OK conversation`; Bob logs `JOINED`. L1's log shows `federating to <L2's mailbox DID>`.
4. **Live text.** Alice: `send Dinner at 7?` → Bob: `RECV … Dinner at 7?`. Record `deliver_ms` from the
   two `ts` stamps (both clocks are chrony-disciplined; note the drift from `dsipctl drift`). Ten
   messages each way; record median and max.
5. **Store and forward.** Bob: `offline`. Alice sends three. Bob: `online`, `sync` → all three, in
   order, once. Then the hard version: `kill -9` Bob's `dsip-msg`, Alice sends, restart Bob with the same
   `--state` → `RESTORED`, then `sync` → the new message and **no** replay of old ones (M§5.4).
6. **Federation outage.** On L2: `systemctl stop dsip-mailbox`. Alice sends two. L1's log shows the dial
   failing and retrying with backoff (4 → 60 s). `systemctl start dsip-mailbox`: the mailbox reloads
   `mailbox-state.json`; Bob reconnects, `sync` → both messages, once. Record the time from restart to
   delivery. Then the other side: stop **L1** (Alice's mailbox is also the group's hub) and have Bob
   send — expect the deposit answered `mailbox.hub-unreachable` and the message held pending, then
   `accepted` after L1 returns (M§9.4, spec-gap 72). Do not leave L1 down past `--hub-timeout`
   (86,400 s) unless you mean to exercise the successor group.
7. **Voicemail blob over HTTPS.** Alice, with a real Opus file:
   `voicemail 01M2N6A0B1C2D3E4F5G6H7J8K9 user.no-answer /tmp/alice.ogg` → `OK sent audio purpose=voicemail`;
   Bob: `RECV-AUDIO … file=<path>`; `cmp` it against Alice's file. On L1: `ls /var/lib/dsip/mailbox/blobs/`
   holds one sealed blob and `grep -l OpusHead` finds nothing (the mailbox never sees plaintext). Repeat
   with Bob `offline` first: his mailbox fetches the blob itself on receipt — `replicated blob <sha256>
   (<n> bytes) from https://<L1>:9443/blobs/…` in L2's log (M§8.4 rule 6) — and Bob, back online, gets
   the audio from L2 even with L1's mailbox stopped. This is the step the two `dsip-mailbox` fixes were
   for: the PUT goes to the `blob_endpoint` the mailbox advertises, which must name a public address.
8. **Record:** `{"run":"6","commit":…,"deliver_ms":{"median":0,"max":0},"offline_sync_ms":0,
   "outage_recover_ms":0,"blob_bytes":0,"blob_put_ms":0,"blob_replicated":true,"pass":true}`.

---

## 4. Teardown / reset between runs
```bash
# any DHT host: drop all held records without restarting
printf '{"op":"shutdown"}\n' | nc -q1 127.0.0.1 4101; systemctl restart dsip-dht
# relays and mailboxes: the state dir holds the cert + key; don't delete it or every CA bundle goes stale
# mailboxes: to start Run 6 clean, stop the service and remove only state/mailbox/mailbox-state.json and
#            state/mailbox/blobs/ — and remove the devices' --state dirs with it, or they resume into a group the
#            mailbox has forgotten
# endpoints: call identities persist; recordings in /tmp
# L4: coturn keeps no state worth resetting; rotate TURN_PASS by deleting /var/lib/dsip/turn.pass and re-running setup
```

---

## 5. What to write up
A table in `docs/dht-findings.md`, "WAN results," with one row per run: hosts, NAT types, RTT,
`publish_acks`, `resolve_ms`, ICE pair + `ice_ms`, `first_rtp_ms`, rhythm scores, and the stats deltas
for Runs 2/4/5, and the commit. Then update the §8.5 risk list entries 1, 3, and 7 from "not measured
on WAN" to the measured numbers. Run 3 goes in as three rows (3a/3b/3c) with the NAT types: what STUN
alone managed, and what the TURN fallback cost in setup time and audio score. Run 2b's two numbers
(time to `session.timeout` / `transport.no-response`, and what a caller sees on a stale hint) argue
for or against the 600 s hint TTL. Run 6 gets its own short section — messaging has no findings
document yet; `docs/messaging-wan-results.md` is the place. Anything a run shows that the spec does
not say (a timer that is wrong for real RTTs, a retry that storms) ends as a `spec-gap` draft, as usual.
