#!/usr/bin/env bash
# DSIP WAN testbed — base config for one host. Idempotent.
#
#   ROLE=bootstrap|dht|relay|mailbox|turn|stun|endpoint   (comma-separate to combine, e.g. ROLE=dht,relay)
#   PUBLIC_IP=<this host's public v4>       (auto-detected if unset)
#   DSIP_REF=<branch|tag|commit>            (default main; pin one commit for a whole campaign — every host the same)
#   PREBUILT=<dir>                          (optional: install binaries from here instead of building; see README §1)
#   DHT_SEED=<32-byte hex>                  (optional: fixed PeerId so bootstrap addrs survive restarts)
#   BOOTSTRAP=<multiaddr>[,<multiaddr>]     (required for ROLE=dht; omit for the bootstrap node itself)
#   RELAY_HOST=<dns name>                   (optional: extra SAN on the relay's and the mailbox's self-signed cert)
#   MAILBOX_OWNER=<did>                     (required for ROLE=mailbox: the identity this mailbox serves)
#   MAILBOX_DOCS="alice bob"                (names under /var/lib/dsip/docs/<name>.json the mailbox resolves from)
#   TURN_USER / TURN_PASS                   (ROLE=turn: long-term credential; default dsip / a generated password)
#
# Example:
#   ROLE=bootstrap,relay,mailbox MAILBOX_OWNER=did:web:alice.example DHT_SEED=$(openssl rand -hex 32) ./node-setup.sh  # L1
#   ROLE=dht,relay,mailbox MAILBOX_OWNER=did:web:bob.example BOOTSTRAP=/ip4/1.2.3.4/tcp/4001/p2p/12D3... ./node-setup.sh # L2
#   ROLE=dht        BOOTSTRAP=... ./node-setup.sh                               # L3
#   ROLE=dht,turn   BOOTSTRAP=... ./node-setup.sh                               # L4 (coturn: STUN and TURN)
#   ROLE=endpoint ./node-setup.sh                                               # NAT'd box (no daemons)
set -euo pipefail
ROLE=${ROLE:?set ROLE}
PUBLIC_IP=${PUBLIC_IP:-$(curl -4 -s https://ifconfig.me || hostname -I | awk '{print $1}')}
DSIP_REF=${DSIP_REF:-main}
SRC=/opt/dsip-src; BIN=/usr/local/bin; STATE=/var/lib/dsip; LOG=/var/log/dsip
DHT_PORT=4001; RELAY_PORT=8443; MAILBOX_PORT=9443
BINS="dsip dsip-relay dsip-dht-node dsip-mailbox dsip-msg"
has(){ [[ ",$ROLE," == *",$1,"* ]]; }

echo "== $(hostname) role=$ROLE public=$PUBLIC_IP ref=$DSIP_REF"

# ---- packages ----------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git curl python3 python3-numpy ffmpeg espeak-ng tcpdump netcat-openbsd jq iproute2 chrony \
  moreutils openssl
if has stun || has turn; then apt-get install -y -q coturn; fi
systemctl enable --now chrony   # envelope replay window is 300 s; clocks must agree
mkdir -p $STATE $LOG $STATE/docs

# ---- binaries: prebuilt, or build here ---------------------------------------
if [ -n "${PREBUILT:-}" ]; then
  for b in $BINS; do install -m755 "$PREBUILT/$b" $BIN/$b; done
  [ -f "$PREBUILT/COMMIT" ] && cp "$PREBUILT/COMMIT" $STATE/commit
else
  # perl + make: forge-media vendors OpenSSL. The toolchain itself comes from impl/rust-toolchain.toml
  # (rustup installs the pinned channel on the first cargo run in impl/).
  apt-get install -y -q build-essential pkg-config libssl-dev cmake clang perl make
  if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
  fi
  source "$HOME/.cargo/env"
  if [ -d $SRC/.git ]; then git -C $SRC fetch -q --tags origin; else git clone -q https://github.com/thevoiceguy/DSIP.git $SRC; fi
  git -C $SRC checkout -q "$DSIP_REF"
  # a branch follows its remote; a tag or a commit stays where it is
  if git -C $SRC symbolic-ref -q HEAD >/dev/null; then git -C $SRC merge -q --ff-only "origin/$DSIP_REF"; fi
  git -C $SRC rev-parse HEAD > $STATE/commit
  # A release build of the whole set wants ~3 GB of RAM and ~6 GB of disk: build on a 4 GB host (or the
  # endpoint box) and hand the result to the small ones with PREBUILT.
  ( cd $SRC/impl && cargo build -q --release -p dsip-cli -p dsip-relay -p dsip-dht -p dsip-mailbox )
  mkdir -p $STATE/prebuilt
  for b in $BINS; do
    install -m755 $SRC/impl/target/release/$b $BIN/$b
    install -m755 $SRC/impl/target/release/$b $STATE/prebuilt/$b
  done
  cp $STATE/commit $STATE/prebuilt/COMMIT
  echo "Prebuilt set for the other hosts: $STATE/prebuilt  (scp -r it, then PREBUILT=<dir> ./node-setup.sh)"
fi
echo "PUBLIC_IP=$PUBLIC_IP" > $STATE/env
echo "commit: $(cat $STATE/commit 2>/dev/null || echo unknown)"

# ---- DHT node (bootstrap or member) ------------------------------------------
if has bootstrap || has dht; then
  SEEDARG=""
  if [ -n "${DHT_SEED:-}" ]; then echo "$DHT_SEED" > $STATE/dht.seed; fi
  [ -f $STATE/dht.seed ] && SEEDARG="--seed $(cat $STATE/dht.seed)"
  BOOTARG=""
  if [ -n "${BOOTSTRAP:-}" ]; then
    echo "$BOOTSTRAP" > $STATE/bootstrap
    for b in ${BOOTSTRAP//,/ }; do BOOTARG="$BOOTARG --bootstrap $b"; done
  fi
  : > $LOG/dht.log   # the PeerId is read from the first `peer:` line below: never an earlier run's
  cat > /etc/systemd/system/dsip-dht.service <<UNIT
[Unit]
Description=DSIP reachability-hints DHT node
After=network-online.target chrony.service
[Service]
ExecStart=$BIN/dsip-dht-node --listen /ip4/0.0.0.0/tcp/$DHT_PORT --control 127.0.0.1:4101 --republish 60 $SEEDARG $BOOTARG
Restart=always
StandardOutput=append:$LOG/dht.log
StandardError=append:$LOG/dht.log
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable dsip-dht; systemctl restart dsip-dht
  sleep 2
  # Compose the shareable bootstrap multiaddr from the KNOWN public IP + listen port + PeerId.
  # Do NOT grep the node's own `listening:` lines and rewrite 0.0.0.0: libp2p expands the wildcard
  # into one NewListenAddr per interface (loopback + any docker/private bridges, loopback often
  # FIRST) and never emits a literal 0.0.0.0 line — so a first-match + s#0.0.0.0# rewrite yields an
  # unreachable 127.0.0.1 bootstrap addr. The PeerId is stable (pinned by DHT_SEED when set); the
  # public IP and port are known here, so build the addr ourselves.
  PEER=$(grep -m1 '^peer: ' $LOG/dht.log | cut -d' ' -f2)
  if [ -z "$PEER" ]; then echo "!! could not read PeerId from $LOG/dht.log — is dsip-dht up?" >&2; exit 1; fi
  ADDR="/ip4/$PUBLIC_IP/tcp/$DHT_PORT/p2p/$PEER"
  echo "$ADDR" > $STATE/my-multiaddr
  echo "DHT multiaddr (give this to other nodes as --bootstrap):"; echo "   $ADDR"
fi

# ---- relay -------------------------------------------------------------------
HOSTARG="--host $PUBLIC_IP"; [ -n "${RELAY_HOST:-}" ] && HOSTARG="$HOSTARG --host $RELAY_HOST"
if has relay; then
  cat > /etc/systemd/system/dsip-relay.service <<UNIT
[Unit]
Description=DSIP relay (wss)
After=network-online.target chrony.service
[Service]
ExecStart=$BIN/dsip-relay --listen 0.0.0.0:$RELAY_PORT --state $STATE/relay $HOSTARG
Restart=always
StandardOutput=append:$LOG/relay.log
StandardError=append:$LOG/relay.log
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable dsip-relay; systemctl restart dsip-relay
  sleep 1.5
  echo "Relay cert (goes into every endpoint's CA bundle): $STATE/relay/cert.pem"
  echo "Relay URL: wss://$PUBLIC_IP:$RELAY_PORT/dsip"
fi

# ---- mailbox + hub (Messaging Profile 1.0) ------------------------------------
if has mailbox; then
  OWNER=${MAILBOX_OWNER:?ROLE=mailbox needs MAILBOX_OWNER=<identity DID>}
  DOCARG=""; for n in ${MAILBOX_DOCS:-alice bob}; do DOCARG="$DOCARG --resolver-file $STATE/docs/$n.json"; done
  # The DID documents and the CA bundle are read when used, so both may arrive after the service starts.
  cat > /etc/systemd/system/dsip-mailbox.service <<UNIT
[Unit]
Description=DSIP mailbox and hub service (wss + blob endpoint, one TLS port)
After=network-online.target chrony.service
[Service]
ExecStart=$BIN/dsip-mailbox --listen 0.0.0.0:$MAILBOX_PORT --state $STATE/mailbox --owner $OWNER $HOSTARG --ca $STATE/ca-all.pem $DOCARG
Restart=always
StandardOutput=append:$LOG/mailbox.log
StandardError=append:$LOG/mailbox.log
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable dsip-mailbox; systemctl restart dsip-mailbox
  sleep 1.5
  echo "Mailbox DID:  $(cat $STATE/mailbox/service.did)"
  echo "Mailbox URI:  wss://$PUBLIC_IP:$MAILBOX_PORT/dsip   cert: $STATE/mailbox/cert.pem"
fi

# ---- STUN / TURN (coturn) ------------------------------------------------------
if has stun || has turn; then
  {
    echo "listening-port=3478"; echo "listening-ip=0.0.0.0"; echo "external-ip=$PUBLIC_IP"
    echo "fingerprint"; echo "no-cli"; echo "no-tls"; echo "no-dtls"
    echo "log-file=/var/log/turnserver.log"; echo "simple-log"
    if has turn; then
      TURN_USER=${TURN_USER:-dsip}
      TURN_PASS=${TURN_PASS:-$(cat $STATE/turn.pass 2>/dev/null || openssl rand -hex 12)}
      echo "$TURN_PASS" > $STATE/turn.pass; chmod 600 $STATE/turn.pass
      echo "lt-cred-mech"; echo "realm=dsip.test"; echo "user=$TURN_USER:$TURN_PASS"
      echo "min-port=49160"; echo "max-port=49200"    # open this UDP range in the cloud firewall
    else
      echo "stun-only"
    fi
  } > /etc/turnserver.conf
  sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
  systemctl enable coturn; systemctl restart coturn
  echo "STUN: $PUBLIC_IP:3478"
  if has turn; then echo "TURN: turn:$PUBLIC_IP:3478  user $TURN_USER  pass $TURN_PASS   (relay ports 49160-49200/udp)"; fi
fi

# ---- endpoint: identity dirs only --------------------------------------------
if has endpoint; then
  mkdir -p $STATE/ids
  for n in alice bob; do
    [ -d $STATE/ids/$n ] || dsip identity init --dir $STATE/ids/$n --name ${n^}
    echo "$n: $(jq -r .identity $STATE/ids/$n/identity.json)"
  done
fi

echo "== done. logs in $LOG; state in $STATE"
