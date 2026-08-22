#!/usr/bin/env bash
# DSIP WAN testbed — base config for one host. Idempotent.
#
#   ROLE=bootstrap|dht|relay|endpoint|stun  (comma-separate to combine, e.g. ROLE=dht,relay)
#   PUBLIC_IP=<this host's public v4>       (auto-detected if unset)
#   DHT_SEED=<32-byte hex>                  (optional: fixed PeerId so bootstrap addrs survive restarts)
#   BOOTSTRAP=<multiaddr>[,<multiaddr>]     (required for ROLE=dht; omit for the bootstrap node itself)
#   RELAY_HOST=<dns name>                   (optional: extra SAN on the relay's self-signed cert)
#
# Example:
#   ROLE=bootstrap,relay DHT_SEED=$(openssl rand -hex 32) ./node-setup.sh      # L1
#   ROLE=dht,relay BOOTSTRAP=/ip4/1.2.3.4/tcp/4001/p2p/12D3... ./node-setup.sh  # L2
#   ROLE=dht        BOOTSTRAP=... ./node-setup.sh                               # L3
#   ROLE=dht,stun   BOOTSTRAP=... ./node-setup.sh                               # L4
#   ROLE=endpoint ./node-setup.sh                                               # NAT'd box (no daemons)
set -euo pipefail
ROLE=${ROLE:?set ROLE}
PUBLIC_IP=${PUBLIC_IP:-$(curl -4 -s https://ifconfig.me || hostname -I | awk '{print $1}')}
SRC=/opt/dsip-src; BIN=/usr/local/bin; STATE=/var/lib/dsip; LOG=/var/log/dsip
DHT_PORT=4001
has(){ [[ ",$ROLE," == *",$1,"* ]]; }

echo "== $(hostname) role=$ROLE public=$PUBLIC_IP"

# ---- packages ----------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git curl build-essential pkg-config libssl-dev cmake clang \
  python3 python3-numpy ffmpeg espeak-ng tcpdump netcat-openbsd jq iproute2 chrony
has stun && apt-get install -y -q coturn
systemctl enable --now chrony   # envelope replay window is 300 s; clocks must agree

# ---- rust --------------------------------------------------------------------
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
source "$HOME/.cargo/env"

# ---- source + build (endpoints need the CLI too) -----------------------------
if [ -d $SRC/.git ]; then git -C $SRC pull -q; else git clone -q https://github.com/thevoiceguy/DSIP.git $SRC; fi
( cd $SRC/impl && cargo build -q --release -p dsip-cli -p dsip-relay -p dsip-dht )
install -m755 $SRC/impl/target/release/dsip          $BIN/dsip
install -m755 $SRC/impl/target/release/dsip-relay    $BIN/dsip-relay
install -m755 $SRC/impl/target/release/dsip-dht-node $BIN/dsip-dht-node
mkdir -p $STATE $LOG
echo "PUBLIC_IP=$PUBLIC_IP" > $STATE/env

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
  systemctl daemon-reload; systemctl enable --now dsip-dht; systemctl restart dsip-dht
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
if has relay; then
  HOSTARG="--host $PUBLIC_IP"; [ -n "${RELAY_HOST:-}" ] && HOSTARG="$HOSTARG --host $RELAY_HOST"
  cat > /etc/systemd/system/dsip-relay.service <<UNIT
[Unit]
Description=DSIP relay (wss)
After=network-online.target chrony.service
[Service]
ExecStart=$BIN/dsip-relay --listen 0.0.0.0:8443 --state $STATE/relay $HOSTARG
Restart=always
StandardOutput=append:$LOG/relay.log
StandardError=append:$LOG/relay.log
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable --now dsip-relay; systemctl restart dsip-relay
  sleep 1.5
  echo "Relay cert (copy to every endpoint as --ca): $STATE/relay/cert.pem"
  echo "Relay URL: wss://$PUBLIC_IP:8443/dsip"
fi

# ---- STUN (coturn in STUN-only mode; forge-ice has no TURN client yet) ------
if has stun; then
  cat > /etc/turnserver.conf <<CONF
listening-port=3478
listening-ip=0.0.0.0
external-ip=$PUBLIC_IP
stun-only
no-cli
log-file=/var/log/turnserver.log
simple-log
CONF
  sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
  systemctl enable --now coturn; systemctl restart coturn
  echo "STUN: $PUBLIC_IP:3478"
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
