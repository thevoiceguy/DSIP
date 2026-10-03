#!/usr/bin/env bash
# DSIP WAN testbed — an emulated NAT for Run 3 (both endpoints behind NAT) on one Linode.
#
# Bob runs inside network namespace `bobnat` (10.200.0.2) behind this host's public address:
#   natlab.sh up            create the namespace, veth pair, forwarding (idempotent)
#   natlab.sh mode cone     masquerade, source port kept when free: one socket → one public port for every
#                           destination, replies only from contacted peers (port-restricted cone)
#   natlab.sh mode symmetric  masquerade fully-random: a new public port per destination (symmetric NAT)
#   natlab.sh stun          classify the mapping from inside the namespace (two STUN servers, one socket)
#   natlab.sh run <cmd…>    run a command as Bob, inside the namespace
#   natlab.sh down          remove everything this script created
# Inbound connections to the namespace are never forwarded: only replies to flows Bob opened come back.
set -euo pipefail
NS=bobnat; HOST_IF=veth-nat; NS_IF=veth-bob; NET=10.200.0
WAN_IF=${WAN_IF:-$(ip -4 route show default | awk '{print $5; exit}')}

up() {
  ip netns list | grep -qw $NS || ip netns add $NS
  if ! ip link show $HOST_IF >/dev/null 2>&1; then
    ip link add $HOST_IF type veth peer name $NS_IF
    ip link set $NS_IF netns $NS
  fi
  ip addr replace $NET.1/24 dev $HOST_IF; ip link set $HOST_IF up
  ip netns exec $NS ip addr replace $NET.2/24 dev $NS_IF
  ip netns exec $NS ip link set $NS_IF up; ip netns exec $NS ip link set lo up
  ip netns exec $NS ip route replace default via $NET.1
  mkdir -p /etc/netns/$NS; echo "nameserver 1.1.1.1" > /etc/netns/$NS/resolv.conf
  sysctl -qw net.ipv4.ip_forward=1
  mode "${1:-cone}"
}

mode() {
  local flags=""
  case "$1" in
    cone) flags="" ;;
    symmetric) flags="fully-random" ;;
    *) echo "mode cone|symmetric" >&2; exit 2 ;;
  esac
  nft delete table ip dsipnat 2>/dev/null || true
  nft -f - <<NFT
table ip dsipnat {
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "$WAN_IF" oifname "$HOST_IF" ct state established,related accept
    iifname "$WAN_IF" oifname "$HOST_IF" drop
  }
  chain input {
    # Unsolicited inbound UDP is dropped here, before its conntrack entry is confirmed. Without this, a peer's
    # ICE checks that arrive before Bob's first packet to that peer leave an unreplied entry on Bob's mapped port,
    # and masquerade then gives Bob's outbound flow a different port: the NAT stops being endpoint-independent.
    type filter hook input priority 0; policy accept;
    iifname "$WAN_IF" meta l4proto udp ct state new drop
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr $NET.0/24 oifname "$WAN_IF" masquerade $flags
  }
}
NFT
  conntrack -F 2>/dev/null || true
  echo "nat mode: $1"
}

stun() {
  ip netns exec $NS python3 - <<'PY'
import socket, struct, os
def mapped(s, server):
    tid = os.urandom(12)
    s.sendto(struct.pack('!HHI', 1, 0, 0x2112A442) + tid, server)
    d, _ = s.recvfrom(2048); i = 20
    while i < len(d):
        t, l = struct.unpack('!HH', d[i:i+4]); v = d[i+4:i+4+l]
        if t == 0x20:
            port = struct.unpack('!H', v[2:4])[0] ^ 0x2112
            ip = socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], b'\x21\x12\xa4\x42')))
            return ip, port
        i += 4 + l + (-l % 4)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4); s.bind(('0.0.0.0', 0))
local = s.getsockname()[1]
a = mapped(s, ('172.232.220.162', 3478))                                  # L4 coturn
b = mapped(s, (socket.gethostbyname('stun.l.google.com'), 19302))         # an independent server
kind = "endpoint-independent mapping (cone)" if a[1] == b[1] else "endpoint-dependent mapping (symmetric)"
print(f"local port {local} → via L4 {a[0]}:{a[1]}, via google {b[0]}:{b[1]}: {kind}")
PY
}

down() {
  nft delete table ip dsipnat 2>/dev/null || true
  ip link del $HOST_IF 2>/dev/null || true
  ip netns del $NS 2>/dev/null || true
  rm -rf /etc/netns/$NS
  sysctl -qw net.ipv4.ip_forward=0
  echo "natlab removed"
}

case "${1:-}" in
  up) up "${2:-cone}" ;;
  mode) mode "${2:?cone|symmetric}" ;;
  stun) stun ;;
  run) shift; exec ip netns exec $NS "$@" ;;
  down) down ;;
  *) sed -n 2,13p "$0"; exit 2 ;;
esac
