#!/usr/bin/env bash
# Run one of the browser-*.mjs WAN checks as a pair: Bob on relay B, Alice on relay A, each a headless browser.
#   URL_A=https://<relay-a>:8443/ URL_B=https://<relay-b>:8443/ tools/wan/browser-pair.sh message|call|presence|presence-audiences|presence-sealed
# Needs `playwright` beside the scripts (see browser-call.mjs); BROWSER=chromium for Chromium. Logs: w-<check>-{alice,bob}.log
# in the current directory; the last line of each is that side's JSON record.
set -u
: "${URL_A:?relay A's page}" "${URL_B:?relay B's page}"
S=$1; P=$(dirname "$0")/browser-$S.mjs; B=w-$S-bob.log; A=w-$S-alice.log; BR=${BROWSER:-firefox}
(ROLE=bob URL=$URL_B NAME=Bob BROWSER=$BR WAIT_S=300 node "$P" > "$B" 2>&1 &)
for _ in $(seq 60); do grep -q '"did"' "$B" 2>/dev/null && break; sleep 2; done
D=$(grep -m1 '"did"' "$B" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["did"])')
ROLE=alice URL=$URL_A NAME=Alice PEER=$D BROWSER=$BR node "$P" > "$A" 2>&1
for _ in $(seq 120); do [ "$(grep -c '^{' "$B")" -ge 2 ] && break; sleep 2; done
echo "ALICE: $(tail -1 "$A")"; echo "BOB: $(grep '^{' "$B" | tail -1)"
grep -q '"ok":true' <(tail -1 "$A") && grep '^{' "$B" | tail -1 | grep -q '"ok":true'
