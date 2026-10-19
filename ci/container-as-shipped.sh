#!/usr/bin/env bash
# The published image, run the way docker-compose.yml runs it: default
# USER patronus (non-root), cap_add NET_ADMIN + NET_RAW only, its sysctl, no
# patronus-applyd, no init. netlab runs everything as root (or with applyd),
# so it cannot see what an unprivileged patronus-web is refused by the
# kernel -- gateway adds and WireGuard tunnels failed with "RTNETLINK
# answers: Operation not permitted" in the shipped image because
# /usr/bin/ip had no file capability.
#
# Proves, from the API of the running container:
#   * a gateway, a load-balancing gateway group and the default gateway can
#     be configured (`ip route` table 4250 + `ip rule` 31000/31900 appear);
#   * a WireGuard tunnel + peer can be created (wg0 up with its address,
#     `wg show` lists the peer) and deleted again;
#   * IPsec (no root broker, no charon in the image) is refused up front with
#     501 naming what is missing and nothing is stored -- not a 500 halfway;
#   * with compose's `sysctls:` load balancing hashes by ports and the
#     Routing API shows no warning (without it, it warns: unit-tested in
#     patronus-network routes::tests).
#
# Usage: ci/container-as-shipped.sh <image>
# Everything it creates is removed on exit; the container is memory/CPU capped.
set -euo pipefail

IMAGE=${1:?usage: ci/container-as-shipped.sh <image>}
TAG=pas-${GITHUB_RUN_ID:-local}-$$
C=$TAG-web

log() { echo "[as-shipped] $*"; }
ok() { echo "[as-shipped] ok: $*"; }
fail() { echo "::error::[as-shipped] $*"; exit 1; }

cleanup() {
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "----- logs: $C -----"; docker logs --tail 80 "$C" 2>&1 || true
  fi
  docker rm -f -v "$C" >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT

# WireGuard is a kernel module: make sure the runner kernel has it loaded
# (an unprivileged container cannot trigger the module autoload itself).
docker run --rm --privileged --user 0 --network none --memory 128m --entrypoint sh "$IMAGE" -c \
  'ip link add wgprobe type wireguard && ip link del wgprobe' \
  || fail "the runner kernel has no WireGuard support"

# Exactly docker-compose.yml's privileges and sysctl (no --user, no --privileged).
docker run -d --name "$C" --cap-add NET_ADMIN --cap-add NET_RAW \
  --sysctl net.ipv4.fib_multipath_hash_policy=1 \
  --memory 1g --memory-swap 1g --cpus 1 -e RUST_LOG=info "$IMAGE" >/dev/null
[ "$(docker exec "$C" id -un)" = patronus ] || fail "image does not run as user patronus"

X() { docker exec "$C" "$@"; }
for _ in $(seq 1 60); do
  X curl -ksf -o /dev/null https://localhost:8443/login && break
  sleep 1
done
X curl -ksf -o /dev/null https://localhost:8443/login || fail "patronus-web did not come up"
PW=$(X cat /var/lib/patronus/initial-admin-password) || fail "no generated admin password"

OUT=
CODE=
# api METHOD PATH [JSON] -> $OUT body, $CODE status (session cookie in the container)
api() {
  local r
  r=$(X curl -ks -b /tmp/jar -c /tmp/jar -X "$1" -H 'Content-Type: application/json' \
        ${3:+--data "$3"} -w '\n%{http_code}' "https://localhost:8443/api$2")
  CODE=${r##*$'\n'}
  OUT=${r%$'\n'*}
}
must() { # CODE METHOD PATH [JSON]
  local want=$1; shift
  api "$@"
  [ "$CODE" = "$want" ] || fail "$1 $2 -> $CODE (want $want): $OUT"
}
must 200 POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}"
ok "logged in with the generated admin password"

# --- routing ---------------------------------------------------------------
GW=$(X ip -4 route show default | awk '{print $3; exit}')
DEV=$(X ip -4 route show default | awk '{print $5; exit}')
[ -n "$GW" ] && [ -n "$DEV" ] || fail "container has no default route"
must 201 POST /routing/gateways "{\"name\":\"WAN_GW\",\"interface\":\"$DEV\",\"address\":\"$GW\",\"monitor_ip\":\"$GW\"}"
must 201 POST /routing/gateways "{\"name\":\"ALT_GW\",\"interface\":\"$DEV\",\"address\":\"$GW\",\"monitor_enabled\":false}"
ok "gateways added (non-root, ip(8) via its file capability)"
must 201 POST /routing/groups '{"name":"LB","members":"WAN_GW:1, ALT_GW:1","trigger":"down"}'
must 200 PUT /routing/default '{"ipv4":"LB"}'
X ip -4 route show table 4250 | grep -q "via $GW" || fail "table 4250: $(X ip -4 route show table 4250)"
X ip -4 rule | grep -q '^31000:' || fail "ip rule 31000 missing: $(X ip -4 rule)"
X ip -4 rule | grep -q '^31900:' || fail "ip rule 31900 missing: $(X ip -4 rule)"
ok "default gateway group installed: table 4250 + rules 31000/31900"
# compose sets the hash policy (/proc/sys is read-only in here): no warning
[ "$(X cat /proc/sys/net/ipv4/fib_multipath_hash_policy)" = 1 ] || fail "compose sysctl not in effect"
api GET /routing
echo "$OUT" | grep -q fib_multipath_hash_policy && fail "hash policy is 1 but GET /api/routing warns: $OUT"
ok "load balancing hashes by ports (compose sysctl), no warning"
must 200 PUT /routing/default '{"ipv4":""}'
must 200 DELETE /routing/groups/LB
must 200 DELETE /routing/gateways/ALT_GW
must 200 DELETE /routing/gateways/WAN_GW
X ip -4 rule | grep -q '^31900:' && fail "rule 31900 left behind after the default was cleared"
ok "routing config removed again"

# --- WireGuard -------------------------------------------------------------
must 201 POST /vpn/wireguard/tunnels '{"addresses":"10.99.0.1/24","endpoint":"192.0.2.1","description":"as-shipped"}'
must 201 POST /vpn/wireguard/peers '{"interface":"wg0","name":"phone"}'
X ip -d link show wg0 | grep -q wireguard || fail "wg0 is not a wireguard link"
X ip -4 addr show wg0 | grep -q 10.99.0.1/24 || fail "wg0 has no 10.99.0.1/24"
X wg show wg0 peers | grep -q . || fail "wg show wg0 lists no peer"
X wg show wg0 listen-port | grep -q 51820 || fail "wg0 does not listen on 51820"
must 200 GET /vpn/wireguard/peers
ok "WireGuard tunnel wg0 + peer created and listed live"
must 200 DELETE /vpn/wireguard/tunnels/wg0
X ip link show wg0 >/dev/null 2>&1 && fail "wg0 still exists after delete"
ok "WireGuard tunnel deleted"

# --- IPsec: refused honestly without a root broker -------------------------
api GET /vpn
if echo "$OUT" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["features"].get("ipsec") else 1)'; then
  must 501 POST /vpn/ipsec/connections '{"name":"site-b","remote_address":"192.0.2.9","local_ts":"10.0.0.0/24","remote_ts":"10.1.0.0/24"}'
  echo "$OUT" | grep -q 'applyd' || fail "IPsec refusal does not say what is missing: $OUT"
  api GET /vpn
  echo "$OUT" | grep -q 'site-b' && fail "refused IPsec tunnel was stored: $OUT"
  ok "IPsec refused with 501 ($OUT), nothing stored"
fi

log "all checks passed"
