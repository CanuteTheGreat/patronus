#!/usr/bin/env bash
# Netlab: prove kernel state, not just API answers. Builds the SHIPPED
# binaries (patronus-cli as `patronus`, patronus-web), then runs every
# ci/netlab/lane-*.sh inside ONE capped sibling container that builds its own
# network namespaces + veth pairs (`ip netns` needs CAP_SYS_ADMIN; writable
# /proc/sys needs systempaths=unconfined; the container is still capped and
# not --privileged).
#
# Usage: ci/netlab/run.sh [scenario ...]
#   default: every lane-*.sh, journey-*.sh, failure-*.sh and upgrade-*.sh.
#   Scenarios source ci/netlab/lib.sh (topology + traffic/kernel assertions).
# Env passed into the container: NETLAB_POWER_CUTS (rounds of
# failure-power-cut.sh). PATRONUS_OLD_DIR=<dir with patronus +
# patronus-web of the previous release> enables the previous-release half of
# upgrade-store.sh (the nightly builds them).
#
# Same sibling-container pattern as ci/privileged-tests.sh: the Forgejo
# runner drops --cap-add from the job container, so the job builds and a
# docker sibling with real capabilities runs the tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${NETLAB_IMAGE:-catthehacker/ubuntu:act-latest}
C=netlab-${GITHUB_RUN_ID:-local}-$$
OUT=$(mktemp -d)
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$OUT"; }
trap cleanup EXIT

if [ $# -eq 0 ]; then
  set -- ci/netlab/lane-*.sh ci/netlab/journey-*.sh ci/netlab/failure-*.sh ci/netlab/upgrade-*.sh
fi

# NETLAB_BIN_DIR: use already-built patronus-cli + patronus-web from there.
BIN=${NETLAB_BIN_DIR:-}
if [ -z "$BIN" ]; then
  cargo build -p patronus-cli -p patronus-web -p patronus-dashboard --bins
  BIN=target/debug
fi
cp "$BIN/patronus-cli" "$OUT/patronus"
cp "$BIN/patronus-web" "$OUT/patronus-web"
# lane K (SD-WAN edge) runs a real dashboard
[ -f "$BIN/patronus-dashboard" ] && cp "$BIN/patronus-dashboard" "$OUT/patronus-dashboard"
for s in "$@"; do cp "$s" "$OUT/"; done
cp ci/netlab/lib.sh "$OUT/"
cp -r ci/netlab/fixtures "$OUT/"
OLD_ENV=
if [ -n "${PATRONUS_OLD_DIR:-}" ]; then
  mkdir -p "$OUT/old"
  cp "$PATRONUS_OLD_DIR/patronus" "$PATRONUS_OLD_DIR/patronus-web" "$OUT/old/"
  [ -f "$PATRONUS_OLD_DIR/version" ] && cp "$PATRONUS_OLD_DIR/version" "$OUT/old-version"
  OLD_ENV="export PATRONUS_OLD_BIN=/t/old/patronus PATRONUS_OLD_WEB=/t/old/patronus-web"
fi
names=$(for s in "$@"; do basename "$s"; done | tr '\n' ' ')

cat > "$OUT/inner.sh" <<INNER
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list.d/*ppa*.list /etc/apt/sources.list.d/*ppa*.sources
# installing a daemon package must not start it in this container (the
# scenarios start what they test, in their own namespaces)
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
for i in 1 2 3; do apt-get update -qq && break; [ "\$i" = 3 ] && exit 1; sleep 15; done
apt-get install -y -qq nftables iproute2 curl python3 dnsmasq-base conntrack sqlite3 iputils-ping >/dev/null
# lane J feature scenarios: rsyslog (syslog), softflowd (NetFlow), igmpproxy, tayga + unbound
# (NAT64/DNS64), xl2tpd + ppp (L2TP), suricata (IDS/IPS), frr (BGP/OSPF)
apt-get install -y -qq --no-install-recommends rsyslog softflowd igmpproxy tayga unbound xl2tpd ppp suricata frr >/dev/null
# wg(8) only; its "recommends" would pull wireguard-dkms + kernel headers
apt-get install -y -qq --no-install-recommends wireguard-tools >/dev/null
export NETLAB_POWER_CUTS=${NETLAB_POWER_CUTS:-4}
$OLD_ENV
echo "--- netlab container: \$(uname -m), kernel \$(uname -r)"
grep Cap /proc/self/status
ip netns add probe && ip netns del probe && echo "network namespaces: ok"
cd /t
for s in $names; do echo "##### \$s"; start=\$(date +%s); bash "/t/\$s"; echo "##### \$s passed in \$((\$(date +%s) - start)) s"; done
INNER

case "$(uname -m)" in
  x86_64) PLATFORM=linux/amd64 ;;
  aarch64|arm64) PLATFORM=linux/arm64 ;;
  *) echo "unsupported build arch $(uname -m)"; exit 1 ;;
esac
# /dev/ppp lets the lane C test run a real PPPoE session (pppd needs it);
# fall back to no device on a host without the ppp driver.
DEVS=()
for d in /dev/ppp /dev/net/tun; do [ -e "$d" ] && DEVS+=(--device "$d"); done
create() {
  docker create --name "$C" --platform "$PLATFORM" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN ${DEVS[@]+"${DEVS[@]}"} "$@" \
    --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
    --memory 2g --memory-swap 2g --cpus 2 -w /t "$IMAGE" bash /t/inner.sh >/dev/null
}
create 2>/dev/null || { echo "netlab: could not pass /dev/ppp and /dev/net/tun to the container"; docker rm -f "$C" >/dev/null 2>&1 || true; DEVS=(); create; }
docker cp "$OUT/." "$C:/t/"
docker start -a "$C"
rc=$(docker inspect -f '{{.State.ExitCode}}' "$C")
exit "$rc"
