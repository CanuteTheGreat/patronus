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
  # lanes J (feature pages) and K (SD-WAN edge) run as their own CI job
  # (netlab-features, `run.sh ci/netlab/lane-j-*.sh ci/netlab/lane-k-*.sh`);
  # NETLAB_ALL=1 puts them back into the default set for a full local run.
  set -- ci/netlab/lane-*.sh ci/netlab/journey-*.sh ci/netlab/failure-*.sh ci/netlab/upgrade-*.sh
  if [ -z "${NETLAB_ALL:-}" ]; then
    keep=()
    for s in "$@"; do case "$s" in */lane-j-*|*/lane-k-*|*/lane-n-*) ;; *) keep+=("$s") ;; esac; done
    set -- "${keep[@]}"
  fi
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
# lane N LDAP login: OpenLDAP (preseeded so the postinst needs no questions); installed here
# because scenarios that ran before it leave the container without working DNS
apt-get install -y -qq debconf-utils >/dev/null
printf 'slapd slapd/password1 password Ldap-Admin-Pw-1\\nslapd slapd/password2 password Ldap-Admin-Pw-1\\nslapd slapd/domain string example.net\\nslapd shared/organization string Example\\nslapd slapd/no_configuration boolean false\\n' | debconf-set-selections
apt-get install -y -qq slapd ldap-utils >/dev/null
# lane N scenarios (OpenVPN, Squid, UPnP, DHCPv6-PD): installed here while DNS still works
apt-get install -y -qq --no-install-recommends openvpn squid miniupnpc radvd isc-dhcp-server git >/dev/null
apt-get install -y -qq --no-install-recommends miniupnpd-nftables >/dev/null 2>&1 || apt-get install -y -qq --no-install-recommends miniupnpd >/dev/null
apt-get install -y -qq dhcpcd-base >/dev/null 2>&1 || apt-get install -y -qq dhcpcd5 >/dev/null 2>&1 || apt-get install -y -qq dhcpcd >/dev/null
# wg(8) only; its "recommends" would pull wireguard-dkms + kernel headers
apt-get install -y -qq --no-install-recommends wireguard-tools >/dev/null
export NETLAB_POWER_CUTS=${NETLAB_POWER_CUTS:-4}
$OLD_ENV
echo "--- netlab container: \$(uname -m), kernel \$(uname -r)"
grep Cap /proc/self/status
ip netns add probe && ip netns del probe && echo "network namespaces: ok"
cd /t
# scenarios share this container: leave nothing of the previous one behind
# (lanes J/K stop their own daemons but not the lib.sh DNS/HTTP helpers)
scrub() { pkill -f 'nl-dnsmasq.pid' 2>/dev/null || true; pkill -f '/t/(nl|lb)-[a-z0-9]+[.]py' 2>/dev/null || true; pkill -x 'suricata|bgpd|ospfd|zebra|staticd|mgmtd|xl2tpd|softflowd|igmpproxy|tayga|unbound|rsyslogd|patronus-web|patronus-dashboard' 2>/dev/null || true; for n in \$(ip netns list | cut -d' ' -f1); do ip netns del "\$n" 2>/dev/null || true; done; sleep 1; }
for s in $names; do scrub; echo "##### \$s"; start=\$(date +%s); bash "/t/\$s"; echo "##### \$s passed in \$((\$(date +%s) - start)) s"; done
INNER

case "$(uname -m)" in
  x86_64) PLATFORM=linux/amd64 ;;
  aarch64|arm64) PLATFORM=linux/arm64 ;;
  *) echo "unsupported build arch $(uname -m)"; exit 1 ;;
esac
# /dev/ppp lets the lane C test run a real PPPoE session (pppd needs it);
# fall back to no device on a host without the ppp driver.
# --device paths are resolved by the docker daemon on the HOST, so do not test
# for them inside this (job) container: a runner job container usually has no
# /dev/ppp even though the host does (create falls back below if it lacks it)
DEVS=(--device /dev/ppp --device /dev/net/tun)
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
