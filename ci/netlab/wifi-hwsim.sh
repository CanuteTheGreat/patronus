#!/usr/bin/env bash
# Host-side runner for ci/netlab/lane-s-wifi-hwsim.sh (per-device Wi-Fi credentials
# on mac80211_hwsim). The kernel module is host-global, so this
#   1. takes a lock and refuses to run if mac80211_hwsim is already loaded,
#   2. loads it with 6 radios (modprobe: sudo when not root),
#   3. moves the new phys into the test container's network namespace
#      (`iw phy X set netns <pid>`, run by a throw-away --net=host --pid=host
#      helper container, so the host needs no `iw`),
#   4. runs the scenario in the container,
#   5. unloads the module again, whatever happened.
#
# Usage:
#   NETLAB_BIN_DIR=<dir with patronus-cli + patronus-web> ci/netlab/wifi-hwsim.sh
#   HWSIM_CONTAINER=<running container with /t, hostapd, wpa_supplicant, iw> ci/netlab/wifi-hwsim.sh
#
# Hosts with the module: rw-man-02/03 (x86_64, kernel 7.0), rw-man-04/05 (arm64,
# untested); rw-man-01 (kernel 6.8) has none. The scenario skips itself (exit 0,
# "SKIP") where it cannot run.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${NETLAB_IMAGE:-debian:trixie}
LOCK=${HWSIM_LOCK:-/tmp/patronus-hwsim.lock}
RADIOS=${HWSIM_RADIOS:-6}
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
C=${HWSIM_CONTAINER:-}
OWN=

exec 9>"$LOCK"
flock -n 9 || { echo "another hwsim run holds $LOCK"; exit 1; }
if grep -q '^mac80211_hwsim ' /proc/modules; then
  echo "mac80211_hwsim is already loaded on this host (another user?): refusing to touch it"; exit 1
fi
# load/unload the host-global module: directly (root or sudo on the host) or, from an unprivileged CI
# job container, through a throw-away privileged sibling that sees the host's /lib/modules
modctl() { # load|unload
  local cmd="rmmod mac80211_hwsim"
  [ "$1" = load ] && cmd="modprobe mac80211_hwsim radios=$RADIOS"
  if $SUDO $cmd >/dev/null 2>&1; then return 0; fi
  docker run --rm --privileged -v /lib/modules:/lib/modules:ro "$IMAGE" sh -c \
    "command -v modprobe >/dev/null || (apt-get update -qq >/dev/null && apt-get install -y -qq kmod >/dev/null); $cmd" >/dev/null 2>&1
}
modctl load || { echo "SKIP wifi-hwsim: this kernel has no mac80211_hwsim (rw-man-01's 6.8 kernel has none)"; exit 0; }

cleanup() {
  [ -n "$OWN" ] && docker rm -fv "$C" >/dev/null 2>&1 || true
  # phys that were moved into the container's namespaces come back to the host when those die
  sleep 1
  modctl unload || { sleep 2; modctl unload || echo "::warning::could not unload mac80211_hwsim"; }
}
trap cleanup EXIT

if [ -z "$C" ]; then
  OWN=1
  C=hwsim-$$
  BIN=${NETLAB_BIN_DIR:-target/debug}
  docker run -d --name "$C" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
    --memory 2g --cpus 2 "$IMAGE" sleep infinity >/dev/null
  docker exec "$C" bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq hostapd wpasupplicant iw nftables iproute2 curl python3 dnsmasq-base conntrack sqlite3 iputils-ping >/dev/null'
  docker exec "$C" mkdir -p /t
  docker cp "$BIN/patronus-cli" "$C:/t/patronus"; docker cp "$BIN/patronus-web" "$C:/t/patronus-web"
  docker cp ci/netlab/lib.sh "$C:/t/"; docker cp ci/netlab/lane-s-wifi-hwsim.sh "$C:/t/"
fi

PID=$(docker inspect -f '{{.State.Pid}}' "$C")
mapfile -t PHYS < <(ls /sys/class/ieee80211 | sort -V | tail -n "$RADIOS")
[ "${#PHYS[@]}" -eq "$RADIOS" ] || { echo "expected $RADIOS hwsim radios, found ${#PHYS[@]}"; exit 1; }
docker run --rm --net=host --pid=host --cap-add NET_ADMIN "$IMAGE" sh -c \
  "command -v iw >/dev/null || (apt-get update -qq >/dev/null && apt-get install -y -qq iw >/dev/null); for p in ${PHYS[*]}; do iw phy \$p set netns $PID || exit 1; done"
echo "--- ${#PHYS[@]} radios (${PHYS[*]}) moved into $C"
docker exec -e PATH="/opt/wifi/wrap:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$C" bash -c 'cd /t && chmod +x *.sh && ./lane-s-wifi-hwsim.sh'
