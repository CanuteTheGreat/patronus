#!/usr/bin/env bash
# Host-side runner for ci/netlab/lane-s-wifi-hwsim.sh (per-device Wi-Fi credentials
# on mac80211_hwsim), lane-s-wifi-chan-hwsim.sh (automatic channel choice) and lane-t-guest-wifi.sh (the guest SSID); HWSIM_SCENARIOS picks others. The kernel module is host-global, so this
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
# Hosts with the module: rw-man-02/03 (x86_64, kernel 7.0; the hwsim-x86_64 runner lane), rw-man-04/05
# (arm64, untested); rw-man-01 (kernel 6.8) has none. Where the module cannot be loaded, or a scenario
# prints SKIP, the run FAILS (HWSIM_ALLOW_SKIP=1 turns that into a skip for a local run) and ends with one
# "HWSIM SUMMARY: ... executed=N" line (ci/hwsim-lock.sh).
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=${NETLAB_IMAGE:-debian:trixie}
RADIOS=${HWSIM_RADIOS:-6}
SCENARIOS=${HWSIM_SCENARIOS:-lane-s-wifi-hwsim.sh lane-s-wifi-chan-hwsim.sh lane-t-guest-wifi.sh}
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
C=${HWSIM_CONTAINER:-}
OWN=

# host-wide mutex (docker network; job containers do not share /tmp, see ci/hwsim-lock.sh)
. ci/hwsim-lock.sh
trap 'hwsim_lock_drop' EXIT
hwsim_lock_take || exit 1
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
modctl load || hwsim_skip_or_fail "this kernel has no mac80211_hwsim (rw-man-01's 6.8 kernel has none)"

cleanup() {
  [ -n "$OWN" ] && docker rm -fv "$C" >/dev/null 2>&1 || true
  # phys that were moved into the container's namespaces come back to the host when those die
  sleep 1
  modctl unload || { sleep 2; modctl unload || echo "::warning::could not unload mac80211_hwsim"; }
  hwsim_lock_drop
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
  docker cp ci/netlab/lib.sh "$C:/t/"; for s in $SCENARIOS; do docker cp "ci/netlab/$s" "$C:/t/"; done
fi

PID=$(docker inspect -f '{{.State.Pid}}' "$C")
# The phys appear in the HOST's network namespace. A CI job container has its own namespace (and sysfs),
# where /sys/class/ieee80211 is empty even though the module is loaded ("expected 6 hwsim radios, found
# 0" in the nightly), so ask a --net=host sibling, which sees the host's sysfs, instead of looking locally.
host_phys() {
  docker run --rm --net=host "$IMAGE" sh -c 'ls /sys/class/ieee80211 2>/dev/null' | sort -V | tail -n "$RADIOS"
}
mapfile -t PHYS < <(host_phys)
[ "${#PHYS[@]}" -eq "$RADIOS" ] || { echo "expected $RADIOS hwsim radios, found ${#PHYS[@]}"; exit 1; }
docker run --rm --net=host --pid=host --cap-add NET_ADMIN "$IMAGE" sh -c \
  "command -v iw >/dev/null || (apt-get update -qq >/dev/null && apt-get install -y -qq iw >/dev/null); for p in ${PHYS[*]}; do iw phy \$p set netns $PID || exit 1; done"
echo "--- ${#PHYS[@]} radios (${PHYS[*]}) moved into $C"
for s in $SCENARIOS; do
  hwsim_run "$s" docker exec -e PATH="/opt/wifi/wrap:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$C" bash -c "cd /t; bash ./$s"
done
hwsim_summary
