#!/usr/bin/env bash
# xbss-hwsim.sh: host-side runner for xbss-scenario.sh on mac80211_hwsim (x86_64 rw-man-02/03; the module is
# host-global: lock, refuse if loaded, load 3 radios, move them into a test container, always unload).
# Proves the Patronus hostapd (hostapd/APKBUILD, patronus-xbss.diff) deletes a station on the old BSS of a radio BEFORE
# creating it on the new one, and that the same scenario with Alpine's stock hostapd shows the overlap the IPQ6018
# firmware asserts on (so the check can go red). Then automatic channel selection (acs-scenario.sh) with the configs the
# image's `ap render` writes, regulatory domain US (host-global like the module: set for the run, reset to 00 after).
# Usage: ci/embedded-aarch64/ax1800/tests/xbss-hwsim.sh   (SCENARIOS="xbss acs" by default)
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=${XBSS_IMAGE:-alpine:3.24}
LOCK=${HWSIM_LOCK:-/tmp/patronus-hwsim.lock}
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
DOCKER="${DOCKER:-$SUDO docker}"
exec 9>"$LOCK"; flock -n 9 || { echo "another hwsim run holds $LOCK"; exit 1; }
if grep -q '^mac80211_hwsim ' /proc/modules; then echo "mac80211_hwsim already loaded (another user?): refusing"; exit 1; fi
C=xbss-hwsim-$$
KIMG=${KMOD_IMAGE:-debian:trixie}
# load/unload the host-global module: directly (root/sudo on the host) or, from a CI job container, through a
# throw-away privileged sibling that sees the host's /lib/modules (as ci/netlab/wifi-hwsim.sh does)
modctl() { local cmd="rmmod mac80211_hwsim"; [ "$1" = load ] && cmd="modprobe mac80211_hwsim radios=3"
  if $SUDO $cmd >/dev/null 2>&1; then return 0; fi
  $DOCKER run --rm --privileged -v /lib/modules:/lib/modules:ro "$KIMG" sh -c \
    "command -v modprobe >/dev/null || (apt-get update -qq >/dev/null && apt-get install -y -qq kmod >/dev/null); $cmd" >/dev/null 2>&1; }
regset() { $DOCKER run --rm --net=host --cap-add NET_ADMIN "$IMAGE" sh -c "apk add -q --no-cache iw >/dev/null && iw reg set $1" >/dev/null 2>&1; }
cleanup() { $DOCKER rm -fv "$C" >/dev/null 2>&1 || true; regset 00 || true; sleep 1; modctl unload || { sleep 2; modctl unload || echo "could not unload mac80211_hwsim"; }; }
trap cleanup EXIT
$DOCKER run -d --name "$C" --cap-add NET_ADMIN --cap-add NET_RAW --security-opt apparmor=unconfined \
  --memory 2g --cpus 2 "$IMAGE" sleep infinity >/dev/null
$DOCKER exec "$C" apk add -q --no-cache bash hostapd wpa_supplicant iw iproute2 abuild build-base openssl-dev libnl3-dev linux-headers
$DOCKER exec "$C" mkdir -p /w/h
tar -cf - stage-hostapd.sh hostapd tests/xbss-scenario.sh tests/acs-scenario.sh overlay/usr/libexec/patronus/ap overlay/etc/patronus/board.sh \
  | $DOCKER exec -i "$C" tar -xf - -C /w/h
echo "--- building the Patronus hostapd package (x86_64, same APKBUILD as the image)"
$DOCKER exec "$C" sh -c 'mkdir -p /out /cache && bash /w/h/stage-hostapd.sh >/dev/null && mkdir -p /opt/ph && tar -xzf /out/hostapd/*/hostapd-2.11-r1*.apk -C /opt/ph usr/sbin/hostapd 2>/dev/null; /opt/ph/usr/sbin/hostapd -v 2>&1 | head -1'
modctl load || { echo "SKIP: no mac80211_hwsim on this kernel"; exit 0; }
PID=$($DOCKER inspect -f '{{.State.Pid}}' "$C")
PHYS=$($DOCKER run --rm --net=host "$IMAGE" sh -c 'ls /sys/class/ieee80211' | sort -V | tail -n 3); [ "$(echo $PHYS | wc -w)" = 3 ] || { echo "expected 3 hwsim radios"; exit 1; }
$DOCKER run --rm --net=host --pid=host --cap-add NET_ADMIN "$IMAGE" sh -c \
  "apk add -q --no-cache iw && for p in $(echo $PHYS); do iw phy \$p set netns $PID || exit 1; done"
echo "--- radios $PHYS moved into $C"
rc=0
case " ${SCENARIOS:-xbss acs} " in *" xbss "*)
echo "=== stock hostapd (Alpine): the overlap must be visible"
$DOCKER exec -e HOSTAPD=/usr/sbin/hostapd -e EXPECT=overlap "$C" sh /w/h/tests/xbss-scenario.sh || rc=1
echo "=== Patronus hostapd"
$DOCKER exec -e HOSTAPD=/opt/ph/usr/sbin/hostapd -e EXPECT=sync "$C" sh /w/h/tests/xbss-scenario.sh || rc=1;; esac
case " ${SCENARIOS:-xbss acs} " in *" acs "*)
echo "=== automatic channel selection (Patronus hostapd, ap render configs, regulatory domain US)"
regset US || { echo "could not set the regulatory domain"; rc=1; }
$DOCKER exec -e HOSTAPD=/opt/ph/usr/sbin/hostapd -e AP_DIR=/w/h/overlay ${ACS_CASES:+-e ACS_CASES="$ACS_CASES"} "$C" sh /w/h/tests/acs-scenario.sh || rc=1;; esac
exit $rc
