#!/usr/bin/env bash
# Host-side unit test of the leftover-module logic in ci/hwsim-lock.sh (hwsim_module_busy / hwsim_claim_module) against a
# FAKE /proc and /sys tree and a fake docker: an idle leftover is unloaded, and every sign of a live radio (use count,
# a radio moved into another namespace, a netdev with carrier, a hostapd process, a running hwsim container, a live loader
# container) makes the claim refuse and never unload. No radios, no root, nothing touches the real module.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
fails=0
mk() { # TOTAL_RADIOS VISIBLE_RADIOS REFCNT
  rm -rf "$W/p" "$W/s" "$W/bin"; mkdir -p "$W/p" "$W/s/bus/platform/drivers/mac80211_hwsim" "$W/s/class/ieee80211" "$W/bin"
  echo "mac80211_hwsim 139264 $3 - Live 0x0" > "$W/p/modules"
  local i
  for ((i = 0; i < $1; i++)); do mkdir -p "$W/s/bus/platform/drivers/mac80211_hwsim/hwsim$i"; done
  for ((i = 0; i < $2; i++)); do
    mkdir -p "$W/s/devices/hwsim$i/net/wlan$i"; echo 0x1003 > "$W/s/devices/hwsim$i/net/wlan$i/flags"   # IFF_UP only: the host brought it up, no carrier
    mkdir -p "$W/s/class/ieee80211/phy$i"; ln -s "$W/s/devices/hwsim$i" "$W/s/class/ieee80211/phy$i/device"   # as in real sysfs
  done
  cat > "$W/bin/docker" <<'D'
#!/bin/sh
case "$1 $2" in
  "ps -q") [ -n "${FAKE_RUNNING:-}" ] && echo abc123; exit 0;;
  "network inspect") [ -n "${FAKE_HOLDER:-}" ] && echo "$FAKE_HOLDER"; exit 0;;
  "container inspect") [ -n "${FAKE_HOLDER_ALIVE:-}" ]; exit $?;;
esac
exit 0
D
  chmod +x "$W/bin/docker"
}
t() { # NAME WANT(unload|refuse|noop)
  local out rc=0 got
  out=$(HWSIM_DOCKER="$W/bin/docker" HWSIM_PROBE_LOCAL=1 HWSIM_PROCROOT="$W/p" HWSIM_SYSROOT="$W/s" bash -c '
    . ci/hwsim-lock.sh
    hwsim_modctl() { echo UNLOADED; : > "$HWSIM_PROCROOT/modules"; }   # spy: the real rmmod is never called
    hwsim_claim_module 0' 2>&1) || rc=$?
  case "$out" in *UNLOADED*) got=unload;; *) [ "$rc" = 0 ] && got=noop || got=refuse;; esac
  if [ "$got" = "$2" ]; then echo "ok - $1"; else echo "FAIL - $1: got $got (rc=$rc) want $2"; echo "$out" | sed 's/^/    /'; fails=$((fails + 1)); fi
}
mk 3 3 0; t "idle leftover (radios visible, down, no daemon) -> unloaded" unload
mk 3 3 0; : > "$W/p/modules"; t "module not loaded -> nothing to do" noop
mk 3 3 2; t "use count != 0 -> refused" refuse
mk 4 0 0; t "all radios moved into another namespace -> refused" refuse
mk 4 3 0; t "one radio moved into another namespace -> refused" refuse
mk 3 3 0; echo 1 > "$W/s/devices/hwsim1/net/wlan1/carrier"; t "a radio netdev has carrier -> refused" refuse
mk 3 3 0; t "radios merely set UP by the host (no carrier) -> idle, unloaded" unload
mk 3 3 0; mkdir -p "$W/p/4242"; echo hostapd > "$W/p/4242/comm"; t "hostapd running -> refused" refuse
mk 3 3 0; mkdir -p "$W/p/4243"; echo wpa_supplicant > "$W/p/4243/comm"; printf 'wpa_supplicant\0-B\0-iwlan1\0' > "$W/p/4243/cmdline"; t "wpa_supplicant bound to a radio's netdev -> refused" refuse
mk 3 3 0; mkdir -p "$W/p/4245"; echo wpa_supplicant > "$W/p/4245/comm"; printf 'wpa_supplicant\0-u\0-s\0' > "$W/p/4245/cmdline"; t "the host's own dbus wpa_supplicant (no radio named) -> idle, unloaded" unload
mk 3 3 0; mkdir -p "$W/p/4244"; echo bash > "$W/p/4244/comm"; t "unrelated process -> still idle, unloaded" unload
mk 3 3 0; FAKE_RUNNING=1 t "a running hwsim test container -> refused" refuse
mk 3 3 0; FAKE_HOLDER=deadbeef0001 FAKE_HOLDER_ALIVE=1 t "loader's job container still alive -> refused" refuse
mk 3 3 0; FAKE_HOLDER=deadbeef0001 t "loader's job container gone (stale record) -> unloaded" unload
mk 3 3 0; rm -rf "$W/s/bus"; t "cannot read the radio list (no driver dir) -> idle only if nothing else live" unload
[ "$fails" = 0 ] || { echo "$fails hwsim reclaim test(s) failed"; exit 1; }
echo "PASS hwsim-reclaim-test"
