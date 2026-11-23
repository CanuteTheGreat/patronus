#!/bin/sh
# Host test (no root, no hwsim, no docker) for the stale-module reaper in ci/hwsim-lock.sh: a mac80211_hwsim that a
# cancelled/killed run left loaded is unloaded by the next run, anything in use is waited for. Fake /proc/modules,
# /proc/<pid>/comm and /sys/class/{ieee80211,net}. `sh ci/embedded-aarch64/ax1800/tests/hwsim-stale-test.sh`
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/hwsim-stale.XXXX"); trap 'rm -rf "$W"' EXIT
pass=0; failn=0
ok() { echo "PASS: $*"; pass=$((pass+1)); }
no() { echo "FAIL: $*"; failn=$((failn+1)); }
. "$ROOT/ci/hwsim-lock.sh"
HWSIM_STALE_DIRECT=1; export HWSIM_STALE_DIRECT

# mkproc PID COMM NETNS CMDLINE...: fake /proc/PID (NETNS 1 = host namespace)
mkproc() { pid=$1; cm=$2; ns=$3; shift 3; mkdir -p "$R/proc/$pid/ns" "$R/proc/$pid/root"; echo "$cm" > "$R/proc/$pid/comm"
  ln -sf "net:[$ns]" "$R/proc/$pid/ns/net"; printf '%s\0' "$@" > "$R/proc/$pid/cmdline"; }
# mk NAME REFCNT: a stale-looking host (3 hwsim phys, interfaces wl24-m wl5-m wsta in the host namespace, no process)
mk() {
  R=$W/$1; rm -rf "$R"; mkdir -p "$R/proc" "$R/sys/class/ieee80211" "$R/sys/class/net"
  echo "mac80211_hwsim 106496 $2 - Live 0x0000000000000000" > "$R/proc/modules"
  echo "cfg80211 1000000 1 mac80211_hwsim, Live 0x0" >> "$R/proc/modules"
  i=0; for n in wl24-m wl5-m wsta; do
    mkdir -p "$R/sys/class/ieee80211/phy$i" "$R/sys/class/net/$n"
    ln -s "../../../devices/virtual/mac80211_hwsim/hwsim$i" "$R/sys/class/ieee80211/phy$i/device"
    ln -s "../ieee80211/phy$i" "$R/sys/class/net/$n/phy80211"; i=$((i+1)); done
  mkdir -p "$R/proc/1/ns" "$R/proc/4242"; echo systemd > "$R/proc/1/comm"; echo sshd > "$R/proc/4242/comm"; ln -s 'net:[1]' "$R/proc/1/ns/net"
  # the runner host's own system wpa_supplicant (pid 986 on rw-man-03): in the host namespace, handles no hwsim interface
  mkproc 986 wpa_supplicant 1 "wpa_supplicant -u -s -O DIR=/run/wpa_supplicant GROUP=netdev"
  HWSIM_PROC=$R/proc; HWSIM_SYS=$R/sys; export HWSIM_PROC HWSIM_SYS
}
probe() { hwsim_stale_probe; }
expect() { # NAME WANT_RC
  out=$(probe 2>&1); rc=$?
  if [ "$rc" = "$2" ]; then ok "$1 (rc=$rc: $out)"; else no "$1: wanted rc=$2, got $rc: $out"; fi; }

mk a 0; expect "leftover of a killed bandsteer run (use count 0, 3 phys, test names, no process) is stale" 0
mk b 1; expect "use count 1 is in use" 1
mk c 0; mkproc 777 hostapd 2 hostapd -B /etc/ap.conf; expect "a hostapd in a job container (other network namespace) keeps it" 1
mk d 0; mkproc 778 wpa_supplicant 1 wpa_supplicant -B -i wl24-m -c /x.conf; expect "a host-namespace wpa_supplicant on -i wl24-m keeps it" 1
mk e 0; mkproc 779 iw 2 iw dev; expect "an iw in a container keeps it" 1
mk e2 0; mkproc 780 hostapd 1 hostapd -B /conf/ap.conf; mkdir -p "$R/proc/780/root/conf"; printf 'interface=wl5-m\nssid=x\n' > "$R/proc/780/root/conf/ap.conf"
expect "a host-namespace hostapd whose config file names wl5-m keeps it" 1
mk e3 0; mkproc 781 hostapd 1 hostapd -B /conf/other.conf; mkdir -p "$R/proc/781/root/conf"; printf 'interface=wlp3s0\n' > "$R/proc/781/root/conf/other.conf"
expect "a host-namespace hostapd on an unrelated interface does not" 0
mk f 0; mv "$R/sys/class/net/wsta" "$R/sys/class/net/wlan0"; expect "a phy whose interface has a foreign name (wlan0) keeps it" 1
mk g 0; rm -r "$R/sys/class/net/wsta"; expect "a phy with no interface in the host namespace (moved into a container) keeps it" 1
mk h 0; mkdir -p "$R/sys/class/ieee80211/phy9" "$R/sys/class/net/wlp3s0"; ln -s ../../../devices/pci0000:00/0000:03:00.0 "$R/sys/class/ieee80211/phy9/device"
ln -s ../ieee80211/phy9 "$R/sys/class/net/wlp3s0/phy80211"; expect "a real (non hwsim) radio is ignored" 0
mk i 0; : > "$R/proc/modules"; expect "module not loaded" 2

# the wait loop: a leftover is unloaded (the unload command edits the fake /proc/modules) and the run goes on
mk j 0; export HWSIM_POLL_SEC=1
unl() { : > "$HWSIM_PROC/modules"; echo unloaded >> "$W/unl.log"; }; rm -f "$W/unl.log"
out=$(HWSIM_WAIT_MIN=1 hwsim_wait_free unl 2>&1); rc=$?
case "$out" in *"stale mac80211_hwsim from a killed run: unloaded"*) m=1;; *) m=0;; esac
[ "$rc" = 0 ] && [ "$m" = 1 ] && [ "$(cat "$W/unl.log" 2>/dev/null)" = unloaded ] && ok "hwsim_wait_free unloads a leftover and logs it" || no "hwsim_wait_free leftover: rc=$rc out=$out"
# a module in use is never unloaded: waits, then refuses
mk k 0; mkdir "$R/proc/800"; echo hostapd > "$R/proc/800/comm"; rm -f "$W/unl.log"
out=$(HWSIM_WAIT_MIN=0 hwsim_wait_free unl 2>&1); rc=$?
case "$out" in *"still loaded after 0 min"*) m=1;; *) m=0;; esac
[ "$rc" = 1 ] && [ "$m" = 1 ] && [ ! -e "$W/unl.log" ] && ok "hwsim_wait_free keeps waiting while hostapd runs, never unloads, then refuses" || no "hwsim_wait_free in use: rc=$rc out=$out"
# a module that is not loaded returns at once
mk l 0; : > "$R/proc/modules"; hwsim_wait_free unl >/dev/null 2>&1 && ok "hwsim_wait_free returns at once when nothing is loaded" || no "hwsim_wait_free not loaded"
# every script that loads the module goes through the helper
for f in ci/netlab/wifi-hwsim.sh ci/embedded-aarch64/ax1800/tests/xbss-hwsim.sh ci/embedded-aarch64/ax1800/tests/bandsteer-hwsim.sh ci/embedded-aarch64/ax1800/tests/steer-hwsim.sh; do
  if grep 'hwsim_wait_free\|hwsim_stale_probe' "$ROOT/$f" >/dev/null; then ok "$f uses the stale-module helper"; else no "$f does not use the stale-module helper"; fi; done
echo "hwsim stale-module tests: $pass passed, $failn failed"
[ "$failn" = 0 ]
