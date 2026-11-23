#!/usr/bin/env bash
# bandsteer-hwsim.sh: proves on mac80211_hwsim (no radio) that ap-steer's band steering (docs 12.18b) moves a dual-band
# station from a unit's 2.4 GHz BSS to the SAME unit's 5 GHz BSS of the same SSID WITHOUT a disconnect, that a station
# that cannot or will not go stays connected on 2.4 GHz, and that a station that comes back is left alone.
#
# Host: an x86 Linux host with docker, sudo and the mac80211_hwsim module (and wireless-regdb); run it ON that host from a
# checkout:  ci/embedded-aarch64/ax1800/tests/bandsteer-hwsim.sh . Takes the host-wide hwsim lock (ci/hwsim-lock.sh),
# refuses when the module is already loaded, unloads it at the end.
#  - 3 radios in a privileged debian:trixie container (hostapd 2.10, wpa_supplicant 2.10): namespace `ap` = ONE unit with
#    two radios (wl24-m on channel 1, wl5-m on channel 36 at 80 MHz, SSID "Home Net", WPA2-PSK, both bridged in br-lan
#    to the `lan` namespace with the server 192.168.77.1), namespace `sta` = the station (wpa_supplicant, 192.168.77.50).
#    The hostapd configs come from the image's `ap render` (fake board/sysfs, as tests/run.sh), only the control socket
#    directory changes, so bss_transition/rrm are the product's. hostapd_cli -a ap-event per BSS (answers + cross-band
#    cleanup), the real ap-steer loop (AP_STEER=off: only band steering; interval 10 s, AP_BANDSTEER_AFTER=20,
#    AP_STEER_RETRY=60 so the cycle can repeat).
#  - MOVE: CYCLES (3) times: the station sits on 2.4 GHz (joined before the 5 GHz radio starts, or sent back with
#    `wpa_cli roam`), the unit asks it to 5 GHz. Measured per move: lost replies / longest gap of `ping -i 0.1`,
#    CTRL-EVENT-DISCONNECTED (must be 0), seconds until it is on the 5 GHz BSS, ap-steer's history events.
#  - BACK: the return to 2.4 GHz is recorded (band-back) and the station is not asked again within the hold.
#  - STAY24: the station is limited to 2.4 GHz (network freq_list=2412, like a 2.4-only client): asked, declines, stays
#    connected on 2.4 GHz, no disconnect; not asked again within AP_STEER_RETRY.
# The last line is RESULT_JSON {...}; non-zero exit when a move disconnected the station, did not reach 5 GHz, or a
# declining station lost its connection. Env: CYCLES, KEEP=1, IMAGE, HWSIM_REQUIRED=1 (CI: no module = failure).
set -euo pipefail
SELF=$(readlink -f "$0"); cd "$(dirname "$SELF")/.."
IMAGE=${IMAGE:-debian:trixie}
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
DOCKER="${DOCKER:-$SUDO docker}"
HWSIM_DOCKER=$DOCKER; . ../../hwsim-lock.sh
C=bandsteer-hwsim-$$
LOADED=
WD=$(mktemp -d)
KIMG=${KMOD_IMAGE:-debian:trixie}
# load/unload the host-global module: directly (root/sudo on the host) or, from a CI job container, through a throw-away
# privileged sibling that sees the host's /lib/modules (as xbss-hwsim.sh)
modctl() { local cmd="rmmod mac80211_hwsim"; [ "$1" = load ] && cmd="modprobe mac80211_hwsim radios=3"
  if $SUDO $cmd >/dev/null 2>&1; then return 0; fi
  $DOCKER run --rm --privileged -v /lib/modules:/lib/modules:ro "$KIMG" sh -c \
    "command -v modprobe >/dev/null || (apt-get update -qq >/dev/null && apt-get install -y -qq kmod >/dev/null); $cmd" >/dev/null 2>&1; }
cleanup() { rc=$?
  if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: container $C, workdir $WD, module and lock left in place"; exit $rc; fi
  $DOCKER exec "$C" iw reg set 00 >/dev/null 2>&1 || true
  $DOCKER rm -fv "$C" >/dev/null 2>&1 || true
  if [ -n "$LOADED" ]; then sleep 1; modctl unload || { sleep 3; modctl unload || echo "could not unload mac80211_hwsim"; }; fi
  hwsim_lock_drop
  rm -rf "$WD"
  exit $rc; }
trap cleanup EXIT
hwsim_lock_take || exit 1
# the module is host-global and may belong to a run in another job container (older runners may not take the lock): wait
# for it to go away, but unload a leftover of a killed run at once (hwsim_wait_free, ci/hwsim-lock.sh)
hwsim_wait_free "modctl unload" || exit 1
echo "--- container $C ($IMAGE), packages"
$DOCKER run -d --name "$C" --privileged --security-opt apparmor=unconfined "$IMAGE" sleep infinity >/dev/null
$DOCKER exec "$C" sh -c 'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq hostapd wpasupplicant iw iproute2 python3-minimal iputils-ping procps >/dev/null 2>&1; hostapd -v 2>&1 | head -1; wpa_supplicant -v | head -1'
tar -cf "$WD/ov.tar" overlay/usr/libexec/patronus/ap overlay/usr/libexec/patronus/ap-steer overlay/usr/libexec/patronus/ap-event overlay/etc/patronus/board.sh
$DOCKER exec "$C" mkdir -p /w/ov && $DOCKER exec -i "$C" tar -xf - -C /w/ov < "$WD/ov.tar"
sed -n '/^#--INNER-BEGIN/,/^#--INNER-END/p' "$SELF" > "$WD/inner.sh"; $DOCKER cp "$WD/inner.sh" "$C:/w/inner.sh"
modctl load || { echo "SKIP: no mac80211_hwsim on this kernel"; [ "${HWSIM_REQUIRED:-0}" = 1 ] && exit 1; exit 0; }
LOADED=1
PHYS=$($DOCKER run --rm --net=host "$IMAGE" sh -c 'ls /sys/class/ieee80211' | sort -V | tail -n 3); [ "$(echo $PHYS | wc -w)" = 3 ] || { echo "expected 3 hwsim radios, got: $PHYS"; exit 1; }
PID=$($DOCKER inspect -f '{{.State.Pid}}' "$C")
$DOCKER run --rm --net=host --pid=host --cap-add NET_ADMIN "$IMAGE" sh -c \
  "apt-get update -qq >/dev/null && apt-get install -y -qq iw >/dev/null 2>&1; for p in $(echo $PHYS); do iw phy \$p set netns $PID || exit 1; done"
echo "--- radios $PHYS moved into $C"
set -- $PHYS
rc=0
$DOCKER exec -e PHY24=$1 -e PHY5=$2 -e PHYSTA=$3 -e CYCLES="${CYCLES:-3}" "$C" bash /w/inner.sh || rc=$?
$DOCKER cp "$C:/w/out/result.json" "$WD/result.json" 2>/dev/null && echo "RESULT_JSON $(cat "$WD/result.json")"
exit $rc

#--INNER-BEGIN
#!/bin/bash
# runs inside the container as root. Env: PHY24 PHY5 PHYSTA CYCLES
set -u
O=/w/ov/overlay; W=/w; R=$W/r; L=$W/log; OUT=$W/out; mkdir -p "$R" "$L" "$OUT"
SSID="Home Net"; PSK=hwsim-band-test; SRV=192.168.77.1; STAIP=192.168.77.50; CTRL=/run/hostapd-u
WPALOG=$L/wpa.log
say() { echo "[$(date +%H:%M:%S)] $*"; }
ns() { local n=$1; shift; ip netns exec "$n" "$@"; }
fail=0; bad() { say "FAIL: $*"; fail=1; }
tnow() { date +%s.%N; }
wcli() { ns sta wpa_cli -p /run/wpa-sta -i wsta "$@"; }
hcli() { local i=$1; shift; ns ap hostapd_cli -p $CTRL -i "$i" "$@"; }
iw reg set US; sleep 1
for n in ap sta lan; do ip netns add $n; done
iw phy "$PHY24" set netns name ap; iw phy "$PHY5" set netns name ap; iw phy "$PHYSTA" set netns name sta
ren() { local n=$1 phy=$2 new=$3 old; old=$(ns $n iw dev | awk -v p="phy#${phy#phy}" '$0 == p { f = 1; next } /^phy#/ { f = 0 } f && /Interface/ { print $2; exit }')
  ns $n ip link set "$old" down; ns $n ip link set "$old" name "$new"; }
ren ap "$PHY24" wl24-m; ren ap "$PHY5" wl5-m; ren sta "$PHYSTA" wsta
ip -n lan link add brL type bridge; ip -n lan link set brL up
ip link add srvh netns lan type veth peer name srvb netns lan
ip -n lan link set srvb master brL up; ip -n lan addr add $SRV/24 dev srvh; ip -n lan link set srvh up; ip -n lan link set lo up
ip link add vl netns lan type veth peer name vp netns ap; ip -n lan link set vl master brL up
ns ap ip link add br-lan type bridge; ns ap ip link set br-lan up; ns ap ip link set vp master br-lan up; ns ap ip link set lo up
ns sta ip link set lo up; ns sta ip addr add $STAIP/24 dev wsta
M24=$(ns ap cat /sys/class/net/wl24-m/address); M5=$(ns ap cat /sys/class/net/wl5-m/address); STAMAC=$(ns sta cat /sys/class/net/wsta/address)
# configs from the product's `ap render` (the fake radios carry the real MACs so the BSSIDs match)
mkdir -p $R/sys/phy0 $R/sys/phy1; echo "$M5" > $R/sys/phy0/macaddress; echo "$M24" > $R/sys/phy1/macaddress
printf '. %s\nAP_COUNTRY=US AP_CHAN24=1 AP_CHAN5=36 AP_HT5=80 AP_HE=0 AP_HTCAPS24="[SHORT-GI-20]" AP_HTCAPS5="[SHORT-GI-20][SHORT-GI-40]" AP_VHTCAPS5="[SHORT-GI-80]"\nAP_SSIDS=m\nSSID_m="%s" KEY_m=%s SEC_m=wpa2\n' \
  $O/etc/patronus/board.sh "$SSID" "$PSK" > $R/board.sh
AP_BOARD=$R/board.sh AP_RENDER_OUT=$R/u AP_SYSFS=$R/sys AP_PHY5=phy0 AP_PHY24=phy1 sh $O/usr/libexec/patronus/ap render > $R/render.log 2>&1
for b in 24 5; do f=$R/u/ap$b.conf; [ -s $f ] || { cat $R/render.log; bad "ap render wrote no ap$b.conf"; exit 1; }
  sed -i "/^patronus_/d; s#/run/hostapd#$CTRL#" $f
  grep "^interface=wl$b-m$" $f > /dev/null || { bad "ap$b.conf: unexpected interface: $(grep ^interface= $f)"; exit 1; }; done
grep -h '^bss_transition\|^rrm_\|^channel=\|^vht_oper' $R/u/ap24.conf $R/u/ap5.conf | tr '\n' ' '; echo "(from ap render)"
mkdir -p $CTRL
start_ap() { # BAND
  ns ap hostapd -B -t -P $L/hostapd-$1.pid -f $L/hostapd-$1.log $R/u/ap$1.conf || bad "hostapd $1"
  for i in $(seq 60); do hcli wl$1-m status 2>/dev/null | grep state=ENABLED >/dev/null && break; sleep 0.5; done
  hcli wl$1-m status | grep state=ENABLED >/dev/null || { bad "hostapd $1 not enabled"; tail -15 $L/hostapd-$1.log; exit 1; }
  ns ap env AP_STEER_STATE=$W/st AP_CTRL=$CTRL AP_RENDER_OUT=$R/u hostapd_cli -B -P $L/cli-$1.pid -p $CTRL -i wl$1-m -a $O/usr/libexec/patronus/ap-event
  ns ap ip link set wl$1-m master br-lan 2>/dev/null || true; }
board() { printf '. %s\nAP_STEER=off AP_BANDSTEER=on AP_BANDSTEER_AFTER=20 AP_STEER_INTERVAL=10 AP_STEER_REPORT=active AP_STEER_RETRY=60 AP_STEER_RETRY_MAX=60 %s\n' \
  $R/board.sh "$*" > $W/board.new; mv $W/board.new $W/board.sh; }
start_ap 24
bssid_of() { hcli wl$1-m status | sed -n 's/^bssid\[0\]=//p' | tr 'A-F' 'a-f'; }
B24=$(bssid_of 24); say "2.4 GHz BSS $B24 (rendered: $(sed -n 's/^bssid=//p' $R/u/ap24.conf | head -1)), station $STAMAC"
cat > $L/sta.conf <<X
ctrl_interface=/run/wpa-sta
update_config=0
network={
  ssid="$SSID"
  psk="$PSK"
  key_mgmt=WPA-PSK
}
X
ns sta wpa_supplicant -B -t -i wsta -c $L/sta.conf -f $WPALOG -P $L/wpa.pid || bad "wpa_supplicant"
waitfor() { local what=$1 tmo=$2; shift 2; local i; for i in $(seq $((tmo * 2))); do "$@" && return 0; sleep 0.5; done; bad "timeout waiting for $what"; return 1; }
cur_bss() { wcli status 2>/dev/null | sed -n 's/^bssid=//p'; }
on_bss() { [ "$(cur_bss)" = "$1" ] && wcli status | grep wpa_state=COMPLETED >/dev/null; }
waitfor "station on 2.4 GHz" 40 on_bss $B24 || { tail -20 $WPALOG; exit 1; }
start_ap 5
B5=$(bssid_of 5); say "5 GHz BSS $B5 (rendered: $(sed -n 's/^bssid=//p' $R/u/ap5.conf | head -1))"
say "station on 2.4 GHz; capabilities hostapd sees: $(hcli wl24-m sta $STAMAC | grep -E '^(ext_capab|supp_op_classes|capability)=' | tr '\n' ' ')"
ns sta ping -c 3 -W 1 $SRV >/dev/null && say "station reaches the server over 2.4 GHz" || bad "no ping over 2.4 GHz"
mkdir -p $W/st $W/db; board
ns ap env AP_BOARD=$W/board.sh AP_RENDER_OUT=$R/u AP_STEER_STATE=$W/st AP_STEER_DB=$W/db AP_CTRL=$CTRL AP_STEER_PID=$L/steer.pid \
  sh $O/usr/libexec/patronus/ap-steer run >> $L/steer.log 2>&1 &
pingstat() { awk -v a="$2" -v b="$3" '/^\[[0-9.]+\].*icmp_seq=/ { ts = substr($1, 2) + 0; if (ts < a || ts > b) next
      match($0, /icmp_seq=[0-9]+/); s = substr($0, RSTART + 9, RLENGTH - 9) + 0; n++
      if (n == 1) f = s; else { g = (ts - pt) * 1000; if (g > mg) mg = g }; pt = ts; l = s }
    END { printf "%d %d %.0f\n", n, (n ? l - f + 1 - n : 0), mg }' "$1"; }
wpa_ev() { awk -v a="$2" -v b="$3" -v p="$1" '{ ts = $1 + 0; if (ts >= a && ts <= b && $0 ~ p) n++ } END { print n + 0 }' $WPALOG; }
wpa_first() { awk -v a="$2" -v p="$1" '{ ts = $1 + 0; if (ts >= a && $0 ~ p) { printf "%.3f\n", ts; exit } }' $WPALOG; }
hist_win() { [ -f $W/db/history ] && awk -v a="${1%.*}" -v b="${2%.*}" '{ if (match($0, /"t":[0-9]+/)) { t = substr($0, RSTART + 4, RLENGTH - 4) + 0
      if (t >= a && t <= b && match($0, /"event":"[a-z-]+"/)) { printf "%s%s", s, substr($0, RSTART + 9, RLENGTH - 10); s = "," } } }' $W/db/history; }
PINGF=; PINGP=
ping_start() { PINGF=$L/ping-$1.log; ip netns exec sta ping -D -i 0.1 -W 1 $SRV > $PINGF 2>&1 & PINGP=$!; sleep 1; }
ping_stop() { kill $PINGP 2>/dev/null; wait $PINGP 2>/dev/null || true; }
json_add() { echo "$2" >> $OUT/$1.jsonl; }
to24() { local k i; for k in 1 2 3; do wcli bssid_ignore clear >/dev/null 2>&1; wcli roam $B24 >/dev/null; for i in $(seq 20); do on_bss $B24 && return 0; sleep 0.5; done; done; return 1; }

move() { # LABEL: wait until the unit asks the station to 5 GHz and it is there
  local lbl=$1 t0 got= i; on_bss $B24 || { bad "$lbl: station not on 2.4 GHz"; return 1; }
  ping_start $lbl; t0=$(tnow)
  for i in $(seq 240); do got=$(wpa_first "CTRL-EVENT-CONNECTED - Connection to $B5" "$t0"); [ -n "$got" ] && break; sleep 1; done
  sleep 8; local t2; t2=$(tnow); ping_stop
  [ -n "$got" ] || bad "$lbl: the station did not reach 5 GHz within 240 s"
  set -- $(pingstat $PINGF "$t0" "$t2"); local rcv=$1 lost=$2 gap=$3
  local dis; dis=$(wpa_ev "CTRL-EVENT-DISCONNECTED" "$t0" "$t2"); [ "$dis" -gt 0 ] && bad "$lbl: CTRL-EVENT-DISCONNECTED seen ($dis)"
  local rt=-; [ -n "$got" ] && rt=$(awk -v a="$got" -v b="$t0" 'BEGIN { printf "%.1f", a - b }')
  local hs; hs=$(hist_win "$t0" "$t2"); [ -z "$hs" ] && hs=-
  grep -q "\"event\":\"band-btm\",\"mac\":\"$STAMAC\"" $W/db/history || bad "$lbl: no band-btm in the history"
  say "$lbl: on 5 GHz after ${rt}s (from watch start) lost=$lost max_gap_ms=$gap disconnect_events=$dis history=$hs"
  json_add move "{\"move\":\"$lbl\",\"reached_5ghz\":$([ -n "$got" ] && echo true || echo false),\"seconds\":\"$rt\",\"replies\":$rcv,\"lost\":$lost,\"max_gap_ms\":$gap,\"disconnect_events\":$dis,\"history\":\"$hs\"}"
  true; }

say "=== MOVE: $CYCLES cycles"
n=0; while [ $n -lt "${CYCLES:-3}" ]; do n=$((n + 1))
  move "move$n"
  if [ $n -lt "${CYCLES:-3}" ]; then
    sleep 5; tb=$(tnow); to24 || bad "could not send the station back to 2.4 GHz"; say "sent back to 2.4 GHz (wpa_cli roam)"
    sleep 25; grep -q "\"event\":\"band-back\",\"mac\":\"$STAMAC\"" $W/db/history || bad "back on 2.4 GHz not recorded"
    # within the hold (AP_STEER_RETRY=60 since the return) it must not be asked again
    a=$(awk -v a="${tb%.*}" -v m="$STAMAC" 'index($0, "\"event\":\"band-btm\",\"mac\":\"" m "\"") { match($0, /"t":[0-9]+/); if (substr($0, RSTART + 4, RLENGTH - 4) + 0 >= a) n++ } END { print n + 0 }' $W/db/history)
    [ "$a" = 0 ] || bad "asked again $a time(s) within the hold after the return"
  fi
done
say "=== STAY24: station limited to 2.4 GHz (freq_list=2412)"
sleep 5; to24 || bad "could not send the station back to 2.4 GHz"; wcli set_network 0 freq_list 2412 >/dev/null; sleep 70
ping_start stay; t0=$(tnow)
asks_since() { awk -v a="${1%.*}" -v m="$STAMAC" 'index($0, "\"event\":\"band-btm\",\"mac\":\"" m "\"") { match($0, /"t":[0-9]+/); if (substr($0, RSTART + 4, RLENGTH - 4) + 0 >= a) n++ } END { print n + 0 }' $W/db/history; }
for i in $(seq 150); do [ "$(asks_since "$t0")" -ge 1 ] && break; sleep 1; done
board AP_STEER_RETRY=600 AP_STEER_RETRY_MAX=600   # once asked: not again within AP_STEER_RETRY
sleep 60; t2=$(tnow); ping_stop
set -- $(pingstat $PINGF "$t0" "$t2"); lost=$2; gap=$3
dis=$(wpa_ev "CTRL-EVENT-DISCONNECTED" "$t0" "$t2")
asks=$(asks_since "$t0")
ans=$(grep "\"event\":\"btm-answer\",\"mac\":\"$STAMAC\"" $W/db/history | tail -1 | sed -n 's/.*"detail":"\([^"]*\)".*/\1/p')
on_bss $B24 || bad "stay24: the station is not on 2.4 GHz any more"
[ "$dis" = 0 ] || bad "stay24: disconnected ($dis)"; [ "$asks" = 1 ] || bad "stay24: asked $asks times (want 1 within AP_STEER_RETRY)"
stay="asked $asks time(s); answer: ${ans:-none}; still on 2.4 GHz; lost=$lost max_gap_ms=$gap disconnect_events=$dis"
say "stay24: $stay"
say "=== ap-steer status"; ns ap env AP_BOARD=$W/board.sh AP_RENDER_OUT=$R/u AP_STEER_STATE=$W/st AP_STEER_DB=$W/db AP_CTRL=$CTRL sh $O/usr/libexec/patronus/ap-steer status 2>&1 | head -14
kill $(cat $L/steer.pid) 2>/dev/null || true
python3 - "$OUT" "$stay" "$fail" <<'PY'
import sys, json
d, stay, fail = sys.argv[1], sys.argv[2], sys.argv[3]
try: mv = [json.loads(l) for l in open(d + '/move.jsonl') if l.strip()]
except FileNotFoundError: mv = []
print('%-8s %-6s %-5s %-7s %-5s %s' % ('move', '5 GHz', 'lost', 'gap ms', 'disc', 'seconds'))
for r in mv: print('%-8s %-6s %-5d %-7d %-5d %s' % (r['move'], 'yes' if r['reached_5ghz'] else 'no', r['lost'], r['max_gap_ms'], r['disconnect_events'], r['seconds']))
open(d + '/result.json', 'w').write(json.dumps({'moves': mv, 'stay24': stay, 'ok': fail == '0'}))
PY
say "done, fail=$fail"; exit $fail
#--INNER-END
