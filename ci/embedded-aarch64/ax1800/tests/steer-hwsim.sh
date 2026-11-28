#!/usr/bin/env bash
# steer-hwsim.sh: proves on mac80211_hwsim (no radio) that ap-steer's soft steering (docs 12.18) moves a station from one
# access point of a network to the other WITHOUT a disconnect, and measures the outage of the old hard kick for comparison.
#
# What it does (host: an x86 Linux host with docker, sudo and the mac80211_hwsim module; run it ON that host, from a
# checkout:  ci/embedded-aarch64/ax1800/tests/steer-hwsim.sh ; refuses when the module is already loaded by someone
# else, the module is host-global; unloads it again at the end, as it resets the regulatory domain):
#  - loads mac80211_hwsim with 3 radios, moves them into a privileged debian:trixie container (hostapd 2.10, wpa_supplicant
#    2.10), where each radio lives in its own network namespace: apA, apB (one hostapd each, SSID "Home Net", WPA2-PSK,
#    2.4 GHz channels 1 and 6, bridged with br-lan to a `lan` namespace that holds the server 192.168.77.1) and sta
#    (wpa_supplicant, 192.168.77.50). The hostapd configs are written by the image's `ap render` (fake board, fake sysfs,
#    as tests/run.sh does), only the interface names and the control socket directory are changed, so bss_transition=1,
#    rrm_neighbor_report=1 and rrm_beacon_report=1 are the product's. hostapd_cli -a ap-event per BSS queues the answers.
#  - runs the real ap-steer loop on both units (own state/history, peers files naming the other unit, AP_STEER_SIGNAL=-10
#    because hwsim reports every station at about -30 dBm, AP_STEER_MARGIN=0 because both units sound alike, interval 10 s,
#    after 30 s, daytime clock). Real hostapd_cli and iw: no AP_STEER_DUMP_DIR, no AP_CLI.
#  - SOFT: SOFT_CYCLES (5) times A->B then B->A. Steering is switched on at the unit the station sits on only (AP_STEER in
#    the board file, re-read every round). Measured per move from `ping -i 0.1` station->server (lost replies, longest
#    gap between two replies), wpa_supplicant events (CTRL-EVENT-DISCONNECTED must not appear), hostapd's BSS-TM-RESP /
#    BEACON-RESP-RX, and ap-steer's history (measure, btm, btm-answer, roamed).
#  - HARD: the old behaviour (hostapd_cli deny_acl ADD_MAC on the station), HARD_RUNS (5) times, measured the same way.
#  - NIGHT: AP_STEER_CLOCK=02:00, a station that ignores move requests (wpa_cli set disable_btm 1): it is disconnected
#    only after AP_STEER_BTM_WAIT, and only when it has had no traffic for AP_STEER_QUIET_IDLE.
# The unit is told to forget a returning station quickly (AP_STEER_RETRY=20, normally hours) so the loop can be repeated;
# a beacon request that stays unanswered makes ap-steer fall back to the plain move request after about 2 minutes.
# Takes about 40 minutes with the defaults (5 soft moves each way, 5 hard kicks, night path).
# Everything ends with one JSON object on the last line (RESULT_JSON ...) and a table; non-zero exit when a soft move
# disconnected the station, did not reach the other unit, or the setup failed.
# Env: SOFT_CYCLES, HARD_RUNS, NIGHT=1|0, KEEP=1 (leave container + module for debugging), IMAGE (debian:trixie).
# Rerun:  git clone -b ap-soft-steering <repo> p && bash p/ci/embedded-aarch64/ax1800/tests/steer-hwsim.sh
set -euo pipefail
SELF=$(readlink -f "$0"); cd "$(dirname "$SELF")/.."
IMAGE=${IMAGE:-debian:trixie}
SUDO=; [ "$(id -u)" = 0 ] || SUDO=sudo
DOCKER="${DOCKER:-$SUDO docker}"
HWSIM_DOCKER=$DOCKER; . ../../hwsim-lock.sh
C=steer-hwsim-$$
WD=$(agent-workdir new steer-hwsim 2>/dev/null || mktemp -d)
cleanup() { rc=$?
  if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: container $C, workdir $WD, module and lock left in place"; exit $rc; fi
  $DOCKER exec "$C" iw reg set 00 >/dev/null 2>&1 || true
  $DOCKER rm -fv "$C" >/dev/null 2>&1 || true
  sleep 1; hwsim_unload
  hwsim_lock_drop
  command -v agent-workdir >/dev/null 2>&1 && agent-workdir done "$WD" >/dev/null 2>&1 || rm -rf "$WD"
  exit $rc; }
trap cleanup EXIT
hwsim_lock_take || exit 1
HWSIM_KMOD_IMAGE=$IMAGE
# a leftover is unloaded when provably idle; a module in use (another user's radios) is never touched
hwsim_claim_module "${HWSIM_MODULE_WAIT_MIN:-0}" || exit 1
echo "--- container $C ($IMAGE), packages"
$DOCKER run -d --name "$C" --privileged --security-opt apparmor=unconfined "$IMAGE" sleep infinity >/dev/null
$DOCKER exec "$C" sh -c 'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq hostapd wpasupplicant iw iproute2 bridge-utils python3-minimal iputils-ping procps >/dev/null 2>&1; hostapd -v 2>&1 | head -1; wpa_supplicant -v | head -1'
# the files under test
tar -cf "$WD/ov.tar" overlay/usr/libexec/patronus/ap overlay/usr/libexec/patronus/ap-steer overlay/usr/libexec/patronus/ap-event overlay/etc/patronus/board.sh
$DOCKER exec "$C" mkdir -p /w/ov && $DOCKER exec -i "$C" tar -xf - -C /w/ov < "$WD/ov.tar"
sed -n '/^#--INNER-BEGIN/,/^#--INNER-END/p' "$SELF" > "$WD/inner.sh"; $DOCKER cp "$WD/inner.sh" "$C:/w/inner.sh"
hwsim_load 3 ci/embedded-aarch64/ax1800/tests/steer-hwsim.sh || { echo "SKIP: no mac80211_hwsim on this kernel"; exit 0; }
PHYS=$(ls /sys/class/ieee80211 | sort -V | tail -n 3); [ "$(echo $PHYS | wc -w)" = 3 ] || { echo "expected 3 hwsim radios, got: $PHYS"; exit 1; }
PID=$($DOCKER inspect -f '{{.State.Pid}}' "$C")
# iw is not on the hosts: a throw-away container in the host's net+pid namespace moves the radios
$DOCKER run --rm --net=host --pid=host --cap-add NET_ADMIN "$IMAGE" sh -c \
  "apt-get update -qq >/dev/null && apt-get install -y -qq iw >/dev/null 2>&1; for p in $(echo $PHYS); do iw phy \$p set netns $PID || exit 1; done"
echo "--- radios $PHYS moved into $C"
set -- $PHYS
rc=0
$DOCKER exec -e PHYA=$1 -e PHYB=$2 -e PHYSTA=$3 -e SOFT_CYCLES="${SOFT_CYCLES:-5}" -e HARD_RUNS="${HARD_RUNS:-5}" -e NIGHT="${NIGHT:-1}" "$C" bash /w/inner.sh || rc=$?
$DOCKER cp "$C:/w/out/result.json" "$WD/result.json" 2>/dev/null && echo "RESULT_JSON $(cat "$WD/result.json")"
exit $rc

#--INNER-BEGIN
#!/bin/bash
# runs inside the container as root. Env: PHYA PHYB PHYSTA SOFT_CYCLES HARD_RUNS NIGHT
set -u
O=/w/ov/overlay; W=/w; R=$W/r; L=$W/log; OUT=$W/out; mkdir -p "$R" "$L" "$OUT"
SSID="Home Net"; PSK=examplekey123; SRV=192.168.77.1; STAIP=192.168.77.50
EVLOG=$L/hostapd-events.log; WPALOG=$L/wpa.log
say() { echo "[$(date +%H:%M:%S)] $*"; }
ns() { local n=$1; shift; ip netns exec "$n" "$@"; }
fail=0; bad() { say "FAIL: $*"; fail=1; }
tnow() { date +%s.%N; }
wcli() { ns sta wpa_cli -p /run/wpa-sta -i "$STAIF" "$@"; }
hcli() { local x=$1; shift; ns ap$x hostapd_cli -p /run/hostapd-$x -i wl$x "$@"; }
bssid_of() { ns ap$1 cat /sys/class/net/wl$1/address; }

# ---------- topology
for n in apA apB sta lan; do ip netns add $n; done
iw phy "$PHYA" set netns name apA; iw phy "$PHYB" set netns name apB; iw phy "$PHYSTA" set netns name sta
ren() { local n=$1 new=$2 old; old=$(ns $n iw dev | awk '/Interface/ { print $2; exit }'); ns $n ip link set "$old" down; ns $n ip link set "$old" name "$new"; }
ren apA wlA; ren apB wlB; ren sta wsta; STAIF=wsta
ip -n lan link add brL type bridge; ip -n lan link set brL up
ip link add srvh netns lan type veth peer name srvb netns lan
ip -n lan link set srvb master brL up; ip -n lan addr add $SRV/24 dev srvh; ip -n lan link set srvh up; ip -n lan link set lo up
for x in A B; do
  ip link add vl$x netns lan type veth peer name vp$x netns ap$x
  ip -n lan link set vl$x master brL up
  ns ap$x ip link add br-lan type bridge; ns ap$x ip link set br-lan up; ns ap$x ip link set vp$x master br-lan up; ns ap$x ip link set lo up
done
ns sta ip link set lo up; ns sta ip addr add $STAIP/24 dev $STAIF
BSSA=$(bssid_of A); BSSB=$(bssid_of B); STAMAC=$(ns sta cat /sys/class/net/$STAIF/address)
say "A=$BSSA B=$BSSB station=$STAMAC"

# ---------- configs from the product's `ap render`
mkdir -p $R/sys/phy0 $R/sys/phy1
render() { # NAME MAC24 CHANNEL
  echo 02:00:00:00:09:00 > $R/sys/phy0/macaddress; echo "$2" > $R/sys/phy1/macaddress
  printf '. %s\nAP_COUNTRY=US AP_CHAN24=%s AP_CHAN5=36 AP_HE=0 AP_HTCAPS24="[SHORT-GI-20]"\nAP_SSIDS=m\nSSID_m="%s" KEY_m=%s SEC_m=wpa2\n' $O/etc/patronus/board.sh "$3" "$SSID" "$PSK" > $R/board-$1.sh
  rm -rf $R/$1; AP_BOARD=$R/board-$1.sh AP_RENDER_OUT=$R/$1 AP_SYSFS=$R/sys AP_PHY5=phy0 AP_PHY24=phy1 sh $O/usr/libexec/patronus/ap render > $R/$1.render 2>&1; }
render A "$BSSA" 1; render B "$BSSB" 6
for x in A B; do f=$R/$x/ap24.conf; [ -s $f ] || { cat $R/$x.render; bad "ap render wrote no ap24.conf"; exit 1; }
  rm -f $R/$x/ap5.conf   # 2.4 GHz only here: the 5 GHz radio does not exist
  # interface names to the hwsim ones, the product's own parameters (patronus_*) are not known to the stock hostapd
  sed -i "/^patronus_/d; s#/run/hostapd#/run/hostapd-$x#; s#wl24-m#wl$x#g" $f; mv $R/$x/deny-wl24-m $R/$x/deny-wl$x
  mkdir -p /run/hostapd-$x; cp $f $f.ht
done
grep -h '^bss_transition\|^rrm_' $R/A/ap24.conf | tr '\n' ' '; echo "(from ap render)"
printf '%s 2437 -40 wpa2 20 6 Home_Net\n' "$BSSB" > $R/A/peers-24; printf '%s 2412 -40 wpa2 20 1 Home_Net\n' "$BSSA" > $R/B/peers-24

# ---------- hostapd + hooks, A first; B appears after the station joined A
cat > $L/hlog.sh <<'X'
#!/bin/sh
echo "$(date +%s.%N) $*" >> /w/log/hostapd-events.log
X
chmod +x $L/hlog.sh
start_ap() { local x=$1
  ns ap$x hostapd -B -t -P $L/hostapd-$x.pid -f $L/hostapd-$x.log $R/$x/ap24.conf || bad "hostapd $x"
  for i in $(seq 40); do hcli $x status 2>/dev/null | grep state=ENABLED >/dev/null && break; sleep 0.5; done
  hcli $x status | grep state=ENABLED >/dev/null || { bad "hostapd $x not enabled"; tail -5 $L/hostapd-$x.log; }
  mkdir -p $W/st-$x $W/db-$x
  ns ap$x env AP_STEER_STATE=$W/st-$x AP_CTRL=/run/hostapd-$x AP_RENDER_OUT=$R/$x hostapd_cli -B -P $L/cli1-$x.pid -p /run/hostapd-$x -i wl$x -a $O/usr/libexec/patronus/ap-event
  ns ap$x hostapd_cli -B -P $L/cli2-$x.pid -p /run/hostapd-$x -i wl$x -a $L/hlog.sh; }
stop_ap() { kill $(cat $L/cli1-$1.pid $L/cli2-$1.pid $L/hostapd-$1.pid 2>/dev/null) 2>/dev/null; sleep 1; }
# hwsim hears every AP at the same level, and wpa_supplicant keeps a station whose AP it hears "great" (SNR > 25) unless
# the other AP promises 5 Mbit/s more. So the AP a station should leave is run without 802.11n (est. 54 Mbit/s against 65):
# mode legacy = that one, ht = the other. Restarting hostapd drops the station: only done between measurements.
setmode() { local x=$1 m=$2 f=$R/$1/ap24.conf; if [ "$m" = legacy ]; then sed '/^ieee80211n=/d; /^ht_capab=/d; /^wmm_enabled=/d' $f.ht > $f; else cp $f.ht $f; fi; }
phase() { # LEGACY_UNIT: that unit runs without 802.11n, the other with
  local l=$1 h; [ "$l" = A ] && h=B || h=A
  stop_ap A; stop_ap B; setmode $l legacy; setmode $h ht; start_ap $l; start_ap $h; say "phase: $l without 802.11n (the one stations leave), $h with"; }
board() { # X ON [extra assignments]: the unit's settings file (ap-steer re-reads it every round)
  local x=$1 on=$2; shift 2
  printf '. %s\nAP_STEER=%s AP_STEER_SIGNAL=-10 AP_STEER_AFTER=30 AP_STEER_INTERVAL=10 AP_STEER_MARGIN=0 AP_STEER_BTM_EVERY=60 AP_STEER_REPORT=active AP_STEER_CLOCK=14:00 AP_STEER_RETRY=20 AP_STEER_RETRY_MAX=20\n%s\n' \
    $O/etc/patronus/board.sh "$on" "$*" > $W/board-$x.sh.new; mv $W/board-$x.sh.new $W/board-$x.sh; }
start_steer() { local x=$1
  ns ap$x env AP_BOARD=$W/board-$x.sh AP_RENDER_OUT=$R/$x AP_STEER_STATE=$W/st-$x AP_STEER_DB=$W/db-$x AP_CTRL=/run/hostapd-$x AP_STEER_PID=$L/steer-$x.pid \
    sh $O/usr/libexec/patronus/ap-steer run >> $L/steer-$x.log 2>&1 & }
start_ap A
cat > $L/sta.conf <<X
ctrl_interface=/run/wpa-sta
update_config=0
network={
  ssid="$SSID"
  psk="$PSK"
  key_mgmt=WPA-PSK
}
X
ns sta wpa_supplicant -B -t -i $STAIF -c $L/sta.conf -f $WPALOG -P $L/wpa.pid || bad "wpa_supplicant"
waitfor() { local what=$1 tmo=$2; shift 2; local i; for i in $(seq $((tmo * 2))); do "$@" && return 0; sleep 0.5; done; bad "timeout waiting for $what"; return 1; }
cur_bss() { wcli status 2>/dev/null | sed -n 's/^bssid=//p'; }
on_bss() { [ "$(cur_bss)" = "$1" ] && wcli status | grep wpa_state=COMPLETED >/dev/null; }
waitfor "station on A" 30 on_bss $BSSA || { tail -20 $WPALOG; exit 1; }
start_ap B
say "capabilities hostapd A sees: $(hcli A sta $STAMAC | grep -E '^(ext_capab|rrm_enabled_capab)=' | tr '\n' ' ')"
hcli A sta $STAMAC | grep '^capability=0x[0-9a-f]*[1-9a-f][0-9a-f]\{3\}$' || true
cap=$(hcli A sta $STAMAC | sed -n 's/^capability=0x//p'); [ $(( 0x$cap & 4096 )) -ne 0 ] || bad "the station does not advertise radio measurement (802.11k)"
ns sta ping -c 3 -W 1 $SRV >/dev/null && say "station reaches the server through A" || bad "no ping through A"
board A 0; board B 0; start_steer A; start_steer B
wcli set bss_transition 1 >/dev/null 2>&1 || true

# hwsim has no path loss: a receiver hears a sender at (sender tx power - 50) dBm, so the radio the station should
# leave is turned down (30 dBm = -20 dBm heard, 5 dBm = -45 dBm heard) and wpa_supplicant sees a weak AP it wants to leave
pw() { ns ap$1 iw dev wl$1 set txpower limit $(($2 * 100)); }
pw A 30; pw B 30
# ---------- measuring helpers
pingstat() { # FILE T0 T1 -> "received lost max_gap_ms"
  awk -v a="$2" -v b="$3" '/^\[[0-9.]+\].*icmp_seq=/ { ts = substr($1, 2) + 0; if (ts < a || ts > b) next
      match($0, /icmp_seq=[0-9]+/); s = substr($0, RSTART + 9, RLENGTH - 9) + 0; n++
      if (n == 1) f = s; else { g = (ts - pt) * 1000; if (g > mg) mg = g }; pt = ts; l = s }
    END { printf "%d %d %.0f\n", n, (n ? l - f + 1 - n : 0), mg }' "$1"; }
wpa_ev() { # PATTERN T0 T1 -> count of wpa_supplicant lines in the window
  awk -v a="$2" -v b="$3" -v p="$1" '{ ts = $1 + 0; if (ts >= a && ts <= b && $0 ~ p) n++ } END { print n + 0 }' $WPALOG; }
wpa_first() { # PATTERN T0 -> epoch of the first matching line after T0 (empty if none)
  awk -v a="$2" -v p="$1" '{ ts = $1 + 0; if (ts >= a && $0 ~ p) { printf "%.3f\n", ts; exit } }' $WPALOG; }
hap_ev() { awk -v a="$2" -v b="$3" -v p="$1" '{ if ($1 + 0 >= a && $1 + 0 <= b && $0 ~ p) n++ } END { print n + 0 }' $EVLOG; }
hist_win() { # X T0 T1 -> compact "event,event,..." from ap-steer's history (its integer second clock)
  [ -f $W/db-$1/history ] && awk -v a="${2%.*}" -v b="${3%.*}" '{ if (match($0, /"t":[0-9]+/)) { t = substr($0, RSTART + 4, RLENGTH - 4) + 0
      if (t >= a && t <= b && match($0, /"event":"[a-z-]+"/)) { printf "%s%s", s, substr($0, RSTART + 9, RLENGTH - 10); s = "," } } }' $W/db-$1/history; }
PINGF=; PINGP=
ping_start() { PINGF=$L/ping-$1.log; ip netns exec sta ping -D -i 0.1 -W 1 $SRV > $PINGF 2>&1 & PINGP=$!; sleep 1; }
ping_stop() { kill $PINGP 2>/dev/null; wait $PINGP 2>/dev/null; }
bssname() { [ "$1" = "$BSSA" ] && echo A || { [ "$1" = "$BSSB" ] && echo B || echo "?"; }; }
json_add() { echo "$2" >> $OUT/$1.jsonl; }
to_bss() { [ "$1" = A ] && echo $BSSA || echo $BSSB; }

reset_to() { # A|B: the station roams back by itself request (wpa_cli roam), quiet before the measurement
  local t; t=$(to_bss $1); on_bss $t && return 0; waitfor "station associated" 60 sh -c "[ -n \"\$(ip netns exec sta wpa_cli -p /run/wpa-sta -i $STAIF status | grep -c COMPLETED | grep 1)\" ]"; local k; for k in 1 2 3; do wcli bssid_ignore clear >/dev/null; wcli roam $t >/dev/null; for i in $(seq 20); do on_bss $t && break; sleep 0.5; done; on_bss $t && break; done
  waitfor "station on $1" 5 on_bss $t; sleep 8; }
# ---------- SOFT
soft_move() { # SRC DST LABEL: steering on at SRC only
  local s=$1 d=$2 lbl=$3 tgt; tgt=$(to_bss $d)
  on_bss "$(to_bss $s)" || { bad "$lbl: station not on $s"; return 1; }
  board A 0; board B 0; pw $s 5; pw $d 30; sleep 40   # both off; the station counts as weak at the old unit for AP_STEER_AFTER
  ping_start $lbl; local t0; t0=$(tnow)
  board $s 1; say "$lbl: steering on at $s"
  local i dis=0 t1= got=
  for i in $(seq 280); do got=$(wpa_first "CTRL-EVENT-CONNECTED - Connection to $tgt" "$t0"); [ -n "$got" ] && break; sleep 1; done
  sleep 14; local t2; t2=$(tnow); ping_stop; board $s 0
  if [ -z "$got" ]; then bad "$lbl: the station did not reach $d within 280 s"; fi
  set -- $(pingstat $PINGF "$t0" "$t2"); local rcv=$1 lost=$2 gap=$3
  dis=$(wpa_ev "CTRL-EVENT-DISCONNECTED" "$t0" "$t2"); local ass; ass=$(wpa_ev "CTRL-EVENT-ASSOC-REJECT|CTRL-EVENT-AUTH-REJECT" "$t0" "$t2")
  local tmr bcn; tmr=$(hap_ev "BSS-TM-RESP.*status_code=0" "$t0" "$t2"); bcn=$(hap_ev "BEACON-RESP-RX" "$t0" "$t2")
  local to=none; [ -n "$got" ] && to=$d; local rt=-; [ -n "$got" ] && rt=$(awk -v a="$got" -v b="$t0" 'BEGIN { printf "%.1f", a - b }')
  local hs; hs=$(hist_win $s "$t0" "$t2"); [ -z "$hs" ] && hs=-; local hd; hd=$(hist_win $d "$t0" "$t2")
  [ "$dis" -gt 0 ] && bad "$lbl: CTRL-EVENT-DISCONNECTED seen ($dis)"
  [ "$tmr" -ge 1 ] || bad "$lbl: no BSS-TM-RESP status_code=0 at the old unit"
  say "$lbl $s->$d: reached=$to after ${rt}s lost=$lost max_gap_ms=$gap disconnect_events=$dis btm_resp_ok=$tmr beacon_resp=$bcn history[$s]=$hs${hd:+ history[$d]=$hd}"
  json_add soft "{\"move\":\"$lbl\",\"from\":\"$s\",\"to\":\"$d\",\"reached\":\"$to\",\"seconds_to_move\":\"$rt\",\"replies\":$rcv,\"lost\":$lost,\"max_gap_ms\":$gap,\"disconnect\":$([ "$dis" -gt 0 ] && echo true || echo false),\"disconnect_events\":$dis,\"bss_tm_resp_status0\":$tmr,\"beacon_resp_rx\":$bcn,\"auth_assoc_rejects\":$ass,\"ap_steer_history\":\"$hs\"}"
  true; }

say "=== soft moves A->B"; phase A; reset_to A; board A 0; board B 0
n=0; while [ $n -lt "${SOFT_CYCLES:-5}" ]; do n=$((n + 1)); soft_move A B "soft$n-AtoB"; [ $n -lt "${SOFT_CYCLES:-5}" ] && reset_to A; done
say "=== soft moves B->A"; phase B; reset_to B
n=0; while [ $n -lt "${SOFT_CYCLES:-5}" ]; do n=$((n + 1)); soft_move B A "soft$n-BtoA"; [ $n -lt "${SOFT_CYCLES:-5}" ] && reset_to B; done

# ---------- HARD (the old behaviour)
h=0; while [ $h -lt "${HARD_RUNS:-5}" ]; do h=$((h + 1))
  board A 0; board B 0; pw A 30; pw B 30; reset_to A; ping_start hard$h; t0=$(tnow); sleep 3
  tk=$(tnow); hcli A deny_acl ADD_MAC $STAMAC >/dev/null
  got=; for i in $(seq 120); do got=$(wpa_first "CTRL-EVENT-CONNECTED - Connection to $BSSB" "$tk"); [ -n "$got" ] && break; sleep 0.5; done
  sleep 4; t2=$(tnow); ping_stop; hcli A deny_acl DEL_MAC $STAMAC >/dev/null
  [ -n "$got" ] || bad "hard$h: not on B after the kick"
  set -- $(pingstat $PINGF "$tk" "$t2"); rcv=$1; lost=$2; gap=$3
  dis=$(wpa_ev "CTRL-EVENT-DISCONNECTED" "$tk" "$t2"); first=$(wpa_first "CTRL-EVENT-DISCONNECTED" "$tk"); rej=$(wpa_ev "REJECT" "$tk" "$t2")
  rt=-; [ -n "$got" ] && rt=$(awk -v a="$got" -v b="$tk" 'BEGIN { printf "%.1f", a - b }')
  say "hard$h: on B after ${rt}s lost=$lost max_gap_ms=$gap disconnect_events=$dis rejects=$rej"
  json_add hard "{\"run\":$h,\"seconds_to_B\":\"$rt\",\"replies\":$rcv,\"lost\":$lost,\"max_gap_ms\":$gap,\"disconnect\":$([ "$dis" -gt 0 ] && echo true || echo false),\"disconnect_events\":$dis,\"rejects\":$rej}"
  sleep 3
done

# ---------- NIGHT
night="skipped (NIGHT=0)"
if [ "${NIGHT:-1}" = 1 ]; then
  board A 0; board B 0; pw A 5; pw B 30; reset_to A
  if wcli set disable_btm 1 2>/dev/null | grep OK >/dev/null; then
    say "=== night path: 02:00, station ignores move requests, quiet idle 60 s, btm wait 30 s"
    rm -rf $W/db-A $W/st-A/sta-* $W/st-A/cap-* $W/st-A/rep-* $W/st-A/btm-*; mkdir -p $W/db-A
    say "waiting 65 s of connected time"; sleep 65
    ping_start night; t0=$(tnow)
    board A 1 "AP_STEER_CLOCK=02:00 AP_STEER_QUIET_IDLE=60 AP_STEER_BTM_WAIT=30 AP_STEER_BLOCK=30"
    got=; for i in $(seq 200); do got=$(wpa_first "CTRL-EVENT-CONNECTED - Connection to $BSSB" "$t0"); [ -n "$got" ] && break; sleep 1; done
    sleep 6; t2=$(tnow); ping_stop; board A 0; wcli set disable_btm 0 >/dev/null 2>&1
    set -- $(pingstat $PINGF "$t0" "$t2"); lost=$2; gap=$3
    dis=$(wpa_ev "CTRL-EVENT-DISCONNECTED" "$t0" "$t2"); tdis=$(wpa_first "CTRL-EVENT-DISCONNECTED" "$t0")
    hl=$(sed -n 's/.*"t":\([0-9]*\),"event":"\([a-z-]*\)".*/\1:\2/p' $W/db-A/history | tr '\n' ' ')
    tb=$(sed -n 's/.*"t":\([0-9]*\),"event":"btm".*/\1/p' $W/db-A/history | head -1); tk2=$(sed -n 's/.*"t":\([0-9]*\),"event":"kick".*/\1/p' $W/db-A/history | head -1)
    wait_s=-; [ -n "$tb" ] && [ -n "$tk2" ] && wait_s=$((tk2 - tb))
    [ -n "$tk2" ] || bad "night: no kick in ap-steer's history"; [ "$dis" -ge 1 ] || bad "night: the station was not disconnected"
    [ "$wait_s" != - ] && [ "$wait_s" -lt 30 ] && bad "night: kicked ${wait_s}s after the move request, before AP_STEER_BTM_WAIT=30"
    night="station ignored the move request (disable_btm=1); ap-steer history: $hl; kick came ${wait_s}s after the request (AP_STEER_BTM_WAIT=30); station disconnected ($dis event(s)), on B after $( [ -n "$got" ] && awk -v a="$got" -v b="$tdis" 'BEGIN { printf "%.1f", a - b }' )s; lost=$lost max_gap_ms=$gap"
    say "night: $night"
  else night="skipped: this wpa_supplicant has no 'set disable_btm'"; say "$night"; fi
fi

# ---------- report
say "=== steering status of A:"; ns apA env AP_BOARD=$W/board-A.sh AP_RENDER_OUT=$R/A AP_STEER_STATE=$W/st-A AP_STEER_DB=$W/db-A AP_CTRL=/run/hostapd-A sh $O/usr/libexec/patronus/ap-steer status 2>&1 | head -12
python3 - "$OUT" "$night" "$fail" <<'PY'
import sys, json
d, night, fail = sys.argv[1], sys.argv[2], sys.argv[3]
def rd(n):
    try: return [json.loads(l) for l in open(d + '/' + n + '.jsonl') if l.strip()]
    except FileNotFoundError: return []
soft, hard = rd('soft'), rd('hard')
def agg(rs):
    return {'runs': len(rs), 'lost_total': sum(r['lost'] for r in rs), 'lost_max': max([r['lost'] for r in rs] or [0]),
            'max_gap_ms_max': max([r['max_gap_ms'] for r in rs] or [0]), 'disconnects': sum(1 for r in rs if r['disconnect']),
            'runs_detail': rs}
res = {'soft_moves': soft, 'hard_kick': agg(hard), 'night_path': night, 'soft_summary': {k: v for k, v in agg(soft).items() if k != 'runs_detail'}, 'ok': fail == '0'}
print('%-14s %-5s %-8s %-5s %-7s %-10s' % ('soft move', 'lost', 'gap ms', 'disc', 'to', 'seconds'))
for r in soft: print('%-14s %-5d %-8d %-5s %-7s %-10s' % (r['move'], r['lost'], r['max_gap_ms'], 'yes' if r['disconnect'] else 'no', r['reached'], r['seconds_to_move']))
print('%-14s %-5s %-8s %-5s %-7s %-10s' % ('hard kick', 'lost', 'gap ms', 'disc', 'to', 'seconds'))
for r in hard: print('%-14s %-5d %-8d %-5s %-7s %-10s' % ('hard%d' % r['run'], r['lost'], r['max_gap_ms'], 'yes' if r['disconnect'] else 'no', 'B', r['seconds_to_B']))
open(d + '/result.json', 'w').write(json.dumps(res))
PY
say "done, fail=$fail"; exit $fail
#--INNER-END
