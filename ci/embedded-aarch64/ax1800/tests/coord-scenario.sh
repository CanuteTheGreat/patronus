#!/bin/sh
# coord-scenario.sh (inside the hwsim container, 4 radios, regulatory domain US): two access points of ONE network (same
# SSID) must not end on the same channel block (docs 12.17). Each "unit" is the image's own `ap start` run in a private
# mount namespace (own /run, /tmp: hostapd control sockets, pid files, logs) on two radios of its own, with the Patronus
# hostapd; the radios hear each other through mac80211_hwsim like units in one house.
#   radios 1,2 = unit a (2.4 / 5 GHz), radios 3,4 = unit b.
# Cases:
#   plan    unit a starts alone, unit b starts afterwards: b's pre-start scan must hear a, so the two 5 GHz radios end on
#           different 80 MHz blocks (36-48 vs 149-161 are the only non-DFS ones) and the 2.4 GHz radios on different
#           channels among 1/6/11.
#   repair  both start at the same moment without the pre-start scan (AP_COORD_NOPLAN: nobody is heard, the case the plan
#           cannot see): when ACS puts them on one block, the re-check after AP_COORD_DELAY must move the unit with the
#           higher MAC key (and only that one) onto the other block.
#   off     AP_COORD5=0 on unit b: it ignores a (the setting really switches it off): b's rendered list stays complete.
# Env: HOSTAPD (binary under test), AP_DIR (dir with usr/libexec/patronus/ap, ap-coord and etc/patronus/board.sh).
# Prints PASS/FAIL lines and "FAILED: none" on success.
set -u
HOSTAPD=${HOSTAPD:-hostapd}; AP_DIR=${AP_DIR:-/w/h/overlay}; CASES=${COORD_CASES:-plan repair off}
T=/ct; rm -rf $T; mkdir -p $T/bin; fails=
pass() { echo "PASS: $*"; }; fail() { echo "FAIL: $*"; fails="$fails|$*"; }
set -- $(ls /sys/class/ieee80211 | sort -V); [ $# -ge 4 ] || { echo "SKIP: need 4 radios, have $#"; exit 0; }
A24=$1; A5=$2; B24=$3; B5=$4
for i in $(iw dev | awk '$1 == "Interface" { print $2 }'); do iw dev $i del; done
ip link add br-lan type bridge 2>/dev/null; ip link set br-lan up
ln -sf "$(command -v $HOSTAPD)" $T/bin/hostapd
HWSIM_CAPS="AP_HTCAPS24='[SHORT-GI-20][SHORT-GI-40]' AP_HTCAPS5='[SHORT-GI-20][SHORT-GI-40]' AP_VHTCAPS5='[SHORT-GI-80]'"
mac() { cat /sys/class/ieee80211/$1/macaddress; }
key() { mac "$1" | cut -d: -f2-; }
board() { # UNIT PHY24 PHY5 extra...: the unit's board file
  u=$1; shift 3
  printf '. %s/etc/patronus/board.sh\n%s\nAP_COUNTRY=US\nAP_SSIDS=%s\nSSID_%s=coordnet KEY_%s=coordtest123 SEC_%s=wpa2\nAP_COORD_DELAY=3600 AP_COORD_INTERVAL=0 AP_ACS_SCANS=1\n%s\n' \
    "$AP_DIR" "$HWSIM_CAPS" "$u" "$u" "$u" "$u" "$*" > $T/board-$u.sh; }
NSA=; NSB=
holder() { # UNIT: a mount namespace of its own, kept alive by a sleep; its pid in $T/ns-UNIT
  # (`ap` calls its own files by their installed path /usr/libexec/patronus/..., bind-mounted from the overlay)
  unshare -m sh -c "mount -t tmpfs t /run; mount -t tmpfs t /tmp; mkdir -p /run/hostapd /usr/libexec/patronus; mount --bind $AP_DIR/usr/libexec/patronus /usr/libexec/patronus; exec sleep 7200" > /dev/null 2>&1 &
  echo $! > $T/ns-$1; sleep 1; }
inu() { u=$1; shift; nsenter -m -t "$(cat $T/ns-$u)" "$@"; }
uenv() { # UNIT PHY24 PHY5 -> env words for the ap scripts
  echo "AP_BOARD=$T/board-$1.sh AP_CHAN_DB=$T/db-$1 AP_PHY24=$2 AP_PHY5=$3 AP_GUARD=/nonexistent AP_GUEST=/nonexistent AP_COORD_AP=$AP_DIR/usr/libexec/patronus/ap AP_COORD_BIN=$AP_DIR/usr/libexec/patronus/ap-coord PATH=$T/bin:$PATH"; }
ap_start() { # UNIT PHY24 PHY5 [extra env]
  u=$1; p24=$2; p5=$3; shift 3
  inu $u env $(uenv $u $p24 $p5) "$@" sh $AP_DIR/usr/libexec/patronus/ap start > $T/start-$u.log 2>&1; }
ap_stop() { u=$1; inu $u sh -c "kill \$(cat /run/patronus-ap-coord.pid 2>/dev/null) 2>/dev/null; env $(uenv $1 x x) sh $AP_DIR/usr/libexec/patronus/ap stop" > /dev/null 2>&1
  for i in $(iw dev | awk '$1 == "Interface" { print $2 }'); do case "$i" in wl*-$u|wl*-coord) iw dev $i del 2>/dev/null;; esac; done
  sleep 1; left=$(iw dev | awk -v u="$u" '$1 == "Interface" && $2 ~ ("^wl.*-" u "$") { print $2 }' | tr '\n' ' ')  # a unit that is stopped must leave nothing on air
  [ -z "$left" ] || { echo "LEFTOVER after stopping unit $u: $left"; ps | grep -E 'hostapd|ap-coord|ap-chan|ap restart' | grep -v grep; }; }
st() { inu "$1" hostapd_cli -p /run/hostapd -i "$2" status 2>/dev/null | sed -n "s/^$3=//p" | head -1; }
wait_up() { u=$1; i=$2; wn=0; until [ "$(st $u $i state)" = ENABLED ]; do wn=$((wn + 1)); [ $wn -gt ${3:-60} ] && return 1; sleep 1; done; }  # own counter: the repair loop's n must not be reset in here
seg() { st "$1" "$2" vht_oper_centr_freq_seg0_idx; }
dump() { echo "--- unit $1: start log"; cat $T/start-$1.log 2>/dev/null; echo "--- unit $1: /run, /tmp, hostapd logs"
  inu $1 sh -c 'ls /run /run/hostapd /tmp; tail -15 /tmp/hostapd-ap5.log /tmp/hostapd-ap24.log /tmp/ap.log /tmp/ap-coord.log 2>/dev/null; ps | grep -c hostapd' 2>&1; iw dev | grep -E 'Interface|channel|ssid' | head -20; }
holder a; holder b
cleanup() { for u in a b; do ap_stop $u; kill $(cat $T/ns-$u 2>/dev/null) 2>/dev/null; done; }
trap cleanup EXIT
echo "    unit a = $A24/$A5 key $(key $A5), unit b = $B24/$B5 key $(key $B5)"
for c in $CASES; do case $c in
plan)
  board a $A24 $A5; board b $B24 $B5
  ap_start a $A24 $A5; wait_up a wl5-a 90 && wait_up a wl24-a 30 || { fail "plan: unit a did not come up (see $T/start-a.log)"; dump a; }
  ca5=$(seg a wl5-a); ca24=$(st a wl24-a channel)
  echo "    unit a alone: 5 GHz centre $ca5, 2.4 GHz channel $ca24"
  ap_start b $B24 $B5; wait_up b wl5-b 90 && wait_up b wl24-b 30 || fail "plan: unit b did not come up (see $T/start-b.log)"
  cb5=$(seg b wl5-b); cb24=$(st b wl24-b channel)
  echo "    unit b started second: 5 GHz centre $cb5, 2.4 GHz channel $cb24"; sed 's/^/    b: /' $T/start-b.log | grep 'ap-coord\|ACS' | head -4
  [ -n "$ca5" ] && [ -n "$cb5" ] && [ "$ca5" != "$cb5" ] && pass "plan: the two units' 5 GHz radios sit on different 80 MHz blocks (centres $ca5 / $cb5)" \
    || { fail "plan: both 5 GHz radios on centre '$ca5' / '$cb5'"; grep -h 'ap-coord\|ap:' $T/start-b.log | head -8; dump b; }
  [ -n "$ca24" ] && [ -n "$cb24" ] && [ "$ca24" != "$cb24" ] && pass "plan: the 2.4 GHz radios sit on different channels ($ca24 / $cb24)" || fail "plan: both 2.4 GHz radios on $ca24 / $cb24"
  ap_stop a; ap_stop b;;
repair)
  sleep 35   # the earlier case's units left BSSs in the kernel scan list for 30 s: with them heard every block looks taken and ACS decides alone
  # The re-check scans with ap-force: the scanning radio leaves its channel for about a second and is not heard meanwhile.
  # Two units that check at the same moment can therefore both miss each other (on a loaded host their scans drift by
  # more than a dwell, and the mover's dwell on the other unit's channel falls into the other unit's off-channel time),
  # so the case staggers the two checks by 30 s. The other cases never run the re-check (AP_COORD_DELAY=3600 in board()):
  # a unit's re-check taking its radio off the air while the other unit scans made 'plan' miss it, 2 runs of 4 on rw-man-02.
  RA=${COORD_REPAIR_DELAY:-30}; RB=$((RA + 30))
  board a $A24 $A5 AP_COORD_DELAY=$RA; board b $B24 $B5 AP_COORD_DELAY=$RB
  ap_start a $A24 $A5 AP_COORD_NOPLAN=1 & pa=$!; ap_start b $B24 $B5 AP_COORD_NOPLAN=1 & pb=$!; wait $pa $pb
  wait_up a wl5-a 90 || fail "repair: unit a 5 GHz not up"; wait_up b wl5-b 90 || fail "repair: unit b 5 GHz not up"
  ca=$(seg a wl5-a); cb=$(seg b wl5-b); echo "    both started blind: centres $ca / $cb"
  if [ "$ca" != "$cb" ]; then pass "repair: (ACS happened to separate them already; the re-check has nothing to fix)"
  else
    ka=$(key $A5); kb=$(key $B5)
    if [ "$(printf '%s\n%s\n' "$ka" "$kb" | sort | head -1)" = "$ka" ]; then mover=b; stayer=a; else mover=a; stayer=b; fi
    first=$ca; echo "    same block $ca: the higher key moves = unit $mover"
    n=0; t0=$(date +%s); while [ $n -lt $((RB + 60)) ] && [ $(( $(date +%s) - t0 )) -lt $((RB + 120)) ]; do sleep 2; n=$((n + 2))
      [ -d /sys/class/ieee80211/$A5 ] && [ -d /sys/class/ieee80211/$B5 ] || { fail "repair: a radio vanished (mac80211_hwsim unloaded by another run?)"; break; }
      wait_up $mover wl5-$mover 8 >/dev/null 2>&1
      ca=$(seg a wl5-a); cb=$(seg b wl5-b); [ -n "$ca" ] && [ -n "$cb" ] && [ "$ca" != "$cb" ] && break; done
    [ -n "$ca" ] && [ -n "$cb" ] && [ "$ca" != "$cb" ] && pass "repair: after the re-check the units sit on different blocks ($ca / $cb)" || { fail "repair: still on one block ($ca / $cb) after ${n}s"; dump a; dump b; }
    # the unit with the lower key kept its block: its centre is the one both reported at the start
    [ "$stayer" = a ] && now=$ca || now=$cb
    [ "$now" = "$first" ] && pass "repair: unit $stayer (lower key) stayed on its block $first" || fail "repair: unit $stayer moved too ($first -> $now)"
  fi
  ap_stop a; ap_stop b;;
off)
  sleep 35   # the kernel keeps a BSS in its scan list for 30 s after its last beacon: let the units of the earlier cases expire
  board a $A24 $A5; board b $B24 $B5; cp $T/board-b.sh $T/board-b1.sh; board b $B24 $B5 AP_COORD5=0
  ap_start a $A24 $A5; wait_up a wl5-a 90 || fail "off: unit a not up"
  ca=$(seg a wl5-a); want="$((ca - 6)) $((ca - 2)) $((ca + 2)) $((ca + 6))"
  rm -rf $T/off; mkdir -p $T/off
  # the real scan from unit b's radio hears unit a: with the setting on the plan names a's block, with it off nothing is planned
  AP_BOARD=$T/board-b1.sh AP_RENDER_OUT=$T/off sh $AP_DIR/usr/libexec/patronus/ap-coord plan 5 $B5 > $T/off.out 2>&1
  got=$(cat $T/off/coord-5 2>/dev/null); [ "$got" = "$want" ] && pass "plan: a real scan from the other unit's radio hears unit a and names its block ($got)" || fail "plan: scan found '$got', unit a is on $want"
  rm -f $T/off/coord-5
  AP_BOARD=$T/board-b.sh AP_RENDER_OUT=$T/off sh $AP_DIR/usr/libexec/patronus/ap-coord plan 5 $B5 > $T/off.out 2>&1
  [ ! -e $T/off/coord-5 ] && pass "off: AP_COORD5=0 -> nothing planned even with unit a on air" || fail "off: a plan file exists with AP_COORD5=0"
  ap_stop a;;
esac; done
if [ -n "$fails" ]; then echo "--- logs"; tail -20 $T/start-a.log $T/start-b.log 2>/dev/null; echo "--- iw dev"; iw dev; fi
echo "FAILED: ${fails:-none}"
[ -z "$fails" ]
