#!/bin/sh
# xbss-scenario.sh (inside the hwsim container, 3 radios moved in): one MAC that is still associated on one SSID of a
# radio authenticates on the OTHER SSID of the same radio. On the IPQ6018 that is exactly the sequence that makes the
# ath11k firmware assert when the MAC is a peer on both BSSes at once (docs/embedded-routers.md 12.6d). hwsim cannot
# assert, so the check is the order of the kernel's station events on the AP radio: the MAC must be deleted on the old
# BSS BEFORE it is created on the new one. Then the flap limit: a MAC hopping back and forth is refused after 6 hops/min.
#   radio 0: hostapd, BSS ap0 "xbss-a" + BSS ap1 "xbss-b" (one hostapd, multi-BSS, as on the router)
#   radio 1 + radio 2: two stations with the SAME MAC (sta1 stays on xbss-a without saying goodbye, sta2 joins xbss-b)
# Env: HOSTAPD (binary under test), EXPECT=sync|overlap (sync = Patronus hostapd, overlap = stock: proves the test can
# fail). Prints PASS/FAIL lines and "FAILED: none" on success.
set -u
HOSTAPD=${HOSTAPD:-hostapd}; EXPECT=${EXPECT:-sync}
T=/tmp/xbss; rm -rf $T; mkdir -p $T; fails=
pass() { echo "PASS: $*"; }; fail() { echo "FAIL: $*"; fails="$fails|$*"; }
set -- $(ls /sys/class/ieee80211 | sort -V); [ $# -ge 3 ] || { echo "SKIP: need 3 radios, have $#"; exit 0; }
P0=$1; P1=$2; P2=$3
for i in $(iw dev | awk '$1 == "Interface" { print $2 }'); do iw dev $i del; done
iw phy $P0 interface add ap0 type __ap; iw phy $P1 interface add sta1 type managed; iw phy $P2 interface add sta2 type managed
A0=02:00:00:aa:00:00; A1=02:00:00:aa:00:01; M=02:00:00:5a:5a:01
ip link set ap0 address $A0; ip link set sta1 address $M; ip link set sta2 address $M
cat > $T/ap.conf <<EOF
driver=nl80211
interface=ap0
bssid=$A0
ctrl_interface=$T/ctrl
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
ssid=xbss-a
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=xbsstest1
rsn_pairwise=CCMP
bss=ap1
bssid=$A1
ctrl_interface=$T/ctrl
ssid=xbss-b
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=xbsstest1
rsn_pairwise=CCMP
EOF
iw event -t > $T/events 2>&1 &
EV=$!
$HOSTAPD -t -dd $T/ap.conf > $T/hostapd.log 2>&1 &
HP=$!
i=0; until hostapd_cli -p $T/ctrl -i ap1 status 2>/dev/null | grep -q state=ENABLED; do i=$((i + 1)); [ $i -gt 30 ] && break; sleep 1; done
sup() { # IF SSID BSSID
  printf 'ctrl_interface=%s/s-%s\nnetwork={\n ssid="%s"\n psk="xbsstest1"\n bssid=%s\n scan_freq=2437\n}\n' $T $1 $2 $3 > $T/$1.conf
  wpa_supplicant -dd -t -i $1 -c $T/$1.conf > $T/$1.log 2>&1 &
  echo $! > $T/$1.pid; sleep 1; }
assoc() { # IF: wait for COMPLETED
  i=0; until wpa_cli -p $T/s-$1 -i $1 status 2>/dev/null | grep -q wpa_state=COMPLETED; do i=$((i + 1)); [ $i -gt 30 ] && return 1; sleep 0.5; done; }
ip link set sta1 up; ip link set sta2 up
sup sta1 xbss-a $A0; assoc sta1 && pass "sta1 ($M) associated on xbss-a" || fail "sta1 did not associate on xbss-a"
hostapd_cli -p $T/ctrl -i ap0 sta $M | head -1 | grep -qx "$M" && pass "ap0 lists $M" || fail "ap0 does not list $M"
: > $T/events.mark; sleep 1; cp $T/events $T/events.before
# the same MAC now joins the other SSID of the same radio while sta1 is still associated (it never said goodbye)
sup sta2 xbss-b $A1; assoc sta2 && pass "sta2 (same MAC) associated on xbss-b" || fail "sta2 did not associate on xbss-b"
sleep 3
# order of the kernel station events on the AP radio after the mark
tail -n +$(( $(wc -l < $T/events.before) + 1 )) $T/events | grep -E "ap[01].*(new|del) station $M" > $T/order
cat $T/order | sed 's/^/    /'
first_new=$(grep -n "ap1.*new station" $T/order | head -1 | cut -d: -f1)
first_del=$(grep -n "ap0.*del station" $T/order | head -1 | cut -d: -f1)
if [ -n "$first_new" ] && [ -n "$first_del" ] && [ "$first_del" -lt "$first_new" ]; then res=sync
elif [ -n "$first_new" ]; then res=overlap; else res=none; fi
if [ "$res" = "$EXPECT" ]; then pass "station events: $res (expected $EXPECT)"; else fail "station events: $res, expected $EXPECT"; fi
if [ "$EXPECT" = sync ]; then
  grep -q 'patronus-xbss: ap1: STA .* moves here from ap0: removed there synchronously' $T/hostapd.log \
    && pass "hostapd logged the synchronous removal" || fail "no patronus-xbss removal line in the hostapd log"
  # flap limit: sta1 and sta2 take turns re-authenticating (each one a hop), the 7th hop within a minute is refused
  kill $(cat $T/sta2.pid); sleep 1; refused=0; n=0
  while [ $n -lt 8 ]; do n=$((n + 1))
    if [ $((n % 2)) = 1 ]; then wpa_cli -p $T/s-sta1 -i sta1 reassociate >/dev/null; else
      [ -f $T/sta2.pid ] && kill -0 $(cat $T/sta2.pid) 2>/dev/null || sup sta2 xbss-b $A1; wpa_cli -p $T/s-sta2 -i sta2 reassociate >/dev/null; fi
    sleep 2.5; done
  grep -q 'patronus-xbss: hopped between SSIDs more than 6 times' $T/hostapd.log && pass "flap limit: a MAC hopping between the SSIDs is held back" \
    || fail "flap limit never triggered ($(grep -c 'moves here from' $T/hostapd.log) hops logged)"
  kill -0 $HP 2>/dev/null && pass "hostapd still running" || fail "hostapd died"
fi
for f in $T/*.pid; do [ -f "$f" ] && kill $(cat $f) 2>/dev/null; done; kill $HP $EV 2>/dev/null
if [ -n "$fails" ]; then for f in hostapd sta1 sta2; do echo "--- $f.log (tail)"; tail -25 $T/$f.log 2>/dev/null; done; echo "--- iw dev"; iw dev; fi
echo "FAILED: ${fails:-none}"
[ -z "$fails" ]
