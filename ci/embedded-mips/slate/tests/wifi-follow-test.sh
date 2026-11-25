#!/bin/sh
# Host test of overlay/usr/libexec/patronus/wifi-follow with stub iw/hostapd (no radio, no root).
# Each check prints "ok: ..." or "FAIL: ..."; the script exits non-zero if any failed.
D=$(cd "$(dirname "$0")/.." && pwd)
WF=$D/overlay/usr/libexec/patronus/wifi-follow
W=$(mktemp -d "${TMPDIR:-/tmp}/wf-test.XXXX"); [ -n "${KEEP:-}" ] && echo "W=$W"; [ -n "${KEEP:-}" ] || trap 'for p in "$W"/run/hostapd-*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done; rm -rf "$W"' EXIT
fails=0
ok() { echo "ok: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails+1)); }
chk() { n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }

mkdir -p "$W/bin" "$W/fx" "$W/hostapd" "$W/wpa" "$W/run"
cat > "$W/bin/iw" <<'X'
#!/bin/sh
# iw dev <if> link|info|scan dump  -> fixtures in $FX
[ "$1" = dev ] || exit 1
f=$FX/$2.$3; [ "$3" = scan ] && f=$FX/$2.scan
[ -f "$f" ] && cat "$f"; exit 0
X
cat > "$W/bin/hostapd" <<'X'
#!/bin/sh
# hostapd -B -P <pid> <conf>: "daemonize" a sleeper, record the conf, publish the AP's channel like the kernel would
pid=$3; conf=$4
echo "$conf" >> "$FX/hostapd.starts"; cp "$conf" "$FX/hostapd.last"
sleep 600 & echo $! > "$pid"
ch=$(sed -n 's/^channel=//p' "$conf"); w=20; grep -q '^vht_oper_chwidth=1' "$conf" && w=80
if [ "$ch" -gt 14 ]; then f=$((5000 + 5*ch)); else f=$((2407 + 5*ch)); fi
ifc=$(sed -n 's/^interface=//p' "$conf")
echo "	channel $ch ($f MHz), width: $w MHz, center1: $f MHz" > "$FX/$ifc.info"
exit 0
X
chmod +x "$W/bin/iw" "$W/bin/hostapd"
cat > "$W/hostapd/ap5.conf" <<'X'
interface=wl5-ap
bridge=br-lan
driver=nl80211
ssid=Test Net
country_code=US
hw_mode=a
channel=36
ieee80211n=1
ieee80211ac=1
ht_capab=[HT40+]
vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42
wmm_enabled=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=TESTPASS
X
cat > "$W/wpa/wpa_supplicant.conf" <<'X'
ctrl_interface=/run/wpa_supplicant
network={
	ssid="Home Net"
	psk="x"
	priority=10
}
network={
	ssid="Other Net"
	psk="y"
}
X
export FX=$W/fx IW=$W/bin/iw HOSTAPD=$W/bin/hostapd HOSTAPD_DIR=$W/hostapd WPA_CONF_DIR=$W/wpa RUN=$W/run/wf PIDDIR=$W/run
export FOLLOW="wl5-sta:wl5-ap:ap5 wl24-sta:wl24-ap:ap24" POLL=0 MIN_RESTART=0
export NOW_CMD="cat $W/fx/now"
now() { echo "$1" > "$FX/now"; }
sta() { # sta <if> <freq> <width> <center>  (associated)
  echo "Connected to aa:bb:cc:dd:ee:ff (on $1)" > "$FX/$1.link"
  echo "	channel $(( $2 >= 5000 ? ($2-5000)/5 : ($2-2407)/5 )) ($2 MHz), width: $3 MHz, center1: $4 MHz" > "$FX/$1.info"
}
nosta() { echo "Not connected." > "$FX/$1.link"; : > "$FX/$1.info"; }
starts() { [ -f "$FX/hostapd.starts" ] && wc -l < "$FX/hostapd.starts" || echo 0; }
lastv() { sed -n "s/^$1=//p" "$FX/hostapd.last" | head -n 1; }
sync_ap() { : ; }

# ---- render
r() { sh "$WF" render "$W/hostapd/ap5.conf" "$@"; }
r wl5-ap 5220 80 5210 > "$W/r44"
chk "render ch44/80: channel, VHT80 centre 42, HT40+" sh -c "grep -q '^channel=44$' $W/r44 && grep -q '^vht_oper_centr_freq_seg0_idx=42$' $W/r44 && grep -q '^ht_capab=\[HT40+\]$' $W/r44 && [ \$(grep -c '^channel=' $W/r44) = 1 ]"
chk "render keeps SSID/bridge/passphrase from the template" sh -c "grep -q '^ssid=Test Net$' $W/r44 && grep -q '^bridge=br-lan$' $W/r44 && grep -q '^wpa_passphrase=TESTPASS$' $W/r44"
r wl5-ap 5745 80 5775 > "$W/r149"
chk "render ch149/80: centre 155, HT40+" sh -c "grep -q '^channel=149$' $W/r149 && grep -q '^vht_oper_centr_freq_seg0_idx=155$' $W/r149 && grep -q '^ht_capab=\[HT40+\]$' $W/r149"
r wl5-ap 5200 80 5210 > "$W/r40"
chk "render ch40/80: HT40- (secondary below)" grep -q '^ht_capab=\[HT40-\]$' "$W/r40"
r wl5-ap 5180 40 5190 > "$W/r36w40"
chk "render ch36/40: HT40+, VHT 20/40 (chwidth 0)" sh -c "grep -q '^ht_capab=\[HT40+\]$' $W/r36w40 && grep -q '^vht_oper_chwidth=0$' $W/r36w40 && ! grep -q seg0 $W/r36w40"
r wl5-ap 5500 80 5530 > "$W/r100"
chk "render DFS ch100: ieee80211h/d on" sh -c "grep -q '^ieee80211h=1$' $W/r100 && grep -q '^ieee80211d=1$' $W/r100"
r wl24-ap 2462 20 2462 > "$W/r11"
chk "render 2.4 GHz ch11/20: hw_mode g, no VHT, no ht_capab" sh -c "grep -q '^hw_mode=g$' $W/r11 && grep -q '^channel=11$' $W/r11 && ! grep -q 'ieee80211ac=1' $W/r11 && ! grep -q ht_capab $W/r11 && grep -q '^interface=wl24-ap$' $W/r11"

# ---- the AP follows the client
now 100; nosta wl5-sta; nosta wl24-sta; : > "$FX/wl5-ap.info"; : > "$FX/wl24-ap.info"
sh "$WF" once
chk "no uplink yet, within STATIC_AFTER: no AP started" test "$(starts)" = 0
sta wl5-sta 5220 80 5210; sta wl24-sta 2462 20 2462
sh "$WF" once
chk "both clients up: both APs started (5 GHz on 44, 2.4 GHz on 11)" sh -c "[ $(starts) = 2 ] && grep -q 'channel=44' $W/run/wf/ap5.conf && grep -q 'channel=11' $W/run/wf/ap24.conf"
chk "ap24 is rendered from ap5.conf (same SSID, own interface)" sh -c "grep -q '^ssid=Test Net$' $W/run/wf/ap24.conf && grep -q '^interface=wl24-ap$' $W/run/wf/ap24.conf"
sh "$WF" once
chk "steady state: no restart" test "$(starts)" = 2
sta wl5-sta 5745 80 5775
sh "$WF" once
chk "client moved to ch149: 5 GHz AP restarted on 149, 2.4 GHz untouched" sh -c "[ $(starts) = 3 ] && grep -q 'channel=149' $W/run/wf/ap5.conf"
chk "exactly one hostapd per AP (old one stopped)" sh -c "[ \$(ls $W/run/hostapd-*.pid | wc -l) = 2 ]"

# ---- client loses the AP's channel: the AP moves to where the home AP is now (needs two matching scans)
nosta wl5-sta
cat > "$FX/wl5-sta.scan" <<'X'
BSS aa:bb:cc:00:00:01(on wl5-sta)
	freq: 5180.0
	signal: -40.00 dBm
	SSID: Home Net
	VHT operation:
		 * channel width: 1 (80 MHz)
		 * center freq segment 1: 42
BSS aa:bb:cc:00:00:02(on wl5-sta)
	freq: 5745.0
	signal: -70.00 dBm
	SSID: Home Net
BSS aa:bb:cc:00:00:03(on wl5-sta)
	freq: 5220.0
	signal: -20.00 dBm
	SSID: Neighbour
X
now 200; sh "$WF" once
chk "client down < SCAN_AFTER: AP stays" test "$(starts)" = 3
now 230; sh "$WF" once
chk "first scan hit on another channel: only noted (no flapping)" test "$(starts)" = 3
now 233; sh "$WF" once
chk "second matching scan: AP moves to the strongest known SSID's channel 36 (80 MHz); the stronger unknown SSID is ignored" sh -c "[ $(starts) = 4 ] && grep -q '^channel=36$' $W/run/wf/ap5.conf && grep -q '^vht_oper_chwidth=1$' $W/run/wf/ap5.conf"

# ---- no uplink at all after boot: the template's own channel
rm -rf "$W/run/wf" "$W/run"/hostapd-*.pid "$FX/hostapd.starts"; nosta wl5-sta; nosta wl24-sta; : > "$FX/wl5-sta.scan"; : > "$FX/wl24-sta.scan"; : > "$FX/wl5-ap.info"; : > "$FX/wl24-ap.info"
now 1000; sh "$WF" once
chk "no uplink, before STATIC_AFTER: nothing started" test "$(starts)" = 0
now 1061; sh "$WF" once
chk "no uplink after STATIC_AFTER: 5 GHz AP on the template's channel 36, 2.4 GHz AP on its default" sh -c "[ $(starts) = 2 ] && grep -q '^channel=36$' $W/run/wf/ap5.conf && grep -q '^channel=6$' $W/run/wf/ap24.conf && grep -q '^hw_mode=g$' $W/run/wf/ap24.conf"

# ---- uplink health: an associated 5 GHz client whose gateway never answers is blacklisted
cat > "$W/bin/ip" <<'X'
#!/bin/sh
# ip route show default dev <if> -> fixture; ip neigh flush dev <if> -> recorded
case "$1" in route) cat "$FX/route.$5" 2>/dev/null;; neigh) echo "$*" >> "$FX/neigh.flush";; esac; exit 0
X
cat > "$W/bin/arping" <<'X'
#!/bin/sh
echo "$*" >> "$FX/arping.calls"; [ -f "$FX/gw.up" ]
X
cat > "$W/bin/wpa_cli" <<'X'
#!/bin/sh
echo "$*" >> "$FX/wpa_cli.calls"; exit 0
X
cat > "$W/bin/pkill" <<'X'
#!/bin/sh
echo "$*" >> "$FX/pkill.calls"; exit 0
X
chmod +x "$W/bin/ip" "$W/bin/arping" "$W/bin/wpa_cli" "$W/bin/pkill"
export PKILL=$W/bin/pkill IPCMD=$W/bin/ip ARPING=$W/bin/arping WPA_CLI=$W/bin/wpa_cli HEALTH_STA=wl5-sta HEALTH_GRACE=25 HEALTH_FAILS=3
rm -f "$FX"/arping.calls "$FX"/wpa_cli.calls "$FX"/neigh.flush "$FX/gw.up"; rm -rf "$W/run/wf"
echo "default via 10.1.1.1 dev wl5-sta proto dhcp metric 100" > "$FX/route.wl5-sta"
sta wl5-sta 5220 80 5210; nosta wl24-sta
now 2000; sh "$WF" once
chk "new association: neighbour table flushed, udhcpc told to renew, no probe inside the grace period" sh -c "grep -q 'flush dev wl5-sta' $FX/neigh.flush && grep -q -- '-USR1 .*dhcpc -f -i wl5-sta' $FX/pkill.calls && [ ! -f $FX/arping.calls ]"
now 2030; sh "$WF" once; now 2033; sh "$WF" once
chk "dead gateway: probed with a broadcast ARP on the client, not yet blacklisted after 2 misses" sh -c "grep -q -- '-b .*-I wl5-sta 10.1.1.1' $FX/arping.calls && [ ! -f $FX/wpa_cli.calls ]"
now 2036; sh "$WF" once
chk "third miss: BSS blacklisted and the client reassociates" sh -c "grep -q 'blacklist aa:bb:cc:dd:ee:ff' $FX/wpa_cli.calls && grep -q 'reassociate' $FX/wpa_cli.calls"
rm -f "$FX/wpa_cli.calls"; touch "$FX/gw.up"; now 2100; sh "$WF" once; now 2130; sh "$WF" once; now 2133; sh "$WF" once; now 2136; sh "$WF" once
chk "answering gateway: never blacklisted" test ! -f "$FX/wpa_cli.calls"
# reassociation to the same BSS (connected time restarts): treated as a new association, grace period restarts
printf 'Station aa:bb:cc:dd:ee:ff (on wl5-sta)\n\tconnected time:\t2 seconds\n' > "$FX/wl5-sta.station"; rm -f "$FX/pkill.calls"; now 2200; sh "$WF" once
printf 'Station aa:bb:cc:dd:ee:ff (on wl5-sta)\n\tconnected time:\t90 seconds\n' > "$FX/wl5-sta.station"; now 2290; sh "$WF" once
printf 'Station aa:bb:cc:dd:ee:ff (on wl5-sta)\n\tconnected time:\t3 seconds\n' > "$FX/wl5-sta.station"; now 2293; sh "$WF" once
chk "same-BSS reassociation (connected time reset): udhcpc renew again" test "$(wc -l < "$FX/pkill.calls")" = 2
rm -f "$FX/wl5-sta.station"
rm -f "$FX/gw.up" "$FX/route.wl5-sta"; sta wl5-sta 5220 80 5210; rm -rf "$W/run/wf"
now 3000; sh "$WF" once; now 3030; sh "$WF" once; now 3033; sh "$WF" once; now 3036; sh "$WF" once
chk "associated but no lease/default route: counts as dead too" grep -q 'blacklist' "$FX/wpa_cli.calls"
chk "gen_wpa5 (board-network) drops disabled= and priority=" grep -q -E '[(]priority[|]disabled[)]=' "$D/overlay/usr/libexec/patronus/board-network"

# ---- per-uplink source routing (both clients in the same upstream subnet)
cat > "$W/bin/ip2" <<'X'
#!/bin/sh
# stub iproute2: addresses/routes from fixtures, rules and table routes kept in $FX/rules and $FX/tables
[ "$1" = -4 ] && shift; [ "$1" = -o ] && shift
case "$1 $2" in
  "addr show") cat "$FX/addr.$4" 2>/dev/null ;;
  "route show") if [ "$3" = default ]; then cat "$FX/defroute.$5" 2>/dev/null; else cat "$FX/kroute.$4" 2>/dev/null; fi ;;
  "rule list") grep "^$4 " "$FX/rules" 2>/dev/null ;;
  "rule del") grep "^$4 " "$FX/rules" >/dev/null 2>&1 || exit 2; grep -v "^$4 " "$FX/rules" > "$FX/rules.n"; mv "$FX/rules.n" "$FX/rules" ;;
  "rule add") echo "$8 from $4 lookup $6" >> "$FX/rules" ;;
  "route flush") grep -v "^$4 " "$FX/tables" > "$FX/tables.n" 2>/dev/null; mv "$FX/tables.n" "$FX/tables" ;;
  "route replace") shift 2; t=$(echo "$*" | sed -n 's/.* table \([0-9]*\).*/\1/p'); echo "$t $*" >> "$FX/tables" ;;
esac; exit 0
X
chmod +x "$W/bin/ip2"
export IPCMD=$W/bin/ip2 HEALTH_STA= FOLLOW= UPLINK_TABLES="wl5-sta:4241:30241 wl24-sta:4242:30242"
rm -rf "$W/run/wf"; : > "$FX/rules"; : > "$FX/tables"
echo "7: wl5-sta    inet 10.1.1.141/24 brd 10.1.1.255 scope global dynamic wl5-sta" > "$FX/addr.wl5-sta"
echo "8: wl24-sta    inet 10.1.1.173/24 brd 10.1.1.255 scope global wl24-sta" > "$FX/addr.wl24-sta"
echo "10.1.1.0/24 proto kernel scope link src 10.1.1.141" > "$FX/kroute.wl5-sta"
echo "10.1.1.0/24 proto kernel scope link src 10.1.1.173" > "$FX/kroute.wl24-sta"
echo "default via 10.1.1.1 proto dhcp metric 100" > "$FX/defroute.wl5-sta"
echo "default via 10.1.1.1 proto dhcp metric 150" > "$FX/defroute.wl24-sta"
now 4000; sh "$WF" once
chk "same-subnet uplinks: one source rule per address (pref 30241 -> 4241, 30242 -> 4242)" sh -c "grep -qx '30241 from 10.1.1.141 lookup 4241' $FX/rules && grep -qx '30242 from 10.1.1.173 lookup 4242' $FX/rules && [ \$(wc -l < $FX/rules) = 2 ]"
chk "each uplink table: its subnet with its own source address + its gateway" sh -c "grep -q '^4242 10.1.1.0/24 dev wl24-sta src 10.1.1.173 table 4242' $FX/tables && grep -q '^4242 default via 10.1.1.1 dev wl24-sta table 4242' $FX/tables && grep -q '^4241 10.1.1.0/24 dev wl5-sta src 10.1.1.141 table 4241' $FX/tables"
cp "$FX/tables" "$FX/tables.before"; now 4003; sh "$WF" once
chk "steady state: nothing rewritten" sh -c "cmp -s $FX/tables $FX/tables.before && [ \$(wc -l < $FX/rules) = 2 ]"
grep -v '^30242 ' "$FX/rules" > "$FX/r.n"; mv "$FX/r.n" "$FX/rules"; now 4006; sh "$WF" once
chk "a flushed rule is restored" grep -qx '30242 from 10.1.1.173 lookup 4242' "$FX/rules"
echo "7: wl5-sta    inet 10.1.1.150/24 brd 10.1.1.255 scope global dynamic wl5-sta" > "$FX/addr.wl5-sta"; now 4009; sh "$WF" once
chk "new lease on one uplink: its rule follows the address, the old one is gone" sh -c "grep -qx '30241 from 10.1.1.150 lookup 4241' $FX/rules && ! grep -q '10.1.1.141' $FX/rules && [ \$(wc -l < $FX/rules) = 2 ]"
: > "$FX/addr.wl5-sta"; : > "$FX/kroute.wl5-sta"; : > "$FX/defroute.wl5-sta"; now 4012; sh "$WF" once
chk "uplink without an address: rule and table removed, the other uplink untouched" sh -c "! grep -q '^30241 ' $FX/rules && ! grep -q '^4241 ' $FX/tables && grep -qx '30242 from 10.1.1.173 lookup 4242' $FX/rules"
chk "board-network: uplinks answer ARP only for their own address (arp_ignore=1, arp_announce=2)" sh -c "grep -q 'echo 1 > \$c/arp_ignore; echo 2 > \$c/arp_announce' '$D/overlay/usr/libexec/patronus/board-network'"
# apply: the management rule covers every uplink client, not only the 2.4 GHz one
cat > "$W/bin/nft" <<'X'
#!/bin/sh
case "$1 $2" in "list chain") echo "chain input {";; "insert rule") echo "$*" >> "$FX/nft.calls";; esac; exit 0
X
chmod +x "$W/bin/nft"; mkdir -p "$W/etc"
printf 'UPLINKS="wl5-sta wl24-sta"\nWAN_IF=wl24-sta\nMGMT_NET=10.1.1.0/24\n' > "$W/etc/board.sh"; : > "$W/etc/embedded.env"; rm -f "$FX/nft.calls"
sed -e "s#/etc/patronus/embedded.env#$W/etc/embedded.env#; s#/etc/patronus/board.sh#$W/etc/board.sh#" "$D/overlay/usr/libexec/patronus/apply" > "$W/apply"
PATH="$W/bin:$PATH" sh "$W/apply" mgmt
chk "apply mgmt: SSH/web from MGMT_NET accepted on BOTH uplinks" grep -q 'iifname { "wl5-sta", "wl24-sta" } ip saddr 10.1.1.0/24' "$FX/nft.calls"

# wifi-follow re-asserts the management rule after any later apply wiped it (first pass, then every MGMT_EVERY-th)
printf '#!/bin/sh\necho "$*" >> "%s/mgmt.calls"\n' "$FX" > "$W/mgmt-apply"; chmod +x "$W/mgmt-apply"; rm -f "$FX/mgmt.calls"
for _ in 1 2 3 4 5 6; do MGMT_APPLY="$W/mgmt-apply" MGMT_EVERY=3 sh "$WF" once; done
chk "wifi-follow: management rule re-asserted by the daemon (once per MGMT_EVERY passes)" sh -c "[ \"\$(cat '$FX/mgmt.calls' 2>/dev/null)\" = 'mgmt' ] || [ \"\$(wc -l < '$FX/mgmt.calls')\" -ge 1 ]"

# ---- blacklist backoff + drop of a client that never carries traffic
export IPCMD=$W/bin/ip HEALTH_STA=wl5-sta FOLLOW= UPLINK_TABLES= RADIO_STATE=$W/state RADIO_SETUP=$W/bin/radio-setup HEALTH_BACKOFF=60 HEALTH_BACKOFF_MAX=1800 HEALTH_DROP_AFTER=4 HEALTH_DROP_WINDOW=1800 RADIO_HOLD=3600 RADIO_HOLD_MAX=86400
printf '#!/bin/sh\necho "$*" >> "%s/radio-setup.calls"\n' "$FX" > "$W/bin/radio-setup"; chmod +x "$W/bin/radio-setup"
# ip stub that also records "link set"
cat > "$W/bin/ip" <<'X'
#!/bin/sh
case "$1" in route) cat "$FX/route.$5" 2>/dev/null;; neigh) echo "$*" >> "$FX/neigh.flush";; link) echo "$*" >> "$FX/link.calls";; esac; exit 0
X
chmod +x "$W/bin/ip"
rm -rf "$W/run/wf" "$W/state"; rm -f "$FX"/wpa_cli.calls "$FX/gw.up" "$FX"/link.calls "$FX"/radio-setup.calls
echo "default via 10.1.1.1 dev wl5-sta proto dhcp metric 100" > "$FX/route.wl5-sta"; sta wl5-sta 5220 80 5210
bl() { n=$(grep -c '^-p .* blacklist' "$FX/wpa_cli.calls" 2>/dev/null); echo "${n:-0}"; }
pp() { for x; do now "$x"; sh "$WF" once; done; }
pp 5000 5030 5033 5036
chk "backoff: first dead streak (3 misses after the grace period) blacklists at once" test "$(bl)" = 1
pp 5040 5065 5068 5071 5080
chk "backoff: a second dead streak inside the 60 s gap does not blacklist again" test "$(bl)" = 1
pp 5100
chk "backoff: after the gap it does" test "$(bl)" = 2
pp 5103 5130 5133 5136 5160
chk "backoff: the gap doubled (120 s): not again 60 s later" test "$(bl)" = 2
pp 5221
chk "backoff: again after 120 s" test "$(bl)" = 3
rm -f "$FX/wpa_cli.calls"; pp 5224 5250 5253 5256 5470
chk "4th dead streak inside 30 min: no blacklist, the client is dropped (supplicant terminated, interface down)" sh -c "! grep -q blacklist $FX/wpa_cli.calls && grep -q 'terminate' $FX/wpa_cli.calls && grep -q 'link set wl5-sta down' $FX/link.calls && [ -f $W/run/wf/wl5-sta.dropped ] && [ \"\$(cat $W/state/wl5-sta.level)\" = 1 ]"
chk "dropped: held for RADIO_HOLD (3600 s)" test "$(cut -d' ' -f2 "$W/run/wf/wl5-sta.dropped")" = $((5470 + 3600))
pp 5500 5530 5533 5536
chk "dropped client: no health probes, no blacklists" test "$(bl)" = 0
nosta wl5-sta; now 6000; sh "$WF" once
chk "inside the hold: client stays off" sh -c "[ -f $W/run/wf/wl5-sta.dropped ] && [ ! -f $FX/radio-setup.calls ]"
now 9070; sh "$WF" once
chk "hold over: client started again through board-network client5" sh -c "grep -qx 'client5 start' $FX/radio-setup.calls && [ ! -f $W/run/wf/wl5-sta.dropped ] && grep -q 'link set wl5-sta up' $FX/link.calls"
sh "$WF" status | grep -q 'wl5-sta: watched\|drops so far' || true

# ---- radio watchdog: firmware restarts and a wedged firmware (kernel log from a fixture)
DEV=0000:00:00.0
cat > "$W/bin/dmesg" <<'X'
#!/bin/sh
cat "$FX/dmesg" 2>/dev/null
X
chmod +x "$W/bin/dmesg"; mkdir -p "$W/drv"; : > "$W/drv/unbind"; : > "$W/drv/bind"
export DMESG=$W/bin/dmesg RADIO_DEV=$DEV RADIO_WATCH=wl5-sta RADIO_DRV_DIR=$W/drv RADIO_EVERY=1 RADIO_WINDOW=900 RADIO_CRASHES=3 RADIO_WEDGE_LINES=10 RADIO_REBIND_MIN=900 HEALTH_STA=
crash() { echo "[ 1.0] ath10k_pci $DEV: Cannot communicate with firmware, previous wmi cmds: 36904:1, attempting restart" >> "$FX/dmesg"; echo "[ 1.1] ath10k_pci $DEV: device successfully recovered" >> "$FX/dmesg"; }
e143() { i=0; while [ $i -lt "$1" ]; do echo "[ 2.0] ath10k_pci $DEV: failed to start hw scan: -143" >> "$FX/dmesg"; i=$((i+1)); done; }
rm -rf "$W/run/wf" "$W/state"; rm -f "$FX"/wpa_cli.calls "$FX"/link.calls "$FX"/radio-setup.calls; : > "$FX/dmesg"
echo "[ 0.5] ath9k 18100000.wmac: Cannot communicate with firmware" >> "$FX/dmesg"   # another radio: ignored
sta wl5-sta 5745 80 5775
now 7000; sh "$WF" once
crash; now 7030; sh "$WF" once
chk "one firmware restart: logged, client kept" sh -c "[ ! -f $W/run/wf/wl5-sta.dropped ] && [ \"\$(wc -l < $W/run/wf/radio.crashes)\" = 1 ]"
crash; crash; now 7060; sh "$WF" once
chk "3 restarts in 15 min: 5 GHz client dropped, the other radio's lines not counted" sh -c "[ -f $W/run/wf/wl5-sta.dropped ] && grep -q terminate $FX/wpa_cli.calls && grep -q 'link set wl5-sta down' $FX/link.calls"
crash; crash; crash; now 7100; sh "$WF" once
chk "already dropped: no second drop (level stays 1)" test "$(cat "$W/state/wl5-sta.level")" = 1
now $((7060 + 3600)); sh "$WF" once; crash; crash; crash; now $((7060 + 3630)); sh "$WF" once
chk "dropped again after its return: hold doubles (7200 s)" test "$(cut -d' ' -f2 "$W/run/wf/wl5-sta.dropped")" = $((7060 + 3630 + 7200))
# wedge: >= RADIO_WEDGE_LINES ESHUTDOWN errors and no recovery since the last look
rm -rf "$W/run/wf" "$W/state"; rm -f "$FX"/wpa_cli.calls "$FX"/link.calls "$FX"/radio-setup.calls; : > "$FX/dmesg"; : > "$W/drv/unbind"; : > "$W/drv/bind"
export FOLLOW="wl5-sta:wl5-ap:ap5"
now 8000; sh "$WF" once   # AP starts on the client's channel
e143 12; now 8030; sh "$WF" once
chk "wedged firmware: client dropped, device re-probed (unbind+bind), interfaces re-created by board-network radio5" sh -c "[ -f $W/run/wf/wl5-sta.dropped ] && grep -qx '$DEV' $W/drv/unbind && grep -qx '$DEV' $W/drv/bind && grep -qx 'radio5' $FX/radio-setup.calls"
: > "$W/drv/unbind"; e143 12; now 8100; sh "$WF" once
chk "wedged again within RADIO_REBIND_MIN: not re-probed in a loop" test ! -s "$W/drv/unbind"
: > "$FX/dmesg"; now 8130; sh "$WF" once
chk "kernel log ring rolled over (counters went down): no action" test ! -s "$W/drv/unbind"
# the 5 GHz client switched off for the board (UPLINK5=off): crashes never "drop" it, a wedged radio is still re-probed (AP-only)
rm -rf "$W/run/wf" "$W/state"; rm -f "$FX"/wpa_cli.calls "$FX"/link.calls "$FX"/radio-setup.calls; : > "$FX/dmesg"; : > "$W/drv/unbind"; : > "$W/drv/bind"
export WAN5_IF=wl5-sta UPLINK5=off
now 9000; sh "$WF" once; crash; crash; crash; now 9030; sh "$WF" once
chk "UPLINK5=off: firmware restarts counted but no client drop" sh -c "[ ! -f $W/run/wf/wl5-sta.dropped ] && [ ! -f $FX/wpa_cli.calls ]"
e143 12; now 9060; sh "$WF" once
chk "UPLINK5=off: wedged radio re-probed so its access point returns, still no drop" sh -c "grep -qx '$DEV' $W/drv/unbind && grep -qx radio5 $FX/radio-setup.calls && [ ! -f $W/run/wf/wl5-sta.dropped ]"
export WAN5_IF= UPLINK5=
# the UI's board settings follow the 5 GHz client's link: republished once per change, not every pass
rm -rf "$W/run/wf"; : > "$FX/bs.calls"
printf '#!/bin/sh\necho "$*" >> %s/bs.calls\n' "$FX" > "$W/bin/bs"; chmod +x "$W/bin/bs"
export WAN5_IF=wl5-sta BOARD_SETTINGS=$W/bin/bs
rm -f "$FX/wl5-sta.link"; sh "$WF" once; sh "$WF" once
echo "Connected to 02:00:00:00:00:01 (on wl5-sta)" > "$FX/wl5-sta.link"; sh "$WF" once; sh "$WF" once
chk "board settings republished on each 5 GHz link change only (down, up)" test "$(grep -c write "$FX/bs.calls")" = 2
rm -f "$FX/wl5-sta.link"; export WAN5_IF= BOARD_SETTINGS=
export RADIO_WATCH= RADIO_DEV= DMESG=dmesg FOLLOW=

[ "$fails" = 0 ] && echo "wifi-follow: all checks passed" || { echo "wifi-follow: $fails failed"; exit 1; }
