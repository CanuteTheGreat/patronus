#!/bin/sh
# Host test of overlay/usr/libexec/patronus/wifi-follow with stub iw/hostapd (no radio, no root).
# Each check prints "ok: ..." or "FAIL: ..."; the script exits non-zero if any failed.
D=$(cd "$(dirname "$0")/.." && pwd)
WF=$D/overlay/usr/libexec/patronus/wifi-follow
W=$(mktemp -d "${TMPDIR:-/tmp}/wf-test.XXXX"); trap 'for p in "$W"/run/hostapd-*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done; rm -rf "$W"' EXIT
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

[ "$fails" = 0 ] && echo "wifi-follow: all checks passed" || { echo "wifi-follow: $fails failed"; exit 1; }
