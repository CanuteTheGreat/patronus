#!/bin/sh
# acs-scenario.sh (inside the hwsim container, 3 radios moved in, regulatory domain US): automatic channel selection
# (hostapd ACS) with the configs the image's `ap render` writes, run by the hostapd under test (the Patronus build).
#   radio 0 = the 2.4 GHz radio, radio 1 = the 5 GHz radio, radio 2 = a station that must associate on what ACS picked.
# Cases: the default plan (no channel setting: 2.4 GHz among 1/6/11, 5 GHz 80 MHz without DFS), 5 GHz 40 MHz, 2.4 GHz
# 40 MHz, DFS excluded (a DFS+non-DFS list must land on the non-DFS part) and DFS allowed (a DFS-only list: radar check,
# then ENABLED). For each: hostapd reaches ENABLED, the channel is in the allowed set, the VHT/HE centre channel and the
# HT40 direction agree with the channel ACS picked, and the kernel runs the radio at that width and centre frequency.
# Env: HOSTAPD (binary under test), AP_DIR (dir with usr/libexec/patronus/ap and etc/patronus/board.sh),
#      ACS_CASES (default "default w40 h24 nodfs dfs"). Prints PASS/FAIL lines and "FAILED: none" on success.
set -u
HOSTAPD=${HOSTAPD:-hostapd}; AP_DIR=${AP_DIR:-/w/h/overlay}; CASES=${ACS_CASES:-default w40 h24 nodfs dfs}
T=/tmp/acs; rm -rf $T; mkdir -p $T /run/hostapd; fails=
pass() { echo "PASS: $*"; }; fail() { echo "FAIL: $*"; fails="$fails|$*"; }
set -- $(ls /sys/class/ieee80211 | sort -V); [ $# -ge 3 ] || { echo "SKIP: need 3 radios, have $#"; exit 0; }
P24=$1; P5=$2; PS=$3
for i in $(iw dev | awk '$1 == "Interface" { print $2 }'); do iw dev $i del; done
ip link add br-lan type bridge 2>/dev/null; ip link set br-lan up
iw reg get | grep -m1 country | sed 's/^/    regdomain: /'
# kernel view of a running AP interface: "<width> <center1 MHz>"
kwidth() { iw dev "$1" info | sed -n 's/.*width: \([0-9]*\) MHz.*center1: \([0-9]*\) MHz.*/\1 \2/p; s/.*width: 20 MHz.*/20 0/p' | head -1; }
st() { hostapd_cli -p /run/hostapd -i "$1" status 2>/dev/null | sed -n "s/^$2=//p" | head -1; }
# run_case NAME WAIT 'ap.env lines' -> renders, starts one hostapd per radio, waits for ENABLED; leaves them running
run_case() {
  name=$1; wait=$2; printf '. %s/etc/patronus/board.sh\n%s\nAP_COUNTRY=US\nAP_SSIDS=m\nSSID_m=acs-%s KEY_m=acstest123 SEC_m=wpa2\n%s\n' \
    "$AP_DIR" "$HWSIM_CAPS" "$name" "$3" > $T/board-$name.sh
  rm -rf $T/$name; mkdir -p $T/$name
  AP_BOARD=$T/board-$name.sh AP_RENDER_OUT=$T/$name AP_GUARD=/nonexistent AP_PHY24=$P24 AP_PHY5=$P5 \
    sh $AP_DIR/usr/libexec/patronus/ap render > $T/$name.render 2>&1
  for b in 24 5; do f=$T/$name/ap$b.conf; [ -f $f ] || { fail "$name: ap render wrote no ap$b.conf"; cat $T/$name.render; continue; }
    eval "phy=\$P$b"; i=$(sed -n 's/^interface=//p' $f)
    iw phy $phy interface add $i type __ap
    $HOSTAPD -t $f > $T/$name-$b.log 2>&1 & echo $! > $T/$name-$b.pid
  done
  for b in 24 5; do i=wl$b-m; n=0; seen=
    until [ "$(st $i state)" = ENABLED ]; do s=$(st $i state); case " $seen " in *" $s "*) ;; *) seen="$seen $s";; esac
      n=$((n + 1)); [ $n -gt $wait ] && break; sleep 1; done
    eval "SEEN$b=\"\$seen\""
    [ "$(st $i state)" = ENABLED ] && pass "$name: $i ENABLED after ${n}s (states seen:${seen:- none})" \
      || { fail "$name: $i not ENABLED after ${wait}s (state $(st $i state))"; tail -20 $T/$name-$b.log; }
  done; }
stop_case() { for b in 24 5; do [ -f $T/$1-$b.pid ] && kill $(cat $T/$1-$b.pid) 2>/dev/null; done; sleep 1
  for i in wl24-m wl5-m; do iw dev $i del 2>/dev/null; done; }
in_set() { case " $2 " in *" $1 "*) return 0;; esac; return 1; }
# check5 NAME WIDTH ALLOWED: channel, centre channel and kernel width/centre for the 5 GHz radio
check5() { ch=$(st wl5-m channel); sec=$(st wl5-m secondary_channel); seg=$(st wl5-m vht_oper_centr_freq_seg0_idx); k=$(kwidth wl5-m)
  echo "    $1 5 GHz: channel=$ch secondary=$sec seg0=$seg kernel='$k'"
  in_set "$ch" "$3" && pass "$1: 5 GHz channel $ch is one ACS may use" || fail "$1: 5 GHz channel $ch not in [$3]"
  case $2 in
    80) want=$(( ch >= 149 ? 155 : ( (ch - 36) / 16 ) * 16 + 42 ))
        [ "$seg" = "$want" ] && [ "$k" = "80 $((5000 + 5 * want))" ] && pass "$1: 80 MHz, centre $want ($((5000 + 5 * want)) MHz) in hostapd and the kernel" \
          || fail "$1: 80 MHz centre: hostapd seg0=$seg kernel '$k', expected $want"
        # the HT40 pair must sit inside the 80 MHz block: 36/44/149/157 pair upwards (+1), 40/48/153/161 downwards (-1)
        base=$(( ch >= 149 ? 149 : 36 )); dir=$(( ((ch - base) / 4) % 2 == 0 ? 1 : -1 ))
        [ "$dir" = "$sec" ] && pass "$1: HT40 direction $sec agrees with channel $ch in block $want" \
          || fail "$1: HT40 direction $sec wrong for channel $ch (centre $want)";;
    40) [ "$sec" = 1 ] || [ "$sec" = -1 ] || sec=0; c40=$((ch + 2 * sec))
        [ "$sec" != 0 ] && [ "$k" = "40 $((5000 + 5 * c40))" ] && pass "$1: 40 MHz, centre $c40 in the kernel" || fail "$1: 40 MHz: secondary=$sec kernel '$k'";;
  esac; }
assoc5() { # a station joins the 5 GHz network ACS put on the air
  ip link set sta0 down 2>/dev/null; iw dev sta0 del 2>/dev/null; iw phy $PS interface add sta0 type managed; ip link set sta0 up
  printf 'ctrl_interface=%s/s\nnetwork={\n ssid="acs-%s"\n psk="acstest123"\n}\n' $T "$1" > $T/sta.conf
  wpa_supplicant -i sta0 -c $T/sta.conf > $T/sta-$1.log 2>&1 & sp=$!; n=0
  until wpa_cli -p $T/s -i sta0 status 2>/dev/null | grep wpa_state=COMPLETED >/dev/null; do n=$((n + 1)); [ $n -gt 40 ] && break; sleep 0.5; done
  f=$(wpa_cli -p $T/s -i sta0 status 2>/dev/null | sed -n 's/^freq=//p')
  [ $n -le 40 ] && pass "$1: a station associated on the ACS channel ($f MHz)" || { fail "$1: station did not associate"; tail -15 $T/sta-$1.log; }
  kill $sp 2>/dev/null; sleep 1; iw dev sta0 del 2>/dev/null; }
NODFS5="36 40 44 48 149 153 157 161 165"
# hwsim radios do not have the IPQ6018's HT/VHT capabilities (LDPC, STBC, beamforming): the board's capability strings
# are replaced by what hwsim offers; the channel plan lines (HT40 direction, centre channel, ACS limits) stay the image's
HWSIM_CAPS="AP_HTCAPS24='[SHORT-GI-20][SHORT-GI-40]' AP_HTCAPS5='[SHORT-GI-20][SHORT-GI-40]' AP_VHTCAPS5='[SHORT-GI-80]'"
for c in $CASES; do case $c in
default)
  # the image's default: nothing about channels in ap.env
  run_case default 60 ""
  c24=$(st wl24-m channel); in_set "$c24" "1 6 11" && pass "default: 2.4 GHz ACS picked $c24 (one of 1/6/11)" || fail "default: 2.4 GHz channel $c24 not 1/6/11"
  [ "$(st wl24-m secondary_channel)" = 0 ] && pass "default: 2.4 GHz at 20 MHz" || fail "default: 2.4 GHz secondary $(st wl24-m secondary_channel)"
  grep -q '^acs_exclude_dfs=1' $T/default/ap5.conf && grep -q '^chanlist=1 6 11' $T/default/ap24.conf && pass "default: rendered ACS limits (no DFS, 1/6/11)" || fail "default: ACS limits not rendered"
  check5 default 80 "$NODFS5"
  assoc5 default
  stop_case default;;
w40)
  run_case w40 60 "AP_HT5=40"; check5 w40 40 "$NODFS5"; stop_case w40;;
h24)
  run_case h24 60 "AP_HT24=40 AP_CHANLIST24="
  c=$(st wl24-m channel); s=$(st wl24-m secondary_channel); k=$(kwidth wl24-m); echo "    h24 2.4 GHz: channel=$c secondary=$s kernel='$k'"
  c40=$((c + 2 * s)); { [ "$s" = 1 ] || [ "$s" = -1 ]; } && [ $((c + 4 * s)) -ge 1 ] && [ $((c + 4 * s)) -le 13 ] && [ "$k" = "40 $((2407 + 5 * c40))" ] \
    && pass "h24: 2.4 GHz 40 MHz on $c with its secondary inside the band (centre $((2407 + 5 * c40)) MHz)" || fail "h24: 2.4 GHz 40 MHz: channel $c secondary $s kernel '$k'"
  stop_case h24;;
nodfs)
  run_case nodfs 60 "AP_CHANLIST5=\"52 56 60 64 149 153 157 161\""
  check5 nodfs 80 "149 153 157 161"
  case "$SEEN5" in *DFS*) fail "nodfs: a radar check ran although DFS is excluded";; *) pass "nodfs: no radar check";; esac
  stop_case nodfs;;
dfs)
  # DFS allowed and only DFS channels listed: ACS picks one, hostapd runs the 60 s channel availability check first
  run_case dfs 150 "AP_DFS=1 AP_CHANLIST5=\"52 56 60 64\""
  check5 dfs 80 "52 56 60 64"
  case "$SEEN5" in *DFS*) pass "dfs: radar check (DFS state) before broadcasting";; *) fail "dfs: no DFS state seen ($SEEN5)";; esac
  assoc5 dfs
  stop_case dfs;;
esac; done
if [ -n "$fails" ]; then echo "--- render outputs"; cat $T/*.render 2>/dev/null; echo "--- iw dev"; iw dev; fi
echo "FAILED: ${fails:-none}"
[ -z "$fails" ]
