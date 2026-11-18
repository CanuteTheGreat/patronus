#!/usr/bin/env bash
# Lane T (wifi): the guest SSID on mac80211_hwsim, through the shipped binaries
# (patronus apply + patronus-web API + the real hostapd/wpa_supplicant).
# Run by ci/netlab/wifi-hwsim.sh (needs the radios in this namespace; SKIPs otherwise).
#
# Proves, with real 802.11 associations:
#   - the guest SSID comes up from the guest settings alone: hostapd ENABLED, joined to
#     br-guest, ap_isolate=1; a station with the shared password joins, gets DHCP from the
#     guest dnsmasq and reaches the internet, and cannot reach the LAN or the router's UI;
#   - a wrong password is refused; two guests on the SSID cannot reach each other;
#   - a voucher is a second working password that stops working when it expires (a 5 s
#     watcher in the web process re-applies the SSID): its station is dropped and cannot
#     come back, the shared-password station stays;
#   - a new shared password: the old one stops working, the new one works;
#   - switching the guest network off takes the SSID down.
set -euo pipefail
set -E
trap 'echo "ABORT at line $LINENO: $BASH_COMMAND" >&2' ERR
. "$(dirname "$0")/lib.sh"

DB=/t/lane-t-wifi.db
X() { ip netns exec "$@"; }
STA="sta1 sta2"
SSID=Guest-hw
WLOG=/t/wifi-run
mkdir -p "$WLOG"
command -v hostapd >/dev/null && command -v hostapd_cli >/dev/null && command -v wpa_supplicant >/dev/null \
  && command -v wpa_cli >/dev/null && command -v iw >/dev/null && command -v dnsmasq >/dev/null \
  || { echo "SKIP lane-t-guest-wifi: hostapd, wpa_supplicant, iw and dnsmasq are not installed"; exit 0; }
command -v udhcpc >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq udhcpc >/dev/null 2>&1 || true; }
UDHCPC=udhcpc; command -v udhcpc >/dev/null || UDHCPC="busybox udhcpc"
phy_of() { # K -> the phy with that radio's MAC in this namespace
  local f
  for f in /sys/class/ieee80211/*/macaddress; do
    [ "$(cat "$f" 2>/dev/null)" = "02:00:00:00:0$1:00" ] && { basename "$(dirname "$f")"; return 0; }
  done
  return 1
}
if [ "$(ls /sys/class/ieee80211 2>/dev/null | wc -l)" -lt 3 ] || ! phy_of 2 >/dev/null; then
  echo "SKIP lane-t-guest-wifi: needs mac80211_hwsim radios in this namespace; run ci/netlab/wifi-hwsim.sh"
  exit 0
fi
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
out_has() { local pat=$1 out; shift; out=$("$@" 2>&1 || true); grep -q -- "$pat" <<<"$out"; }

# A radio goes back to the HOST's namespace when its namespace is deleted: hand every radio
# back to this container's own namespace (pid 1) before a namespace goes away.
wifi_release() {
  local ns p
  for ns in "$@"; do
    ip netns list | grep -w "$ns" >/dev/null || continue
    for p in $(ip netns exec "$ns" iw phy 2>/dev/null | awk '/^Wiphy/ {print $2}'); do
      ip netns exec "$ns" iw phy "$p" set netns 1 2>/dev/null || true
    done
  done
}
wifi_clean() {
  nl_stop_servers
  for n in $STA; do ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null || true; done
  sleep 0.5
  wifi_release nl-rtr $STA
  for n in $STA; do ip netns del "$n" 2>/dev/null || true; rm -rf "/etc/netns/$n"; done
}
trap '[ -n "${WIFI_KEEP:-}" ] || wifi_clean' EXIT

nl_fail() {
  set +e
  echo "FAIL: $*" >&2
  { echo "--- router"; R ip -br addr; R bridge link; R nft list table inet patronus_guest; echo "--- hostapd"; cat /var/lib/patronus/net/guest/hostapd.conf 2>/dev/null | grep -v -e sae_password -e wpa_passphrase;
    echo "--- hostapd log"; tail -20 /run/patronus/patronus-daemon.guest-hostapd.log 2>/dev/null; echo "--- web log"; tail -15 "$NL_T/nl-web.log"; } >&2 2>/dev/null || true
  exit 1
}

wifi_topo() {
  wifi_clean
  iw phy "$(phy_of 0)" set netns name nl-rtr
  local i=2
  for n in $STA; do
    ip netns add "$n"; ip -n "$n" link set lo up
    mkdir -p "/etc/netns/$n"; : > "/etc/netns/$n/resolv.conf"
    iw phy "$(phy_of $i)" set netns name "$n"
    i=$((i + 1))
  done
  sleep 1
  APIF=$(R ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$APIF" ] || { R ip -br link; nl_fail "the AP radio did not arrive in the router namespace"; }
  for n in $STA; do
    local w; w=$(X "$n" ip -br link | awk '/^wlan/ {print $1; exit}')
    [ -n "$w" ] || nl_fail "$n has no wlan interface"
    eval "SIF_$n=$w; SMAC_$n=\$(X $n cat /sys/class/net/$w/address)"
    X "$n" ip link set "$w" up
  done
}
sif() { local v="SIF_$1"; echo "${!v}"; }
smac() { local v="SMAC_$1"; echo "${!v}"; }
sta_stop() { X "$1" wpa_cli -p "$WLOG/wpa-$1" -i "$(sif "$1")" terminate >/dev/null 2>&1 || true; sleep 0.5; }
sta_join() { # STA PASS
  local n=$1 pass=$2 w; w=$(sif "$n")
  sta_stop "$n"
  mkdir -p "$WLOG/wpa-$n"; rm -f "$WLOG/wpa-$n/$w"
  { echo "ctrl_interface=$WLOG/wpa-$n"; echo "update_config=0"
    echo "network={"; echo " ssid=\"$SSID\""; echo " key_mgmt=WPA-PSK"; echo " psk=\"$pass\""; echo " ieee80211w=1"; echo " scan_freq=2437"; echo "}"; } > "$WLOG/wpa-$n.conf"
  X "$n" wpa_supplicant -B -i "$w" -c "$WLOG/wpa-$n.conf" -P "$WLOG/wpa-$n.pid" -f "$WLOG/wpa-$n.log" >/dev/null 2>&1
}
sta_state() { X "$1" wpa_cli -p "$WLOG/wpa-$1" -i "$(sif "$1")" status 2>/dev/null | sed -n 's/^wpa_state=//p'; }
sta_connected() { [ "$(sta_state "$1")" = COMPLETED ]; }
expect_joined() {
  nl_wait 25 sta_connected "$2" || { tail -20 "$WLOG/wpa-$2.log" 2>/dev/null; nl_fail "$1: $2 did not associate (state $(sta_state "$2"))"; }
  nl_ok "$1 (associated)"
}
expect_refused() { sleep 8; if sta_connected "$2"; then nl_fail "$1: $2 associated but must be refused"; fi; nl_ok "$1 (refused, state $(sta_state "$2"))"; }
sta_dhcp() { # STA
  local n=$1
  NL_N=$n X "$n" $UDHCPC -i "$(sif "$n")" -n -q -t 5 -T 2 -s "$NL_T/nl-udhcpc.sh" >/dev/null 2>&1 || nl_fail "$n got no DHCP lease"
}
sta_ip() { awk '{print $1}' "$NL_T/nl-lease-$1"; }
S1() { X sta1 "$@"; }
sta_net_ok() { X "$1" curl -s -m 4 -o "$NL_OUT.net" "http://$NL_WWW/" && grep -q "sees $NL_RTR_WAN" "$NL_OUT.net"; }

cat > "$NL_T/nl-udhcpc.sh" <<'EOF'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    [ -n "$router" ] && ip route replace default via "${router%% *}" dev "$interface"
    echo "nameserver ${dns%% *}" > /etc/resolv.conf
    echo "$ip ${router%% *} $dns $lease" > "/t/nl-lease-$NL_N"
    ;;
esac
exit 0
EOF
chmod +x "$NL_T/nl-udhcpc.sh"

rm -f "$DB" "$NL_T/nl-jar"
export PATRONUS_GUEST_TICK_SECS=5
nl_write_installer_toml
nl_up
wifi_topo
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply failed"; }
nl_web_start "$DB"; nl_login
nl_bg C python3 "$NL_T/nl-tcp.py" $NL_CLIENT 9000
nl_ok "booted: AP radio $APIF in the router, stations $STA (hwsim)"

echo "=== 1. the guest SSID from the settings alone"
nl_api PUT /svc/guest "{\"enabled\":true,\"vlan_id\":0,\"address\":\"192.168.30.1/24\",\"dns_upstreams\":\"$NL_DNS\",\"wifi\":true,\"ssid\":\"$SSID\",\"wifi_psk\":\"guest-pass-one\",\"wifi_security\":\"wpa2_wpa3\",\"wifi_band\":\"2g\",\"wifi_channel\":6,\"wifi_iface\":\"$APIF\"}"
[ "$NL_CODE" = 200 ] || nl_fail "enable guest Wi-Fi: $NL_CODE $(cat "$NL_OUT")"
CTRL=/run/patronus/guest-hostapd
nl_wait 20 R hostapd_cli -p "$CTRL" -i "$APIF" status || nl_fail "guest hostapd is not answering"
out_has 'state=ENABLED' R hostapd_cli -p "$CTRL" -i "$APIF" status || nl_fail "guest hostapd is not ENABLED"
out_has "$APIF" R bridge link show master br-guest || nl_fail "$APIF is not a port of br-guest"
grep -q '^ap_isolate=1' /var/lib/patronus/net/guest/hostapd.conf || nl_fail "ap_isolate is not set"
[ "$(stat -c %a /var/lib/patronus/net/guest/hostapd.conf)" = 600 ] && [ "$(stat -c %a /var/lib/patronus/net/guest/hostapd.psk)" = 600 ] || nl_fail "guest Wi-Fi files are not 0600"
nl_api GET /svc/guest; [ "$(jget 'd["status"]["wifi"]["available"]')" = True ] || nl_fail "status does not show the radio: $(cat "$NL_OUT")"
nl_ok "guest hostapd ENABLED on $APIF, joined to br-guest, ap_isolate=1, files 0600, status shows the radio"

echo "=== 2. a station joins with the shared password"
sta_join sta1 guest-pass-one; expect_joined "sta1 with the shared password" sta1
sta_dhcp sta1
case "$(sta_ip sta1)" in 192.168.30.*) ;; *) nl_fail "sta1 address $(sta_ip sta1)";; esac
nl_wait 8 sta_net_ok sta1 || nl_fail "a station on the guest SSID has no internet"
nl_ok "sta1 got $(sta_ip sta1) from the guest DHCP and reaches the internet (masqueraded)"
nl_expect_no_tcp "Wi-Fi guest -> LAN client" S1 $NL_CLIENT 9000
nl_expect_no_tcp "Wi-Fi guest -> router web UI" S1 192.168.30.1 8443
sta_join sta2 wrong-password-x; expect_refused "sta2 with a wrong password" sta2

echo "=== 3. guests on the SSID cannot reach each other"
sta_join sta2 guest-pass-one; expect_joined "sta2 with the shared password" sta2
sta_dhcp sta2
nl_bg_ns() { local ns=$1; shift; ip netns exec "$ns" "$@" >/dev/null 2>&1 & NL_PIDS+=($!); }
nl_bg_ns sta2 python3 "$NL_T/nl-tcp.py" 0.0.0.0 9000
sleep 0.5
nl_expect_no_tcp "sta1 -> sta2 over the same SSID (ap_isolate)" S1 "$(sta_ip sta2)" 9000

echo "=== 4. vouchers expire"
nl_api POST /svc/guest/action/voucher '{"name":"visitor","minutes":1}'; [ "$NL_CODE" = 200 ] || nl_fail "voucher: $NL_CODE"
VC=$(jget 'd["wifi_password"]')
grep -q "voucher-" /var/lib/patronus/net/guest/hostapd.psk || nl_fail "the voucher is not in the PSK file"
sta_stop sta2; sta_join sta2 "$VC"; expect_joined "sta2 with the voucher password" sta2
PID0=$(cat /run/patronus/patronus-daemon.guest-hostapd.pid)
nl_ok "voucher accepted live (hostapd pid $PID0 untouched: $(cat /run/patronus/patronus-daemon.guest-hostapd.pid))"
[ "$(cat /run/patronus/patronus-daemon.guest-hostapd.pid)" = "$PID0" ] || nl_fail "adding a voucher restarted hostapd"
echo "waiting for the voucher to expire (1 minute + the 5 s watcher)..."
sleep 70
voucher_gone() { ! grep -q "voucher-" /var/lib/patronus/net/guest/hostapd.psk; }
nl_wait 20 voucher_gone || nl_fail "the expired voucher is still in the PSK file"
sleep 8
if sta_connected sta2; then nl_fail "the station on the expired voucher is still connected"; fi
nl_ok "expired voucher: removed from the PSK file, its station was dropped and cannot return (state $(sta_state sta2))"
nl_wait 25 sta_connected sta1 || nl_fail "the shared-password station lost its connection when a voucher expired"
nl_wait 8 sta_net_ok sta1 || nl_fail "sta1 has no internet after the voucher expired"
nl_ok "the shared-password station reconnected and works"

echo "=== 5. a new shared password"
nl_api POST /svc/guest/action/new_password; [ "$NL_CODE" = 200 ] || nl_fail "new_password: $NL_CODE"
NEWPW=$(jget 'd["wifi_password"]')
nl_wait 20 R hostapd_cli -p "$CTRL" -i "$APIF" status || nl_fail "hostapd is not answering after the password change"
sta_stop sta1; sta_join sta1 guest-pass-one; expect_refused "sta1 with the OLD shared password" sta1
sta_stop sta1; sta_join sta1 "$NEWPW"; expect_joined "sta1 with the new shared password" sta1

echo "=== 6. off: the SSID goes"
nl_api PUT /svc/guest '{"enabled":false}'; [ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE"
guest_hostapd_gone() { ! pgrep -f '[g]uest/hostapd.conf' >/dev/null; }
nl_wait 15 guest_hostapd_gone || nl_fail "guest hostapd still running after switching the guest network off"
! out_has br-guest R ip -br link || nl_fail "br-guest still exists"
nl_ok "off: hostapd stopped, bridge removed"
echo "PASS lane-t-guest-wifi"
