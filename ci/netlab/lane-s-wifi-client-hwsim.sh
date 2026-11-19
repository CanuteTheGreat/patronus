#!/usr/bin/env bash
# Lane S (f): a Wi-Fi STA uplink as the failover WAN of a gateway group (USE=wifi-client + USE=multiwan) on
# mac80211_hwsim, through the shipped binaries (patronus apply, patronus applyd's gateway monitor, the patronus-web API,
# the real wpa_supplicant and udhcpc). The mwan3-style setup of an OpenWrt router whose backup uplink is a Wi-Fi network
# (e.g. a satellite-internet router's own Wi-Fi), docs/WIFI-UPLINK.md.
#
#   LAN client -- [ router ] -- rtr-wan -- isp ------------------ inet (198.51.100.10 www)
#                       \-- wlan (radio 1, station) ~~ radio 0 (access point "upstream-sat", namespace sat:
#                           hostapd WPA2 + DHCP 10.42.0.100-150, routes 10.42.0.0/24 to inet over 192.0.2.0/24 WITHOUT
#                           NAT, so the internet host sees the router's Wi-Fi lease address only if the router NATs)
#
# Proves:
#   iwd      - an iwd running on the router's radio is ended before wpa_supplicant takes it (never two supplicants),
#              and the apply says so (only when the image has iwd; skipped with a note otherwise)
#   join     - the uplink is configured through the API (not by hand): wpa_supplicant runs for the device with a 0600
#              config, associates (wpa_cli COMPLETED), GET /api/wifi/uplinks reports it connected without the passphrase;
#              the wlan in DHCP mode (role opt1) gets a lease from the upstream DHCP server; outbound NAT on the wlan
#   monitor  - gateway WWAN (dynamic: learned from the wlan's DHCP default route) is online at 10.42.0.1
#   failover - group FAILOVER (WAN tier 1, WWAN tier 2) as default: the LAN uses the wired WAN; the wired WAN's link
#              goes down -> within the monitor's down threshold the default moves to the Wi-Fi uplink and the LAN
#              client still reaches the internet host (which sees the router's Wi-Fi lease address = NAT on the wlan);
#              the wired WAN comes back -> traffic returns to it
#   bad key  - a wrong passphrase: GET /api/wifi/uplinks says, in words, that the passphrase is most likely wrong;
#              the right one reconnects
#   reboot   - fresh namespaces + `patronus apply`: wpa_supplicant and the DHCP client come back by themselves, the
#              uplink reconnects, and failover to it works again from the boot state
set -euo pipefail
set -E
. "$(dirname "$0")/lib.sh"

T=/t/wu; mkdir -p "$T"
DB=$T/config.db
export NO_COLOR=1 CLICOLOR=0 PATRONUS_INIT=direct PATRONUS_NET_DIR=$T/net PATRONUS_RUN_DIR=$T/run
export PATRONUS_APPLYD_SOCKET=$T/applyd.sock PATRONUS_GATEWAY_STATUS=$T/gateway-status.json
export PATRONUS_WPA_CTRL=$T/wpa-ctrl
SSID=upstream-sat
GOOD_PSK=sat-backup-pass-1
BAD_PSK=not-the-right-pass-2
X() { ip netns exec "$@"; }
SAT() { ip netns exec sat "$@"; }
APPLYD_PID=

command -v hostapd >/dev/null && command -v wpa_supplicant >/dev/null && command -v wpa_cli >/dev/null \
  && command -v iw >/dev/null && command -v dnsmasq >/dev/null \
  || { echo "SKIP lane-s-wifi-client-hwsim: hostapd, wpa_supplicant, iw and dnsmasq are not installed"; exit 0; }
command -v udhcpc >/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq udhcpc >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq udhcpc >/dev/null 2>&1; } || true
}
command -v udhcpc >/dev/null || { echo "SKIP lane-s-wifi-client-hwsim: no udhcpc (DHCP client) in this image"; exit 0; }
phy_of() { # K -> the phy with that radio's MAC in this namespace
  local f
  for f in /sys/class/ieee80211/*/macaddress; do
    [ "$(cat "$f" 2>/dev/null)" = "02:00:00:00:0$1:00" ] && { basename "$(dirname "$f")"; return 0; }
  done
  return 1
}
if ! phy_of 0 >/dev/null || ! phy_of 1 >/dev/null; then
  echo "SKIP lane-s-wifi-client-hwsim: needs mac80211_hwsim radios in this namespace; run ci/netlab/wifi-hwsim.sh"
  exit 0
fi

dump() {
  set +e
  echo "--- debug: rtr routes"; R ip -4 route; R ip -4 route show table 4250; R ip -4 addr
  echo "--- debug: gateway status"; cat "$PATRONUS_GATEWAY_STATUS" 2>/dev/null; echo
  echo "--- debug: radios"; R iw dev; R ls /sys/class/ieee80211; ls /sys/class/ieee80211
  echo "--- debug: wpa_cli status"; R wpa_cli -p "$PATRONUS_WPA_CTRL" -i "$WIF" status 2>&1
  echo "--- debug: uplinks API"; nl_api GET /wifi/uplinks; cat "$NL_OUT"; echo
  for f in "$T/applyd.log" "$NL_T/nl-web.log" "$T/run"/patronus-wpa.*.log "$T/run"/patronus-dhcpc.*.log "$T/hostapd.log" "$T/sat-dnsmasq.log"; do
    [ -f "$f" ] && { echo "--- $f"; tail -40 "$f"; }
  done
  true
}
fail() { dump; nl_fail "$*"; }
trap 'echo "ERR at line $LINENO: $BASH_COMMAND" >&2' ERR

applyd_start() {
  env PATRONUS_DB="$DB" RUST_LOG=info ip netns exec nl-rtr "$P" --db "$DB" applyd \
      --socket "$PATRONUS_APPLYD_SOCKET" --group nogroup >>"$T/applyd.log" 2>&1 &
  APPLYD_PID=$!
  for _ in $(seq 1 40); do [ -S "$PATRONUS_APPLYD_SOCKET" ] && return 0; sleep 0.25; done
  fail "patronus applyd did not create its socket"
}
applyd_stop() {
  [ -n "$APPLYD_PID" ] && kill "$APPLYD_PID" 2>/dev/null
  wait "$APPLYD_PID" 2>/dev/null || true
  APPLYD_PID=
  rm -f "$PATRONUS_APPLYD_SOCKET"
}
# what a power cut ends: every daemon the router ran (no init system here), its runtime state
router_daemons_stop() {
  local p
  for p in $(ip netns pids nl-rtr 2>/dev/null); do kill "$p" 2>/dev/null || true; done
  sleep 1
  for p in $(ip netns pids nl-rtr 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$T/run" "$PATRONUS_WPA_CTRL" "$PATRONUS_GATEWAY_STATUS"
}
radio_home() { # the router's radio back to the container's namespace (as when its namespace dies)
  local p
  for p in $(R iw phy 2>/dev/null | awk '/^Wiphy/ {print $2}'); do R iw phy "$p" set netns 1 2>/dev/null || true; done
}
cleanup() {
  set +e
  nl_web_stop; applyd_stop
  radio_home; router_daemons_stop
  for p in $(ip netns pids sat 2>/dev/null); do kill "$p" 2>/dev/null; done
  sleep 0.5
  for p in $(ip netns exec sat iw phy 2>/dev/null | awk '/^Wiphy/ {print $2}'); do ip netns exec sat iw phy "$p" set netns 1; done
  ip netns del sat 2>/dev/null
  nl_down
  true
}
trap cleanup EXIT

must() { # CODE METHOD PATH [JSON]
  local want=$1; shift
  nl_api "$@"
  [ "$NL_CODE" = "$want" ] || fail "$1 $2 -> $NL_CODE (want $want): $(cat "$NL_OUT")"
}
wait_for() { # DESC SECONDS CMD...
  local d=$1 n=$2; shift 2
  for _ in $(seq 1 $((n * 4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "timed out after ${n}s waiting for: $d"
}
who() { C curl -s --max-time 4 "http://$NL_WWW/" | awk '{print $3}'; }
who_is() { [ "$(who)" = "$1" ]; }
default_via() { R ip -4 route show table 4250 proto 253; }
via_is() { default_via | grep "$1" >/dev/null; }
gw_field() { # NAME FIELD -> from GET /api/routing
  nl_api GET /routing >/dev/null
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print([g.get(sys.argv[3]) for g in d["gateways"] if g["name"]==sys.argv[2]][0])' "$NL_OUT" "$1" "$2"
}
gw_online() { [ "$(gw_field "$1" state)" = online ]; }
wpa_state() { R wpa_cli -p "$PATRONUS_WPA_CTRL" -i "$WIF" status 2>/dev/null | sed -n 's/^wpa_state=//p'; }
associated() { [ "$(wpa_state)" = COMPLETED ]; }
lease() { R ip -4 -o addr show dev "$WIF" | awk '{print $4}' | sed -n 's#^\(10\.42\.0\.1[0-5][0-9]\)/24$#\1#p'; }
has_lease() { [ -n "$(lease)" ]; }
uplink_field() { # FIELD -> of the first uplink in GET /api/wifi/uplinks
  nl_api GET /wifi/uplinks >/dev/null
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["uplinks"][0].get(sys.argv[2]))' "$NL_OUT" "$1"
}
uplink_connected() { [ "$(uplink_field connected)" = True ]; }
problem_says_passphrase() { uplink_field problem | grep -i 'wrong passphrase' >/dev/null; }

# --- the upstream access point (a satellite/Wi-Fi router) ----------------------------------------------------
sat_up() {
  ip netns add sat; ip -n sat link set lo up
  iw phy "$(phy_of 0)" set netns name sat
  sleep 1
  SAT_IF=$(SAT ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$SAT_IF" ] || fail "the upstream AP radio did not arrive in its namespace"
  SAT ip addr add 10.42.0.1/24 dev "$SAT_IF"
  SAT sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  { echo "interface=$SAT_IF"; echo "driver=nl80211"; echo "ctrl_interface=$T/sat-ctrl"; echo "ssid=$SSID"
    echo "hw_mode=g"; echo "channel=6"; echo "country_code=US"
    echo "wpa=2"; echo "wpa_key_mgmt=WPA-PSK"; echo "rsn_pairwise=CCMP"; echo "wpa_passphrase=$GOOD_PSK"; } > "$T/sat-hostapd.conf"
  SAT hostapd -B -P "$T/sat-hostapd.pid" -f "$T/hostapd.log" "$T/sat-hostapd.conf" >/dev/null 2>&1 \
    || { cat "$T/hostapd.log"; fail "upstream hostapd did not start"; }
  wait_for "upstream AP enabled" 15 sh -c "ip netns exec sat hostapd_cli -p $T/sat-ctrl -i $SAT_IF status | grep state=ENABLED"
  SAT dnsmasq --no-daemon --port=0 --interface="$SAT_IF" --bind-interfaces --dhcp-range=10.42.0.100,10.42.0.150,12h \
    --dhcp-option=3,10.42.0.1 --dhcp-option=6,"$NL_DNS" --dhcp-leasefile="$T/sat.leases" --log-dhcp \
    --pid-file="$T/sat-dnsmasq.pid" >"$T/sat-dnsmasq.log" 2>&1 &
  nl_ok "upstream access point $SSID (WPA2) with DHCP 10.42.0.100-150 in namespace sat"
}
# its wired side to the internet host; nl-inet is new after every nl_up
sat_link() {
  SAT ip link del sat-up 2>/dev/null || true
  ip link add sat-up netns sat type veth peer name inet2 netns nl-inet
  SAT ip addr add 192.0.2.1/24 dev sat-up; SAT ip link set sat-up up
  SAT ip route replace 198.51.100.0/24 via 192.0.2.10
  INET ip addr add 192.0.2.10/24 dev inet2; INET ip link set inet2 up
  INET ip route add 10.42.0.0/24 via 192.0.2.1
}
radio_to_router() {
  iw phy "$(phy_of 1)" set netns name nl-rtr
  sleep 1
  WIF=$(R ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$WIF" ] || fail "the router's radio did not arrive in its namespace"
}

# --- 1. boot with the wired WAN, the upstream AP in range ------------------------------------------------------
rm -rf "$T"/*; mkdir -p "$T"
nl_up
sat_up; sat_link; radio_to_router
nl_write_installer_toml
nl_apply "$DB" || { cat "$NL_OUT"; fail "boot apply"; }
nl_assert_router_baseline
who_is "$NL_RTR_WAN" || fail "before any uplink config the LAN should leave via the wired WAN"
applyd_start
nl_web_start "$DB"
nl_login
must 200 PUT /interfaces/dhcp-client '{"client":"udhcpc"}'

# --- 2. iwd on the radio is ended before wpa_supplicant takes it ------------------------------------------------
IWD_BIN=$(command -v iwd || ls /usr/libexec/iwd 2>/dev/null || true)
if [ -z "$IWD_BIN" ]; then
  apt-get install -y -qq iwd dbus-daemon >/dev/null 2>&1 || apt-get install -y -qq iwd dbus >/dev/null 2>&1 || true
  IWD_BIN=$(command -v iwd || ls /usr/libexec/iwd 2>/dev/null || true)
fi
IWD=0
if [ -n "$IWD_BIN" ] && command -v dbus-daemon >/dev/null; then
  mkdir -p /run/dbus; [ -S /run/dbus/system_bus_socket ] || dbus-daemon --system --fork >/dev/null 2>&1 || true
  # iwd quits without /dev/rfkill (ci/netlab/wifi-hwsim.sh allows misc devices; the node is made here)
  if [ ! -e /dev/rfkill ] && [ -r /sys/class/misc/rfkill/dev ]; then
    rf=$(cat /sys/class/misc/rfkill/dev); mknod /dev/rfkill c "${rf%:*}" "${rf#*:}" 2>/dev/null || true
  fi
  ip netns exec nl-rtr "$IWD_BIN" >"$T/iwd.log" 2>&1 &
  for _ in $(seq 1 40); do R ip link show "$WIF" >/dev/null 2>&1 || break; sleep 0.25; done
  sleep 1
  if pgrep -x iwd >/dev/null; then
    IWD=1
    R ip link show "$WIF" >/dev/null 2>&1 && fail "iwd runs but $WIF is still there (iwd replaces the radio's device)"
    nl_ok "iwd runs on the router's radio (as the image starts it at boot) and has replaced $WIF with its own device"
  fi
fi
[ "$IWD" = 1 ] || echo "note: iwd could not be started in this container; the iwd hand-over is proven by unit tests only"

# --- 3. the uplink through the API --------------------------------------------------------------------------------
must 200 PUT "/wifi/uplinks/$WIF" "{\"ssid\":\"$SSID\",\"security\":\"wpa2\",\"psk\":\"$GOOD_PSK\",\"description\":\"satellite backup\"}"
APPLIED=$(cat "$NL_OUT")
if [ "$IWD" = 1 ]; then
  grep -q 'iwd' <<<"$APPLIED" || fail "the apply did not say what it did to iwd: $APPLIED"
  pgrep -x iwd >/dev/null && fail "iwd still runs beside wpa_supplicant"
  nl_ok "iwd ended before wpa_supplicant took $WIF ($(python3 -c 'import json,sys; print([l for l in json.load(open(sys.argv[1]))["applied"] if "iwd" in l][0])' "$NL_OUT"))"
  # iwd deleted the radio's device when it took it and removed its own when it stopped: Patronus made it again
  grep -q "$WIF: device created on radio" <<<"$APPLIED" || fail "the device iwd removed was not created again: $APPLIED"
  R ip link show "$WIF" >/dev/null 2>&1 || fail "$WIF does not exist after iwd"
  nl_ok "the radio's device $WIF (removed by iwd) was created again on its radio"
fi
grep -q "$GOOD_PSK" <<<"$APPLIED" && fail "the API response carries the passphrase"
pgrep -f "[w]pa_supplicant -i $WIF -D nl80211" >/dev/null || fail "no wpa_supplicant for $WIF"
CONF=$T/net/wpa/$WIF.conf
[ "$(stat -c %a "$CONF")" = 600 ] || fail "wpa_supplicant config is not 0600"
wait_for "wpa_supplicant associated with $SSID" 30 associated
nl_ok "wpa_supplicant runs for $WIF (config 0600) and is associated with $SSID (wpa_cli COMPLETED)"
wait_for "API reports the uplink connected" 15 uplink_connected
nl_api GET /wifi/uplinks
grep -q "$GOOD_PSK" "$NL_OUT" && fail "GET /wifi/uplinks carries the passphrase"
[ "$(nl_json "$NL_OUT" 'd["uplinks"][0]["has_psk"]')" = True ] || fail "has_psk: $(cat "$NL_OUT")"
nl_ok "GET /api/wifi/uplinks: connected to $(nl_json "$NL_OUT" 'd["uplinks"][0]["ap_bssid"]') at $(nl_json "$NL_OUT" 'd["uplinks"][0]["freq"]') MHz, passphrase never returned"
must 400 PUT "/wifi/uplinks/$WIF" '{"ssid":"x","security":"wpa2","psk":"short"}'
must 400 PUT "/wifi/uplinks/bad%20dev" "{\"ssid\":\"$SSID\",\"psk\":\"$GOOD_PSK\"}"
nl_ok "bad input is refused (400)"

must 200 PUT "/interfaces/$WIF" '{"role":"opt1","ipv4_mode":"dhcp"}'
wait_for "DHCP lease on $WIF" 40 has_lease
LEASE=$(lease)
nl_ok "the Wi-Fi uplink got a DHCP lease from the upstream router: $LEASE"

# --- 4. gateways + monitor ------------------------------------------------------------------------------------
must 201 POST /routing/gateways '{"name":"WAN","interface":"@wan"}'
must 201 POST /routing/gateways '{"name":"WWAN","interface":"@opt1","description":"Wi-Fi backup"}'
wait_for "gateway WWAN online" 20 gw_online WWAN
[ "$(gw_field WWAN resolved_address)" = 10.42.0.1 ] || fail "WWAN should have learned 10.42.0.1 from DHCP, has $(gw_field WWAN resolved_address)"
[ "$(gw_field WWAN dynamic)" = True ] || fail "WWAN should be a dynamic gateway"
wait_for "gateway WAN online" 20 gw_online WAN
nl_ok "monitor: WWAN (dynamic, learned 10.42.0.1 from the Wi-Fi DHCP lease) and WAN online"
nl_assert_nft_has "oifname \"$WIF\" masquerade"
nl_ok "the Wi-Fi uplink carries a gateway, so it gets automatic outbound NAT"

# --- 5. failover --------------------------------------------------------------------------------------------------
must 201 POST /routing/groups '{"name":"FAILOVER","members":"WAN:1, WWAN:2","trigger":"down"}'
must 200 PUT /routing/default '{"ipv4":"FAILOVER"}'
via_is 'via 203.0.113.1 dev rtr-wan' || fail "default via group: $(default_via)"
who_is "$NL_RTR_WAN" || fail "tier 1: the LAN should leave via the wired WAN, got $(who)"
nl_ok "default gateway FAILOVER: tier 1 (wired WAN) carries the LAN's traffic"

failover() { # LABEL link|silent: the wired WAN's link goes down, or its upstream router stops answering pings
  if [ "$2" = link ]; then ISP ip link set up0 down; else ISP ip addr flush dev up0; fi
  local t0=$SECONDS
  wait_for "default route to move to the Wi-Fi uplink ($1)" 20 via_is "via 10.42.0.1 dev $WIF"
  local dt=$((SECONDS - t0))
  [ "$(gw_field WAN state)" = down ] || fail "WAN should be down, is $(gw_field WAN state)"
  wait_for "LAN traffic over the Wi-Fi uplink ($1)" 10 who_is "$(lease)"
  nl_ok "$1: wired WAN $([ "$2" = link ] && echo link down || echo silent) -> default via the Wi-Fi uplink after ${dt} s (down threshold 5 lost probes); the internet host sees $(who) = the router's Wi-Fi lease (NAT on $WIF)"
  if [ "$2" = link ]; then ISP ip link set up0 up; else ISP ip addr add 203.0.113.1/24 dev up0; fi
  wait_for "default route back on the wired WAN ($1)" 30 via_is 'via 203.0.113.1 dev rtr-wan'
  wait_for "LAN traffic back on the wired WAN ($1)" 10 who_is "$NL_RTR_WAN"
  nl_ok "$1: wired WAN back -> traffic returns to it"
}
failover "failover" link

# --- 6. a wrong passphrase says so ------------------------------------------------------------------------------
must 200 PUT "/wifi/uplinks/$WIF" "{\"ssid\":\"$SSID\",\"security\":\"wpa2\",\"psk\":\"$BAD_PSK\"}"
wait_for "the API to name the wrong passphrase" 60 problem_says_passphrase
nl_ok "wrong passphrase -> uplink status: $(uplink_field problem)"
associated && fail "associated with a wrong passphrase?"
who_is "$NL_RTR_WAN" || fail "the wired WAN must keep working while the Wi-Fi uplink is broken"
must 200 PUT "/wifi/uplinks/$WIF" "{\"ssid\":\"$SSID\",\"security\":\"wpa2\",\"psk\":\"$GOOD_PSK\"}"
wait_for "re-associated with the right passphrase" 40 associated
wait_for "API connected again" 15 uplink_connected
wait_for "gateway WWAN online again" 45 gw_online WWAN
grep -q "$WIF holds a DHCP lease but lost its default route" "$T/applyd.log" \
  || fail "the monitor did not ask for a DHCP renew after wpa_supplicant's restart dropped the route"
nl_ok "the right passphrase reconnects (API connected); the monitor renewed the DHCP lease to get the default route back (wpa_supplicant's restart took the device down), WWAN online"

# --- 7. reboot ------------------------------------------------------------------------------------------------------
nl_web_stop; applyd_stop
radio_home; router_daemons_stop
nl_up; sat_link; radio_to_router
nl_apply "$DB" || { cat "$NL_OUT"; fail "reboot apply"; }
grep -q 'wifi-client' "$NL_OUT" || { cat "$NL_OUT"; fail "boot apply did not run the Wi-Fi uplink applier"; }
pgrep -f "[w]pa_supplicant -i $WIF -D nl80211" >/dev/null || { cat "$NL_OUT"; fail "boot: no wpa_supplicant for $WIF"; }
pgrep -f "[u]dhcpc .*$WIF" >/dev/null || { cat "$NL_OUT"; fail "boot: no DHCP client for $WIF"; }
applyd_start
nl_web_start "$DB"; nl_login
wait_for "boot: associated again" 30 associated
wait_for "boot: DHCP lease again" 40 has_lease
wait_for "boot: gateway WWAN online" 30 gw_online WWAN
via_is 'via 203.0.113.1 dev rtr-wan' || fail "boot: default should be the wired WAN: $(default_via)"
nl_ok "reboot: wpa_supplicant and the DHCP client came back by themselves; associated, lease $(lease), WWAN online"
failover "after reboot" silent

# --- 8. removing the uplink stops wpa_supplicant -------------------------------------------------------------------
must 200 PUT /routing/default '{"ipv4":""}'
must 200 DELETE "/wifi/uplinks/$WIF"
wait_for "wpa_supplicant stopped" 10 sh -c "! pgrep -f '[w]pa_supplicant -i $WIF -D nl80211'"
[ -e "$T/net/wpa/$WIF.conf" ] && fail "the uplink's config (with the passphrase) is left behind"
nl_ok "deleting the uplink stops wpa_supplicant and removes its config"
echo "PASS lane-s-wifi-client-hwsim"
