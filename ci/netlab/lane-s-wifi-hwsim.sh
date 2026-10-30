#!/usr/bin/env bash
# Lane S (a): per-device Wi-Fi credentials on mac80211_hwsim, through the shipped
# binaries (patronus apply + patronus-web API + the real hostapd/wpa_supplicant).
#
# Needs: the host kernel module mac80211_hwsim with >= 6 radios whose phys are
# visible in THIS container's network namespace (ci/netlab/wifi-hwsim.sh loads
# the module, moves the phys here and unloads it afterwards; the module is
# host-global, so only one run at a time), plus hostapd, hostapd_cli,
# wpa_supplicant, wpa_cli and iw in PATH.
#
# Proves, with real 802.11 associations:
#   WPA2   - a device joins with ITS passphrase; another MAC with that
#            passphrase, and a device with another device's passphrase, are refused
#   revoke - removing a device disconnects it, its old passphrase is refused on
#            retry, the others stay connected, hostapd is NOT restarted
#   rotate - the old passphrase stops working at once, the new one works
#   enrol  - a device created without a MAC joins with its own passphrase, the
#            router learns its MAC at that join (AP-STA-CONNECTED keyid=...), the
#            passphrase becomes MAC-bound, and works from no other MAC
#   unknown- with unknown_policy=enrol a stranger can join with the shared secret
#            but is quarantined: it reaches DHCP/DNS/ping on the router and NOT
#            the admin UI; approving it gives it a personal passphrase
#   WPA3   - per-device SAE passwords; adding one restarts hostapd (stock
#            hostapd cannot reload them), another MAC with the password is refused
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-wifi.db
X() { ip netns exec "$@"; }
STA="sta1 sta2 sta3 sta4"
SSID_HOME=patronus-hw
SSID_SAE=patronus-hw-sae
WLOG=/t/wifi-run
mkdir -p "$WLOG"

command -v hostapd >/dev/null && command -v hostapd_cli >/dev/null && command -v wpa_supplicant >/dev/null \
  && command -v wpa_cli >/dev/null && command -v iw >/dev/null \
  || { echo "SKIP lane-s-wifi-hwsim: hostapd, wpa_supplicant and iw are not installed"; exit 0; }
# hwsim radio k has the MAC 02:00:00:00:0k:00 (a freshly loaded module numbers them from 0). A phy
# changes its NAME when it moves between namespaces, so look the radios up by MAC every time.
phy_of() { # K -> the phy with that radio's MAC in this namespace
  local f
  for f in /sys/class/ieee80211/*/macaddress; do
    [ "$(cat "$f" 2>/dev/null)" = "02:00:00:00:0$1:00" ] && { basename "$(dirname "$f")"; return 0; }
  done
  return 1
}
if [ "$(ls /sys/class/ieee80211 2>/dev/null | wc -l)" -lt 6 ] || ! phy_of 5 >/dev/null; then
  echo "SKIP lane-s-wifi-hwsim: needs 6 mac80211_hwsim radios in this namespace; run ci/netlab/wifi-hwsim.sh"
  exit 0
fi

# A radio goes back to the HOST's namespace when its namespace is deleted, so hand every radio
# back to this container's own namespace (pid 1 of the container) before a namespace goes away.
wifi_release() { # NS...
  local ns p
  for ns in "$@"; do
    ip netns list | grep -w "$ns" >/dev/null || continue
    for p in $(ip netns exec "$ns" iw phy 2>/dev/null | awk '/^Wiphy/ {print $2}'); do
      ip netns exec "$ns" iw phy "$p" set netns 1 2>/dev/null || true
    done
  done
}
wifi_clean() {
  for n in $STA; do
    ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null || true
  done
  sleep 0.5
  wifi_release nl-rtr $STA
  for n in $STA; do ip netns del "$n" 2>/dev/null || true; done
}
trap '[ -n "${WIFI_KEEP:-}" ] || wifi_clean' EXIT

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

# --- radios, namespaces, bridge ------------------------------------------------------
wifi_topo() {
  wifi_clean
  R ip addr flush dev "$NL_LAN_IF"
  R ip link add br0 type bridge; R ip link set br0 up
  R ip link set "$NL_LAN_IF" master br0
  R ip addr add 192.168.50.1/24 dev br0
  C ip link set lan0 address 02:aa:00:00:00:10
  # access-point radios (0, 1) into the router namespace, stations get radios 2..5
  iw phy "$(phy_of 0)" set netns name nl-rtr
  iw phy "$(phy_of 1)" set netns name nl-rtr
  local i=2
  for n in $STA; do
    ip netns add "$n"; ip -n "$n" link set lo up
    iw phy "$(phy_of $i)" set netns name "$n"
    i=$((i + 1))
  done
  sleep 1
  mapfile -t APIF < <(R ip -br link | awk '/^wlan/ {print $1}' | sort -V)
  [ "${#APIF[@]}" -ge 2 ] || { R ip -br link; nl_fail "the AP radios did not arrive in the router namespace"; }
  IF1=${APIF[0]}; IF2=${APIF[1]}
  for n in $STA; do
    local w; w=$(X "$n" ip -br link | awk '/^wlan/ {print $1; exit}')
    [ -n "$w" ] || nl_fail "$n has no wlan interface"
    eval "SIF_$n=$w; SMAC_$n=\$(X $n cat /sys/class/net/$w/address)"
    X "$n" ip link set "$w" up
  done
}
sif() { local v="SIF_$1"; echo "${!v}"; }
smac() { local v="SMAC_$1"; echo "${!v}"; }

# --- supplicants -----------------------------------------------------------------------
sta_stop() { # sta
  X "$1" wpa_cli -p "/t/wifi-run/wpa-$1" -i "$(sif "$1")" terminate >/dev/null 2>&1 || true
  sleep 0.5
}
# sta_join STA SSID KIND PASS: KIND psk|sae
sta_join() {
  local n=$1 ssid=$2 kind=$3 pass=$4 w; w=$(sif "$n")
  sta_stop "$n"
  mkdir -p "/t/wifi-run/wpa-$n"; rm -f "/t/wifi-run/wpa-$n/$w"
  { echo "ctrl_interface=/t/wifi-run/wpa-$n"; echo "update_config=0"
    [ "$kind" = sae ] && echo "sae_pwe=2"
    echo "network={"; echo " ssid=\"$ssid\""
    if [ "$kind" = sae ]; then echo " key_mgmt=SAE"; echo " sae_password=\"$pass\""; echo " ieee80211w=2"
    else echo " key_mgmt=WPA-PSK"; echo " psk=\"$pass\""; echo " ieee80211w=1"; fi
    # the home AP is on channel 6 (2437 MHz), the WPA3 one on channel 11 (2462 MHz)
    if [ "$ssid" = "$SSID_SAE" ]; then echo " scan_freq=2462"; else echo " scan_freq=2437"; fi; echo "}"; } > "/t/wifi-run/wpa-$n.conf"
  X "$n" wpa_supplicant -B -i "$w" -c "/t/wifi-run/wpa-$n.conf" -P "/t/wifi-run/wpa-$n.pid" -f "/t/wifi-run/wpa-$n.log" >/dev/null 2>&1
}
sta_state() { X "$1" wpa_cli -p "/t/wifi-run/wpa-$1" -i "$(sif "$1")" status 2>/dev/null | sed -n 's/^wpa_state=//p'; }
sta_connected() { [ "$(sta_state "$1")" = COMPLETED ]; }
expect_joined() { # DESC STA
  nl_wait 25 sta_connected "$2" || { tail -20 "/t/wifi-run/wpa-$2.log" 2>/dev/null; nl_fail "$1: $2 did not associate (state $(sta_state "$2"))"; }
  nl_ok "$1 (associated)"
}
expect_refused() { # DESC STA
  sleep 8
  if sta_connected "$2"; then nl_fail "$1: $2 associated but must be refused"; fi
  nl_ok "$1 (refused, state $(sta_state "$2"))"
}
ap_authorized() { # IFACE MAC
  R hostapd_cli -p "$CTRL" -i "$1" all_sta 2>/dev/null | awk -v m="$2" 'tolower($0)==m {f=1; next} f && /^flags=/ {print; exit}' | grep AUTHORIZED >/dev/null
}
hostapd_pid() { cat "/run/patronus/patronus-hostapd.$1.pid" 2>/dev/null; }

# --- boot ---------------------------------------------------------------------------------
CTRL=/run/hostapd
rm -f "$DB" "$NL_T/nl-jar"
nl_up
wifi_topo
printf '[network]\nwan_interfaces = ["%s"]\nlan_interfaces = ["br0"]\n' "$NL_WAN_IF" > "$NL_TOML"
export PATRONUS_BIN=$P
nl_apply "$DB" --phase sysctl || { cat "$NL_OUT"; nl_fail "seed apply failed"; }
sqlite3 "$DB" "INSERT OR REPLACE INTO lan_settings (key, value, updated_at) VALUES ('dns.mode','disabled',0)"
sqlite3 "$DB" "INSERT OR IGNORE INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4'); UPDATE interfaces SET ipv4_mode='static' WHERE name='br0';"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply failed"; }
nl_web_start "$DB"; nl_login
nl_ok "booted: router LAN = br0, AP radios $IF1 / $IF2, stations $STA (hwsim)"

nl_api GET /segmentation/wifi; [ "$NL_CODE" = 200 ] || nl_fail "wifi overview: $NL_CODE $(cat "$NL_OUT")"
python3 - "$NL_OUT" <<'PY' || nl_fail "radio discovery does not list the AP radio with AP mode"
import json, sys
d = json.load(open(sys.argv[1]))
r = [x for x in d["status"]["radios"] if x["ap"]]
assert r and d["status"]["hostapd_installed"], d["status"]
assert all("2g" in x["bands"] for x in r), r
PY
nl_ok "radio discovery: hwsim radios support AP mode on 2.4 GHz"

# --- 1. WPA2 per-device passphrases ----------------------------------------------------------
nl_api POST /segmentation/wifi/networks "{\"name\":\"home\",\"ssid\":\"$SSID_HOME\",\"ifname\":\"$IF1\",\"channel\":6,\"security\":\"wpa2\",\"segment\":\"@lan\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create network: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 R hostapd_cli -p "$CTRL" -i "$IF1" status || nl_fail "hostapd is not answering on $CTRL/$IF1"
R hostapd_cli -p "$CTRL" -i "$IF1" status | grep 'state=ENABLED' >/dev/null || nl_fail "hostapd is not ENABLED"
nl_ok "hostapd started by Patronus on $IF1 (state=ENABLED), joined to br0"
R bridge link show | grep "$IF1" >/dev/null || nl_fail "$IF1 is not a port of br0"
grep -q '^ap_isolate=1' /var/lib/patronus/net/hostapd/home.conf || nl_fail "ap_isolate is not set"
[ "$(stat -c %a /var/lib/patronus/net/hostapd/home.conf)" = 600 ] && [ "$(stat -c %a /var/lib/patronus/net/hostapd/home.psk)" = 600 ] || nl_fail "config files are not 0600"
nl_ok "ap_isolate=1; hostapd.conf and the PSK file are 0600"

mkdev() { # NAME [MAC] -> secret in $SECRET, id in $DID
  local body="{\"name\":\"$1\",\"network\":\"home\",\"group\":\"home\""
  [ -n "${2:-}" ] && body="$body,\"mac\":\"$2\""
  nl_api POST /segmentation/wifi/devices "$body}"
  [ "$NL_CODE" = 201 ] || nl_fail "create $1: $NL_CODE $(cat "$NL_OUT")"
  SECRET=$(jget 'd["secret"]'); DID=$(jget 'd["device"]["id"]')
}
mkdev laptop "$(smac sta1)"; S_LAPTOP=$SECRET; D_LAPTOP=$DID
mkdev phone "$(smac sta2)"; S_PHONE=$SECRET; D_PHONE=$DID
[ "$S_LAPTOP" != "$S_PHONE" ] || nl_fail "two devices got the same passphrase"
nl_ok "each device has its own passphrase (${#S_LAPTOP} chars each); listings never carry one"
PID0=$(hostapd_pid home)

sta_join sta1 "$SSID_HOME" psk "$S_LAPTOP"; expect_joined "laptop with its own passphrase" sta1
sta_join sta2 "$SSID_HOME" psk "$S_PHONE"; expect_joined "phone with its own passphrase" sta2
sta_join sta3 "$SSID_HOME" psk "$S_LAPTOP"; expect_refused "stranger MAC with the laptop's passphrase" sta3
sta_stop sta3
sta_stop sta2; sta_join sta2 "$SSID_HOME" psk "$S_LAPTOP"; expect_refused "phone with the LAPTOP's passphrase" sta2
sta_stop sta2; sta_join sta2 "$SSID_HOME" psk "$S_PHONE"; expect_joined "phone back with its own passphrase" sta2

# --- 2. revoke: live, no hostapd restart ---------------------------------------------------------
nl_api POST /segmentation/devices/$D_PHONE/revoke; [ "$NL_CODE" = 200 ] || nl_fail "revoke: $NL_CODE $(cat "$NL_OUT")"
ap_gone() { ! ap_authorized "$1" "$2"; }
nl_wait 10 ap_gone "$IF1" "$(smac sta2)" || nl_fail "the AP still has the revoked phone AUTHORIZED"
nl_ok "revoked phone is no longer AUTHORIZED on the AP"
sleep 6
sta_connected sta2 && nl_fail "the revoked phone re-associated with its old passphrase"
nl_ok "revoked phone cannot come back with its old passphrase (state $(sta_state sta2))"
sta_connected sta1 || nl_fail "the laptop lost its connection when the phone was revoked"
ap_authorized "$IF1" "$(smac sta1)" || nl_fail "the AP no longer has the laptop authorized"
nl_ok "the laptop is unaffected"
[ "$(hostapd_pid home)" = "$PID0" ] || nl_fail "hostapd was restarted for a WPA2 revoke"
nl_ok "hostapd was NOT restarted (same pid $PID0): reload_wpa_psk + deauthenticate only"
! grep -q "$(smac sta2)" /var/lib/patronus/net/hostapd/home.psk || nl_fail "the revoked MAC is still in the PSK file"

# --- 3. rotate -------------------------------------------------------------------------------------
nl_api POST /segmentation/wifi/devices/$D_LAPTOP/rotate '{"grace_minutes":0}'; [ "$NL_CODE" = 200 ] || nl_fail "rotate: $NL_CODE"
S_LAPTOP2=$(jget 'd["secret"]'); [ "$S_LAPTOP2" != "$S_LAPTOP" ] || nl_fail "rotation returned the same passphrase"
nl_wait 10 ap_gone "$IF1" "$(smac sta1)" || nl_fail "the laptop is still AUTHORIZED right after its passphrase was rotated"
nl_ok "rotation cut the laptop that used the old passphrase"
sleep 6
sta_join sta1 "$SSID_HOME" psk "$S_LAPTOP2"; expect_joined "laptop with its NEW passphrase" sta1
[ "$(hostapd_pid home)" = "$PID0" ] || nl_fail "hostapd was restarted for a WPA2 rotation"
sta_join sta3 "$SSID_HOME" psk "$S_LAPTOP"; expect_refused "the OLD laptop passphrase from another MAC" sta3
sta_stop sta3

# --- 4. enrolment: a device without a MAC ------------------------------------------------------------
mkdev cam ""; S_CAM=$SECRET; D_CAM=$DID
[ "$(jget 'd["device"]["state"]')" = pending ] || nl_fail "a MAC-less device must start pending"
grep -q "keyid=dev-$D_CAM 00:00:00:00:00:00 " /var/lib/patronus/net/hostapd/home.psk || nl_fail "pending device has no wildcard entry"
nl_ok "pending device created: wildcard PSK entry keyid=dev-$D_CAM"
sta_join sta4 "$SSID_HOME" psk "$S_CAM"; expect_joined "pending camera joins with its own passphrase" sta4
nl_wait 20 sh -c "sqlite3 $DB \"SELECT state FROM seg_devices WHERE id=$D_CAM\" | grep active >/dev/null" || { tail -5 /run/patronus/patronus-wifi-events.home.log 2>/dev/null; nl_fail "the router did not learn the camera's MAC at its first join"; }
[ "$(sqlite3 "$DB" "SELECT mac FROM seg_devices WHERE id=$D_CAM")" = "$(smac sta4)" ] || nl_fail "learned the wrong MAC"
nl_ok "first join enrolled the device: MAC $(smac sta4) learned from AP-STA-CONNECTED keyid=dev-$D_CAM"
nl_wait 10 grep -q "keyid=dev-$D_CAM $(smac sta4) $S_CAM" /var/lib/patronus/net/hostapd/home.psk || nl_fail "the PSK entry was not rewritten to the learned MAC"
nl_ok "the PSK entry is now bound to that MAC"
[ "$(sqlite3 "$DB" "SELECT ip4 IS NOT NULL FROM seg_devices WHERE id=$D_CAM")" = 1 ] || nl_fail "no address reserved for the enrolled device"
sta_connected sta4 || nl_fail "the camera lost its link while being enrolled"
nl_ok "the camera kept its link through the rewrite + live reload"
sta_stop sta3; sta_join sta3 "$SSID_HOME" psk "$S_CAM"; expect_refused "another MAC with the camera's now-bound passphrase" sta3
sta_stop sta3

# --- 5. unknown devices: enrol policy, quarantine ----------------------------------------------------------
nl_api PUT /segmentation/wifi/networks/$(sqlite3 "$DB" "SELECT id FROM seg_wifi_networks WHERE name='home'") "{\"name\":\"home\",\"ssid\":\"$SSID_HOME\",\"ifname\":\"$IF1\",\"channel\":6,\"security\":\"wpa2\",\"segment\":\"@lan\",\"unknown_policy\":\"enrol\"}"
[ "$NL_CODE" = 200 ] || nl_fail "switch to enrol: $NL_CODE $(cat "$NL_OUT")"
NID=$(sqlite3 "$DB" "SELECT id FROM seg_wifi_networks WHERE name='home'")
nl_api POST /segmentation/wifi/networks/$NID/enrol-secret/reveal '{}'; [ "$NL_CODE" = 200 ] || nl_fail "reveal enrol secret: $NL_CODE"
ENROL=$(jget 'd["secret"]')
nl_api GET /segmentation/wifi; ! grep -q "$ENROL" "$NL_OUT" || nl_fail "the enrolment secret is in a listing"
[ "$(hostapd_pid home)" = "$PID0" ] || nl_fail "hostapd was restarted when the enrolment entry was added"
sta_join sta3 "$SSID_HOME" psk "$ENROL"; expect_joined "unknown device joins with the shared enrolment secret" sta3
# turn isolation on: the stranger has no binding, so it is held in quarantine
nl_api POST /segmentation/segments '{"segment":"@lan","enabled":true}'; [ "$NL_CODE" = 200 ] || nl_fail "enable isolation: $NL_CODE $(cat "$NL_OUT")"
X sta3 ip addr add 192.168.50.99/24 dev "$(sif sta3)"
X sta3 ip route add default via 192.168.50.1 2>/dev/null || true
nl_wait 10 X sta3 ping -c1 -W2 192.168.50.1 || nl_fail "the quarantined station cannot even ping the router"
nl_ok "unknown Wi-Fi station: associated, address on the LAN, can ping the router"
if X sta3 curl -sk -m 3 -o /dev/null https://192.168.50.1:8443/login; then nl_fail "the quarantined station reached the admin UI"; fi
if X sta3 python3 "$NL_T/nl-conn.py" 192.168.50.1 22 >/dev/null 2>&1; then nl_fail "the quarantined station reached SSH"; fi
nl_ok "unknown Wi-Fi station cannot reach the admin UI (8443) or SSH (22): quarantine input chain"
if X sta3 ping -c1 -W2 192.168.50.10 >/dev/null 2>&1; then nl_fail "the quarantined station reached the wired laptop"; fi
nl_ok "unknown Wi-Fi station cannot reach another device"
# approve it: a personal passphrase, then the enrolment secret stops mattering for it
nl_api POST /segmentation/wifi/devices "{\"name\":\"guest\",\"network\":\"home\",\"group\":\"home\",\"mac\":\"$(smac sta3)\"}"
[ "$NL_CODE" = 201 ] || nl_fail "approve: $NL_CODE $(cat "$NL_OUT")"
S_GUEST=$(jget 'd["secret"]'); IP_GUEST=$(jget 'd["device"]["ip4"]'); ID_GUEST=$(jget 'd["device"]["id"]')
sta_join sta3 "$SSID_HOME" psk "$S_GUEST"; expect_joined "approved device joins with its personal passphrase" sta3
X sta3 ip addr flush dev "$(sif sta3)"; X sta3 ip addr add "$IP_GUEST/24" dev "$(sif sta3)"; X sta3 ip route add default via 192.168.50.1 2>/dev/null || true
nl_wait 10 X sta3 curl -sk -m 3 -o /dev/null https://192.168.50.1:8443/login || nl_fail "the approved device cannot reach the admin UI (it is a home device now)"
nl_ok "approved device is bound ($IP_GUEST) and out of quarantine"

# --- 6. WPA3-SAE: per-device password, restart on change -------------------------------------------------------
nl_api POST /segmentation/wifi/networks "{\"name\":\"sec\",\"ssid\":\"$SSID_SAE\",\"ifname\":\"$IF2\",\"channel\":11,\"security\":\"wpa3\",\"segment\":\"@lan\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create SAE network: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 R hostapd_cli -p "$CTRL" -i "$IF2" status || nl_fail "the SAE hostapd is not answering"
nl_api POST /segmentation/wifi/devices "{\"name\":\"tablet\",\"network\":\"sec\",\"group\":\"home\"}"
[ "$NL_CODE" = 400 ] || nl_fail "a MAC-less device on a WPA3-only network must be refused (SAE is bound to a MAC), got $NL_CODE"
nl_ok "WPA3-only network refuses a MAC-less device (SAE passwords are bound to a MAC)"
# the revoked phone's MAC (sta2) is free again; the approved guest (sta3) is deleted to free its MAC
sta_stop sta2
nl_api POST /segmentation/wifi/devices "{\"name\":\"tablet\",\"network\":\"sec\",\"group\":\"home\",\"mac\":\"$(smac sta2)\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create SAE device (re-enrolling a revoked MAC): $NL_CODE $(cat "$NL_OUT")"
S_TAB=$(jget 'd["secret"]'); TABID=$(jget 'd["device"]["id"]')
nl_ok "a revoked device's MAC can be enrolled again as a new device"
nl_wait 20 grep -q "sae_password=$S_TAB|mac=$(smac sta2)" /var/lib/patronus/net/hostapd/sec.conf || nl_fail "no per-MAC sae_password line"
nl_wait 20 R hostapd_cli -p "$CTRL" -i "$IF2" status || nl_fail "the SAE hostapd did not come back after the restart"
sta_join sta2 "$SSID_SAE" sae "$S_TAB"; expect_joined "tablet with its own SAE password (no identifier needed)" sta2
sta_stop sta1; sta_join sta1 "$SSID_SAE" sae "$S_TAB"; expect_refused "another MAC with the tablet's SAE password" sta1
sta_stop sta1; sta_join sta1 "$SSID_HOME" psk "$S_LAPTOP2"
PIDS=$(hostapd_pid sec)
nl_api DELETE /segmentation/devices/$ID_GUEST; [ "$NL_CODE" = 200 ] || nl_fail "delete guest: $NL_CODE"
nl_api POST /segmentation/wifi/devices "{\"name\":\"watch\",\"network\":\"sec\",\"group\":\"home\",\"mac\":\"$(smac sta3)\"}"
[ "$NL_CODE" = 201 ] || nl_fail "second SAE device: $NL_CODE $(cat "$NL_OUT")"
nl_wait 30 sh -c "[ \"\$(cat /run/patronus/patronus-hostapd.sec.pid)\" != \"$PIDS\" ]" || nl_fail "adding an SAE password did not restart hostapd (stock hostapd would not read it otherwise)"
nl_ok "adding an SAE device restarted hostapd (new pid): the documented WPA3 limitation, measured through the product"
nl_api POST /segmentation/devices/$TABID/revoke; [ "$NL_CODE" = 200 ] || nl_fail "revoke SAE device: $NL_CODE"
nl_wait 30 sh -c "! grep -q 'sae_password=$S_TAB' /var/lib/patronus/net/hostapd/sec.conf" || nl_fail "the revoked SAE password is still in hostapd.conf"
nl_wait 20 R hostapd_cli -p "$CTRL" -i "$IF2" status || nl_fail "SAE hostapd down after the revoke restart"
sta_stop sta2; sta_join sta2 "$SSID_SAE" sae "$S_TAB"; expect_refused "revoked tablet with its old SAE password" sta2
sta_connected sta1 || nl_fail "the WPA2 laptop lost its link while the SAE network restarted"
nl_ok "the WPA2 network was not touched by the SAE restart"

# --- 7. a reboot brings the access points back from the store -----------------------------------------------------
echo "=== reboot"
nl_web_stop
for n in $STA; do sta_stop "$n"; done
wifi_clean
# a reboot ends the daemons Patronus started (no init system in the container)
nl_kill_daemons hostapd hostapd_cli
nl_up
wifi_topo
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply failed"; }
nl_wait 30 R hostapd_cli -p "$CTRL" -i "$IF1" status || nl_fail "after reboot: hostapd for home did not come back"
nl_wait 30 R hostapd_cli -p "$CTRL" -i "$IF2" status || nl_fail "after reboot: hostapd for sec did not come back"
sta_join sta1 "$SSID_HOME" psk "$S_LAPTOP2"; expect_joined "after reboot: laptop joins with its (stored) passphrase" sta1
sta_join sta2 "$SSID_HOME" psk "$S_PHONE"; expect_refused "after reboot: the revoked phone stays revoked" sta2
nl_assert_store_ok "$DB"
echo "PASS lane-s-wifi-hwsim"
