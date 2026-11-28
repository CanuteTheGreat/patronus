#!/usr/bin/env bash
# Lane S (f): Wi-Fi 6 / 6E / 7 on the standard tier, on mac80211_hwsim, through the shipped binaries (patronus apply +
# patronus-web API + the real hostapd/wpa_supplicant), docs/WIFI-MODERN.md.
#
# Needs (ci/netlab/wifi-hwsim.sh with HWSIM_HOSTAPD_SRC=<version>): hwsim radios and a hostapd + wpa_supplicant built
# with CONFIG_IEEE80211AX/BE (the Gentoo ebuild's options) first on PATH; the distribution's older hostapd stays at
# /usr/sbin/hostapd for the degradation check. Runs twice in the nightly: with the module's mlo=0 (everything but
# multi-link) and with mlo=1 (multi-link radios; their radar detection is refused by hwsim, so the 160 MHz DFS case
# is the mlo=0 pass's).
# Radios: 0 = the router's access point, 1 = the station.
#
# Proves (every association is a real SAE handshake of the station with the router's hostapd):
#   caps     - the API names what the radio supports (Wi-Fi 7, 2.4/5/6 GHz, 320 MHz) and what hostapd was built with
#   ax5      - Wi-Fi 6 on 5 GHz at 80 MHz: the station associates with HE ([HE] in hostapd's station flags)
#   ax160    - Wi-Fi 6 on 5 GHz at 160 MHz (after the DFS channel availability check)
#   6e       - a WPA2 network on 6 GHz is refused with the reason; WPA3 on 6 GHz channel 37 at 160 MHz with a per-device
#              SAE password bound to the station's MAC (H2E only): associated with HE on 6135 MHz, pings the router
#   us       - country US: the regulatory database marks 6 GHz passive-scan, so the network stays off (fail closed)
#              and the API says why; back to DE it comes up again
#   be320    - Wi-Fi 7 on 6 GHz at 320 MHz: associated with EHT ([EHT])
#   mlo      - one SSID over 5 GHz + 6 GHz (multi-link): both links up, the station joins with two links and pings
#   old      - the distribution's hostapd without CONFIG_IEEE80211BE: the same network runs Wi-Fi 6 on one link and
#              the warnings name the missing build option and the missing multi-link support
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-wifi-modern.db
X() { ip netns exec "$@"; }
SSID=patronus-modern
WLOG=/t/wifi-run
mkdir -p "$WLOG"
CTRL=/run/hostapd

command -v hostapd >/dev/null && command -v wpa_supplicant >/dev/null && command -v iw >/dev/null \
  || { echo "SKIP lane-s-wifi-modern-hwsim: hostapd, wpa_supplicant and iw are not installed"; exit 0; }
HAPD=$(command -v hostapd)
grep -a eht_oper_chwidth "$HAPD" >/dev/null && grep -a mld_ap "$HAPD" >/dev/null \
  || { echo "SKIP lane-s-wifi-modern-hwsim: $HAPD has no 802.11be/MLD support (run wifi-hwsim.sh with HWSIM_HOSTAPD_SRC)"; exit 0; }
MLO=$(cat /sys/module/mac80211_hwsim/parameters/mlo 2>/dev/null || echo N)
phy_of() { # K -> the phy with that radio's MAC in this namespace
  local f
  for f in /sys/class/ieee80211/*/macaddress; do
    [ "$(cat "$f" 2>/dev/null)" = "02:00:00:00:0$1:00" ] && { basename "$(dirname "$f")"; return 0; }
  done
  return 1
}
if ! phy_of 0 >/dev/null || ! phy_of 1 >/dev/null; then
  echo "SKIP lane-s-wifi-modern-hwsim: needs mac80211_hwsim radios in this namespace; run ci/netlab/wifi-hwsim.sh"
  exit 0
fi

wifi_release() {
  local ns p
  for ns in "$@"; do
    ip netns list | grep -w "$ns" >/dev/null || continue
    for p in $(ip netns exec "$ns" iw phy 2>/dev/null | awk '/^Wiphy/ {print $2}'); do
      ip netns exec "$ns" iw phy "$p" set netns 1 2>/dev/null || true
    done
  done
}
sta_stop() {
  X sta1 wpa_cli -p "$WLOG/wpa-sta1" -i "${SIF:-wlan0}" terminate >/dev/null 2>&1 || true
  sleep 1
}
wifi_clean() {
  nl_stop_servers
  sta_stop
  for n in sta1; do ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null || true; done
  sleep 0.5
  wifi_release nl-rtr sta1
  ip netns del sta1 2>/dev/null || true
}
trap '[ -n "${WIFI_KEEP:-}" ] || wifi_clean' EXIT
trap 'echo "--- hostapd configs"; for f in /var/lib/patronus/net/hostapd/*.conf; do echo "## $f"; grep -v -E "^(sae_password|wpa_psk)" "$f"; done 2>/dev/null; tail -30 "$WLOG/wpa-sta1.log" 2>/dev/null' ERR
set -E

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

wifi_topo() {
  wifi_clean
  R ip addr flush dev "$NL_LAN_IF"
  R ip link add br0 type bridge; R ip link set br0 up
  R ip link set "$NL_LAN_IF" master br0
  R ip addr add 192.168.50.1/24 dev br0
  iw phy "$(phy_of 0)" set netns name nl-rtr
  ip netns add sta1; ip -n sta1 link set lo up
  iw phy "$(phy_of 1)" set netns name sta1
  sleep 1
  IF1=$(R ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$IF1" ] || nl_fail "the AP radio did not arrive in the router namespace"
  SIF=$(X sta1 ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$SIF" ] || nl_fail "the station radio did not arrive"
  SMAC=$(X sta1 cat "/sys/class/net/$SIF/address")
  X sta1 ip link set "$SIF" up
}

ap_up() { R hostapd_cli -p "$CTRL" -i "$IF1" status 2>/dev/null | grep 'state=ENABLED' >/dev/null; }
ap_down() { ! R hostapd_cli -p "$CTRL" -i "$IF1" status >/dev/null 2>&1; }
hostapd_pid() { cat /run/patronus/patronus-hostapd.home.pid 2>/dev/null; }
sta_flags() { R hostapd_cli -p "$CTRL" -i "$IF1" sta "$SMAC" 2>/dev/null | sed -n 's/^flags=//p'; }
has_flag() { local f; f=$(sta_flags); case "$f" in *"[$1]"*) return 0;; esac; return 1; }

# --- the station: SAE with H2E (6 GHz allows nothing else) ------------------------------------------------------------
sta_start() { # PASSWORD [FREQS]
  sta_stop
  mkdir -p "$WLOG/wpa-sta1"; rm -f "$WLOG/wpa-sta1/$SIF"; : > "$WLOG/wpa-sta1.log"
  { echo "ctrl_interface=$WLOG/wpa-sta1"; echo "update_config=0"; echo "country=$CC"; echo "sae_pwe=1"
    echo "network={"; echo " ssid=\"$SSID\""; echo " key_mgmt=SAE"; echo " sae_password=\"$1\""; echo " ieee80211w=2"
    [ -n "${2:-}" ] && echo " scan_freq=$2"
    echo "}"; } > "$WLOG/wpa-sta1.conf"
  X sta1 wpa_supplicant -B -i "$SIF" -c "$WLOG/wpa-sta1.conf" -P "$WLOG/wpa-sta1.pid" -f "$WLOG/wpa-sta1.log" -dd >/dev/null 2>&1
}
sta_connected() { [ "$(X sta1 wpa_cli -p "$WLOG/wpa-sta1" -i "$SIF" status 2>/dev/null | sed -n 's/^wpa_state=//p')" = COMPLETED ]; }
sta_link() { X sta1 iw dev "$SIF" link 2>/dev/null; }
sta_freq() { sta_link | sed -n 's/^[[:space:]]*freq: *\([0-9]*\).*/\1/p' | head -1; }
sta_pings() { X sta1 ping -c1 -W2 192.168.50.1 >/dev/null; }
sta_ip() { X sta1 ip addr replace 192.168.50.50/24 dev "$SIF"; }
expect_assoc() { # WHAT FLAG FREQ
  nl_wait 60 sta_connected || { tail -40 "$WLOG/wpa-sta1.log"; R hostapd_cli -p "$CTRL" -i "$IF1" status || true; nl_fail "$1: the station did not associate"; }
  [ -z "$3" ] || [ "$(sta_freq)" = "$3" ] || { sta_link; nl_fail "$1: the station is on $(sta_freq) MHz, not $3"; }
  nl_wait 10 has_flag "$2" || { echo "station flags: $(sta_flags)"; nl_fail "$1: the association is not $2"; }
  sta_ip; nl_wait 15 sta_pings || nl_fail "$1: the station cannot ping the router"
}
conf_has() { local l; for l in "$@"; do grep -x -- "$l" /var/lib/patronus/net/hostapd/home.conf >/dev/null || { cat /var/lib/patronus/net/hostapd/home.conf | grep -v -E '^(sae_password|wpa_psk)'; nl_fail "hostapd.conf lacks: $l"; }; done; }

# --- boot -------------------------------------------------------------------------------------------------------------
CC=DE    # DE opens 6 GHz (LPI, 5945-6425 MHz) for an access point in wireless-regdb; US does not (passive scan)
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
nl_ok "booted: router LAN = br0, AP radio $IF1, station radio $SIF (hwsim, $("$HAPD" -v 2>&1 | head -1 || true))"

NET='"name":"home","ssid":"'$SSID'","ifname":"'$IF1'","segment":"@lan","unknown_policy":"reject","country":"'$CC'"'
put_net() { # JSON fields (after the common ones)
  nl_api PUT "/segmentation/wifi/networks/$NID" "{$NET,$1}"
  [ "$NL_CODE" = 200 ] || nl_fail "update network ($1): $NL_CODE $(cat "$NL_OUT")"
}
gen_json() { nl_api GET /segmentation/wifi; [ "$NL_CODE" = 200 ] || nl_fail "wifi overview: $NL_CODE"; }

# --- 1. ax5: Wi-Fi 6 at 80 MHz on 5 GHz --------------------------------------------------------------------------------
nl_api POST /segmentation/wifi/networks "{$NET,\"band\":\"5g\",\"channel\":36,\"width\":80,\"security\":\"wpa3\",\"standard\":\"ax\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create the network: $NL_CODE $(cat "$NL_OUT")"
NID=$(jget 'd["id"]')
nl_api POST /segmentation/wifi/devices "{\"name\":\"laptop\",\"network\":\"home\",\"group\":\"home\",\"mac\":\"$SMAC\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create the device: $NL_CODE $(cat "$NL_OUT")"
SECRET=$(jget 'd["secret"]')
nl_wait 30 ap_up || nl_fail "hostapd did not come up on 5 GHz"
gen_json
python3 - "$NL_OUT" "$IF1" <<'PY' || nl_fail "the API does not describe the radio's and hostapd's capabilities"
import json, sys
d = json.load(open(sys.argv[1])); s = d["status"]
r = [x for x in s["radios"] if sys.argv[2] in x["ifaces"]][0]
assert r["supports"][:3] == ["Wi-Fi 7", "2.4 / 5 / 6 GHz", "320 MHz"], r["supports"]
assert s["hostapd"]["ax"] and s["hostapd"]["be"] and s["hostapd"]["mld"], s["hostapd"]
g = s["networks"][0]["generation"]
assert g["standard"] == "ax" and g["width"] == 80 and not g["warnings"], g
assert 1 <= g["bss_color"] <= 63, g
PY
nl_ok "API: the radio supports Wi-Fi 7, 2.4/5/6 GHz, 320 MHz, WPA3; hostapd has AX+BE+MLD; the network runs Wi-Fi 6 at 80 MHz"
conf_has hw_mode=a channel=36 ieee80211h=1 ieee80211ax=1 he_oper_chwidth=1 he_oper_centr_freq_seg0_idx=42 ieee80211w=2
sta_start "$SECRET"
expect_assoc "5 GHz Wi-Fi 6 at 80 MHz" HE 5180
nl_ok "Wi-Fi 6 (802.11ax) at 80 MHz on 5 GHz: the station associated with HE on 5180 MHz with its own SAE password and pings the router"

# --- 2. ax160: 160 MHz on 5 GHz (36-64 holds radar channels: hostapd waits out the 60 s availability check) -----------
if [ "$MLO" = Y ]; then
  echo "    (mlo=1 radios: hwsim refuses radar detection (EBUSY), the 160 MHz DFS case runs in the mlo=0 pass)"
else
put_net '"band":"5g","channel":36,"width":160,"security":"wpa3","standard":"ax"'
conf_has vht_capab=[VHT160] vht_oper_chwidth=2 he_oper_chwidth=2 he_oper_centr_freq_seg0_idx=50
echo "... DFS channel availability check (60 s)"
nl_wait 120 ap_up || { R hostapd_cli -p "$CTRL" -i "$IF1" status || true; nl_fail "hostapd did not come up at 160 MHz"; }
sta_start "$SECRET"
expect_assoc "5 GHz Wi-Fi 6 at 160 MHz" HE 5180
R iw dev "$IF1" info | grep 'width: 160 MHz' >/dev/null || { R iw dev "$IF1" info; nl_fail "the radio is not at 160 MHz"; }
nl_ok "Wi-Fi 6 at 160 MHz on 5 GHz (after the DFS check): associated with HE, the radio reports width 160 MHz"
fi

# --- 3. 6e: 6 GHz is WPA3-only; a per-device SAE password on channel 37 at 160 MHz --------------------------------------
nl_api PUT "/segmentation/wifi/networks/$NID" "{$NET,\"band\":\"6g\",\"channel\":37,\"width\":160,\"security\":\"wpa2\",\"standard\":\"ax\"}"
[ "$NL_CODE" = 400 ] || nl_fail "a WPA2 network on 6 GHz must be refused, got $NL_CODE"
grep -q 'WPA3' "$NL_OUT" && grep -q 'Per-device credentials' "$NL_OUT" || nl_fail "the refusal does not explain WPA3-only and per-device credentials: $(cat "$NL_OUT")"
nl_ok "a WPA2 network on 6 GHz is refused (400) with the reason and what per-device credentials become"
put_net '"band":"6g","channel":37,"width":160,"security":"wpa3","standard":"ax"'
nl_wait 30 ap_up || nl_fail "hostapd did not come up on 6 GHz"
conf_has op_class=134 channel=37 he_oper_chwidth=2 he_oper_centr_freq_seg0_idx=47 sae_pwe=1 ieee80211w=2
grep -x "sae_password=$SECRET|mac=$SMAC" /var/lib/patronus/net/hostapd/home.conf >/dev/null || nl_fail "no per-MAC SAE password line on 6 GHz"
sta_start "$SECRET"
expect_assoc "6 GHz Wi-Fi 6E at 160 MHz" HE 6135
nl_ok "Wi-Fi 6E: WPA3-SAE (H2E) on 6 GHz channel 37 at 160 MHz with the device's own MAC-bound password: associated with HE on 6135 MHz, pings"

# --- 4. us: fail closed where the regulatory database does not open 6 GHz ------------------------------------------------
NET_DE=$NET; NET=${NET//\"country\":\"DE\"/\"country\":\"US\"}
put_net '"band":"6g","channel":37,"width":160,"security":"wpa3","standard":"ax"'
nl_wait 20 ap_down || nl_fail "the 6 GHz network kept transmitting under country US"
gen_json
python3 - "$NL_OUT" <<'PY' || nl_fail "the API does not say why the 6 GHz network is off"
import json, sys
g = json.load(open(sys.argv[1]))["status"]["networks"][0]["generation"]
assert "regulatory database" in g["error"] and "US" in g["error"], g
PY
nl_ok "country US: wireless-regdb marks 6 GHz passive-scan, the network stays off and the API names the regulatory reason"
NET=$NET_DE

# --- 5. be320: Wi-Fi 7 at 320 MHz -------------------------------------------------------------------------------------------
put_net '"band":"6g","channel":37,"width":320,"security":"wpa3","standard":"be"'
nl_wait 30 ap_up || nl_fail "hostapd did not come up at 320 MHz"
conf_has op_class=137 ieee80211be=1 eht_oper_chwidth=9 eht_oper_centr_freq_seg0_idx=31
sta_start "$SECRET"
expect_assoc "6 GHz Wi-Fi 7 at 320 MHz" EHT 6135
R iw dev "$IF1" info | grep 'width: 320 MHz' >/dev/null || { R iw dev "$IF1" info; nl_fail "the radio is not at 320 MHz"; }
nl_ok "Wi-Fi 7 (802.11be) at 320 MHz on 6 GHz: associated with EHT, the radio reports width 320 MHz"

# --- 6. mlo: one SSID over 5 GHz and 6 GHz -----------------------------------------------------------------------------------
if [ "$MLO" != Y ]; then
  echo "    (mlo=0 radios: the multi-link case runs in the mlo=1 pass)"
else
put_net '"band":"5g","channel":36,"width":80,"security":"wpa3","standard":"be","mlo_links":"6g/37/160"'
two_links() { [ "$(R ls "$CTRL" 2>/dev/null | grep -c "^${IF1}_link")" -ge 2 ] && R hostapd_cli -p "$CTRL" -i "${IF1}_link1" status 2>/dev/null | grep 'state=ENABLED' >/dev/null; }
nl_wait 40 two_links || { ls "$CTRL"; nl_fail "the multi-link access point did not bring up both links"; }
grep -x mld_ap=1 /var/lib/patronus/net/hostapd/home-link1.conf >/dev/null || nl_fail "no link config for 6 GHz"
sta_start "$SECRET"
nl_wait 60 sta_connected || { tail -40 "$WLOG/wpa-sta1.log"; nl_fail "the station did not join the multi-link access point"; }
mlo_ok() { local t; t=$(sta_link); grep -q 'Link 0' <<<"$t" && grep -q 'Link 1' <<<"$t" && grep -q 'freq: 6135' <<<"$t"; }
nl_wait 15 mlo_ok || { sta_link; nl_fail "the station is not associated over two links"; }
sta_ip; nl_wait 15 sta_pings || nl_fail "the multi-link station cannot ping the router"
sta_link | sed 's/^/    /'
gen_json
python3 - "$NL_OUT" <<'PY' || nl_fail "the API does not list the second link"
import json, sys
g = json.load(open(sys.argv[1]))["status"]["networks"][0]["generation"]
assert g["standard"] == "be" and [l["band"] for l in g["links"]] == ["6g"] and not g["warnings"], g
PY
nl_ok "Wi-Fi 7 multi-link: one SSID on 5 GHz (36/80) + 6 GHz (37/160), the station is associated over both links and pings"
fi

# --- 7. old: a hostapd built without 802.11be degrades to Wi-Fi 6 on one link, and says why ---------------------------------
if [ -x /usr/sbin/hostapd ] && ! grep -a eht_oper_chwidth /usr/sbin/hostapd >/dev/null; then
  OLD=$(/usr/sbin/hostapd -v 2>&1 | head -1 || true)
  mkdir -p /opt/wifi/old; ln -sf /usr/sbin/hostapd /opt/wifi/old/hostapd; ln -sf /usr/sbin/hostapd_cli /opt/wifi/old/hostapd_cli
  PATH=/opt/wifi/old:$PATH nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "apply with the old hostapd failed"; }
  grep -q 'CONFIG_IEEE80211BE' "$NL_OUT" && grep -q 'AP MLD' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "the apply does not name the missing hostapd build options"; }
  nl_wait 30 ap_up || nl_fail "the old hostapd did not start the network"
  conf_has ieee80211ax=1
  ! grep -x ieee80211be=1 /var/lib/patronus/net/hostapd/home.conf >/dev/null || nl_fail "Wi-Fi 7 was configured on a hostapd without it"
  [ ! -e /var/lib/patronus/net/hostapd/home-link1.conf ] || nl_fail "a link config was left for a hostapd without multi-link"
  sta_start "$SECRET"
  expect_assoc "Wi-Fi 6 on the older hostapd" HE 5180
  nl_ok "$OLD (no CONFIG_IEEE80211BE): the network runs Wi-Fi 6 on one link, the warnings name the build option and the missing multi-link support"
  PATH=${PATH#/opt/wifi/old:}
else
  echo "    (no distribution hostapd without 802.11be here: degradation proven by the unit tests only)"
fi

nl_assert_store_ok "$DB"
echo "PASS lane-s-wifi-modern-hwsim"
