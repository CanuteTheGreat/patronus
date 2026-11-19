#!/usr/bin/env bash
# Lane S (e): automatic Wi-Fi channel choice of the standard tier on mac80211_hwsim, through the shipped binaries
# (patronus apply + patronus-web API + the channel service + the real hostapd/wpa_supplicant), docs/WIFI-AUTO-CHANNEL.md.
#
# Radios (ci/netlab/wifi-hwsim.sh loads 6): 0 = the router's access point, 1 and 3 = neighbour access points (plain
# hostapd in namespace nbr, moved between channels by the test), 2 = a station that stays connected through the moves.
#
# Proves:
#   start    - with neighbours on channels 1 and 6 the access point picks 11 on its own; the API shows the channel and
#              why, the history has a "start" entry, a repeated apply does not restart or re-measure the running radio
#   live     - changing the tuning (a neighbour costs more, fewer samples) restarts nothing
#   CSA      - the neighbours move onto channel 11 and away from the others; "re-check now" (the same code as the
#              nightly check) moves the radio to a quiet channel by channel switch announcement: hostapd keeps its pid,
#              the connected station keeps its association (no disconnect event) and still pings the router, the
#              history says moved by CSA, and hostapd's own files name the new channel
#   restart  - with the switch announcement set to off the next move restarts the radio onto the new channel and the
#              station comes back on it
#   boot     - after a reboot the radio is measured again and avoids the occupied channel
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-wifi-chan.db
X() { ip netns exec "$@"; }
SSID=patronus-chan
WLOG=/t/wifi-run
mkdir -p "$WLOG"

command -v hostapd >/dev/null && command -v hostapd_cli >/dev/null && command -v wpa_supplicant >/dev/null \
  && command -v wpa_cli >/dev/null && command -v iw >/dev/null \
  || { echo "SKIP lane-s-wifi-chan-hwsim: hostapd, wpa_supplicant and iw are not installed"; exit 0; }
phy_of() { # K -> the phy with that radio's MAC in this namespace
  local f
  for f in /sys/class/ieee80211/*/macaddress; do
    [ "$(cat "$f" 2>/dev/null)" = "02:00:00:00:0$1:00" ] && { basename "$(dirname "$f")"; return 0; }
  done
  return 1
}
if [ "$(ls /sys/class/ieee80211 2>/dev/null | wc -l)" -lt 4 ] || ! phy_of 3 >/dev/null; then
  echo "SKIP lane-s-wifi-chan-hwsim: needs mac80211_hwsim radios in this namespace; run ci/netlab/wifi-hwsim.sh"
  exit 0
fi

wifi_release() { # NS...: radios go back to the host's namespace when theirs dies
  local ns p
  for ns in "$@"; do
    ip netns list | grep -w "$ns" >/dev/null || continue
    for p in $(ip netns exec "$ns" iw phy 2>/dev/null | awk '/^Wiphy/ {print $2}'); do
      ip netns exec "$ns" iw phy "$p" set netns 1 2>/dev/null || true
    done
  done
}
nbr_kill() { # kill every neighbour hostapd
  local f
  for f in "$WLOG"/nbr-*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
}
wifi_clean() {
  nl_stop_servers
  nbr_kill
  X sta1 wpa_cli -p "$WLOG/wpa-sta1" -i "${SIF:-wlan0}" terminate >/dev/null 2>&1 || true
  for n in sta1 nbr; do ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null || true; done
  sleep 0.5
  wifi_release nl-rtr sta1 nbr
  for n in sta1 nbr; do ip netns del "$n" 2>/dev/null || true; done
}
trap '[ -n "${WIFI_KEEP:-}" ] || wifi_clean' EXIT

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

wifi_topo() {
  wifi_clean
  R ip addr flush dev "$NL_LAN_IF"
  R ip link add br0 type bridge; R ip link set br0 up
  R ip link set "$NL_LAN_IF" master br0
  R ip addr add 192.168.50.1/24 dev br0
  C ip link set lan0 address 02:aa:00:00:00:10
  iw phy "$(phy_of 0)" set netns name nl-rtr
  ip netns add nbr; ip -n nbr link set lo up
  iw phy "$(phy_of 1)" set netns name nbr
  iw phy "$(phy_of 3)" set netns name nbr
  ip netns add sta1; ip -n sta1 link set lo up
  iw phy "$(phy_of 2)" set netns name sta1
  sleep 1
  IF1=$(R ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$IF1" ] || nl_fail "the AP radio did not arrive in the router namespace"
  mapfile -t NIF < <(X nbr ip -br link | awk '/^wlan/ {print $1}' | sort -V)
  [ "${#NIF[@]}" -ge 2 ] || nl_fail "the neighbour radios did not arrive"
  SIF=$(X sta1 ip -br link | awk '/^wlan/ {print $1; exit}')
  [ -n "$SIF" ] || nl_fail "the station radio did not arrive"
  SMAC=$(X sta1 cat "/sys/class/net/$SIF/address")
  X sta1 ip link set "$SIF" up
}

# neighbour N (0|1) on channel CH, or "off": an open hostapd of its own
nbr_set() {
  local n=$1 ch=$2 pf="$WLOG/nbr-$1.pid" cf="$WLOG/nbr-$1.conf"
  [ -f "$pf" ] && { kill "$(cat "$pf")" 2>/dev/null || true; rm -f "$pf"; sleep 0.5; }
  [ "$ch" = off ] && return 0
  { echo "interface=${NIF[$n]}"; echo "driver=nl80211"; echo "ctrl_interface=$WLOG/nbr-ctrl"
    echo "ssid=neighbour-$n-ch$ch"; echo "hw_mode=g"; echo "channel=$ch"; echo "country_code=US"; } > "$cf"
  X nbr hostapd -B -P "$pf" "$cf" >"$WLOG/nbr-$n.log" 2>&1 || { cat "$WLOG/nbr-$n.log"; nl_fail "neighbour $n did not start on channel $ch"; }
}

# hostapd of the router
CTRL=/run/hostapd
ap_up() { R hostapd_cli -p "$CTRL" -i "$IF1" status 2>/dev/null | grep 'state=ENABLED' >/dev/null; }
ap_chan() { R hostapd_cli -p "$CTRL" -i "$IF1" status 2>/dev/null | sed -n 's/^channel=//p'; }
hostapd_pid() { cat /run/patronus/patronus-hostapd.home.pid 2>/dev/null; }
api_state() { # prints the channel block of the network from GET /segmentation/wifi
  nl_api GET /segmentation/wifi; [ "$NL_CODE" = 200 ] || nl_fail "wifi overview: $NL_CODE"
}
hist_events() { sqlite3 "$DB" "SELECT group_concat(event, ',') FROM (SELECT event FROM seg_wifi_chan_history ORDER BY id)"; }
stale_wait() { # the kernel keeps an access point 30 s after its last beacon: let the old ones age out
  echo "... waiting 25 s for the kernel to forget the neighbours that left"; sleep 25
}

# --- the station ------------------------------------------------------------------------------------------
sta_start() { # PASSPHRASE
  mkdir -p "$WLOG/wpa-sta1"; rm -f "$WLOG/wpa-sta1/$SIF"
  { echo "ctrl_interface=$WLOG/wpa-sta1"; echo "update_config=0"
    echo "network={"; echo " ssid=\"$SSID\""; echo " key_mgmt=WPA-PSK"; echo " psk=\"$1\""; echo " ieee80211w=1"
    echo " freq_list=2412 2437 2462"; echo "}"; } > "$WLOG/wpa-sta1.conf"
  X sta1 wpa_supplicant -B -i "$SIF" -c "$WLOG/wpa-sta1.conf" -P "$WLOG/wpa-sta1.pid" -f "$WLOG/wpa-sta1.log" >/dev/null 2>&1
}
sta_state() { X sta1 wpa_cli -p "$WLOG/wpa-sta1" -i "$SIF" status 2>/dev/null | sed -n 's/^wpa_state=//p'; }
sta_connected() { [ "$(sta_state)" = COMPLETED ]; }
sta_freq() { X sta1 iw dev "$SIF" link 2>/dev/null | sed -n 's/^[[:space:]]*freq: *\([0-9]*\).*/\1/p'; }
sta_disconnects() { grep -c 'CTRL-EVENT-DISCONNECTED' "$WLOG/wpa-sta1.log" 2>/dev/null || true; }
sta_pings() { X sta1 ping -c1 -W2 192.168.50.1; }
freq_of() { echo $((2407 + $1 * 5)); }
want_freq() { [ "$(sta_freq)" = "$(freq_of "$1")" ]; }

# --- boot -------------------------------------------------------------------------------------------------
export PATRONUS_WIFI_CHAN_POLL=2     # the channel service looks for a "re-check now" every 2 s here
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
nl_ok "booted: router LAN = br0, AP radio $IF1, neighbour radios ${NIF[*]}, station radio $SIF (hwsim)"

# --- 1. start: the quietest channel wins ------------------------------------------------------------------------
nbr_set 0 1; nbr_set 1 6
nl_ok "neighbours on channel 1 and channel 6"
nl_api POST /segmentation/wifi/networks "{\"name\":\"home\",\"ssid\":\"$SSID\",\"ifname\":\"$IF1\",\"security\":\"wpa2\",\"segment\":\"@lan\",\"chanlist\":\"1,6,11\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create an automatic network: $NL_CODE $(cat "$NL_OUT")"
nl_wait 60 ap_up || nl_fail "hostapd did not come up"
[ "$(ap_chan)" = 11 ] || { R hostapd_cli -p "$CTRL" -i "$IF1" status; cat "$NL_OUT"; nl_fail "start: the radio is on channel $(ap_chan), not the free channel 11"; }
nl_ok "automatic channel at start: with neighbours on 1 and 6 the radio picked channel 11 on its own"
grep '^channel=11$' /var/lib/patronus/net/hostapd/home.conf >/dev/null || nl_fail "the hostapd.conf does not name channel 11"
api_state
python3 - "$NL_OUT" <<'PY' || nl_fail "the API does not show the automatic channel and why"
import json, sys
d = json.load(open(sys.argv[1]))
n = d["networks"][0]
assert n["channel"] == "auto", n["channel"]
run = d["status"]["networks"][0]["channel"]
assert run["auto"] and run["channel"] == 11, run
assert "channel 11" in run["reason"], run["reason"]
cands = {c["channel"]: c for c in run["candidates"]}
assert set(cands) == {1, 6, 11}, cands
assert cands[11]["neighbours"] == 0 and cands[1]["neighbours"] == 1 and cands[6]["neighbours"] == 1, cands
assert cands[11]["score"] < cands[1]["score"] and cands[11]["score"] < cands[6]["score"], cands
ch = d["channels"][str(n["id"])]
assert [h["event"] for h in ch["history"]] == ["start"], ch["history"]
assert run["csa_capable"] is True, run
PY
nl_ok "API: channel 11, the reason, every candidate's score and neighbours, CSA capable, a 'start' history entry"
PID0=$(hostapd_pid)
nl_api GET /segmentation/wifi >/dev/null
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "second apply failed"; }
[ "$(hostapd_pid)" = "$PID0" ] && [ "$(ap_chan)" = 11 ] || nl_fail "a repeated apply restarted or moved the running radio"
[ "$(hist_events)" = start ] || nl_fail "a repeated apply measured again: $(hist_events)"
nl_ok "a repeated apply leaves the running radio alone (same pid, same channel, no new measurement)"
ps -eo args | grep '[w]ifi-chan run home' >/dev/null || nl_fail "the channel service is not running"
nl_ok "the channel service (patronus wifi-chan run home) is running"

# a device and a station that must keep its link through every move
nl_api POST /segmentation/wifi/devices "{\"name\":\"laptop\",\"network\":\"home\",\"group\":\"home\",\"mac\":\"$SMAC\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create device: $NL_CODE $(cat "$NL_OUT")"
SECRET=$(jget 'd["secret"]')
sta_start "$SECRET"
nl_wait 40 sta_connected || { tail -20 "$WLOG/wpa-sta1.log"; nl_fail "the station did not associate on channel 11"; }
X sta1 ip addr add 192.168.50.50/24 dev "$SIF"
nl_wait 10 sta_pings || nl_fail "the station cannot ping the router"
want_freq 11 || nl_fail "the station is not on channel 11 ($(sta_freq))"
nl_ok "a station is associated on channel 11 and pings the router"
[ "$(hostapd_pid)" = "$PID0" ] || nl_fail "adding a device restarted hostapd"

# --- 2. live: tuning changes restart nothing ----------------------------------------------------------------------
NID=$(sqlite3 "$DB" "SELECT id FROM seg_wifi_networks WHERE name='home'")
put_net() { # extra JSON fields
  nl_api PUT /segmentation/wifi/networks/$NID "{\"name\":\"home\",\"ssid\":\"$SSID\",\"ifname\":\"$IF1\",\"security\":\"wpa2\",\"segment\":\"@lan\",\"unknown_policy\":\"reject\",\"channel\":\"auto\",\"chanlist\":\"1,6,11\"$1}"
  [ "$NL_CODE" = 200 ] || nl_fail "update network: $NL_CODE $(cat "$NL_OUT")"
}
put_net ',"bss_cost":10,"confirm":2,"confirm_gap":2,"min_gain":5,"rounds":2,"dwell":120'
[ "$(hostapd_pid)" = "$PID0" ] || nl_fail "a change of the channel tuning restarted hostapd"
[ "$(sqlite3 "$DB" "SELECT chan_bss_cost||','||chan_confirm||','||chan_confirm_gap FROM seg_wifi_networks WHERE id=$NID")" = "10,2,2" ] || nl_fail "tuning not stored"
nl_ok "tuning (neighbour cost, samples, gap) is live: stored, hostapd not restarted"
nl_api PUT /segmentation/wifi/networks/$NID "{\"name\":\"home\",\"ssid\":\"$SSID\",\"ifname\":\"$IF1\",\"channel\":\"auto\",\"width\":80}"
[ "$NL_CODE" = 400 ] || nl_fail "80 MHz on 2.4 GHz must be refused, got $NL_CODE"
nl_api PUT /segmentation/wifi/networks/$NID "{\"name\":\"home\",\"ssid\":\"$SSID\",\"ifname\":\"$IF1\",\"channel\":\"auto\",\"chanlist\":\"1,99\"}"
[ "$NL_CODE" = 400 ] || nl_fail "a channel list with channel 99 must be refused, got $NL_CODE"
nl_ok "invalid width / channel list are refused (400) and nothing is stored"

# --- 3. CSA: the neighbours move, "re-check now" moves the radio and the station stays -------------------------------
nbr_set 0 11; nbr_set 1 11
nl_ok "both neighbours moved onto channel 11 (the radio's channel)"
stale_wait
D0=$(sta_disconnects)
nl_api POST /segmentation/wifi/networks/$NID/recheck-channel; [ "$NL_CODE" = 200 ] || nl_fail "re-check now: $NL_CODE $(cat "$NL_OUT")"
moved() { [ "$(ap_chan)" != 11 ]; }
nl_wait 120 moved || { sqlite3 "$DB" "SELECT event, channel, reason FROM seg_wifi_chan_history"; nl_fail "the radio did not leave the occupied channel 11"; }
NEWCH=$(ap_chan)
case "$NEWCH" in 1|6) ;; *) nl_fail "moved to channel $NEWCH, not a free candidate";; esac
nl_ok "re-check: the radio moved from channel 11 to the free channel $NEWCH"
[ "$(hostapd_pid)" = "$PID0" ] || nl_fail "the channel move restarted hostapd (it must be a channel switch announcement)"
nl_wait 20 want_freq "$NEWCH" || nl_fail "the station did not follow to channel $NEWCH (on $(sta_freq))"
sta_connected || nl_fail "the station lost its association during the move"
[ "$(sta_disconnects)" = "$D0" ] || nl_fail "the station saw a disconnect during the move"
nl_wait 10 sta_pings || nl_fail "the station cannot ping the router after the move"
nl_ok "CSA: hostapd kept its pid, the station followed to channel $NEWCH with no disconnect and still pings the router"
conf_names() { grep "^channel=$1\$" /var/lib/patronus/net/hostapd/home.conf >/dev/null; }
nl_wait 15 conf_names "$NEWCH" || nl_fail "hostapd's files do not name the new channel"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "apply after the move failed"; }
[ "$(hostapd_pid)" = "$PID0" ] && [ "$(ap_chan)" = "$NEWCH" ] || nl_fail "the next apply restarted the radio after a CSA"
nl_ok "hostapd's files follow the live channel: the next apply finds nothing to do"
ev=$(hist_events)
case "$ev" in start,sample,sample,move) ;; *) nl_fail "history after the move: $ev";; esac
sqlite3 "$DB" "SELECT reason FROM seg_wifi_chan_history WHERE event='move'" | grep 'by CSA' >/dev/null || nl_fail "the move is not recorded as CSA"
[ "$(sqlite3 "$DB" "SELECT requested_at IS NULL FROM seg_wifi_chan_state WHERE network_id=$NID")" = 1 ] || nl_fail "the re-check request was not cleared"
nl_api GET /segmentation/wifi
python3 - "$NL_OUT" "$NEWCH" <<'PY' || nl_fail "the API does not show the move"
import json, sys
d = json.load(open(sys.argv[1]))
run = d["status"]["networks"][0]["channel"]
assert run["channel"] == int(sys.argv[2]) and "by CSA" in run["reason"], run
h = d["channels"][str(d["networks"][0]["id"])]["history"]
assert h[0]["event"] == "move" and "moved from 11" in h[0]["reason"], h[0]
PY
nl_ok "API and history: moved from 11 by CSA, with the reason"

# --- 4. a further re-check with nothing to gain stays ---------------------------------------------------------------------
nl_api POST /segmentation/wifi/networks/$NID/recheck-channel; [ "$NL_CODE" = 200 ] || nl_fail "re-check now: $NL_CODE"
stayed() { [ "$(sqlite3 "$DB" "SELECT count(*) FROM seg_wifi_chan_history WHERE event='stay'")" -ge 1 ]; }
nl_wait 120 stayed || { sqlite3 "$DB" "SELECT event, reason FROM seg_wifi_chan_history"; nl_fail "no 'stay' entry after the second re-check"; }
[ "$(ap_chan)" = "$NEWCH" ] || nl_fail "the radio moved although nothing was clearly better"
nl_ok "hysteresis: nothing clearly better, the radio stays on channel $NEWCH ('stay' in the history)"

# --- 5. channel switch off: the move is a restart ---------------------------------------------------------------------------
put_net ',"bss_cost":10,"confirm":2,"confirm_gap":2,"min_gain":5,"csa":"off"'
nbr_set 0 "$NEWCH"; nbr_set 1 "$NEWCH"
stale_wait
PID1=$(hostapd_pid)
nl_api POST /segmentation/wifi/networks/$NID/recheck-channel; [ "$NL_CODE" = 200 ] || nl_fail "re-check now: $NL_CODE"
restarted() { [ "$(hostapd_pid)" != "$PID1" ] && [ -n "$(hostapd_pid)" ]; }
nl_wait 150 restarted || { sqlite3 "$DB" "SELECT event, reason FROM seg_wifi_chan_history"; nl_fail "with the channel switch off the radio did not move by restart"; }
nl_wait 30 ap_up || nl_fail "hostapd did not come back"
CH2=$(ap_chan)
[ "$CH2" != "$NEWCH" ] || nl_fail "restarted but still on the occupied channel $NEWCH"
nl_wait 60 want_freq "$CH2" || nl_fail "the station did not come back on channel $CH2 (on $(sta_freq))"
nl_wait 20 sta_pings || nl_fail "the station cannot ping the router after the restart"
sqlite3 "$DB" "SELECT reason FROM seg_wifi_chan_history WHERE event='move' ORDER BY id DESC LIMIT 1" | grep 'by restart' >/dev/null || nl_fail "the second move is not recorded as a restart"
sqlite3 "$DB" "SELECT event || ' ch=' || ifnull(channel,'') || ' ' || reason FROM seg_wifi_chan_history ORDER BY id" | sed 's/^/    history: /'
nl_ok "CSA off: the radio restarted onto channel $CH2, the station came back on it, history says 'by restart'"

# --- 6. a reboot measures again ---------------------------------------------------------------------------------------------------
echo "=== reboot"
nl_web_stop
X sta1 wpa_cli -p "$WLOG/wpa-sta1" -i "$SIF" terminate >/dev/null 2>&1 || true
nbr_kill
wifi_clean
nl_kill_daemons hostapd hostapd_cli patronus
nl_up
wifi_topo
nbr_set 0 1; nbr_set 1 6
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply failed"; }
nl_wait 60 ap_up || nl_fail "after reboot: hostapd did not come back"
[ "$(ap_chan)" = 11 ] || nl_fail "after reboot with neighbours on 1 and 6 the radio is on channel $(ap_chan), not 11"
nl_ok "reboot: the radio is measured again at start and takes the free channel 11 (the old record said $CH2)"
[ "$(sqlite3 "$DB" "SELECT count(*) FROM seg_wifi_chan_history WHERE event='start'")" = 2 ] || nl_fail "no second 'start' entry"
nl_assert_store_ok "$DB"
echo "PASS lane-s-wifi-chan-hwsim"
