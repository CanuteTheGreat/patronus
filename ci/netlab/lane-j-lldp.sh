#!/usr/bin/env bash
# Lane J: LLDP (USE=lldp). A second, independent lldpd runs on the LAN client
# (a stand-in for a managed switch, system name "nl-switch", port = its lan0)
# and speaks real IEEE 802.1AB frames (ethertype 0x88cc) over the veth pair to
# the router. With the LLDP page enabled for @lan only, the router's lldpd
# (a) announces the router on the LAN cable (the client's lldpd lists it as
# its neighbour), (b) lists nl-switch with its port and chassis in the
# status the page renders, (c) sends nothing on the WAN port, which is not
# listed; it survives a reboot (patronus apply); rx-only keeps the router
# silent while still hearing the switch; disabling stops the daemon.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-lldp.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons lldpd
pkill -x lldpd 2>/dev/null || true
SW_SOCK=/tmp/nl-sw-lldpd.socket
SW_CONF=/tmp/nl-sw-lldpd.conf
mkdir -p /run/lldpd

sw_start() {
  cat > "$SW_CONF" <<CONF
configure system hostname nl-switch
configure lldp tx-interval 1
configure lldp portidsubtype ifname
CONF
  rm -f "$SW_SOCK"
  # the switch is a real lldpd of its own, inside the client namespace
  ip netns exec nl-client lldpd -d -u "$SW_SOCK" -p /tmp/nl-sw-lldpd.pid -O "$SW_CONF" -I lan0 \
    >"$NL_T/nl-sw-lldpd.log" 2>&1 &
  SW_PID=$!
  nl_wait 10 test -S "$SW_SOCK" || { cat "$NL_T/nl-sw-lldpd.log"; nl_fail "the client's lldpd did not start"; }
}
sw_stop() { pkill -F /tmp/nl-sw-lldpd.pid 2>/dev/null || true; sleep 0.5; }
# what the "switch" has heard (system names of its neighbours)
sw_hears() { lldpcli -u "$SW_SOCK" -f keyvalue show neighbors details 2>/dev/null | grep -F "chassis.name=" || true; }
# LLDP frames seen on a wire for N seconds, by source role
frames() { # NETNS DEV SECONDS
  ip netns exec "$1" timeout "$3" tcpdump -i "$2" -n -e -c 50 ether proto 0x88cc 2>/dev/null | grep -c "ethertype LLDP" || true
}

nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login

echo "=== validation"
nl_api_code "bad interface" 400 POST /svc/lldp/interfaces '{"iface":"lan;x"}'
nl_api_code "bad mode" 400 POST /svc/lldp/interfaces '{"iface":"@lan","mode":"both"}'
nl_api_code "enable without an interface" 400 PUT /svc/lldp '{"enabled":true}'
nl_api_code "bad interval" 400 PUT /svc/lldp '{"tx_interval":0}'
nl_api_ok "LAN" POST /svc/lldp/interfaces '{"iface":"@lan","description":"core uplink"}'
ROW=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_code "duplicate" 400 POST /svc/lldp/interfaces '{"iface":"@lan"}'
pgrep -x lldpd >/dev/null && nl_fail "lldpd started although a change was refused"
nl_ok "bad interface/mode/interval, a missing interface and a duplicate are refused (400), nothing started"

echo "=== before: the switch hears nothing from the router"
sw_start
sleep 3
[ -z "$(sw_hears)" ] || nl_fail "the switch already hears a neighbour: $(sw_hears)"
nl_ok "no LLDP neighbour before the page is enabled"

echo "=== enable on @lan"
nl_api_ok "settings" PUT /svc/lldp '{"system_name":"nl-router","tx_interval":1}'
nl_api_ok "enable" PUT /svc/lldp '{"enabled":true}'
nl_wait 10 pgrep -x lldpd || { tail -20 "$NL_T/nl-web.log"; nl_fail "lldpd did not start"; }
CONF=/var/lib/patronus/net/lldpd.conf
grep -x "configure ports $NL_LAN_IF lldp status rx-and-tx" "$CONF" >/dev/null \
  && grep -x 'configure system hostname nl-router' "$CONF" >/dev/null \
  || { cat "$CONF"; nl_fail "lldpd.conf does not carry the page's settings"; }
# lldpd renames its processes ("lldpd: monitor."), so the daemon is asked instead of its command line
RSOCK=$(find /run /var/run /var/lib/patronus -name lldpd.socket 2>/dev/null | head -1)
[ -S "$RSOCK" ] || nl_fail "router lldpd control socket not found"
IFS_SEEN=$(lldpcli -u "$RSOCK" -f keyvalue show interfaces | sed -n 's/^lldp\.\([^.]*\)\..*/\1/p' | sort -u | tr '\n' ' ')
[ "$IFS_SEEN" = "$NL_LAN_IF " ] || nl_fail "lldpd is not limited to $NL_LAN_IF: [$IFS_SEEN]"
nl_ok "lldpd running for $NL_LAN_IF only (its interface list: $IFS_SEEN)"
nl_wait 20 sh -c "lldpcli -u $SW_SOCK -f keyvalue show neighbors details | grep -qF 'chassis.name=nl-router'" \
  || { lldpcli -u "$SW_SOCK" show neighbors details || true; nl_fail "the switch never heard the router's LLDP announcement"; }
nl_ok "the switch hears the router: $(sw_hears | head -1)"

echo "=== the router lists the switch (real frames, read live)"
ok=0
for _ in $(seq 1 30); do
  nl_api GET /svc/lldp
  if python3 - "$NL_OUT" <<'PY' 2>/dev/null
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
n = [x for x in st["neighbors"] if x.get("system_name") == "nl-switch"]
assert n, st
assert n[0]["interface"] == "rtr-lan" and n[0]["protocol"] == "LLDP", n
assert n[0]["port_id"] == "lan0", n
assert st["neighbor_count"] == len(st["neighbors"]) >= 1, st
PY
  then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || { cat "$NL_OUT"; nl_fail "the status does not list nl-switch on rtr-lan with port lan0"; }
nl_ok "status lists nl-switch on $NL_LAN_IF, port lan0, protocol LLDP"
nl_web GET /svc/lldp
[ "$NL_CODE" = 200 ] && grep -F 'svc-settings-form' "$NL_OUT" >/dev/null || nl_fail "LLDP page: $NL_CODE"
nl_ok "the LLDP page renders"

echo "=== the WAN side is silent"
n=$(frames nl-isp up0 4)
[ "$n" = 0 ] || nl_fail "$n LLDP frames reached the WAN port"
n=$(frames nl-client lan0 4)
[ "$n" -ge 2 ] || nl_fail "only $n LLDP frames on the LAN in 4 s (two senders at 1 s)"
nl_ok "0 LLDP frames on the WAN port, $n on the LAN"

echo "=== rx-only: the router stays silent but still listens"
nl_api_ok "rx-only" PUT /svc/lldp/interfaces/"$ROW" '{"iface":"@lan","mode":"rx-only"}'
nl_wait 10 sh -c "grep -qx 'configure ports $NL_LAN_IF lldp status rx-only' $CONF" || nl_fail "mode not written"
nl_wait 10 pgrep -x lldpd || nl_fail "lldpd gone after a mode change"
nl_wait 15 sh -c "lldpcli -u $RSOCK -f keyvalue show interfaces detail ports $NL_LAN_IF 2>/dev/null | grep -qx 'lldp.$NL_LAN_IF.status=RX only'" \
  || nl_fail "the daemon does not report RX only on $NL_LAN_IF"
stat() { lldpcli -u "$RSOCK" -f keyvalue show statistics ports "$NL_LAN_IF" | sed -n "s/^lldp\\.$NL_LAN_IF\\.$1\\.$1=//p"; }
sleep 2; TX1=$(stat tx); RX1=$(stat rx); sleep 4; TX2=$(stat tx); RX2=$(stat rx)
[ "$TX1" = "$TX2" ] || nl_fail "the router still transmits in rx-only mode (tx $TX1 -> $TX2)"
[ "$RX2" -gt "$RX1" ] || nl_fail "the router stopped listening in rx-only mode (rx $RX1 -> $RX2)"
nl_ok "rx-only: tx counter frozen at $TX2, rx still counting ($RX1 -> $RX2)"

echo "=== reboot: patronus apply brings LLDP back"
nl_web_stop
sw_stop
nl_kill_daemons lldpd
pkill -x lldpd 2>/dev/null || true
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_wait 10 pgrep -x lldpd || nl_fail "lldpd not started by the boot apply"
sw_start
nl_web_start "$DB"; nl_login
ok=0
for _ in $(seq 1 30); do
  nl_api GET /svc/lldp
  if python3 - "$NL_OUT" <<'PY' 2>/dev/null
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert any(x.get("system_name") == "nl-switch" for x in st["neighbors"]), st
PY
  then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || nl_fail "no neighbour after the reboot"
nl_ok "after reboot: lldpd back, nl-switch listed"

echo "=== disable"
nl_api_ok "disable" PUT /svc/lldp '{"enabled":false}'
nl_wait 10 sh -c "! lldpcli -u $RSOCK show chassis" || nl_fail "router lldpd still running"
nl_api GET /svc/lldp
[ "$(nl_json "$NL_OUT" 'd["status"]["running"]')" = False ] || nl_fail "status still says running"
nl_ok "disabled: router lldpd stopped"
sw_stop
nl_web_stop
echo "ALL LLDP CHECKS PASSED"
