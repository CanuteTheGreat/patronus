#!/usr/bin/env bash
# Lane E (WAN & routing) netlab test. Runs INSIDE the capped netlab
# container (ci/netlab/run.sh) as root with the shipped binaries in /t.
#
#   client ---- rtr-lan [ rtr ] rtr-wan  ---- isp  (203.0.113.1) ---- inet 198.51.100.10
#                             rtr-wan2 ---- isp2 (100.64.0.1)  ---- inet (via 192.0.2.10)
#
# The inet host's HTTP server answers "<host> sees <client address>", so the
# masqueraded source address tells which uplink a connection really used
# (203.0.113.2 = WAN1, 100.64.0.2 = WAN2).
#
# Proves (kernel state + real traffic, configured through the web API with
# the gateway monitor running in the root `patronus applyd`):
#  - gateways: a dynamic one (learned from WAN1's boot default route) and a
#    static one; the monitor reports both online; a monitor IP gets a host
#    route through its own gateway (proto 252)
#  - gateway group FAILOVER (WAN1 tier 1, WAN2 tier 2) as default gateway:
#    traffic leaves via WAN1; when WAN1's upstream stops answering the
#    default route moves to WAN2 within seconds and LAN traffic follows
#    (masqueraded on the second uplink); when it answers again traffic
#    returns to WAN1
#  - load balancing: both in tier 1 -> one multipath default route, port
#    hashing on, connections from one client spread over both uplinks
#  - policy routing: a firewall rule with a gateway sends one service out
#    WAN2 while everything else uses the default gateway; survives reboot
#  - static routes via an IP and via a gateway name reach the kernel (proto
#    251); bad input and deleting a gateway in use are refused (400)
#  - reboot (fresh namespaces + `patronus apply`) rebuilds all of it; a
#    second apply changes nothing; Default = automatic removes Patronus'
#    default route
set -eu
. "$(dirname "$0")/lib.sh"

T=/t/lanee
rm -rf "$T"; mkdir -p "$T"
DB=$T/config.db
export NO_COLOR=1 CLICOLOR=0 PATRONUS_INIT=direct PATRONUS_NET_DIR=$T/net PATRONUS_RUN_DIR=$T/run
export PATRONUS_APPLYD_SOCKET=$T/applyd.sock PATRONUS_GATEWAY_STATUS=$T/gateway-status.json
ISP2() { ip netns exec nl-isp2 "$@"; }
APPLYD_PID=

dump() {
  echo "--- debug: rtr routes"; R ip -4 route 2>/dev/null || true; R ip -4 route show proto 253 2>/dev/null || true
  echo "--- debug: gateway status"; cat "$PATRONUS_GATEWAY_STATUS" 2>/dev/null || true; echo
  for f in "$T/applyd.log" "$NL_T/nl-web.log"; do [ -f "$f" ] && { echo "--- $f"; tail -40 "$f"; }; done; true
}
fail() { dump; nl_fail "$*"; }

second_wan() {
  ip netns del nl-isp2 2>/dev/null || true
  ip netns add nl-isp2; ip -n nl-isp2 link set lo up
  ip link add rtr-wan2 netns nl-rtr type veth peer name up0 netns nl-isp2
  ip link add down1 netns nl-isp2 type veth peer name inet1 netns nl-inet
  ISP2 ip addr add 100.64.0.1/24 dev up0; ISP2 ip link set up0 up
  ISP2 ip addr add 192.0.2.1/24 dev down1; ISP2 ip link set down1 up
  ISP2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  ISP2 ip route add 198.51.100.0/24 via 192.0.2.10
  INET ip addr add 192.0.2.10/24 dev inet1; INET ip link set inet1 up
  INET ip route add 100.64.0.0/24 via 192.0.2.1
  R ip link set rtr-wan2 up
}

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
cleanup() { nl_web_stop; applyd_stop; nl_down; ip netns del nl-isp2 2>/dev/null || true; }
trap cleanup EXIT

must() { # CODE METHOD PATH [JSON]
  local want=$1; shift
  nl_api "$@"
  [ "$NL_CODE" = "$want" ] || fail "$1 $2 -> $NL_CODE (want $want): $(cat "$NL_OUT")"
}
# who: which uplink the LAN client's connection to the internet host used
who() { C curl -s --max-time 4 "http://$NL_WWW/" | awk '{print $3}'; }
wait_for() { # DESC SECONDS CMD...
  local d=$1 n=$2; shift 2
  for _ in $(seq 1 $((n * 4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "timed out after ${n}s waiting for: $d"
}
default_via() { R ip -4 route show table 4250 proto 253; }
gw_state() { # NAME -> state from GET /api/routing
  nl_api GET /routing >/dev/null
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print([g["state"] for g in d["gateways"] if g["name"]==sys.argv[2]][0])' "$NL_OUT" "$1"
}
state_is() { [ "$(gw_state "$1")" = "$2" ]; }
via_is() { default_via | grep -q "$1"; }

# --- 1. boot with one WAN, then a second uplink on OPT1 -------------------
nl_up; second_wan
nl_write_installer_toml
nl_apply "$DB" || { cat "$NL_OUT"; fail "boot apply"; }
nl_assert_router_baseline
[ "$(who)" = "$NL_RTR_WAN" ] || fail "before lane E config the LAN should leave via WAN1"
applyd_start
nl_web_start "$DB"
nl_login
must 200 PUT /interfaces/rtr-wan2 '{"role":"opt1","ipv4_mode":"static","ipv4":["100.64.0.2/24"],"gateway4":"100.64.0.1"}'
nl_assert_nft_has 'oifname "rtr-wan" masquerade'

# --- 2. gateways + monitor -------------------------------------------------
must 201 POST /routing/gateways '{"name":"WAN1","interface":"@wan"}'
must 201 POST /routing/gateways '{"name":"WAN2","interface":"@opt1","monitor_ip":"192.0.2.10","description":"backup uplink"}'
nl_assert_nft_has 'oifname "rtr-wan2" masquerade'
nl_ok "an OPT interface with a gateway gets automatic outbound NAT"
# the monitor installs the pinned host route on its next tick (1 s): poll,
# a loaded CI host can be late
for _ in $(seq 1 30); do
  R ip -4 route show proto 252 | grep -q '192.0.2.10 via 100.64.0.1 dev rtr-wan2' && break
  sleep 0.5
done
R ip -4 route show proto 252 | grep -q '192.0.2.10 via 100.64.0.1 dev rtr-wan2' \
  || fail "monitor IP host route missing: $(R ip -4 route show proto 252)"
nl_ok "monitor IP 192.0.2.10 is pinned to WAN2 (proto 252)"
wait_for "WAN1 online" 15 state_is WAN1 online
wait_for "WAN2 online" 15 state_is WAN2 online
nl_api GET /routing
python3 - "$NL_OUT" <<'EOF' || fail "routing status: $(cat "$NL_OUT")"
import json, sys
d = json.load(open(sys.argv[1]))
g = {x["name"]: x for x in d["gateways"]}
assert g["WAN1"]["dynamic"] and g["WAN1"]["resolved_address"] == "203.0.113.1", g["WAN1"]
assert g["WAN1"]["dev"] == "rtr-wan", g["WAN1"]
assert g["WAN2"]["resolved_address"] == "100.64.0.1" and g["WAN2"]["rtt_ms"] is not None, g["WAN2"]
assert d["monitor_running"], d
EOF
nl_ok "monitor: WAN1 (dynamic, learned 203.0.113.1) and WAN2 online with round-trip times"
nl_web GET /routing
[ "$NL_CODE" = 200 ] && grep -q 'data-gateway="WAN2"' "$NL_OUT" && grep -q 'backup uplink' "$NL_OUT" \
  || fail "routing page ($NL_CODE)"
nl_ok "Routing page lists the gateways"

# --- 3. failover group as default gateway ---------------------------------
must 201 POST /routing/groups '{"name":"FAILOVER","members":"WAN1:1, WAN2:2","trigger":"down"}'
must 200 PUT /routing/default '{"ipv4":"FAILOVER"}'
via_is 'via 203.0.113.1 dev rtr-wan' || fail "default via group: $(default_via)"
rules=$(R ip -4 rule show)
grep -q '^31000:.*lookup main suppress_prefixlength 0' <<<"$rules" && grep -q '^31900:.*lookup 4250' <<<"$rules" \
  || fail "policy rules: $rules"
[ "$(who)" = "$NL_RTR_WAN" ] || fail "LAN should leave via WAN1"
nl_ok "default gateway FAILOVER: tier 1 (WAN1) carries the traffic"

ISP ip addr flush dev up0      # WAN1's upstream router stops answering
t0=$(date +%s)
wait_for "default route to move to WAN2" 20 via_is 'via 100.64.0.1 dev rtr-wan2'
nl_ok "WAN1 silent -> default route via WAN2 after $(( $(date +%s) - t0 )) s"
[ "$(gw_state WAN1)" = down ] || fail "WAN1 should be down, is $(gw_state WAN1)"
got=$(who)
[ "$got" = 100.64.0.2 ] || fail "after failover the LAN should leave via WAN2, got '$got'"
nl_ok "LAN traffic fails over to WAN2 (internet host sees 100.64.0.2)"

ISP ip addr add 203.0.113.1/24 dev up0
wait_for "default route back on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'
[ "$(who)" = "$NL_RTR_WAN" ] || fail "LAN should be back on WAN1"
nl_ok "WAN1 answers again -> traffic returns to WAN1"

# --- 4. load balancing ----------------------------------------------------
must 200 PUT /routing/groups/FAILOVER '{"name":"FAILOVER","members":"WAN1:1, WAN2:1:1","trigger":"down"}'
default_via | grep -q nexthop || fail "no multipath default: $(default_via)"
nl_assert_sysctl net.ipv4.fib_multipath_hash_policy 1
seen=$(for _ in $(seq 1 40); do who; done | sort | uniq -c)
echo "$seen"
grep -q "$NL_RTR_WAN" <<<"$seen" && grep -q 100.64.0.2 <<<"$seen" || fail "flows did not spread: $seen"
nl_ok "load balancing: 40 connections from one client used both uplinks"
must 200 PUT /routing/groups/FAILOVER '{"name":"FAILOVER","members":"WAN1:1, WAN2:2","trigger":"down"}'
via_is 'via 203.0.113.1 dev rtr-wan' || fail "back to failover: $(default_via)"

# --- 4b. policy routing: one service via WAN2 while the default is WAN1 ----
who8080() { C curl -s --max-time 4 "http://$NL_WWW:8080/" | awk '{print $3}'; }
[ "$(who8080)" = "$NL_RTR_WAN" ] || fail ":8080 should leave via WAN1 before the policy rule"
must 201 POST /firewall/rules '{"name":"pbr-8080","chain":"forward","action":"accept","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.10","port":"8080","description":"pbr-8080","enabled":true,"gateway":"WAN2"}'
PBR_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
pol=$(R nft list chain inet patronus pbr 2>&1)
grep -qE 'meta mark set 0x0*10002' <<<"$pol" || fail "pbr chain: $pol"
R ip -4 rule show | grep -q 'fwmark 0x10002 lookup 65538' || fail "no fwmark rule for WAN2: $(R ip -4 rule show)"
got=$(who8080)
[ "$got" = 100.64.0.2 ] || fail "policy rule: :8080 should leave via WAN2, got '$got'"
[ "$(who)" = "$NL_RTR_WAN" ] || fail "policy rule: :80 should still leave via WAN1"
nl_ok "policy routing: :8080 leaves via WAN2 (sees 100.64.0.2) while :80 stays on WAN1"
must 400 POST /firewall/rules '{"name":"pbr-bad","chain":"forward","action":"accept","interface":"@lan","protocol":"tcp","destination":"198.51.100.10","port":"8081","description":"x","enabled":true,"gateway":"NOSUCH"}'
must 400 POST /firewall/rules '{"name":"pbr-drop","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","destination":"198.51.100.10","port":"8082","description":"x","enabled":true,"gateway":"WAN2"}'
nl_ok "a policy rule naming no gateway, or a drop rule with a gateway, is refused (400)"

# --- 5. static routes -------------------------------------------------------
C ip addr add 10.77.0.1/32 dev lo
must 201 POST /routing/routes '{"destination":"10.77.0.0/24","gateway":"192.168.50.10","description":"lab behind client"}'
must 201 POST /routing/routes '{"destination":"198.18.0.0/15","gateway":"WAN2"}'
R ip -4 route show proto 251 | grep -q '10.77.0.0/24 via 192.168.50.10 dev rtr-lan' || fail "static route: $(R ip -4 route show proto 251)"
R ip -4 route show proto 251 | grep -q '198.18.0.0/15 via 100.64.0.1 dev rtr-wan2' || fail "static via gateway name: $(R ip -4 route show proto 251)"
R ping -c1 -W2 10.77.0.1 >/dev/null || fail "router cannot reach 10.77.0.1 through the static route"
nl_ok "static routes via an IP and via gateway WAN2 are in the kernel; 10.77.0.1 answers"
must 400 POST /routing/routes '{"destination":"10.88.0.0/16","gateway":"NOPE"}'
must 400 POST /routing/routes '{"destination":"0.0.0.0/0","gateway":"192.168.50.10"}'
must 400 DELETE /routing/gateways/WAN2
grep -q 'still used by' "$NL_OUT" || fail "delete in use: $(cat "$NL_OUT")"
nl_ok "bad routes and deleting a gateway in use are refused (400)"

# --- 6. reboot --------------------------------------------------------------
nl_web_stop; applyd_stop
rm -f "$PATRONUS_GATEWAY_STATUS"     # /run is empty after a reboot
nl_up; second_wan
C ip addr add 10.77.0.1/32 dev lo
nl_apply "$DB" || { cat "$NL_OUT"; fail "reboot apply"; }
grep -q 'routes' "$NL_OUT" || { cat "$NL_OUT"; fail "boot apply did not run the routes phase"; }
R ip -4 addr show rtr-wan2 | grep -q 100.64.0.2/24 || fail "WAN2 address not rebuilt"
via_is 'via 203.0.113.1 dev rtr-wan' || fail "default after reboot: $(default_via)"
R ip -4 route show proto 251 | grep -q '10.77.0.0/24 via 192.168.50.10' || fail "static route lost on reboot"
R ip -4 route show proto 252 | grep -q '192.0.2.10 via 100.64.0.1' || fail "monitor route lost on reboot"
[ "$(who)" = "$NL_RTR_WAN" ] || fail "after reboot the LAN should leave via WAN1"
[ "$(who8080)" = 100.64.0.2 ] || fail "after reboot the policy rule should still send :8080 via WAN2"
nl_ok "reboot: patronus apply rebuilt the default gateway group, policy routing, static and monitor routes"
nl_apply "$DB" --phase routes || { cat "$NL_OUT"; fail "second apply"; }
grep -q 'routes up to date' "$NL_OUT" || { cat "$NL_OUT"; fail "second apply was not a no-op"; }
nl_ok "a second apply changes nothing"
DRY=$(R "$P" --db "$DB" apply --bootstrap "$NL_TOML" --dry-run 2>&1)
grep -q '^### routes (routes)' <<<"$DRY" && grep -q 'proto 253' <<<"$DRY" || { echo "$DRY"; fail "dry-run lacks the routes phase"; }
nl_ok "patronus apply --dry-run shows the routes phase"

# failover also works from the boot state once applyd's monitor runs
applyd_start
ISP ip addr flush dev up0
wait_for "post-reboot failover to WAN2" 20 via_is 'via 100.64.0.1 dev rtr-wan2'
nl_ok "after the reboot applyd's monitor fails over on its own"
ISP ip addr add 203.0.113.1/24 dev up0
wait_for "post-reboot failback" 20 via_is 'via 203.0.113.1 dev rtr-wan'

# --- 7. automatic default ---------------------------------------------------
nl_web_start "$DB"; nl_login
must 200 PUT /routing/default '{"ipv4":""}'
[ -z "$(default_via)" ] || fail "Default = automatic left a Patronus default route: $(default_via)"
rules=$(R ip -4 rule show)
if grep -qE '^31900:' <<<"$rules"; then fail "default-gateway rule left behind: $rules"; fi
[ "$(who)" = "$NL_RTR_WAN" ] || fail "automatic: WAN1 (role WAN, metric 100) should win"
[ "$(who8080)" = 100.64.0.2 ] || fail "policy routing does not depend on a default gateway"
must 200 DELETE "/firewall/rules/$PBR_ID"
[ "$(who8080)" = "$NL_RTR_WAN" ] || fail "rule deleted: :8080 should follow the default route again"
nl_assert_nft_lacks 'meta mark set'
nl_ok "deleting the policy rule sends :8080 back to the default route"
nl_ok "Default gateway automatic: Patronus' default route is gone, WAN keeps routing"
echo "lane-e-routing: all checks passed"
