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
#  - multi-WAN polish (docs/MULTIWAN.md), tc netem on WAN1's upstream:
#    * a warning level below the down threshold: warning shown + event + dashboard tile, the
#      gateway keeps carrying traffic; trigger choice: a 'loss' group ignores high latency, a
#      'latency' group fails over and back; a gateway's DNS server is pinned to it and listed as
#      a resolver upstream while the gateway carries traffic
#    * sticky connections: one client keeps one uplink for all its flows, clients get their own
#      map entries, a lost uplink drops the assignments, a returning one does not rebalance,
#      the timeout expires idle clients, switching it off removes the nft table
#    * kill states: after a failover the stale NAT entry keeps a UDP/TCP flow on WAN1's address
#      (none), with kill states (down) the flow moves to WAN2 within seconds, with down_recovery
#      it moves back when WAN1 returns; the action is in the status, the page and an event
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
SRV_PID=
SND_PID=

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
cleanup() { kill $SND_PID $SRV_PID 2>/dev/null; nl_web_stop; applyd_stop; nl_down; ip netns del nl-isp2 2>/dev/null || true; }
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
via_is() { default_via | grep "$1" >/dev/null; }

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
  R ip -4 route show proto 252 | grep '192.0.2.10 via 100.64.0.1 dev rtr-wan2' >/dev/null && break
  sleep 0.5
done
R ip -4 route show proto 252 | grep '192.0.2.10 via 100.64.0.1 dev rtr-wan2' >/dev/null \
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
default_via | grep nexthop >/dev/null || fail "no multipath default: $(default_via)"
nl_assert_sysctl net.ipv4.fib_multipath_hash_policy 1
seen=$(for _ in $(seq 1 40); do who; done | sort | uniq -c)
echo "$seen"
grep -q "$NL_RTR_WAN" <<<"$seen" && grep -q 100.64.0.2 <<<"$seen" || fail "flows did not spread: $seen"
nl_ok "load balancing: 40 connections from one client used both uplinks"
# weighted ECMP: WAN1 weight 1, WAN2 weight 3 -> the kernel nexthops carry the
# weights and WAN2 carries clearly more of the flows (expected 3:1 of 80)
must 200 PUT /routing/groups/FAILOVER '{"name":"FAILOVER","members":"WAN1:1:1, WAN2:1:3","trigger":"down"}'
dv=$(default_via)
case "$dv" in *"weight 3"*) ;; *) fail "weight 3 not on the multipath default: $dv" ;; esac
# The split is a random sample (source ports hash the flows): 80 flows at p=0.75 miss the
# unchanged "> 2x" bar about 4% of the time on a correct kernel (run 972: 27/53). Re-sample up
# to 3 times; a real weighting bug fails every round, a bad draw does not (p ~ 1e-4 for all 3).
for round in 1 2 3; do
  w1=0; w2=0
  for _ in $(seq 1 80); do
    case "$(who)" in 100.64.0.2) w2=$((w2 + 1)) ;; "$NL_RTR_WAN") w1=$((w1 + 1)) ;; esac
  done
  [ "$w2" -gt $((w1 * 2)) ] && break
  echo "weighted ECMP sample $round: WAN1 $w1, WAN2 $w2 (not > 2x), re-sampling"
done
[ "$w2" -gt $((w1 * 2)) ] || fail "weights 1:3 should send about 3x more flows via WAN2 (WAN1 $w1, WAN2 $w2)"
nl_ok "weighted ECMP 1:3: kernel nexthop weight 3, 80 connections split WAN1 $w1 / WAN2 $w2"
must 200 PUT /routing/groups/FAILOVER '{"name":"FAILOVER","members":"WAN1:1, WAN2:2","trigger":"down"}'
via_is 'via 203.0.113.1 dev rtr-wan' || fail "back to failover: $(default_via)"

# --- 4b. policy routing: one service via WAN2 while the default is WAN1 ----
who8080() { C curl -s --max-time 4 "http://$NL_WWW:8080/" | awk '{print $3}'; }
[ "$(who8080)" = "$NL_RTR_WAN" ] || fail ":8080 should leave via WAN1 before the policy rule"
must 201 POST /firewall/rules '{"name":"pbr-8080","chain":"forward","action":"accept","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.10","port":"8080","description":"pbr-8080","enabled":true,"gateway":"WAN2"}'
PBR_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
pol=$(R nft list chain inet patronus pbr 2>&1)
grep -qE 'meta mark set 0x0*10002' <<<"$pol" || fail "pbr chain: $pol"
R ip -4 rule show | grep 'fwmark 0x10002 lookup 65538' >/dev/null || fail "no fwmark rule for WAN2: $(R ip -4 rule show)"
got=$(who8080)
[ "$got" = 100.64.0.2 ] || fail "policy rule: :8080 should leave via WAN2, got '$got'"
[ "$(who)" = "$NL_RTR_WAN" ] || fail "policy rule: :80 should still leave via WAN1"
nl_ok "policy routing: :8080 leaves via WAN2 (sees 100.64.0.2) while :80 stays on WAN1"
must 400 POST /firewall/rules '{"name":"pbr-bad","chain":"forward","action":"accept","interface":"@lan","protocol":"tcp","destination":"198.51.100.10","port":"8081","description":"x","enabled":true,"gateway":"NOSUCH"}'
must 400 POST /firewall/rules '{"name":"pbr-drop","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","destination":"198.51.100.10","port":"8082","description":"x","enabled":true,"gateway":"WAN2"}'
nl_ok "a policy rule naming no gateway, or a drop rule with a gateway, is refused (400)"

# --- 4c. thresholds, warning level, trigger choice (netem on WAN1's upstream) ---
# Gateway WAN1 gets a warning level (40 ms) below its down threshold (100 ms), a DNS server of its own,
# and the group FAILOVER a trigger. tc netem on the ISP side delays the replies the monitor sees.
gwf() { # GATEWAY PYTHON-EXPR over g (the gateway's object in GET /routing)
  nl_api GET /routing >/dev/null
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); g=[x for x in d["gateways"] if x["name"]==sys.argv[2]][0]; print(eval(sys.argv[3]))' "$NL_OUT" "$1" "$2"
}
gw_is() { [ "$(gwf "$1" 'g["state"]')" = "$2" ]; }
gw_warning_is() { [ "$(gwf "$1" 'g["warning"] or ""')" = "$2" ]; }
event_count() { nl_api GET "/events?kind=$1" >/dev/null; python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$NL_OUT"; }
wait_event() { # KIND [MORE-THAN]
  local n=${2:-0}
  for _ in $(seq 1 60); do [ "$(event_count "$1")" -gt "$n" ] && return 0; sleep 1; done
  fail "no $1 event: $(cat "$NL_OUT")"
}
set_group() { # JSON of the FAILOVER group
  must 200 PUT /routing/groups/FAILOVER "$1"
}
GRP_FAILOVER='"name":"FAILOVER","members":"WAN1:1, WAN2:2"'

must 200 PUT /routing/gateways/WAN1 '{"name":"WAN1","interface":"@wan","latency_threshold":100,"latency_warn":40,"loss_threshold":30,"loss_warn":10,"dns_servers":"198.51.100.53"}'
must 400 PUT /routing/gateways/WAN1 '{"name":"WAN1","interface":"@wan","latency_threshold":100,"latency_warn":100}'
must 400 PUT /routing/gateways/WAN1 '{"name":"WAN1","interface":"@wan","dns_servers":"2001:db8::53"}'
nl_ok "gateway settings: warning level below the down threshold, DNS server of the right family only"
wait_for "WAN1 online" 20 gw_is WAN1 online
R ip -4 route show proto 252 | grep '198.51.100.53 via 203.0.113.1 dev rtr-wan' >/dev/null \
  || fail "DNS server of WAN1 is not pinned to it: $(R ip -4 route show proto 252)"
nl_ok "DNS server 198.51.100.53 of WAN1 is pinned to WAN1 with a host route (proto 252)"
nl_web GET /dns
grep -q 'id="gateway-upstreams"' "$NL_OUT" && grep -q 'now: 198.51.100.53' "$NL_OUT" \
  || fail "DNS page does not list the active gateway's DNS server ($NL_CODE)"
nl_ok "DNS page: the DNS server of the active gateway WAN1 is a resolver upstream"

# the warning level shows and is notified, the gateway keeps carrying the traffic
W0=$(event_count gateway_warning)
ISP tc qdisc add dev up0 root netem delay 60ms
wait_for "WAN1 warning: latency" 40 gw_warning_is WAN1 latency
[ "$(gw_state WAN1)" = online ] || fail "a warning is not a failure: WAN1 is $(gw_state WAN1)"
via_is 'via 203.0.113.1 dev rtr-wan' || fail "a warning must not move the default route: $(default_via)"
[ "$(who)" = "$NL_RTR_WAN" ] || fail "WAN1 still carries the LAN while it only warns"
wait_event gateway_warning "$W0"
nl_web GET /
grep -q 'data-uplink="WAN1"' "$NL_OUT" && grep -q 'warning: latency' "$NL_OUT" \
  || fail "dashboard Uplinks tile does not show the WAN1 warning ($NL_CODE)"
nl_ok "60 ms (warn 40, down 100): WAN1 warns, stays online and carries traffic; gateway_warning event; dashboard tile shows it"

# trigger choice: a group that only reacts to packet loss ignores high latency ...
set_group "{$GRP_FAILOVER,\"trigger\":\"loss\"}"
ISP tc qdisc change dev up0 root netem delay 160ms
wait_for "WAN1 state latency" 40 gw_is WAN1 latency
sleep 3
via_is 'via 203.0.113.1 dev rtr-wan' || fail "trigger loss must keep WAN1 while only the latency is high: $(default_via)"
nl_ok "group trigger 'loss': WAN1 at 160 ms (down 100) stays in service"
# ... the latency trigger leaves it
D0=$(event_count gateway_degraded)
set_group "{$GRP_FAILOVER,\"trigger\":\"latency\"}"
t0=$(date +%s)
wait_for "default route to move to WAN2 on latency" 20 via_is 'via 100.64.0.1 dev rtr-wan2'
nl_ok "group trigger 'latency': default route moved to WAN2 after $(( $(date +%s) - t0 )) s"
[ "$(who)" = 100.64.0.2 ] || fail "latency failover: the LAN should leave via WAN2"
wait_event gateway_degraded "$D0"
ISP tc qdisc del dev up0 root
wait_for "WAN1 online again" 40 gw_is WAN1 online
wait_for "default back on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'
[ "$(who)" = "$NL_RTR_WAN" ] || fail "latency gone: the LAN should be back on WAN1"
nl_ok "latency gone: group fails back, LAN traffic on WAN1 again"
set_group "{$GRP_FAILOVER,\"trigger\":\"down\"}"

# --- 4d. sticky connections in a load-balancing group ---------------------------
CDEV=lan0
for h in 11 12 13; do C ip addr add 192.168.50.$h/24 dev $CDEV; done
who_from() { C curl -s --max-time 4 --interface "$1" "http://$NL_WWW/" | awk '{print $3}'; }
LB="\"name\":\"FAILOVER\",\"members\":\"WAN1:1:1, WAN2:1:1\",\"trigger\":\"down\",\"kill_states\":\"none\""
set_group "{$LB,\"sticky_secs\":300}"
T4=$(R nft list table inet patronus_wan 2>&1) || fail "no sticky table: $T4"
grep -q 'update @st' <<<"$T4" && grep -q 'numgen random mod 2' <<<"$T4" || fail "sticky rules: $T4"
nl_ok "sticky group: nft table patronus_wan has the per-client map and the weighted pick"
seen=$(for _ in $(seq 1 40); do who; done | sort | uniq -c)
echo "$seen"
[ "$(wc -l <<<"$seen")" = 1 ] || fail "sticky: one client must keep one uplink for all its flows: $seen"
nl_ok "sticky: 40 connections from one client all used one uplink"
for a in 192.168.50.11 192.168.50.12 192.168.50.13; do
  s=$(for _ in $(seq 1 15); do who_from $a; done | sort | uniq -c)
  [ "$(wc -l <<<"$s")" = 1 ] || fail "sticky: client $a was split over uplinks: $s"
done
MAPS=$(R nft list table inet patronus_wan)
for a in 192.168.50.10 192.168.50.11 192.168.50.12 192.168.50.13; do
  grep -q "$a" <<<"$MAPS" || fail "client $a has no sticky assignment: $MAPS"
done
grep -qE 'expires [0-9]+m' <<<"$MAPS" || fail "sticky entries carry a timeout: $MAPS"
nl_ok "sticky: four clients each keep their own uplink; the assignments sit in the map with a timeout"

# an uplink that goes away drops its clients' assignments; the client moves, and stays when it returns
W1=$(who)
if [ "$W1" = "$NL_RTR_WAN" ]; then BAD=ISP; BADWAN=WAN1; BADADDR=203.0.113.1/24; OTHER=100.64.0.2
else BAD=ISP2; BADWAN=WAN2; BADADDR=100.64.0.1/24; OTHER=$NL_RTR_WAN; fi
echo "client is on $W1; taking $BADWAN away"
$BAD ip addr flush dev up0
wait_for "$BADWAN down" 30 gw_is $BADWAN down
client_on() { [ "$(who)" = "$1" ]; }
wait_for "the client to move to the other uplink" 20 client_on "$OTHER"
nl_ok "sticky: $BADWAN lost -> its clients are assigned again, the client now leaves via $OTHER"
$BAD ip addr add $BADADDR dev up0
wait_for "$BADWAN online again" 30 gw_is $BADWAN online
sleep 2
seen=$(for _ in $(seq 1 25); do who; done | sort | uniq -c)
[ "$(wc -l <<<"$seen")" = 1 ] && grep -q "$OTHER" <<<"$seen" || fail "sticky: the client must stay on $OTHER after $BADWAN returns: $seen"
nl_ok "sticky: $BADWAN is back, the client stays on $OTHER (affinity beats rebalancing)"
# the timeout: an idle client's assignment disappears
set_group "{$LB,\"sticky_secs\":0}"     # a new timeout applies to a fresh table: old entries keep theirs
set_group "{$LB,\"sticky_secs\":3}"
who >/dev/null; sleep 6
MAPS=$(R nft list table inet patronus_wan)
if grep -q '192.168.50.10' <<<"$MAPS"; then fail "sticky: the idle client's assignment should have expired: $MAPS"; fi
nl_ok "sticky: an idle client's assignment expires after the timeout (3 s)"
must 400 PUT /routing/groups/FAILOVER "{$LB,\"sticky_secs\":99999999}"
must 400 PUT /routing/groups/FAILOVER "{$LB,\"kill_states\":\"always\"}"
set_group "{$LB,\"sticky_secs\":0}"
if R nft list table inet patronus_wan >/dev/null 2>&1; then fail "sticky off: the table should be gone"; fi
nl_ok "sticky off: the nft table is removed; bad timeout / kill-states values are refused (400)"
for h in 11 12 13; do C ip addr del 192.168.50.$h/24 dev $CDEV; done
set_group "{$GRP_FAILOVER,\"trigger\":\"down\",\"kill_states\":\"none\"}"
wait_for "default on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'

# --- 4e. kill states: an existing flow moves within seconds ----------------------
# A UDP flow (one socket, one conntrack entry) and a TCP connection from the LAN client to the internet
# host. The server logs the source address it sees. Without kill states the stale NAT entry keeps the flow
# on WAN1's address after the route moved; with them the entry is deleted and the next packet is
# masqueraded on the new uplink.
cat >"$T/srv.py" <<'PYEOF'
import socket, sys, threading, time
log = open(sys.argv[1], 'a', buffering=1)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('0.0.0.0', 9999))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(('0.0.0.0', 9998)); t.listen(8)
def tcp():
    while True:
        c, a = t.accept()
        log.write('%f tcp %s\n' % (time.time(), a[0]))
        threading.Thread(target=lambda c=c: [c.recv(100) for _ in iter(int, 1)], daemon=True).start()
threading.Thread(target=tcp, daemon=True).start()
while True:
    _, a = u.recvfrom(100)
    log.write('%f udp %s\n' % (time.time(), a[0]))
PYEOF
cat >"$T/snd.py" <<'PYEOF'
import socket, sys, time
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('0.0.0.0', 40000))
t = socket.create_connection((sys.argv[1], 9998))
while True:
    u.sendto(b'x', (sys.argv[1], 9999))
    try: t.send(b'y')
    except OSError: pass
    time.sleep(0.2)
PYEOF
SRV_LOG=$T/srv.log; : >"$SRV_LOG"
INET python3 -u "$T/srv.py" "$SRV_LOG" & SRV_PID=$!
sleep 1
C python3 -u "$T/snd.py" "$NL_WWW" & SND_PID=$!
seen_udp() { awk -v s="$1" -v t="$2" '$2=="udp" && $3==s && $1>t {n++} END {exit !n}' "$SRV_LOG"; }
wait_for "the UDP flow to reach the server via WAN1" 15 seen_udp "$NL_RTR_WAN" 0
ct_wan1() { R conntrack -L -p tcp 2>/dev/null | grep -E "dport=9998 .*src=$NL_WWW dst=$NL_RTR_WAN " >/dev/null; }
wait_for "the TCP connection tracked on WAN1's address" 10 ct_wan1

kill_cycle() { # MODE: failover then recovery; sets MOVE_SECS
  local mode=$1
  set_group "{$GRP_FAILOVER,\"trigger\":\"down\",\"kill_states\":\"$mode\"}"
  wait_for "default on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'
  ISP ip addr flush dev up0
  wait_for "default route on WAN2" 30 via_is 'via 100.64.0.1 dev rtr-wan2'
  MOVED=$(date +%s.%N)
}
# negative control: kill states off -> the stale NAT entry keeps the flow on WAN1's address
kill_cycle none
sleep 10
if seen_udp 100.64.0.2 "$MOVED"; then fail "kill_states none: the UDP flow moved by itself (no kill expected)"; fi
ct_wan1 || fail "kill_states none: the TCP entry should still be tracked on WAN1's address"
nl_ok "kill_states none: 10 s after the failover the flow still carries WAN1's NAT address (stale state kept)"
ISP ip addr add 203.0.113.1/24 dev up0
wait_for "default back on WAN1" 30 via_is 'via 203.0.113.1 dev rtr-wan'
K0=$(event_count gateway_states_killed)
# kill states on down: the flow moves
kill_cycle down
wait_for "the UDP flow to reach the server via WAN2" 12 seen_udp 100.64.0.2 "$MOVED"
nl_ok "kill_states down: the existing UDP flow left via WAN2 $(awk -v m="$MOVED" -v n="$(date +%s.%N)" 'BEGIN{printf "%.0f", n-m}') s after the route moved"
no_ct_wan1() { ! ct_wan1; }
wait_for "the TCP entry on WAN1's address to be deleted" 10 no_ct_wan1
nl_ok "kill_states down: the TCP connection's tracked state on WAN1's address is gone"
wait_event gateway_states_killed "$K0"
nl_api GET /routing >/dev/null
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); g=[x for x in d["gateways"] if x["name"]=="WAN1"][0]; assert g["killed"] and g["killed"]["count"]>=1, g' "$NL_OUT" \
  || fail "WAN1 status has no kill record: $(cat "$NL_OUT")"
nl_web GET /routing
grep -q 'connection(s) deleted' "$NL_OUT" || fail "Routing page does not show the kill-states action"
nl_ok "kill-states action is in the gateway status, the Routing page and a gateway_states_killed event"
# recovery: with 'down' the flow stays; with 'down_recovery' it moves back
ISP ip addr add 203.0.113.1/24 dev up0
wait_for "default back on WAN1" 30 via_is 'via 203.0.113.1 dev rtr-wan'
set_group "{$GRP_FAILOVER,\"trigger\":\"down\",\"kill_states\":\"down_recovery\"}"
ISP ip addr flush dev up0
wait_for "default route on WAN2" 30 via_is 'via 100.64.0.1 dev rtr-wan2'
wait_for "UDP flow on WAN2 again" 12 seen_udp 100.64.0.2 "$(date +%s.%N)"
ISP ip addr add 203.0.113.1/24 dev up0
BACK=$(date +%s.%N)
wait_for "default back on WAN1" 30 via_is 'via 203.0.113.1 dev rtr-wan'
wait_for "the UDP flow to return to WAN1's address" 15 seen_udp "$NL_RTR_WAN" "$BACK"
nl_ok "kill_states down_recovery: WAN1 is back -> the fallback's flow was deleted and left via WAN1 again"
kill "$SND_PID" "$SRV_PID" 2>/dev/null || true; wait "$SND_PID" "$SRV_PID" 2>/dev/null || true
set_group "{$GRP_FAILOVER,\"trigger\":\"down\"}"
must 200 PUT /routing/gateways/WAN1 '{"name":"WAN1","interface":"@wan"}'
wait_for "default on WAN1" 20 via_is 'via 203.0.113.1 dev rtr-wan'

# --- 5. static routes -------------------------------------------------------
C ip addr add 10.77.0.1/32 dev lo
must 201 POST /routing/routes '{"destination":"10.77.0.0/24","gateway":"192.168.50.10","description":"lab behind client"}'
must 201 POST /routing/routes '{"destination":"198.18.0.0/15","gateway":"WAN2"}'
R ip -4 route show proto 251 | grep '10.77.0.0/24 via 192.168.50.10 dev rtr-lan' >/dev/null || fail "static route: $(R ip -4 route show proto 251)"
R ip -4 route show proto 251 | grep '198.18.0.0/15 via 100.64.0.1 dev rtr-wan2' >/dev/null || fail "static via gateway name: $(R ip -4 route show proto 251)"
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
R ip -4 addr show rtr-wan2 | grep 100.64.0.2/24 >/dev/null || fail "WAN2 address not rebuilt"
via_is 'via 203.0.113.1 dev rtr-wan' || fail "default after reboot: $(default_via)"
R ip -4 route show proto 251 | grep '10.77.0.0/24 via 192.168.50.10' >/dev/null || fail "static route lost on reboot"
R ip -4 route show proto 252 | grep '192.0.2.10 via 100.64.0.1' >/dev/null || fail "monitor route lost on reboot"
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
