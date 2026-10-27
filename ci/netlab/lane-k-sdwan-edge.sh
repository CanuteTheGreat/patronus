#!/usr/bin/env bash
# Lane K: SD-WAN edge agent (USE=sdwan), end to end with three real parties:
# the SD-WAN dashboard (patronus-dashboard) and two Patronus appliances, each
# with its own store, firewall, web UI and `patronus edge run` agent, joined
# through an "ISP" namespace.
#
#   client A 192.168.50.10 - [site A] --203.0.113.0/24--\                    /- dashboard 198.51.100.50
#                                                         [ isp ] ---------
#   client B 192.168.60.10 - [site B] --203.0.114.0/24--/  (second uplink 203.0.115.0/24)
#
# Proven: enrollment with one-time tokens (reused/garbage tokens refused);
# the agents build WireGuard tunnel sdwan0 with each other's keys, overlay
# addresses and routed LAN subnets; the clients ping each other through it and
# the ISP only ever sees UDP/51820 (never the clients' addresses); the dashboard
# lists both sites with measured paths; when site B's preferred endpoint is cut
# the agent moves to its second endpoint and, once the preferred one works
# again, back; a revoked edge disappears from its peer; `patronus apply`
# rebuilds the overlay from the store; leaving the overlay removes the tunnel.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"
export PATRONUS_EDGE_FAILBACK_SECS=25
NS() { local n=$1; shift; ip netns exec "$n" "$@"; }
PASS="$NL_PASS"
DASH=http://198.51.100.50:8443
JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
PIDS=()
diag() { # what the agents saw, printed when the scenario fails
  echo "--- diagnostics"
  for f in /t/run-a/patronus-daemon.edge-agent.log /t/net-a/edge-state.json /t/run-b/patronus-daemon.edge-agent.log /t/net-b/edge-state.json /t/dash.log; do
    [ -f "$f" ] && { echo "### $f"; tail -25 "$f"; }
  done
  for n in sa sb; do echo "### wg show ($n)"; ip netns exec $n wg show 2>&1 | head -20; done
}
cleanup() {
  local rc=$?
  [ "$rc" = 0 ] || diag
  # NETLAB_KEEP=1: leave the namespaces and daemons up for debugging
  [ -n "${NETLAB_KEEP:-}" ] && [ "$rc" != 0 ] && return 0
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  for n in "${NSS[@]:-}"; do :; done
  pkill -x patronus 2>/dev/null || true
  pkill -x patronus-web 2>/dev/null || true
  pkill -x patronus-dashboard 2>/dev/null || true
  sleep 1
  for n in dash isp sa sb ca cb; do ip netns del "$n" 2>/dev/null || true; done
  rm -rf /t/net-a /t/net-b /t/run-a /t/run-b
}
NSS=(dash isp sa sb ca cb)
trap cleanup EXIT
cleanup
rm -rf /t/net-a /t/net-b /t/run-a /t/run-b; rm -f /t/site-a.db /t/site-b.db /t/dash.db /t/jar-a /t/jar-b /t/dash.log

# --- topology ---------------------------------------------------------------
for n in "${NSS[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add d0 netns isp type veth peer name e0 netns dash
ip link add a0 netns isp type veth peer name wanA netns sa
ip link add b0 netns isp type veth peer name wanB netns sb
ip link add b1 netns isp type veth peer name wanB2 netns sb
ip link add lanA netns sa type veth peer name lan0 netns ca
ip link add lanB netns sb type veth peer name lan0 netns cb
addr() { NS "$1" ip addr add "$2" dev "$3"; NS "$1" ip link set "$3" up; }
addr isp 198.51.100.1/24 d0; addr dash 198.51.100.50/24 e0; NS dash ip route add default via 198.51.100.1
addr isp 203.0.113.1/24 a0; addr sa 203.0.113.2/24 wanA; NS sa ip route add default via 203.0.113.1
addr isp 203.0.114.1/24 b0; addr sb 203.0.114.2/24 wanB; NS sb ip route add default via 203.0.114.1
addr isp 203.0.115.1/24 b1; addr sb 203.0.115.2/24 wanB2
# a multi-homed site answers from the address a packet arrived on: source-based routing for
# its second uplink (WireGuard replies from the address it was reached on)
NS sb ip route add default via 203.0.115.1 dev wanB2 table 115
NS sb ip rule add from 203.0.115.2 lookup 115
addr sa 192.168.50.1/24 lanA; addr ca 192.168.50.10/24 lan0; NS ca ip route add default via 192.168.50.1
addr sb 192.168.60.1/24 lanB; addr cb 192.168.60.10/24 lan0; NS cb ip route add default via 192.168.60.1
NS isp sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
# the ISP counts what crosses it: clear-text LAN addresses must never show up
NS isp nft -f - <<'NFT'
table ip lab {
  chain counted {
    type filter hook forward priority 0; policy accept;
    ip saddr 192.168.50.0/24 counter comment "clear_a"
    ip saddr 192.168.60.0/24 counter comment "clear_b"
    udp dport 51820 counter comment "wg"
  }
}
NFT
counter() { NS isp nft list chain ip lab counted | grep "comment \"$1\"" | grep -o 'packets [0-9]*' | head -1 | cut -d' ' -f2; }
# helpers the polling loops call (functions, so no sh -c)
a_ep() { NS sa wg show sdwan0 | grep -q "endpoint: $1"; }
ping_ab() { NS ca ping -c 1 -W 2 192.168.60.10; }
isp_cut_b1() { NS isp nft flush chain ip lab counted; NS isp nft add rule ip lab counted ip daddr 203.0.114.2 udp dport 51820 drop; NS isp nft add rule ip lab counted udp dport 51820 counter comment "wg"; }
isp_open() { NS isp nft flush chain ip lab counted; NS isp nft add rule ip lab counted udp dport 51820 counter comment "wg"; }

# --- the dashboard ------------------------------------------------------------
ip netns exec dash env PATRONUS_DB_PATH=/t/dash.db PATRONUS_JWT_SECRET="$JWT_SECRET" PATRONUS_NODE_ADDR=0.0.0.0:8443 RUST_LOG=info \
  "$NL_T/patronus-dashboard" >/t/dash.log 2>&1 &
PIDS+=($!)
nl_wait 60 NS isp curl -sf -o /dev/null "$DASH/health" || { tail -30 /t/dash.log; nl_fail "the dashboard did not come up"; }
dash() { # METHOD PATH [JSON] [TOKEN]: from the ISP namespace
  local m=$1 p=$2 d=${3:-} t=${4:-}
  local args=(-s -o /tmp/dash.out -w '%{http_code}' -X "$m" -H 'content-type: application/json')
  [ -n "$t" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-d "$d")
  DCODE=$(NS isp curl "${args[@]}" "$DASH$p")
}
dash POST /api/v1/auth/init-admin '{"email":"admin@errant.solutions","name":"Admin","password":"Netlab-Admin-Passw0rd!","role":"admin"}'
[ "$DCODE" = 200 ] || nl_fail "init-admin: $DCODE $(cat /tmp/dash.out)"
dash POST /api/v1/auth/login '{"email":"admin@errant.solutions","password":"Netlab-Admin-Passw0rd!"}'
[ "$DCODE" = 200 ] || nl_fail "login: $DCODE $(cat /tmp/dash.out)"
JWT=$(nl_json /tmp/dash.out 'd["access_token"]')
nl_ok "dashboard up (HTTP API, admin logged in)"

echo "=== enrollment tokens"
dash POST /api/v1/edge/tokens '{"label":"site-a"}'
[ "$DCODE" = 401 ] || nl_fail "an anonymous request created a token: $DCODE"
nl_ok "creating a token without a login is refused (401)"
dash POST /api/v1/edge/tokens '{"label":"site-a"}' "$JWT"; [ "$DCODE" = 200 ] || nl_fail "token A: $DCODE $(cat /tmp/dash.out)"
TOKEN_A=$(nl_json /tmp/dash.out 'd["token"]')
dash POST /api/v1/edge/tokens '{"label":"site-b"}' "$JWT"; TOKEN_B=$(nl_json /tmp/dash.out 'd["token"]')
grep -q "$TOKEN_A" /t/dash.db 2>/dev/null && nl_fail "the token is stored in clear text"
nl_ok "two one-time tokens created (only digests are stored)"
dash POST /api/v1/edge/enroll '{"token":"pedge_enroll_garbage","name":"x","public_key":"AAAA","endpoints":[{"address":"1.2.3.4:5"}]}'
[ "$DCODE" = 401 ] || nl_fail "garbage token accepted: $DCODE"
nl_ok "an unknown token cannot enroll (401)"

# --- two Patronus appliances ---------------------------------------------------
site() { # NAME NS WAN LAN LANADDR DB TOML
  printf '[network]\nwan_interfaces = ["%s"]\nlan_interfaces = ["%s"]\n' "$3" "$4" > "/t/toml-$1"
  NS "$2" env PATRONUS_NET_DIR="/t/net-$1" PATRONUS_RUN_DIR="/t/run-$1" "$NL_T/patronus" --db "$6" apply --bootstrap "/t/toml-$1" >"/tmp/apply-$1.out" 2>&1 || { cat "/tmp/apply-$1.out"; nl_fail "site $1: patronus apply"; }
  mkdir -p "/t/tls-$1"
  NS "$2" env PATRONUS_NET_DIR="/t/net-$1" PATRONUS_RUN_DIR="/t/run-$1" PATRONUS_DB="$6" PATRONUS_BOOTSTRAP="/t/toml-$1" PATRONUS_ADMIN_PASSWORD="$PASS" PATRONUS_ADMIN_PASSWORD_FILE="/t/pw-$1" PATRONUS_TLS_DIR="/t/tls-$1" RUST_LOG=info \
     PATRONUS_EDGE_FAILBACK_SECS=25 "$NL_T/patronus-web" >"/t/web-$1.log" 2>&1 &
  PIDS+=($!)
}
site a sa wanA lanA 192.168.50.1 /t/site-a.db
site b sb wanB lanB 192.168.60.1 /t/site-b.db
nl_wait 60 NS ca curl -sk -o /dev/null https://192.168.50.1:8443/login || { tail -20 /t/web-a.log; nl_fail "site A web did not come up"; }
nl_wait 60 NS cb curl -sk -o /dev/null https://192.168.60.1:8443/login || { tail -20 /t/web-b.log; nl_fail "site B web did not come up"; }
web() { # SITE METHOD PATH [JSON]  (from that site's LAN client, as the admin)
  local s=$1 m=$2 p=$3 d=${4:-}
  local c=ca ip=192.168.50.1; [ "$s" = b ] && { c=cb; ip=192.168.60.1; }
  local args=(-sk -b "/t/jar-$s" -c "/t/jar-$s" -o /tmp/web.out -w '%{http_code}' -X "$m" -H 'content-type: application/json')
  [ -n "$d" ] && args+=(-d "$d")
  WCODE=$(NS "$c" curl "${args[@]}" "https://$ip:8443$p")
}
for s in a b; do
  web $s POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"
  [ "$WCODE" = 200 ] || nl_fail "site $s login: $WCODE $(cat /tmp/web.out)"
done
nl_ok "both appliances are up with their own web UI"

configure() { # SITE NAME TOKEN ENDPOINTS-JSON-LIST SUBNET
  local s=$1
  web $s PUT /api/svc/edge "{\"enabled\":true,\"dashboard_url\":\"$DASH\",\"name\":\"$2\",\"enrollment_token\":\"$3\"}"
  [ "$WCODE" = 400 ] || nl_fail "site $s: enabling with no endpoint was not refused ($WCODE)"
  python3 - "$4" <<'PY' | while read -r ep; do web $s POST /api/svc/edge/endpoints "$ep"; [ "$WCODE" = 201 ] || nl_fail "site $s endpoint: $WCODE $(cat /tmp/web.out)"; done
import json, sys
for e in json.loads(sys.argv[1]): print(json.dumps(e))
PY
  web $s POST /api/svc/edge/subnets "{\"prefix\":\"$5\"}"; [ "$WCODE" = 201 ] || nl_fail "site $s subnet: $WCODE $(cat /tmp/web.out)"
  web $s PUT /api/svc/edge "{\"enabled\":true,\"dashboard_url\":\"$DASH\",\"name\":\"$2\",\"enrollment_token\":\"$3\"}"
  [ "$WCODE" = 200 ] || nl_fail "site $s: enable: $WCODE $(cat /tmp/web.out)"
}
echo "=== validation on the edge page"
web a PUT /api/svc/edge '{"dashboard_url":"ftp://nope"}'; [ "$WCODE" = 400 ] || nl_fail "bad URL accepted ($WCODE)"
web a POST /api/svc/edge/endpoints '{"address":"example.com:51820"}'; [ "$WCODE" = 400 ] || nl_fail "hostname endpoint accepted ($WCODE)"
web a POST /api/svc/edge/subnets '{"prefix":"fd00::/64"}'; [ "$WCODE" = 400 ] || nl_fail "IPv6 subnet accepted ($WCODE)"
nl_ok "a bad dashboard URL, a non-IP endpoint and an IPv6 subnet are refused (400)"

echo "=== site A joins"
configure a site-a "$TOKEN_A" '[{"address":"203.0.113.2:51820","interface_type":"fiber","cost_per_gb":0}]' 192.168.50.0/24
a_tunnel_up() { NS sa wg show sdwan0 >/dev/null 2>&1 && NS sa ip -o addr show sdwan0 | grep -q 'inet 10.99.0.1/16'; }
nl_wait 60 a_tunnel_up || { cat /t/web-a.log | tail -20; nl_fail "site A has no tunnel sdwan0 with its overlay address"; }
nl_ok "site A enrolled: tunnel sdwan0 up with overlay address $(NS sa ip -o -4 addr show sdwan0 | awk '{print $4}')"
web a GET /api/svc/edge
python3 - /tmp/web.out <<'PY' || nl_fail "page status does not show an enrolled agent"
import json, sys
d = json.load(open(sys.argv[1])); st = d["status"]
assert st["enrolled"] and st["agent_running"] and st["site_id"], st
assert d["settings"]["enrollment_token"] == "", "the used token must be erased: %r" % d["settings"]["enrollment_token"]
PY
nl_ok "status: enrolled, agent running, the one-time token erased from the page"
dash POST /api/v1/edge/enroll "{\"token\":\"$TOKEN_A\",\"name\":\"again\",\"public_key\":\"$(NS sa wg show sdwan0 public-key)\",\"endpoints\":[{\"address\":\"1.2.3.4:5\"}]}"
[ "$DCODE" = 401 ] || nl_fail "a used token enrolled a second site ($DCODE)"
nl_ok "a used token is refused (401)"

echo "=== site B joins with two endpoints (the first is preferred)"
configure b site-b "$TOKEN_B" '[{"address":"203.0.114.2:51820","interface_type":"fiber","cost_per_gb":0},{"address":"203.0.115.2:51820","interface_type":"lte","cost_per_gb":5}]' 192.168.60.0/24
b_overlay() { NS sb ip -o addr show sdwan0 | grep -q 'inet 10.99.0.2/16'; }
nl_wait 90 b_overlay || { tail -20 /t/web-b.log; nl_fail "site B has no overlay address"; }
nl_ok "site B enrolled: overlay address 10.99.0.2/16"

echo "=== the overlay carries traffic between the LANs"
nl_wait 120 ping_ab || {
  echo "--- site A"; NS sa wg show; NS sa ip route; echo "--- site B"; NS sb wg show; NS sb ip route; cat /tmp/apply-a.out | tail -3; tail -5 /t/web-a.log
  nl_fail "client A cannot reach client B through the overlay"; }
NS ca ping -c 3 -W 2 192.168.60.10 >/dev/null || nl_fail "ping A -> B"
NS cb ping -c 3 -W 2 192.168.50.10 >/dev/null || nl_fail "ping B -> A"
nl_ok "client A <-> client B (192.168.50.10 <-> 192.168.60.10) through the SD-WAN tunnel"
NS sa ip route get 192.168.60.10 | grep -q 'dev sdwan0' || nl_fail "site A does not route the remote LAN through sdwan0"
nl_ok "site A routes 192.168.60.0/24 via sdwan0: $(NS sa ip route get 192.168.60.10 | head -1)"
[ "$(counter clear_a)" = 0 ] && [ "$(counter clear_b)" = 0 ] || nl_fail "the ISP saw clear-text LAN traffic"
[ "$(counter wg)" -gt 0 ] || nl_fail "no WireGuard packets crossed the ISP"
nl_ok "the ISP carried $(counter wg) WireGuard packets and 0 clear-text LAN packets"
NS sa wg show sdwan0 | grep -q 'latest handshake' || nl_fail "no handshake on site A"
NS sa wg show sdwan0 | grep -q 'endpoint: 203.0.114.2:51820' || nl_fail "site A is not using site B's preferred endpoint"
nl_ok "site A's peer for site B uses the preferred endpoint 203.0.114.2:51820"

echo "=== the dashboard shows both sites and the measured paths"
paths_ok() { dash GET /api/v1/paths '' "$JWT"; python3 -c 'import json; d=json.load(open("/tmp/dash.out")); assert len(d)>=2'; }
nl_wait 60 paths_ok || { cat /tmp/dash.out; nl_fail "the dashboard has no paths"; }
dash GET /api/v1/sites '' "$JWT"
python3 - /tmp/dash.out <<'PY' || nl_fail "dashboard sites"
import json, sys
d = json.load(open(sys.argv[1]))
names = sorted(s["name"] for s in d)
assert names == ["site-a", "site-b"], names
assert all(s["status"].lower() == "active" for s in d), d
PY
dash GET /api/v1/edge/edges '' "$JWT"
python3 - /tmp/dash.out <<'PY' || nl_fail "dashboard edges"
import json, sys
d = {e["name"]: e for e in json.load(open(sys.argv[1]))}
assert d["site-a"]["overlay_ip"] == "10.99.0.1" and d["site-b"]["overlay_ip"] == "10.99.0.2", d
assert d["site-a"]["subnets"] == ["192.168.50.0/24"] and d["site-b"]["subnets"] == ["192.168.60.0/24"], d
PY
dash GET /api/v1/paths '' "$JWT"
python3 - /tmp/dash.out <<'PY' || nl_fail "dashboard paths"
import json, sys
d = json.load(open(sys.argv[1]))
assert d, d
print("paths:", [(p.get("status"), p.get("src_endpoint") or p.get("src"), p.get("dst_endpoint") or p.get("dst")) for p in d][:4])
PY
nl_ok "dashboard: both sites active, overlay addresses and subnets recorded, paths with metrics reported by the agents"

echo "=== endpoint failover: cut site B's preferred endpoint"
isp_cut_b1
nl_wait 200 a_ep 203.0.115.2:51820 || { NS sa wg show; tail -15 /t/net-a/edge-state.json 2>/dev/null; nl_fail "site A did not move to site B's second endpoint"; }
nl_ok "site A switched its peer for site B to the second endpoint 203.0.115.2:51820"
nl_wait 60 ping_ab || nl_fail "client A cannot reach client B on the second endpoint"
nl_ok "traffic flows again through the second uplink"
echo "=== failback when the preferred endpoint works again"
isp_open
# WireGuard roams a peer's endpoint to the source address of its latest
# authenticated packet: site B answers from whichever uplink its routes pick, so
# `wg show` can show the second address again right after the agent steered back.
# The agent's own state (what it configured) is the proof of the steering.
a_steer_idx() { python3 -c 'import json,sys; d=json.load(open("/t/net-a/edge-state.json")); print(d["peers"][0]["endpoint_index"])' 2>/dev/null; }
back_on_primary() { [ "$(a_steer_idx)" = 0 ] && ping_ab; }
nl_wait 200 back_on_primary || { NS sa wg show; nl_fail "site A did not return to the preferred endpoint"; }
nl_ok "site A is back on the preferred endpoint 203.0.114.2:51820 and traffic flows"

echo "=== patronus apply rebuilds the overlay from the store (a reboot)"
NS sa ip link del sdwan0
NS sa env PATRONUS_NET_DIR=/t/net-a PATRONUS_RUN_DIR=/t/run-a "$NL_T/patronus" --db /t/site-a.db apply >"/tmp/apply-a2.out" 2>&1 || { cat /tmp/apply-a2.out; nl_fail "apply after losing the tunnel"; }
NS sa wg show sdwan0 | grep -q 'peer:' || nl_fail "the tunnel was not rebuilt with its peer"
nl_wait 60 ping_ab || nl_fail "no traffic after the rebuild"
nl_ok "tunnel and peer rebuilt by patronus apply, traffic flows"

echo "=== revoking an edge removes it from its peers"
dash GET /api/v1/edge/edges '' "$JWT"
SID_B=$(python3 -c 'import json,sys; print([e["site_id"] for e in json.load(open(sys.argv[1])) if e["name"]=="site-b"][0])' /tmp/dash.out)
dash DELETE "/api/v1/edge/edges/$SID_B" '' "$JWT"; [ "$DCODE" = 200 ] || nl_fail "revoke: $DCODE $(cat /tmp/dash.out)"
a_no_peer() { ! NS sa wg show sdwan0 | grep -q 'peer:'; }
nl_wait 90 a_no_peer || { NS sa wg show; nl_fail "site A still has the revoked site as a peer"; }
nl_ok "after the revoke site A's agent removed the peer"
b_unenrolled() { web b GET /api/svc/edge; python3 -c 'import json; d=json.load(open("/tmp/web.out")); assert not d["status"]["enrolled"]'; }
nl_wait 60 b_unenrolled || nl_fail "site B still believes it is enrolled"
nl_ok "site B's agent noticed the revoked credential"

echo "=== leaving the overlay"
web a PUT /api/svc/edge '{"enabled":false}'; [ "$WCODE" = 200 ] || nl_fail "disable: $WCODE $(cat /tmp/web.out)"
NS sa ip link show sdwan0 >/dev/null 2>&1 && nl_fail "tunnel still present after leaving the overlay"
a_agent_gone() { ! pgrep -f "patronus --db /t/site-a.db edge run"; }
nl_wait 20 a_agent_gone || nl_fail "site A's agent is still running"
NS sa nft list ruleset | grep -q sdwan0 && nl_fail "SD-WAN firewall rules still present"
nl_ok "disabled: tunnel removed, agent stopped, firewall rules gone"
echo "ALL SD-WAN EDGE CHECKS PASSED"
