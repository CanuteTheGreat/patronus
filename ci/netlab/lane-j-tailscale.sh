#!/usr/bin/env bash
# Lane J: Tailscale mesh VPN client (USE=tailscale), proven against a real Headscale
# control server (no internet login in CI) and a second tailscale node:
#
#   router (203.0.113.2) --- isp --- headscale (198.51.100.10:8080, nl-inet)
#                              \---- peer node (198.19.0.2, nl-peer)
#
# - the Tailscale page joins the router to the tailnet with a pre-auth key read from a FILE
#   (the key is in no API answer and not in the configuration store); tailscaled runs under
#   the supervisor on the configured interface and the router gets a tailnet address;
# - the peer sees the router, tailscale pings it, and by default cannot open the router's web
#   interface through the tailnet (the interface is firewalled); "Let tailnet devices reach this
#   router" opens it, switching it off closes it again;
# - an advertised LAN route, once approved on the control server, is used by the peer: the LAN
#   client answers the peer's ping only while "Let tailnet devices reach the LAN" is on;
# - the node keeps its identity across a reboot (no key file needed any more) and switching the
#   page off stops tailscaled and removes the interface.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-tailscale.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
command -v tailscaled >/dev/null && command -v headscale >/dev/null || nl_fail "tailscale / headscale are not installed in the netlab container (ci/netlab/run.sh installs them for this scenario)"
HS=/t/hs; PEER=/t/ts-peer; STATE=/t/ts-router
KEY=/t/ts-router.key
rm -rf "$HS" "$PEER" "$STATE"; mkdir -p "$HS" "$PEER" "$STATE"
HSURL=http://198.51.100.10:8080
api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
PEERNS() { ip netns exec nl-peer "$@"; }
PTS() { PEERNS tailscale --socket=$PEER/sock "$@"; }
HSC() { INET headscale -c $HS/config.yaml "$@"; }

kill_pidfile() { [ -s "$1" ] && kill "$(cat "$1")" 2>/dev/null || true; rm -f "$1"; }
cleanup() {
  kill_pidfile $PEER/tailscaled.pid; kill_pidfile $HS/headscale.pid
  pkill -x tailscaled 2>/dev/null || true
  ip netns del nl-peer 2>/dev/null || true
}
trap cleanup EXIT
pkill -x tailscaled 2>/dev/null || true

cat > $HS/config.yaml <<EOF
server_url: $HSURL
listen_addr: 198.51.100.10:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: true
noise:
  private_key_path: $HS/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: $HS/db.sqlite
dns:
  magic_dns: false
  base_domain: tailnet.test
  nameservers:
    global: []
unix_socket: $HS/headscale.sock
unix_socket_permission: "0770"
log:
  level: info
EOF

start_headscale() { # in the (new) nl-inet namespace
  kill_pidfile $HS/headscale.pid
  INET headscale -c $HS/config.yaml serve >>$HS/headscale.log 2>&1 &
  echo $! > $HS/headscale.pid
  for _ in $(seq 1 60); do HSC users list >/dev/null 2>&1 && return 0; sleep 0.5; done
  cat $HS/headscale.log; nl_fail "headscale did not start"
}
peer_ns() { # the second node's namespace, behind the ISP
  ip netns del nl-peer 2>/dev/null || true
  ip netns add nl-peer; ip -n nl-peer link set lo up
  ip link add pisp netns nl-isp type veth peer name p0 netns nl-peer
  ISP ip addr add 198.19.0.1/24 dev pisp; ISP ip link set pisp up
  ip -n nl-peer addr add 198.19.0.2/24 dev p0; ip -n nl-peer link set p0 up
  ip -n nl-peer route add default via 198.19.0.1
}
boot() { # a reboot: fresh namespaces, headscale and the peer's namespace back, patronus apply
  kill_pidfile $PEER/tailscaled.pid
  pkill -x tailscaled 2>/dev/null || true
  nl_kill_daemons nothing
  nl_up; peer_ns; start_headscale
  nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
  nl_ok "boot: patronus apply"
}
mkkey() { HSC preauthkeys create --user "$UID_HS" --reusable --expiration 2h -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])'; }

# functions nl_wait polls (they run in this shell)
ts_state() { nl_api GET /svc/tailscale && jget 'd["status"].get("backend_state","")'; }
running() { [ "$(ts_state 2>/dev/null || true)" = Running ]; }
peer_pongs() { local o; o=$(PTS ping -c 1 --timeout=3s "$RIP" 2>&1 || true); grep -q pong <<<"$o"; }
peer_web_code() { PEERNS curl -sk -m 4 -o /dev/null -w '%{http_code}' "https://$RIP:8443/login" 2>/dev/null || true; }
peer_web_open() { [ "$(peer_web_code)" = 200 ]; }
peer_web_closed() { [ "$(peer_web_code)" != 200 ]; }
peer_has_route() { local o; o=$(PEERNS ip route show table 52 2>/dev/null || true); grep -q '192.168.50.0/24' <<<"$o"; }
peer_pings_lan() { PEERNS ping -c1 -W3 $NL_CLIENT >/dev/null 2>&1; }
no_ts_iface() { ! R ip link show tailscale0 >/dev/null 2>&1; }

boot
HSC users create lab >/dev/null
UID_HS=$(HSC users list -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
mkkey > $KEY; chmod 600 $KEY
nl_ok "headscale is up and issued a pre-auth key"
nl_web_start "$DB"; nl_login

echo "=== validation"
for body in '{"login_server":"headscale"}' '{"auth_key_file":"relative"}' '{"interface":"bad name"}' '{"advertise_routes":"10.0.0.0/99"}'; do
  nl_api PUT /svc/tailscale "$body"
  [ "$NL_CODE" = 400 ] || nl_fail "accepted $body: $NL_CODE $(cat "$NL_OUT")"
done
nl_ok "a control server without a scheme, a relative key path, a bad device name and a bad route are refused (400)"

echo "=== 1. join the tailnet with a key from a file"
api_ok PUT /svc/tailscale "{\"enabled\":true,\"login_server\":\"$HSURL\",\"auth_key_file\":\"$KEY\",\"hostname\":\"rtr\",\"state_dir\":\"$STATE\",\"open_port\":true,\"advertise_routes\":\"192.168.50.0/24\"}"
nl_wait 90 running || { nl_api GET /svc/tailscale; cat "$NL_OUT"; tail -30 $HS/headscale.log; nl_fail "the router did not reach Running"; }
nl_api GET /svc/tailscale
RIP=$(jget 'd["status"]["addresses"][0]')
case "$RIP" in 100.64.*) ;; *) nl_fail "no tailnet address: $(cat "$NL_OUT")";; esac
R ip link show tailscale0 >/dev/null 2>&1 || nl_fail "no tailscale0 interface in the router namespace"
nl_ok "the router joined the tailnet as $RIP on tailscale0"
KEYTXT=$(cat $KEY)
grep -qF "$KEYTXT" "$NL_OUT" && nl_fail "the pre-auth key is in the API answer"
sqlite3 "$DB" .dump >"$NL_OUT"
grep -qF "$KEYTXT" "$NL_OUT" && nl_fail "the pre-auth key is stored in the configuration"
nl_ok "the pre-auth key itself is in no API answer and not in the configuration store"
nl_assert_nft_has 'udp dport 41641 accept'

echo "=== 2. the peer joins and talks to the router"
PEERNS tailscaled --state=$PEER/state --socket=$PEER/sock --port=41642 --tun=tspeer0 >$PEER/tailscaled.log 2>&1 &
echo $! > $PEER/tailscaled.pid
for _ in $(seq 1 40); do PTS status >/dev/null 2>&1 && break; sleep 0.5; done
PKEY=$(mkkey)
PTS up --reset --timeout=60s --login-server=$HSURL --auth-key="$PKEY" --hostname=peer --accept-routes --netfilter-mode=off >$PEER/up.log 2>&1 || { cat $PEER/up.log; nl_fail "the peer could not join"; }
nl_wait 60 peer_pongs || { PTS ping -c 3 --timeout=5s $RIP || true; PTS status || true; nl_fail "the peer cannot tailscale-ping the router"; }
nl_ok "the peer pings the router through the tailnet"

echo "=== 3. the tailnet interface is firewalled"
peer_web_closed || nl_fail "the router's web interface answered through the tailnet by default"
nl_ok "by default the router's web interface does not answer on the tailnet"
api_ok PUT /svc/tailscale '{"allow_input":true}'
nl_wait 20 peer_web_open || nl_fail "allow_input did not open the web interface to the tailnet"
nl_ok "with 'tailnet devices reach this router' on, the peer reaches the login page"
api_ok PUT /svc/tailscale '{"allow_input":false}'
nl_wait 20 peer_web_closed || nl_fail "switching allow_input off did not close it"
nl_ok "switching it off closes the interface again"

echo "=== 4. an advertised LAN route"
NODE=$(HSC nodes list -o json | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin) if "rtr" in (n.get("given_name",""), n.get("name",""))][0])')
HSC nodes approve-routes -i "$NODE" -r 192.168.50.0/24 >/dev/null 2>&1 || nl_fail "could not approve the advertised route on headscale"
nl_wait 60 peer_has_route || { PEERNS ip route show table 52; PTS status; nl_fail "the peer did not learn the advertised LAN route"; }
nl_ok "the peer learned 192.168.50.0/24 through the tailnet"
peer_pings_lan && nl_fail "the peer reached the LAN client while 'reach the LAN' was off"
nl_ok "with 'tailnet devices reach the LAN' off the LAN stays unreachable"
api_ok PUT /svc/tailscale '{"allow_lan":true}'
nl_wait 20 peer_pings_lan || { R nft list ruleset | grep -i tailscale || true; nl_fail "the peer cannot reach the LAN client with allow_lan on"; }
nl_ok "with it on, the peer pings the LAN client ($NL_CLIENT) through the router"
api_ok PUT /svc/tailscale '{"allow_lan":false}'

echo "=== 5. reboot: the node keeps its identity"
rm -f $KEY
nl_web_stop
boot
nl_web_start "$DB"; nl_login
nl_wait 90 running || { nl_api GET /svc/tailscale; cat "$NL_OUT"; nl_fail "after the reboot the node is not Running again (no key file needed)"; }
nl_api GET /svc/tailscale
[ "$(jget 'd["status"]["addresses"][0]')" = "$RIP" ] || nl_fail "the router has a new tailnet address after the reboot"
nl_ok "after a reboot the router is back on the tailnet with the same address $RIP"

echo "=== 6. off stops it"
api_ok PUT /svc/tailscale '{"enabled":false}'
nl_wait 20 no_ts_iface || nl_fail "tailscale0 is still there after switching the page off"
nl_assert_nft_lacks 'Tailscale'
nl_ok "switched off: tailscaled stopped, the interface and the firewall rules are gone"
nl_web_stop
nl_down
