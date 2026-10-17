#!/usr/bin/env bash
# Lane A (foundation) netlab test. Runs INSIDE the capped netlab container
# (see ci/netlab/run.sh) as root with CAP_NET_ADMIN/CAP_SYS_ADMIN, with the
# shipped binaries in /t: `patronus` (patronus-cli) and `patronus-web`.
#
# Topology, rebuilt from scratch for every "boot" (a fresh network namespace
# = empty nftables, ip_forward=0, exactly what a reboot gives the kernel):
#
#   lan (192.168.50.10) --- rtr-lan [rtr] rtr-wan --- wan (203.0.113.1)
#                       192.168.50.1      203.0.113.2
#
# The wan namespace has NO route back to 192.168.50.0/24, so a LAN client
# can only reach it if the router really masquerades.
#
# Proves:
#  1. fresh box: `patronus apply` with only patronus.toml turns on
#     forwarding, LAN->WAN works with the WAN address as source, WAN->LAN and
#     WAN->router SSH are dropped, LAN->router SSH (anti-lockout) works.
#  2. rules + NAT created through the web API are applied live, survive a
#     patronus-web restart (listed again by the API) and a reboot (fresh
#     namespace + `patronus apply` reproduces them in `nft list ruleset` and
#     in real traffic).
#  3. `patronus firewall apply|flush` is the firewall-only subset.
set -euo pipefail

P=/t/patronus
WEB=/t/patronus-web
PASS='Netlab-Test-Passw0rd!'
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }
R() { ip netns exec rtr "$@"; }
L() { ip netns exec lan "$@"; }
W() { ip netns exec wan "$@"; }

cat > /t/peer.py <<'EOF'
# TCP server: reply with the client's source address, one line per connection.
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
while True:
    c, a = s.accept(); c.sendall((a[0] + "\n").encode()); c.close()
EOF
cat > /t/conn.py <<'EOF'
# Connect and print what the server says; exit 1 if unreachable in 2s.
import socket, sys
try:
    c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
    print(c.recv(100).decode().strip())
except OSError as e:
    print("unreachable:", e); sys.exit(1)
EOF

PIDS=()
bg() { "$@" & PIDS+=($!); }
stop_bg() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; PIDS=(); sleep 0.3; }

topology_down() {
  stop_bg
  for n in rtr lan wan; do ip netns del "$n" 2>/dev/null || true; done
}
topology_up() {
  topology_down
  for n in rtr lan wan; do ip netns add "$n"; ip -n "$n" link set lo up; done
  ip link add rtr-lan netns rtr type veth peer name lan0 netns lan
  ip link add rtr-wan netns rtr type veth peer name wan0 netns wan
  R ip addr add 192.168.50.1/24 dev rtr-lan; R ip link set rtr-lan up
  R ip addr add 203.0.113.2/24 dev rtr-wan; R ip link set rtr-wan up
  L ip addr add 192.168.50.10/24 dev lan0; L ip link set lan0 up
  L ip route add default via 192.168.50.1
  W ip addr add 203.0.113.1/24 dev wan0; W ip link set wan0 up
  # services to reach
  bg W python3 /t/peer.py 203.0.113.1 8080
  bg W python3 /t/peer.py 203.0.113.1 8081
  bg L python3 /t/peer.py 192.168.50.10 9000
  bg R python3 /t/peer.py 0.0.0.0 22      # stands in for sshd
  bg R python3 /t/peer.py 0.0.0.0 2222
  sleep 0.5
  # a WAN-side attacker that knows the LAN prefix
  W ip route add 192.168.50.0/24 via 203.0.113.2
  # A new namespace copies IPv4 devconf from the host (devconf_inherit_init_net
  # = 0), and CI hosts run Docker with forwarding on; a booting box starts
  # with forwarding off, so start there to prove Patronus turns it on.
  R sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv6/conf/all/forwarding'
  [ "$(R cat /proc/sys/net/ipv4/ip_forward)" = 0 ] || fail "fresh namespace already forwards"
  [ -z "$(R nft list ruleset)" ] || fail "fresh namespace already has a ruleset"
}

reach() { "$@" >/tmp/reach.out 2>&1; }  # $1.. = netns wrapper + conn.py args
expect_reach() { local d=$1; shift; reach "$@" || { cat /tmp/reach.out; fail "$d: expected reachable"; }; ok "$d ($(cat /tmp/reach.out))"; }
expect_blocked() { local d=$1; shift; if reach "$@"; then fail "$d: expected blocked, got $(cat /tmp/reach.out)"; fi; ok "$d (blocked)"; }

assert_router_state() {
  [ "$(R cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || fail "ip_forward not 1"
  [ "$(R cat /proc/sys/net/ipv6/conf/all/forwarding)" = 1 ] || fail "ipv6 forwarding not 1"
  [ "$(R cat /proc/sys/net/ipv6/conf/rtr-wan/accept_ra)" = 2 ] || fail "WAN accept_ra not 2"
  ok "sysctl: net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.rtr-wan.accept_ra=2"
  RS=$(R nft list ruleset)
  for want in 'policy drop' 'iifname "rtr-lan" tcp dport { 22, 8443 } accept' \
              'iifname "rtr-lan" accept' 'oifname "rtr-wan" masquerade'; do
    grep -qF "$want" <<<"$RS" || { echo "$RS"; fail "ruleset lacks: $want"; }
  done
  if grep -q 'iifname "rtr-wan" tcp dport { 22, 8443 }' <<<"$RS"; then fail "anti-lockout open on WAN"; fi
  ok "nft ruleset has drop policies, LAN anti-lockout, LAN->any, WAN masquerade"
}

assert_default_traffic() {
  expect_reach "LAN -> WAN host (masqueraded)" L python3 /t/conn.py 203.0.113.1 8081
  [ "$(cat /tmp/reach.out)" = 203.0.113.2 ] || fail "WAN saw source $(cat /tmp/reach.out), not the router's WAN address"
  ok "WAN host saw the router's WAN address 203.0.113.2 as source"
  expect_reach "LAN -> router SSH (anti-lockout)" L python3 /t/conn.py 192.168.50.1 22
  expect_blocked "WAN -> router SSH" W python3 /t/conn.py 203.0.113.2 22
  expect_blocked "WAN -> LAN host" W python3 /t/conn.py 192.168.50.10 9000
}

TOML=/t/patronus.toml
printf '[network]\nwan_interface = "rtr-wan"\nlan_interface = "rtr-lan"\n' > "$TOML"

echo "=== 1. fresh box: patronus apply with only patronus.toml"
topology_up
expect_blocked "LAN -> WAN before apply (no forwarding)" L python3 /t/conn.py 203.0.113.1 8081
R "$P" --db /t/box1.db apply --bootstrap "$TOML"
assert_router_state
assert_default_traffic
DRY=$(R "$P" --db /t/box1.db apply --dry-run --bootstrap "$TOML")
grep -q '^### sysctl (sysctl)' <<<"$DRY" && grep -q '^### firewall (firewall)' <<<"$DRY" \
  && grep -q 'oifname "rtr-wan" masquerade' <<<"$DRY" || { echo "$DRY"; fail "dry-run output"; }
ok "patronus apply --dry-run renders the plan"

echo "=== 2. rules via the web API, then restart and reboot"
topology_up
DB=/t/box2.db
WEB_PID=
stop_web() { [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null; wait "$WEB_PID" 2>/dev/null || true; WEB_PID=; }
start_web() {
  env PATRONUS_DB=$DB PATRONUS_BOOTSTRAP=$TOML PATRONUS_ADMIN_PASSWORD="$PASS" \
     PATRONUS_ADMIN_PASSWORD_FILE=/t/pw PATRONUS_TLS_DIR=/t/tls RUST_LOG=info \
     ip netns exec rtr "$WEB" >>/t/web.log 2>&1 &
  WEB_PID=$!
  for i in $(seq 1 60); do
    L curl -sk -o /dev/null https://192.168.50.1:8443/login && return 0; sleep 0.5
  done
  cat /t/web.log; fail "patronus-web did not come up on 192.168.50.1:8443 (reached from the LAN)"
}
api() { # method path [json]
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  L curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.1:8443/api$2"
}
# boot first (as the init system does), then the web UI
R "$P" --db $DB apply --bootstrap "$TOML"
start_web
ok "patronus-web reachable from the LAN through the anti-lockout rule"
code=$(api POST /auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"); [ "$code" = 200 ] || fail "login $code $(cat /tmp/api.out)"
for body in \
  '{"name":"netlab-block-8080","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"203.0.113.1","port":"8080","description":"netlab-block-8080","enabled":true}' \
  '{"name":"netlab-wan-2222","chain":"input","action":"accept","interface":"@wan","protocol":"tcp","source":"any","destination":"any","port":"2222","description":"netlab-wan-2222","enabled":true}'; do
  code=$(api POST /firewall/rules "$body"); [ "$code" = 201 ] || fail "add rule $code $(cat /tmp/api.out)"
done
code=$(api POST /firewall/nat '{"rule_type":"SNAT","interface":"@wan","source":"192.168.60.0/24","destination":"any","target":"203.0.113.2","description":"netlab-snat","enabled":true}')
[ "$code" = 201 ] || fail "add NAT $code $(cat /tmp/api.out)"
code=$(api POST /firewall/rules '{"action":"accept","interface":"eth0","protocol":"tcp","source":"0.0.0.0/0; flush ruleset","destination":"any","port":"1","description":"evil","enabled":true}')
[ "$code" = 400 ] || fail "injection payload got $code"
ok "API: 2 filter rules + 1 NAT rule created (201), injection rejected (400)"

assert_api_rules() {
  code=$(api GET /firewall/rules); [ "$code" = 200 ] || fail "list $code"
  for m in netlab-block-8080 netlab-wan-2222 Anti-lockout; do grep -q "$m" /tmp/api.out || fail "API list lacks $m"; done
  code=$(api GET /firewall/nat); grep -q netlab-snat /tmp/api.out || fail "API NAT list lacks netlab-snat"
}
assert_user_rules_live() {
  RS=$(R nft list ruleset)
  for want in 'netlab-block-8080' 'netlab-wan-2222' 'netlab-snat' 'to 203.0.113.2'; do
    grep -qF "$want" <<<"$RS" || { echo "$RS"; fail "ruleset lacks $want"; }
  done
  ok "nft ruleset has the API-created rules"
  expect_blocked "LAN -> WAN:8080 (user block rule)" L python3 /t/conn.py 203.0.113.1 8080
  expect_reach "LAN -> WAN:8081 (still allowed)" L python3 /t/conn.py 203.0.113.1 8081
  expect_reach "WAN -> router:2222 (user allow rule)" W python3 /t/conn.py 203.0.113.2 2222
  expect_blocked "WAN -> router SSH" W python3 /t/conn.py 203.0.113.2 22
}
assert_api_rules
assert_user_rules_live

echo "--- restart patronus-web"
stop_web
# drop the firewall from the kernel: the restarted patronus-web must load it
# again from the store, not find it left over
R nft flush ruleset
start_web
code=$(api POST /auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"); [ "$code" = 200 ] || fail "re-login $code"
assert_api_rules
ok "rules listed by the API after a patronus-web restart"
assert_user_rules_live
stop_web

echo "--- reboot: fresh namespace, only 'patronus apply'"
topology_up
R "$P" --db $DB apply --bootstrap "$TOML"
assert_router_state
assert_user_rules_live
assert_default_traffic
echo "--- nft list ruleset after boot apply:"; R nft list ruleset

echo "=== 3. config history: roll back to before netlab-wan-2222 was added"
REVS=$(R "$P" --db $DB config revisions); echo "$REVS"
REV=$(awk '/before create firewall rule netlab-wan-2222/{print $1; exit}' <<<"$REVS")
[ -n "$REV" ] || fail "no revision recorded for the API change"
R "$P" --db $DB config rollback "$REV"
RS=$(R nft list ruleset)
grep -q netlab-block-8080 <<<"$RS" || fail "rollback lost the earlier rule"
if grep -q netlab-wan-2222 <<<"$RS"; then fail "rollback kept the later rule"; fi
expect_blocked "WAN -> router:2222 after rollback" W python3 /t/conn.py 203.0.113.2 2222
ok "patronus config rollback restored the store and the kernel to revision $REV"

echo "=== 4. patronus firewall apply|flush"
R "$P" --db $DB firewall flush
[ -z "$(R nft list ruleset)" ] || fail "flush left a ruleset"
R "$P" --db $DB firewall apply --bootstrap "$TOML"
R nft list ruleset | grep -q netlab-block-8080 || fail "firewall apply did not restore user rules"
ok "firewall flush removes the table, firewall apply restores it from the store"

stop_web; topology_down
echo "ALL LANE A NETLAB CHECKS PASSED"
