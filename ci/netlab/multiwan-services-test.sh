#!/usr/bin/env bash
# Multi-WAN polish (lane E) netlab in a real Gentoo stage3, once per init system (run by
# `NETLAB_TEST=multiwan-services-test.sh ci/netlab/lan-services.sh openrc|systemd`), with the shipped binaries and init
# files: patronus-applyd (root, runs the gateway monitor) and patronus-web (user patronus) are started by OpenRC /
# systemd, conntrack-tools is the distro's.
#
#   lan 192.168.50.10 -- rtr-lan 192.168.50.1 [ router = this container ] rtr-wan  203.0.113.2 -- isp1 203.0.113.1 --+
#                                                                         rtr-wan2 100.64.0.2  -- isp2 100.64.0.1 --+-- inet 198.51.100.10
#
# Proves, with the real init and a real conntrack: a gateway group with a latency trigger leaves a slow uplink (tc
# netem) and comes back; kill states delete the tracked state of an idle TCP connection when its uplink goes away and
# (down_recovery) the fallback's when the better uplink returns, while an active UDP flow follows the route; sticky connections keep a client on its uplink (also after the
# other uplink returns); the DNS server of a gateway is pinned to it; the monitor, sticky table and kill states survive
# `patronus apply` (reboot-equivalent) and the second apply changes nothing.
set -euo pipefail
INIT=${1:?openrc|systemd}

fail() {
  echo "FAIL: $*" >&2
  set +e
  echo "--- debug: routes, rules, table 4250, tracked connections, gateway status"
  ip -4 route; ip -4 rule; ip -4 route show table 4250; conntrack -L 2>/dev/null | head -20
  cat /run/patronus/gateway-status.json 2>/dev/null; echo
  N lan curl -sv --max-time 4 http://198.51.100.10/ 2>&1 | tail -12
  exit 1
}
ok() { echo "ok - $*"; }
N() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
has() { grep -qF -- "$2" <<<"$1" || fail "$3: $1"; }
wait_for() { # DESC SECONDS cmd...
  local d=$1 s=$2; shift 2
  for _ in $(seq 1 $((s * 4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "timed out after ${s}s waiting for: $d"
}

echo "=== 0. install the shipped binaries and $INIT service files"
install -m755 /t/patronus-cli /usr/bin/patronus-cli
ln -sf patronus-cli /usr/bin/patronus
install -m755 /t/patronus-web /usr/bin/patronus-web
getent group patronus >/dev/null || groupadd -r patronus
getent passwd patronus >/dev/null || useradd -r -g patronus -d /var/lib/patronus -s /sbin/nologin patronus
install -d -o patronus -g patronus /var/lib/patronus /var/log/patronus
install -d -o root -g patronus -m 0750 /etc/patronus
install -d -o patronus -g patronus -m 0700 /etc/patronus/tls
printf '[network]\nwan_interface = "rtr-wan"\nlan_interface = "rtr-lan"\n' > /etc/patronus/patronus.toml
case "$INIT" in
openrc)
  sed -i 's/^#\?rc_sys=.*/rc_sys="docker"/' /etc/rc.conf
  printf 'rc_provide="loopback net"\nrc_depend_strict="NO"\n' >> /etc/rc.conf
  mkdir -p /run/openrc && touch /run/openrc/softlevel
  for s in applyd web firewall; do install -m755 "/t/patronus-$s.initd" "/etc/init.d/patronus-$s"; done
  ;;
systemd)
  for s in applyd web firewall; do install -m644 "/t/patronus-$s.service" /etc/systemd/system/; done
  systemctl daemon-reload
  ;;
esac
command -v conntrack >/dev/null || fail "conntrack-tools missing from the image (the multiwan package depends on it)"

echo "=== 1. topology: client, router (this container), two ISPs, an internet host reachable through both"
for ns in lan isp1 isp2 inet; do ip netns add $ns; N $ns ip link set lo up; done
ip link add rtr-lan type veth peer name lan0 netns lan
ip link add rtr-wan type veth peer name up0 netns isp1
ip link add rtr-wan2 type veth peer name up0 netns isp2
ip link add down0 netns isp1 type veth peer name in1 netns inet
ip link add down0 netns isp2 type veth peer name in2 netns inet
ip addr add 192.168.50.1/24 dev rtr-lan; ip link set rtr-lan up
ip addr add 203.0.113.2/24 dev rtr-wan; ip link set rtr-wan up
N lan ip addr add 192.168.50.10/24 dev lan0; N lan ip link set lan0 up; N lan ip route add default via 192.168.50.1
N isp1 ip addr add 203.0.113.1/24 dev up0; N isp1 ip link set up0 up
N isp1 ip addr add 198.51.100.1/24 dev down0; N isp1 ip link set down0 up
N isp1 sysctl -qw net.ipv4.ip_forward=1
N isp2 ip addr add 100.64.0.1/24 dev up0; N isp2 ip link set up0 up
N isp2 ip addr add 192.0.2.1/24 dev down0; N isp2 ip link set down0 up
N isp2 sysctl -qw net.ipv4.ip_forward=1
N isp1 sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
N isp2 sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
N inet ip addr add 198.51.100.10/24 dev in1; N inet ip link set in1 up
N inet ip addr add 192.0.2.10/24 dev in2; N inet ip link set in2 up
N inet ip route add 203.0.113.0/24 via 198.51.100.1
N inet ip route add 100.64.0.0/24 via 192.0.2.1
N isp1 ip route add 100.64.0.0/24 via 198.51.100.10
N isp2 ip route add 198.51.100.0/24 via 192.0.2.10
N inet sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
# the internet host answers "<host> sees <client address>" and logs UDP/TCP sources
cat > /t/srv.py <<'PY'
import socket, sys, threading, time, http.server
log = open(sys.argv[1], 'a', buffering=1)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ('inet sees %s\n' % self.client_address[0]).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(http.server.ThreadingHTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); self.socket.bind(self.server_address)
        self.server_name = 'inet'; self.server_port = self.server_address[1]
threading.Thread(target=S(('0.0.0.0', 80), H).serve_forever, daemon=True).start()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('0.0.0.0', 9999))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(('0.0.0.0', 9998)); t.listen(8)
def tcp():
    while True:
        c, a = t.accept()
        threading.Thread(target=lambda c=c: [c.recv(100) for _ in iter(int, 1)], daemon=True).start()
threading.Thread(target=tcp, daemon=True).start()
while True:
    _, a = u.recvfrom(100)
    log.write('%f udp %s\n' % (time.time(), a[0]))
PY
cat > /t/snd.py <<'PY'
import socket, sys, time
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('0.0.0.0', 40000))
while True:
    u.sendto(b'x', (sys.argv[1], 9999))
    time.sleep(0.2)
PY
cat > /t/idle.py <<'PY'
import socket, sys, time
t = socket.create_connection((sys.argv[1], 9998))
time.sleep(3600)
PY
: > /t/srv.log
N inet python3 -u /t/srv.py /t/srv.log >/t/srv.out 2>&1 & SRV=$!
SND=; IDLE=
trap 'kill $SRV $SND $IDLE 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do N lan curl -s -m 2 -o /dev/null http://198.51.100.10/ 2>/dev/null && break; sleep 0.5; done
ok "topology built; the internet host answers through ISP 1's address plan"

echo "=== 2. boot, applyd + web as $INIT services, login"
# the router's own default route (what a dynamic gateway would learn)
ip route del default 2>/dev/null || true   # the container's own docker route must not carry the test traffic
ip route add default via 203.0.113.1 dev rtr-wan metric 100
patronus apply >/t/apply.out 2>&1 || { cat /t/apply.out; fail "patronus apply"; }
case "$INIT" in
  openrc) rc-service patronus-applyd start; rc-service patronus-web start ;;
  systemd) systemctl start patronus-applyd patronus-web ;;
esac
for _ in $(seq 1 60); do N lan curl -sk -o /dev/null https://192.168.50.1/login && break; sleep 0.5; done
getent group patronus-admin >/dev/null || groupadd -r patronus-admin
id nladmin >/dev/null 2>&1 || useradd -m -G patronus-admin -s /bin/sh nladmin
PASS=nlpass-Mw7-4x
echo "nladmin:$PASS" | chpasswd -c SHA512
api() {
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  N lan curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.1$2"
}
want() { local w=$1; shift; local code; code=$(api "$@"); [ "$code" = "$w" ] || fail "$1 $2 -> $code (want $w): $(cat /tmp/api.out)"; }
want 200 POST /api/auth/login "{\"username\":\"nladmin\",\"password\":\"$PASS\"}"
ok "applyd (root) and the web UI (patronus) run under $INIT"

who() { N lan curl -s --max-time 4 http://198.51.100.10/ | awk '{print $3}'; }
gw_json() { # GATEWAY EXPR over g
  api GET /api/routing >/dev/null
  python3 -c 'import json,sys; d=json.load(open("/tmp/api.out")); g=[x for x in d["gateways"] if x["name"]==sys.argv[1]][0]; print(eval(sys.argv[2]))' "$1" "$2"
}
gw_is() { [ "$(gw_json "$1" 'g["state"]')" = "$2" ]; }
via_is() { ip -4 route show table 4250 proto 253 | grep "$1" >/dev/null; }
client_on() { [ "$(who)" = "$1" ]; }
seen_udp() { awk -v s="$1" -v t="$2" '$2=="udp" && $3==s && $1>t {n++} END {exit !n}' /t/srv.log; }

echo "=== 3. second uplink, gateways, a failover group with a latency trigger"
want 200 PUT /api/interfaces/rtr-wan2 '{"role":"opt1","ipv4_mode":"static","ipv4":["100.64.0.2/24"],"gateway4":"100.64.0.1"}'
want 201 POST /api/routing/gateways '{"name":"WAN1","interface":"@wan","address":"203.0.113.1","latency_threshold":100,"latency_warn":40,"dns_servers":"198.51.100.53"}'
want 201 POST /api/routing/gateways '{"name":"WAN2","interface":"@opt1","address":"100.64.0.1","monitor_ip":"192.0.2.10"}'
GRP='"name":"FAILOVER","members":"WAN1:1, WAN2:2"'
want 201 POST /api/routing/groups "{$GRP,\"trigger\":\"latency\",\"kill_states\":\"down_recovery\"}"
want 200 PUT /api/routing/default '{"ipv4":"FAILOVER"}'
wait_for "both gateways online" 30 gw_is WAN1 online
wait_for "WAN2 online" 30 gw_is WAN2 online
via_is 'via 203.0.113.1 dev rtr-wan' || fail "default via the group: $(ip -4 route show table 4250)"
[ "$(who)" = 203.0.113.2 ] || fail "the client should leave via WAN1"
ip -4 route show proto 252 | grep '198.51.100.53 via 203.0.113.1 dev rtr-wan' >/dev/null \
  || fail "DNS server of WAN1 is not pinned to it: $(ip -4 route show proto 252)"
ok "gateways and group configured through the API; WAN1 carries the LAN; WAN1's DNS server is pinned to it"

echo "=== 4. latency trigger (tc netem on ISP 1), warning level"
N isp1 tc qdisc add dev up0 root netem delay 60ms
warn_is() { [ "$(gw_json WAN1 'g["warning"] or ""')" = latency ]; }
wait_for "WAN1 warning: latency" 40 warn_is
via_is 'via 203.0.113.1 dev rtr-wan' || fail "a warning must not move the default route"
N isp1 tc qdisc change dev up0 root netem delay 160ms
wait_for "default route to WAN2" 40 via_is 'via 100.64.0.1 dev rtr-wan2'
[ "$(who)" = 100.64.0.2 ] || fail "latency failover: the client should leave via WAN2"
N isp1 tc qdisc del dev up0 root
wait_for "default back on WAN1" 40 via_is 'via 203.0.113.1 dev rtr-wan'
wait_for "client back on WAN1" 10 client_on 203.0.113.2
ok "latency trigger fails over to WAN2 and back ($INIT); a warning level alone moves nothing"

echo "=== 5. kill states: the tracked state of an idle connection goes with its uplink"
# Linux re-masquerades an ACTIVE flow whose output interface changed by itself; the tracked state of an idle TCP
# connection (five days) would stay behind: kill states deletes it with the uplink (down) and, with down_recovery,
# the fallback's when the better uplink returns.
idle_ct() { conntrack -L -p tcp 2>/dev/null | grep -E "dport=9998 .*src=198.51.100.10 dst=$1 " >/dev/null; }
no_idle_ct() { ! idle_ct "$1"; }
idle_start() { # WAN-ADDRESS the connection must be tracked on
  [ -z "$IDLE" ] || { kill "$IDLE" 2>/dev/null || true; wait "$IDLE" 2>/dev/null || true; }
  conntrack -F >/dev/null 2>&1 || true
  N lan python3 -u /t/idle.py 198.51.100.10 & IDLE=$!
  wait_for "the idle TCP connection tracked on $1" 10 idle_ct "$1"
}
want 200 PUT /api/routing/groups/FAILOVER "{$GRP,\"trigger\":\"down\",\"kill_states\":\"down\"}"
N lan python3 -u /t/snd.py 198.51.100.10 & SND=$!
wait_for "UDP flow seen via WAN1" 15 seen_udp 203.0.113.2 0
idle_start 203.0.113.2
N isp1 ip addr flush dev up0
wait_for "default on WAN2" 30 via_is 'via 100.64.0.1 dev rtr-wan2'
MOVED=$(date +%s.%N)
wait_for "the idle connection's state on WAN1's address deleted" 10 no_idle_ct 203.0.113.2
wait_for "the UDP flow to reach the internet host as 100.64.0.2" 12 seen_udp 100.64.0.2 "$MOVED"
ok "kill states ($INIT): the idle TCP connection's tracked state left with WAN1; the active UDP flow follows the route to WAN2"
want 200 PUT /api/routing/groups/FAILOVER "{$GRP,\"trigger\":\"down\",\"kill_states\":\"down_recovery\"}"
idle_start 100.64.0.2
N isp1 ip addr add 203.0.113.1/24 dev up0
BACK=$(date +%s.%N)
wait_for "default back on WAN1" 30 via_is 'via 203.0.113.1 dev rtr-wan'
wait_for "the fallback's idle connection state deleted" 12 no_idle_ct 100.64.0.2
wait_for "the UDP flow back on WAN1's address" 15 seen_udp 203.0.113.2 "$BACK"
ok "down_recovery ($INIT): WAN1 returned, the idle connection tracked on the fallback was deleted and the UDP flow left through WAN1 again"
kill $SND $IDLE 2>/dev/null || true; wait $SND $IDLE 2>/dev/null || true; SND=; IDLE=
want 200 GET /api/routing
has "$(cat /tmp/api.out)" '"killed":{' "the gateway status has no kill-states record"
has "$(N lan curl -sk -b /t/jar https://192.168.50.1/routing)" "connection(s) deleted" "Routing page lacks the kill-states action"
ok "the kill-states action shows in the gateway status and on the Routing page"

echo "=== 6. sticky connections"
want 200 PUT /api/routing/groups/FAILOVER '{"name":"FAILOVER","members":"WAN1:1:1, WAN2:1:1","trigger":"down","kill_states":"none","sticky_secs":300}'
T6=$(nft list table inet patronus_wan 2>&1) || fail "no sticky table: $T6"
has "$T6" "numgen random mod 2" "sticky rules lack the weighted pick"
seen=$(for _ in $(seq 1 30); do who; done | sort | uniq -c)
[ "$(wc -l <<<"$seen")" = 1 ] || fail "sticky: one client must keep one uplink: $seen"
W1=$(who)
if [ "$W1" = 203.0.113.2 ]; then BAD=isp1; BADADDR=203.0.113.1/24; BADWAN=WAN1; OTHER=100.64.0.2
else BAD=isp2; BADADDR=100.64.0.1/24; BADWAN=WAN2; OTHER=203.0.113.2; fi
N $BAD ip addr flush dev up0
wait_for "$BADWAN down" 30 gw_is $BADWAN down
wait_for "the client to move" 20 client_on "$OTHER"
N $BAD ip addr add $BADADDR dev up0
wait_for "$BADWAN online again" 30 gw_is $BADWAN online
sleep 2
seen=$(for _ in $(seq 1 20); do who; done | sort | uniq -c)
[ "$(wc -l <<<"$seen")" = 1 ] && grep -q "$OTHER" <<<"$seen" || fail "sticky: the client must stay on $OTHER: $seen"
ok "sticky ($INIT): one client keeps one uplink for 30 flows, moves when its uplink goes away and stays on the other when it returns"

echo "=== 7. reboot-equivalent apply keeps the setup; a second apply changes nothing"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply: $APPLY"; }
nft list table inet patronus_wan >/dev/null 2>&1 || fail "the sticky table is gone after patronus apply"
client_on "$OTHER" || fail "patronus apply moved the sticky client"
want 200 PUT /api/routing/groups/FAILOVER '{"name":"FAILOVER","members":"WAN1:1, WAN2:2","trigger":"down"}'
nft list table inet patronus_wan >/dev/null 2>&1 && fail "sticky off: the table should be gone"
patronus apply --phase routes >/t/apply.out 2>&1 || { cat /t/apply.out; fail "second apply"; }
patronus apply --phase routes >/t/apply2.out 2>&1 || { cat /t/apply2.out; fail "third apply"; }
grep -q 'routes up to date' /t/apply2.out || { cat /t/apply2.out; fail "an unchanged apply must report no change"; }
ok "apply ($INIT): the sticky table survives it, switching sticky off removes it, an unchanged apply is a no-op"
echo "multiwan-services-test ($INIT): all checks passed"
