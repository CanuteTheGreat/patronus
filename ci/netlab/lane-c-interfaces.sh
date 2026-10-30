#!/usr/bin/env bash
# Lane C (interfaces & L2) netlab test. Runs INSIDE the capped netlab
# container (ci/netlab/run.sh) as root with the shipped binaries in /t:
# `patronus` (patronus-cli) and `patronus-web`.
#
#   lan (192.168.50.10) ---- rtr-lan [        ] rtr-wan ---- wan  (dnsmasq DHCP, 203.0.113.1)
#                            rtr-trunk[  rtr  ] rtr-ppp ---- isp  (pppoe-server, 198.51.100.1)
#   sw: trunk0 (VLAN 100,    rtr-b1/b2[        ] rtr-p1 ---- h1   (10.40.0.11)
#       QinQ 200/20),        (bond)            rtr-p2 ---- h2   (10.40.0.12)
#       swbr <- sw-b1/sw-b2
#
# Everything on rtr except rtr-lan's address is configured through the web
# API (logged in from the LAN), then the box is "rebooted" (fresh
# namespaces, daemons killed) and `patronus apply` alone must rebuild it.
#
# Proves (kernel state + real traffic, not API answers):
#  - WAN in DHCP mode gets a lease from dnsmasq (udhcpc, and dhcpcd when the
#    distro has it), default route via the DHCP router, LAN->WAN NAT works
#  - 802.1Q VLAN subinterface carries tagged traffic (tcpdump sees the tag);
#    QinQ (802.1ad outer + 802.1Q inner) passes traffic
#  - active-backup bond fails over when the active slave's peer goes down
#  - bridge forwards between its ports and carries the router address
#  - static IPv4/IPv6, MTU and MAC reach the kernel
#  - PPPoE client gets an address from a pppoe-server netns
#  - anti-lockout: changes that would cut off the admin's session -> 409
#  - unprivileged patronus-web applies through the root `patronus applyd`
#  - a second apply is a no-op; everything survives a fresh-netns apply
#
# No pipefail on purpose: piping into grep -q would fail whenever grep exits
# early and cmd gets EPIPE.
set -eu

P=/t/patronus
WEB=/t/patronus-web
PASS='Netlab-Test-Passw0rd!'
C=/t/lanec
rm -rf "$C"; mkdir -p "$C"
export PATRONUS_NET_DIR=$C/net PATRONUS_RUN_DIR=$C/run PATRONUS_INIT=direct NO_COLOR=1 CLICOLOR=0
DB=$C/config.db
TOML=$C/patronus.toml
printf '[network]\nwan_interface = "rtr-wan"\nlan_interface = "rtr-lan"\n' > "$TOML"

fail() { echo "FAIL: $*" >&2; dump; exit 1; }
ok() { echo "ok - $*"; }
R() { ip netns exec rtr "$@"; }
L() { ip netns exec lan "$@"; }
dump() {
  echo "--- debug: processes"; ps -eo pid,ppid,stat,args 2>/dev/null | grep -v '\[' || true
  echo "--- debug: rtr links/addrs/routes"; R ip -d addr 2>/dev/null | head -120 || true
  R ip route 2>/dev/null || true; ls -la "$C/run" 2>/dev/null || true
  for f in "$C"/run/*.log /t/lanec-web.log /t/lanec-applyd.log "$C"/pppoe-server.log "$C"/pppd-server.log "$C"/dnsmasq.log; do
    [ -f "$f" ] && { echo "--- $f"; tail -40 "$f"; }
  done; true
}

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq dnsmasq-base busybox ppp pppoe tcpdump iputils-ping util-linux >/dev/null
apt-get install -y -qq dhcpcd-base >/dev/null 2>&1 || apt-get install -y -qq dhcpcd5 >/dev/null 2>&1 || true
HAVE_DHCPCD=$(command -v dhcpcd >/dev/null && echo 1 || echo 0)
echo "dhcpcd available: $HAVE_DHCPCD; pppd $(pppd --version 2>&1 | head -1)"

NS="rtr lan wan sw isp h1 h2"
killall_daemons() {
  pkill -f 'udhcpc|dhcpcd|pppd|pppoe-server|dnsmasq|patronus-web|applyd --socket' 2>/dev/null || true
  sleep 0.5
}
topology_down() { killall_daemons; for n in $NS; do ip netns del "$n" 2>/dev/null || true; done; }
topology_up() {
  topology_down
  for n in $NS; do ip netns add "$n"; ip -n "$n" link set lo up; done
  ip link add rtr-lan netns rtr type veth peer name lan0 netns lan
  ip link add rtr-wan netns rtr type veth peer name wan0 netns wan
  ip link add rtr-trunk netns rtr type veth peer name trunk0 netns sw
  ip link add rtr-b1 netns rtr type veth peer name sw-b1 netns sw
  ip link add rtr-b2 netns rtr type veth peer name sw-b2 netns sw
  ip link add rtr-ppp netns rtr type veth peer name wanp0 netns isp
  ip link add rtr-p1 netns rtr type veth peer name eth0 netns h1
  ip link add rtr-p2 netns rtr type veth peer name eth0 netns h2
  # the console-configured management LAN (what the installer leaves)
  R ip addr add 192.168.50.1/24 dev rtr-lan; R ip link set rtr-lan up
  ip -n lan addr add 192.168.50.10/24 dev lan0; ip -n lan link set lan0 up
  ip -n lan route add default via 192.168.50.1
  # WAN side: DHCP server
  ip -n wan addr add 203.0.113.1/24 dev wan0; ip -n wan link set wan0 up
  ip netns exec wan dnsmasq --no-daemon --user=root --group=root --port=0 --interface=wan0 --bind-interfaces \
    --dhcp-range=203.0.113.100,203.0.113.150,255.255.255.0,2m --dhcp-option=3,203.0.113.1 \
    --dhcp-option=6,203.0.113.53 --dhcp-leasefile=$C/dnsmasq.leases --log-dhcp >$C/dnsmasq.log 2>&1 &
  # switch side: VLAN 100, QinQ 200/20, and a bridge for the bond
  ip -n sw link set trunk0 up
  ip -n sw link add link trunk0 name trunk0.100 type vlan id 100
  ip -n sw addr add 10.100.0.2/24 dev trunk0.100; ip -n sw link set trunk0.100 up
  ip -n sw link add link trunk0 name s200 type vlan id 200 protocol 802.1ad
  ip -n sw link add link s200 name c20 type vlan id 20
  ip -n sw addr add 10.220.0.2/24 dev c20; ip -n sw link set s200 up; ip -n sw link set c20 up
  ip -n sw link add swbr type bridge; ip -n sw link set sw-b1 master swbr; ip -n sw link set sw-b2 master swbr
  ip -n sw link set sw-b1 up; ip -n sw link set sw-b2 up; ip -n sw link set swbr up
  ip -n sw addr add 10.30.0.2/24 dev swbr
  for h in h1 h2; do ip -n $h link set eth0 up; done
  ip -n h1 addr add 10.40.0.11/24 dev eth0; ip -n h2 addr add 10.40.0.12/24 dev eth0
  # ISP side: PPPoE access concentrator
  ip -n isp link set wanp0 up
  printf 'require-pap\nlcp-echo-interval 10\nlcp-echo-failure 3\nms-dns 198.51.100.53\ndebug\nlogfile %s/pppd-server.log\n' "$C" > /etc/ppp/pppoe-server-options
  printf '"patronus-test" * "ppp-s3cret" *\n' > /etc/ppp/pap-secrets; chmod 600 /etc/ppp/pap-secrets
  # -k: kernel-mode PPPoE (the user-space relay needs the ppp_async line
  # discipline, which a container may not autoload)
  ip netns exec isp pppoe-server -k -F -I wanp0 -L 198.51.100.1 -R 198.51.100.10 -N 4 >$C/pppoe-server.log 2>&1 &
  R sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
  sleep 0.5
}

WEB_PID=
stop_web() { [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null; wait "$WEB_PID" 2>/dev/null || true; WEB_PID=; }
start_web() { # [unprivileged]
  local pre=()
  if [ "${1:-}" = unprivileged ]; then
    pre=(setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=+net_admin,+net_raw --ambient-caps=+net_admin,+net_raw)
  fi
  env PATRONUS_DB=$DB PATRONUS_BOOTSTRAP=$TOML PATRONUS_ADMIN_PASSWORD="$PASS" \
     PATRONUS_ADMIN_PASSWORD_FILE=$C/web/pw PATRONUS_TLS_DIR=$C/web/tls RUST_LOG=info \
     PATRONUS_APPLYD_SOCKET=$C/applyd.sock \
     ip netns exec rtr "${pre[@]}" "$WEB" >>/t/lanec-web.log 2>&1 &
  WEB_PID=$!
  for i in $(seq 1 60); do
    L curl -sk -o /dev/null https://192.168.50.1:8443/login && break; sleep 0.5
    [ "$i" = 60 ] && fail "patronus-web did not come up"
  done
  code=$(api POST /auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"); [ "$code" = 200 ] || fail "login $code"
}
api() { # method path [json]
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  L curl -sk -b $C/jar -c $C/jar -o $C/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.1:8443/api$2"
}
must() { # expected-code method path [json]
  local want=$1; shift
  local code; code=$(api "$@")
  [ "$code" = "$want" ] || fail "$1 $2 -> $code (want $want): $(cat $C/api.out)"
}
wait_for() { # description seconds command...
  local d=$1 s=$2; shift 2
  for i in $(seq 1 $((s * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out: $d"
}
has_addr() { R ip -o addr show dev "$1" | grep "inet6\? $2" >/dev/null; }
ping_ok() { ip netns exec "$1" ping -c 2 -W 2 -i 0.3 "$2" >/dev/null || fail "ping $1 -> $2"; }

topology_up
echo "=== 1. boot with only patronus.toml: nothing but roles, nothing touched"
OUT=$(R "$P" --db $DB apply --bootstrap "$TOML" 2>&1); echo "$OUT"
grep -q 'interfaces.*nothing to apply' <<<"$OUT" || fail "fresh box: interfaces applier changed something"
has_addr rtr-lan 192.168.50.1/24 || fail "console LAN address was touched"
ok "role-only interfaces are left exactly as the OS configured them"

echo "=== 2. configure everything through the web API (as root)"
mkdir -p $C/web; start_web
must 200 GET /interfaces
python3 - "$C/api.out" <<'EOF' || fail "overview JSON"
import json, sys
d = json.load(open(sys.argv[1]))
names = {x["name"] for x in d["devices"]}
assert {"rtr-lan", "rtr-wan", "rtr-trunk", "rtr-b1"} <= names, names
assert d["client_interface"]["interface"] == "rtr-lan", d["client_interface"]
assert d["mgmt"] == ["rtr-lan"], d["mgmt"]
assert d["vlans"] == [] and d["bonds"] == [] and d["bridges"] == [] and d["pppoe"] == []
assert d["features"]["vlan"] and d["features"]["pppoe"]
EOF
ok "overview: kernel devices, admin connected via rtr-lan, honest empty VLAN/bond/bridge/PPPoE lists"

# LAN: keep the admin's address, add IPv6
must 200 PUT /interfaces/rtr-lan '{"role":"lan","ipv4_mode":"static","ipv4":["192.168.50.1/24"],"ipv6_mode":"static","ipv6":["fd00:50::1/64"]}'
# WAN: DHCP client (udhcpc first)
must 200 PUT /interfaces/dhcp-client '{"client":"udhcpc"}'
must 200 PUT /interfaces/rtr-wan '{"role":"wan","ipv4_mode":"dhcp"}'
# trunk: MTU + MAC, no address; VLAN 100 + QinQ 200/20
must 200 PUT /interfaces/rtr-trunk '{"ipv4_mode":"none","mtu":1600,"mac":"02:00:00:00:c0:01"}'
must 200 POST /interfaces/vlans '{"parent":"rtr-trunk","vlan_id":100}'
must 200 PUT /interfaces/rtr-trunk.100 '{"role":"opt1","ipv4_mode":"static","ipv4":["10.100.0.1/24"],"ipv6_mode":"static","ipv6":["fd00:100::1/64"]}'
must 200 POST /interfaces/vlans '{"parent":"rtr-trunk","vlan_id":200,"protocol":"802.1ad","name":"svlan200"}'
must 200 POST /interfaces/vlans '{"parent":"svlan200","vlan_id":20,"name":"qinq20"}'
must 200 PUT /interfaces/qinq20 '{"role":"opt5","ipv4_mode":"static","ipv4":["10.220.0.1/24"]}'
# bond (active-backup) + bridge
must 200 POST /interfaces/bonds '{"name":"bond0","mode":"active-backup","members":["rtr-b1","rtr-b2"],"primary":"rtr-b1","miimon":100}'
must 200 PUT /interfaces/bond0 '{"role":"opt2","ipv4_mode":"static","ipv4":["10.30.0.1/24"]}'
must 200 POST /interfaces/bridges '{"name":"br0","members":["rtr-p1","rtr-p2"],"stp":false}'
must 200 PUT /interfaces/br0 '{"role":"opt3","ipv4_mode":"static","ipv4":["10.40.0.1/24"]}'
# PPPoE
must 200 POST /interfaces/pppoe '{"name":"pppoe0","parent":"rtr-ppp","username":"patronus-test","password":"ppp-s3cret","default_route":false,"use_peer_dns":false}'
ok "API accepted LAN static v4+v6, WAN DHCP, VLAN, QinQ, bond, bridge, PPPoE, MTU/MAC"

echo "--- validation and anti-lockout"
must 400 POST /interfaces/vlans '{"parent":"rtr-trunk","vlan_id":5000}'
must 400 POST /interfaces/bonds '{"name":"bond1","members":["nope0"]}'
must 400 PUT /interfaces/rtr-trunk.100 '{"ipv4_mode":"static","ipv4":["10.100.0.1"]}'
must 400 DELETE /interfaces/vlans/rtr-trunk.100
must 409 PUT /interfaces/rtr-lan '{"role":"opt9","ipv4_mode":"static","ipv4":["192.168.50.1/24"]}'
grep -q 'anti-lockout' $C/api.out || fail "409 without the reason: $(cat $C/api.out)"
must 409 PUT /interfaces/rtr-lan '{"role":"lan","ipv4_mode":"static","ipv4":["192.168.50.2/24"]}'
must 409 POST /interfaces/rtr-lan/down '{}'
must 400 POST /interfaces/bridges '{"name":"br1","members":["rtr-lan"]}'
has_addr rtr-lan 192.168.50.1/24 || fail "refused change still touched rtr-lan"
R nft list ruleset | grep 'iifname "rtr-lan" tcp dport { 22, 8443 } accept' >/dev/null || fail "anti-lockout rule moved"
ok "invalid input -> 400 (incl. enslaving the LAN); role move / address change / disable of the admin's interface -> 409, kernel untouched"

assert_kernel() { # $1 = label
  local lbl=$1
  # static v4/v6 on LAN
  has_addr rtr-lan 192.168.50.1/24 && has_addr rtr-lan fd00:50::1/64 || fail "$lbl: LAN static v4/v6"
  # MTU / MAC
  local tj; tj=$(R ip -j link show rtr-trunk)
  python3 -c 'import json,sys; l=json.loads(sys.argv[1])[0]; assert l["mtu"]==1600 and l["address"]=="02:00:00:00:c0:01", l' "$tj" || fail "$lbl: MTU/MAC"
  ok "$lbl: static IPv4+IPv6 on rtr-lan, MTU 1600 + MAC 02:00:00:00:c0:01 on rtr-trunk"
  # DHCP WAN
  wait_for "$lbl: DHCP lease on rtr-wan" 30 sh -c "ip netns exec rtr ip -4 -o addr show dev rtr-wan | grep 'inet 203.0.113.1[0-5][0-9]/24.*dynamic' >/dev/null"
  R ip -4 route show default | grep 'default via 203.0.113.1 dev rtr-wan proto dhcp' >/dev/null || { R ip route; fail "$lbl: no DHCP default route"; }
  ok "$lbl: rtr-wan leased $(R ip -4 -o addr show dev rtr-wan | awk '{print $4}') from dnsmasq, default via 203.0.113.1"
  L ping -c 2 -W 2 203.0.113.1 >/dev/null || fail "$lbl: LAN -> WAN through NAT"
  ok "$lbl: LAN host reaches the WAN through the DHCP-addressed uplink"
  # VLAN with the tag on the wire
  R ip -d link show rtr-trunk.100 | grep 'vlan protocol 802.1Q id 100' >/dev/null || fail "$lbl: VLAN device"
  ip netns exec sw timeout 8 tcpdump -nn -e -c 2 -i trunk0 'vlan 100 and icmp' >$C/tcpdump.out 2>&1 &
  local td=$!; sleep 1
  ping_ok sw 10.100.0.1
  wait $td || true
  grep -q 'vlan 100' $C/tcpdump.out || { cat $C/tcpdump.out; fail "$lbl: no 802.1Q tag 100 on the wire"; }
  has_addr rtr-trunk.100 fd00:100::1/64 || fail "$lbl: VLAN IPv6"
  ok "$lbl: VLAN 100 carries tagged traffic (tcpdump on the trunk: $(grep -m1 -o 'vlan 100, p 0' $C/tcpdump.out || echo 'vlan 100'))"
  R ip -d link show svlan200 | grep 'vlan protocol 802.1ad id 200' >/dev/null || fail "$lbl: 802.1ad S-VLAN"
  ping_ok sw 10.220.0.1
  ok "$lbl: QinQ 802.1ad 200 / 802.1Q 20 passes traffic"
  # bond + failover
  grep -q 'Bonding Mode: fault-tolerance (active-backup)' <(R cat /proc/net/bonding/bond0) || fail "$lbl: bond mode"
  wait_for "$lbl: bond0 active slave rtr-b1" 10 sh -c "ip netns exec rtr grep -q 'Currently Active Slave: rtr-b1' /proc/net/bonding/bond0"
  ping_ok sw 10.30.0.1
  ip -n sw link set sw-b1 down
  wait_for "$lbl: bond fails over to rtr-b2" 10 sh -c "ip netns exec rtr grep -q 'Currently Active Slave: rtr-b2' /proc/net/bonding/bond0"
  ping_ok sw 10.30.0.1
  ip -n sw link set sw-b1 up
  ok "$lbl: active-backup bond failed over to rtr-b2 when rtr-b1's peer went down; traffic kept flowing"
  # bridge
  R ip -d link show rtr-p1 | grep 'master br0' >/dev/null || fail "$lbl: rtr-p1 not in br0"
  ping_ok h1 10.40.0.12
  ping_ok h1 10.40.0.1
  ok "$lbl: br0 bridges h1 <-> h2 and answers on 10.40.0.1"
  # PPPoE
  if [ -c /dev/ppp ]; then
    wait_for "$lbl: pppoe0 up with an address from the access concentrator" 40 sh -c "ip netns exec rtr ip -4 -o addr show dev pppoe0 | grep 'peer 198.51.100.1' >/dev/null"
    R ping -c 2 -W 2 198.51.100.1 >/dev/null || fail "$lbl: ping over PPPoE"
    ok "$lbl: PPPoE: $(R ip -4 -o addr show dev pppoe0 | awk '{print $4, $5, $6}') via pppoe-server in the isp netns"
  else
    fail "$lbl: /dev/ppp is not available in the netlab container (run.sh passes --device /dev/ppp)"
  fi
}
assert_kernel "web API"

echo "--- idempotency"
OUT=$(R "$P" --db $DB apply --phase interfaces 2>&1); echo "$OUT"
grep -q 'interfaces.*nothing to apply' <<<"$OUT" || fail "second apply was not a no-op"
ok "a second 'patronus apply' changes nothing"
DRY=$(R "$P" --db $DB apply --dry-run --phase interfaces 2>&1)
grep -q 'interfaces already match the store' <<<"$DRY" || { echo "$DRY"; fail "dry-run"; }
ok "dry-run reports the kernel matches the store"

if [ "$HAVE_DHCPCD" = 1 ]; then
  echo "--- switch the DHCP client to dhcpcd"
  must 200 PUT /interfaces/dhcp-client '{"client":"dhcpcd"}'
  wait_for "dhcpcd runs for rtr-wan" 10 pgrep -x dhcpcd
  pgrep -f 'udhcpc -f -i rtr-wan' >/dev/null && fail "udhcpc still running after the switch"
  wait_for "dhcpcd lease on rtr-wan" 40 sh -c "ip netns exec rtr ip -4 -o addr show dev rtr-wan | grep 'inet 203.0.113.1[0-5][0-9]/24' >/dev/null"
  ok "dhcpcd took over rtr-wan and holds $(R ip -4 -o addr show dev rtr-wan | awk '{print $4}')"
  must 200 PUT /interfaces/dhcp-client '{"client":"udhcpc"}'
fi

echo "=== 3. unprivileged patronus-web + root apply broker"
stop_web
chmod 777 $C $C/web; chmod 666 $DB*; chmod -R a+rwX $C/web $C/net $C/run 2>/dev/null || true
env PATRONUS_DB=$DB RUST_LOG=info ip netns exec rtr "$P" --db $DB applyd --socket $C/applyd.sock --group nogroup >/t/lanec-applyd.log 2>&1 &
wait_for "applyd socket" 10 test -S $C/applyd.sock
start_web unprivileged
must 200 GET /interfaces
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert {v["name"] for v in d["vlans"]} == {"rtr-trunk.100","svlan200","qinq20"}, d["vlans"]; assert d["pppoe"][0]["password"] == "", "password leaked"' $C/api.out \
  || fail "config not listed after restart (or PPPoE password exposed)"
ok "after a patronus-web restart the API lists the stored VLANs/bonds/bridges/PPPoE (password redacted)"
must 200 POST /interfaces/vlans '{"parent":"rtr-trunk","vlan_id":300,"description":"via broker"}'
R ip -d link show rtr-trunk.300 | grep 'id 300' >/dev/null || fail "VLAN 300 not created through the broker"
grep -q 'through the root broker' /t/lanec-web.log || fail "web did not use the broker"
grep -q 'applyd: applying interfaces' /t/lanec-applyd.log || fail "broker log"
must 200 DELETE /interfaces/vlans/rtr-trunk.300
R ip link show rtr-trunk.300 >/dev/null 2>&1 && fail "deleted VLAN still in the kernel"
ok "web running as nobody (CAP_NET_ADMIN only) created and deleted VLAN 300 through 'patronus applyd' (root)"
stop_web

echo "=== 4. reboot: fresh namespaces, only 'patronus apply'"
topology_up
OUT=$(R "$P" --db $DB apply --bootstrap "$TOML" 2>&1); echo "$OUT"
grep -q 'interfaces ' <<<"$OUT" && ! grep -q '✗' <<<"$OUT" || fail "boot apply: a phase failed"
R ip -d link show bond0 | grep 'bond mode active-backup' >/dev/null || fail "bond not rebuilt"
assert_kernel "after reboot"
R nft list ruleset | grep 'iifname "rtr-lan" tcp dport { 22, 8443 } accept' >/dev/null || fail "anti-lockout after reboot"
R nft list ruleset | grep 'oifname "rtr-wan" masquerade' >/dev/null || fail "WAN masquerade after reboot"
ok "boot apply rebuilt VLAN/QinQ/bond/bridge/PPPoE/DHCP/static config and the role-based firewall"

echo "=== 5. un-assign + delete removes devices; stale daemons stop"
start_web
must 200 PUT /interfaces/br0 '{}'
must 200 DELETE /interfaces/bridges/br0
R ip link show br0 >/dev/null 2>&1 && fail "br0 still exists"
R ip -d link show rtr-p1 | grep master >/dev/null && fail "rtr-p1 still enslaved"
must 200 DELETE /interfaces/pppoe/pppoe0
# [p]/[u]: the pattern must not match this 'sh -c' wrapper's own cmdline
wait_for "pppd stopped" 10 sh -c "! pgrep -f '[p]ppd file $C/net/ppp/pppoe0.options'"
must 200 PUT /interfaces/rtr-wan '{"role":"wan","ipv4_mode":"none"}'
wait_for "udhcpc stopped" 10 sh -c '! pgrep -f "[u]dhcpc -f -i rtr-wan"'
R ip -4 -o addr show dev rtr-wan | grep inet >/dev/null && fail "rtr-wan kept an IPv4 address in mode none"
ok "deleting br0/pppoe0 removed them from the kernel; WAN mode none stopped the DHCP client and cleared the lease"
stop_web
topology_down
echo "ALL LANE C NETLAB CHECKS PASSED"
