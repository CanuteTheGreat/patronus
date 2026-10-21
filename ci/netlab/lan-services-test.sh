#!/usr/bin/env bash
# Lane D (LAN services) netlab test. Runs INSIDE the capped Gentoo container
# started by ci/netlab/lan-services.sh, as root, with the shipped binaries
# and init files in /t. $1 = openrc | systemd (which init system drives the
# daemons: rc-service or systemctl, both through patronus_core::ServiceManager).
#
# The container's netns is the router:
#
#   c1, c2, adm --- [br rtr-lan 192.168.50.1/24, fd00:50::1/64]
#   c3          --- [br rtr-opt1 192.168.60.1/24]
#   dhcpsrv 10.70.0.2 --- rtr-srv 10.70.0.1      (remote DHCP server for the relay)
#                         rtr-wan 203.0.113.2/24 (dummy; DDNS publishes it)
#
# Everything is configured through the web API (the same calls the UI
# forms make) of a patronus-web running as the unprivileged `patronus`
# user, which applies through `patronus applyd` (root). Proves, from client
# namespaces: DHCPv4 lease from the range and the static mapping (Kea, then
# dnsmasq), lease table in the API and the page, DHCPv6 address, RA seen by
# rdisc6 (radvd, then dnsmasq), Unbound host override / domain override /
# DNSBL (manual + list URL), dnsmasq forwarder mode, NTP served by chrony,
# DDNS update request, DHCP relay to a remote server, and a reboot
# (daemons stopped, configs deleted, `patronus apply` restores everything).
set -euo pipefail
INIT=${1:?openrc|systemd}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }
N() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

svc() { # svc start|stop|restart|status NAME
  if [ "$INIT" = openrc ]; then rc-service "$2" "$1"; else systemctl "$1" "$2"; fi
}
running() {
  if [ "$INIT" = openrc ]; then rc-service "$1" status >/dev/null 2>&1
  else systemctl is-active --quiet "$1"; fi
}
expect_running() { for s in "$@"; do running "$s" || fail "$s is not running ($INIT)"; done; ok "running under $INIT: $*"; }
expect_stopped() { for s in "$@"; do if running "$s"; then fail "$s still running"; fi; done; ok "stopped: $*"; }
has() { grep -qF -- "$2" "$1" || { echo "--- $1"; cat "$1" 2>/dev/null || true; fail "$1 lacks: $2"; }; }

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
if [ "$INIT" = openrc ]; then
  # an OpenRC container: no kernel/boot services, `net` provided by docker
  sed -i 's/^#\?rc_sys=.*/rc_sys="docker"/' /etc/rc.conf
  printf 'rc_provide="loopback net"\nrc_depend_strict="NO"\n' >> /etc/rc.conf
  mkdir -p /run/openrc && touch /run/openrc/softlevel
  for s in applyd web firewall; do install -m755 "/t/patronus-$s.initd" "/etc/init.d/patronus-$s"; done
  # the container may not set the clock (no CAP_SYS_TIME): serve, don't steer
  echo 'ARGS="-x"' >> /etc/conf.d/chronyd
else
  for s in applyd web firewall; do install -m644 "/t/patronus-$s.service" /etc/systemd/system/; done
  mkdir -p /etc/systemd/system/chronyd.service.d
  # the container has no CAP_SYS_TIME: lift the unit's condition and serve
  # time without steering the clock (-x), as in the OpenRC path
  printf '[Unit]\nConditionCapability=\n[Service]\nType=simple\nPIDFile=\nExecStart=\nExecStart=/usr/sbin/chronyd -n -x -f /etc/chrony/chrony.conf\n' \
    > /etc/systemd/system/chronyd.service.d/netlab.conf
  systemctl daemon-reload
fi
command -v kea-dhcp4 dnsmasq radvd unbound chronyd >/dev/null

echo "=== 1. topology"
ip link add rtr-lan type bridge
sysctl -qw net.ipv6.conf.rtr-lan.accept_dad=0
ip link set rtr-lan up
ip addr add 192.168.50.1/24 dev rtr-lan
ip -6 addr add fd00:50::1/64 dev rtr-lan nodad
ip link add rtr-opt1 type bridge
ip link set rtr-opt1 up
ip addr add 192.168.60.1/24 dev rtr-opt1
ip link add rtr-wan type dummy
ip link set rtr-wan up
ip addr add 203.0.113.2/24 dev rtr-wan
client() { # ns bridge [mac]
  ip netns add "$1"
  ip link add "$1-eth" type veth peer name "$1-br"
  ip link set "$1-eth" netns "$1"
  [ -n "${3:-}" ] && ip -n "$1" link set "$1-eth" address "$3"
  ip link set "$1-br" master "$2" up
  ip -n "$1" link set lo up
  N "$1" sysctl -qw "net.ipv6.conf.$1-eth.accept_ra=1"
  ip -n "$1" link set "$1-eth" up
}
client c1 rtr-lan
client c2 rtr-lan aa:bb:cc:00:00:02
client adm rtr-lan
client c3 rtr-opt1
ip -n adm addr add 192.168.50.5/24 dev adm-eth
ip netns add dhcpsrv
ip link add rtr-srv type veth peer name srv0
ip link set srv0 netns dhcpsrv
ip addr add 10.70.0.1/24 dev rtr-srv
ip link set rtr-srv up
ip -n dhcpsrv addr add 10.70.0.2/24 dev srv0
ip -n dhcpsrv link set srv0 up
ip -n dhcpsrv link set lo up
ip -n dhcpsrv route add default via 10.70.0.1
C1MAC=$(ip -n c1 -br link show c1-eth | awk '{print $3}')
sleep 1
ok "router bridges rtr-lan/rtr-opt1, clients c1 ($C1MAC) c2 (aa:bb:cc:00:00:02) adm c3, relay target dhcpsrv"

# helpers for the services the test itself needs
# a DNS server for the domain override (corp.test), on the router's loopback
dnsmasq --conf-file=/dev/null --port=5353 --listen-address=127.0.0.2 --bind-interfaces \
  --no-resolv --address=/corp.test/10.9.9.9 --pid-file=/run/corpdns.pid --user=root
# the remote DHCP server the relay forwards to
N dhcpsrv dnsmasq --conf-file=/dev/null --port=0 --interface=srv0 --dhcp-authoritative \
  --dhcp-range=192.168.60.100,192.168.60.150,255.255.255.0,600 \
  --dhcp-leasefile=/run/dhcpsrv.leases --pid-file=/run/dhcpsrv.pid --user=root
# the DDNS provider: records every request path
cat > /t/ddns.py <<'EOF'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open("/t/ddns.log", "a").write(self.path + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"good\n")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()
EOF
python3 /t/ddns.py & DDNS_PID=$!
cat > /t/blocklist.txt <<'EOF'
# hosts-format block list served as file://
0.0.0.0 tracker.test
malware.test
EOF

echo "=== 2. boot: patronus apply on a fresh box"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply"; }
echo "$APPLY" | tail -12
# DNS defaults to the resolver because Unbound is installed (USE=unbound)
has /etc/unbound/unbound.conf "Managed by Patronus"
has /etc/unbound/unbound.conf "interface: 192.168.50.1"
expect_running unbound
if grep -q "interface: 203.0.113.2" /etc/unbound/unbound.conf; then fail "unbound serves the WAN"; fi
ok "fresh box: Unbound resolver on the LAN only"

echo "=== 3. patronus-applyd + patronus-web through $INIT (web as user patronus)"
svc start patronus-applyd
svc start patronus-web
for i in $(seq 1 60); do
  N adm curl -sk -o /dev/null https://192.168.50.1:8443/login && break; sleep 0.5
done
N adm curl -sk -o /dev/null https://192.168.50.1:8443/login || fail "web UI not reachable from the LAN"
WEBUSER=$(ps -o user= -C patronus-web | head -1)
[ "$WEBUSER" = patronus ] || fail "patronus-web runs as $WEBUSER, expected patronus"
[ -S /run/patronus/applyd.sock ] || fail "no applyd socket"
[ "$(stat -c '%U:%G %a' /run/patronus/applyd.sock)" = "root:patronus 660" ] || fail "applyd socket perms $(stat -c '%U:%G %a' /run/patronus/applyd.sock)"
ok "web UI up as user patronus; applyd socket root:patronus 0660"
PASS=$(tr -d '\n' < /var/lib/patronus/initial-admin-password)
api() { # method path [json] -> prints code, body in /tmp/api.out
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  N adm curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.1:8443$2"
}
want() { # code method path [json]
  local w=$1; shift
  local code; code=$(api "$@")
  [ "$code" = "$w" ] || fail "$1 $2 -> $code (want $w): $(cat /tmp/api.out)"
}
want 200 POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"

echo "=== 4. configure everything through the API (what the UI forms send)"
want 201 POST /api/dhcp/pools '{"interface":"@lan","range_start":"192.168.50.100","range_end":"192.168.50.150","lease_time":600,"domain":"lan.test"}'
POOL=$(python3 -c 'import json;print(json.load(open("/tmp/api.out"))["id"])')
want 201 POST "/api/dhcp/pools/$POOL/static" '{"mac":"AA:BB:CC:00:00:02","ip":"192.168.50.20","hostname":"printer"}'
want 201 POST /api/dhcp/v6 '{"interface":"@lan","range_start":"fd00:50::100","range_end":"fd00:50::1ff","lease_time":600}'
want 201 POST /api/dhcp/ra '{"interface":"@lan","mode":"managed","min_interval":3,"max_interval":10}'
want 201 POST /api/dns/hosts '{"hostname":"nas","domain":"home.test","address":"192.168.50.5"}'
want 201 POST /api/dns/domains '{"domain":"corp.test","server":"127.0.0.2@5353"}'
want 201 POST /api/dns/blocklist '{"domain":"ads.test"}'
want 200 PUT /api/dns/settings '{"blocklist_urls":"file:///t/blocklist.txt","dnssec":false}'
want 200 PUT /api/ntp '{"enabled":true,"servers":"192.0.2.123"}'
want 201 POST /api/ddns '{"provider":"custom","hostname":"home.test","server":"http://127.0.0.1:8099/update?host=%h&ip=%i"}'
# injection attempts never reach a daemon config
want 400 POST /api/dhcp/pools/$POOL/static '{"mac":"aa:bb:cc:00:00:09","ip":"192.168.50.30","hostname":"x\nsubnet4"}'
want 400 POST /api/dns/hosts '{"hostname":"evil","domain":"x.test\"\nlocal-zone: \".\" always_nxdomain","address":"1.2.3.4"}'
want 400 POST /api/dhcp/pools '{"interface":"@lan","range_start":"192.168.50.200","range_end":"192.168.50.100"}'
ok "API: pool, static mapping, DHCPv6, RA, overrides, DNSBL, NTP, DDNS created; bad input -> 400"

echo "=== 5. DHCPv4 + DHCPv6 + RA with Kea and radvd (auto backend: Kea is installed)"
has /etc/kea/kea-dhcp4.conf "Managed by Patronus"
has /etc/kea/kea-dhcp4.conf '"pool": "192.168.50.100 - 192.168.50.150"'
has /etc/kea/kea-dhcp4.conf '"hw-address": "aa:bb:cc:00:00:02"'
has /etc/kea/kea-dhcp4.conf '"ntp-servers"'
[ "$(stat -c %U:%G /etc/kea/kea-dhcp4.conf)" = root:dhcp ] || fail "kea-dhcp4.conf owner $(stat -c %U:%G /etc/kea/kea-dhcp4.conf)"
has /etc/kea/kea-dhcp6.conf '"pool": "fd00:50::100 - fd00:50::1ff"'
has /etc/radvd.conf "AdvManagedFlag on;"
expect_running kea-dhcp4 kea-dhcp6 radvd
expect_stopped dnsmasq

lease4() { # ns -> address from the DHCPv4 server
  local ns=$1
  ip -n "$ns" -4 addr flush dev "$ns-eth"
  N "$ns" dhcpcd -4 -1 -p -t 40 --nohook resolv.conf "$ns-eth" >"/t/dhcpcd-$ns.log" 2>&1 \
    || { cat "/t/dhcpcd-$ns.log"; fail "$ns: no DHCPv4 lease"; }
  ip -n "$ns" -4 -o addr show dev "$ns-eth" | awk '{print $4}' | cut -d/ -f1 | head -1
}
in_range() { python3 -c "import ipaddress,sys;a=ipaddress.ip_address('$1');sys.exit(0 if ipaddress.ip_address('$2')<=a<=ipaddress.ip_address('$3') else 1)"; }
check_v4() { # label
  local a1 a2
  a1=$(lease4 c1); in_range "$a1" 192.168.50.100 192.168.50.150 || fail "c1 got $a1, outside the pool"
  ok "$1: c1 got $a1 from the configured range"
  a2=$(lease4 c2); [ "$a2" = 192.168.50.20 ] || fail "c2 got $a2, not its static mapping 192.168.50.20"
  ok "$1: c2 got its static mapping 192.168.50.20"
  C1ADDR=$a1
}
check_v6() { # label
  local out a
  out=$(N c1 rdisc6 -1 c1-eth 2>&1) || { echo "$out"; fail "rdisc6 saw no RA"; }
  grep -qE 'Stateful address conf\.\s*:\s*Yes' <<<"$out" || { echo "$out"; fail "RA without the managed (M) flag"; }
  grep -q 'fd00:50::/64' <<<"$out" || { echo "$out"; fail "RA without prefix fd00:50::/64"; }
  ok "$1: rdisc6 sees the RA (M flag, prefix fd00:50::/64)"
  ip -n c1 -6 addr flush dev c1-eth scope global
  N c1 dhcpcd -6 -1 -p -t 60 --nohook resolv.conf c1-eth >/t/dhcpcd6.log 2>&1 \
    || { cat /t/dhcpcd6.log; fail "c1: no DHCPv6 lease"; }
  a=$(ip -n c1 -6 -o addr show dev c1-eth scope global | awk '{print $4}' | cut -d/ -f1 | grep '^fd00:50::' | head -1)
  [ -n "$a" ] && in_range "$a" fd00:50::100 fd00:50::1ff || { ip -n c1 -6 addr; fail "c1: DHCPv6 address $a not from the pool"; }
  ok "$1: c1 got DHCPv6 address $a"
}
check_v4 "Kea"
check_v6 "Kea + radvd"
want 200 GET /api/dhcp/leases
grep -qi "$C1MAC" /tmp/api.out && grep -q '192.168.50.20' /tmp/api.out \
  || fail "lease API lacks c1/c2: $(cat /tmp/api.out)"
want 200 GET /dhcp
grep -qi "$C1MAC" /tmp/api.out && grep -q "$C1ADDR" /tmp/api.out \
  || fail "/dhcp page lacks the lease of c1"
ok "lease table (API and page) shows the real leases from Kea"

echo "=== 6. DNS (Unbound): overrides, domain override, DNSBL"
check_dns() { # label
  local r
  r=$(N c1 dig +short +time=3 @192.168.50.1 nas.home.test A)
  [ "$r" = 192.168.50.5 ] || fail "$1: nas.home.test -> '$r'"
  r=$(N c1 dig +short +time=3 @192.168.50.1 corp.test A)
  [ "$r" = 10.9.9.9 ] || fail "$1: corp.test (domain override) -> '$r'"
  for d in ads.test tracker.test malware.test; do
    r=$(N c1 dig +time=3 @192.168.50.1 "$d" A)
    grep -q 'status: NXDOMAIN' <<<"$r" || { echo "$r"; fail "$1: $d not blocked"; }
  done
  ok "$1: dig @router: host override, domain override resolve; ads/tracker/malware.test NXDOMAIN"
}
check_dns "Unbound"
has /etc/unbound/unbound.conf 'local-zone: "tracker.test." always_nxdomain'

echo "=== 7. NTP served to the LAN"
has /etc/chrony/chrony.conf "allow 192.168.50.0/24"
expect_running chronyd
NTP=$(N c1 timeout 40 chronyd -Q -t 30 -f /dev/null 'pidfile /run/chrony-c1.pid' 'server 192.168.50.1 iburst maxsamples 2' 2>&1) \
  || { echo "$NTP"; fail "no NTP answer from the router"; }
grep -qi 'offset\|wrong by' <<<"$NTP" || { echo "$NTP"; fail "chronyd -Q output"; }
ok "c1 got time from the router's NTP server ($(grep -io 'system clock wrong by.*' <<<"$NTP" | head -1))"

echo "=== 8. dynamic DNS"
grep -q 'host=home.test&ip=203.0.113.2' /t/ddns.log || fail "DDNS endpoint saw: $(cat /t/ddns.log 2>/dev/null)"
want 200 GET /dns
grep -q '203.0.113.2' /tmp/api.out || fail "/dns page lacks the published address"
ok "DDNS published the WAN address 203.0.113.2; page shows it"

echo "=== 9. dnsmasq backend: DHCPv4/v6 + RA + relay from one daemon"
want 200 PUT /api/dhcp/settings '{"backend":"dnsmasq","ra_backend":"dnsmasq"}'
has /etc/dnsmasq.conf "Managed by Patronus"
has /etc/dnsmasq.conf "dhcp-range=set:p$POOL,192.168.50.100,192.168.50.150,255.255.255.0,600"
has /etc/dnsmasq.conf "port=0"
expect_running dnsmasq unbound
expect_stopped kea-dhcp4 kea-dhcp6 radvd
# the retired daemons' files no longer describe the old pools (a manual
# start would otherwise serve them next to dnsmasq), and Kea accepts them
for f in /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp6.conf /etc/radvd.conf; do
  has "$f" "Managed by Patronus"
  if grep -qE '192\.168\.50\.|fd00:50::|aa:bb:cc:00:00:02|rtr-lan' "$f"; then cat "$f"; fail "$f still lists a retired pool"; fi
done
grep -q '"subnet4": \[\]' /etc/kea/kea-dhcp4.conf || { cat /etc/kea/kea-dhcp4.conf; fail "kea-dhcp4.conf still has subnets"; }
kea-dhcp4 -t /etc/kea/kea-dhcp4.conf >/tmp/kea-t.out 2>&1 || { cat /tmp/kea-t.out; fail "kea-dhcp4 -t rejects the idle config"; }
kea-dhcp6 -t /etc/kea/kea-dhcp6.conf >/tmp/kea-t.out 2>&1 || { cat /tmp/kea-t.out; fail "kea-dhcp6 -t rejects the idle config"; }
ok "kea/radvd configs emptied when the backend moved to dnsmasq (kea -t accepts them)"
check_v4 "dnsmasq"
check_v6 "dnsmasq RA + DHCPv6"
want 200 GET /api/dhcp/leases
grep -q '"source":"dnsmasq"' /tmp/api.out || fail "no dnsmasq leases in the API"
# relay: c3 on opt1 gets its address from the remote server via the router
code=$(api POST /api/firewall/rules '{"name":"dhcp-relay-opt1","chain":"input","action":"accept","interface":"rtr-opt1","protocol":"udp","source":"any","destination":"any","port":"67","description":"dhcp relay","enabled":true}')
case "$code" in 2??) ;; *) fail "firewall rule for the relay -> $code: $(cat /tmp/api.out)" ;; esac
# ... and the server's replies, which come back to the relay address on the
# server-facing interface (an admin adds both rules in Firewall > Rules)
code=$(api POST /api/firewall/rules '{"name":"dhcp-relay-replies","chain":"input","action":"accept","interface":"rtr-srv","protocol":"udp","source":"10.70.0.2","destination":"any","port":"67","description":"dhcp relay replies","enabled":true}')
case "$code" in 2??) ;; *) fail "firewall rule for relay replies -> $code: $(cat /tmp/api.out)" ;; esac
want 201 POST /api/dhcp/relays '{"interface":"rtr-opt1","servers":"10.70.0.2"}'
has /etc/dnsmasq.conf "dhcp-relay=192.168.60.1,10.70.0.2"
a3=$(lease4 c3); in_range "$a3" 192.168.60.100 192.168.60.150 || fail "c3 got $a3 via the relay"
grep -q "$a3" /run/dhcpsrv.leases || fail "remote server has no lease for $a3"
ok "relay: c3 got $a3 from the remote DHCP server through the router"

echo "=== 10. DNS forwarder mode (dnsmasq)"
want 200 PUT /api/dns/settings '{"mode":"forwarder"}'
expect_stopped unbound
expect_running dnsmasq
if grep -q '^port=0' /etc/dnsmasq.conf; then fail "forwarder mode still has port=0"; fi
check_dns "dnsmasq forwarder"

echo "=== 11. reboot: daemons stopped, generated configs deleted, only 'patronus apply'"
for s in patronus-web patronus-applyd dnsmasq unbound chronyd kea-dhcp4 kea-dhcp6 radvd; do svc stop "$s" >/dev/null 2>&1 || true; done
rm -f /etc/dnsmasq.conf /etc/unbound/unbound.conf /etc/chrony/chrony.conf /etc/kea/kea-dhcp4.conf /etc/radvd.conf
expect_stopped dnsmasq chronyd
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply after reboot"; }
grep -E '^\S+ (dhcp|dns|ntp|ddns) ' <<<"$APPLY" || true
has /etc/dnsmasq.conf "dhcp-host=aa:bb:cc:00:00:02,192.168.50.20,printer"
has /etc/chrony/chrony.conf "allow 192.168.50.0/24"
expect_running dnsmasq chronyd
check_v4 "after reboot"
check_dns "after reboot"
DRY=$(patronus apply --dry-run 2>&1)
grep -q '^### dhcp (services)' <<<"$DRY" && grep -q '^### dns (services)' <<<"$DRY" || { echo "$DRY" | head -40; fail "dry-run lacks LAN services"; }
ok "patronus apply --dry-run renders the LAN service configs"

kill "$DDNS_PID" 2>/dev/null || true
echo "=== lane D netlab ($INIT): all checks passed"
