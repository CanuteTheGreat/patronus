#!/usr/bin/env bash
# Lane T: guest network (USE=guest) in the shipped binaries. Two guest clients
# sit behind two ports of the router (bridge br-guest, ports isolated), the
# normal LAN client and the usual "internet" stay as in every lane. Proven on
# the kernel, with real packets:
#  - off by default: no bridge, no table, no DHCP;
#  - a guest gets DHCP (address, router, DNS), resolves names through the
#    router, and reaches the internet (masqueraded);
#  - a guest cannot reach LAN hosts, the router's management ports (any of its
#    addresses), the router's WAN address, another guest (layer 2 isolation,
#    and the same setting off lets them talk), nor private ranges behind the
#    WAN (setting off lets them through); nothing can start a connection INTO
#    the guest network;
#  - bandwidth caps are measured: per network (shared by both guests) and per
#    guest, download and upload;
#  - access: a daily schedule and a timed window close the network in the
#    kernel (DHCP keeps answering), the timed window closes by itself;
#  - bad input (overlapping subnet, missing port) is refused or undone with
#    nothing half-applied; settings survive `config rollback` and a reboot;
#  - switching it off removes the bridge, the table and the daemon.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

set -E
trap 'echo "ABORT at line $LINENO: $BASH_COMMAND" >&2' ERR
DB=/t/lane-t-guest.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v udhcpc >/dev/null || apt-get install -y -qq udhcpc >/dev/null 2>&1 || apt-get install -y -qq busybox >/dev/null 2>&1
command -v udhcpc >/dev/null || command -v busybox >/dev/null || nl_fail "no DHCP client (udhcpc) in the lab image"
UDHCPC=udhcpc; command -v udhcpc >/dev/null || UDHCPC="busybox udhcpc"
command -v dnsmasq >/dev/null || nl_fail "dnsmasq missing in the lab image"

# a failure prints the router's view, so a CI log says why
nl_fail() {
  set +e
  echo "FAIL: $*" >&2
  { echo "--- router addresses/routes"; R ip -br addr; R ip route; echo "--- bridge"; R bridge link; echo "--- nft ruleset"; R nft list ruleset;
    echo "--- inet listeners"; INET ss -ltn; echo "--- guest 1 view"; G1 ip -br addr; G1 ip route; G1 curl -sv -m 3 -o /dev/null "http://$NL_WWW:8081/up" 2>&1 | tail -8; echo "--- guest dnsmasq conf"; cat /var/lib/patronus/net/guest/dnsmasq.conf; echo "--- web log tail"; tail -20 "$NL_T/nl-web.log"; } >&2 2>/dev/null || true
  exit 1
}
G1() { ip netns exec nl-gst1 "$@"; }
G2() { ip netns exec nl-gst2 "$@"; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
guest_dnsmasq_alive() { pgrep -f '[g]uest/dnsmasq.conf' >/dev/null; }
guest_dnsmasq_gone() { ! guest_dnsmasq_alive; }
# out_has PATTERN CMD...: the command's output matches (no pipe into grep -q: see ci/lint-no-pipe-grep-q.sh)
out_has() { local pat=$1 out; shift; out=$("$@" 2>&1 || true); grep -q -- "$pat" <<<"$out"; }

# --- helper servers -----------------------------------------------------------
cat > "$NL_T/nl-bulk.py" <<'EOF'
# bulk HTTP: GET /blob streams zeros; PUT/POST /up discards what it is sent
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received = 0
    def do_GET(self):
        if self.path == "/received":
            body = str(H.received).encode()
            self.send_response(200); self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        n = 256 * 1024 * 1024
        self.send_response(200); self.send_header("content-length", str(n)); self.end_headers()
        chunk = b"\0" * 65536
        try:
            for _ in range(n // len(chunk)): self.wfile.write(chunk)
        except OSError: pass
    def do_PUT(self):
        left = int(self.headers.get("content-length", "0"))
        try:
            while left > 0:
                b = self.rfile.read(min(65536, left))
                if not b: break
                left -= len(b); H.received += len(b)
        except OSError: pass
        body = b"ok\n"
        self.send_response(200); self.send_header("content-length", "3"); self.end_headers(); self.wfile.write(body)
    do_POST = do_PUT
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True; daemon_threads = True
    def server_bind(self):  # HTTPServer.server_bind does a reverse DNS lookup (socket.getfqdn): slow without DNS
        socketserver.TCPServer.server_bind(self); self.server_port = self.server_address[1]
S((sys.argv[1], int(sys.argv[2])), H).serve_forever()
EOF
head -c 24000000 /dev/zero > "$NL_T/nl-upload.bin"
cat > "$NL_T/nl-udhcpc.sh" <<'EOF'
#!/bin/sh
# udhcpc script: configure the guest namespace like a normal client would, keep what was offered
case "$1" in
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    [ -n "$router" ] && ip route replace default via "${router%% *}" dev "$interface"
    echo "nameserver ${dns%% *}" > /etc/resolv.conf
    echo "$ip ${router%% *} $dns $lease" > "/t/nl-lease-$NL_N"
    ;;
esac
exit 0
EOF
chmod +x "$NL_T/nl-udhcpc.sh"

bulk_up() { INET ss -ltn | awk '$4 ~ /:8081$/ {f=1} END {exit !f}'; }
# a background server inside a guest namespace (nl_down stops it with the others)
nl_bg_ns() { local ns=$1; shift; ip netns exec "$ns" "$@" >/dev/null 2>&1 & NL_PIDS+=($!); }

guest_topo() {
  for n in 1 2; do ip netns del nl-gst$n 2>/dev/null || true; ip netns add nl-gst$n; ip -n nl-gst$n link set lo up; mkdir -p /etc/netns/nl-gst$n; : > /etc/netns/nl-gst$n/resolv.conf; done
  ip link add gst-a netns nl-rtr type veth peer name g0 netns nl-gst1
  ip link add gst-b netns nl-rtr type veth peer name g0 netns nl-gst2
  R ip link set gst-a up; R ip link set gst-b up; G1 ip link set g0 up; G2 ip link set g0 up
  INET ip addr add 10.77.7.7/32 dev inet0
  ISP ip route replace 10.77.7.7/32 via $NL_WWW
  nl_bg_ns nl-inet python3 "$NL_T/nl-bulk.py" $NL_WWW 8081
  nl_bg_ns nl-inet python3 "$NL_T/nl-tcp.py" 10.77.7.7 9000
  nl_wait 5 bulk_up || nl_fail "the helper servers in the internet namespace did not start"
}
guest_boot() { # DB: a reboot with the guest ports present
  # servers started by this scenario die with the old kernel (nl_down would trip over a dead one)
  for p in "${NL_PIDS[@]:-}"; do [ -n "$p" ] || continue; kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
  NL_PIDS=()
  nl_kill_daemons dnsmasq
  nl_up; guest_topo
  nl_apply "$1" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
  nl_ok "boot: patronus apply ($(grep -c '✓' "$NL_OUT") appliers ok)"
}
guest_cleanup() { for n in 1 2; do ip netns del nl-gst$n 2>/dev/null || true; rm -rf /etc/netns/nl-gst$n; done; }
trap 'guest_cleanup' EXIT
guest_dhcp() { # N: run the DHCP client in guest N
  NL_N=$1 ip netns exec nl-gst$1 $UDHCPC -i g0 -n -q -t 5 -T 2 -s "$NL_T/nl-udhcpc.sh" >"$NL_OUT.dhcp$1" 2>&1 \
    || { cat "$NL_OUT.dhcp$1"; nl_fail "guest $1 got no DHCP lease"; }
}
lease_field() { awk -v f="$2" '{print $f}' "$NL_T/nl-lease-$1"; }   # 1 ip, 2 router, 3 dns, 4 lease
speed() { # NS-FN URL...: bytes/s as an integer (curl exits 28 when -m ends the transfer: expected)
  local fn=$1 o; shift
  o=$("$fn" curl -s -m "${SPEED_SECS:-8}" -o /dev/null -w '%{speed_download}' "$@" 2>/dev/null || true)
  echo "${o%%.*}"
}
speed_up() { # NS-FN URL: bytes/s that ARRIVED at the server over a 6 s window (curl's own figure counts what sits in the send buffer)
  # The server counts bytes from every connection, so no upload may outlive its own window. curl ends itself (-m 9, the
  # window is 2 + 6 s) and is waited for: `kill $!` would only hit the subshell running the G1/G2 wrapper and leave curl
  # uploading into the next measurement (a capped run went on in the background and doubled the per-guest figure).
  local fn=$1 b1 b2 pid; shift
  "$fn" curl -s -m 9 -T "$NL_T/nl-upload.bin" -o /dev/null "$@" >/dev/null 2>&1 & pid=$!
  sleep 2; b1=$(INET curl -s http://$NL_WWW:8081/received); sleep 6; b2=$(INET curl -s http://$NL_WWW:8081/received)
  wait "$pid" 2>/dev/null || true
  echo $(( (b2 - b1) / 6 ))
}
upload_secs() { # NS-FN URL: seconds to upload the whole file
  local fn=$1 t0; shift; t0=$SECONDS
  "$fn" curl -s -m 30 -T "$NL_T/nl-upload.bin" -o /dev/null "$@" >/dev/null 2>&1 || true
  echo $(( SECONDS - t0 ))
}
between() { # DESC VALUE LO HI
  [ "${2:-0}" -ge "$3" ] && [ "${2:-0}" -le "$4" ] || nl_fail "$1: measured $2 B/s, expected $3..$4 B/s"
  nl_ok "$1: measured $2 B/s (expected $3..$4)"
}
hm() { date -d "@$(( $(date +%s) + $1 ))" +%H:%M; }
internet_ok() { # NS-FN
  "$1" curl -s -m 4 -o "$NL_OUT.net" http://$NL_WWW/ && grep -q "sees $NL_RTR_WAN" "$NL_OUT.net"
}
web_ok() { local c; c=$("$1" curl -s -m 3 -o /dev/null -w '%{http_code}' "$2" || true); [ "$c" = 200 ]; }
internet_closed() { ! internet_ok G1; }

nl_write_installer_toml
guest_cleanup
nl_up; guest_topo
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_bg C python3 "$NL_T/nl-tcp.py" $NL_CLIENT 9000

echo "=== 1. off by default"
nl_api GET /svc/guest; [ "$NL_CODE" = 200 ] || nl_fail "guest page API: $NL_CODE"
[ "$(jget 'd["settings"]["enabled"]')" = False ] || nl_fail "guest network is not off by default: $(cat "$NL_OUT")"
[ "$(jget 'd["settings"]["bridge"]')" = br-guest ] && [ "$(jget 'd["settings"]["address"]')" = 192.168.30.1/24 ] || nl_fail "defaults missing: $(cat "$NL_OUT")"
! R ip link show br-guest >/dev/null 2>&1 || nl_fail "bridge exists although the guest network is off"
nl_assert_nft_lacks patronus_guest
! guest_dnsmasq_alive || nl_fail "guest DHCP runs although the guest network is off"
nl_web GET /svc/guest; [ "$NL_CODE" = 200 ] && grep -q 'Guest network' "$NL_OUT" || nl_fail "guest page ($NL_CODE)"
nl_ok "defaults shown, nothing exists while it is off"

echo "=== 2. bad input is refused as a whole"
nl_api PUT /svc/guest '{"enabled":true,"vlan_id":0,"ports":"gst-a,gst-b","address":"192.168.50.5/24"}'
[ "$NL_CODE" = 400 ] || nl_fail "a subnet overlapping the LAN must be refused (400), got $NL_CODE $(cat "$NL_OUT")"
grep -q 'overlaps' "$NL_OUT" || nl_fail "the refusal does not say why: $(cat "$NL_OUT")"
for bad in '{"dhcp_start":"10.9.9.9"}' '{"router_ports":"tcp/99999"}' '{"access":"schedule","schedule_from":"25:61"}' '{"address":"192.168.30.1/31"}'; do
  nl_api PUT /svc/guest "$bad"; [ "$NL_CODE" = 400 ] || nl_fail "$bad must be refused (400), got $NL_CODE"
done
nl_api GET /svc/guest
[ "$(jget 'd["settings"]["enabled"]')" = False ] && [ "$(jget 'd["settings"]["address"]')" = 192.168.30.1/24 ] || nl_fail "refused input changed the settings"
! R ip link show br-guest >/dev/null 2>&1 || nl_fail "refused input created the bridge"
nl_ok "overlap and bad values refused (400), nothing stored, nothing in the kernel"

echo "=== 3. switch on: DHCP, DNS and the internet for guests"
NET_CFG='{"enabled":true,"vlan_id":0,"ports":"gst-a,gst-b","address":"192.168.30.1/24","dns_upstreams":"'$NL_DNS'","lease_minutes":45}'
nl_api PUT /svc/guest "$NET_CFG"
[ "$NL_CODE" = 200 ] || nl_fail "enable guest network: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 guest_dnsmasq_alive || nl_fail "guest dnsmasq did not start"
out_has bridge R ip -d link show br-guest || nl_fail "br-guest is not a bridge"
[ "$(R ip -4 -o addr show dev br-guest | awk '{print $4}')" = 192.168.30.1/24 ] || nl_fail "br-guest address: $(R ip -4 -o addr show dev br-guest)"
[ "$(R cat /proc/sys/net/ipv6/conf/br-guest/disable_ipv6)" = 1 ] || nl_fail "IPv6 is on in the guest network"
for p in gst-a gst-b; do
  out_has 'isolated on' R bridge -d link show dev $p || nl_fail "$p is not an isolated bridge port: $(R bridge -d link show dev $p)"
done
nl_assert_nft_has "table inet patronus_guest" "jump guest_in" 'oifname != "rtr-wan" drop' "masquerade"
nl_ok "bridge, address, no IPv6, isolated ports, guest nft table in the kernel"
guest_dhcp 1; guest_dhcp 2
G1IP=$(lease_field 1 1); G2IP=$(lease_field 2 1)
[ "$G1IP" != "$G2IP" ] || nl_fail "both guests got $G1IP"
case $G1IP in 192.168.30.*) ;; *) nl_fail "guest 1 address $G1IP is outside the guest range";; esac
[ "$(lease_field 1 2)" = 192.168.30.1 ] && [ "$(lease_field 1 3)" = 192.168.30.1 ] || nl_fail "lease: router/DNS $(cat "$NL_T/nl-lease-1")"
[ "$(lease_field 1 4)" = 2700 ] || nl_fail "lease time $(lease_field 1 4) s, want 2700 (45 min setting)"
nl_ok "guests got $G1IP and $G2IP, router and DNS 192.168.30.1, 45-minute lease (the setting)"
G1 python3 -c "import socket; assert socket.gethostbyname('www.example.test')=='$NL_WWW'" || nl_fail "guest DNS through the router failed"
nl_ok "guest resolves www.example.test through the router's guest DNS"
G1 curl -s -m 5 -o "$NL_OUT" http://www.example.test/ && grep -q "www.example.test sees $NL_RTR_WAN" "$NL_OUT" || nl_fail "guest has no internet: $(cat "$NL_OUT" 2>/dev/null)"
nl_ok "guest reaches the internet, masqueraded as $NL_RTR_WAN"
G1 ping -c1 -W2 192.168.30.1 >/dev/null || nl_fail "guest cannot ping the router (allow_ping is on by default)"
nl_ok "guest pings the router (allow_ping default)"

echo "=== 4. isolation"
nl_bg_ns nl-gst2 python3 "$NL_T/nl-tcp.py" 0.0.0.0 9000
nl_bg_ns nl-gst1 python3 "$NL_T/nl-tcp.py" 0.0.0.0 9000
sleep 0.5
web_ok G1 "http://$NL_WWW:8081/up" || nl_fail "control: a guest cannot reach an internet server"
nl_ok "control: a guest reaches a server on the internet"
nl_expect_no_tcp "guest -> LAN client" G1 $NL_CLIENT 9000
nl_expect_no_tcp "guest -> router web UI on its guest address" G1 192.168.30.1 8443
nl_expect_no_tcp "guest -> router SSH on its guest address" G1 192.168.30.1 22
nl_expect_no_tcp "guest -> router web UI on its LAN address" G1 $NL_RTR_LAN 8443
nl_expect_no_tcp "guest -> router web UI on its WAN address" G1 $NL_RTR_WAN 8443
nl_expect_no_tcp "guest -> router SSH on its WAN address" G1 $NL_RTR_WAN 22
nl_expect_no_tcp "guest 1 -> guest 2 (same bridge)" G1 "$G2IP" 9000
G1 ping -c1 -W2 "$G2IP" >/dev/null 2>&1 && nl_fail "guest 1 pings guest 2"
nl_ok "guest 1 cannot ping guest 2"
nl_expect_no_tcp "LAN client -> guest 1 (nothing starts a connection into the guest network)" C "$G1IP" 9000
C ping -c1 -W2 "$G1IP" >/dev/null 2>&1 && nl_fail "LAN client pings a guest"
nl_expect_no_tcp "guest -> private range behind the WAN (10.77.7.7)" G1 10.77.7.7 9000
# the settings are real: each one lifted, the thing it blocks works
nl_api PUT /svc/guest '{"block_private":false}'; [ "$NL_CODE" = 200 ] || nl_fail "block_private off: $NL_CODE"
nl_expect_tcp "block_private=off: guest -> 10.77.7.7 now works" G1 10.77.7.7 9000
nl_api PUT /svc/guest '{"block_private":true}'; [ "$NL_CODE" = 200 ] || nl_fail "block_private on: $NL_CODE"
nl_expect_no_tcp "block_private=on again" G1 10.77.7.7 9000
nl_api PUT /svc/guest '{"isolate_clients":false}'; [ "$NL_CODE" = 200 ] || nl_fail "isolate off: $NL_CODE"
out_has 'isolated off' R bridge -d link show dev gst-a || nl_fail "gst-a still isolated"
nl_expect_tcp "isolate_clients=off: guest 1 -> guest 2 works (layer 2)" G1 "$G2IP" 9000
nl_api PUT /svc/guest '{"isolate_clients":true}'; [ "$NL_CODE" = 200 ] || nl_fail "isolate on: $NL_CODE"
nl_expect_no_tcp "isolate_clients=on again" G1 "$G2IP" 9000
# the LAN itself is untouched by all of this
nl_expect_online

echo "=== 5. router services for guests are settings"
nl_api PUT /svc/guest '{"router_ports":"tcp/9000"}'; [ "$NL_CODE" = 200 ] || nl_fail "router_ports: $NL_CODE"
nl_bg_ns nl-rtr python3 "$NL_T/nl-tcp.py" 192.168.30.1 9000
sleep 0.5
nl_expect_tcp "router_ports=tcp/9000: guest -> router 192.168.30.1:9000" G1 192.168.30.1 9000
nl_expect_no_tcp "other router ports stay closed" G1 192.168.30.1 8443
nl_api PUT /svc/guest '{"router_ports":""}'; [ "$NL_CODE" = 200 ] || nl_fail "router_ports off: $NL_CODE"
nl_expect_no_tcp "router_ports emptied: closed again" G1 192.168.30.1 9000
nl_api PUT /svc/guest '{"egress_ports":"tcp/80,udp/53"}'; [ "$NL_CODE" = 200 ] || nl_fail "egress_ports: $NL_CODE"
web_ok G1 "http://$NL_WWW:80/" || nl_fail "egress_ports=tcp/80: port 80 must work"
! web_ok G1 "http://$NL_WWW:8081/up" || nl_fail "egress_ports=tcp/80: port 8081 must be out"
nl_ok "egress_ports=tcp/80,udp/53: web works, port 8081 is out"
nl_api PUT /svc/guest '{"egress_ports":""}'; [ "$NL_CODE" = 200 ] || nl_fail "egress off: $NL_CODE"
web_ok G1 "http://$NL_WWW:8081/up" || nl_fail "egress limit removed but 8081 is still out"
nl_ok "egress limit removed"

echo "=== 6. bandwidth caps, measured"
SPEED_SECS=7
base=$(speed G1 http://$NL_WWW:8081/blob)
[ "$base" -gt 3000000 ] || nl_fail "uncapped download only $base B/s: the lab is too slow to measure caps"
nl_ok "uncapped download: $base B/s"
# network cap: 8 Mbit/s = 1,000,000 B/s shared by every guest (tc tbf on the bridge)
nl_api PUT /svc/guest '{"down_kbit":8000}'; [ "$NL_CODE" = 200 ] || nl_fail "down_kbit: $NL_CODE $(cat "$NL_OUT")"
out_has tbf R tc qdisc show dev br-guest || nl_fail "no tbf qdisc on br-guest: $(R tc qdisc show dev br-guest)"
between "network download cap 8000 kbit/s, one guest" "$(speed G1 http://$NL_WWW:8081/blob)" 700000 1150000
( speed G1 http://$NL_WWW:8081/blob > "$NL_OUT.s1" ) & p1=$!; ( speed G2 http://$NL_WWW:8081/blob > "$NL_OUT.s2" ) & p2=$!; wait $p1 $p2
s1=$(cat "$NL_OUT.s1"); s2=$(cat "$NL_OUT.s2")
between "network cap shared: both guests together" $((s1 + s2)) 700000 1250000
nl_ok "per-guest shares of the shared cap: $s1 and $s2 B/s"
nl_api PUT /svc/guest '{"down_kbit":0}'; [ "$NL_CODE" = 200 ] || nl_fail "down_kbit off: $NL_CODE"
! out_has tbf R tc qdisc show dev br-guest || nl_fail "cap removed in the store but the tbf qdisc is still there"
[ "$(speed G1 http://$NL_WWW:8081/blob)" -gt 3000000 ] || nl_fail "download is still capped after removing the cap"
nl_ok "cap removed: back to full speed"
# per-guest cap: 4 Mbit/s = 500,000 B/s EACH (nft meter on the guest's address)
nl_api PUT /svc/guest '{"client_down_kbit":4000}'; [ "$NL_CODE" = 200 ] || nl_fail "client_down_kbit: $NL_CODE $(cat "$NL_OUT")"
nl_assert_nft_has "set down_clients" "per-guest download cap"
( speed G1 http://$NL_WWW:8081/blob > "$NL_OUT.s1" ) & p1=$!; ( speed G2 http://$NL_WWW:8081/blob > "$NL_OUT.s2" ) & p2=$!; wait $p1 $p2
s1=$(cat "$NL_OUT.s1"); s2=$(cat "$NL_OUT.s2")
between "per-guest download cap 4000 kbit/s: guest 1" "$s1" 300000 650000
between "per-guest download cap 4000 kbit/s: guest 2 at the same time" "$s2" 300000 650000
nl_api PUT /svc/guest '{"client_down_kbit":0}'; [ "$NL_CODE" = 200 ] || nl_fail "client_down off: $NL_CODE"
# upload: network 2 Mbit/s (ingress policer) = 250,000 B/s
nl_api PUT /svc/guest '{"up_kbit":2000}'; [ "$NL_CODE" = 200 ] || nl_fail "up_kbit: $NL_CODE $(cat "$NL_OUT")"
out_has police R tc filter show dev br-guest parent ffff: || nl_fail "no ingress policer on br-guest"
between "network upload cap 2000 kbit/s" "$(speed_up G1 http://$NL_WWW:8081/up)" 150000 330000
nl_api PUT /svc/guest '{"up_kbit":0}'; [ "$NL_CODE" = 200 ] || nl_fail "up_kbit off: $NL_CODE"
! out_has police R tc filter show dev br-guest parent ffff: || nl_fail "upload cap removed in the store, policer still there"
nl_api PUT /svc/guest '{"client_up_kbit":2000}'; [ "$NL_CODE" = 200 ] || nl_fail "client_up_kbit: $NL_CODE"
between "per-guest upload cap 2000 kbit/s" "$(speed_up G2 http://$NL_WWW:8081/up)" 150000 330000
nl_api PUT /svc/guest '{"client_up_kbit":0}'; [ "$NL_CODE" = 200 ] || nl_fail "client_up off: $NL_CODE"
[ "$(upload_secs G1 http://$NL_WWW:8081/up)" -le 4 ] || nl_fail "uploading 24 MB still takes over 4 s after removing every cap"
nl_ok "all caps removed: upload back to full speed"

echo "=== 7. access: schedule and timed window close the network in the kernel"
today=$(date +%w); other=$(( (today + 1) % 7 ))
nl_api PUT /svc/guest "{\"access\":\"schedule\",\"schedule_from\":\"$(hm -3600)\",\"schedule_to\":\"$(hm 3600)\",\"schedule_days\":\"$today\"}"
[ "$NL_CODE" = 200 ] || nl_fail "schedule (open now): $NL_CODE $(cat "$NL_OUT")"
nl_wait 5 internet_ok G1 || nl_fail "inside the schedule the guest has no internet"
nl_ok "schedule window around now on today's weekday: open"
nl_api PUT /svc/guest "{\"schedule_from\":\"$(hm 7200)\",\"schedule_to\":\"$(hm 10800)\"}"; [ "$NL_CODE" = 200 ] || nl_fail "schedule (closed hours): $NL_CODE"
nl_assert_nft_has "guest network is closed"
! internet_ok G1 || nl_fail "outside the schedule hours the guest still has internet"
G1 python3 -c "import socket; socket.setdefaulttimeout(2); socket.gethostbyname('www.example.test')" 2>/dev/null && nl_fail "DNS still answers while the network is closed"
guest_dhcp 1   # DHCP keeps answering: the guest keeps its address and just has no way out
nl_ok "outside the hours: no internet, no DNS, DHCP still answers"
nl_api PUT /svc/guest "{\"schedule_from\":\"$(hm -3600)\",\"schedule_to\":\"$(hm 3600)\",\"schedule_days\":\"$other\"}"; [ "$NL_CODE" = 200 ] || nl_fail "schedule (other weekday): $NL_CODE"
nl_wait 8 internet_closed || nl_fail "on a weekday outside the schedule the guest still has internet"
nl_ok "right hours, wrong weekday: closed"
nl_api PUT /svc/guest "{\"schedule_days\":\"0,1,2,3,4,5,6\"}"; [ "$NL_CODE" = 200 ] || nl_fail "schedule (all days): $NL_CODE"
nl_wait 5 internet_ok G1 || nl_fail "all weekdays + hours around now: still closed"
nl_ok "all weekdays, hours around now: open again"
# timed: closed until opened; the kernel closes it again by itself
nl_api PUT /svc/guest '{"access":"timed","open_until":0}'; [ "$NL_CODE" = 200 ] || nl_fail "timed: $NL_CODE"
! internet_ok G1 || nl_fail "timed access is open although nobody opened it"
nl_api PUT /svc/guest "{\"open_until\":$(( $(date +%s) + 9 ))}"; [ "$NL_CODE" = 200 ] || nl_fail "open_until: $NL_CODE"
nl_wait 5 internet_ok G1 || nl_fail "timed window did not open"
nl_ok "timed access opened for 9 s"
sleep 11
! internet_ok G1 || nl_fail "the timed window did not close by itself"
nl_ok "the window closed by itself (kernel clock, no daemon involved)"
nl_api POST /svc/guest/action/open '{"minutes":30}'; [ "$NL_CODE" = 200 ] || nl_fail "open action: $NL_CODE $(cat "$NL_OUT")"
nl_wait 5 internet_ok G1 || nl_fail "the Open button did not open the network"
nl_api POST /svc/guest/action/close; [ "$NL_CODE" = 200 ] || nl_fail "close action: $NL_CODE"
nl_wait 5 internet_closed || nl_fail "the Close button did not close the network"
nl_ok "Open for 30 minutes / Close now buttons work"
nl_api PUT /svc/guest '{"access":"always"}'; [ "$NL_CODE" = 200 ] || nl_fail "access always: $NL_CODE"
nl_wait 5 internet_ok G1 || nl_fail "access=always: no internet"

echo "=== 8. Wi-Fi password and vouchers (the SSID itself needs a radio: lane-t-guest-wifi.sh)"
nl_api POST /svc/guest/action/new_password; [ "$NL_CODE" = 200 ] || nl_fail "new_password: $NL_CODE"
PW=$(jget 'd["wifi_password"]'); [ "${#PW}" = 16 ] || nl_fail "generated password: $PW"
nl_api GET /svc/guest; [ "$(jget 'd["settings"]["wifi_psk"]')" = '********' ] || nl_fail "the password is returned by the API"
grep -qF "$PW" "$NL_OUT" && nl_fail "the generated password appears in GET /svc/guest"
nl_api POST /svc/guest/action/voucher '{"name":"friday","minutes":30}'; [ "$NL_CODE" = 200 ] || nl_fail "voucher: $NL_CODE $(cat "$NL_OUT")"
VC=$(jget 'd["wifi_password"]'); [ "${#VC}" = 12 ] || nl_fail "voucher code: $VC"
nl_api GET /svc/guest; grep -qF "$VC" "$NL_OUT" && nl_fail "a voucher code is listed by the API"
[ "$(jget 'd["collections"]["vouchers"][0]["code"]')" = '********' ] || nl_fail "voucher list: $(cat "$NL_OUT")"
nl_api POST /svc/guest/action/nope; [ "$NL_CODE" != 200 ] || nl_fail "an unknown action must fail"
nl_api POST /svc/guest/action/share; [ "$NL_CODE" = 200 ] || nl_fail "share card: $NL_CODE $(cat "$NL_OUT")"
URI=$(jget 'd["uri"]'); [ "$(jget 'd["wifi_password"]')" = "$PW" ] && [ "$URI" = "WIFI:T:WPA;S:Guest;P:$PW;;" ] || nl_fail "share card does not carry the password and the join text: $URI"
grep -q '<svg' "$NL_OUT" || nl_fail "share card has no QR code"
nl_ok "Show Wi-Fi password and QR code: password, join-this-network text and an SVG QR code (an audited reveal)"
nl_ok "password generated once, vouchers listed without their codes"

echo "=== 9. audit log"
for a in guest_settings guest_open guest_close guest_new_password guest_voucher_save; do
  [ "$(sqlite3 "$DB" "select count(*) from audit_log where action='$a'")" -ge 1 ] || nl_fail "no audit entry $a"
done
DET=$(sqlite3 "$DB" "select details from audit_log where action like 'guest%'"); grep -qF "$PW" <<<"$DET" && nl_fail "a password is in the audit log"
nl_ok "settings, open/close, password and voucher changes are audited (no secrets in the log)"

echo "=== 10. a failed apply is undone; rollback and reboot keep the settings"
nl_api PUT /svc/guest '{"ports":"gst-a,gst-b,nope0"}'
[ "$NL_CODE" != 200 ] || nl_fail "a missing port must fail"
nl_api GET /svc/guest; [ "$(jget 'd["settings"]["ports"]')" = "gst-a,gst-b" ] || nl_fail "failed apply not undone: $(cat "$NL_OUT")"
nl_ok "missing port: refused, store unchanged"
nl_api PUT /svc/guest '{"address":"192.168.31.1/24","lease_minutes":30,"dhcp_start":"","dhcp_end":""}'; [ "$NL_CODE" = 200 ] || nl_fail "move the subnet: $NL_CODE $(cat "$NL_OUT")"
[ "$(R ip -4 -o addr show dev br-guest | awk '{print $4}')" = 192.168.31.1/24 ] || nl_fail "br-guest did not move"
guest_dhcp 1; case $(lease_field 1 1) in 192.168.31.*) ;; *) nl_fail "guest stayed on $(lease_field 1 1)";; esac
nl_ok "subnet changed live: guest renewed on 192.168.31.0/24"
REVS=$(R "$P" --db "$DB" config revisions); REV=$(awk '/before change guest settings/{print $1; exit}' <<<"$REVS")   # newest first
[ -n "$REV" ] || { echo "$REVS"; nl_fail "no config revision for the guest change"; }
R "$P" --db "$DB" config rollback "$REV" >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "config rollback $REV failed"; }
[ "$(R ip -4 -o addr show dev br-guest | awk '{print $4}')" = 192.168.30.1/24 ] || nl_fail "rollback did not restore the guest subnet: $(R ip -4 -o addr show dev br-guest)"
[ "$(sqlite3 "$DB" "select value from lan_settings where key='guest.address'")" = 192.168.30.1/24 ] || nl_fail "rollback did not restore the setting"
guest_dhcp 2; case $(lease_field 2 1) in 192.168.30.*) ;; *) nl_fail "after rollback guest 2 got $(lease_field 2 1)";; esac
nl_ok "config rollback restored settings, bridge address and DHCP to the 192.168.30.0/24 network"

echo "=== reboot: fresh kernel, only 'patronus apply'"
nl_web_stop
guest_boot "$DB"
nl_wait 20 guest_dnsmasq_alive || nl_fail "guest DHCP not back after boot"
nl_assert_nft_has "table inet patronus_guest"
[ "$(R ip -4 -o addr show dev br-guest | awk '{print $4}')" = 192.168.30.1/24 ] || nl_fail "br-guest not rebuilt at boot"
for p in gst-a gst-b; do out_has 'isolated on' R bridge -d link show dev $p || nl_fail "$p not isolated after boot"; done
guest_dhcp 1; guest_dhcp 2
nl_wait 5 internet_ok G1 || nl_fail "guest has no internet after the reboot"
nl_expect_no_tcp "after boot: guest -> router web UI" G1 192.168.30.1 8443
nl_ok "the guest network came back from the store alone, isolation intact"
nl_web_start "$DB"; nl_login

echo "=== 11. switch off: everything goes"
nl_api PUT /svc/guest '{"enabled":false}'; [ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE $(cat "$NL_OUT")"
nl_wait 10 guest_dnsmasq_gone || nl_fail "guest dnsmasq still running"
! R ip link show br-guest >/dev/null 2>&1 || nl_fail "bridge br-guest still exists"
nl_assert_nft_lacks patronus_guest
! out_has master R ip link show gst-a || nl_fail "gst-a is still in a bridge"
nl_expect_online
nl_ok "off: bridge, table and daemon removed, ports released, the LAN is untouched"
nl_api PUT /svc/guest '{"enabled":true}'; [ "$NL_CODE" = 200 ] || nl_fail "re-enable: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 guest_dnsmasq_alive || nl_fail "guest DHCP did not come back"
guest_dhcp 1; nl_wait 5 internet_ok G1 || nl_fail "no internet after re-enabling"
nl_ok "switched on again from the same settings"
echo "PASS lane-t-guest"
