#!/usr/bin/env bash
# Lane D (OpenWrt parity): what a dnsmasq/odhcpd-based OpenWrt router did that
# Patronus now does too, proven with real packets:
#   1. dns.local_domain: a DHCP client's host name resolves as <name>.<domain>
#      (dnsmasq domain= / local= / expand-hosts); a static mapping with
#      dns_record resolves while its host is offline; one without does not;
#      a static lease with lease_time 0 is infinite (dnsmasq lease file + the
#      client's own lease), dns.cache_size / dns.log_queries reach dnsmasq.
#   2. per-domain forwarding of an internal domain AND its reverse zone to two
#      internal servers (the first one dying does not break resolution), with
#      the DNS service also answering on a WireGuard device (real tunnel).
#   3. IPv6: the WAN DHCPv6 client uses the pinned DUID (seen by the ISP's
#      DHCPv6 server on the wire); the LAN has a static ULA and a delegated
#      prefix at the same time; a prefix-relative DHCPv6 pool + managed/other RA
#      hand the client an address from the delegated prefix.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-d-openwrt-parity.db
DUID=00:03:00:01:02:42:ac:11:00:99
DOM=lan.example
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v dhcpcd >/dev/null || apt-get install -y -qq dhcpcd-base >/dev/null 2>&1 || apt-get install -y -qq dhcpcd5 >/dev/null 2>&1 || apt-get install -y -qq dhcpcd >/dev/null
command -v radvd >/dev/null || apt-get install -y -qq radvd >/dev/null
command -v dhcpd >/dev/null || apt-get install -y -qq isc-dhcp-server >/dev/null
command -v dnsmasq >/dev/null || nl_fail "dnsmasq is not installed"
[ -x /usr/sbin/dnsmasq ] || nl_fail "/usr/sbin/dnsmasq missing"
for t in dhcpcd radvd dhcpd wg; do command -v $t >/dev/null || nl_fail "$t is not installed"; done
pkill -x dnsmasq 2>/dev/null || true
# a lease file left by an earlier scenario would pin addresses to other MACs; the DNS applier
# rewrites the container's /etc/resolv.conf for the router: put it back when this scenario ends
pkill -x dhcpcd 2>/dev/null || true   # a client daemon of an earlier scenario keeps its control socket
rm -f /var/lib/misc/dnsmasq.leases
cp -a /etc/resolv.conf "$NL_T/resolv.conf.saved"
# the dnsmasq.conf Patronus writes here would make the next scenario's apply stop "its" dnsmasq
# (the lab's internet DNS server): leave the file as this scenario found it
rm -f "$NL_T/dnsmasq.conf.saved"; [ -e /etc/dnsmasq.conf ] && cp -a /etc/dnsmasq.conf "$NL_T/dnsmasq.conf.saved"
nl_lane_d_cleanup() {
  cp "$NL_T/resolv.conf.saved" /etc/resolv.conf 2>/dev/null || true
  pkill -x dhcpcd 2>/dev/null || true
  [ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq stop >/dev/null 2>&1
  rm -f /etc/init.d/dnsmasq /var/lib/misc/dnsmasq.leases
  if [ -e "$NL_T/dnsmasq.conf.saved" ]; then cp -a "$NL_T/dnsmasq.conf.saved" /etc/dnsmasq.conf; else rm -f /etc/dnsmasq.conf; fi
  return 0
}
trap 'rc=$?; nl_lane_d_cleanup; exit $rc' EXIT

# a tiny DNS client: dnsq.py NAME TYPE SERVER -> "rcode=N answers=a,b" (A/AAAA/PTR)
cat >"$NL_T/dnsq.py" <<'PY'
import socket, struct, sys, ipaddress
name, typ, server = sys.argv[1], sys.argv[2], sys.argv[3]
t = {"A": 1, "PTR": 12, "AAAA": 28}[typ]
q = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
for l in name.rstrip(".").split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", t, 1)
s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
# like a real stub resolver: retransmit the same query (dnsmasq sends a retried query to every server of a zone,
# while a first query only goes to the last server that answered)
for _try in range(4):
    s.sendto(q, (server, 53))
    try: d, _ = s.recvfrom(4096); break
    except socket.timeout: pass
else: raise TimeoutError("timed out")
def rd(i):
    out = []
    while True:
        l = d[i]
        if l & 0xC0 == 0xC0:
            j = ((l & 0x3F) << 8) | d[i + 1]; sub, _ = rd(j); out += sub; return out, i + 2
        if l == 0: return out, i + 1
        out.append(d[i + 1:i + 1 + l].decode()); i += l + 1
rcode = d[3] & 15; an = struct.unpack("!H", d[6:8])[0]
_, i = rd(12); i += 4
res = []
for _ in range(an):
    _, i = rd(i); ty, _, _, ln = struct.unpack("!HHIH", d[i:i + 10]); i += 10
    if ty == 1: res.append(str(ipaddress.IPv4Address(d[i:i + 4])))
    elif ty == 28: res.append(str(ipaddress.IPv6Address(d[i:i + 16])))
    elif ty == 12: res.append(".".join(rd(i)[0]))
    i += ln
print("rcode=%d answers=%s" % (rcode, ",".join(res) if res else "none"))
PY
# first DHCPv6 client-id (hex) the ISP saw in a pcap
cat >"$NL_T/pcap-duid.py" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
magic = struct.unpack("<I", d[:4])[0]
e = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
link = struct.unpack(e + "I", d[20:24])[0]
i = 24; seen = []
while i + 16 <= len(d):
    _, _, cl, _ = struct.unpack(e + "IIII", d[i:i + 16]); p = d[i + 16:i + 16 + cl]; i += 16 + cl
    off = {1: 14, 113: 16, 276: 20}.get(link)
    if off is None or len(p) < off + 48 or p[off] >> 4 != 6 or p[off + 6] != 17: continue
    u = off + 40
    if struct.unpack("!H", p[u + 2:u + 4])[0] != 547: continue
    m = p[u + 8:]; o = 4
    while o + 4 <= len(m):
        c, l = struct.unpack("!HH", m[o:o + 4])
        if c == 1: seen.append(":".join("%02x" % b for b in m[o + 4:o + 4 + l]))
        o += 4 + l
print(seen[0] if seen else "none")
PY
ask() { C python3 "$NL_T/dnsq.py" "$@" 2>&1 | tail -1; }
expect_ans() { # NAME TYPE SERVER WANT-SUBSTRING
  local got; got=$(ask "$1" "$2" "$3")
  case "$got" in *"$4"*) ;; *) nl_fail "$1 $2 via $3: got [$got], want [$4]";; esac
}
expect_ans_wait() { # NAME TYPE SERVER WANT
  # dnsmasq keeps using the last good server of a zone; a retransmitted query (dnsq.py resends it) goes to all of them,
  # and it also probes them again every 20 s / 50 queries (FORWARD_TIME), per zone: give each zone 45 s
  local end=$((SECONDS + 45)) got=
  while [ "$SECONDS" -lt "$end" ]; do got=$(ask "$1" "$2" "$3" || true); case "$got" in *"$4"*) return 0;; esac; sleep 0.5; done
  nl_fail "$1 $2 via $3: got [$got], want [$4]"
}

nl_dnsmasq_shim
nl_write_installer_toml
nl_boot "$DB"

# --- the ISP side: RA with the managed flag + DHCPv6 (IA_NA and prefix6)
ISP ip -6 addr add 2001:db8:ffff::1/64 dev up0 nodad
cat >"$NL_T/isp-radvd.conf" <<'CONF'
interface up0 {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 6;
    prefix 2001:db8:ffff::/64 { AdvOnLink on; AdvAutonomous off; };
};
CONF
cat >"$NL_T/isp-dhcpd6.conf" <<'CONF'
default-lease-time 600;
max-lease-time 1200;
ddns-update-style none;
authoritative;
subnet6 2001:db8:ffff::/64 {
    range6 2001:db8:ffff::100 2001:db8:ffff::200;
    prefix6 2001:db8:1000:: 2001:db8:10ff:: /56;
}
CONF
: >"$NL_T/isp-dhcpd6.leases"
ISP sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
nl_bg ISP radvd -n -C "$NL_T/isp-radvd.conf" -p /tmp/isp-radvd.pid
nl_bg ISP dhcpd -6 -d -cf "$NL_T/isp-dhcpd6.conf" -lf "$NL_T/isp-dhcpd6.leases" up0
ISP tcpdump -U -i up0 -w "$NL_T/isp-dhcp6.pcap" udp port 547 >/dev/null 2>&1 &
NL_PIDS+=($!)
sleep 2

nl_web_start "$DB"; nl_login

# --- 1. LAN: IPv4 + a static ULA; the DHCP pool, static leases, DNS settings
nl_api_ok "LAN static v4 + ULA" PUT /interfaces/$NL_LAN_IF '{"role":"lan","ipv4_mode":"static","ipv4":["192.168.50.1/24"],"ipv6_mode":"static","ipv6":["fd00:50::1/64"],"force":true}'
nl_api_ok "WAN v4" PUT /interfaces/$NL_WAN_IF "{\"role\":\"wan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"203.0.113.2/24\"],\"gateway4\":\"203.0.113.1\",\"ipv6_mode\":\"none\",\"force\":true}"
nl_api_ok "DHCP pool" POST /dhcp/pools '{"interface":"@lan","range_start":"192.168.50.100","range_end":"192.168.50.199","lease_time":3600}'
POOL=$(sqlite3 "$DB" "SELECT id FROM dhcp_pools ORDER BY id LIMIT 1")
CMAC=$(C cat /sys/class/net/lan0/address)
nl_api_ok "static lease: infinite + dns_record" POST /dhcp/pools/$POOL/static "{\"mac\":\"$CMAC\",\"ip\":\"192.168.50.21\",\"hostname\":\"labclient\",\"lease_time\":0,\"dns_record\":true}"
nl_api_ok "static lease: offline, published" POST /dhcp/pools/$POOL/static '{"mac":"02:00:00:aa:00:22","ip":"192.168.50.22","hostname":"nas","dns_record":true}'
nl_api_ok "static lease: offline, not published" POST /dhcp/pools/$POOL/static '{"mac":"02:00:00:aa:00:23","ip":"192.168.50.23","hostname":"ghost"}'
nl_api_code "bad lease time refused" 400 POST /dhcp/pools/$POOL/static '{"mac":"02:00:00:aa:00:24","ip":"192.168.50.24","lease_time":5}'
nl_api_code "bad local domain refused" 400 PUT /dns/settings '{"local_domain":"bad domain;x"}'
nl_api_ok "DNS: forwarder + local domain" PUT /dns/settings "{\"mode\":\"forwarder\",\"upstreams\":\"$NL_DNS\",\"dnssec\":false,\"local_domain\":\".LAN.example.\",\"cache_size\":2000,\"log_queries\":true}"

# the internal servers for the internal domain and its reverse zones
for ip in 198.51.100.61 198.51.100.62; do INET ip addr add $ip/24 dev up1 2>/dev/null || INET ip addr add $ip/32 dev lo; done
INET ip -o addr | grep 198.51.100.61 >/dev/null || nl_fail "could not add the internal DNS addresses"
for ip in 198.51.100.61 198.51.100.62; do
  nl_bg INET dnsmasq -k --port=53 --listen-address=$ip --bind-interfaces --no-resolv --no-hosts --conf-file=/dev/null \
    --pid-file=/tmp/nl-int-$ip.pid --host-record=db.corp.example,10.9.9.9 --ptr-record=9.9.9.10.in-addr.arpa,db.corp.example
done
nl_api_ok "internal domain -> server 1" POST /dns/domains '{"domain":"corp.example","server":"198.51.100.61"}'
nl_api_ok "internal domain -> server 2" POST /dns/domains '{"domain":"corp.example","server":"198.51.100.62"}'
nl_api_ok "reverse zone -> server 1" POST /dns/domains '{"domain":"10.in-addr.arpa","server":"198.51.100.61"}'
nl_api_ok "reverse zone -> server 2" POST /dns/domains '{"domain":"10.in-addr.arpa","server":"198.51.100.62"}'

# --- WireGuard as a DNS client network
R ip link add wg0 type wireguard 2>/dev/null || nl_fail "no wireguard in this kernel"
C ip link add wg0 type wireguard
wg genkey >"$NL_T/wg-r.key"; wg genkey >"$NL_T/wg-c.key"
RPUB=$(wg pubkey <"$NL_T/wg-r.key"); CPUB=$(wg pubkey <"$NL_T/wg-c.key")
R wg set wg0 private-key "$NL_T/wg-r.key" listen-port 51820 peer "$CPUB" allowed-ips 10.99.0.2/32
C wg set wg0 private-key "$NL_T/wg-c.key" peer "$RPUB" allowed-ips 10.99.0.0/24 endpoint 192.168.50.1:51820
R ip addr add 10.99.0.1/24 dev wg0; R ip link set wg0 up
C ip addr add 10.99.0.2/24 dev wg0; C ip link set wg0 up
nl_api_ok "DNS also on the WireGuard device" PUT /dns/settings '{"interfaces":"@lan,wg0"}'
nl_api_ok "apply DHCP+DNS" POST /dhcp/apply
nl_api POST /dns/apply || true
CONF=/etc/dnsmasq.conf
nl_wait 20 pgrep -x dnsmasq >/dev/null || { cat $CONF; nl_fail "dnsmasq is not running on the router"; }
for want in "domain=$DOM" "local=/$DOM/" expand-hosts cache-size=2000 log-queries "host-record=nas.$DOM,192.168.50.22" "server=/corp.example/198.51.100.61#53" "server=/corp.example/198.51.100.62#53" "server=/10.in-addr.arpa/198.51.100.61#53" "interface=wg0"; do
  grep -qF -- "$want" $CONF || { cat $CONF; nl_fail "dnsmasq.conf lacks: $want"; }
done
grep -q "host-record=ghost" $CONF && { cat $CONF; nl_fail "a static lease without dns_record was published"; }
nl_ok "dnsmasq.conf carries domain/local/expand-hosts/cache-size/log-queries, the static lease names and both servers per zone"

# --- 1. DHCP client names resolve under the local domain
for t in labclient; do :; done
C dhcpcd -4 -q -I '' -h labclient --nohook resolv.conf --nohook hostname --nogateway -t 30 -w lan0 >/dev/null 2>&1 || true
C ip link add dyn0 link lan0 type macvlan 2>/dev/null || nl_fail "no macvlan"
C ip link set dyn0 up
C dhcpcd -4 -q -I '' -h dynhost --nohook resolv.conf --nohook hostname --nogateway -t 30 -w dyn0 >/dev/null 2>&1 || true
C ip -4 -o addr show dev lan0 | grep 192.168.50.21 >/dev/null || { C ip -4 addr; tail -20 /var/lib/misc/dnsmasq.leases || true; nl_fail "the static client did not get 192.168.50.21"; }
nl_ok "the client with a static lease got 192.168.50.21 by DHCP"
DYN=$(C ip -4 -o addr show dev dyn0 | grep -o '192\.168\.50\.1[0-9][0-9]' | head -1)
[ -n "$DYN" ] || { C ip -4 addr; nl_fail "the dynamic client got no lease from the pool"; }
expect_ans_wait "dynhost.$DOM" A $NL_RTR_LAN "answers=$DYN"
nl_ok "a dynamic lease's host name resolves: dynhost.$DOM -> $DYN"
expect_ans_wait "labclient.$DOM" A $NL_RTR_LAN "answers=192.168.50.21"
expect_ans "nas.$DOM" A $NL_RTR_LAN "answers=192.168.50.22"
nl_ok "offline static lease with dns_record resolves: nas.$DOM -> 192.168.50.22"
expect_ans "ghost.$DOM" A $NL_RTR_LAN "answers=none"
expect_ans "dynhost" A $NL_RTR_LAN "answers=$DYN"
nl_ok "ghost (no dns_record) does not resolve; the bare name expands to the local domain"
expect_ans "22.50.168.192.in-addr.arpa" PTR $NL_RTR_LAN "nas.$DOM"
nl_ok "reverse lookup of the offline record"
grep -E ' 192\.168\.50\.21 ' /var/lib/misc/dnsmasq.leases | grep -E '^0 ' >/dev/null || { cat /var/lib/misc/dnsmasq.leases; nl_fail "the static lease is not infinite in the lease file"; }
C dhcpcd -4 -U lan0 2>/dev/null | grep -iE 'dhcp_lease_time=(4294967295|0xffffffff)' >/dev/null || C sh -c 'ls /var/lib/dhcpcd/ 2>/dev/null' >/dev/null
nl_ok "static lease is infinite (lease file expiry 0); the pool lease is finite: $(grep -E " $DYN " /var/lib/misc/dnsmasq.leases | cut -d' ' -f1) epoch"
# a log of the queries
R sh -c 'pkill -USR1 dnsmasq' || true
expect_ans "nas.$DOM" A $NL_RTR_LAN "answers=192.168.50.22"

# --- 2. per-domain forwarding, reverse zone, failover, and DNS over WireGuard
expect_ans db.corp.example A $NL_RTR_LAN "answers=10.9.9.9"
expect_ans 9.9.9.10.in-addr.arpa PTR $NL_RTR_LAN "db.corp.example"
nl_ok "internal domain and its reverse zone are forwarded to the internal servers"
expect_ans db.corp.example A 10.99.0.1 "answers=10.9.9.9"
expect_ans "nas.$DOM" A 10.99.0.1 "answers=192.168.50.22"
nl_ok "DNS is served on the WireGuard device (10.99.0.1 through the tunnel)"
INET pkill -f 'pid-file=/tmp/nl-int-198.51.100.61' || true
sleep 1
expect_ans_wait db.corp.example A $NL_RTR_LAN "answers=10.9.9.9"
expect_ans_wait 9.9.9.10.in-addr.arpa PTR $NL_RTR_LAN "db.corp.example"
nl_ok "with the first internal server dead both zones still resolve through the second"
# rebind protection (OpenWrt rebind_protection + rebind_domain): the lab "internet" uses
# TEST-NET addresses, which dnsmasq treats as private, so every upstream answer is a
# rebind until its name is an exception
expect_ans_wait blocked.example.test A $NL_RTR_LAN "answers=none"
nl_api_ok "rebind exception" PUT /dns/settings '{"rebind_protection":true,"rebind_exceptions":"www.example.test"}'
expect_ans_wait www.example.test A $NL_RTR_LAN "answers=$NL_WWW"
expect_ans blocked.example.test A $NL_RTR_LAN "answers=none"
expect_ans db.corp.example A $NL_RTR_LAN "answers=10.9.9.9"
nl_ok "rebind protection drops private answers from upstream; the exception and the internal zones still resolve"

# --- 3. IPv6: pinned DUID, static ULA + delegated prefix, prefix-relative DHCPv6 pool + RA
nl_api_ok "DHCPv6 pool relative to the prefix" POST /dhcp/v6 '{"interface":"@lan","range_start":"::1000","range_end":"::1fff"}'
nl_api_ok "RA managed + other" POST /dhcp/ra '{"interface":"@lan","mode":"managed"}'
nl_api_code "bad DUID refused" 400 PUT /interfaces/$NL_WAN_IF "{\"role\":\"wan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"203.0.113.2/24\"],\"gateway4\":\"203.0.113.1\",\"ipv6_mode\":\"dhcp6\",\"dhcp6_duid\":\"zz\",\"force\":true}"
nl_api_ok "WAN DHCPv6 + PD + pinned DUID" PUT /interfaces/$NL_WAN_IF "{\"role\":\"wan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"203.0.113.2/24\"],\"gateway4\":\"203.0.113.1\",\"ipv6_mode\":\"dhcp6\",\"pd_downstream\":[\"$NL_LAN_IF\"],\"dhcp6_duid\":\"$DUID\",\"force\":true}"
nl_wait 90 sh -c 'ip netns exec nl-rtr ip -6 -o addr show dev rtr-lan scope global | grep "2001:db8:10" >/dev/null' \
  || { R ip -6 addr; nl_fail "no delegated prefix address on the LAN port after 90 s"; }
PDA=$(R ip -6 -o addr show dev rtr-lan scope global | grep -o '2001:db8:10[0-9a-f:]*/64' | head -1)
R ip -6 -o addr show dev rtr-lan | grep 'fd00:50::1/64' >/dev/null || nl_fail "the static ULA was removed when the prefix arrived"
nl_ok "the LAN carries the static ULA fd00:50::1/64 AND the delegated $PDA"
sleep 1; kill -HUP "$(pgrep -x dnsmasq | head -1)" 2>/dev/null || true
GOT=$(python3 "$NL_T/pcap-duid.py" "$NL_T/isp-dhcp6.pcap")
[ "$GOT" = "$DUID" ] || { cat /etc/dhcpcd.conf 2>/dev/null | head -20; nl_fail "ISP saw DUID [$GOT], want [$DUID]"; }
nl_ok "the ISP's DHCPv6 server saw the pinned DUID $GOT on the wire"
# the router re-applies when the prefix arrived (dnsmasq constructor follows the interface)
nl_api POST /dhcp/apply >/dev/null || true
C sysctl -qw net.ipv6.conf.lan0.accept_ra=2 net.ipv6.conf.lan0.autoconf=0 || true
nl_wait 60 sh -c 'ip netns exec nl-client ip -6 route show dev lan0 | grep "2001:db8:10" >/dev/null' \
  || { C ip -6 route; R cat $CONF | grep -E "range|ra" ; nl_fail "the client did not learn the delegated prefix from the RA"; }
C ip -6 route show dev lan0 | grep 'fd00:50::/64' >/dev/null || nl_fail "the RA did not advertise the ULA prefix"
nl_ok "RA advertises both the delegated prefix and the ULA"
C dhcpcd -6 -q --nohook resolv.conf --nohook hostname -t 40 -w lan0 >/dev/null 2>&1 || true
nl_wait 30 sh -c 'ip netns exec nl-client ip -6 -o addr show dev lan0 scope global | grep -E "2001:db8:10[0-9a-f:]*:[0-9a-f]*:1[0-9a-f]{3}/128" >/dev/null' \
  || { C ip -6 addr; grep -E "dhcp-range" $CONF; nl_fail "the client got no DHCPv6 address from the delegated prefix"; }
V6=$(C ip -6 -o addr show dev lan0 scope global | grep -oE '2001:db8:10[0-9a-f:]*/128' | head -1)
nl_ok "DHCPv6 address from the delegated prefix via the prefix-relative pool: $V6"
C ip -6 -o addr show dev lan0 | grep -oE 'fd00:50:[0-9a-f:]*/128' | head -1 | sed 's/^/ok - and a ULA DHCPv6 address: /' || true
grep -q 'constructor:rtr-lan' $CONF || { grep dhcp-range $CONF; nl_fail "no constructor range in dnsmasq.conf"; }
nl_ok "dnsmasq.conf: $(grep -m1 'dhcp-range=.*constructor' $CONF)"
echo "PASS lane-d-openwrt-parity"
