#!/usr/bin/env bash
# Lane D (OpenWrt migration): `patronus import-uci` turns an x86 OpenWrt
# router's configuration (ci/netlab/fixtures/uci-router: dnsmasq local
# domain + per-domain forwarding, static lease with an infinite lease and a
# DNS record, firewall REJECT/synflood/MSS/IP-options include, a WireGuard
# server whose peers keep their old configs, a port forward, a static route,
# a ULA prefix) into the store in one step, and the imported box works with
# real packets:
#   1. the import report never shows a key or password; a second run adds nothing
#   2. dnsmasq: local domain, static lease name, host records, both servers of
#      the internal zone, the reverse zone, cache size, query log
#   3. nftables: REJECT on the WAN, SYN flood limit, MSS clamp, the IPv4
#      options drop, the port forward, masquerade of the LAN and the tunnel
#   4. WireGuard: same server key and port; a peer using its OLD client config
#      (key + endpoint on the WAN address) connects unchanged, reaches the LAN,
#      resolves names through the tunnel, and the static route through it exists
#   5. the static-lease client gets its address and its name resolves
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-d-uci-import.db
rm -f "$DB" "$NL_T/nl-jar"
command -v dnsmasq >/dev/null || nl_fail "dnsmasq is not installed"
for t in dhcpcd wg; do command -v $t >/dev/null || nl_fail "$t is not installed"; done
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
# a tiny A-record client: nl-a.py NAME SERVER -> first address or "none"
cat >"$NL_T/nl-a.py" <<'PY'
import socket, struct, sys
name, server = sys.argv[1], sys.argv[2]
q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, (server, 53)); d, _ = s.recvfrom(4096)
except OSError:
    print("timeout"); sys.exit(0)
an = struct.unpack("!H", d[6:8])[0]; i = 12
while d[i]: i += d[i] + 1
i += 5
for _ in range(an):
    i += 2 if d[i] & 0xC0 == 0xC0 else (d.index(b"\x00", i) - i + 1)
    ty, _, _, ln = struct.unpack("!HHIH", d[i:i + 10]); i += 10
    if ty == 1: print(socket.inet_ntoa(d[i:i + 4])); sys.exit(0)
    i += ln
print("none")
PY

# the router's configuration, as read from it (secrets are test values)
U=$NL_T/uci-router
rm -rf "$U"; cp -r "$(dirname "$0")/fixtures/uci-router" "$U"
SRV_PRIV=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
PEER_PRIV=cEhzR3xbVwCJk9i0e6dbHUeW8wy9vEaRbNk+9bk5TlE=
SRV_PUB=$(printf '%s' "$SRV_PRIV" | wg pubkey)
PEER_PUB=$(printf '%s' "$PEER_PRIV" | wg pubkey)
sed -i "s|PLACEHOLDER-SITE-B-PUB|$PEER_PUB|" "$U/etc/config/network"
MAPS=(--map lan=$NL_LAN_IF --map wan=$NL_WAN_IF --map vpn=wg0)

nl_up
R "$P" --db "$DB" import-uci "$U" "${MAPS[@]}" --dry-run >"$NL_T/imp-dry.txt" 2>&1 \
  || { cat "$NL_T/imp-dry.txt"; nl_fail "import-uci --dry-run failed"; }
R "$P" --db "$DB" import-uci "$U" "${MAPS[@]}" >"$NL_T/imp.txt" 2>&1 \
  || { cat "$NL_T/imp.txt"; nl_fail "import-uci failed"; }
for s in "$SRV_PRIV" "$PEER_PRIV" FpCyhws9cxwWoV4xELtfJvjJN; do
  if grep -F -- "$s" "$NL_T/imp-dry.txt" "$NL_T/imp.txt" >/dev/null; then nl_fail "the import report shows a key"; fi
done
grep -F "tunnel wg0" "$NL_T/imp-dry.txt" >/dev/null || { cat "$NL_T/imp-dry.txt"; nl_fail "dry run does not list the tunnel"; }
nl_ok "import-uci: dry run + import, no key in either report ($(grep -c . "$NL_T/imp.txt") report lines)"
R "$P" --db "$DB" import-uci "$U" "${MAPS[@]}" >"$NL_T/imp2.txt" 2>&1 || { cat "$NL_T/imp2.txt"; nl_fail "second import failed"; }
grep -F "wireguard wg0: already present" "$NL_T/imp2.txt" >/dev/null || { cat "$NL_T/imp2.txt"; nl_fail "second run is not idempotent"; }
[ "$(sqlite3 "$DB" 'SELECT count(*) FROM wg_peers')" = 2 ] || nl_fail "peers duplicated"
nl_ok "a second import adds nothing"

nl_write_installer_toml
nl_dnsmasq_shim
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "patronus apply of the imported store failed"; }
nl_ok "boot: patronus apply of the imported store"

# --- 2. DNS / DHCP
for ip in 198.51.100.61 198.51.100.62; do INET ip addr add $ip/24 dev inet0; done
for ip in 198.51.100.61 198.51.100.62; do
  nl_bg INET dnsmasq -k --port=53 --listen-address=$ip --bind-interfaces --no-resolv --no-hosts --conf-file=/dev/null \
    --pid-file=/tmp/nl-int-$ip.pid --host-record=db.corp.example,10.9.9.9 --ptr-record=9.9.9.10.in-addr.arpa,db.corp.example
done
CONF=/etc/dnsmasq.conf
nl_wait 20 pgrep -x dnsmasq >/dev/null || { cat $CONF; nl_fail "dnsmasq is not running"; }
for want in domain=home.example local=/home.example/ expand-hosts cache-size=1000 log-queries \
  "host-record=nas.home.example,192.168.50.21" "server=/corp.example/198.51.100.61#53" \
  "server=/corp.example/198.51.100.62#53" "server=/10.in-addr.arpa/198.51.100.61#53"; do
  grep -F -- "$want" $CONF >/dev/null || { cat $CONF; nl_fail "dnsmasq.conf lacks: $want"; }
done
nl_ok "dnsmasq.conf: local domain, static lease name, both internal servers, reverse zone, cache, query log"

# --- 3. firewall
RS=$(R nft list ruleset)
chk() { case "$RS" in *"$1"*) ;; *) echo "$RS"; nl_fail "ruleset lacks: $1";; esac; }
chk "reject with tcp reset"
chk "limit rate over"
chk "maxseg size set rt mtu"
chk "ip hdrlength > 5"
chk "udp dport 51820 accept"
chk "dnat ip to 192.168.50.10:9000"
nl_ok "nftables: REJECT, SYN flood, MSS clamp, IP options drop, WireGuard port open, port forward"
C ip addr add 192.168.50.10/24 dev lan0 2>/dev/null || true
nl_expect_tcp "WAN -> port forward 9100 -> LAN host :9000" ISP $NL_RTR_WAN 9100

# --- 4. WireGuard with the peer's old config (endpoint = the WAN address)
nl_wait 20 sh -c 'ip netns exec nl-rtr wg show wg0 public-key >/dev/null 2>&1' || nl_fail "wg0 is not up"
[ "$(R wg show wg0 public-key)" = "$SRV_PUB" ] || nl_fail "the server key changed"
[ "$(R wg show wg0 listen-port)" = 51820 ] || nl_fail "the listen port changed"
nl_ok "wg0 keeps the old server key and port"
printf '%s' "$PEER_PRIV" >"$NL_T/peer.key"
ISP ip link add wgc type wireguard
ISP wg set wgc private-key "$NL_T/peer.key" peer "$SRV_PUB" allowed-ips 10.99.0.0/24,192.168.50.0/24 endpoint $NL_RTR_WAN:51820 persistent-keepalive 5
ISP ip addr add 10.99.0.9/24 dev wgc; ISP ip link set wgc up
ISP ip route add 192.168.50.0/24 dev wgc
nl_wait 20 sh -c 'ip netns exec nl-isp ping -c1 -W1 10.99.0.1 >/dev/null 2>&1' || { R wg show; nl_fail "the peer cannot reach the server through the tunnel"; }
nl_ok "the peer's unchanged config connects (handshake at $(R wg show wg0 latest-handshakes | awk '{print $2}'))"
nl_expect_tcp "tunnel peer -> LAN host" ISP 192.168.50.10 9000
R ip route show 10.200.0.0/24 | grep 10.99.0.9 >/dev/null || { R ip route; nl_fail "no route to the site behind the peer"; }
nl_ok "static route 10.200.0.0/24 via the tunnel peer"
GOT=$(ISP python3 "$NL_T/nl-a.py" router.home.example 10.99.0.1)
[ "$GOT" = 192.168.50.1 ] || { cat $CONF; nl_fail "DNS through the tunnel: got [$GOT]"; }
nl_ok "DNS answers through the tunnel (router.home.example -> $GOT)"

# --- 5. static lease
C ip addr flush dev lan0
C ip link set lan0 down; C ip link set lan0 address 02:00:00:00:00:21; C ip link set lan0 up
C dhcpcd -4 -q -I '' --nohook resolv.conf --nohook hostname --nogateway -t 30 -w lan0 >/dev/null 2>&1 || true
C ip -4 -o addr show dev lan0 | grep 192.168.50.21 >/dev/null || { C ip -4 addr; nl_fail "the static-lease client did not get 192.168.50.21"; }
GOT=$(C python3 "$NL_T/nl-a.py" nas.home.example $NL_RTR_LAN)
[ "$GOT" = 192.168.50.21 ] || nl_fail "nas.home.example -> [$GOT]"
GOT=$(C python3 "$NL_T/nl-a.py" db.corp.example $NL_RTR_LAN)
[ "$GOT" = 10.9.9.9 ] || nl_fail "internal zone forwarding: db.corp.example -> [$GOT]"
nl_ok "static lease 192.168.50.21 by DHCP, nas.home.example resolves, the internal zone forwards"
C dhcpcd -k lan0 >/dev/null 2>&1 || true
echo "PASS lane-d-uci-import"
