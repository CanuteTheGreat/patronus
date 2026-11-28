#!/usr/bin/env bash
# Lane J: DHCPv6 relay agent (USE=dhcp6-relay). LAN clients (namespace nl-client,
# and a second segment "guest", namespace nl-g) can only reach a DHCPv6 server
# that sits on a third segment (OPT1, "IoT", namespace nl-iot) if the router
# relays for them. Two servers are used:
#   - a PROBE (python) that records every Relay-forward it receives field by
#     field (hop-count, link-address, peer-address, Interface-Id, inner message)
#     and answers with a Relay-reply, so the wire format is checked exactly;
#   - the real ISC dhcpd (subnet6 per client segment), so a real client
#     exchange (Solicit/Advertise/Request/Reply) is proven end to end: the
#     address comes from the pool of the segment the client is on, which only
#     works if the relay names that segment (link-address / Interface-Id) and
#     returns the answer on the right interface.
# Every check first proves the negative (no relay: no answer).
#   - unicast server, all-servers multicast (ff02::1:2) on the upstream link
#   - two client interfaces to one server, each served from its own pool
#   - Interface-Id on and off (the link-address alone must still decide)
#   - a downstream relay's Relay-forward: hop-count + 1, link-address ::,
#     the answer goes to port 547 of the downstream relay; hop limit drops
#   - server-type messages from clients and Relay-replies from a host that is
#     not the configured server are not relayed
#   - validation refuses bad servers/interfaces (400), nothing starts
#   - firewall opens udp/547 on the client interface only; survives reboot
set -euo pipefail
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"   # the relay daemon is `patronus dhcp6-relay run`
DB=/t/lane-j-dhcp6-relay.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v dhcpd >/dev/null || apt-get install -y -qq isc-dhcp-server >/dev/null 2>&1 || true
command -v dhcpd >/dev/null || nl_fail "isc dhcpd is not installed"
nl_write_installer_toml
nl_kill_daemons
LAN6=2001:db8:50::1
IOT_RTR6=2001:db8:60::1
IOT_SRV6=2001:db8:60::2
IOT_SPOOF6=2001:db8:60::99
G6=2001:db8:70::1

net_up() {
  for ns in nl-iot nl-g; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip -n $ns link set lo up; done
  ip link add rtr-iot netns nl-rtr type veth peer name iot0 netns nl-iot
  ip link add rtr-g netns nl-rtr type veth peer name g0 netns nl-g
  R ip link set rtr-iot up; R ip link set rtr-g up
  ip -n nl-iot link set iot0 up; ip -n nl-g link set g0 up
  R ip addr add 10.60.0.1/24 dev rtr-iot
  R ip addr add 10.70.0.1/24 dev rtr-g
}
v6_addrs() {
  R ip -6 addr replace $LAN6/64 dev rtr-lan nodad
  R ip -6 addr replace $IOT_RTR6/64 dev rtr-iot nodad
  R ip -6 addr replace $G6/64 dev rtr-g nodad
  ip -n nl-iot -6 addr replace $IOT_SRV6/64 dev iot0 nodad
  ip -n nl-iot -6 addr replace $IOT_SPOOF6/64 dev iot0 nodad
  settled
}
no_tentative() {
  local n
  for n in nl-rtr nl-client nl-iot nl-g; do
    [ -z "$(ip -n $n -6 addr show tentative)" ] || return 1
  done
}
settled() { nl_wait 10 no_tentative || nl_fail "link-local addresses stayed tentative"; }

cat > "$NL_T/nl-d6.py" <<'PY'
# nl-d6.py client DEV [full]     DHCPv6 client: Solicit (+ Request) to ff02::1:2; prints "ADV src addr" / "REPLY src addr" / "TIMEOUT"
# nl-d6.py listen DEV SECS       print every datagram received on port 546 ("GOT type src")
# nl-d6.py sendtype DEV TYPE     send a bare message of this type to ff02::1:2 (a client must never send server types)
# nl-d6.py relayc DEV HOP        act as a downstream relay: Relay-forward (hop HOP) from port 547; prints "RREPL hop link peer innertype"
# nl-d6.py probe DEV LOG [mcast] server probe on port 547: logs every Relay-forward as JSON, answers with a Relay-reply
# nl-d6.py spoof SRC DST DEV IID  send a Relay-reply (wrapping an Advertise) from SRC to DST:547
import json, os, select, socket, struct, sys, time

def ifx(n): return socket.if_nametoindex(n)
def opt(c, d): return struct.pack("!HH", c, len(d)) + d
def opts(b):
    i, d = 0, {}
    while i + 4 <= len(b):
        c, l = struct.unpack("!HH", b[i:i + 4]); d.setdefault(c, b[i + 4:i + 4 + l]); i += 4 + l
    return d
def sock(dev, port):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::", port))
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifx(dev))
    return s
def duid(dev):
    mac = open(f"/sys/class/net/{dev}/address").read().strip().replace(":", "")
    return struct.pack("!HH", 3, 1) + bytes.fromhex(mac)
def src(a): return a[0].split("%")[0]
def iaaddr(msg):
    ia = opts(msg[4:]).get(3)
    if not ia: return None
    a = opts(ia[12:]).get(5)
    return socket.inet_ntop(socket.AF_INET6, a[:16]) if a else None
def recv(s, t, want=None):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 0.2)
        if r:
            b, a = s.recvfrom(9000)
            if want is None or want(b): return b, a
    return None, None

def client(dev, full):
    s = sock(dev, 546); d = duid(dev); xid = os.urandom(3)
    ia = struct.pack("!III", 1, 0, 0)
    s.sendto(bytes([1]) + xid + opt(1, d) + opt(8, b"\0\0") + opt(3, ia), ("ff02::1:2", 547, 0, ifx(dev)))
    b, a = recv(s, 6, lambda b: b[0] == 2 and b[1:4] == xid)
    if b is None: print("TIMEOUT"); return
    addr = iaaddr(b)
    print("ADV", src(a), addr or "none", flush=True)
    if not full or not addr: return
    xid2 = os.urandom(3)
    iaopt = opt(5, socket.inet_pton(socket.AF_INET6, addr) + struct.pack("!II", 0, 0))
    req = bytes([3]) + xid2 + opt(1, d) + opt(2, opts(b[4:])[2]) + opt(8, b"\0\0") + opt(3, ia + iaopt)
    s.sendto(req, ("ff02::1:2", 547, 0, ifx(dev)))
    b, a = recv(s, 6, lambda b: b[0] == 7 and b[1:4] == xid2)
    print("REPLY", src(a) if a else "-", iaaddr(b) if b else "none", flush=True)

def listen(dev, secs):
    s = sock(dev, 546); print("listening", flush=True)
    end = time.time() + float(secs)
    while time.time() < end:
        b, a = recv(s, 0.5)
        if b: print("GOT", b[0], src(a), flush=True)

def sendtype(dev, t):
    s = sock(dev, 546)
    s.sendto(bytes([int(t)]) + os.urandom(3) + opt(1, duid(dev)), ("ff02::1:2", 547, 0, ifx(dev)))

def forw(hop, link, peer, inner, iid=None):
    o = (opt(18, iid) if iid else b"") + opt(9, inner)
    return bytes([12, hop]) + socket.inet_pton(socket.AF_INET6, link) + socket.inet_pton(socket.AF_INET6, peer) + o

def relayc(dev, hop):
    s = sock(dev, 547)
    xid = os.urandom(3)
    sol = bytes([1]) + xid + opt(1, struct.pack("!HH", 3, 1) + bytes(6)) + opt(3, struct.pack("!III", 1, 0, 0))
    s.sendto(forw(int(hop), "::", "fe80::dead:beef", sol), ("ff02::1:2", 547, 0, ifx(dev)))
    b, a = recv(s, 4, lambda b: b[0] == 13)
    if b is None: print("TIMEOUT"); return
    inner = opts(b[34:])[9]
    print("RREPL", b[1], socket.inet_ntop(socket.AF_INET6, b[2:18]), socket.inet_ntop(socket.AF_INET6, b[18:34]), inner[0], src(a), flush=True)

def answer(m):
    if m[0] == 12:
        o = opts(m[34:])
        r = bytes([13]) + m[1:2] + m[2:34]
        if 18 in o: r += opt(18, o[18])
        return r + opt(9, answer(o[9]))
    return bytes([2]) + m[1:4] + opt(1, opts(m[4:]).get(1, b"")) + opt(2, struct.pack("!HH", 3, 1) + bytes.fromhex("020000000099"))

def probe(dev, log, mcast):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::", 547))
    if mcast:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, socket.inet_pton(socket.AF_INET6, "ff02::1:2") + struct.pack("@I", ifx(dev)))
    f = open(log, "a", buffering=1); print("listening", file=f)
    while True:
        b, a = s.recvfrom(9000)
        if b[0] != 12 or len(b) < 34: continue
        o = opts(b[34:])
        d = {"hop": b[1], "link": socket.inet_ntop(socket.AF_INET6, b[2:18]), "peer": socket.inet_ntop(socket.AF_INET6, b[18:34]),
             "iid": o[18].decode() if 18 in o else None, "inner": o[9][0] if 9 in o else None,
             "innerlen": len(o[9]) if 9 in o else 0, "from": src(a), "sport": a[1], "dst_mcast": bool(mcast)}
        print(json.dumps(d), file=f)
        s.sendto(answer(b), a)

def spoof(sa, dst, dev, iid):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sa, 547))
    adv = bytes([2]) + os.urandom(3) + opt(1, b"x" * 10) + opt(2, b"y" * 10)
    s.sendto(bytes([13, 0]) + bytes(16) + socket.inet_pton(socket.AF_INET6, "fe80::1") + opt(18, iid.encode()) + opt(9, adv), (dst, 547))

a = sys.argv[1:]
{"client": lambda: client(a[1], len(a) > 2), "listen": lambda: listen(a[1], a[2]), "sendtype": lambda: sendtype(a[1], a[2]),
 "relayc": lambda: relayc(a[1], a[2]), "probe": lambda: probe(a[1], a[2], len(a) > 3), "spoof": lambda: spoof(a[1], a[2], a[3], a[4])}[a[0]]()
PY

cat > "$NL_T/dhcpd6.conf" <<'CONF'
default-lease-time 600;
max-lease-time 1200;
ddns-update-style none;
authoritative;
subnet6 2001:db8:60::/64 { range6 2001:db8:60::100 2001:db8:60::110; }
subnet6 2001:db8:50::/64 { range6 2001:db8:50::100 2001:db8:50::110; }
subnet6 2001:db8:70::/64 { range6 2001:db8:70::100 2001:db8:70::110; }
CONF

SRV_PID=""
stop_srv() {
  if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true; SRV_PID=""; fi
  # dhcpd/probe left by an earlier run of this lane inside the namespace
  pkill -f '[n]l-d6.py probe' 2>/dev/null || true
  pkill -x dhcpd 2>/dev/null || true
  sleep 0.3
}
PLOG=$NL_T/probe.log
start_probe() { # [mcast]
  stop_srv; : > "$PLOG"
  ip netns exec nl-iot python3 "$NL_T/nl-d6.py" probe iot0 "$PLOG" "$@" >"$NL_T/probe.out" 2>&1 &
  SRV_PID=$!
  nl_wait 8 grep -F listening "$PLOG" || { cat "$NL_T/probe.out"; nl_fail "probe did not start"; }
}
start_dhcpd() {
  stop_srv; : > "$NL_T/dhcpd6.leases"
  ip netns exec nl-iot dhcpd -6 -d -cf "$NL_T/dhcpd6.conf" -lf "$NL_T/dhcpd6.leases" iot0 >"$NL_T/dhcpd.log" 2>&1 &
  SRV_PID=$!
  nl_wait 10 grep -F "Server starting service" "$NL_T/dhcpd.log" || { cat "$NL_T/dhcpd.log"; nl_fail "dhcpd did not start"; }
}
probe_n() { local n; n=$(grep -c . "$PLOG" || true); echo $((n - 1)); }   # first line is "listening"
probe_last() { tail -n 1 "$PLOG"; }
jf() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d[sys.argv[2]])' "$1" "$2"; }
client_ll() { ip -n nl-client -6 -j addr show dev lan0 scope link | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["addr_info"][0]["local"])'; }
dc() { ip netns exec "$1" python3 "$NL_T/nl-d6.py" "${@:2}"; }   # dc NAMESPACE ARGS...

diag() {
  set +e
  echo "--- diag: relay processes"; ps -eo pid,stat,args | grep '[d]hcp6-relay'
  echo "--- diag: stats"; cat /run/patronus/dhcp6-relay.stats /var/lib/patronus/net/run/dhcp6-relay.stats 2>/dev/null
  echo "--- diag: relay config"; cat /var/lib/patronus/net/dhcp6-relay.json 2>/dev/null
  echo "--- diag: probe log"; cat "$PLOG" 2>/dev/null
  echo "--- diag: dhcpd"; tail -20 "$NL_T/dhcpd.log" 2>/dev/null
  echo "--- diag: sockets in the router"; R ss -6lunp 2>/dev/null
  echo "--- diag: nft input"; R nft list chain inet patronus input 2>/dev/null | head -40
  echo "--- diag: relay log"; tail -5 /var/log/patronus-daemon.dhcp6-relay.log /var/lib/patronus/net/log/*dhcp6-relay* 2>/dev/null
}
trap 'rc=$?; [ $rc = 0 ] || diag; stop_srv' EXIT

nl_up; net_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login
nl_api_ok "OPT1 on the server segment" PUT /interfaces/rtr-iot '{"role":"opt1","ipv4_mode":"static","ipv4":["10.60.0.1/24"]}'
nl_api_ok "OPT2 on the guest segment" PUT /interfaces/rtr-g '{"role":"opt2","ipv4_mode":"static","ipv4":["10.70.0.1/24"]}'
v6_addrs

echo "=== without the relay a client gets no answer"
start_probe
out=$(dc nl-client client lan0)
[ "$out" = TIMEOUT ] || nl_fail "client heard an answer with no relay: $out"
[ "$(probe_n)" = 0 ] || nl_fail "the server saw a message with no relay"
nl_ok "no relay: the Solicit stays on the client segment"

echo "=== validation"
nl_api_code "not an IPv6 address" 400 POST /svc/dhcp6-relay/rules '{"iface":"@lan","server":"192.0.2.1"}'
nl_api_code "garbage server" 400 POST /svc/dhcp6-relay/rules '{"iface":"@lan","server":"x;y"}'
nl_api_code "no server" 400 POST /svc/dhcp6-relay/rules '{"iface":"@lan"}'
nl_api_code "no interface" 400 POST /svc/dhcp6-relay/rules "{\"server\":\"$IOT_SRV6\"}"
nl_api_code "bad interface" 400 POST /svc/dhcp6-relay/rules "{\"iface\":\"lan;x\",\"server\":\"$IOT_SRV6\"}"
nl_api_code "bad hop limit" 400 PUT /svc/dhcp6-relay '{"hop_limit":0}'
nl_api_code "hop limit too high" 400 PUT /svc/dhcp6-relay '{"hop_limit":33}'
nl_api_code "enable without rules" 400 PUT /svc/dhcp6-relay '{"enabled":true}'
nl_api_ok "a multicast rule row without an upstream is stored" POST /svc/dhcp6-relay/rules '{"iface":"@lan","server":"ff02::1:2","description":"needs upstream"}'
nl_api_code "but it cannot be applied" 400 PUT /svc/dhcp6-relay '{"enabled":true}'
nl_api GET /svc/dhcp6-relay
RID=$(nl_json "$NL_OUT" 'd["collections"]["rules"][0]["id"]')
nl_api_ok "remove it" DELETE /svc/dhcp6-relay/rules/"$RID"
if R pgrep -f 'dhcp6-relay run' >/dev/null 2>&1; then nl_fail "relay started although the change was refused"; fi
nl_ok "bad servers, interfaces and limits and an unusable rule are refused (400), nothing started"

echo "=== unicast server: the Relay-forward on the wire"
nl_api_ok "rule: @lan -> probe" POST /svc/dhcp6-relay/rules "{\"iface\":\"@lan\",\"server\":\"$IOT_SRV6\",\"description\":\"lan to server\"}"
nl_api_ok "enable" PUT /svc/dhcp6-relay '{"enabled":true}'
nl_wait 10 pgrep -f 'dhcp6-relay run' || { tail -20 "$NL_T/nl-web.log"; nl_fail "relay daemon did not start"; }
CONF=/var/lib/patronus/net/dhcp6-relay.json
python3 - "$CONF" <<'PY' || { cat "$CONF"; nl_fail "generated relay config is wrong"; }
import json, sys
c = json.load(open(sys.argv[1]))
assert c["hop_limit"] == 32 and c["interface_id"] is True and c["rate_limit"] == 500, c
assert c["rules"] == [{"id": c["rules"][0]["id"], "iface": "rtr-lan", "server": "2001:db8:60::2", "upstream": None}], c
PY
nl_ok "relay running, config resolved @lan to rtr-lan"
listening547() { [ -n "$(R ss -6lunH | awk '$4 ~ /:547$/')" ]; }
nl_wait 8 listening547 || nl_fail "nothing listens on udp/547 in the router"
CLL=$(client_ll)
out=$(dc nl-client client lan0)
echo "$out"
case "$out" in "ADV $(R ip -6 -j addr show dev rtr-lan scope link | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["addr_info"][0]["local"])') "*) ;; *) nl_fail "Advertise did not come from the router's link-local address: $out";; esac
[ "$(probe_n)" = 1 ] || { cat "$PLOG"; nl_fail "the server must see exactly one Relay-forward, saw $(probe_n)"; }
L=$(probe_last)
[ "$(jf "$L" hop)" = 0 ] || nl_fail "hop-count: $L"
[ "$(jf "$L" link)" = "$LAN6" ] || nl_fail "link-address must be the interface's global address $LAN6: $L"
[ "$(jf "$L" peer)" = "$CLL" ] || nl_fail "peer-address must be the client's address $CLL: $L"
[ "$(jf "$L" iid)" = rtr-lan ] || nl_fail "Interface-Id: $L"
[ "$(jf "$L" inner)" = 1 ] || nl_fail "inner message must be the Solicit: $L"
[ "$(jf "$L" from)" = "$IOT_RTR6" ] || nl_fail "Relay-forward must come from the upstream address: $L"
[ "$(jf "$L" sport)" = 547 ] || nl_fail "Relay-forward must use source port 547 (servers answer there): $L"
nl_ok "Relay-forward: hop 0, link $LAN6, peer $CLL, Interface-Id rtr-lan, inner Solicit; the Advertise comes back from the router"

echo "=== a client never sends server messages; the relay does not forward them"
n0=$(probe_n)
for t in 2 7 13 0; do dc nl-client sendtype lan0 $t; done
sleep 1
[ "$(probe_n)" = "$n0" ] || { cat "$PLOG"; nl_fail "a server-type message from a client was relayed"; }
nl_ok "Advertise/Reply/Relay-reply/reserved types from a client are dropped"

echo "=== a Relay-reply from a host that is not the server is ignored"
dc nl-client listen lan0 4 > "$NL_T/lan-hears.txt" 2>&1 &
lp=$!
nl_wait 5 grep -F listening "$NL_T/lan-hears.txt" || true
ip netns exec nl-iot python3 "$NL_T/nl-d6.py" spoof $IOT_SPOOF6 $IOT_RTR6 iot0 rtr-lan
wait $lp || true
[ "$(grep -c GOT "$NL_T/lan-hears.txt" || true)" = 0 ] || { cat "$NL_T/lan-hears.txt"; nl_fail "a forged Relay-reply from $IOT_SPOOF6 reached the client"; }
nl_ok "forged Relay-reply from another host: not delivered"

echo "=== another relay's Relay-forward: hop + 1, link-address ::, answer to port 547"
n0=$(probe_n)
out=$(dc nl-client relayc lan0 3)
echo "$out"
[ "$(probe_n)" = $((n0 + 1)) ] || nl_fail "nested Relay-forward not relayed once"
L=$(probe_last)
[ "$(jf "$L" hop)" = 4 ] || nl_fail "hop-count must be 3 + 1: $L"
[ "$(jf "$L" link)" = "::" ] || nl_fail "link-address of a relayed Relay-forward must be ::: $L"
[ "$(jf "$L" peer)" = "$CLL" ] || nl_fail "peer-address must be the downstream relay ($CLL): $L"
[ "$(jf "$L" inner)" = 12 ] || nl_fail "inner message must be the downstream Relay-forward: $L"
case "$out" in "RREPL 3 :: fe80::dead:beef 2 "*) ;; *) nl_fail "downstream relay must get the inner Relay-reply (hop 3, peer fe80::dead:beef, wrapping an Advertise): $out";; esac
nl_ok "nested relay: hop 4 toward the server, the unwrapped Relay-reply reaches the downstream relay's port 547"
n0=$(probe_n)
out=$(dc nl-client relayc lan0 32)
[ "$out" = TIMEOUT ] && [ "$(probe_n)" = "$n0" ] || nl_fail "hop-count 32 must be dropped (limit 32): $out"
out=$(dc nl-client relayc lan0 31)
case "$out" in "RREPL 31 "*) ;; *) nl_fail "hop 31 + 1 = 32 is within the limit: $out";; esac
nl_ok "hop limit: 31 relayed (becomes 32), 32 dropped"

echo "=== real server (ISC dhcpd), two client interfaces, each served from its own pool"
nl_api_ok "rule: guest segment -> same server" POST /svc/dhcp6-relay/rules "{\"iface\":\"@opt2\",\"server\":\"$IOT_SRV6\"}"
python3 - "$CONF" <<'PY' || { cat "$CONF"; nl_fail "config after the second rule"; }
import json, sys
c = json.load(open(sys.argv[1]))
assert sorted(r["iface"] for r in c["rules"]) == ["rtr-g", "rtr-lan"], c
PY
nl_wait 10 grep -F rtr-g "$CONF" || true
start_dhcpd
sleep 1
out=$(dc nl-client client lan0 full); echo "$out"
echo "$out" | grep -E '^ADV .* 2001:db8:50::1[01][0-9a-f]$' >/dev/null || nl_fail "LAN client Advertise: want an address from 2001:db8:50::/64: $out"
echo "$out" | grep -E '^REPLY .* 2001:db8:50::1[01][0-9a-f]$' >/dev/null || nl_fail "LAN client Reply: $out"
nl_ok "LAN client: Solicit -> Advertise -> Request -> Reply, address from the LAN pool"
out=$(dc nl-g client g0 full); echo "$out"
echo "$out" | grep -E '^ADV .* 2001:db8:70::1[01][0-9a-f]$' >/dev/null || nl_fail "guest client Advertise: want an address from 2001:db8:70::/64: $out"
echo "$out" | grep -E '^REPLY .* 2001:db8:70::1[01][0-9a-f]$' >/dev/null || nl_fail "guest client Reply: $out"
nl_ok "guest client: its own pool (answer returned on the right interface)"
grep -F 'iaaddr 2001:db8:50::' "$NL_T/dhcpd6.leases" >/dev/null || { cat "$NL_T/dhcpd6.leases"; nl_fail "dhcpd has no lease from the LAN pool"; }
grep -F 'iaaddr 2001:db8:70::' "$NL_T/dhcpd6.leases" >/dev/null || nl_fail "dhcpd has no lease from the guest pool"
nl_ok "the server's lease file holds one lease per segment"

echo "=== Interface-Id off: the link-address alone decides"
nl_api_ok "interface_id off" PUT /svc/dhcp6-relay '{"interface_id":false}'
nl_wait 10 grep -F '"interface_id": false' "$CONF" || nl_fail "relay config not rewritten"
sleep 2
out=$(dc nl-g client g0 full); echo "$out"
echo "$out" | grep -E '^REPLY .* 2001:db8:70::1[01][0-9a-f]$' >/dev/null || nl_fail "without Interface-Id the guest client got no/wrong answer: $out"
out=$(dc nl-client client lan0); echo "$out"
echo "$out" | grep -E '^ADV .* 2001:db8:50::1[01][0-9a-f]$' >/dev/null || nl_fail "without Interface-Id the LAN client got no/wrong answer: $out"
start_probe
out=$(dc nl-client client lan0); echo "$out"
L=$(probe_last)
[ "$(jf "$L" iid)" = None ] || nl_fail "an Interface-Id was sent although it is off: $L"
[ "$(jf "$L" link)" = "$LAN6" ] || nl_fail "link-address: $L"
nl_ok "no Interface-Id on the wire, both segments still served by link-address"
nl_api_ok "interface_id on again" PUT /svc/dhcp6-relay '{"interface_id":true}'
nl_wait 10 grep -F '"interface_id": true' "$CONF" || nl_fail "relay config not rewritten"
sleep 2

echo "=== all-servers multicast (ff02::1:2) on the upstream link"
nl_api_ok "disable (a rule edit re-applies, and an enabled relay with no rule is refused)" PUT /svc/dhcp6-relay '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -f "[d]hcp6-relay run"' || nl_fail "relay still running after disable"
nl_api GET /svc/dhcp6-relay
for id in $(python3 -c 'import json,sys; print(" ".join(str(r["id"]) for r in json.load(open(sys.argv[1]))["collections"]["rules"]))' "$NL_OUT"); do
  nl_api_ok "remove rule $id" DELETE /svc/dhcp6-relay/rules/"$id"
done
nl_api_code "no rules left: refuses to apply" 400 PUT /svc/dhcp6-relay '{"enabled":true}'
nl_api_ok "multicast rule for the LAN" POST /svc/dhcp6-relay/rules '{"iface":"@lan","server":"ff02::1:2","upstream":"@opt1","description":"all servers on OPT1"}'
nl_api_ok "multicast rule for the guests" POST /svc/dhcp6-relay/rules '{"iface":"@opt2","server":"FF02::1:2","upstream":"@opt1"}'
nl_api_ok "apply" PUT /svc/dhcp6-relay '{"enabled":true}'
nl_wait 10 grep -F 'ff02::1:2' "$CONF" || nl_fail "relay config not rewritten for the multicast rules"
sleep 2
start_probe mcast
out=$(dc nl-client client lan0); echo "$out"
case "$out" in ADV*) ;; *) nl_fail "multicast server: no Advertise ($out)";; esac
[ "$(probe_n)" = 1 ] || { cat "$PLOG"; nl_fail "the multicast probe must see one Relay-forward, saw $(probe_n)"; }
L=$(probe_last)
[ "$(jf "$L" link)" = "$LAN6" ] && [ "$(jf "$L" from)" = "$IOT_RTR6" ] || nl_fail "multicast Relay-forward: $L"
nl_ok "ff02::1:2 on the upstream link: the probe hears the Relay-forward from the router's upstream address"
start_dhcpd
sleep 1
out=$(dc nl-client client lan0 full); echo "$out"
echo "$out" | grep -E '^REPLY .* 2001:db8:50::1[01][0-9a-f]$' >/dev/null || nl_fail "real server over multicast, LAN: $out"
out=$(dc nl-g client g0 full); echo "$out"
echo "$out" | grep -E '^REPLY .* 2001:db8:70::1[01][0-9a-f]$' >/dev/null || nl_fail "real server over multicast, guest: $out"
nl_ok "ISC dhcpd found through the all-servers group serves both segments"

echo "=== firewall, status, page"
nl_assert_nft_has 'iifname "rtr-lan" meta nfproto ipv6 udp dport 547 accept'
nl_assert_nft_has 'iifname "rtr-g" meta nfproto ipv6 udp dport 547 accept'
nl_assert_nft_has 'iifname "rtr-iot" udp sport 547 udp dport 547 accept'
nl_assert_nft_lacks 'iifname "rtr-iot" meta nfproto ipv6 udp dport 547 accept'
nl_ok "udp/547 opens on the client interfaces and the replies on the upstream interface only"
nl_api GET /svc/dhcp6-relay
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the running relay"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert st["rules"] == 2, st
PY
STATS=$(ls /run/patronus/dhcp6-relay.stats /var/lib/patronus/net/run/dhcp6-relay.stats /run/dhcp6-relay.stats 2>/dev/null | head -1 || true)
nl_wait 8 test -s "${STATS:-/nonexistent}" || nl_fail "no stats file"
sleep 2
python3 - "$STATS" <<'PY' || { cat "$STATS"; nl_fail "stats do not count the relayed messages"; }
import json, sys
st = json.load(open(sys.argv[1]))
assert sum(r["forwarded"] for r in st["rules"]) >= 2 and sum(r["replies"] for r in st["rules"]) >= 2, st
PY
nl_web GET /svc/dhcp6-relay
[ "$NL_CODE" = 200 ] && grep -F 'svc-settings-form' "$NL_OUT" >/dev/null || nl_fail "DHCPv6 relay page: $NL_CODE"
nl_ok "status, counters and page show the relay"

echo "=== reboot: patronus apply brings it back"
nl_web_stop
stop_srv
pkill -f '[d]hcp6-relay run' || true
nl_kill_daemons
nl_wait 10 sh -c '! pgrep -f "[d]hcp6-relay run"' || nl_fail "relay survived the simulated reboot"
nl_up; net_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_wait 10 pgrep -f 'dhcp6-relay run' || nl_fail "relay not started by the boot apply"
v6_addrs
start_dhcpd
sleep 2
out=$(dc nl-client client lan0 full); echo "$out"
echo "$out" | grep -E '^REPLY .* 2001:db8:50::1[01][0-9a-f]$' >/dev/null || nl_fail "no DHCPv6 after the reboot: $out"
nl_ok "after reboot: clients are served again"

echo "=== disable: relay stops"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/dhcp6-relay '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -f "[d]hcp6-relay run"' || nl_fail "relay still running"
out=$(dc nl-client client lan0); echo "$out"
[ "$out" = TIMEOUT ] || nl_fail "still relayed after disabling: $out"
nl_assert_nft_lacks 'meta nfproto ipv6 udp dport 547 accept'
nl_ok "disabled: relay stopped, no listener, no firewall rule, nothing crosses"
nl_web_stop
for ns in nl-iot nl-g; do ip netns del $ns 2>/dev/null || true; done
echo "ALL DHCP6-RELAY CHECKS PASSED"
