#!/usr/bin/env bash
# Lane J: mDNS repeater (USE=mdns). A printer-like device on a second LAN
# segment (OPT1, "IoT") answers mDNS for nl-printer.local; a client on the LAN
# asks for it. mDNS is link-local, so without the repeater the question never
# leaves the LAN. With the mDNS page enabled for @lan + @opt1, avahi-daemon
# (reflector) carries the query to OPT1 and the answer back; the firewall
# opens UDP 5353 on exactly those interfaces (never the WAN); it survives a
# reboot; disabling stops it and discovery fails again.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-mdns.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons avahi-daemon
IOT_RTR=10.60.0.1
IOT_DEV=10.60.0.20

# second segment: rtr-iot (router, OPT1) <-> iot0 in namespace nl-iot
iot_up() {
  ip netns del nl-iot 2>/dev/null || true
  ip netns add nl-iot; ip -n nl-iot link set lo up
  ip link add rtr-iot netns nl-rtr type veth peer name iot0 netns nl-iot
  R ip addr add $IOT_RTR/24 dev rtr-iot; R ip link set rtr-iot up
  ip -n nl-iot addr add $IOT_DEV/24 dev iot0; ip -n nl-iot link set iot0 up
  ip -n nl-iot route add default via $IOT_RTR
}

cat > "$NL_T/nl-mdns.py" <<'PY'
# nl-mdns.py respond NAME IP SECONDS | query NAME LOCAL-IP SECONDS
import socket, struct, sys, time
GRP = "224.0.0.251"
def qname(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"
def sock(local):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 5353))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GRP) + socket.inet_aton(local))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    return s
mode, name, ip, secs = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
want = qname(name)
end = time.time() + secs
if mode == "respond":
    s = sock(ip)
    s.settimeout(0.5)
    while time.time() < end:
        try:
            d, a = s.recvfrom(9000)
        except socket.timeout:
            continue
        flags = struct.unpack(">H", d[2:4])[0]
        if flags & 0x8000 or want.lower() not in d.lower():
            continue
        ans = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + want + struct.pack(">HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(ip)
        s.sendto(ans, (GRP, 5353))
        print("answered query from", a[0], flush=True)
else:
    s = sock(ip)
    s.settimeout(0.5)
    q = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + want + struct.pack(">HH", 1, 1)
    nxt = 0
    while time.time() < end:
        if time.time() >= nxt:
            s.sendto(q, (GRP, 5353)); nxt = time.time() + 1
        try:
            d, a = s.recvfrom(9000)
        except socket.timeout:
            continue
        flags = struct.unpack(">H", d[2:4])[0]
        if flags & 0x8000 and want.lower() in d.lower():
            print("%s is %s (answer relayed by %s)" % (name, socket.inet_ntoa(d[-4:]), a[0]))
            sys.exit(0)
    print("no answer for", name); sys.exit(1)
PY
# discover N: the IoT device answers for N+1 s while the LAN client asks for N s
discover() {
  # not through the IOT function: `func &` forks a subshell, and killing it
  # would leave the python responder running
  ip netns exec nl-iot python3 "$NL_T/nl-mdns.py" respond nl-printer.local $IOT_DEV $(( $1 + 1 )) >"$NL_T/nl-mdns-resp.txt" 2>&1 &
  local rp=$! rc=0
  sleep 0.3
  C python3 "$NL_T/nl-mdns.py" query nl-printer.local $NL_CLIENT "$1" >"$NL_OUT" 2>&1 || rc=$?
  kill $rp 2>/dev/null; wait $rp 2>/dev/null || true
  return $rc
}

nl_up; iot_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_web_start "$DB"; nl_login
nl_api_ok "OPT1 on the IoT port" PUT /interfaces/rtr-iot "{\"role\":\"opt1\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$IOT_RTR/24\"]}"

echo "=== without the repeater, discovery stays on its own segment"
if discover 3; then nl_fail "mDNS crossed segments with no repeater: $(cat "$NL_OUT")"; fi
nl_ok "no repeater: $(cat "$NL_OUT")"

echo "=== validation"
nl_api_code "bad interface" 400 POST /svc/mdns/interfaces '{"iface":"lan;x"}'
nl_api_ok "LAN" POST /svc/mdns/interfaces '{"iface":"@lan"}'
nl_api_code "duplicate" 400 POST /svc/mdns/interfaces '{"iface":"@lan"}'
nl_api_code "enable with one interface" 400 PUT /svc/mdns '{"enabled":true}'
pgrep -x avahi-daemon >/dev/null && nl_fail "avahi started although the change was refused"
nl_ok "bad/duplicate interface and a one-interface repeater are refused (400), nothing started"

echo "=== enable: @lan + @opt1"
nl_api_ok "OPT1" POST /svc/mdns/interfaces '{"iface":"@opt1","description":"IoT"}'
nl_api_ok "enable" PUT /svc/mdns '{"enabled":true}'
nl_wait 10 pgrep -x avahi-daemon || { tail -20 "$NL_T/nl-web.log"; nl_fail "avahi-daemon did not start"; }
CONF=/var/lib/patronus/net/avahi-daemon.conf
grep -x "allow-interfaces=$NL_LAN_IF,rtr-iot" "$CONF" >/dev/null && grep -x 'enable-reflector=yes' "$CONF" >/dev/null \
  || { cat "$CONF"; nl_fail "avahi config does not reflect between $NL_LAN_IF and rtr-iot"; }
nl_ok "avahi-daemon running as a reflector between $NL_LAN_IF and rtr-iot"
nl_assert_nft_has "iifname \"$NL_LAN_IF\" udp dport 5353 ip daddr 224.0.0.251 accept" \
                  "iifname \"rtr-iot\" udp dport 5353 ip6 daddr ff02::fb accept"
nl_assert_nft_lacks "iifname \"$NL_WAN_IF\" udp dport 5353"
discover 8 || { cat "$NL_OUT" "$NL_T/nl-mdns-resp.txt"; nl_fail "the LAN client did not discover the IoT device through the repeater"; }
nl_ok "LAN client discovered the OPT1 device: $(cat "$NL_OUT")"
nl_api GET /svc/mdns
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the running repeater"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert set(st["interfaces"]) == {"rtr-lan", "rtr-iot"}, st
PY
nl_web GET /svc/mdns
[ "$NL_CODE" = 200 ] && grep -F 'svc-settings-form' "$NL_OUT" >/dev/null || nl_fail "mDNS page: $NL_CODE"
nl_ok "status + page show the repeater"

echo "=== reboot: patronus apply brings the repeater back"
nl_web_stop
nl_kill_daemons avahi-daemon
nl_up; iot_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot apply"; }
nl_wait 10 pgrep -x avahi-daemon || nl_fail "avahi-daemon not started by the boot apply"
discover 8 || { cat "$NL_OUT"; nl_fail "no discovery after the reboot"; }
nl_ok "after reboot: discovery across segments works again"

echo "=== disable: discovery stops crossing"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/mdns '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x avahi-daemon' || nl_fail "avahi-daemon still running"
nl_assert_nft_lacks "udp dport 5353"
if discover 3; then nl_fail "mDNS still repeated after disabling: $(cat "$NL_OUT")"; fi
nl_ok "disabled: repeater stopped, 5353 closed, no discovery"
nl_web_stop
ip netns del nl-iot 2>/dev/null || true
echo "ALL MDNS CHECKS PASSED"
