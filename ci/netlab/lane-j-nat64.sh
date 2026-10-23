#!/usr/bin/env bash
# Lane J: NAT64 / DNS64 (USE=nat64). An IPv6-only LAN client reaches an
# IPv4-only web server on the "internet" through tayga: without NAT64 the
# 2001:db8:64::/96 destination is unreachable; with the NAT64 page enabled the
# request is translated, masqueraded to the WAN address (the server sees
# 203.0.113.2) and the answer comes back. Unbound's DNS64 answers an AAAA query
# for the IPv4-only www.example.test with an address in the NAT64 prefix.
# Reboot and disable are checked. The lab's "internet" uses documentation
# addresses, which tayga refuses to translate through the well-known prefix
# 64:ff9b::/96 (RFC 6052: global IPv4 addresses only), so the scenario uses a
# network-specific /96 (2001:db8:64::/96), as tayga's own documentation advises.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-nat64.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons tayga
pkill -x unbound 2>/dev/null || true

cat > "$NL_T/nl-get6.py" <<'PY'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 80), timeout=4, source_address=None)
    s.sendall(("GET / HTTP/1.0\r\nHost: " + sys.argv[1] + "\r\n\r\n").encode())
    d = b""
    while True:
        c = s.recv(4096)
        if not c: break
        d += c
    print(d.decode().strip().splitlines()[-1])
except OSError as e:
    print("unreachable:", e); sys.exit(1)
PY
cat > "$NL_T/nl-aaaa.py" <<'PY'
import socket, struct, sys
name, server = sys.argv[1], sys.argv[2]
q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", 28, 1)
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, (server, 53)); d, _ = s.recvfrom(4096)
want = socket.inet_pton(socket.AF_INET6, sys.argv[3])
print("answer ok" if want in d else "no synthesized AAAA in answer: " + d.hex())
sys.exit(0 if want in d else 1)
PY

plumb6() { # IPv6 LAN (the lanes' address plan is IPv4); the client keeps no IPv6 route beyond the router
  R ip -6 addr add fd00:50::1/64 dev "$NL_LAN_IF" nodad
  C ip -6 addr add fd00:50::10/64 dev lan0 nodad
  C ip -6 route add default via fd00:50::1
}

nl_boot "$DB"; plumb6
nl_web_start "$DB"; nl_login

echo "=== without NAT64 the prefix is unreachable"
if OUT=$(C python3 "$NL_T/nl-get6.py" "2001:db8:64::198.51.100.10" 2>&1); then nl_fail "reached an IPv4 host over IPv6 with no NAT64: $OUT"; fi
nl_ok "baseline: 2001:db8:64::198.51.100.10 is unreachable ($OUT)"

echo "=== validation"
for bad in '{"prefix":"2001:db8:64::/64"}' '{"prefix":"10.0.0.0/8"}' '{"pool":"fd00::/64"}' '{"clients":"lan;x"}'; do
  nl_api_code "bad nat64 setting $bad" 400 PUT /svc/nat64 "$bad"
done
nl_ok "a /64 prefix, an IPv4 prefix, an IPv6 pool and a bad interface are refused (400)"

echo "=== DNS64 needs the resolver: point Unbound at the internet DNS for example.test"
nl_api_ok "dns settings" PUT /dns/settings '{"mode":"resolver","dnssec":false}'
nl_api_ok "dns domain override" POST /dns/domains "{\"domain\":\"example.test\",\"server\":\"$NL_DNS\"}"
nl_wait 15 pgrep -x unbound || nl_fail "unbound is not running"

echo "=== enable NAT64 + DNS64"
nl_api_ok "enable" PUT /svc/nat64 '{"enabled":true,"prefix":"2001:db8:64::/96","pool":"192.168.255.0/24","clients":"@lan","dns64":true}'
nl_wait 10 pgrep -x tayga || nl_fail "tayga did not start"
nl_ok "tayga running: $(pgrep -ax tayga | head -1 | cut -c1-120)"
R ip link show nat64 >/dev/null || nl_fail "no nat64 device"
R ip -6 route show | grep -q '2001:db8:64::/96 dev nat64' || { R ip -6 route show; nl_fail "the NAT64 prefix is not routed into nat64"; }
R ip route show | grep -q '192.168.255.0/24 dev nat64' || nl_fail "the translation pool is not routed into nat64"
nl_ok "kernel: nat64 device up, 2001:db8:64::/96 and 192.168.255.0/24 routed into it"
nl_assert_sysctl net.ipv6.conf.all.forwarding 1
nl_assert_nft_has "oifname \"nat64\" ip6 daddr 2001:db8:64::/96 accept" "ip saddr 192.168.255.0/24 oifname \"$NL_WAN_IF\" masquerade"
OUT=$(C python3 "$NL_T/nl-get6.py" "2001:db8:64::198.51.100.10" 2>&1) || { echo "$OUT"; R tayga --help >/dev/null 2>&1; cat /run/patronus/patronus-daemon.tayga.log 2>/dev/null | tail -20; nl_fail "IPv6-only client could not reach the IPv4 server through NAT64: $OUT"; }
case "$OUT" in *"sees $NL_RTR_WAN"*) ;; *) nl_fail "server did not see the WAN address: $OUT";; esac
nl_ok "IPv6-only client -> http://[2001:db8:64::198.51.100.10]/ : $OUT"
grep -q 'module-config: "dns64 iterator"' /etc/unbound/unbound.conf && grep -q 'dns64-prefix: 2001:db8:64::/96' /etc/unbound/unbound.conf \
  || { cat /etc/unbound/unbound.conf; nl_fail "unbound.conf has no dns64 setup"; }
nl_wait 15 C python3 "$NL_T/nl-aaaa.py" www.example.test fd00:50::1 2001:db8:64::198.51.100.10 || { C python3 "$NL_T/nl-aaaa.py" www.example.test fd00:50::1 2001:db8:64::198.51.100.10 || true; nl_fail "DNS64 did not synthesize the AAAA record"; }
nl_ok "Unbound DNS64: AAAA www.example.test = 2001:db8:64::198.51.100.10 (synthesized from the IPv4-only A record)"
nl_api GET /svc/nat64
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show NAT64 running"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"] and st["device"], st
PY
nl_ok "status: tayga running, device up"
nl_web GET /svc/nat64
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "NAT64 page: $NL_CODE"

echo "=== reboot: patronus apply rebuilds the device, routes and daemon"
nl_web_stop
nl_kill_daemons tayga
pkill -x unbound 2>/dev/null || true
nl_boot "$DB"; plumb6
nl_wait 10 pgrep -x tayga || nl_fail "tayga not started by the boot apply"
OUT=$(C python3 "$NL_T/nl-get6.py" "2001:db8:64::198.51.100.10" 2>&1) || nl_fail "NAT64 does not work after the reboot: $OUT"
nl_ok "after reboot: $OUT"

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/nat64 '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x tayga' || nl_fail "tayga still running"
R ip link show nat64 >/dev/null 2>&1 && nl_fail "nat64 device still exists"
nl_assert_nft_lacks "nat64"
if OUT=$(C python3 "$NL_T/nl-get6.py" "2001:db8:64::198.51.100.10" 2>&1); then nl_fail "NAT64 still works after disabling: $OUT"; fi
nl_ok "disabled: tayga stopped, device and firewall rules removed, prefix unreachable again"
nl_web_stop
pkill -x unbound 2>/dev/null || true
echo "ALL NAT64 CHECKS PASSED"
