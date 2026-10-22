#!/usr/bin/env bash
# Lane B: IPv6 network prefix translation (NPTv6) from the web UI API,
# proven with real IPv6 traffic through the kernel (the ISP has no route for
# the ULA, so the client only gets online through the translation):
#   LAN client fd00:50::10 --- router (NPTv6 fd00:50::/64 <-> 2001:db8:50::/64) --- ISP --- internet host
# - outbound: the internet host sees the client as 2001:db8:50::10 (host
#   bits kept, prefix swapped);
# - inbound: a firewall-permitted connection from the internet to the
#   EXTERNAL address 2001:db8:50::10 reaches the client;
# - mappings survive a reboot (`patronus apply`) and deleting one removes
#   the translation.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-npt.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml

cat > "$NL_T/nl-tcp6.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
while True:
    c, a = s.accept(); c.sendall((a[0] + "\n").encode()); c.close()
PY
cat > "$NL_T/nl-conn6.py" <<'PY'
import socket, sys
try:
    c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
    print(c.recv(100).decode().strip())
except OSError as e:
    print("unreachable:", e); sys.exit(1)
PY

plumb6() { # IPv6 on the topology (the lanes' address plan is IPv4)
  R ip -6 addr add fd00:50::1/64 dev "$NL_LAN_IF" nodad
  C ip -6 addr add fd00:50::10/64 dev lan0 nodad
  C ip -6 route add default via fd00:50::1
  R ip -6 addr add 2001:db8:ee::2/64 dev "$NL_WAN_IF" nodad
  R ip -6 route add default via 2001:db8:ee::1
  ISP ip -6 addr add 2001:db8:ee::1/64 dev up0 nodad
  ISP ip -6 addr add 2001:db8:ff::1/64 dev down0 nodad
  ISP sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
  ISP ip -6 route add 2001:db8:50::/64 via 2001:db8:ee::2
  INET ip -6 addr add 2001:db8:ff::10/64 dev inet0 nodad
  INET ip -6 route add default via 2001:db8:ff::1
  nl_bg INET python3 "$NL_T/nl-tcp6.py" 2001:db8:ff::10 9001
  nl_bg C python3 "$NL_T/nl-tcp6.py" fd00:50::10 9002
  sleep 0.5
}
seen() { C python3 "$NL_T/nl-conn6.py" 2001:db8:ff::10 9001; }

nl_boot "$DB"; plumb6
nl_web_start "$DB"; nl_login
if OUT=$(seen); then nl_fail "a ULA client reached the internet without a mapping: $OUT"; fi
nl_ok "baseline: without a mapping the ULA client cannot reach the internet (no return route for fd00:50::/64)"

echo "=== NPTv6 mapping through the API"
for bad in '{"name":"x","rule_type":"NPT","interface":"@wan","source":"any","destination":"any","target":"fd00:50::/48","external_address":"2001:db8:50::/64","description":"","enabled":true}' \
           '{"name":"x","rule_type":"NPT","interface":"@wan","source":"any","destination":"any","target":"10.0.0.0/24","external_address":"203.0.113.0/24","description":"","enabled":true}'; do
  nl_api POST /firewall/nat "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "a bad NPTv6 rule was accepted: $NL_CODE $(cat "$NL_OUT")"
done
nl_ok "different prefix lengths / IPv4 prefixes are refused (400)"
nl_api POST /firewall/nat '{"name":"lan-npt","rule_type":"NPT","interface":"@wan","source":"any","destination":"any","target":"fd00:50::/64","external_address":"2001:db8:50::/64","description":"LAN ULA to the delegated prefix","enabled":true}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "add NPTv6: $NL_CODE $(cat "$NL_OUT")"
nl_assert_nft_has 'ip6 daddr 2001:db8:50::/64 dnat ip6 prefix to fd00:50::/64' 'ip6 saddr fd00:50::/64 snat ip6 prefix to 2001:db8:50::/64'
nl_ok "nft ruleset has the prefix dnat (inbound) and snat (outbound)"

OUT=$(seen) || nl_fail "client -> internet host after the mapping: $OUT"
[ "$OUT" = 2001:db8:50::10 ] || nl_fail "the internet host saw $OUT, want 2001:db8:50::10"
nl_ok "outbound: the internet host sees the client as 2001:db8:50::10"

echo "=== inbound to the external address needs a filter rule, then reaches the client"
OUT=$(INET python3 "$NL_T/nl-conn6.py" 2001:db8:50::10 9002 || true)
case "$OUT" in unreachable*) ;; *) nl_fail "inbound reached the client without a filter rule: $OUT";; esac
nl_api POST /firewall/rules '{"name":"npt-in","chain":"forward","action":"accept","interface":"@wan","protocol":"tcp","source":"any","destination":"fd00:50::10","port":"9002","description":"npt-in","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add forward rule: $NL_CODE $(cat "$NL_OUT")"
OUT=$(INET python3 "$NL_T/nl-conn6.py" 2001:db8:50::10 9002) || nl_fail "inbound to 2001:db8:50::10:9002: $OUT"
[ "$OUT" = 2001:db8:ff::10 ] || nl_fail "the client saw $OUT, want the internet host 2001:db8:ff::10"
nl_ok "inbound: internet host -> 2001:db8:50::10 reaches the client (fd00:50::10), source kept"

echo "=== reboot: the mapping comes back from the store"
nl_web_stop
nl_boot "$DB"; plumb6
OUT=$(seen) || nl_fail "after reboot: $OUT"
[ "$OUT" = 2001:db8:50::10 ] || nl_fail "after reboot the internet host saw $OUT"
nl_ok "after reboot: outbound still translated"

echo "=== delete the mapping"
nl_web_start "$DB"; nl_login
nl_api GET /firewall/nat
ID=$(python3 -c 'import json,sys; print([r["id"] for r in json.load(open(sys.argv[1])) if r["name"]=="lan-npt"][0])' "$NL_OUT")
nl_api DELETE "/firewall/nat/$ID"
[ "$NL_CODE" = 200 ] || nl_fail "delete: $NL_CODE"
nl_assert_nft_lacks 'prefix to'
if OUT=$(seen); then nl_fail "after the delete the ULA client still reaches the internet: $OUT"; fi
nl_ok "deleting the mapping removes the translation"
nl_web_stop
nl_down
