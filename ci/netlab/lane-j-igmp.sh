#!/usr/bin/env bash
# Lane J: IGMP proxy (USE=igmp). A multicast source on the WAN side (the ISP
# namespace) streams to 239.1.1.1; a LAN client joins the group. Without the
# proxy nothing arrives; with the IGMP page enabled (igmpproxy upstream =
# WAN, downstream = LAN) the kernel's multicast router has both interfaces and
# the stream reaches the client; the firewall rules are generated, the proxy
# comes back after a reboot, and disabling it stops the stream.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-igmp.db
GROUP=239.1.1.1
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons igmpproxy

cat > "$NL_T/nl-mc-send.py" <<'PY'
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(sys.argv[2]))
end = time.time() + float(sys.argv[3])
while time.time() < end:
    s.sendto(b"mc-stream-" + str(time.time()).encode(), (sys.argv[1], 5000)); time.sleep(0.2)
PY
cat > "$NL_T/nl-mc-recv.py" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 5000))
mreq = struct.pack("4s4s", socket.inet_aton(sys.argv[1]), socket.inet_aton(sys.argv[2]))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
s.settimeout(float(sys.argv[3]))
try:
    d, a = s.recvfrom(1500)
    print("got", d.decode()[:20], "from", a[0])
except socket.timeout:
    print("timeout"); sys.exit(1)
PY
# receive(): the client joins and waits N seconds while the ISP side streams
receive() {
  ISP python3 "$NL_T/nl-mc-send.py" $GROUP 203.0.113.1 $(( $1 + 2 )) &
  local sp=$!
  local rc=0
  C python3 "$NL_T/nl-mc-recv.py" $GROUP $NL_CLIENT "$1" >"$NL_OUT" 2>&1 || rc=$?
  kill $sp 2>/dev/null; wait $sp 2>/dev/null || true
  return $rc
}

nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== without the proxy the stream does not cross the router"
if receive 4; then nl_fail "multicast reached the LAN with no proxy: $(cat "$NL_OUT")"; fi
nl_ok "no proxy: the LAN client receives nothing ($(cat "$NL_OUT"))"

echo "=== validation"
nl_api_code "enable without downstream" 400 PUT /svc/igmp '{"enabled":true}'
nl_api_code "bad interface" 400 POST /svc/igmp/downstream '{"iface":"lan;x"}'
nl_ok "enabling with no downstream interface and a bad interface name are refused (400)"

echo "=== enable the proxy: upstream @wan, downstream @lan"
nl_api_ok "downstream" POST /svc/igmp/downstream '{"iface":"@lan"}'
nl_api_code "duplicate downstream" 400 POST /svc/igmp/downstream '{"iface":"@lan"}'
nl_api_ok "enable" PUT /svc/igmp '{"enabled":true,"upstream":"@wan"}'
nl_wait 10 pgrep -x igmpproxy || nl_fail "igmpproxy did not start"
nl_ok "igmpproxy running: $(pgrep -ax igmpproxy | head -1 | cut -c1-120)"
grep -q "phyint $NL_WAN_IF upstream" /var/lib/patronus/net/igmpproxy.conf && grep -q "phyint $NL_LAN_IF downstream" /var/lib/patronus/net/igmpproxy.conf \
  || { cat /var/lib/patronus/net/igmpproxy.conf; nl_fail "igmpproxy.conf does not name the WAN as upstream and the LAN as downstream"; }
nl_ok "igmpproxy.conf: $NL_WAN_IF upstream, $NL_LAN_IF downstream"
nl_wait 10 grep -q "$NL_LAN_IF" /proc/net/ip_mr_vif || true
R cat /proc/net/ip_mr_vif | grep -q "$NL_WAN_IF" && R cat /proc/net/ip_mr_vif | grep -q "$NL_LAN_IF" \
  || { R cat /proc/net/ip_mr_vif; nl_fail "the kernel multicast router does not hold both interfaces"; }
nl_ok "kernel multicast router (ip_mr_vif) holds $NL_WAN_IF and $NL_LAN_IF"
nl_assert_nft_has "iifname \"$NL_WAN_IF\" oifname \"$NL_LAN_IF\" ip daddr 224.0.0.0/4 accept" "ip protocol igmp accept"
receive 8 || { cat "$NL_OUT"; nl_fail "the LAN client did not receive the multicast stream through the proxy"; }
nl_ok "LAN client received the WAN multicast stream through the router: $(cat "$NL_OUT")"
nl_api GET /svc/igmp
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the running proxy"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert len(st["multicast_router_interfaces"]) >= 2, st
PY
nl_ok "status: running, multicast router interfaces listed"
nl_web GET /svc/igmp
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "IGMP page: $NL_CODE"

echo "=== reboot: patronus apply restarts the proxy and the firewall rules"
nl_web_stop
nl_kill_daemons igmpproxy
nl_boot "$DB"
nl_wait 10 pgrep -x igmpproxy || nl_fail "igmpproxy not started by the boot apply"
nl_assert_nft_has "ip daddr 224.0.0.0/4 accept"
receive 8 || { cat "$NL_OUT"; nl_fail "no multicast after the reboot"; }
nl_ok "after reboot: the stream reaches the client again"

echo "=== disable: the stream stops"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/igmp '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x igmpproxy' || nl_fail "igmpproxy still running"
nl_assert_nft_lacks "224.0.0.0/4"
sleep 1
if receive 4; then nl_fail "multicast still forwarded after disabling: $(cat "$NL_OUT")"; fi
nl_ok "disabled: proxy stopped, firewall rules gone, no stream"
nl_web_stop
echo "ALL IGMP CHECKS PASSED"
