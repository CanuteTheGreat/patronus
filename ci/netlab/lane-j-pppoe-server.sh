#!/usr/bin/env bash
# Lane J: PPPoE server / access concentrator (USE=pppoe-server). The PPPoE page
# turns on rp-pppoe's pppoe-server + pppd on the LAN port; a real PPPoE client
# (pppd + pppoe in the client namespace, i.e. another router's WAN) dials in
# over the LAN veth with CHAP, gets an address from the pool (a fixed one for a
# user that has one), pings the server through the PPP link and reaches the
# internet through the router's NAT (the isp has no route back to the pool). A
# wrong password / disabled user is refused, the secrets block is managed
# without touching other lines, no password reaches the API, the session
# devices (ppp<unit_base>..) are firewalled as a range of their own, and a
# reboot brings the server back.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-pppoe-server.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons pppoe-server pppd pppoe
mkdir -p /etc/ppp
echo '# hand-written line that must survive' > /etc/ppp/chap-secrets
: > /etc/ppp/pap-secrets

PW_ALICE='alice-secret-1'
PW_BOB='bob-secret-123'
UNIT=1000

client_up() { # USER PASSWORD
  cat > "$NL_T/pppoe-client.options" <<EOF
user $1
password $2
noauth
refuse-pap
noccp
nodefaultroute
usepeerdns
ipcp-accept-local
ipcp-accept-remote
lcp-echo-interval 10
lcp-echo-failure 3
mtu 1492
mru 1492
nodetach
EOF
  if [ -e /sys/module/pppoe ] && [ -n "$(find /usr/lib /usr/lib64 -name rp-pppoe.so 2>/dev/null | head -1)" ]; then
    CLIENT_MODE=kernel
    ip netns exec nl-client pppd plugin rp-pppoe.so lan0 file "$NL_T/pppoe-client.options" ifname ppp-cli >/tmp/pppoe-client.log 2>&1 &
  else
    CLIENT_MODE=userspace
    ip netns exec nl-client pppd pty "pppoe -I lan0 -m 1412" sync file "$NL_T/pppoe-client.options" ifname ppp-cli >/tmp/pppoe-client.log 2>&1 &
  fi
  CLIENT_PID=$!
}
client_down() {
  kill "${CLIENT_PID:-0}" 2>/dev/null || true
  C pkill -x pppd 2>/dev/null || true
  C pkill -x pppoe 2>/dev/null || true
  sleep 1
}
cli_ppp() { C ip -o addr show 2>/dev/null | grep 'ppp-cli .*inet 10.70.0.' >/dev/null; }
srv_sessions() { R sh -c "ip -o addr show | grep -c 'ppp[0-9]* .*inet 10.70.0.1 '" 2>/dev/null || true; }
connect() { # USER PASSWORD
  client_up "$@"
  nl_wait 25 cli_ppp
}

nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== validation"
nl_api_code "enable without interface" 400 PUT /svc/pppoe-server '{"enabled":true}'
nl_api_code "enable without users" 400 PUT /svc/pppoe-server '{"enabled":true,"interfaces":"@lan"}'
for bad in '{"username":"a b","password":"alice-secret-1"}' '{"username":"alice","password":"short"}' '{"username":"alice","password":"pass\"word123"}' '{"username":"alice"}'; do
  nl_api_code "bad user $bad" 400 POST /svc/pppoe-server/users "$bad"
done
nl_api_code "pool containing the server address" 400 PUT /svc/pppoe-server '{"range_start":"10.70.0.1","range_end":"10.70.0.20"}'
nl_api_code "pool larger than max sessions allow" 400 PUT /svc/pppoe-server '{"max_sessions":4000}'
nl_api_code "bad router service" 400 PUT /svc/pppoe-server '{"router_ports":"53"}'
nl_api_code "unknown setting" 400 PUT /svc/pppoe-server '{"nonsense":1}'
nl_ok "missing interface/users, bad users, bad pool/router services and unknown settings are refused (400)"
nl_api_ok "serve on the WAN (stored, not enabled)" PUT /svc/pppoe-server '{"interfaces":"@wan"}'
nl_api_ok "add alice" POST /svc/pppoe-server/users "{\"username\":\"alice\",\"password\":\"$PW_ALICE\"}"
ID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_code "enabling on the WAN port is refused" 400 PUT /svc/pppoe-server '{"enabled":true}'
nl_assert_nft_lacks "ppp1000"

echo "=== a user and the server"
nl_api GET /svc/pppoe-server
grep -q "$PW_ALICE" "$NL_OUT" && nl_fail "the API returned the password"
nl_ok "the settings/user list never return the password"
nl_api_ok "enable" PUT /svc/pppoe-server \
  "{\"enabled\":true,\"interfaces\":\"@lan\",\"local_ip\":\"10.70.0.1\",\"range_start\":\"10.70.0.10\",\"range_end\":\"10.70.0.19\",\"unit_base\":$UNIT,\"ac_name\":\"patronus-ac\",\"dns1\":\"198.51.100.53\",\"router_ports\":\"udp/53,tcp/22\"}"
nl_wait 10 pgrep -x pppoe-server || nl_fail "pppoe-server did not start"
nl_ok "pppoe-server running: $(pgrep -ax pppoe-server | head -1 | cut -c1-200)"
pgrep -ax pppoe-server | grep -q -- "-I $NL_LAN_IF" || nl_fail "not serving on $NL_LAN_IF"
pgrep -ax pppoe-server | grep -q -- "-C patronus-ac" || nl_fail "access concentrator name not passed"
grep -q 'hand-written line that must survive' /etc/ppp/chap-secrets && grep -q '"alice" \* "alice-secret-1" \*' /etc/ppp/chap-secrets || { cat /etc/ppp/chap-secrets; nl_fail "chap-secrets: Patronus block missing or foreign line lost"; }
[ "$(stat -c %a /etc/ppp/chap-secrets)" = 600 ] || nl_fail "chap-secrets is not mode 0600"
nl_ok "chap-secrets has the user in a Patronus block, the foreign line is kept, mode 0600"
OPT=$(find /run /var -path '*pppoe-server/options' 2>/dev/null | head -1)
[ -n "$OPT" ] && [ "$(stat -c %a "$OPT")" = 600 ] && grep -q 'require-chap' "$OPT" || nl_fail "pppd options file missing/not 0600/no CHAP"
nl_ok "pppd options generated (mode 0600, CHAP required)"
# the session devices form a range of their own: ppp1000..ppp1009 (10 sessions from 1000)
nl_assert_nft_has "\"ppp1000\", \"ppp1001\""
nl_assert_nft_has "icmp type echo-request accept"
nl_assert_nft_has "udp dport { 53 } accept"
nl_assert_nft_has "masquerade"
nl_ok "firewall: session devices ppp1000..ppp1009 get ping, the chosen router services, forwarding to the WAN and NAT"
nl_assert_nft_lacks "iifname \"ppp0\""

echo "=== a real PPPoE client dials in"
connect alice "$PW_ALICE" || { tail -30 /tmp/pppoe-client.log; tail -20 /run/patronus/patronus-daemon.pppoe-server.log; nl_fail "the PPPoE client never got a PPP address"; }
nl_ok "client ($CLIENT_MODE) got a PPP address: $(C ip -o addr show | grep -o 'inet 10.70.0.[0-9]*' | head -1)"
C ping -c 3 -W 2 10.70.0.1 >/dev/null || nl_fail "client cannot ping the server's address through PPP"
nl_ok "client pings the server's address 10.70.0.1 through the PPPoE/PPP link"
R ip -o addr show | grep "ppp1000.*10.70.0.1" >/dev/null || nl_fail "the router's session device is not ppp$UNIT"
nl_ok "the server's session device is ppp$UNIT (inside the configured range)"
C ip route replace default dev ppp-cli
OUT=$(C curl -s --max-time 10 "http://$NL_WWW/") || nl_fail "client cannot reach the internet through the PPPoE server"
nl_ok "client reaches the internet through the router: $OUT"
echo "$OUT" | grep -q "10.70.0." && nl_fail "client address leaked upstream: no NAT"
nl_ok "the isp saw the router's WAN address, not the pool address (masquerade works)"
C curl -s --max-time 3 "http://$NL_RTR_LAN:8443/" >/dev/null 2>&1 && nl_fail "client reached the web UI through the session"
C ip route del default dev ppp-cli
nl_api GET /svc/pppoe-server
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the session"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert st["session_count"] >= 1 and st["pool_size"] == 10, st
PY
nl_ok "status: server running, the session is listed"
nl_web GET /svc/pppoe-server
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "PPPoE server page: $NL_CODE"
grep -q "$PW_ALICE" "$NL_OUT" && nl_fail "the page returned the password"
client_down

echo "=== a wrong password and a disabled user are refused"
connect alice "not-the-password"; cli_ppp && nl_fail "a wrong password connected"
nl_ok "alice with a wrong password gets no PPP address"
client_down
nl_api_ok "add bob (fixed address)" POST /svc/pppoe-server/users "{\"username\":\"bob\",\"password\":\"$PW_BOB\",\"address\":\"10.70.0.77\"}"
nl_api_code "same fixed address twice" 400 POST /svc/pppoe-server/users '{"username":"carol","password":"carol-secret-1","address":"10.70.0.77"}'
nl_api_ok "disable alice" PUT "/svc/pppoe-server/users/$ID" '{"enabled":false}'
grep -q '"alice"' /etc/ppp/chap-secrets && nl_fail "disabled user still in chap-secrets"
connect alice "$PW_ALICE"; cli_ppp && nl_fail "a disabled user connected"
nl_ok "alice (disabled) is refused"
client_down
connect bob "$PW_BOB" || { tail -20 /tmp/pppoe-client.log; nl_fail "bob could not connect"; }
C ip -o addr show | grep -q 'inet 10.70.0.77' || nl_fail "bob did not get his fixed address"
nl_ok "bob got his fixed address 10.70.0.77"
client_down
nl_api_ok "enable alice again" PUT "/svc/pppoe-server/users/$ID" '{"enabled":true}'

echo "=== reboot: patronus apply brings the server back"
nl_web_stop
nl_kill_daemons pppoe-server pppd pppoe
nl_boot "$DB"
nl_wait 10 pgrep -x pppoe-server || nl_fail "pppoe-server not started by the boot apply"
nl_assert_nft_has "\"ppp1000\", \"ppp1001\""
connect alice "$PW_ALICE" || { tail -20 /tmp/pppoe-client.log; nl_fail "no PPPoE session after the reboot"; }
nl_ok "after reboot: a client connects again"
client_down

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/pppoe-server '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x pppoe-server' || nl_fail "pppoe-server still running"
nl_assert_nft_lacks "ppp1000"
grep -q 'Managed by Patronus' /etc/ppp/chap-secrets && nl_fail "managed block still in chap-secrets"
grep -q 'hand-written line that must survive' /etc/ppp/chap-secrets || nl_fail "foreign line lost"
nl_ok "disabled: pppoe-server stopped, session rules removed, secrets block removed, foreign line kept"
nl_web_stop
echo "ALL PPPOE-SERVER CHECKS PASSED"
