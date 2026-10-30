#!/usr/bin/env bash
# Lane J: L2TP server (USE=l2tp). The L2TP page turns on xl2tpd + pppd on the
# WAN interface; a real L2TP client (a second xl2tpd + pppd in the ISP
# namespace) dials in with MS-CHAPv2, gets an address from the pool and pings
# the server's tunnel address through the PPP link. A wrong/disabled user is
# refused, the chap-secrets block is managed without touching other lines, UDP
# 1701 is opened only while the server is on, and a reboot brings it back.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-l2tp.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_kill_daemons xl2tpd pppd
mkdir -p /etc/ppp
echo '# hand-written line that must survive' > /etc/ppp/chap-secrets

# the L2TP client (LAC) in the ISP namespace
cat > "$NL_T/l2tp-client.conf" <<EOF
[global]
port = 1701
[lac patronus]
lns = $NL_RTR_WAN
ppp debug = no
pppoptfile = $NL_T/l2tp-client.options
length bit = yes
autodial = yes
redial = yes
redial timeout = 3
max redials = 20
EOF
client_up() { # USER
  cat > "$NL_T/l2tp-client.options" <<EOF
name $1
noauth
refuse-pap
refuse-chap
refuse-mschap
noccp
nodefaultroute
usepeerdns
ipcp-accept-local
ipcp-accept-remote
lcp-echo-interval 10
lcp-echo-failure 3
EOF
  : > /tmp/l2tp-client-ctl; rm -f /tmp/l2tp-client-ctl
  ip netns exec nl-isp xl2tpd -D -c "$NL_T/l2tp-client.conf" -C /tmp/l2tp-client-ctl -p /tmp/l2tp-client.pid >/tmp/l2tp-client.log 2>&1 &
  CLIENT_PID=$!
}
# the server's side of a session: its ppp interface with the tunnel address
srv_ppp() { R ip -o addr show 2>/dev/null | grep 'ppp[0-9]* .*10.88.0.1' >/dev/null; }
client_down() {
  kill "${CLIENT_PID:-0}" 2>/dev/null || true; pkill -f "l2tp-client.conf" 2>/dev/null || true; ISP pkill -x pppd 2>/dev/null || true; sleep 1
  # a client that dials again while the server still holds the old tunnel
  # (the server notices a dead peer only after its timeouts) can wait for its
  # redial for a long time: let the server drop the session first
  if srv_ppp; then
    nl_wait 30 sh -c '! ip netns exec nl-rtr ip -o addr show | grep "ppp[0-9]* .*10.88.0.1" >/dev/null' \
      || echo "note: the server still holds the old PPP session after 30 s"
  fi
}
isp_ppp() { ISP ip -o addr show 2>/dev/null | grep 'ppp[0-9]* .*inet 10.88.0.' >/dev/null; }
# dial and wait; a client whose first attempt got lost is started once more
connect() { # USER
  client_up "$1"
  nl_wait 25 isp_ppp && return 0
  echo "note: no PPP address after 25 s; starting the client again"
  tail -5 /tmp/l2tp-client.log || true
  client_down
  client_up "$1"
  nl_wait 40 isp_ppp
}

nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== validation"
nl_api_code "enable without users" 400 PUT /svc/l2tp '{"enabled":true}'
for bad in '{"username":"a b","password":"longenough1"}' '{"username":"alice","password":"short"}' '{"username":"alice","password":"pass\"word123"}' '{"username":"alice"}'; do
  nl_api_code "bad user $bad" 400 POST /svc/l2tp/users "$bad"
done
nl_api_code "pool containing the server address" 400 PUT /svc/l2tp '{"range_start":"10.88.0.1","range_end":"10.88.0.20"}'
nl_ok "enabling without users, bad user names/passwords and a pool that contains the server address are refused (400)"
nl_assert_nft_lacks "udp dport 1701"

echo "=== a user and the server"
nl_api_ok "add alice" POST /svc/l2tp/users '{"username":"alice","password":"alice-secret-1"}'
ID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api GET /svc/l2tp
grep -q 'alice-secret-1' "$NL_OUT" && nl_fail "the API returned the password"
nl_ok "the user list never returns the password"
nl_api_ok "enable" PUT /svc/l2tp '{"enabled":true,"interface":"@wan","local_ip":"10.88.0.1","range_start":"10.88.0.10","range_end":"10.88.0.50"}'
nl_wait 10 pgrep -x xl2tpd || nl_fail "xl2tpd did not start"
nl_ok "xl2tpd running: $(pgrep -ax xl2tpd | head -1 | cut -c1-120)"
grep -q 'hand-written line that must survive' /etc/ppp/chap-secrets && grep -q '"alice" \* "alice-secret-1" \*' /etc/ppp/chap-secrets || { cat /etc/ppp/chap-secrets; nl_fail "chap-secrets: managed block missing or foreign line lost"; }
[ "$(stat -c %a /etc/ppp/chap-secrets)" = 600 ] || nl_fail "chap-secrets is not mode 0600"
nl_ok "chap-secrets has the user in a Patronus block, the foreign line is kept, mode 0600"
nl_assert_nft_has "iifname \"$NL_WAN_IF\" udp dport 1701 accept"

echo "=== a real L2TP client dials in"
connect alice || { cat /tmp/l2tp-client.log | tail -20; tail -20 /run/patronus/patronus-daemon.xl2tpd.log; nl_fail "the L2TP client never got a PPP address"; }
nl_ok "client got a PPP address: $(ISP ip -o addr show | grep -o 'inet 10.88.0.[0-9]*' | head -1)"
ISP ping -c 3 -W 2 10.88.0.1 >/dev/null || nl_fail "client cannot ping the server's tunnel address through PPP"
nl_ok "client pings the server's tunnel address 10.88.0.1 through the L2TP/PPP link"
R ip -o addr show | grep 'ppp[0-9]* .*10.88.0.1' >/dev/null || nl_fail "the router has no ppp interface with 10.88.0.1"
nl_api GET /svc/l2tp
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the session"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"], st
assert st["ppp_sessions"], st
PY
nl_ok "status: server running, a PPP session is listed"
nl_web GET /svc/l2tp
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "L2TP page: $NL_CODE"

echo "=== a disabled user is refused"
client_down
# a server with no enabled user is refused (and the change undone), so there is a second user first
nl_api_ok "add bob" POST /svc/l2tp/users '{"username":"bob","password":"bob-secret-123"}'
nl_api_ok "disable alice" PUT "/svc/l2tp/users/$ID" '{"enabled":false}'
grep -q '"alice"' /etc/ppp/chap-secrets && nl_fail "disabled user still in chap-secrets"
client_up alice
sleep 12
isp_ppp && nl_fail "a disabled user connected"
nl_ok "alice (disabled) is refused: no PPP address after 12 s"
client_down
nl_api_ok "enable alice again" PUT "/svc/l2tp/users/$ID" '{"enabled":true}'
connect alice || { tail -20 /tmp/l2tp-client.log; tail -20 /run/patronus/patronus-daemon.xl2tpd.log; nl_fail "alice could not connect after being re-enabled"; }
nl_ok "re-enabled user connects again"
client_down

echo "=== reboot: patronus apply brings the server back"
nl_web_stop
nl_kill_daemons xl2tpd pppd
nl_boot "$DB"
nl_wait 10 pgrep -x xl2tpd || nl_fail "xl2tpd not started by the boot apply"
nl_assert_nft_has "udp dport 1701 accept"
connect alice || { tail -20 /tmp/l2tp-client.log; tail -20 /run/patronus/patronus-daemon.xl2tpd.log; nl_fail "no L2TP session after the reboot"; }
nl_ok "after reboot: a client connects again"
client_down

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/l2tp '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x xl2tpd' || nl_fail "xl2tpd still running"
nl_assert_nft_lacks "udp dport 1701"
grep -q 'Managed by Patronus' /etc/ppp/chap-secrets && nl_fail "managed block still in chap-secrets"
grep -q 'hand-written line that must survive' /etc/ppp/chap-secrets || nl_fail "foreign line lost"
nl_ok "disabled: xl2tpd stopped, UDP 1701 closed, secrets block removed, foreign line kept"
nl_web_stop
echo "ALL L2TP CHECKS PASSED"
