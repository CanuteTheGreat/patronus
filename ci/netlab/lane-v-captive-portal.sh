#!/usr/bin/env bash
# Lane U: captive portal (USE=captive-portal) in the shipped binaries, proven on the kernel with real packets. The portal
# zone is the LAN port; the LAN client is the portal client; the internet side runs a FreeRADIUS server.
#  - off: the client reaches the internet, no portal table;
#  - zone on: the client's web requests land on the sign-in page (HTTP 80 redirect to HTTPS on the router's standard
#    port), everything else beyond the router is refused, the RFC 8908 API says captive, DHCP hands out option 114;
#  - click-through (terms), portal users, vouchers and RADIUS each sign the client in; wrong input is refused;
#  - idle timeout, hard timeout (voucher time), logout and an administrator's disconnect each block the client again;
#  - RADIUS accounting Start and Stop reach the FreeRADIUS server;
#  - per-client bandwidth classes exist while a limited session runs and are gone after it;
#  - MAC and IP passthrough skip the portal, an allowed destination is reachable before sign-in;
#  - switching the zone off removes the table.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

set -E
trap 'echo "ABORT at line $LINENO: $BASH_COMMAND" >&2' ERR
DB=/t/lane-v-captive-portal.db
rm -f "$DB" "$NL_T/nl-jar"
RTR=$NL_RTR_LAN
PORTAL="https://$RTR"
# a signed-in client reaches the portal on its own port (the standard ports are the router's again)
PORTAL_S="https://$RTR:8003"
RADIUS_IP=198.51.100.30
RADIUS_SECRET=netlab-radius-test-secret
RLOG=$NL_T/nl-radius.log
FR=/etc/freeradius/3.0
command -v freeradius >/dev/null || nl_fail "freeradius missing in the lab image (ci/netlab/run.sh installs it)"
command -v tc >/dev/null || nl_fail "tc (iproute2) missing in the lab image"

nl_fail() {
  set +e
  echo "FAIL: $*" >&2
  { echo "--- nft ruleset"; R nft list ruleset; echo "--- sessions"; sqlite3 "$DB" 'SELECT id, zone, ip, mac, method, username, started, expires, ended, end_reason FROM cp_sessions';
    echo "--- tc"; R tc -s class show dev "$NL_LAN_IF"; R tc filter show dev "$NL_LAN_IF" ingress; echo "--- radius log tail"; tail -40 "$RLOG";
    echo "--- web log tail"; grep -i -e captive -e portal -e error "$NL_T/nl-web.log" | tail -40; } >&2 2>/dev/null || true
  exit 1
}
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
# out_has PATTERN CMD...: the command's output matches (no pipe into grep -q: see ci/lint-no-pipe-grep-q.sh)
out_has() { local pat=$1 out; shift; out=$("$@" 2>&1 || true); grep -q -- "$pat" <<<"$out"; }

# --- RADIUS server on the internet side -----------------------------------------------------------------------------
fr_restore() { for f in clients.conf mods-config/files/authorize; do [ -f "$FR/$f.nl-orig" ] && mv -f "$FR/$f.nl-orig" "$FR/$f"; done; true; }
cleanup() { fr_restore; }
trap cleanup EXIT
fr_setup() {
  for f in clients.conf mods-config/files/authorize; do [ -f "$FR/$f.nl-orig" ] || cp -p "$FR/$f" "$FR/$f.nl-orig"; done
  printf '\nclient netlab-router {\n  ipaddr = 203.0.113.0/24\n  secret = %s\n  require_message_authenticator = yes\n}\n' "$RADIUS_SECRET" >> "$FR/clients.conf"
  { printf 'raduser Cleartext-Password := "rad-pass-1"\n        Session-Timeout = 3600\n\n'; cat "$FR/mods-config/files/authorize.nl-orig"; } > "$FR/mods-config/files/authorize"
  INET ip addr add $RADIUS_IP/24 dev inet0
  : > "$RLOG"
  ip netns exec nl-inet freeradius -X >"$RLOG" 2>&1 &
  NL_PIDS+=($!)
  for _ in $(seq 1 60); do grep -q 'Ready to process requests' "$RLOG" && return 0; sleep 0.5; done
  tail -30 "$RLOG"; nl_fail "FreeRADIUS did not start"
}

# --- client helpers ------------------------------------------------------------------------------------------------
online() { C curl -s -m 4 -o "$NL_OUT.net" "http://$NL_WWW/" && grep -q "sees $NL_RTR_WAN" "$NL_OUT.net"; }
offline() { ! online; }
tcp_out() { C python3 "$NL_T/nl-conn.py" "$1" 9000 >/dev/null 2>&1; }
# portal REQ...: a request from the client to the portal (curl -k: the lab's self-signed certificate); body in $NL_OUT
portal() { PCODE=$(C curl -sk -m 8 -o "$NL_OUT" -w '%{http_code}' "$@" || true); }
login() { portal -X POST "$@" "$PORTAL/login"; }
logout() { portal -X POST "$PORTAL_S/logout"; }
expect_online() { nl_wait 8 online || nl_fail "$1: the client is not online"; nl_ok "$1: client online (masqueraded as $NL_RTR_WAN)"; }
expect_blocked() {
  nl_wait 12 offline || nl_fail "$1: the client still reaches the internet"
  ! tcp_out "$NL_WWW" || nl_fail "$1: TCP to the internet still passes"
  nl_ok "$1: client blocked (web goes to the portal, other TCP refused)"
}
last_session() { sqlite3 "$DB" "SELECT $1 FROM cp_sessions ORDER BY id DESC LIMIT 1"; }
ended_with() { [ "$(last_session end_reason)" = "$1" ]; }
zone_put() { nl_api_ok "zone change $1" PUT "/svc/captive/zones/$ZID" "$1"; sleep 2; }

nl_write_installer_toml
nl_dnsmasq_shim
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
fr_setup
CMAC=$(C cat /sys/class/net/lan0/address 2>/dev/null || true)
[ -n "$CMAC" ] || nl_fail "client MAC unknown"

echo "=== 1. off: nothing in the way"
expect_online "portal off"
nl_assert_nft_lacks patronus_portal
nl_api GET /svc/captive; [ "$NL_CODE" = 200 ] || nl_fail "captive settings API: $NL_CODE $(cat "$NL_OUT")"
[ "$(jget 'd["settings"]["https_port"]')" = 8003 ] && [ "$(jget 'd["settings"]["http_port"]')" = 8002 ] || nl_fail "default portal ports: $(cat "$NL_OUT")"
nl_web GET /captive-portal; [ "$NL_CODE" = 200 ] && grep -q 'Signed-in clients' "$NL_OUT" || nl_fail "sessions page ($NL_CODE)"
nl_api_code "a RADIUS zone without a server" 400 POST /svc/captive/zones '{"name":"x","interface":"@lan","auth":"radius"}'
nl_ok "off by default; RADIUS zone without a server refused"

echo "=== 2. zone on: the client is captured"
nl_api POST /svc/captive/zones '{"name":"lobby","interface":"@lan","auth":"none","idle_minutes":1,"hard_minutes":480,"page_title":"Lobby Wi-Fi","terms_text":"I accept the lab terms."}'
[ "$NL_CODE" = 201 ] || nl_fail "add zone: $NL_CODE $(cat "$NL_OUT")"
ZID=$(jget 'd["id"]')
nl_wait 10 out_has "table inet patronus_portal" R nft list tables || nl_fail "portal table not loaded"
nl_assert_nft_has "redirect to :8002"
expect_blocked "zone on, not signed in"
portal_http_up() { [ "$(C curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$NL_WWW/" || true)" = 302 ]; }
nl_wait 15 portal_http_up || nl_fail "the portal's HTTP listener does not answer"
PCODE=$(C curl -s -m 8 -o /dev/null -w '%{http_code} %{redirect_url}' "http://$NL_WWW/some/page?x=1" || true)
case "$PCODE" in "302 https://$RTR/?redirurl=http%3A%2F%2F$NL_WWW%2Fsome%2Fpage%3Fx%3D1") ;; *) nl_fail "HTTP is not sent to the portal: $PCODE";; esac
nl_ok "HTTP to anywhere -> 302 to $PORTAL/ with the page asked for"
portal "$PORTAL/"
[ "$PCODE" = 200 ] && grep -q 'Lobby Wi-Fi' "$NL_OUT" && grep -q 'name="terms"' "$NL_OUT" || nl_fail "splash page over HTTPS 443 ($PCODE): $(head -c 400 "$NL_OUT")"
nl_ok "splash page served on https://router/ (standard port), zone texts shown"
portal "https://$RTR:8003/api/captive"
[ "$PCODE" = 200 ] && [ "$(jget 'd["captive"]')" = True ] || nl_fail "RFC 8908 API before login: $PCODE $(cat "$NL_OUT")"
grep -q "\"user-portal-url\":\"https://$RTR:8003/\"" "$NL_OUT" || nl_fail "RFC 8908 user-portal-url: $(cat "$NL_OUT")"
nl_ok "RFC 8908 API: captive, user-portal-url"
nl_api_ok "DHCP pool on the zone" POST /dhcp/pools '{"interface":"@lan","range_start":"192.168.50.100","range_end":"192.168.50.199","lease_time":3600}'
nl_wait 15 grep -q "114,\"https://$RTR:8003/api/captive\"" /etc/dnsmasq.conf || { grep -n dhcp-option /etc/dnsmasq.conf; nl_fail "DHCP option 114 missing"; }
nl_ok "DHCP option 114 (RFC 8910) points at the API"

echo "=== 3. click-through: terms first"
login --data-urlencode "redirurl=http://$NL_WWW/x"
[ "$PCODE" = 400 ] && grep -q 'role="alert"' "$NL_OUT" || nl_fail "login without the terms must be refused (400), got $PCODE"
offline || nl_fail "refused login let the client out"
login --data-urlencode terms=1 --data-urlencode "redirurl=http://$NL_WWW/x"
[ "$PCODE" = 303 ] || nl_fail "click-through login: $PCODE $(head -c 300 "$NL_OUT")"
REDIR=$(C curl -sk -m 8 -o /dev/null -w '%{redirect_url}' -X POST --data-urlencode terms=1 "$PORTAL_S/login" || true)
[ "$REDIR" = "$PORTAL_S/status" ] || nl_fail "signed-in login answer should lead to the status page on the portal port: $REDIR"
expect_online "click-through"
portal "https://$RTR:8003/api/captive"
[ "$(jget 'd["captive"]')" = False ] || nl_fail "RFC 8908 API after login: $(cat "$NL_OUT")"
nl_api GET /captive-portal/sessions; [ "$(jget 'len(d["sessions"])')" = 1 ] && [ "$(jget 'd["sessions"][0]["mac"]')" = "$CMAC" ] || nl_fail "sessions API: $(cat "$NL_OUT")"
out_has "$CMAC" R "$P" --db "$DB" captive-portal sessions || nl_fail "CLI does not list the session"
nl_ok "session listed in the API and the CLI"

echo "=== 4. logout blocks again"
portal "$PORTAL_S/logout"
[ "$PCODE" = 200 ] && grep -q 'id="cp-logout"' "$NL_OUT" || nl_fail "status page on the portal port: $PCODE"
offline && nl_fail "a GET of /logout must not sign out" || true
logout
[ "$PCODE" = 200 ] || nl_fail "logout: $PCODE"
expect_blocked "after logout"
ended_with "logged out" || nl_fail "end reason: $(last_session end_reason)"

echo "=== 5. idle timeout (1 minute)"
login --data-urlencode terms=1; [ "$PCODE" = 303 ] || nl_fail "login: $PCODE"
expect_online "signed in again"
# no forwarded traffic from now on (a check through the router would count as activity): watch the store
for _ in $(seq 1 60); do ended_with "idle timeout" && break; sleep 2; done
ended_with "idle timeout" || nl_fail "idle timeout did not end the session after 120 s"
expect_blocked "after the idle timeout"

echo "=== 6. portal users + per-client bandwidth + administrator's disconnect"
zone_put '{"auth":"local","idle_minutes":0,"download_kbit":2000,"upload_kbit":1000}'
nl_api_ok "add portal user" POST /svc/captive/users '{"username":"guest1","password":"guest-pass-1"}'
[ "$(sqlite3 "$DB" "SELECT substr(password,1,10) FROM cp_users WHERE username='guest1'")" = '$argon2id$' ] || nl_fail "portal password not stored as argon2id"
login --data-urlencode username=guest1 --data-urlencode password=wrong --data-urlencode terms=1
[ "$PCODE" = 401 ] || nl_fail "wrong password: $PCODE"
login --data-urlencode username=nobody --data-urlencode password=guest-pass-1 --data-urlencode terms=1
[ "$PCODE" = 401 ] || nl_fail "unknown user: $PCODE"
offline || nl_fail "refused login let the client out"
login --data-urlencode username=guest1 --data-urlencode password=guest-pass-1 --data-urlencode terms=1
[ "$PCODE" = 303 ] || nl_fail "portal user login: $PCODE"
expect_online "portal user"
[ "$(last_session username)" = guest1 ] || nl_fail "session user: $(last_session username)"
out_has "rate 2Mbit" R tc class show dev "$NL_LAN_IF" || nl_fail "no 2 Mbit/s download class"
out_has "police" R tc filter show dev "$NL_LAN_IF" ingress || nl_fail "no upload policer"
nl_ok "download class 2 Mbit/s and upload policer on $NL_LAN_IF"
SID=$(last_session id)
nl_api_ok "disconnect" POST "/captive-portal/sessions/$SID/disconnect"
for _ in $(seq 1 15); do ended_with "disconnected by an administrator" && break; sleep 1; done
ended_with "disconnected by an administrator" || nl_fail "admin disconnect: $(last_session end_reason)"
expect_blocked "after the administrator's disconnect"
! out_has "rate 2Mbit" R tc class show dev "$NL_LAN_IF" || nl_fail "bandwidth class left behind"
nl_ok "bandwidth class removed with the session"

echo "=== 7. vouchers: hard timeout = the voucher's time"
zone_put '{"auth":"voucher","idle_minutes":0,"download_kbit":0,"upload_kbit":0}'
nl_api_ok "voucher roll" POST /svc/captive/rolls '{"name":"day1","zone":"lobby","count":3,"minutes":1}'
mapfile -t CODES < <(R "$P" --db "$DB" captive-portal vouchers day1)
[ "${#CODES[@]}" = 3 ] && [ "${#CODES[0]}" = 10 ] || nl_fail "voucher codes: ${CODES[*]:-none}"
nl_web GET "/captive-portal/rolls/$(sqlite3 "$DB" "SELECT id FROM cp_voucher_rolls WHERE name='day1'")/print"
[ "$NL_CODE" = 200 ] && grep -q "${CODES[1]}" "$NL_OUT" || nl_fail "print sheet ($NL_CODE)"
nl_ok "roll of 3 codes, print sheet lists them"
login --data-urlencode voucher=WRONGCODE1 --data-urlencode terms=1
[ "$PCODE" = 401 ] || nl_fail "wrong voucher: $PCODE"
login --data-urlencode "voucher=${CODES[0],,}" --data-urlencode terms=1
[ "$PCODE" = 303 ] || nl_fail "voucher login (lower case): $PCODE"
expect_online "voucher"
EXP=$(( $(last_session expires) - $(last_session started) ))
[ "$EXP" -le 60 ] && [ "$EXP" -ge 58 ] || nl_fail "voucher session length $EXP s, want 60"
for _ in $(seq 1 45); do ended_with "hard timeout" && break; online >/dev/null 2>&1 || true; sleep 2; done
ended_with "hard timeout" || nl_fail "hard timeout did not end the session: $(last_session end_reason)"
expect_blocked "after the hard timeout"
login --data-urlencode "voucher=${CODES[0]}" --data-urlencode terms=1
[ "$PCODE" = 401 ] || nl_fail "a used-up voucher must be refused, got $PCODE"
nl_ok "used-up voucher refused"

echo "=== 8. RADIUS: login, accounting Start/Stop"
zone_put "{\"auth\":\"radius\",\"radius_server\":\"$RADIUS_IP\",\"radius_secret\":\"$RADIUS_SECRET\",\"radius_nas_id\":\"netlab-portal\"}"
login --data-urlencode username=raduser --data-urlencode password=wrong --data-urlencode terms=1
[ "$PCODE" = 401 ] || nl_fail "RADIUS reject: $PCODE"
grep -q 'Access-Reject' "$RLOG" || nl_fail "FreeRADIUS saw no rejected request"
login --data-urlencode username=raduser --data-urlencode password=rad-pass-1 --data-urlencode terms=1
[ "$PCODE" = 303 ] || nl_fail "RADIUS login: $PCODE $(head -c 300 "$NL_OUT")"
expect_online "RADIUS user"
RSID=$(last_session sid)
[ "$(( $(last_session expires) - $(last_session started) ))" = 3600 ] || nl_fail "Session-Timeout from RADIUS not used"
nl_wait 10 grep -q "Acct-Session-Id = \"$RSID\"" "$RLOG" || nl_fail "no accounting for $RSID at the RADIUS server"
nl_wait 5 out_has "Acct-Status-Type = Start" grep -B25 -A5 "Acct-Session-Id = \"$RSID\"" "$RLOG" || nl_fail "accounting Start missing"
out_has "NAS-Identifier = \"netlab-portal\"" cat "$RLOG" || nl_fail "NAS-Identifier missing"
nl_ok "RADIUS Access-Accept used (Session-Timeout 3600), accounting Start received"
logout
expect_blocked "RADIUS user logged out"
nl_wait 10 out_has "Acct-Status-Type = Stop" grep -B25 -A5 "Acct-Session-Id = \"$RSID\"" "$RLOG" || nl_fail "accounting Stop missing"
out_has "Acct-Terminate-Cause = User-Request" cat "$RLOG" || nl_fail "Stop without terminate cause"
nl_ok "accounting Stop (User-Request) received"

echo "=== 9. passthrough"
nl_api POST /svc/captive/passthrough "{\"zone\":\"lobby\",\"kind\":\"host\",\"value\":\"$NL_BLOCKED\"}"; [ "$NL_CODE" = 201 ] || nl_fail "host passthrough: $NL_CODE"
nl_wait 10 tcp_out "$NL_BLOCKED" || nl_fail "allowed destination not reachable before sign-in"
! tcp_out "$NL_WWW" || nl_fail "passthrough destination opened everything"
nl_ok "allowed destination reachable before sign-in, nothing else"
nl_api POST /svc/captive/passthrough "{\"zone\":\"lobby\",\"kind\":\"mac\",\"value\":\"$CMAC\"}"; [ "$NL_CODE" = 201 ] || nl_fail "MAC passthrough: $NL_CODE"
PMAC=$(jget 'd["id"]')
expect_online "MAC passthrough, no login"
nl_api_ok "remove MAC passthrough" DELETE "/svc/captive/passthrough/$PMAC"
expect_blocked "MAC passthrough removed"
nl_api POST /svc/captive/passthrough "{\"zone\":\"lobby\",\"kind\":\"ip\",\"value\":\"$NL_CLIENT\"}"; [ "$NL_CODE" = 201 ] || nl_fail "IP passthrough: $NL_CODE"
PIP=$(jget 'd["id"]')
expect_online "IP passthrough, no login"
nl_api_ok "remove IP passthrough" DELETE "/svc/captive/passthrough/$PIP"
expect_blocked "IP passthrough removed"

echo "=== 10. switch off"
zone_put '{"enabled":false}'
nl_wait 10 sh -c "! ip netns exec nl-rtr nft list table inet patronus_portal >/dev/null 2>&1" || nl_fail "portal table left after the zone was switched off"
expect_online "zone off"
echo "PASS lane-v-captive-portal"
