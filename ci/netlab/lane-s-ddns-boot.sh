#!/usr/bin/env bash
# Lane s: a dynamic-DNS provider that cannot be reached must not block the boot pass.
# Found 2026-11-27 (twin rehearsal): the router came up with a WAN lease but no working uplink, the ddns applier timed out (30 s per
# hostname) and `patronus apply --phase interfaces --phase routes --phase services` failed, so patronus-services retried the whole pass
# five times (~65 s each) and patronus-web came up minutes late.
#
#   client ---- rtr-lan [ rtr ] rtr-wan ---- isp ---- inet   (the ISP DROPs everything to the DDNS endpoint 198.51.100.20)
#
# Proves, with real packets (DROP, not reject, so the client really has to time out):
#  - the boot pass exits 0 within a few seconds, prints a DDNS warning and keeps the failure (fails, next_try) in the status file
#  - an immediate second pass makes no request at all (backoff) and still exits 0
#  - one run's total DDNS time is bounded by ddns.run_budget_secs however many clients there are
#  - patronus-web answers within NL_WEB_MAX seconds of being started right after the pass
#  - once the endpoint is reachable and "Update now" is pressed the update goes through and the status turns ok
# Static WAN stands in for the DHCP lease: the applier only needs an address on @wan.
set -eu
. "$(dirname "$0")/lib.sh"

T=$NL_T/lane-ddns-boot
rm -rf "$T"; mkdir -p "$T"
DB=$T/config.db
PASS="interfaces routes services"
cleanup() { nl_web_stop; nl_down; rm -f /var/lib/patronus/ddns-status.json; }
trap cleanup EXIT
rm -f /var/lib/patronus/ddns-status.json
mkdir -p /var/lib/patronus

boot_pass() { # -> exit status of the second boot pass; output in $NL_OUT
  R "$P" --db "$DB" apply --phase interfaces --phase routes --phase services >"$NL_OUT" 2>&1
}
timed() { # CMD... -> elapsed whole seconds in $ELAPSED, rc in $RC
  local s e; s=$(date +%s.%N); RC=0; "$@" || RC=$?; e=$(date +%s.%N)
  ELAPSED=$(python3 -c "print(int(float('$e')-float('$s')+0.999))")
}
add_client() { # HOST
  sqlite3 "$DB" "INSERT INTO ddns_clients (enabled, provider, hostname, interface, server, updated_at, family)
    VALUES (1,'custom','$1','@wan','http://198.51.100.20:8080/update?host=%h&ip=%i',strftime('%s','now'),'ipv4')"
}
status_get() { python3 -c 'import json,sys; d=json.load(open("/var/lib/patronus/ddns-status.json")); print(eval(sys.argv[1]))' "$1"; }

nl_up
nl_write_installer_toml
nl_boot "$DB"
# the ISP silently drops everything towards the DDNS endpoint
ISP nft add table ip dropddns
ISP nft 'add chain ip dropddns dropchain { type filter hook forward priority 0; policy accept; }'
ISP nft add rule ip dropddns dropchain ip daddr 198.51.100.20 drop
add_client home.example.test

echo "=== 1. unreachable provider: the boot pass succeeds with a warning"
timed boot_pass
[ "$RC" = 0 ] || { cat "$NL_OUT"; nl_fail "boot pass exited $RC with the DDNS endpoint unreachable"; }
[ "$ELAPSED" -le 20 ] || nl_fail "boot pass took ${ELAPSED}s (connect timeout default 5 s)"
grep -q 'DDNS home.example.test: update failed' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no DDNS warning in the apply output"; }
nl_ok "boot pass exit 0 in ${ELAPSED}s, DDNS reported as a warning"
[ "$(status_get 'd["custom:home.example.test"]["fails"]')" = 1 ] || nl_fail "status file lacks fails=1: $(cat /var/lib/patronus/ddns-status.json)"
[ "$(status_get 'd["custom:home.example.test"]["ok"]')" = False ] || nl_fail "status says ok"
nl_ok "failure kept with its backoff in the status file"

echo "=== 2. backoff: the next pass does not ask again"
timed boot_pass
[ "$RC" = 0 ] && [ "$ELAPSED" -le 3 ] || { cat "$NL_OUT"; nl_fail "second pass rc=$RC in ${ELAPSED}s (backoff should skip the request)"; }
grep -q 'next try in' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no backoff note"; }
nl_ok "second pass: exit 0 in ${ELAPSED}s, backoff honoured"

echo "=== 3. many clients: one run stays inside ddns.run_budget_secs"
sqlite3 "$DB" "INSERT INTO lan_settings (key,value,updated_at) VALUES ('ddns.connect_timeout_secs','3',0),('ddns.run_budget_secs','5',0)
  ON CONFLICT(key) DO UPDATE SET value=excluded.value"
for i in 1 2 3 4 5 6; do add_client "h$i.example.test"; done
timed boot_pass
[ "$RC" = 0 ] || { cat "$NL_OUT"; nl_fail "pass with six unreachable clients exited $RC"; }
[ "$ELAPSED" -le 12 ] || nl_fail "six clients took ${ELAPSED}s with a 5 s budget"
grep -q 'budget is used up' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no budget note"; }
nl_ok "six unreachable clients: exit 0 in ${ELAPSED}s (budget 5 s, connect timeout 3 s)"

echo "=== 4. the web UI answers right after the pass"
S=$(date +%s)
nl_web_start "$DB"
W=$(( $(date +%s) - S ))
[ "$W" -le "${NL_WEB_MAX:-15}" ] || nl_fail "patronus-web needed ${W}s"
nl_ok "patronus-web answers ${W}s after it was started"

echo "=== 5. the provider comes back: Update now goes through"
ISP nft flush chain ip dropddns dropchain
sqlite3 "$DB" "DELETE FROM ddns_clients WHERE hostname <> 'home.example.test'"
sqlite3 "$DB" "INSERT INTO lan_settings (key,value,updated_at) VALUES ('ddns.force','$(( $(date +%s) + 5 ))',0)
  ON CONFLICT(key) DO UPDATE SET value=excluded.value"
timed boot_pass
[ "$RC" = 0 ] || { cat "$NL_OUT"; nl_fail "pass after recovery exited $RC"; }
[ "$(status_get 'd["custom:home.example.test"]["ok"]')" = True ] || { cat "$NL_OUT"; nl_fail "update did not succeed: $(cat /var/lib/patronus/ddns-status.json)"; }
[ "$(status_get 'd["custom:home.example.test"]["fails"]')" = 0 ] || nl_fail "fails not reset"
nl_ok "update reached the provider, status ok, failure counter reset"
echo "lane-s-ddns-boot: pass"
