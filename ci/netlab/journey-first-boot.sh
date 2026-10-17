#!/usr/bin/env bash
# Customer journey: fresh install -> first boot -> a LAN client is online
# through NAT -> the admin adds a block rule in the web UI -> the traffic is
# really blocked (other traffic still flows) -> reboot -> still enforced ->
# the admin deletes the rule -> traffic flows again -> reboot -> still
# deleted. Every step asserts real traffic from the LAN client and the
# router's kernel state, not just an HTTP status.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/var/lib/patronus-journey/config.db   # a fresh install: no store yet
rm -rf "$(dirname "$DB")"
nl_write_installer_toml

echo "=== fresh install, first boot"
nl_up
nl_expect_http_blocked "LAN -> internet before Patronus ran (router not forwarding)" "http://$NL_WWW/"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "first boot apply"; }
grep -q 'first boot: seeded the default ruleset' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "first boot did not seed defaults"; }
nl_ok "first boot seeded the default ruleset from the installer's patronus.toml"
nl_assert_store_ok "$DB"
nl_assert_router_baseline
nl_expect_online
nl_assert_conntrack "dst=$NL_WWW .*dport=80 .*dst=$NL_RTR_WAN"   # the NATed flow, reply to the WAN address
nl_expect_wan_closed
nl_expect_tcp "LAN -> router SSH (anti-lockout)" C $NL_RTR_LAN 22

echo "=== admin blocks blocked.example.test in the web UI"
nl_web_start "$DB"
nl_login
nl_web GET /firewall
[ "$NL_CODE" = 200 ] && grep -q 'Anti-lockout' "$NL_OUT" || nl_fail "firewall page ($NL_CODE) does not list the anti-lockout rule"
nl_ok "firewall page lists the seeded rules"
nl_expect_http "LAN -> blocked.example.test before the rule" http://blocked.example.test/ "blocked.example.test sees $NL_RTR_WAN"
nl_api POST /firewall/rules '{"name":"journey-block","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"journey-block","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add rule: $NL_CODE $(cat "$NL_OUT")"
RULE_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT")
nl_ok "rule journey-block created (id $RULE_ID)"
nl_web GET /firewall
grep -q 'journey-block' "$NL_OUT" || nl_fail "firewall page does not show the new rule"
nl_ok "firewall page shows journey-block"
nl_assert_nft_has 'ip daddr 198.51.100.20 tcp dport 80 drop'
nl_expect_http_blocked "LAN -> blocked.example.test after the rule" http://blocked.example.test/
nl_expect_http "LAN -> www.example.test still works" http://www.example.test/ "sees $NL_RTR_WAN"
nl_expect_http "LAN -> blocked.example.test:8080 (other port) still works" http://blocked.example.test:8080/ "sees"

echo "=== reboot"
nl_web_stop
nl_boot "$DB"
nl_assert_router_baseline
nl_assert_nft_has 'ip daddr 198.51.100.20 tcp dport 80 drop'
nl_expect_http_blocked "after reboot: LAN -> blocked.example.test" http://blocked.example.test/
nl_expect_online
nl_web_start "$DB"
nl_login
nl_web GET /firewall
grep -q 'journey-block' "$NL_OUT" || nl_fail "after reboot the firewall page lost the rule"
nl_ok "after reboot the firewall page still shows journey-block"

echo "=== admin deletes the rule"
nl_api DELETE "/firewall/rules/$RULE_ID"
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 204 ] || nl_fail "delete: $NL_CODE $(cat "$NL_OUT")"
nl_assert_nft_lacks 'journey-block'
nl_expect_http "LAN -> blocked.example.test after delete" http://blocked.example.test/ "sees $NL_RTR_WAN"
nl_web_stop
nl_boot "$DB"
nl_assert_nft_lacks 'journey-block'
nl_expect_http "after reboot: deletion persisted" http://blocked.example.test/ "sees $NL_RTR_WAN"

nl_down
echo "JOURNEY FIRST BOOT: ALL CHECKS PASSED"
