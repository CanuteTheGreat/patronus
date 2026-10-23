#!/usr/bin/env bash
# Lane N: factory reset in the shipped binary. After a firewall rule, a VRF
# and a group were configured, a reset (typed confirmation + the admin's
# password) backs the configuration up, replaces it with first-boot
# defaults and applies it: the rule leaves nftables, the VRF device goes, the
# router still forwards for the LAN, the admin account still logs in and the
# backup is listed. A wrong password or confirmation changes nothing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-factory.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api POST /firewall/rules '{"name":"reset-me","chain":"forward","action":"reject","interface":"@lan","protocol":"tcp","source":"any","destination":"'$NL_WWW'","port":"9000","description":"reset-me","enabled":true}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "rule: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /system/groups '{"name":"temp","privileges":{"vpn":"read"}}'
[ "$NL_CODE" = 201 ] || nl_fail "group: $NL_CODE"
nl_assert_nft_has "reset-me"
nl_expect_http_blocked "rule blocks LAN -> www:9000" http://$NL_WWW:9000/

nl_api POST /system/factory-reset '{"password":"wrong-password-123","confirm":"RESET"}'
[ "$NL_CODE" = 403 ] || nl_fail "wrong password should be 403, got $NL_CODE"
nl_api POST /system/factory-reset "{\"password\":\"$NL_PASS\",\"confirm\":\"yes\"}"
[ "$NL_CODE" = 400 ] || nl_fail "missing RESET should be 400, got $NL_CODE"
nl_assert_nft_has "reset-me"
nl_ok "wrong password / confirmation: refused, nothing changed"

nl_api POST /system/factory-reset "{\"password\":\"$NL_PASS\",\"confirm\":\"RESET\"}"
[ "$NL_CODE" = 200 ] || nl_fail "reset: $NL_CODE $(cat "$NL_OUT")"
BK=$(jget 'd["backup"]')
nl_assert_nft_lacks "reset-me"
nl_ok "the rule is gone from nftables"
online() { nl_expect_ping $NL_WWW; nl_expect_http "LAN -> www (masqueraded)" http://$NL_WWW/ "sees $NL_RTR_WAN"; }
online
[ "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM rbac_groups')" = 0 ] || nl_fail "the group survived"
nl_ok "the router still works (default ruleset), groups are gone"
rm -f "$NL_T/nl-jar"; nl_login
nl_api GET /system/backups
grep -q "$BK" "$NL_OUT" || nl_fail "the pre-reset backup $BK is not listed"
nl_ok "admin still logs in; backup $BK kept"

echo "=== reboot: still the defaults"
nl_web_stop
nl_boot "$DB"
nl_assert_nft_lacks "reset-me"
online
echo "PASS lane-n-factory-reset"
