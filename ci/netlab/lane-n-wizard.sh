#!/usr/bin/env bash
# Lane N: first-boot setup wizard in the shipped binary. The wizard page is
# served, /api/setup/status lists the ports and "not completed"; one
# POST /api/setup/apply sets WAN/LAN roles + addresses and a DHCP pool, which
# the real appliers put on the kernel/dnsmasq; "completed" persists in the
# store and the settings survive a reboot (`patronus apply`).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-wizard.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_web GET /setup; [ "$NL_CODE" = 200 ] && grep -q 'id="setup-form"' "$NL_OUT" || nl_fail "setup page: $NL_CODE"
nl_api GET /setup/status; [ "$NL_CODE" = 200 ] || nl_fail "status $NL_CODE"
[ "$(jget 'd["completed"]')" = False ] || nl_fail "wizard should start as not completed: $(cat "$NL_OUT")"
[ "$(jget 'any(i["name"]=="rtr-lan" for i in d["interfaces"])')" = True ] || nl_fail "ports not listed: $(cat "$NL_OUT")"
nl_ok "wizard page served; status lists the ports; not completed yet"

nl_api POST /setup/apply '{"wan_interface":"rtr-lan","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24"}'
[ "$NL_CODE" = 400 ] || nl_fail "same port for WAN and LAN must be refused: $NL_CODE"
nl_api POST /setup/apply '{"wan_interface":"rtr-wan","wan_mode":"static","wan_ipv4":"203.0.113.2/24","wan_gateway":"203.0.113.1","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","dhcp":false,"force":true}'
[ "$NL_CODE" = 200 ] || nl_fail "apply: $NL_CODE $(cat "$NL_OUT")"
nl_ok "wizard applied"
nl_api POST /setup/apply '{"wan_interface":"rtr-wan","lan_interface":"rtr-lan","lan_ipv4":"192.168.50.1/24","dhcp":true,"force":true}'
[ "$NL_CODE" = 400 ] || nl_fail "a DHCP pool without a range must be refused (400), got $NL_CODE $(cat "$NL_OUT")"
nl_ok "an incomplete DHCP pool is refused"

nl_api GET /setup/status
[ "$(jget 'd["completed"]')" = True ] || nl_fail "not marked completed"
R ip -4 addr show rtr-lan | grep 'inet 192.168.50.1/24' >/dev/null || nl_fail "LAN address missing"
R ip -4 addr show rtr-wan | grep 'inet 203.0.113.2/24' >/dev/null || nl_fail "WAN address missing"
nl_ok "addresses on the kernel, completed flag in the store (the DHCP pool goes through the DHCP page's manager, proven by lan-services)"

echo "=== reboot: everything comes back from the store"
nl_web_stop
nl_boot "$DB"
R ip -4 addr show rtr-lan | grep 'inet 192.168.50.1/24' >/dev/null || nl_fail "LAN address lost after reboot"
nl_expect_ping $NL_WWW
echo "PASS lane-n-wizard"
