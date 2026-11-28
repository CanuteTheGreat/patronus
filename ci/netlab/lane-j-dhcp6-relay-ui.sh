#!/usr/bin/env bash
# Lane J (UI): the DHCPv6 relay page driven in a real browser (ci/dhcp6-relay-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router: menu entry, every setting and the rules table, phone width
# in the light and dark scheme, a refused server / no-rule switch-on / multicast rule without upstream shown ON THE PAGE,
# then a rule saved through the form, the relay switched on and off and the rule deleted. Needs Playwright + Firefox
# preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing). The relayed traffic is
# proven by lane-j-dhcp6-relay.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

export PATH="$NL_T:$PATH"   # the relay daemon is `patronus dhcp6-relay run`
DB=/t/lane-j-dhcp6-relay-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/dhcp6-relay-page-e2e.py" ] || { echo "SKIP lane-j-dhcp6-relay-ui: ci/dhcp6-relay-page-e2e.py was not copied next to the scenarios"; exit 0; }
nl_write_installer_toml
nl_kill_daemons
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"
nl_ok "booted"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" \
      "$PW/bin/python" "$NL_T/dhcp6-relay-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the DHCPv6 relay page e2e failed (exit $rc)"
nl_ok "DHCPv6 relay page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks"
nl_web_stop
nl_kill_daemons
pkill -f '[d]hcp6-relay run' || true
echo "ALL DHCP6-RELAY UI CHECKS PASSED"
