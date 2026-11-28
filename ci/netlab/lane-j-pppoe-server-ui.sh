#!/usr/bin/env bash
# Lane J (UI): the PPPoE server page driven in a real browser (ci/pppoe-server-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router: menu entry, every setting, the users table, phone width in the
# light and dark scheme, a refused pool shown on the page, a user through the form (password never shown), then switching
# the server on and off through the page. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh
# (fails, never skips, when they are missing). The PPPoE traffic is proven by lane-j-pppoe-server.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-pppoe-server-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/pppoe-server-page-e2e.py" ] || nl_fail "ci/pppoe-server-page-e2e.py was not copied next to the scenarios"
nl_write_installer_toml
nl_kill_daemons pppoe-server pppd pppoe
: > /etc/ppp/chap-secrets 2>/dev/null || { mkdir -p /etc/ppp; : > /etc/ppp/chap-secrets; }
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_IFACES=@lan \
      "$PW/bin/python" "$NL_T/pppoe-server-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the PPPoE server page e2e failed (exit $rc)"
nl_ok "PPPoE server page driven in Firefox: $(echo "$out" | grep -c '^PASS:') checks passed"
nl_web_stop
echo "ALL PPPOE-SERVER UI CHECKS PASSED"
