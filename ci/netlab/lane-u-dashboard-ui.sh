#!/usr/bin/env bash
# Lane U (UI): the customizable dashboard, the system activity page and the Diagnostics port test driven in a real
# browser (ci/dashboard-page-e2e.py, Playwright + Firefox) against the shipped patronus-web in the netlab router:
# default layout, keyboard and mouse add/remove/reorder, persistence across reloads, a second (read-only) user who
# keeps the default and their own layout, reset, axe-core contrast/ARIA in light and dark on desktop (1280) and phone
# (390), the process list with sorting and the daemon filter, and the port test. Needs Playwright + Firefox preinstalled
# at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing). The API behind every button is also
# proven by the web crate's dashboard_tests and, for the port test, by lane-h-diag.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-u-dashboard-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/dashboard-page-e2e.py" ] || { echo "SKIP lane-u-dashboard-ui: ci/dashboard-page-e2e.py was not copied next to the scenarios"; exit 0; }

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_ok "booted: router with its web UI"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_PORT_TEST_HOST="$NL_CLIENT" AXE_JS="$NL_T/axe.min.js" \
      "$PW/bin/python" "$NL_T/dashboard-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the dashboard page e2e failed (exit $rc)"
nl_ok "dashboard, activity page and port test driven in Firefox (light/dark, desktop/phone): $(grep -c '^PASS:' <<<"$out") checks passed"
nl_web_stop
nl_down
echo "PASS lane-u-dashboard-ui"
