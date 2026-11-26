#!/usr/bin/env bash
# Lane H (UI): System > Access log in a real browser (ci/access-log-page-e2e.py, Playwright + Firefox): menu entry,
# listed requests, filter/reset, detail dialog, statistics drill-down, audit tab, 1280 + 390 px, light + dark, contrast.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
DB=/t/lane-h-access-log-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/access-log-page-e2e.py" ] || { echo "SKIP lane-h-access-log-ui: ci/access-log-page-e2e.py was not copied next to the scenarios"; exit 0; }
nl_write_installer_toml
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" "$PW/bin/python" "$NL_T/access-log-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the access log page e2e failed (exit $rc)"
nl_ok "access log page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-h-access-log-ui"
