#!/usr/bin/env bash
# Lane H (UI): System > Configuration history driven in a real browser (ci/config-history-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router: make changes, see their revisions, diff, restore (the later change
# is gone, the earlier one remains), the 390 px phone layout and the confirm-or-revert timer with its banner.
# Fails (never skips) when Playwright/Firefox cannot be installed: the journey is the gate for this page.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-history-ui.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
PW=/opt/pw
if [ ! -x "$PW/bin/playwright" ]; then
  { apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1 \
    && python3 -m venv "$PW" && "$PW/bin/pip" install -q playwright \
    && "$PW/bin/playwright" install --with-deps firefox >/dev/null 2>&1; } \
    || { echo "resolv.conf:"; cat /etc/resolv.conf; nl_fail "Playwright/Firefox could not be installed in the netlab container"; }
fi
[ -f "$NL_T/config-history-page-e2e.py" ] || nl_fail "ci/config-history-page-e2e.py was not copied next to the scenarios"

nl_write_installer_toml
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_ok "booted, logged in"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" "$PW/bin/python" "$NL_T/config-history-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the configuration history page e2e failed (exit $rc)"
nl_ok "configuration history driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-h-history-ui"
