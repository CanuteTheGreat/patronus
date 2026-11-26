#!/usr/bin/env bash
# Lane W (UI): the UI language and the API reference driven in a real browser (ci/i18n-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router: the sign-in page follows the browser's language, a wrong
# password shows the API's error in German, the menu and the API reference page are German, the account's own language
# beats the browser, a refused change shows the German error, the system default applies to everyone, and desktop and
# phone widths do not scroll sideways. The API side (translated errors, per-account language, the OpenAPI document
# against the router's routes) is also proven by the web crate's tests.
# Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-w-i18n-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/i18n-page-e2e.py" ] || { echo "SKIP lane-w-i18n-ui: ci/i18n-page-e2e.py was not copied next to the scenarios"; exit 0; }

nl_write_installer_toml
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_ok "booted"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" "$PW/bin/python" "$NL_T/i18n-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the language page e2e failed (exit $rc)"
nl_ok "language and API reference driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-w-i18n-ui"
