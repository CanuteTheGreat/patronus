#!/usr/bin/env bash
# Lane B/J (UI): the security overview page driven in a real browser (ci/security-page-e2e.py, Playwright +
# Firefox) against the shipped patronus-web in the netlab router, at 1280 and 390 px in light and dark: menu entry,
# grade, every check with a badge and a Fix link, the threat-feed catalog, the dashboard card, no sideways
# scrolling, colour scheme; the dry-run dialog, apply (one revision, score up), Undo, alert-only mode from the
# catalog. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they
# are missing). The kernel side is proven by lane-b-security.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-security-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/security-page-e2e.py" ] || { echo "SKIP lane-b-security-ui: ci/security-page-e2e.py was not copied next to the scenarios"; exit 0; }
trap 'nl_web_stop' EXIT

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
# something for the baseline to do
nl_api PUT /guard/settings '{"enabled":false}'
[ "$NL_CODE" = 200 ] || nl_fail "guard off: $NL_CODE $(cat "$NL_OUT")"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_SHOTS=/t/shots \
      "$PW/bin/python" "$NL_T/security-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the security page e2e failed (exit $rc)"
nl_ok "security overview page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks at 1280/390 px, light and dark"
