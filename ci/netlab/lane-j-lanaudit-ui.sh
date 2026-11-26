#!/usr/bin/env bash
# Lane J (UI): the LAN security audit page driven in a real browser (ci/lanaudit-page-e2e.py,
# Playwright + Firefox) against the shipped patronus-web in the netlab router, at 1280 and 390 px
# in light and dark: the menu entry, the data loading, no sideways scrolling, the colour scheme, a
# refused setting shown on the page, saving the form and starting a scan from the page. Needs
# Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh. The scan side is proven by
# lane-j-lanaudit.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-lanaudit-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/lanaudit-page-e2e.py" ] || { echo "SKIP lane-j-lanaudit-ui: ci/lanaudit-page-e2e.py was not copied next to the scenarios"; exit 0; }
export PATRONUS_LANAUDIT_FORCE_BUILTIN=1 PATRONUS_LANAUDIT_TICK_SECS=1
trap 'nl_web_stop' EXIT

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /lanaudit/settings '{"enabled":true,"interval_hours":0}'
[ "$NL_CODE" = 200 ] || nl_fail "enable: $NL_CODE $(cat "$NL_OUT")"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_SHOTS=/t/shots \
      "$PW/bin/python" "$NL_T/lanaudit-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the LAN audit page e2e failed (exit $rc)"
nl_ok "LAN audit page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks at 1280/390 px, light and dark"
