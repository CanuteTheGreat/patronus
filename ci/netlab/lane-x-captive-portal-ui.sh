#!/usr/bin/env bash
# Lane X (UI): the captive portal's sign-in page driven in a real browser (ci/captive-portal-e2e.py, Playwright +
# Firefox) by a client of a portal zone on a 390 px phone viewport, light and dark: redirect to the HTTPS page, layout,
# labels, touch target, WCAG AA contrast, refusal shown, sign-in to the page first asked for, status page, logout.
# Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing);
# the kernel side of every step is proven by lane-x-captive-portal.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-x-captive-portal-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/captive-portal-e2e.py" ] || nl_fail "ci/captive-portal-e2e.py was not copied next to the scenarios (ci/netlab/run.sh)"

nl_write_installer_toml
nl_up
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
nl_web_start "$DB"; nl_login
nl_api_ok "portal zone on the LAN" POST /svc/captive/zones '{"name":"lobby","interface":"@lan","auth":"none","page_title":"Lobby Wi-Fi","accent_color":"#0f766e"}'
for _ in $(seq 1 30); do C curl -sk -m 3 -o /dev/null "https://$NL_RTR_LAN/" && break; sleep 0.5; done
nl_ok "portal zone on $NL_LAN_IF, sign-in page answering"

out=$(C env ROUTER="$NL_RTR_LAN" TARGET_URL="http://$NL_WWW/" TARGET_TEXT="sees $NL_RTR_WAN" PORTAL_TITLE="Lobby Wi-Fi" \
      "$PW/bin/python" "$NL_T/captive-portal-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the captive portal page e2e failed (exit $rc)"
nl_ok "sign-in page driven in Firefox on a phone viewport: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-x-captive-portal-ui"
