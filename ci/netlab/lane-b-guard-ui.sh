#!/usr/bin/env bash
# Lane B (UI): the brute-force protection page driven in a real browser (ci/guard-page-e2e.py, Playwright + Firefox)
# against the shipped patronus-web in the netlab router, at 1280 and 390 px in light and dark: menu entry, data, no
# sideways scrolling, colour scheme, a refused setting shown on the page, saving the form, banning and lifting a ban
# from the page. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they
# are missing). The kernel side is proven by lane-b-guard.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-guard-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/guard-page-e2e.py" ] || { echo "SKIP lane-b-guard-ui: ci/guard-page-e2e.py was not copied next to the scenarios"; exit 0; }
export PATRONUS_GUARD_TICK_SECS=1
trap 'nl_web_stop' EXIT

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api PUT /guard/settings '{"enabled":true,"journal":"off","log_files":["/t/guard-ui-none.log"]}'
[ "$NL_CODE" = 200 ] || nl_fail "enable: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /guard/bans '{"address":"203.0.113.9","secs":3600,"reason":"seeded"}'
[ "$NL_CODE" = 201 ] || nl_fail "seed ban: $NL_CODE $(cat "$NL_OUT")"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_SHOTS=/t/shots \
      "$PW/bin/python" "$NL_T/guard-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the brute-force page e2e failed (exit $rc)"
nl_ok "brute-force page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks at 1280/390 px, light and dark"
