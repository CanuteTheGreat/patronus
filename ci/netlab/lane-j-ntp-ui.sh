#!/usr/bin/env bash
# Lane J (UI): the NTP page (access list + GPS/PPS source) driven in a real browser (ci/ntp-page-e2e.py, Playwright +
# Firefox) against the shipped patronus-web in the netlab router: menu entry, every field, saving both forms through
# the page, refused input shown on the page, phone width in both colour schemes. The daemons behind it are proven by
# lane-j-ntp.sh. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they
# are missing).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-ntp-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/ntp-page-e2e.py" ] || { echo "SKIP lane-j-ntp-ui: ci/ntp-page-e2e.py was not copied next to the scenarios"; exit 0; }
rm -f /etc/chrony/chrony.conf /etc/conf.d/gpsd

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" \
      "$PW/bin/python" "$NL_T/ntp-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the NTP page e2e failed (exit $rc)"
nl_ok "NTP page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
nl_web_stop
echo "PASS lane-j-ntp-ui"
