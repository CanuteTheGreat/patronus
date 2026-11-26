#!/usr/bin/env bash
# Lane H (UI): the notification matcher editor driven in a real browser (ci/notify-matchers-page-e2e.py, Playwright +
# Firefox) against the shipped patronus-web in the netlab router: build a tree with buttons, keys and drag and drop,
# save, reload, preview on the event log, point a channel at it, 1280 + 390 px, light + dark, contrast, no overflow.
# Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh (fails, never skips, when they are missing);
# the API behind every button is proven by lane-h-notify-matchers.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-notify-matchers-ui.db
rm -f "$DB" "$NL_T/nl-jar"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/notify-matchers-page-e2e.py" ] || { echo "SKIP lane-h-notify-matchers-ui: ci/notify-matchers-page-e2e.py was not copied next to the scenarios"; exit 0; }

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
# a few past events for the preview, kinds/severities/subjects that the e2e matcher separates
python3 - "$DB" <<'PY'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1]); c.execute("PRAGMA busy_timeout=5000")
now = int(time.time())
rows = [("gateway_down", "WAN", "critical"), ("gateway_down", "guest-wan", "critical"), ("gateway_up", "WAN", "info"),
        ("tunnel_down", "office", "warning"), ("tunnel_up", "office", "info"), ("config_changed", "firewall", "info")]
for i, (k, s, v) in enumerate(rows):
    c.execute("INSERT INTO system_events (ts, kind, subject, severity, detail) VALUES (?,?,?,?,?)", (now - 3600 * (i + 1), k, s, v, "seeded for the editor test"))
c.commit()
PY
out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_CONTRAST="$NL_T/contrast.js" \
      "$PW/bin/python" "$NL_T/notify-matchers-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the matcher editor e2e failed (exit $rc)"
nl_ok "matcher editor driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
echo "PASS lane-h-notify-matchers-ui"
