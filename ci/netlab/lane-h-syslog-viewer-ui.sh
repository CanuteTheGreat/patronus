#!/usr/bin/env bash
# Lane H (UI): the system log page driven in a real browser (ci/syslog-page-e2e.py, Playwright + Firefox) against the
# shipped patronus-web in the netlab router: coloured entries per priority, boot separators, filters kept in the
# address, live mode with pause/resume, timespan, download link, phone layout, light + dark contrast, the Monitoring
# preview. The log it reads is a busybox-format file seeded here (every priority, a line without priority, a kernel
# line, two boots, identifiers web-a/web-b, one needle) plus a writer that appends a line a second; the real loggers
# are proven by lane-h-syslog-viewer.sh. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-syslog-viewer-ui.db
W=$NL_T/h-syslog-ui
rm -rf "$W" "$DB" "$NL_T/nl-jar"; mkdir -p "$W"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/syslog-page-e2e.py" ] || { echo "SKIP lane-h-syslog-viewer-ui: ci/syslog-page-e2e.py was not copied next to the scenarios"; exit 0; }

LOG=$W/messages
python3 - "$LOG" <<'PY'
import sys, time
t = time.time() - 3600
rows = [
    ("kern.info", "kernel", "[    0.000000] Linux version 6.12.118 (build@host)"),
    ("daemon.notice", "patronus-boot", "boot 11111111-2222-4333-8444-555555555555"),
    ("daemon.emerg", "web-a", "emergency line"), ("daemon.alert", "web-a", "alert line"), ("daemon.crit", "web-a", "critical line"),
    ("daemon.err", "web-b", "error line"), ("daemon.warn", "web-b", "warning line"), ("daemon.notice", "web-a", "notice line"),
    ("daemon.info", "web-a", "info line needle-in-haystack"), ("daemon.debug", "web-b", "debug line"),
    ("kern.err", "kernel", "[   12.345678] ath11k: firmware crashed"),
    (None, "oldlogger", "a record without any priority"),
    ("daemon.notice", "patronus-boot", "boot 99999999-2222-4333-8444-555555555555"),
    ("daemon.info", "other", "after the second boot"),
]
with open(sys.argv[1], "w") as f:
    for i, (fl, ident, msg) in enumerate(rows):
        ts = time.strftime("%b %e %H:%M:%S", time.localtime(t + i * 10))
        f.write("%s lab %s%s[%d]: %s\n" % (ts, (fl + " ") if fl else "", ident, 100 + i, msg) if ident != "kernel" else "%s lab %s kernel: %s\n" % (ts, fl, msg))
PY
cat > "$W/writer.py" <<'PY'
import sys, time
n = 0
while True:
    n += 1
    with open(sys.argv[1], "a") as f:
        f.write("%s lab daemon.info e2e-live[7]: tick %d\n" % (time.strftime("%b %e %H:%M:%S"), n))
    time.sleep(1)
PY
export PATRONUS_SYSLOG=$LOG
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
python3 "$W/writer.py" "$LOG" & WRITER=$!
trap 'kill $WRITER 2>/dev/null || true' EXIT
nl_ok "booted with a seeded system log and a live writer"

out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_SHOTS="$NL_T/syslog-shots" \
      "$PW/bin/python" "$NL_T/syslog-page-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the system log page e2e failed (exit $rc)"
nl_ok "system log page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks passed"
