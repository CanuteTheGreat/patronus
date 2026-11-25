#!/usr/bin/env bash
# Lane H: the structured system log viewer (/logs, /api/logs/system) on real loggers, from the LAN client.
#
#  1. standard tier: `patronus apply` configures the installed rsyslog (drop-in with facility.severity in every line);
#     lines written with `logger -p daemon.warning -t test-ident ...` reach the API with the priority the logger
#     recorded (no guessing), and the filters work: minimum priority, identifier (with * wildcard), free text, limit.
#  2. live mode: a new line reaches an open Server-Sent-Events stream in under 2 s; a stream resumed from its cursor
#     (query parameter and Last-Event-ID) misses nothing written while it was away.
#  3. boot separators: a boot record line with a new boot id yields a "boot" item, the same id again yields none.
#  4. router tier writer: busybox syslogd (facility.level in each line) is read the same way; settings are
#     typed (PUT /api/logs/system/settings), validated (400) and change the source at run time.
#  5. memory: a 60 MB log file answers a 2000-line page quickly and patronus-web's resident memory grows by a
#     bounded amount (the file is read from its end, never loaded).
#  6. the page and its menu entry exist; the Monitoring card is a preview that links to it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

W=$NL_T/h-syslog
DB=$W/c.db
rm -rf "$W" "$NL_T/nl-jar"; mkdir -p "$W"
nl_write_installer_toml
command -v logger >/dev/null || { echo "SKIP lane-h-syslog-viewer: logger not installed"; exit 0; }
HAVE_RSYSLOG=0; command -v rsyslogd >/dev/null && HAVE_RSYSLOG=1
HAVE_BB=0; command -v busybox >/dev/null && busybox syslogd --help >/dev/null 2>&1 && HAVE_BB=1
[ "$HAVE_RSYSLOG" = 1 ] || [ "$HAVE_BB" = 1 ] || { echo "SKIP lane-h-syslog-viewer: neither rsyslog nor busybox in this image"; exit 0; }

MANAGED=/var/log/patronus/system.log
nl_kill_daemons rsyslogd
# Debian ships rsyslog without a SysV script: the minimal one Patronus' service manager calls (as lane-j-syslog)
mkdir -p /etc/init.d
cat > /etc/init.d/rsyslog <<'EOF'
#!/bin/sh
PIDF=/run/rsyslogd.pid
alive() { [ -f $PIDF ] && kill -0 "$(cat $PIDF)" 2>/dev/null; }
case "$1" in
  start) alive || rsyslogd -i $PIDF ;;
  stop)
    if alive; then
      P=$(cat $PIDF); kill "$P"
      # wait for the old daemon to be gone: on exit imuxsock unlinks /dev/log, and
      # a slow old rsyslogd doing that after the new one bound it leaves logger with
      # no socket (marker lines never forwarded, 11-15 run 1250)
      i=0; while kill -0 "$P" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
    fi
    rm -f $PIDF ;;
  restart) $0 stop; $0 start; i=0; while [ ! -S /dev/log ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done ;;
  status) alive && echo "rsyslogd is running" || { echo "rsyslogd is not running"; exit 3; } ;;
esac
exit 0
EOF
chmod 755 /etc/init.d/rsyslog
# installing systemd (strongSwan's charon-systemd) leaves /var/log root:syslog 0755: rsyslog,
# running as user syslog, then cannot create /var/log/syslog
chgrp syslog /var/log 2>/dev/null || true; chmod 775 /var/log
rm -f /etc/rsyslog.d/50-patronus.conf
grep -q 'rsyslog.d' /etc/rsyslog.conf || echo '$IncludeConfig /etc/rsyslog.d/*.conf' >> /etc/rsyslog.conf
rm -rf /var/log/patronus; rm -f /etc/rsyslog.d/40-patronus-priority.conf
nl_boot "$DB"

j() { nl_json "$NL_OUT" "$1"; }
stop_loggers() {
  for n in rsyslogd syslogd; do pkill -x "$n" 2>/dev/null || true; done
  sleep 0.5; rm -f /dev/log
}
trap 'stop_loggers; nl_web_stop || true; kill ${SSE_PID:-} 2>/dev/null || true' EXIT

if [ "$HAVE_RSYSLOG" = 1 ]; then
  echo "=== 1. standard tier: rsyslog writes the priority, Patronus configured it"
  [ -f /etc/rsyslog.d/40-patronus-priority.conf ] || nl_fail "patronus apply wrote no rsyslog priority drop-in"
  grep -F 'syslogseverity-text' /etc/rsyslog.d/40-patronus-priority.conf >/dev/null || nl_fail "drop-in lacks the severity"
  nl_ok "apply wrote /etc/rsyslog.d/40-patronus-priority.conf"
  pgrep -x rsyslogd >/dev/null || nl_fail "patronus apply did not leave rsyslogd running"
  nl_wait 20 test -S /dev/log || nl_fail "rsyslogd did not open /dev/log"
  logger -p daemon.warning -t test-ident "flap one"
  logger -p user.err -t other-ident "boom two"
  logger -p daemon.info -t test-ident "just info three"
  nl_wait 15 test -s "$MANAGED" || nl_fail "rsyslog wrote nothing to $MANAGED"
  grep -E ' daemon\.warning test-ident(\[[0-9]+\])?: flap one' "$MANAGED" >/dev/null || { cat "$MANAGED"; nl_fail "managed file has no facility.severity"; }
  nl_ok "managed file carries daemon.warning in the line"
fi

# the standard-tier files back end, or the router tier's busybox writer when rsyslog is absent
export PATRONUS_SYSLOG=$W/plain-messages
: > "$PATRONUS_SYSLOG"
nl_web_start "$DB"; nl_login

if [ "$HAVE_RSYSLOG" = 1 ]; then
  nl_api GET "/logs/system?identifier=test-ident"
  [ "$NL_CODE" = 200 ] || nl_fail "logs: $NL_CODE $(cat "$NL_OUT")"
  [ "$(j 'd["backend"]')" = files ] || nl_fail "backend: $(cat "$NL_OUT")"
  [ "$(j 'len([e for e in d["entries"] if e["type"]=="line"])')" = 2 ] || nl_fail "identifier filter: $(cat "$NL_OUT")"
  [ "$(j '[e["priority"] for e in d["entries"]]')" = "[4, 6]" ] || nl_fail "priorities not read from the lines: $(cat "$NL_OUT")"
  nl_ok "identifier filter: 2 lines, priorities 4 (warning) and 6 (info) read from the log, in time order"
  nl_api GET "/logs/system?identifier=test-ident&min_priority=warning"
  [ "$(j '[e["message"] for e in d["entries"]]')" = "['flap one']" ] || nl_fail "min_priority=warning: $(cat "$NL_OUT")"
  nl_api GET "/logs/system?min_priority=err"
  [ "$(j '[e["message"] for e in d["entries"] if e["type"]=="line"]')" = "['boom two']" ] || nl_fail "min_priority=err: $(cat "$NL_OUT")"
  nl_ok "minimum priority keeps warning and worse, err and worse"
  nl_api GET "/logs/system?identifier=*-ident"
  [ "$(j 'len(d["entries"])')" = 3 ] || nl_fail "wildcard: $(cat "$NL_OUT")"
  nl_api GET "/logs/system?q=JUST%20INFO"
  [ "$(j 'len(d["entries"])')" = 1 ] || nl_fail "free text: $(cat "$NL_OUT")"
  nl_api GET "/logs/system?limit=1"
  [ "$(j 'd["entries"][-1]["message"]')" = "just info three" ] && [ -n "$(j 'd["older_cursor"]')" ] && [ "$(j 'd["older_cursor"]')" != None ] || nl_fail "limit/cursor: $(cat "$NL_OUT")"
  OLD=$(j 'd["older_cursor"]')
  nl_api GET "/logs/system?limit=1&cursor=$OLD"
  [ "$(j 'd["entries"][-1]["message"]')" = "boom two" ] || nl_fail "older page: $(cat "$NL_OUT")"
  nl_ok "wildcard, free text and paging by cursor"
  for bad in "min_priority=loud" "since=yesterday" "limit=0" "since=2026-11-25%2012:00&until=2026-11-25%2011:00"; do
    nl_api GET "/logs/system?$bad"
    [ "$NL_CODE" = 400 ] || nl_fail "bad filter $bad answered $NL_CODE"
  done
  nl_ok "bad filters are refused with 400"

  echo "=== 2. live stream under 2 s, resumable"
  : > "$W/sse1"
  C curl -sk -N -m 40 -b "$NL_T/nl-jar" "$NL_UI/api/logs/system/stream?identifier=test-live" >"$W/sse1" 2>&1 &
  SSE_PID=$!
  nl_wait 10 grep -F 'event: hello' "$W/sse1" || { cat "$W/sse1"; nl_fail "stream did not open"; }
  sleep 1
  t0=$(date +%s.%N)
  logger -p daemon.notice -t test-live "live line one"
  nl_wait 5 grep -F 'live line one' "$W/sse1" || { cat "$W/sse1"; nl_fail "live line never arrived"; }
  t1=$(date +%s.%N)
  python3 - "$t0" "$t1" <<'PY' || nl_fail "live line took 2 s or more"
import sys; sys.exit(0 if float(sys.argv[2]) - float(sys.argv[1]) < 2.0 else 1)
PY
  nl_ok "a new line reached the live stream in under 2 s"
  LASTID=$(grep '^id: ' "$W/sse1" | tail -1 | sed 's/^id: //')
  [ -n "$LASTID" ] || nl_fail "stream events carry no id"
  kill "$SSE_PID" 2>/dev/null || true; wait "$SSE_PID" 2>/dev/null || true
  logger -p daemon.err -t test-live "missed while away A"
  logger -p daemon.err -t test-live "missed while away B"
  sleep 1
  : > "$W/sse2"
  C curl -sk -N -m 8 -b "$NL_T/nl-jar" -H "Last-Event-ID: $LASTID" "$NL_UI/api/logs/system/stream?identifier=test-live" >"$W/sse2" 2>&1 || true
  grep -F 'missed while away A' "$W/sse2" >/dev/null && grep -F 'missed while away B' "$W/sse2" >/dev/null || { cat "$W/sse2"; nl_fail "resume lost lines"; }
  [ "$(grep -c 'live line one' "$W/sse2" || true)" = 0 ] || nl_fail "resume repeated a line"
  nl_ok "resumed from Last-Event-ID: both lines written while away, none repeated"

  echo "=== 3. boot separators"
  logger -p daemon.notice -t patronus-boot "boot 11111111-2222-4333-8444-555555555555"
  logger -p daemon.info -t sep-test "first boot line"
  logger -p daemon.notice -t patronus-boot "boot 11111111-2222-4333-8444-555555555555"   # a logger restart: same boot
  logger -p daemon.notice -t patronus-boot "boot 99999999-2222-4333-8444-555555555555"   # a new boot
  logger -p daemon.info -t sep-test "second boot line"
  sleep 1
  nl_api GET "/logs/system?limit=50"
  [ "$(j 'len([e for e in d["entries"] if e["type"]=="boot" and (e["boot_id"] or "").startswith(("11111111","99999999"))])')" = 2 ] || nl_fail "boot separators: $(cat "$NL_OUT")"
  [ "$(j '[e["type"] for e in d["entries"]][-6:]')" = "['line', 'line', 'line', 'boot', 'line', 'line']" ] || nl_fail "separator placement / repeated id drew a separator: $(j '[e["type"] for e in d["entries"]]')"
  nl_ok "one separator per boot id (a repeated id draws none)"
fi

echo "=== 4. busybox syslogd (the router tier's writer), typed settings"
if [ "$HAVE_BB" = 1 ]; then
  stop_loggers
  BB=$W/bb-messages; : > "$BB"
  busybox syslogd -n -O "$BB" >"$W/bb.log" 2>&1 &
  nl_wait 10 test -S /dev/log || { cat "$W/bb.log"; nl_fail "busybox syslogd did not open /dev/log"; }
  nl_api PUT /logs/system/settings "{\"settings\":{\"logview.file_path\":\"$BB\",\"logview.managed_file\":\"$W/none.log\"}}"
  [ "$NL_CODE" = 200 ] || nl_fail "settings PUT: $NL_CODE $(cat "$NL_OUT")"
  [ "$(j 'd["effective"]["file_path"]')" = "$BB" ] || nl_fail "setting not effective: $(cat "$NL_OUT")"
  logger -p daemon.err -t bb-ident "busybox err line"
  logger -p daemon.debug -t bb-ident "busybox debug line"
  nl_wait 10 grep -F 'busybox err line' "$BB" || nl_fail "busybox syslogd wrote nothing"
  nl_api GET "/logs/system?identifier=bb-ident&min_priority=err"
  [ "$(j '[(e["message"], e["priority"], e["facility"]) for e in d["entries"]]')" = "[('busybox err line', 3, 'daemon')]" ] || { cat "$BB"; nl_fail "busybox facility.level not read: $(cat "$NL_OUT")"; }
  nl_ok "busybox syslogd: facility.level read, minimum priority works"
else
  echo "SKIP busybox part: no busybox syslogd applet"
fi
nl_api PUT /logs/system/settings '{"settings":{"logview.max_limit":"99999"}}'
[ "$NL_CODE" = 400 ] || nl_fail "an impossible setting was accepted: $NL_CODE"
nl_api PUT /logs/system/settings '{"settings":{"logview.nonsense":"1"}}'
[ "$NL_CODE" = 400 ] || nl_fail "an unknown key was accepted: $NL_CODE"
nl_ok "invalid settings refused (400) and nothing changed"

echo "=== 5. memory: a 60 MB log is read from its end"
BIG=$W/big-messages
python3 - "$BIG" <<'PY'
import sys, time
t = time.time() - 6 * 3600
with open(sys.argv[1], "w") as f:
    n = 0
    while f.tell() < 60 * 1024 * 1024:
        s = time.strftime("%b %e %H:%M:%S", time.localtime(t + n * 0.01))
        f.write("%s lab daemon.%s big-ident[%d]: padding padding padding padding padding line %d\n" % (s, "warn" if n % 7 == 0 else "info", n % 5000, n))
        n += 1
PY
nl_api PUT /logs/system/settings "{\"settings\":{\"logview.file_path\":\"$BIG\",\"logview.managed_file\":\"$W/none.log\"}}"
[ "$NL_CODE" = 200 ] || nl_fail "settings PUT: $NL_CODE"
rss() { awk '/^VmRSS:/ {print $2}' "/proc/$NL_WEB_PID/status"; }
R0=$(rss)
s0=$(date +%s.%N)
nl_api GET "/logs/system?limit=2000"
s1=$(date +%s.%N)
[ "$NL_CODE" = 200 ] && [ "$(j 'd["count"]')" = 2000 ] || nl_fail "big page: $NL_CODE $(head -c 300 "$NL_OUT")"
nl_api GET "/logs/system?limit=2000&min_priority=warning&q=nothing-like-this"
[ "$NL_CODE" = 200 ] || nl_fail "scan-limited query: $NL_CODE"
R1=$(rss)
python3 - "$s0" "$s1" "$R0" "$R1" <<'PY' || nl_fail "page too slow or memory grew too much"
import sys
s0, s1, r0, r1 = map(float, sys.argv[1:])
print("page took %.2f s, RSS %d -> %d kB" % (s1 - s0, r0, r1))
sys.exit(0 if (s1 - s0) < 3.0 and (r1 - r0) < 20 * 1024 else 1)
PY
nl_ok "2000-line page from a 60 MB file within budget; a needle-less scan stops at the scan limit"
[ "$(j 'd["scan_limited"]')" = True ] || nl_fail "an exhausted scan budget was not reported: $(head -c 300 "$NL_OUT")"

echo "=== 6. the page and the Monitoring preview"
nl_web GET /logs
[ "$NL_CODE" = 200 ] && grep -F 'id="sl-pane"' "$NL_OUT" >/dev/null && grep -F 'href="/logs"' "$NL_OUT" >/dev/null || nl_fail "/logs page: $NL_CODE"
nl_web GET /monitoring
[ "$NL_CODE" = 200 ] && grep -F 'id="log-preview"' "$NL_OUT" >/dev/null && grep -F 'Open the system log' "$NL_OUT" >/dev/null || nl_fail "monitoring preview: $NL_CODE"
nl_ok "/logs renders, the menu links it, Monitoring shows a preview with a link"
nl_api GET "/logs/system/download?min_priority=warning&limit=5"
[ "$NL_CODE" = 200 ] && grep -E ' warning ' "$NL_OUT" >/dev/null || nl_fail "download: $NL_CODE"
nl_ok "the filtered view downloads as text"
echo "lane-h-syslog-viewer: all checks passed"
