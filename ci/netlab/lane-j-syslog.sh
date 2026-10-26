#!/usr/bin/env bash
# Lane J: remote syslog forwarding (USE=syslog) from the web UI API. A target
# added on the Syslog page becomes an rsyslog omfwd action in
# /etc/rsyslog.d/50-patronus.conf, rsyslog is restarted, and a real log message
# arrives at a UDP collector on the "internet" side; severity filtering, the
# test button, the local log in the status, reboot and delete are checked.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-syslog.db
rm -f "$DB" "$NL_T/nl-jar" /tmp/syslog-rx
nl_write_installer_toml
nl_kill_daemons rsyslogd

# Debian/Ubuntu ship rsyslog without a SysV script (systemd-only): give the
# netlab container the minimal init script Patronus' service manager calls.
mkdir -p /etc/init.d
cat > /etc/init.d/rsyslog <<'EOF'
#!/bin/sh
PIDF=/run/rsyslogd.pid
alive() { [ -f $PIDF ] && kill -0 "$(cat $PIDF)" 2>/dev/null; }
case "$1" in
  start) alive || rsyslogd -i $PIDF ;;
  stop) alive && kill "$(cat $PIDF)"; rm -f $PIDF ;;
  restart) $0 stop; sleep 0.5; $0 start ;;
  status) alive && echo "rsyslogd is running" || { echo "rsyslogd is not running"; exit 3; } ;;
esac
exit 0
EOF
chmod 755 /etc/init.d/rsyslog
rm -f /etc/rsyslog.d/50-patronus.conf
grep -q 'rsyslog.d' /etc/rsyslog.conf || echo '$IncludeConfig /etc/rsyslog.d/*.conf' >> /etc/rsyslog.conf

cat > "$NL_T/nl-syslog-rx.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    d, a = s.recvfrom(65535)
    open(sys.argv[3], "ab").write(d + b"\n")
PY
: > /tmp/syslog-rx

nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-syslog-rx.py" 0.0.0.0 514 /tmp/syslog-rx
sleep 0.5
nl_web_start "$DB"; nl_login

rx() { grep -c -- "$1" /tmp/syslog-rx || true; }

echo "=== nothing configured: rsyslog untouched"
[ ! -e /etc/rsyslog.d/50-patronus.conf ] || nl_fail "drop-in written with no target"
nl_api GET /svc/syslog
[ "$NL_CODE" = 200 ] || nl_fail "overview: $NL_CODE"
nl_ok "overview answers (settings, rows, schema, status)"

echo "=== validation"
for bad in '{"host":"a b"}' '{"host":"198.51.100.10","port":0}' '{"host":"198.51.100.10","proto":"icmp"}' '{"host":"198.51.100.10","severity":"loud"}' '{}'; do
  nl_api_code "bad target $bad" 400 POST /svc/syslog/targets "$bad"
done
nl_ok "bad hosts, ports, protocols and severities are refused (400)"

echo "=== add a collector"
nl_api_ok "add target" POST /svc/syslog/targets "{\"host\":\"$NL_WWW\",\"port\":514,\"proto\":\"udp\",\"severity\":\"notice\"}"
ID=$(nl_json "$NL_OUT" 'd["id"]')
grep -q "target=\"$NL_WWW\" port=\"514\" protocol=\"udp\"" /etc/rsyslog.d/50-patronus.conf || { cat /etc/rsyslog.d/50-patronus.conf; nl_fail "drop-in lacks the omfwd action"; }
nl_ok "wrote /etc/rsyslog.d/50-patronus.conf with an omfwd action to $NL_WWW:514"
pgrep -x rsyslogd >/dev/null || nl_fail "rsyslogd is not running after the change"
nl_ok "rsyslogd running"
nl_api_ok "test message" POST /svc/syslog/action/test '{}'
MSG=$(nl_json "$NL_OUT" 'd["sent"]')
nl_wait 15 grep -qF -- "$MSG" /tmp/syslog-rx || { cat /tmp/syslog-rx; nl_fail "the collector never received: $MSG"; }
nl_ok "the collector on the internet side received: $MSG"

echo "=== severity filter"
logger -t lane-j -p user.info "marker-info-$$"
logger -t lane-j -p user.err "marker-err-$$"
nl_wait 15 grep -qF -- "marker-err-$$" /tmp/syslog-rx || nl_fail "err message not forwarded"
[ "$(rx "marker-info-$$")" = 0 ] || nl_fail "an info message passed the >= notice filter"
nl_ok "err forwarded, info (below the notice filter) not"
nl_api_ok "lower the filter" PUT "/svc/syslog/targets/$ID" '{"severity":"info"}'
nl_wait 10 pgrep -x rsyslogd
sleep 1
logger -t lane-j -p user.info "marker-info2-$$"
nl_wait 15 grep -qF -- "marker-info2-$$" /tmp/syslog-rx || nl_fail "info not forwarded after lowering the filter"
nl_ok "after editing the severity to info, info messages are forwarded too"

echo "=== local log in the status"
# rsyslog writes /var/log/syslog asynchronously (`-` prefix): the message can
# take a moment to reach the file the status reads, so ask again for a few seconds
cat > "$NL_T/syslog-check.py" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
st = d["status"]
assert st["installed"] and st["running"], st
assert any(sys.argv[2] in l for l in st["recent_log"]), st["recent_log"][-5:]
assert st["forwarding_to"], st
PY
ok=
for _ in $(seq 1 15); do
  nl_api GET /svc/syslog
  if python3 "$NL_T/syslog-check.py" "$NL_OUT" "marker-err-$$" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { python3 "$NL_T/syslog-check.py" "$NL_OUT" "marker-err-$$" || true; nl_fail "status.recent_log lacks the local message"; }
nl_ok "status shows rsyslog running and the recent local log (including the message just sent)"
nl_web GET /svc/syslog
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "Syslog page: $NL_CODE"
nl_ok "the Syslog page renders"

echo "=== reboot: patronus apply brings forwarding back"
nl_web_stop
nl_kill_daemons rsyslogd
nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-syslog-rx.py" 0.0.0.0 514 /tmp/syslog-rx
sleep 0.5
pgrep -x rsyslogd >/dev/null || nl_fail "rsyslogd not started by the boot apply"
sleep 1
logger -t lane-j -p user.err "marker-reboot-$$"
nl_wait 15 grep -qF -- "marker-reboot-$$" /tmp/syslog-rx || nl_fail "forwarding did not come back after the reboot"
nl_ok "after reboot: forwarding works again"

echo "=== delete the collector"
nl_web_start "$DB"; nl_login
nl_api_ok "delete target" DELETE "/svc/syslog/targets/$ID"
grep -q omfwd /etc/rsyslog.d/50-patronus.conf && nl_fail "omfwd action still in the drop-in"
nl_wait 10 pgrep -x rsyslogd
sleep 1
logger -t lane-j -p user.crit "marker-after-delete-$$"
sleep 2
[ "$(rx "marker-after-delete-$$")" = 0 ] || nl_fail "still forwarding after the target was deleted"
nl_ok "deleted: nothing is forwarded any more"
nl_api_code "delete twice" 404 DELETE "/svc/syslog/targets/$ID"
nl_web_stop
nl_kill_daemons rsyslogd
echo "ALL SYSLOG CHECKS PASSED"
