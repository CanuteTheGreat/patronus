#!/usr/bin/env bash
# Lane N: General setup (System page > General). Host name, DNS domain and
# time zone are set through PUT /api/system/general on the real binaries and
# checked on the system itself: the running kernel host name, /etc/hostname,
# the marked /etc/hosts block (rest of the file untouched), /etc/localtime +
# /etc/timezone. Bad input is refused (400) with nothing changed, an unknown
# zone is refused and rolled back, and a reboot (`patronus apply`) puts the
# settings back after something reset them.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-general.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

OLD_HOST=$(cat /proc/sys/kernel/hostname)
restore() { echo "$OLD_HOST" >/proc/sys/kernel/hostname 2>/dev/null || true; }
trap restore EXIT
ZONE=/usr/share/zoneinfo/Europe/Berlin
if [ ! -f "$ZONE" ]; then mkdir -p "$(dirname "$ZONE")"; printf 'TZif' >"$ZONE"; fi
grep -q 'patronus lane marker' /etc/hosts 2>/dev/null || echo '10.9.9.9 lanemarker  # patronus lane marker' >>/etc/hosts

nl_api GET /system/general; [ "$NL_CODE" = 200 ] || nl_fail "GET general: $NL_CODE"
[ "$(jget 'd["settings"]["hostname"]')" = None ] || nl_fail "nothing should be managed yet: $(cat "$NL_OUT")"
nl_web GET /system; [ "$NL_CODE" = 200 ] && grep -q 'id="general-form"' "$NL_OUT" || nl_fail "System page has no general form: $NL_CODE"
nl_ok "unmanaged until set; the System page has the form"

for bad in '{"hostname":"a.b"}' '{"hostname":"bad name"}' '{"timezone":"../etc/passwd"}' '{"timezone":"/etc/passwd"}' '{"domain":"-x-"}'; do
  nl_api PUT /system/general "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "$bad must be refused (400), got $NL_CODE $(cat "$NL_OUT")"
done
[ "$(cat /proc/sys/kernel/hostname)" = "$OLD_HOST" ] || nl_fail "refused input changed the host name"
nl_ok "bad names and zones refused with 400, nothing changed"

nl_api PUT /system/general '{"hostname":"Lane-GW","domain":"lab.example","timezone":"Europe/Berlin"}'
[ "$NL_CODE" = 200 ] || nl_fail "PUT general: $NL_CODE $(cat "$NL_OUT")"
[ "$(cat /proc/sys/kernel/hostname)" = "lane-gw" ] || nl_fail "running host name: $(cat /proc/sys/kernel/hostname)"
[ "$(cat /etc/hostname)" = "lane-gw" ] || nl_fail "/etc/hostname: $(cat /etc/hostname)"
grep -q '^127.0.1.1 lane-gw.lab.example lane-gw$' /etc/hosts || nl_fail "/etc/hosts block: $(cat /etc/hosts)"
grep -q 'lanemarker' /etc/hosts || nl_fail "foreign /etc/hosts line was lost"
[ "$(readlink /etc/localtime)" = "$ZONE" ] || nl_fail "/etc/localtime -> $(readlink /etc/localtime)"
[ "$(cat /etc/timezone)" = "Europe/Berlin" ] || nl_fail "/etc/timezone: $(cat /etc/timezone)"
nl_api GET /system/general
[ "$(jget 'd["settings"]["hostname"]')" = lane-gw ] || nl_fail "stored: $(cat "$NL_OUT")"
nl_ok "host name, domain and time zone applied to the kernel and /etc"

nl_api PUT /system/general '{"timezone":"Mars/Base"}'
[ "$NL_CODE" != 200 ] || nl_fail "unknown zone must be refused"
[ "$(readlink /etc/localtime)" = "$ZONE" ] || nl_fail "failed apply changed /etc/localtime"
nl_api GET /system/general
[ "$(jget 'd["settings"]["timezone"]')" = Europe/Berlin ] || nl_fail "rollback failed: $(cat "$NL_OUT")"
nl_ok "unknown time zone refused and rolled back"

echo "=== reboot: something resets the box, patronus apply restores it"
nl_web_stop
echo "$OLD_HOST" >/proc/sys/kernel/hostname; echo "$OLD_HOST" >/etc/hostname; rm -f /etc/localtime /etc/timezone
nl_boot "$DB"
[ "$(cat /proc/sys/kernel/hostname)" = "lane-gw" ] || nl_fail "host name not restored at boot: $(cat /proc/sys/kernel/hostname)"
[ "$(readlink /etc/localtime)" = "$ZONE" ] || nl_fail "time zone not restored at boot"
grep -q '^127.0.1.1 lane-gw.lab.example lane-gw$' /etc/hosts || nl_fail "/etc/hosts not restored"
nl_ok "settings survive a reboot"
echo "PASS lane-n-general"
