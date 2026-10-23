#!/usr/bin/env bash
# Lane J: intrusion detection / prevention (USE=intrusion-detection). A custom
# rule on the Intrusion detection page ("payload contains evil-pattern, port
# 80") is loaded into Suricata watching the WAN interface: a LAN client's HTTP
# request carrying the pattern raises an alert in eve.json (also shown on the
# page), an ordinary request does not. Switching to inline IPS mode with a
# `drop` rule makes the firewall queue forwarded packets (NFQUEUE) and the
# request with the pattern is really dropped while normal traffic still
# passes. A rule Suricata rejects leaves the old rules running; reboot and
# disable are checked.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-ids.db
EVE=/var/log/suricata/eve.json
rm -f "$DB" "$NL_T/nl-jar" "$EVE"
# Suricata renames its threads ("Suricata-Main"): match the command line, not the process name
suri_up() { pgrep -f '^/usr/bin/suricata -c' >/dev/null; }
suri_pid() { pgrep -f '^/usr/bin/suricata -c' | head -1; }
suri_kill() { pkill -f '^/usr/bin/suricata -c' 2>/dev/null || true; sleep 1; rm -rf /var/lib/patronus/net /run/patronus; }
suri_gone() { ! suri_up; }
nl_write_installer_toml
suri_kill
mkdir -p /var/log/suricata

alerts() { grep -c '"event_type":"alert"' "$EVE" 2>/dev/null || true; }
evil() { C curl -s --max-time 4 -o "$NL_OUT" -H 'X-Probe: evil-pattern' "http://$NL_WWW/"; }
plain() { C curl -s --max-time 4 -o "$NL_OUT" "http://$NL_WWW/"; }

nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== validation"
for bad in '{"msg":"x","src":"1.2.3.4; drop"}' '{"msg":"x","dport":"http"}' '{"msg":"x","content":"a\"b"}' '{"msg":"x","proto":"gre"}' '{"src":"any"}'; do
  nl_api_code "bad rule $bad" 400 POST /svc/ids/rules "$bad"
done
nl_api_code "bad home net" 400 PUT /svc/ids '{"home_net":"10.0.0.0/8, nope"}'
nl_ok "bad sources, ports, patterns, protocols, missing messages and a bad HOME_NET are refused (400)"

echo "=== a rule and IDS mode on the WAN"
nl_api_ok "add rule" POST /svc/ids/rules '{"action":"alert","proto":"tcp","dport":"80","content":"evil-pattern","msg":"Netlab evil pattern"}'
RID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_ok "enable" PUT /svc/ids '{"enabled":true,"mode":"ids","interface":"@wan","home_net":"192.168.50.0/24","distro_rules":false}'
nl_wait 60 suri_up || { tail -30 /run/patronus/patronus-daemon.suricata.log 2>/dev/null; nl_fail "suricata did not start"; }
nl_ok "suricata running: $(pgrep -af "^/usr/bin/suricata -c" | head -1 | cut -c1-140)"
grep -q 'evil-pattern' /var/lib/patronus/net/suricata/patronus.rules || nl_fail "patronus.rules lacks the rule"
nl_ok "rule written: $(grep -v '^#' /var/lib/patronus/net/suricata/patronus.rules | head -1)"
# suricata needs a moment to open the capture and load rules
nl_wait 60 grep -q 'rtr-wan\|Engine started\|threads' /run/patronus/patronus-daemon.suricata.log || true
sleep 8
plain || nl_fail "ordinary request failed"
N0=$(alerts)
for i in 1 2 3; do evil || nl_fail "request with the pattern failed in IDS mode (it must only alert)"; done
nl_wait 30 sh -c "[ \$(grep -c '\"event_type\":\"alert\"' $EVE) -gt $N0 ]" || { tail -5 "$EVE"; nl_fail "no alert for the request carrying the pattern"; }
grep '"event_type":"alert"' "$EVE" | grep -q 'Netlab evil pattern' || nl_fail "alert lacks the rule message"
nl_ok "alert in eve.json: $(grep '"event_type":"alert"' "$EVE" | tail -1 | cut -c1-160)"
N1=$(alerts)
for i in 1 2 3; do plain; done
sleep 3
[ "$(alerts)" = "$N1" ] || nl_fail "an ordinary request raised an alert"
nl_ok "ordinary requests raise no alert"
nl_api GET /svc/ids
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not list the alert"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"] and st["running"] and st["mode"] == "ids", st
assert any("Netlab evil pattern" in (a.get("signature") or "") for a in st["alerts"]), st["alerts"]
PY
nl_ok "the page's status lists the alert"
nl_web GET /svc/ids
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "IDS page: $NL_CODE"

echo "=== a rule suricata rejects keeps the old rules running"
# The API cannot produce a rule Suricata refuses (every field is validated), but a damaged
# backup import or a hand-edited store can: put one straight into the store.
PID=$(suri_pid)
sqlite3 "$DB" "INSERT INTO ids_rules (action, proto, src, dst, dport, content, msg, enabled, updated_at) VALUES ('alert','bogusproto','any','any','80','x','broken rule',1,0)"
nl_api_code "apply with a rule suricata rejects" 400 PUT /svc/ids '{"distro_rules":false}'
grep -q 'rejected by suricata -T' "$NL_OUT" || nl_fail "the refusal does not name suricata -T: $(cat "$NL_OUT")"
sleep 1
[ "$(suri_pid)" = "$PID" ] || nl_fail "suricata was restarted by a refused rule"
grep -q bogusproto /var/lib/patronus/net/suricata/patronus.rules && nl_fail "the rejected rule replaced the running rules file"
nl_ok "a rule suricata rejects is refused (suricata -T), the old instance (pid $PID) and its rules stay untouched"
sqlite3 "$DB" "DELETE FROM ids_rules WHERE proto = 'bogusproto'"
nl_api_ok "recover" PUT /svc/ids '{"distro_rules":false}'

echo "=== inline IPS: a drop rule really drops"
nl_api_ok "rule -> drop" PUT "/svc/ids/rules/$RID" '{"action":"drop"}'
nl_api_ok "mode -> ips" PUT /svc/ids '{"mode":"ips"}'
suri_q3() { pgrep -af '^/usr/bin/suricata -c' | grep -q -- '-q 3'; }
nl_wait 60 suri_q3 || nl_fail "suricata was not restarted in NFQUEUE mode"
R nft list chain inet patronus ids_ips | grep -q 'queue' || { R nft list ruleset | tail -30; nl_fail "no queue rule in the ids_ips chain"; }
nl_ok "firewall: ids_ips chain queues forwarded traffic ($(R nft list chain inet patronus ids_ips | grep -c queue) rules); suricata runs with -q 3"
sleep 8
plain || nl_fail "ordinary traffic does not pass in IPS mode"
nl_ok "ordinary request passes through the inline IPS"
if evil; then nl_fail "the request with the pattern was NOT dropped in IPS mode: $(cat "$NL_OUT")"; fi
nl_ok "request carrying the pattern is dropped inline"

echo "=== reboot: patronus apply restores the IPS"
nl_web_stop
suri_kill
nl_boot "$DB"
nl_wait 60 suri_up || nl_fail "suricata not started by the boot apply"
R nft list chain inet patronus ids_ips | grep -q queue || nl_fail "queue rule missing after the boot apply"
sleep 10
plain || nl_fail "ordinary traffic blocked after the reboot"
if evil; then nl_fail "pattern not dropped after the reboot"; fi
nl_ok "after reboot: IPS active again (normal traffic passes, pattern dropped)"

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/ids '{"enabled":false}'
nl_wait 20 suri_gone || nl_fail "suricata still running"
R nft list chain inet patronus ids_ips >/dev/null 2>&1 && nl_fail "ids_ips chain still present"
evil || nl_fail "traffic with the pattern is still blocked with the IDS off"
nl_ok "disabled: suricata stopped, queue chain gone, nothing is blocked"
nl_web_stop
echo "ALL IDS CHECKS PASSED"
