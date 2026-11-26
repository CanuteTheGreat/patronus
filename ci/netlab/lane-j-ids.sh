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
#
# Rule-set manager (C120): a local HTTP "rule source" serves a test rule set (no internet in CI);
# the product's own task downloads it, a policy turns its rule into a drop (really dropped inline),
# a category / classtype / SID policy beats the ruleset one, an alert-only policy only logs, a
# suppress made from an alert stops the alert, a broken download is refused (suricata -T) while
# the old set keeps running, and the alert browser API finds the alerts.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-ids.db
EVE=/var/log/suricata/eve.json
rm -f "$DB" "$NL_T/nl-jar" "$EVE"
# Suricata renames its threads ("Suricata-Main"): match the command line, not the process name
suri_up() { pgrep -f '^/usr/bin/suricata -c' >/dev/null; }
suri_pid() { pgrep -f '^/usr/bin/suricata -c' | head -1; }
# (the downloaded rule sets are data on disk: a reboot keeps them, so they survive the scrub)
suri_kill() {
  pkill -f '^/usr/bin/suricata -c' 2>/dev/null || true; sleep 1
  rm -rf /t/ids-keep
  [ -d /var/lib/patronus/net/suricata/sources ] && mv /var/lib/patronus/net/suricata/sources /t/ids-keep
  rm -rf /var/lib/patronus/net /run/patronus
  [ -d /t/ids-keep ] && { mkdir -p /var/lib/patronus/net/suricata; mv /t/ids-keep /var/lib/patronus/net/suricata/sources; }
  return 0
}
suri_gone() { ! suri_up; }
nl_write_installer_toml
suri_kill
mkdir -p /var/log/suricata

alerts() { grep -c '"event_type":"alert"' "$EVE" 2>/dev/null || true; }
evil() { C curl -s --max-time 4 -o "$NL_OUT" -H 'X-Probe: evil-pattern' "http://$NL_WWW/"; }
plain() { C curl -s --max-time 4 -o "$NL_OUT" "http://$NL_WWW/"; }

# the product's own task (alert history, scheduled rule-set downloads) ticks every 2 s here
export PATRONUS_IDS_TICK_SECS=2
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
grep '"event_type":"alert"' "$EVE" | grep 'Netlab evil pattern' >/dev/null || nl_fail "alert lacks the rule message"
nl_ok "alert in eve.json: $(grep '"event_type":"alert"' "$EVE" | tail -1 | cut -c1-160)"
# eve.json is written asynchronously: the first alert shows up before the other two requests'
# alerts do, and counting then made the late ones look like alerts from the ordinary requests
# (lane-j-ids failed on main in runs 1021 and 1038). Wait until the count stops moving.
prev=-1; stable=0
for _ in $(seq 1 30); do
  cur=$(alerts)
  if [ "$cur" = "$prev" ]; then stable=$((stable + 1)); else stable=0; fi
  [ "$stable" -ge 3 ] && break
  prev=$cur; sleep 1
done
N1=$(alerts)
for i in 1 2 3; do plain; done
sleep 3
[ "$(alerts)" = "$N1" ] || { grep '"event_type":"alert"' "$EVE" | tail -n +$((N1 + 1)) | cut -c1-300; nl_fail "an ordinary request raised an alert ($N1 -> $(alerts))"; }
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
suri_q3() { pgrep -af '^/usr/bin/suricata -c' | grep -- '-q 3' >/dev/null; }
nl_wait 60 suri_q3 || nl_fail "suricata was not restarted in NFQUEUE mode"
ids_chain=$(R nft list chain inet patronus ids_ips 2>&1 || true)
grep -q 'queue' <<<"$ids_chain" || { echo "$ids_chain"; R nft list ruleset | tail -30; nl_fail "no queue rule in the ids_ips chain"; }
nl_ok "firewall: ids_ips chain queues forwarded traffic ($(R nft list chain inet patronus ids_ips | grep -c queue) rules); suricata runs with -q 3"
sleep 8
plain || nl_fail "ordinary traffic does not pass in IPS mode"
nl_ok "ordinary request passes through the inline IPS"
if evil; then nl_fail "the request with the pattern was NOT dropped in IPS mode: $(cat "$NL_OUT")"; fi
nl_ok "request carrying the pattern is dropped inline"

echo "=== rule sets: a local HTTP source (no internet), download, policy, suppress, refusal"
SRC=/t/ids-src
rm -rf "$SRC"; mkdir -p "$SRC/rules"
mkset() { # [EXTRA RULE LINE]: write the test rule set and pack it
  printf '%s\n' 'alert tcp any any -> any 80 (msg:"Netlab set evil-set"; flow:to_server; content:"evil-set"; classtype:trojan-activity; sid:2900001; rev:1;)' > "$SRC/rules/netlab-test.rules"
  [ -z "${1:-}" ] || printf '%s\n' "$1" >> "$SRC/rules/netlab-test.rules"
  tar -czf "$SRC/set.tar.gz.new" -C "$SRC" rules && mv "$SRC/set.tar.gz.new" "$SRC/set.tar.gz"
}
mkset
nl_bg INET python3 -m http.server 8081 --bind 0.0.0.0 --directory "$SRC"
src_up() { R curl -sf -m 3 -o /dev/null "http://$NL_WWW:8081/set.tar.gz"; }
nl_wait 20 src_up || nl_fail "the local rule source did not come up"
SETS=/var/lib/patronus/net/suricata
evil2() { C curl -s --max-time 4 -o "$NL_OUT" -H 'X-Probe: evil-set' "http://$NL_WWW/"; }
eve_n() { { grep -c '"signature_id":2900001' "$EVE" 2>/dev/null || true; } | head -1; }
ids_warm() { nl_wait 60 suri_q3 || nl_fail "suricata is not running in NFQUEUE mode"; sleep 10; }
rs() { nl_api GET /svc/ids >/dev/null; python3 - "$NL_OUT" "$1" "$2" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))["status"]["rule_sets"]
r = [x for x in rows if x["key"] == sys.argv[2]]
print(r[0].get(sys.argv[3], "") if r else "")
PY
}
rs_is() { [ "$(rs "$1" "$2")" = "$3" ]; }
browser_n() { # QUERY -> number of alerts the alert browser finds
  nl_api GET "/svc/ids/alerts?$1&limit=500" >/dev/null; nl_json "$NL_OUT" 'd["total"]'
}
browser_ge() { [ "$(browser_n "$1")" -ge "$2" ]; }

echo "--- the page refuses bad sources, policies, overrides and suppress entries"
nl_api_code "ftp url" 400 POST /svc/ids/sources '{"key":"x1","name":"x","url":"ftp://x.example/a"}'
nl_api_code "key with a path" 400 POST /svc/ids/sources "{\"key\":\"../x\",\"name\":\"x\",\"url\":\"http://$NL_WWW:8081/set.tar.gz\"}"
nl_api_code "bad scope" 400 POST /svc/ids/policies '{"scope":"galaxy","target":"x","action":"drop"}'
nl_api_code "bad policy action" 400 POST /svc/ids/policies '{"scope":"ruleset","target":"x","action":"explode"}'
nl_api_code "sid 0" 400 POST /svc/ids/overrides '{"sid":0,"action":"disable"}'
nl_api_code "limit without tracking" 400 POST /svc/ids/suppress '{"sid":5,"kind":"limit","track":"none","count":1,"seconds":60}'
nl_api_code "address without tracking" 400 POST /svc/ids/suppress '{"sid":5,"kind":"suppress","ip":"10.0.0.1"}'
nl_api_code "bad address" 400 POST /svc/ids/suppress '{"sid":5,"kind":"suppress","track":"by_src","ip":"nope"}'
nl_api_code "bad window" 400 PUT /svc/ids '{"update_hour":24}'
nl_ok "bad URL, key, scope, action, SID, tracking, address and update hour are refused (400)"

echo "--- a new rule set is downloaded by the product's own task, checked and loaded"
nl_api GET /svc/ids
python3 - "$NL_OUT" <<'PY' || nl_fail "the seeded rule sources are missing or already switched on"
import json, sys
c = json.load(open(sys.argv[1]))["collections"]["sources"]
keys = {r["key"]: r for r in c}
assert {"et-open", "abuse-sslbl", "abuse-urlhaus"} <= set(keys), keys
assert all(not r["enabled"] and r["licence"] and r["url"].startswith("https://") for r in c), c
PY
nl_ok "ET Open and the abuse.ch lists are listed with URL and licence, all switched off"
nl_api_ok "add the local source" POST /svc/ids/sources "{\"key\":\"netlab\",\"name\":\"Netlab test rules\",\"url\":\"http://$NL_WWW:8081/set.tar.gz\",\"format\":\"tar.gz\",\"licence\":\"test\",\"enabled\":true,\"max_mb\":8}"
nl_api_code "the same key again" 400 POST /svc/ids/sources "{\"key\":\"netlab\",\"name\":\"again\",\"url\":\"http://$NL_WWW:8081/set.tar.gz\"}"
nl_wait 120 rs_is netlab status ok || { nl_api GET /svc/ids; cat "$NL_OUT"; tail -20 "$NL_T/nl-web.log"; nl_fail "the rule set was not downloaded by the scheduled task"; }
nl_wait 60 grep -q 'sid:2900001;' "$SETS/sources.rules" || nl_fail "sources.rules lacks the downloaded rule"
grep -q '^alert tcp any any -> any 80 (msg:"Netlab set evil-set"' "$SETS/sources.rules" || nl_fail "the downloaded rule was not loaded as shipped"
[ "$(rs netlab rules)" = 1 ] || nl_fail "the rule set shows $(rs netlab rules) rules, want 1"
nl_ok "downloaded by the task without a click: $(rs netlab message)"
ids_warm
nl_api GET /svc/ids
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the loaded rules"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["running"] and st["rules_loaded"] >= 1 and st["last_rule_update"], st
PY

echo "--- as shipped (alert): the matching request passes and is logged, the browser finds it"
E0=$(eve_n)
evil2 || nl_fail "a request matching an alert rule must pass in IPS mode"
nl_wait 30 sh -c "[ \$(grep -c '\"signature_id\":2900001' $EVE) -gt $E0 ]" || nl_fail "no alert for the downloaded rule"
nl_wait 40 browser_ge "sid=2900001&action=allowed" 1 || nl_fail "the alert browser does not list the alert"
nl_api GET "/svc/ids/alerts?sid=2900001&limit=5"
python3 - "$NL_OUT" <<'PY' || nl_fail "the alert row is wrong"
import json, sys
a = json.load(open(sys.argv[1]))["alerts"][0]
assert "Netlab set evil-set" in a["signature"] and a["sid"] == 2900001 and a["action"] == "allowed", a
assert a["dst_ip"] == "198.51.100.10" and a["dst_port"] == 80 and a["proto"] == "TCP" and a["time"] > 1_000_000_000, a
PY
nl_api GET "/svc/ids/alerts/top?by=sid&window=1h"
[ "$(nl_json "$NL_OUT" 'any(r["key"] == "2900001" and r["count"] >= 1 for r in d["top"])')" = True ] || nl_fail "top rules: $(cat "$NL_OUT")"
nl_api GET "/svc/ids/alerts/top?by=dst&window=1h"
[ "$(nl_json "$NL_OUT" 'd["top"][0]["key"]')" = "$NL_WWW" ] || nl_fail "top destinations: $(cat "$NL_OUT")"
nl_api_code "unknown filter value" 400 GET "/svc/ids/alerts?src=not-an-address"
nl_api GET /svc/ids/summary
[ "$(nl_json "$NL_OUT" 'd["alerts_24h"] >= 1')" = True ] || nl_fail "summary: $(cat "$NL_OUT")"
nl_ok "alert-only rule: request passes, alert logged and listed (filter by SID, top rules, top destinations, summary)"

echo "--- policy: ruleset drop really drops; a category alert only logs; classtype and SID beat the ruleset"
nl_api_ok "ruleset netlab -> drop" POST /svc/ids/policies '{"scope":"ruleset","target":"netlab","action":"drop"}'
PRS=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_code "the same policy twice" 400 POST /svc/ids/policies '{"scope":"ruleset","target":"netlab","action":"alert"}'
grep -q '^drop tcp any any -> any 80 (msg:"Netlab set evil-set"' "$SETS/sources.rules" || nl_fail "the policy did not turn the rule into a drop"
ids_warm
if evil2; then nl_fail "ruleset policy drop: the matching request was NOT dropped"; fi
plain || nl_fail "ordinary traffic must still pass with the drop policy"
nl_wait 40 browser_ge "sid=2900001&action=blocked" 1 || nl_fail "the dropped flow is not listed as blocked"
nl_ok "policy drop: the matching flow is dropped inline, ordinary traffic passes, the alert is listed as blocked"
nl_api_ok "category netlab-test -> alert" POST /svc/ids/policies '{"scope":"category","target":"netlab-test","action":"alert"}'
PCAT=$(nl_json "$NL_OUT" 'd["id"]')
ids_warm
E1=$(eve_n)
evil2 || nl_fail "category policy alert (more specific than the ruleset drop): the request must pass"
nl_wait 30 sh -c "[ \$(grep -c '\"signature_id\":2900001' $EVE) -gt $E1 ]" || nl_fail "category policy alert: nothing was logged"
nl_ok "policy alert (category beats ruleset): the request passes and is only logged"
nl_api_ok "classtype trojan-activity -> drop" POST /svc/ids/policies '{"scope":"classtype","target":"trojan-activity","action":"drop"}'
PCLS=$(nl_json "$NL_OUT" 'd["id"]')
ids_warm
if evil2; then nl_fail "classtype policy drop (beats the category alert): the request was NOT dropped"; fi
nl_ok "classtype drop beats the category alert"
nl_api_ok "SID 2900001 -> disable" POST /svc/ids/overrides '{"sid":2900001,"action":"disable","note":"netlab"}'
POV=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_code "a second override for the SID" 400 POST /svc/ids/overrides '{"sid":2900001,"action":"drop"}'
grep -q 'sid:2900001;' "$SETS/sources.rules" && nl_fail "the SID override did not remove the rule"
ids_warm
E2=$(eve_n)
for i in 1 2 3; do evil2 || nl_fail "SID override disable: the request must pass"; done
sleep 4
[ "$(eve_n)" = "$E2" ] || nl_fail "a disabled rule still alerted"
nl_ok "SID override disable beats everything: no rule, no alert, the request passes"
nl_api_ok "drop the SID override" DELETE "/svc/ids/overrides/$POV"
nl_api_ok "drop the classtype policy" DELETE "/svc/ids/policies/$PCLS"
nl_api_ok "drop the category policy" DELETE "/svc/ids/policies/$PCAT"
nl_api_ok "ruleset netlab -> alert" PUT "/svc/ids/policies/$PRS" '{"action":"alert"}'
ids_warm

echo "--- suppress from the alert (one click) stops the alert, removing the entry brings it back"
evil2 || nl_fail "alert policy: the request must pass"
nl_wait 40 browser_ge "sid=2900001" 1 || nl_fail "no alert to suppress"
nl_api GET "/svc/ids/alerts?sid=2900001&limit=1"
AID=$(nl_json "$NL_OUT" 'd["alerts"][0]["id"]')
nl_api_code "unknown alert" 404 POST /svc/ids/alerts/999999999/suppress '{"scope":"rule"}'
nl_api_code "bad scope" 400 POST "/svc/ids/alerts/$AID/suppress" '{"scope":"galaxy"}'
nl_api_ok "suppress the rule for everyone" POST "/svc/ids/alerts/$AID/suppress" '{"scope":"rule","kind":"suppress"}'
SID_ROW=$(nl_json "$NL_OUT" 'd["id"]')
grep -q 'suppress gen_id 1, sig_id 2900001' "$SETS/threshold.config" || nl_fail "threshold.config lacks the suppress line"
ids_warm
E3=$(eve_n)
for i in 1 2 3; do evil2 || nl_fail "suppressed rule: the request must pass"; done
sleep 4
[ "$(eve_n)" = "$E3" ] || nl_fail "a suppressed rule still alerted ($E3 -> $(eve_n))"
nl_ok "suppressed from one alert: three matching requests raise no alert"
nl_api_ok "remove the suppress entry" DELETE "/svc/ids/suppress/$SID_ROW"
ids_warm
evil2 || nl_fail "request must pass"
nl_wait 30 sh -c "[ \$(grep -c '\"signature_id\":2900001' $EVE) -gt $E3 ]" || nl_fail "the alert did not come back after the suppress entry was removed"
nl_api_ok "limit by source from the alert" POST "/svc/ids/alerts/$AID/suppress" '{"scope":"source","kind":"limit","count":1,"seconds":3600}'
grep -q 'threshold gen_id 1, sig_id 2900001, type limit, track by_src, count 1, seconds 3600' "$SETS/threshold.config" || nl_fail "threshold.config lacks the limit line"
nl_ok "removing the entry brings the alert back; a per-source limit is rendered to threshold.config"
LID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_ok "remove the limit" DELETE "/svc/ids/suppress/$LID"

echo "--- a broken download is refused and the running rules stay; a good one replaces them"
mkset 'alert bogusproto any any -> any any (msg:"broken rule"; sid:2900099; rev:1;)'
PID=$(suri_pid)
nl_api_ok "update now (broken set)" POST /svc/ids/action/update '{}'
rs_is netlab status rejected || { nl_api GET /svc/ids; cat "$NL_OUT"; nl_fail "a rule set suricata rejects must show as rejected, it is: $(rs netlab status)"; }
MSG=$(rs netlab message)
grep -q 'suricata -T' <<<"$MSG" || nl_fail "the refusal does not name suricata -T: $(rs netlab message)"
sleep 1
[ "$(suri_pid)" = "$PID" ] || nl_fail "suricata was restarted by a refused rule set"
grep -q bogusproto "$SETS/sources.rules" && nl_fail "the rejected rule set replaced the running rules"
grep -q 'sid:2900001;' "$SETS/sources.rules" || nl_fail "the old rule set is no longer loaded"
[ ! -d "$SETS/sources/netlab/next" ] || nl_fail "the refused download was left in place"
E4=$(eve_n)
evil2 || nl_fail "request must pass"
nl_wait 30 sh -c "[ \$(grep -c '\"signature_id\":2900001' $EVE) -gt $E4 ]" || nl_fail "the old rule set stopped working"
nl_ok "refused (suricata -T), pid $PID and the previous rules keep running: $(rs netlab message | cut -c1-110)"
mkset 'alert tcp any any -> any 80 (msg:"Netlab second"; content:"evil-two"; sid:2900002; rev:1;)'
nl_api_ok "update now (good set)" POST /svc/ids/action/update '{}'
rs_is netlab status ok || nl_fail "a good new set must be accepted, it is: $(rs netlab status) $(rs netlab message)"
[ "$(rs netlab rules)" = 2 ] || nl_fail "rules after the update: $(rs netlab rules), want 2"
grep -q 'sid:2900002;' "$SETS/sources.rules" || nl_fail "the new rule is not loaded"
[ -f "$SETS/sources/netlab/prev/netlab-test.rules" ] || nl_fail "the previous rule set was not kept"
[ "$(suri_pid)" != "$PID" ] || nl_fail "suricata was not restarted onto the new rules"
nl_api_ok "update now (unchanged)" POST /svc/ids/action/update '{}'
rs_is netlab status unchanged || nl_fail "the same download again must show unchanged, it is: $(rs netlab status)"
nl_ok "a good update replaces the rules (the old set is kept as prev); the same bytes again are 'unchanged'"
ids_warm

echo "--- a rule set switched off is not loaded, switched on again it needs no download"
nl_api GET /svc/ids
SRC_ID=$(nl_json "$NL_OUT" '[r["id"] for r in d["collections"]["sources"] if r["key"]=="netlab"][0]')
nl_api_ok "source off" PUT "/svc/ids/sources/$SRC_ID" '{"enabled":false}'
grep -q 'sid:2900001;' "$SETS/sources.rules" && nl_fail "a switched-off rule set is still loaded"
nl_api_ok "source on" PUT "/svc/ids/sources/$SRC_ID" '{"enabled":true}'
grep -q 'sid:2900001;' "$SETS/sources.rules" || nl_fail "the rule set did not come back from the files on disk"
nl_ok "off: not loaded; on: back from the files already on disk"
ids_warm

echo "=== reboot: patronus apply restores the IPS"
nl_web_stop
suri_kill
nl_boot "$DB"
nl_wait 60 suri_up || nl_fail "suricata not started by the boot apply"
# capture first: a pipe into grep -q under pipefail dies of SIGPIPE when grep exits early
ids_chain=$(R nft list chain inet patronus ids_ips 2>&1 || true)
grep -q queue <<<"$ids_chain" || { echo "$ids_chain"; R nft list ruleset | tail -30; nl_fail "queue rule missing after the boot apply"; }
sleep 10
plain || nl_fail "ordinary traffic blocked after the reboot"
if evil; then nl_fail "pattern not dropped after the reboot"; fi
nl_ok "after reboot: IPS active again (normal traffic passes, pattern dropped)"
grep -q 'sid:2900001;' "$SETS/sources.rules" || nl_fail "the downloaded rule set is not loaded after the reboot"
E5=$(eve_n)
evil2 || nl_fail "alert policy after the reboot: the request must pass"
nl_wait 30 sh -c "[ \$(grep -c '\"signature_id\":2900001' $EVE) -gt $E5 ]" || nl_fail "the downloaded rule set does not alert after the reboot"
nl_ok "after reboot: the downloaded rule set and its policy are back without any download"

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/ids '{"enabled":false}'
nl_wait 20 suri_gone || nl_fail "suricata still running"
R nft list chain inet patronus ids_ips >/dev/null 2>&1 && nl_fail "ids_ips chain still present"
evil || nl_fail "traffic with the pattern is still blocked with the IDS off"
nl_ok "disabled: suricata stopped, queue chain gone, nothing is blocked"
nl_web_stop
echo "ALL IDS CHECKS PASSED"
