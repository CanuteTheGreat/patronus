#!/usr/bin/env bash
# Lane H: notification matchers (docs/NOTIFY-MATCHERS.md) on the real binaries. A local webhook receiver on the
# internet side of the lab records every delivery; the box's clock is faked (PATRONUS_FAKE_TIME_FILE) so a
# calendar window can be tested at will.
#
#  1. API: a bad tree is refused (400: empty any, two items under not, a bad time, too deep), a good one saved,
#     a matcher in use cannot be deleted, "would match" preview judges the last events.
#  2. channels: one follows the matcher  all[ any[kind gateway_down, kind gateway_up],
#     calendar Mon-Fri 22:00-06:00, not[ subject GW_B* ] ]; one is a plain channel made through the old API
#     (kinds + min_severity, no matcher: gets an equivalent one); one is a row as an older document leaves it
#     (matcher empty: its own kinds + min_severity).
#  3. real gateway events (two gateways whose monitor stops answering):
#       Monday 23:00 (in the window)  gateway_down GW_A -> matcher channel; GW_B refused by the "not"
#       Monday 12:00 (outside)        gateway_up, gateway_down -> matcher channel gets nothing
#       Tuesday 02:00 (Monday's night, past midnight) gateway_up GW_A -> delivered, GW_B refused
#       Saturday 23:00 (Friday's window ended Saturday 06:00) gateway_down -> nothing
#     while the legacy channels get every gateway_down (critical) at every time of day.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-notify-matchers.db
LOG="$NL_T/nm-http.log"
FAKE="$NL_T/nm-fake-time"
rm -f "$DB" "$NL_T/nl-jar" "$LOG"; : > "$LOG"
set_clock() { printf '%s\n' "$1" > "$FAKE"; }
set_clock "2026-11-23 23:00"   # a Monday
export PATRONUS_FAKE_TIME_FILE="$FAKE"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
j() { nl_json "$NL_OUT" "$1"; }

cat > "$NL_T/nl-nm-http.py" <<'PY'
import http.server, json, sys
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0))).decode()
        with open(LOG, 'a') as f:
            f.write(json.dumps({'path': self.path, 'body': body}) + '\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 9210), H).serve_forever()
PY
nl_bg INET python3 "$NL_T/nl-nm-http.py" "$LOG"
for _ in $(seq 1 40); do INET bash -c "exec 3<>/dev/tcp/$NL_WWW/9210" 2>/dev/null && break; sleep 0.25; done
H="http://$NL_WWW:9210"

# deliveries to /<path> whose event is <kind> about <subject>
got() { python3 - "$LOG" "$1" "$2" "$3" <<'PY'
import json, sys
log, path, kind, subj = sys.argv[1:5]
n = 0
for l in open(log):
    if not l.strip(): continue
    r = json.loads(l)
    if r['path'] != path: continue
    b = json.loads(r['body'])
    if b.get('kind') == kind and (subj == '*' or b.get('subject') == subj): n += 1
print(n)
PY
}
wait_got() { # path kind subject want : wait until the count reaches `want` (or time out)
  local n
  for _ in $(seq 1 60); do n=$(got "$1" "$2" "$3"); [ "$n" -ge "$4" ] && return 0; sleep 1; done
  nl_fail "expected $4 delivery(ies) of $2/$3 to $1, got $n: $(cat "$LOG")"
}
settle() { sleep 8; }

echo "=== 1. matcher API"
TREE='{"op":"all","items":[
  {"op":"any","items":[{"op":"kind","kinds":["gateway_down"]},{"op":"kind","kinds":["gateway_up"]}]},
  {"op":"calendar","days":["mon","tue","wed","thu","fri"],"start":"22:00","end":"06:00"},
  {"op":"not","items":[{"op":"subject","glob":"GW_B*"}]}]}'
for bad in '{"tree":{"op":"any","items":[]}}' \
           '{"tree":{"op":"not","items":[{"op":"kind","kinds":["test"]},{"op":"kind","kinds":["tunnel_up"]}]}}' \
           '{"tree":{"op":"calendar","days":["mon"],"start":"25:00","end":"06:00"}}' \
           '{"tree":{"op":"kind","kinds":["no_such_kind"]}}' \
           '{"tree":{"op":"all","items":[{"op":"all","items":[{"op":"all","items":[{"op":"all","items":[{"op":"all","items":[{"op":"all","items":[{"op":"all","items":[{"op":"all","items":[{"op":"all"}]}]}]}]}]}]}]}]}}'; do
  nl_api PUT /system/matchers/bad "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "bad matcher accepted ($NL_CODE): $bad"
done
nl_api PUT /system/matchers/night-gw "{\"description\":\"gateway trouble on weekday nights\",\"tree\":$TREE}"
[ "$NL_CODE" = 200 ] || nl_fail "save matcher: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /system/matchers
[ "$(j 'len(d)')" = 1 ] || nl_fail "list: $(cat "$NL_OUT")"
nl_api GET /system/matchers/limits
[ "$(j 'd["max_depth"]')" = 8 ] || nl_fail "limits: $(cat "$NL_OUT")"
nl_ok "5 bad trees refused (400), a nested tree saved, listed, limits served"

echo "=== 2. channels"
add() { nl_api POST /system/hooks "$1"; [ "$NL_CODE" = 201 ] || nl_fail "add channel: $NL_CODE $(cat "$NL_OUT") <- $1"; j 'd["id"]'; }
MID=$(add "{\"name\":\"m1\",\"url\":\"$H/m1\",\"matcher\":\"night-gw\"}")
ALLEV=$(add "{\"name\":\"all-ev\",\"url\":\"$H/all-ev\"}")   # every event: the barrier that tells when an event has fired
LEG=$(add "{\"name\":\"legacy-api\",\"url\":\"$H/legacy-api\",\"kinds\":\"gateway_down\",\"min_severity\":\"critical\"}")
nl_api POST /system/hooks "{\"name\":\"x\",\"url\":\"$H/x\",\"matcher\":\"missing\"}"
[ "$NL_CODE" = 400 ] || nl_fail "channel with an unknown matcher accepted ($NL_CODE)"
# a channel row as a document from before matchers leaves it: matcher empty
python3 - "$DB" "$H" <<'PY'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1]); c.execute("PRAGMA busy_timeout=5000")
c.execute("INSERT INTO event_hooks (name,url,secret,kinds,enabled,created_at,channel,target,sender,username,min_severity,matcher) VALUES ('legacy-row',?,?,?,1,?,'webhook','','','','critical','')",
          (sys.argv[2] + '/legacy-row', '', 'gateway_down,tunnel_down', int(time.time())))
c.commit()
PY
nl_api GET /system/hooks
[ "$(j '[h["matcher"] for h in d if h["name"]=="legacy-api"][0]')" = "auto-legacy-api" ] || nl_fail "legacy channel has no equivalent matcher: $(cat "$NL_OUT")"
[ "$(j '[h["matcher"] for h in d if h["name"]=="legacy-row"][0]')" = "" ] || nl_fail "legacy row changed: $(cat "$NL_OUT")"
nl_api DELETE /system/matchers/night-gw
[ "$NL_CODE" = 400 ] || nl_fail "a matcher in use was deleted ($NL_CODE)"
nl_ok "matcher channel, old-API channel (gets auto-legacy-api), pre-matcher row, unknown matcher refused, in-use delete refused"

echo "=== 3. real events against the fake clock"
for g in GW_A GW_B; do
  nl_api POST /routing/gateways "{\"name\":\"$g\",\"interface\":\"@wan\",\"monitor_ip\":\"$NL_WWW\"}"
  [ "$NL_CODE" = 201 ] || nl_fail "add gateway $g: $NL_CODE $(cat "$NL_OUT")"
done
sleep 6
: > "$LOG"
block()   { ISP nft add table ip nl_icmp; ISP nft "add chain ip nl_icmp f { type filter hook forward priority 0; }"; ISP nft "add rule ip nl_icmp f ip daddr $NL_WWW icmp type echo-request drop"; }
unblock() { ISP nft delete table ip nl_icmp; }

# Monday 23:00: inside the window
block
wait_got /legacy-api gateway_down GW_A 1; wait_got /legacy-api gateway_down GW_B 1
wait_got /legacy-row gateway_down GW_A 1
wait_got /all-ev gateway_down GW_A 1; wait_got /m1 gateway_down GW_A 1; settle
[ "$(got /m1 gateway_down GW_B)" = 0 ] || nl_fail "the 'not subject GW_B*' leaf let GW_B through: $(cat "$LOG")"
nl_ok "Monday 23:00 (in the window): GW_A delivered, GW_B refused by 'not'; both legacy channels deliver"

# Monday 12:00: outside the window
set_clock "2026-11-23 12:00"
unblock
wait_got /all-ev gateway_up GW_A 1; settle
[ "$(got /m1 gateway_up '*')" = 0 ] || nl_fail "m1 got a gateway_up at 12:00 (outside the window): $(cat "$LOG")"
block
wait_got /all-ev gateway_down GW_A 2; wait_got /legacy-api gateway_down GW_A 2; wait_got /legacy-row gateway_down GW_A 2; settle
[ "$(got /m1 gateway_down GW_A)" = 1 ] || nl_fail "m1 got a gateway_down at 12:00 (outside the window): $(cat "$LOG")"
nl_ok "Monday 12:00 (outside): gateway_up and gateway_down not sent to the matcher channel, legacy channels still deliver"

# Tuesday 02:00: the tail of Monday's 22:00-06:00 window, past midnight
set_clock "2026-11-24 02:00"
unblock
wait_got /all-ev gateway_up GW_A 2; wait_got /m1 gateway_up GW_A 1; settle
[ "$(got /m1 gateway_up GW_B)" = 0 ] || nl_fail "GW_B delivered through 'not': $(cat "$LOG")"
[ "$(got /legacy-api gateway_up '*')" = 0 ] || nl_fail "the critical-only gateway_down channel got a gateway_up"
nl_ok "Tuesday 02:00 (Monday's window past midnight): gateway_up GW_A delivered, GW_B refused"

# Saturday 23:00: Friday's window ended Saturday 06:00, Saturday is not a window day
set_clock "2026-11-28 23:00"
block
wait_got /all-ev gateway_down GW_A 3; wait_got /legacy-api gateway_down GW_A 3; settle
[ "$(got /m1 gateway_down GW_A)" = 1 ] || nl_fail "m1 delivered on Saturday night: $(cat "$LOG")"
nl_ok "Saturday 23:00 (no window): matcher channel silent, legacy channel delivers"
unblock

echo "=== 4. preview and rewiring"
nl_api POST /system/matchers/preview "{\"tree\":$TREE}"
[ "$NL_CODE" = 200 ] && [ "$(j 'd["total"] > 0')" = True ] || nl_fail "preview: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /system/matchers/preview '{"tree":{"op":"all","items":[]}}'
[ "$(j 'd["matched"] == d["total"]')" = True ] || nl_fail "an empty 'all' must match every event: $(cat "$NL_OUT")"
nl_api PUT "/system/hooks/$MID/matcher" '{"matcher":""}'
[ "$NL_CODE" = 200 ] || nl_fail "rewire: $NL_CODE $(cat "$NL_OUT")"
nl_api PUT "/system/hooks/$MID/matcher" '{"matcher":"nope"}'
[ "$NL_CODE" = 400 ] || nl_fail "rewire to an unknown matcher: $NL_CODE"
nl_api DELETE "/system/hooks/$LEG"
nl_api GET /system/matchers
[ "$(j '[m["name"] for m in d if m["name"]=="auto-legacy-api"] == []')" = True ] || nl_fail "the channel's own matcher stayed after deleting it: $(cat "$NL_OUT")"
nl_ok "preview judges the event log, a channel can be rewired, deleting a channel removes its own matcher"

nl_web_stop
nl_down
echo "lane-h-notify-matchers: all checks passed"
