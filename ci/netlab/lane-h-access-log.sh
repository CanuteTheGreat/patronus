#!/usr/bin/env bash
# Lane H: web/API access log, proven against the real binaries.
#
#  - a wrong password, an API-key read, an operator's firewall-rule POST and a
#    404 each become a row with the right principal, status and PATH GROUP
#    (the route template: no ids, no query string, no token);
#  - the statistics add up to the rows;
#  - a burst of failed sign-ins raises the `login_failures` event;
#  - the page and the CSV download are served to the admin only.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-access-log.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
kreq() { # TOKEN METHOD PATH
  NL_CODE=$(C curl -sk -o "$NL_OUT" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $1" "$NL_UI$3")
}
# rows are written in batches: poll until the expected row is visible
wait_rows() { # QUERY EXPR (evaluated on the answer, must be true)
  for _ in $(seq 1 30); do
    nl_api GET "/system/access-log?$1&limit=500"
    if [ "$NL_CODE" = 200 ] && [ "$(jget "$2")" = True ]; then return 0; fi
    sleep 1
  done
  nl_fail "no matching rows for $1: $(head -c 600 "$NL_OUT")"
}

echo "=== a short burst threshold so the event can be proven"
nl_api PUT /system/access-log/settings '{"login_burst":4,"login_window_secs":120,"event_cooldown_secs":60}'
[ "$NL_CODE" = 200 ] || nl_fail "settings: $NL_CODE $(cat "$NL_OUT")"
nl_ok "typed settings accepted"

echo "=== traffic: wrong password, API key read, operator POST, 404"
nl_api POST /system/api-keys '{"name":"collector","scope":"readonly"}'
[ "$NL_CODE" = 201 ] || nl_fail "create key: $NL_CODE"
TOK=$(jget 'd["token"]')
kreq "$TOK" GET /api/status/summary
[ "$NL_CODE" = 200 ] || nl_fail "key read: $NL_CODE"

for i in 1 2 3 4 5; do
  C curl -sk -o /dev/null -X POST -H 'content-type: application/json' \
    -d '{"username":"mallory","password":"not-the-password"}' "$NL_UI/api/auth/login"
done

nl_api POST /firewall/rules '{"name":"alog","action":"accept","interface":"any","protocol":"tcp","source":"any","destination":"any","port":"9","description":"","enabled":true,"chain":"input"}'
[ "$NL_CODE" = 201 ] || [ "$NL_CODE" = 200 ] || nl_fail "operator rule POST: $NL_CODE $(cat "$NL_OUT")"
nl_web GET "/api/no-such-thing/4242?token=hunter2-secret"
[ "$NL_CODE" = 404 ] || nl_fail "404 expected: $NL_CODE"

wait_rows "limit=500" 'any(r["status"]==404 for r in d["rows"]) and any(r["method"]=="POST" and r["path_group"]=="/api/firewall/rules" for r in d["rows"]) and any(r["principal_kind"]=="api_key" for r in d["rows"])'
nl_ok "rows exist"

nl_api GET "/system/access-log?limit=500"
python3 - "$NL_OUT" <<'PY' || nl_fail "row content"
import json, sys
raw = open(sys.argv[1]).read()
d = json.loads(raw)
rows = d["rows"]
assert "hunter2-secret" not in raw and "4242" not in raw, "raw path/query stored"
assert "not-the-password" not in raw, "password stored"
bad = [r for r in rows if r["path_group"] == "/api/auth/login" and r["status"] == 401]
assert len(bad) == 5 and all(r["attempted_user"] == "mallory" and r["principal_kind"] == "anonymous" for r in bad), bad
key = [r for r in rows if r["principal_kind"] == "api_key" and r["path_group"] == "/api/status/summary"]
assert key and key[0]["principal_name"] == "collector" and key[0]["status"] == 200, key
post = [r for r in rows if r["method"] == "POST" and r["path_group"] == "/api/firewall/rules"]
assert post and post[0]["principal_kind"] == "user" and post[0]["principal_name"] == "admin", post
nf = [r for r in rows if r["status"] == 404]
assert nf and all("no-such-thing" not in r["path_group"] and "4242" not in r["path_group"] for r in nf), nf
PY
nl_ok "principal, status and path group are right; no id, query or password stored"

echo "=== statistics add up"
nl_api GET "/system/access-log?limit=500"
TOTAL=$(jget 'd["total"]')
nl_api GET "/system/access-log/stats"
[ "$NL_CODE" = 200 ] || nl_fail "stats: $NL_CODE"
python3 - "$NL_OUT" <<'PY' || nl_fail "stats maths"
import json, sys
s = json.load(open(sys.argv[1]))
assert s["requests"] >= 9, s
assert s["client_errors"] >= 6, s          # 5 failed logins + the 404
assert sum(b["requests"] for b in s["buckets"]) == s["requests"], s
assert any(t["value"] == "/api/auth/login" for t in s["top_path_group"]), s
PY
nl_api GET "/system/access-log/stats?status=4xx"
[ "$(jget 'd["requests"]')" = "$(jget 'd["client_errors"]')" ] || nl_fail "4xx filter: $(cat "$NL_OUT")"
nl_ok "totals, buckets and the status filter agree"

echo "=== failed-login burst became an event"
for _ in $(seq 1 30); do
  nl_api GET "/events?kind=login_failures"
  [ "$(jget 'len(d)')" -ge 1 ] && break
  sleep 1
done
[ "$(jget 'len(d)')" -ge 1 ] || nl_fail "no login_failures event: $(cat "$NL_OUT")"
nl_ok "login_failures event in /api/events"

echo "=== admin only; page and CSV"
kreq "$TOK" GET /api/system/access-log
[ "$NL_CODE" = 403 ] || nl_fail "an API key read the access log: $NL_CODE"
nl_web GET /system/access-log
[ "$NL_CODE" = 200 ] && grep -q 'id="dlg-stats"' "$NL_OUT" || nl_fail "page: $NL_CODE"
nl_web GET "/api/system/access-log/csv?status=4xx"
[ "$NL_CODE" = 200 ] && grep -q '^' "$NL_OUT" && grep -q '/api/auth/login' "$NL_OUT" || nl_fail "csv: $NL_CODE"
nl_api GET "/system/audit-log"
[ "$NL_CODE" = 200 ] && [ "$(jget 'len(d["rows"])')" -ge 1 ] || nl_fail "audit log: $NL_CODE $(head -c 300 "$NL_OUT")"
nl_ok "the API key is refused, the page and CSV are served, configuration changes are listed"
