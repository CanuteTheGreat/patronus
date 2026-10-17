#!/usr/bin/env bash
# Customer journey: back up a configured box, then (1) restore it onto a
# replacement box (fresh install, empty store) and (2) restore it onto the
# same box after the admin broke things -- each time proving the restored
# rules are enforced in real traffic, also after a reboot.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/bk-box1.db
DB2=/t/bk-box2.db
rm -f "$DB" "$DB2" /t/backup.json
nl_write_installer_toml

echo "=== configure box 1 and back it up"
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api POST /firewall/rules '{"name":"bk-block","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"bk-block","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add bk-block: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /firewall/rules '{"name":"bk-wan-2222","chain":"input","action":"accept","interface":"@wan","protocol":"tcp","source":"any","destination":"any","port":"2222","description":"bk-wan-2222","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add bk-wan-2222: $NL_CODE"
nl_web_stop
R "$P" --db "$DB" config export -o /t/backup.json 2>"$NL_OUT" || { cat "$NL_OUT"; nl_fail "export"; }
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); n=[r["name"] for r in d["tables"]["firewall_rules"]]; assert "bk-block" in n and "bk-wan-2222" in n, n' /t/backup.json
nl_ok "backup written ($(wc -c </t/backup.json) bytes, mode $(stat -c %a /t/backup.json))"

echo "=== restore onto a replacement box (fresh install)"
nl_up
nl_apply "$DB2" || { cat "$NL_OUT"; nl_fail "replacement first boot"; }
nl_expect_http "replacement box before restore: blocked.example.test reachable" http://blocked.example.test/ "sees"
R "$P" --db "$DB2" config import /t/backup.json >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "import"; }
nl_assert_nft_has bk-block bk-wan-2222
nl_expect_http_blocked "replacement box after restore: bk-block enforced" http://blocked.example.test/
nl_expect_tcp "WAN -> router:2222 (restored allow rule)" ISP $NL_RTR_WAN 2222
nl_expect_online
nl_boot "$DB2"
nl_expect_http_blocked "replacement box after reboot: bk-block enforced" http://blocked.example.test/
nl_web_start "$DB2"; nl_login
nl_api GET /firewall/rules
grep -q bk-block "$NL_OUT" || nl_fail "restored rule not listed by the web API"
nl_ok "restored rules listed by the replacement box's web UI API"
nl_web_stop

echo "=== the admin deletes rules on box 1, then restores the backup"
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api GET /firewall/rules
for id in $(python3 -c 'import json,sys; print(" ".join(str(r["id"]) for r in json.load(open(sys.argv[1])) if r["name"].startswith("bk-")))' "$NL_OUT"); do
  nl_api DELETE "/firewall/rules/$id"; [ "$NL_CODE" = 200 ] || nl_fail "delete $id: $NL_CODE"
done
nl_web_stop
nl_expect_http "box 1 after deleting: blocked.example.test reachable" http://blocked.example.test/ "sees"
R "$P" --db "$DB" config import /t/backup.json >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "import on box 1"; }
nl_expect_http_blocked "box 1 after restore: bk-block enforced again" http://blocked.example.test/
R "$P" --db "$DB" config revisions | grep -q 'before import of /t/backup.json' || nl_fail "import left no revision"
nl_ok "the configuration the import replaced is kept as a revision"
nl_boot "$DB"
nl_expect_http_blocked "box 1 after reboot: bk-block enforced" http://blocked.example.test/
nl_assert_store_ok "$DB"

echo "=== a file that is not a Patronus export is refused, nothing changes"
echo '{"tables":{"no_such_table":[]}}' > /t/junk.json
before=$(nl_ruleset_fingerprint)
if R "$P" --db "$DB" config import /t/junk.json >"$NL_OUT" 2>&1; then nl_fail "junk import succeeded"; fi
[ "$(nl_ruleset_fingerprint)" = "$before" ] || nl_fail "junk import changed the ruleset"
nl_expect_http_blocked "after refused junk import: bk-block still enforced" http://blocked.example.test/

nl_down
echo "JOURNEY BACKUP/RESTORE: ALL CHECKS PASSED"
