#!/usr/bin/env bash
# Customer journey: configuration backup + restore THROUGH THE WEB API (the calls the
# System page's "Back up now", "Restore" and "Upload and restore" buttons make), not through
# `patronus config import` (journey-backup-restore.sh covers the CLI path) and not by copying
# files. The backup holds settings (host name), web accounts and firewall rules. The box is then
# reconfigured completely differently (other rules, other host name, another admin account,
# the backed-up account gone), and the restore must bring the original back, proven by what the
# box DOES: kernel host name, nft ruleset and real LAN/WAN traffic, and real logins of the
# restored accounts (an account that only appears in a listing proves nothing). Also after a
# reboot (`patronus apply`), and again through the upload path. A garbage upload changes nothing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/bkapi.db
rm -f "$DB" "$NL_T/nl-jar" /t/bkapi-*.json
BKDIR=/t/bkapi-backups
rm -rf "$BKDIR"; mkdir -p "$BKDIR"
export PATRONUS_BACKUP_DIR=$BKDIR
OPS_USER=bk-ops;   OPS_PW='Bk-Ops-Journey-Pass-1!'
INT_USER=bk-intruder; INT_PW='Bk-Intruder-Pass-1!'
HOST_A=bk-original; HOST_B=bk-changed
OLD_HOST=$(cat /proc/sys/kernel/hostname)
trap 'echo "$OLD_HOST" >/proc/sys/kernel/hostname 2>/dev/null || true' EXIT
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
# Log in as USER/PASSWORD with a fresh cookie jar; prints the HTTP status.
login_as() {
  rm -f "$NL_T/nl-jar"
  nl_api POST /auth/login "{\"username\":\"$1\",\"password\":\"$2\"}"
  echo "$NL_CODE"
}
admin_login() { [ "$(login_as admin "$NL_PASS")" = 200 ] || nl_fail "admin login: $NL_CODE $(cat "$NL_OUT")"; }
rule() { # NAME CHAIN ACTION IFACE DEST PORT
  nl_api POST /firewall/rules "{\"name\":\"$1\",\"chain\":\"$2\",\"action\":\"$3\",\"interface\":\"$4\",\"protocol\":\"tcp\",\"source\":\"any\",\"destination\":\"$5\",\"port\":\"$6\",\"description\":\"$1\",\"enabled\":true}"
  [ "$NL_CODE" = 201 ] || nl_fail "add $1: $NL_CODE $(cat "$NL_OUT")"
}
delete_rules_named() { # PREFIX
  nl_api GET /firewall/rules
  for id in $(python3 -c 'import json,sys; print(" ".join(str(r["id"]) for r in json.load(open(sys.argv[1])) if r["name"].startswith(sys.argv[2])))' "$NL_OUT" "$1"); do
    nl_api DELETE "/firewall/rules/$id"; [ "$NL_CODE" = 200 ] || nl_fail "delete rule $id: $NL_CODE"
  done
}
# What the box does in configuration A (the backed-up one) and in B.
assert_state_a() { # DESC
  [ "$(cat /proc/sys/kernel/hostname)" = "$HOST_A" ] || nl_fail "$1: kernel host name is $(cat /proc/sys/kernel/hostname), want $HOST_A"
  nl_assert_nft_has bk-a-block bk-a-wan-2222
  nl_assert_nft_lacks bk-b-block
  nl_expect_http_blocked "$1: bk-a-block enforced (blocked.example.test)" http://blocked.example.test/
  nl_expect_http "$1: www.example.test reachable (B's block is gone)" http://www.example.test/ "sees"
  nl_expect_tcp "$1: WAN -> router:2222 open (restored allow rule)" ISP $NL_RTR_WAN 2222
}
assert_state_b() {
  [ "$(cat /proc/sys/kernel/hostname)" = "$HOST_B" ] || nl_fail "B: kernel host name is $(cat /proc/sys/kernel/hostname)"
  nl_assert_nft_has bk-b-block
  nl_assert_nft_lacks bk-a-block bk-a-wan-2222
  nl_expect_http "B: blocked.example.test reachable" http://blocked.example.test/ "sees"
  nl_expect_http_blocked "B: bk-b-block enforced (www.example.test)" http://www.example.test/
  nl_expect_no_tcp "B: WAN -> router:2222 closed" ISP $NL_RTR_WAN 2222
}
assert_accounts_a() { # DESC: logins really work / are refused
  [ "$(login_as "$OPS_USER" "$OPS_PW")" = 200 ] || nl_fail "$1: restored account $OPS_USER cannot log in ($NL_CODE $(cat "$NL_OUT"))"
  nl_api GET /auth/me; [ "$NL_CODE" = 200 ] || nl_fail "$1: $OPS_USER session unusable: $NL_CODE"
  grep -q "$OPS_USER" "$NL_OUT" || nl_fail "$1: /auth/me does not name $OPS_USER: $(cat "$NL_OUT")"
  # an operator must not be able to restore (admins only): the role came back too
  nl_api POST /system/restore '{}'
  [ "$NL_CODE" = 403 ] || nl_fail "$1: operator may not restore, got $NL_CODE"
  [ "$(login_as "$INT_USER" "$INT_PW")" != 200 ] || nl_fail "$1: account $INT_USER (made after the backup) still logs in"
  admin_login
  nl_ok "$1: restored account logs in as operator, the later account is gone, admin works"
}

nl_write_installer_toml
echo "=== configuration A: rules, host name, an operator account"
nl_boot "$DB"
nl_web_start "$DB"; admin_login
rule bk-a-block forward drop @lan 198.51.100.20 80
rule bk-a-wan-2222 input accept @wan any 2222
nl_api PUT /system/general "{\"hostname\":\"$HOST_A\"}"
[ "$NL_CODE" = 200 ] || nl_fail "set host name A: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /system/users "{\"username\":\"$OPS_USER\",\"password\":\"$OPS_PW\",\"role\":\"operator\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create $OPS_USER: $NL_CODE $(cat "$NL_OUT")"
assert_state_a "config A"

echo "=== back up through the API (Back up now)"
nl_api POST /system/backups
[ "$NL_CODE" = 201 ] || nl_fail "create backup: $NL_CODE $(cat "$NL_OUT")"
BK=$(jget 'd["name"]')
nl_api GET "/system/backups/$BK"
[ "$NL_CODE" = 200 ] || nl_fail "download backup: $NL_CODE"
cp "$NL_OUT" /t/bkapi-download.json
python3 - /t/bkapi-download.json "$OPS_USER" <<'PY' || nl_fail "the backup does not carry rules, host name and accounts"
import json, sys
d = json.load(open(sys.argv[1])); t = d["tables"]
assert any(r["name"] == "bk-a-block" for r in t["firewall_rules"]), "rules"
assert any(u["username"] == sys.argv[2] for u in t["web_users"]), "accounts"
assert "bk-original" in json.dumps(t), "host name"
PY
nl_ok "backup $BK holds the rules, the host name and the accounts"

echo "=== configuration B: everything different"
delete_rules_named bk-a-
rule bk-b-block forward drop @lan "$NL_WWW" 80
nl_api PUT /system/general "{\"hostname\":\"$HOST_B\"}"
[ "$NL_CODE" = 200 ] || nl_fail "set host name B: $NL_CODE"
nl_api GET /system/users
OPS_ID=$(python3 -c 'import json,sys; print([u["id"] for u in json.load(open(sys.argv[1])) if u["username"]==sys.argv[2]][0])' "$NL_OUT" "$OPS_USER")
nl_api DELETE "/system/users/$OPS_ID"; [ "$NL_CODE" = 200 ] || nl_fail "delete $OPS_USER: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /system/users "{\"username\":\"$INT_USER\",\"password\":\"$INT_PW\",\"role\":\"admin\"}"
[ "$NL_CODE" = 201 ] || nl_fail "create $INT_USER: $NL_CODE $(cat "$NL_OUT")"
assert_state_b
[ "$(login_as "$OPS_USER" "$OPS_PW")" != 200 ] || nl_fail "deleted account still logs in"
[ "$(login_as "$INT_USER" "$INT_PW")" = 200 ] || nl_fail "intruder account cannot log in"
admin_login

echo "=== restore the stored backup through the API (Restore button)"
nl_api POST "/system/backups/$BK/restore"
[ "$NL_CODE" = 200 ] || nl_fail "restore: $NL_CODE $(cat "$NL_OUT")"
[ "$(jget 'd["ok"]')" = True ] || nl_fail "restore answer: $(cat "$NL_OUT")"
assert_state_a "after restore"
assert_accounts_a "after restore"
nl_api GET /firewall/rules
grep -q bk-a-block "$NL_OUT" && ! grep -q bk-b-block "$NL_OUT" || nl_fail "the rule list does not match the restored configuration"
nl_web_stop

echo "=== the restored configuration survives a reboot"
nl_boot "$DB"
assert_state_a "after reboot"
nl_web_start "$DB"
assert_accounts_a "after reboot"
nl_expect_online

echo "=== restore from an uploaded file (Upload and restore), after the box drifted again"
delete_rules_named bk-a-
rule bk-b-block forward drop @lan "$NL_WWW" 80
nl_api PUT /system/general "{\"hostname\":\"$HOST_B\"}"; [ "$NL_CODE" = 200 ] || nl_fail "host name B again: $NL_CODE"
assert_state_b
# the System page posts the file's text as the body
NL_CODE=$(C curl -sk -m 60 -b "$NL_T/nl-jar" -c "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' -X POST \
  -H 'content-type: application/json' --data-binary @/t/bkapi-download.json "$NL_UI/api/system/restore")
[ "$NL_CODE" = 200 ] || nl_fail "upload restore: $NL_CODE $(cat "$NL_OUT")"
assert_state_a "after upload restore"
assert_accounts_a "after upload restore"

echo "=== a file that is not a Patronus export is refused and nothing changes"
before=$(nl_ruleset_fingerprint)
NL_CODE=$(C curl -sk -m 60 -b "$NL_T/nl-jar" -c "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' -X POST \
  -H 'content-type: application/json' -d '{"tables":{"no_such_table":[]}}' "$NL_UI/api/system/restore")
case "$NL_CODE" in 4??) ;; *) nl_fail "junk upload answered $NL_CODE (want 4xx)";; esac
[ "$(nl_ruleset_fingerprint)" = "$before" ] || nl_fail "junk upload changed the ruleset"
assert_state_a "after refused junk upload"
nl_web_stop
nl_assert_store_ok "$DB"

nl_down
echo "JOURNEY BACKUP/RESTORE (API): ALL CHECKS PASSED"
