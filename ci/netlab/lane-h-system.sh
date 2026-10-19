#!/usr/bin/env bash
# Lane H: web accounts, two-factor login and backup/restore through the web
# API on the real binaries, with the effects checked in the store, in
# nftables and in real traffic -- and across a reboot.
#
#  1. accounts: an operator and a read-only account are created in the UI,
#     survive a patronus-web restart and a reboot; roles are enforced.
#  2. backup -> change -> restore (stored backup and an uploaded file):
#     the firewall rule added after the backup disappears from nftables and
#     its traffic flows again; a reboot keeps the restored state.
#  3. TOTP: admin enrols (code computed here from the secret, like an
#     authenticator app); afterwards a password alone is refused and
#     password + code logs in; a recovery code works once; `patronus users
#     reset-2fa` turns it off again (lost phone).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h.db
rm -f "$DB" "$NL_T/nl-jar"
rm -rf /t/backups
export PATRONUS_BACKUP_DIR=/t/backups
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login

totp() { # SECRET OFFSET-STEPS -> the code an authenticator app shows
  python3 - "$1" "$2" <<'EOF'
import base64, hashlib, hmac, struct, sys, time
s = sys.argv[1]; k = base64.b32decode(s + "=" * (-len(s) % 8))
c = int(time.time()) // 30 + int(sys.argv[2])
h = hmac.new(k, struct.pack(">Q", c), hashlib.sha1).digest(); o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))
EOF
}
# login USER PASSWORD [CODE] -> HTTP status in $NL_CODE, cookie in the jar
login_as() {
  rm -f "$NL_T/nl-jar"
  local body="{\"username\":\"$1\",\"password\":\"$2\"${3:+,\"totp_code\":\"$3\"}}"
  nl_api POST /auth/login "$body"
}
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($1)" "$NL_OUT"; }

echo "=== 1. accounts"
nl_api POST /system/users '{"username":"ops","password":"Ops-Passw0rd-123","role":"operator"}'
[ "$NL_CODE" = 201 ] || nl_fail "create ops: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /system/users '{"username":"viewer","password":"Viewer-Passw0rd-1","role":"readonly"}'
[ "$NL_CODE" = 201 ] || nl_fail "create viewer: $NL_CODE"
nl_api POST /system/users '{"username":"weak","password":"changeme","role":"readonly"}'
[ "$NL_CODE" = 400 ] || nl_fail "weak password accepted: $NL_CODE"
ROWS=$(sqlite3 "$DB" "SELECT username||':'||role FROM web_users ORDER BY id")
[ "$ROWS" = "$(printf 'admin:admin\nops:operator\nviewer:readonly')" ] || nl_fail "store rows: $ROWS"
grep -q argon2 <<<"$(sqlite3 "$DB" "SELECT password_hash FROM web_users WHERE username='ops'")" || nl_fail "password not hashed"
nl_ok "accounts stored in web_users (argon2 hashes), weak password refused"
nl_web_stop; nl_web_start "$DB"
login_as viewer Viewer-Passw0rd-1
[ "$NL_CODE" = 200 ] || nl_fail "viewer login after restart: $NL_CODE"
nl_api POST /firewall/rules '{"name":"x","chain":"input","action":"accept","interface":"@lan","protocol":"tcp","source":"any","destination":"any","port":"2222","description":"x","enabled":true}'
[ "$NL_CODE" = 403 ] || nl_fail "read-only account changed the firewall: $NL_CODE"
login_as ops Ops-Passw0rd-123
[ "$NL_CODE" = 200 ] || nl_fail "ops login: $NL_CODE"
nl_api POST /system/users '{"username":"evil","password":"Evil-Passw0rd-123","role":"admin"}'
[ "$NL_CODE" = 403 ] || nl_fail "operator created an account: $NL_CODE"
nl_api POST /system/backups
[ "$NL_CODE" = 403 ] || nl_fail "operator created a backup: $NL_CODE"
nl_ok "accounts survive a restart; read-only cannot change config, operator cannot manage accounts/backups"

echo "=== 2. backup -> change -> restore"
nl_login
nl_api POST /system/backups
[ "$NL_CODE" = 201 ] || nl_fail "create backup: $NL_CODE $(cat "$NL_OUT")"
BK=$(json 'd["name"]')
[ "$(stat -c %a "/t/backups/$BK")" = 600 ] || nl_fail "backup file mode $(stat -c %a "/t/backups/$BK")"
nl_web GET "/api/system/backups/$BK"
[ "$NL_CODE" = 200 ] || nl_fail "download: $NL_CODE"
cp "$NL_OUT" /t/downloaded-backup.json
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert {r["username"] for r in d["tables"]["web_users"]} == {"admin","ops","viewer"}' /t/downloaded-backup.json \
  || nl_fail "downloaded backup lacks the accounts"
nl_ok "backup $BK (0600) downloaded: $(wc -c </t/downloaded-backup.json) bytes with the accounts"
nl_expect_http "before the change: blocked.example.test reachable" http://blocked.example.test/ "sees"
nl_api POST /firewall/rules '{"name":"after-backup","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"after-backup","enabled":true}'
[ "$NL_CODE" = 201 ] || nl_fail "add rule: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /system/users '{"username":"temp","password":"Temp-Passw0rd-123","role":"operator"}'
nl_assert_nft_has after-backup
nl_expect_http_blocked "after the change: blocked.example.test blocked" http://blocked.example.test/

nl_api POST "/system/backups/$BK/restore"
[ "$NL_CODE" = 200 ] || nl_fail "restore stored backup: $NL_CODE $(cat "$NL_OUT")"
nl_assert_nft_lacks after-backup
nl_expect_http "after restoring $BK: blocked.example.test reachable again" http://blocked.example.test/ "sees"
[ -z "$(sqlite3 "$DB" "SELECT 1 FROM web_users WHERE username='temp'")" ] || nl_fail "restore kept the later account"
sqlite3 "$DB" "SELECT summary FROM config_revisions" | grep -q "before restore of $BK" || nl_fail "no revision before the restore"
nl_ok "stored backup restored: rule gone from nftables, later account gone, previous config kept as a revision"

# break it again, then restore by uploading the downloaded file
nl_api POST /firewall/rules '{"name":"after-backup-2","chain":"forward","action":"drop","interface":"@lan","protocol":"tcp","source":"any","destination":"198.51.100.20","port":"80","description":"after-backup-2","enabled":true}'
nl_assert_nft_has after-backup-2
NL_CODE=$(C curl -sk -b "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' -X POST \
  -H 'content-type: application/json' --data-binary @/t/downloaded-backup.json "$NL_UI/api/system/restore")
[ "$NL_CODE" = 200 ] || nl_fail "upload restore: $NL_CODE $(cat "$NL_OUT")"
UP=$(json 'd["restored"]')
[ -f "/t/backups/$UP" ] || nl_fail "uploaded file not kept as $UP"
nl_assert_nft_lacks after-backup-2
nl_expect_http "after the upload restore: reachable again" http://blocked.example.test/ "sees"
NL_CODE=$(C curl -sk -b "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' -X POST \
  -H 'content-type: application/json' --data-binary '{"tables":{"no_such_table":[]}}' "$NL_UI/api/system/restore")
[ "$NL_CODE" = 400 ] || nl_fail "junk upload: $NL_CODE"
nl_ok "uploaded backup restored (kept as $UP); junk refused with 400"
nl_web_stop
nl_boot "$DB"
nl_assert_nft_lacks after-backup
nl_expect_http "after reboot: restored config in force" http://blocked.example.test/ "sees"

echo "=== 3. two-factor login (TOTP)"
nl_web_start "$DB"; nl_login
nl_api POST /auth/2fa/setup "{\"password\":\"$NL_PASS\"}"
[ "$NL_CODE" = 200 ] || nl_fail "2fa setup: $NL_CODE $(cat "$NL_OUT")"
SECRET=$(json 'd["secret"]')
URI=$(json 'd["otpauth_uri"]')
[[ "$URI" == otpauth://totp/Patronus:admin\?secret=* ]] || nl_fail "otpauth uri: $URI"
nl_api POST /auth/2fa/enable "{\"code\":\"$(totp "$SECRET" 0)\"}"
[ "$NL_CODE" = 200 ] || nl_fail "2fa enable: $NL_CODE $(cat "$NL_OUT")"
RECOVERY=$(json 'd["recovery_codes"][0]')
[ -n "$(sqlite3 "$DB" "SELECT totp_secret FROM web_users WHERE username='admin'")" ] || nl_fail "secret not stored"
login_as admin "$NL_PASS"
[ "$NL_CODE" = 401 ] && grep -q '"totp_required":true' "$NL_OUT" || nl_fail "password alone: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /status
[ "$NL_CODE" = 401 ] || nl_fail "got a session without the code"
login_as admin "$NL_PASS" 000000x
[ "$NL_CODE" = 401 ] || nl_fail "junk code: $NL_CODE"
CODE=$(totp "$SECRET" 1)
login_as admin "$NL_PASS" "$CODE"
[ "$NL_CODE" = 200 ] || nl_fail "password + code: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /status
[ "$NL_CODE" = 200 ] || nl_fail "session after 2FA login: $NL_CODE"
login_as admin "$NL_PASS" "$CODE"
[ "$NL_CODE" = 401 ] || nl_fail "a TOTP code was accepted twice"
login_as admin "$NL_PASS" "$RECOVERY"
[ "$NL_CODE" = 200 ] || nl_fail "recovery code: $NL_CODE"
login_as admin "$NL_PASS" "$RECOVERY"
[ "$NL_CODE" = 401 ] || nl_fail "a recovery code was accepted twice"
nl_ok "after enrolment: password alone refused, password + TOTP code ok, codes and recovery codes work once"
nl_web_stop
nl_boot "$DB"
nl_web_start "$DB"
login_as admin "$NL_PASS"
[ "$NL_CODE" = 401 ] || nl_fail "after reboot 2FA is off: $NL_CODE"
# codes are accepted once and only newer than the last one: like a user,
# wait for the app to show a fresh code if the last one was just used
LAST=$(sqlite3 "$DB" "SELECT totp_last_step FROM web_users WHERE username='admin'")
while [ $(( $(date +%s) / 30 + 1 )) -le "$LAST" ]; do sleep 1; done
login_as admin "$NL_PASS" "$(totp "$SECRET" 1)"
[ "$NL_CODE" = 200 ] || nl_fail "after reboot password + code: $NL_CODE"
nl_ok "two-factor login survives a reboot"
OUT=$(R "$P" --db "$DB" users reset-2fa admin 2>&1) || nl_fail "users reset-2fa: $OUT"
login_as admin "$NL_PASS"
[ "$NL_CODE" = 200 ] || nl_fail "after reset-2fa: $NL_CODE"
nl_ok "patronus users reset-2fa admin (lost phone) -> password login again"
LIST=$(R "$P" --db "$DB" users list 2>&1)
grep -q "ops" <<<"$LIST" && grep -q "viewer" <<<"$LIST" || nl_fail "users list: $LIST"
nl_web_stop
nl_down
