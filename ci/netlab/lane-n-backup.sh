#!/usr/bin/env bash
# Lane N: remote + encrypted automatic backup in the shipped binary. A WebDAV
# style PUT server on the "internet" host receives the configuration: on
# demand ("back up now") and on its own schedule; with a passphrase the file
# is encrypted (no readable config on the server), restores only with the
# right passphrase, and the credentials are never returned by the API.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-backup.db
DAV=/tmp/dav; rm -rf "$DAV"; mkdir -p "$DAV"
rm -f "$DB" "$NL_T/nl-jar"
cat >"$NL_T/nl-put.py" <<'PY'
import http.server, sys, os, base64
D = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):
        if self.headers.get("Authorization") != "Basic " + base64.b64encode(b"backup:s3cret").decode():
            self.send_response(401); self.end_headers(); return
        n = int(self.headers.get("Content-Length", 0))
        open(os.path.join(D, os.path.basename(self.path)), "wb").write(self.rfile.read(n))
        self.send_response(201); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8081), H).serve_forever()
PY
nl_write_installer_toml
nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-put.py" "$DAV"
sleep 1
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api POST /system/backup-targets '{"name":"bad","url":"file:///etc"}'
[ "$NL_CODE" = 400 ] || nl_fail "file:// target must be refused: $NL_CODE"

echo "=== encrypted target, run now"
nl_api POST /system/backup-targets "{\"name\":\"offsite\",\"url\":\"http://$NL_WWW:8081/dav\",\"username\":\"backup\",\"password\":\"s3cret\",\"passphrase\":\"correct horse battery\",\"interval_hours\":0}"
[ "$NL_CODE" = 201 ] || nl_fail "create target: $NL_CODE $(cat "$NL_OUT")"; TID=$(jget 'd["id"]')
nl_api POST /system/backup-targets/$TID/run
[ "$NL_CODE" = 200 ] || nl_fail "run: $NL_CODE $(cat "$NL_OUT")"; F=$(jget 'd["file"]')
case "$F" in *.json.enc) ;; *) nl_fail "file name $F";; esac
[ -s "$DAV/$F" ] || nl_fail "nothing arrived on the server"
head -c4 "$DAV/$F" | grep -q PBK1 || nl_fail "not an encrypted backup"
! grep -aq 'web_users\|tables' "$DAV/$F" || nl_fail "readable configuration on the remote server"
nl_ok "encrypted backup $F arrived on the remote server and holds no readable configuration"
nl_api GET /system/backup-targets
! grep -q 's3cret\|correct horse' "$NL_OUT" || nl_fail "the API returned a credential"
[ "$(jget 'd[0]["last_status"]')" = ok ] || nl_fail "status not recorded"
nl_ok "API shows last status and never returns credentials"

echo "=== restore needs the passphrase"
CODE() { C curl -sk -b "$NL_T/nl-jar" -o "$NL_OUT" -w '%{http_code}' -X POST "$@" "$NL_UI/api/system/restore"; }
cp "$DAV/$F" "$NL_T/up.enc"
[ "$(CODE --data-binary @"$NL_T/up.enc")" = 400 ] || nl_fail "restore without passphrase should be 400"
[ "$(CODE -H 'X-Backup-Passphrase: wrong wrong wrong' --data-binary @"$NL_T/up.enc")" = 400 ] || nl_fail "wrong passphrase should be 400"
c=$(CODE -H 'X-Backup-Passphrase: correct horse battery' --data-binary @"$NL_T/up.enc"); [ "$c" = 200 ] || nl_fail "restore with passphrase: $c $(cat "$NL_OUT")"
nl_ok "restore: refused without/with a wrong passphrase, accepted with the right one"

echo "=== scheduled upload, unattended"
nl_login
nl_api POST /system/backup-targets "{\"name\":\"nightly\",\"url\":\"http://$NL_WWW:8081/dav\",\"username\":\"backup\",\"password\":\"s3cret\",\"interval_hours\":24}"
[ "$NL_CODE" = 201 ] || nl_fail "create nightly: $NL_CODE"
nl_wait 150 sh -c "ls $DAV/*.json >/dev/null 2>&1" || nl_fail "scheduled upload of a plain backup"
grep -q '"tables"' "$DAV"/*.json || nl_fail "plain backup is not a configuration export"
nl_ok "the scheduler uploaded a plain backup by itself"
echo "PASS lane-n-backup"
