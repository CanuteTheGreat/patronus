#!/usr/bin/env bash
# Lane N: signed plugins in the shipped binaries. A plugin is made and signed
# with `patronus plugin` (real ed25519), installed from the Packages API:
# nothing installs without a trusted key, a tampered or foreign-signed bundle
# is refused, the plugin's service runs and is reachable from the LAN only
# through the port its manifest exposes (firewall rule), an update replaces
# the running version, a downgrade is refused, disabling/revoking the key
# stops it and closes the port, it survives a reboot (`patronus apply`), and
# a file changed on disk keeps it from starting.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-plugins.db
rm -f "$DB" "$NL_T/nl-jar"
W=$NL_T/plug; rm -rf "$W"; mkdir -p "$W"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

# --- make a plugin: an HTTP service that answers "hello <version>"
mk() { # version -> $W/src (plugin dir)
  rm -rf "$W/src"; mkdir -p "$W/src/files/bin"
  cat >"$W/src/plugin.json" <<JSON
{"name":"hello","version":"$1","description":"netlab plugin","author":"netlab",
 "service":{"exec":["bin/serve","18080"],"port":18080,"proto":"tcp","expose":"lan"}}
JSON
  cat >"$W/src/files/bin/serve" <<PY
#!/usr/bin/env python3
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"hello $1\n"
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
PY
  chmod 755 "$W/src/files/bin/serve"
}
"$P" plugin keygen --out "$W/good" >/dev/null
"$P" plugin keygen --out "$W/evil" >/dev/null
GOOD_PUB=$(cat "$W/good.pub")
mk 1.0.0; "$P" plugin pack "$W/src" --key "$W/good.key" --out "$W/v1.pplug" >/dev/null
mk 1.1.0; "$P" plugin pack "$W/src" --key "$W/good.key" --out "$W/v11.pplug" >/dev/null
mk 9.9.9; "$P" plugin pack "$W/src" --key "$W/evil.key" --out "$W/evil.pplug" >/dev/null
"$P" plugin verify "$W/v1.pplug" --pub "$W/good.pub" >/dev/null || nl_fail "patronus plugin verify rejects its own bundle"
! "$P" plugin verify "$W/v1.pplug" --pub "$W/evil.pub" >/dev/null 2>&1 || nl_fail "verify accepted the wrong key"
nl_ok "bundles made and signed with patronus plugin (v1.0.0, v1.1.0; a third signed by an untrusted key)"

hello() { C curl -s -m 3 "http://$NL_RTR_LAN:18080/" 2>/dev/null || true; }
inst() { nl_api POST /packages/plugins "$(cat "$1")"; }

inst "$W/v1.pplug"
[ "$NL_CODE" = 400 ] && grep -q "not trusted" "$NL_OUT" || nl_fail "install without a trusted key: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /packages/keys "{\"label\":\"netlab\",\"public_key\":\"$GOOD_PUB\"}"
[ "$NL_CODE" = 201 ] || nl_fail "trust key: $NL_CODE $(cat "$NL_OUT")"
inst "$W/evil.pplug"
[ "$NL_CODE" = 400 ] || nl_fail "a bundle signed by an untrusted key must be refused, got $NL_CODE"
sed 's/netlab plugin/netlab plugim/' "$W/v1.pplug" > "$W/tampered.pplug"
inst "$W/tampered.pplug"
[ "$NL_CODE" = 400 ] && grep -qi "signature" "$NL_OUT" || nl_fail "a tampered bundle must be refused: $NL_CODE $(cat "$NL_OUT")"
nl_ok "no key, untrusted key and tampered bundle are all refused"

inst "$W/v1.pplug"
[ "$NL_CODE" = 201 ] || nl_fail "install v1: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 bash -c '[ "$(ip netns exec nl-client curl -s -m 2 http://192.168.50.1:18080/)" = "hello 1.0.0" ]' || { R ss -ltnp; nl_fail "the plugin does not answer from the LAN"; }
nl_assert_nft_has "tcp dport 18080"
nl_ok "plugin hello 1.0.0 runs under the supervisor, LAN reaches it through its exposed port"
[ "$(R sh -c 'ps -eo stat=,args= | grep -c "[b]in/serve 18080"')" -ge 1 ] || nl_fail "no service process"
nl_api GET /packages; [ "$(jget '[p["trust"] for p in d["plugins"]][0]')" = verified ] || nl_fail "list: $(cat "$NL_OUT")"

inst "$W/v1.pplug"; [ "$NL_CODE" = 400 ] || nl_fail "same version again must be refused, got $NL_CODE"
inst "$W/v11.pplug"; [ "$NL_CODE" = 201 ] || nl_fail "update: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 bash -c '[ "$(ip netns exec nl-client curl -s -m 2 http://192.168.50.1:18080/)" = "hello 1.1.0" ]' || nl_fail "the update is not what runs"
inst "$W/v1.pplug"; [ "$NL_CODE" = 400 ] || nl_fail "downgrade must be refused, got $NL_CODE"
nl_ok "update to 1.1.0 replaced the running service; same version and downgrade are refused"

nl_api PUT /packages/plugins/hello '{"enabled":false}'; [ "$NL_CODE" = 200 ] || nl_fail "disable $NL_CODE"
nl_wait 20 bash -c '[ -z "$(ip netns exec nl-client curl -s -m 2 http://192.168.50.1:18080/)" ]' || nl_fail "still answering after disable"
nl_assert_nft_lacks "tcp dport 18080"
nl_api PUT /packages/plugins/hello '{"enabled":true}'; [ "$NL_CODE" = 200 ] || nl_fail "enable $NL_CODE"
nl_wait 20 bash -c '[ "$(ip netns exec nl-client curl -s -m 2 http://192.168.50.1:18080/)" = "hello 1.1.0" ]' || nl_fail "does not come back after enable"
nl_ok "disabled: stopped and the port closed; enabled: back"

echo "=== reboot (power cut: every process goes, the store stays)"
nl_web_stop
pkill -f "bin/serve 18080" || true
rm -f /run/patronus/*plugin-hello*
nl_boot "$DB"
nl_wait 20 bash -c '[ "$(ip netns exec nl-client curl -s -m 2 http://192.168.50.1:18080/)" = "hello 1.1.0" ]' || nl_fail "plugin not running after reboot"
nl_ok "after reboot (patronus apply) the plugin is running again"

echo "=== a file changed on disk keeps it from starting"
pkill -f "bin/serve 18080" || true
DIR=$(find /var/lib/patronus/net/plugins/hello -maxdepth 1 -mindepth 1 -type d | head -1)
echo "# tampered" >> "$DIR/bin/serve"
nl_apply "$DB" || true
sleep 2
[ -z "$(hello)" ] || nl_fail "a modified plugin file still runs"
grep -q "changed on disk" "$NL_OUT" || { cat "$NL_OUT"; nl_fail "apply did not say why the plugin was not started"; }
nl_ok "digest check at apply: a modified file stops the plugin ($(grep -o 'plugin hello not started: [^\"]*' "$NL_OUT" | head -1))"
sed -i '$d' "$DIR/bin/serve"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "apply after restoring the file"; }
nl_wait 20 bash -c '[ "$(ip netns exec nl-client curl -s -m 2 http://192.168.50.1:18080/)" = "hello 1.1.0" ]' || nl_fail "plugin does not start again once the file is restored"
nl_web_start "$DB"; nl_login
echo "=== revoke the key"
KID=$(sqlite3 "$DB" "SELECT key_id FROM plugin_keys LIMIT 1")
nl_api DELETE /packages/keys/$KID; [ "$NL_CODE" = 200 ] || nl_fail "revoke $NL_CODE"
nl_api GET /packages; [ "$(jget '[p["running"] for p in d["plugins"]][0]')" = False ] || nl_fail "plugin still running without a trusted key"
nl_assert_nft_lacks "tcp dport 18080"
nl_ok "revoking the key stops its plugin and closes its port"

nl_api POST /packages/keys "{\"label\":\"netlab\",\"public_key\":\"$GOOD_PUB\"}"; [ "$NL_CODE" = 201 ] || nl_fail "re-trust $NL_CODE"
nl_api DELETE /packages/plugins/hello; [ "$NL_CODE" = 200 ] || nl_fail "remove $NL_CODE"
[ ! -e /var/lib/patronus/net/plugins/hello ] || nl_fail "plugin files remain"
[ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM plugins")" = 0 ] || nl_fail "plugin row remains"
nl_ok "removed: files and store row gone"
echo "PASS lane-n-plugins"
