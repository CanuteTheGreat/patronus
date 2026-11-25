#!/usr/bin/env bash
# Lane N: schema-driven settings of signed plugins (crates/patronus-network/src/plugin_settings.rs, gap G of
# docs/design/proxmox-9.3-ideas.md) in the shipped binaries. A plugin is made and signed with `patronus plugin`;
# its manifest carries a `settings` schema. Proven here, against real processes:
#   - the Packages page, driven by ci/plugin-settings-e2e.py (Playwright + Firefox, 1280/390, light/dark): form
#     drawn from the schema, hints on hover and focus, an invalid value refused, a valid one saved and delivered
#     to the plugin's own 0600 file and service, the secret never sent back to the browser;
#   - a required setting without a value keeps the service from starting (fail closed), and a service already
#     running is stopped when that value is removed;
#   - the API refuses out-of-range values, unknown keys and a bad GitOps document, and masks secrets;
#   - an update whose schema narrows a limit drops the stored value that no longer fits (default again);
#   - the values survive a reboot (`patronus apply`), and removing the plugin removes values and files.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-plugin-settings.db
rm -f "$DB" "$NL_T/nl-jar"
W=$NL_T/plugset; rm -rf "$W"; mkdir -p "$W"
PW=/opt/pw
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/plugin-settings-e2e.py" ] || { echo "SKIP lane-n-plugin-settings: ci/plugin-settings-e2e.py was not copied next to the scenarios"; exit 0; }
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
FILE=/var/lib/patronus/net/plugins/setdemo.settings.json
URL="http://$NL_RTR_LAN:18081/"
served() { C curl -s -m 3 "$URL" 2>/dev/null || true; }
# polling helpers (functions, never `sh -c`: lib.sh helpers are bash functions; and no `| grep -q`)
serves_has() { local o; o=$(served); [[ "$o" == *"$1"* ]]; }
serves_nothing() { [ -z "$(served)" ]; }
jv() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

# --- a plugin whose service serves its own settings file (read on every request)
mk() { # version, interval max
  rm -rf "$W/src"; mkdir -p "$W/src/files/bin"
  cat >"$W/src/plugin.json" <<JSON
{"name":"setdemo","version":"$1","description":"netlab settings demo","author":"netlab",
 "service":{"exec":["bin/serve","18081","{settings}"],"port":18081,"proto":"tcp","expose":"lan"},
 "settings":[
  {"key":"interval","type":"int","label":"Check interval","hint":"Seconds between two checks; shorter means more load.","min":5,"max":$2,"default":60},
  {"key":"name","type":"string","label":"Instance name","hint":"Lowercase letters, digits and dashes.","pattern":"[a-z][a-z0-9-]*","max":20,"default":"demo"},
  {"key":"mode","type":"enum","label":"Mode","hint":"Fast skips the safety checks.","values":["fast","safe"],"default":"safe"},
  {"key":"token","type":"string","label":"API token","hint":"Kept on the router; shown only as 'saved'.","secret":true,"required":true},
  {"key":"debug","type":"bool","label":"Debug logging","hint":"Writes more detail to the plugin log.","default":false},
  {"key":"listen","type":"port","label":"Listen port","hint":"Port the plugin would bind.","min":1024,"default":18081},
  {"key":"hosts","type":"list","item":"address","label":"Allowed hosts","hint":"One IP address per line, at most 4.","max":4},
  {"key":"gateway","type":"address","label":"Gateway","hint":"Optional upstream address."}
 ]}
JSON
  cat >"$W/src/files/bin/serve" <<'PY'
#!/usr/bin/env python3
import http.server, sys
port, path = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = open(path, "rb").read()
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
PY
  chmod 755 "$W/src/files/bin/serve"
}
"$P" plugin keygen --out "$W/good" >/dev/null
mk 1.0.0 3600; "$P" plugin pack "$W/src" --key "$W/good.key" --out "$W/v1.pplug" >/dev/null
mk 1.1.0 50;   "$P" plugin pack "$W/src" --key "$W/good.key" --out "$W/v11.pplug" >/dev/null
# a schema that breaks its own rule is refused at pack time, before anything is signed
sed 's/"min":5,"max":3600/"min":9,"max":3/' "$W/src/plugin.json" > "$W/bad.json"
cp -r "$W/src" "$W/badsrc"; cp "$W/bad.json" "$W/badsrc/plugin.json"
! "$P" plugin pack "$W/badsrc" --key "$W/good.key" --out "$W/bad.pplug" >/dev/null 2>&1 || nl_fail "a schema with min > max was signed"
nl_ok "bundles with a settings schema made and signed (v1.0.0, v1.1.0 with a narrower limit); a broken schema is refused at pack time"

nl_api POST /packages/keys "{\"label\":\"netlab\",\"public_key\":\"$(cat "$W/good.pub")\"}"
[ "$NL_CODE" = 201 ] || nl_fail "trust key: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /packages/plugins "$(cat "$W/v1.pplug")"
[ "$NL_CODE" = 201 ] || nl_fail "install v1: $NL_CODE $(cat "$NL_OUT")"

# --- fail closed: the required token has no value, so the service does not start
sleep 2
[ -z "$(served)" ] || nl_fail "the plugin started although its required setting has no value"
nl_api GET /packages
[ "$(jv '[p["running"] for p in d["plugins"] if p["name"]=="setdemo"][0]')" = False ] || nl_fail "list says running without its required setting"
[ ! -e "$FILE" ] || nl_fail "a settings file exists before any value was saved"
nl_ok "a required setting without a value keeps the service from starting"

# --- the browser: form, hints, refusals, save, secret handling, file and service
out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_WRITE=1 E2E_PLUGIN=setdemo \
      E2E_SETTINGS_FILE="$FILE" E2E_PLUGIN_URL="$URL" E2E_SHOTS="${E2E_SHOTS:-$NL_T/shots}" \
      "$PW/bin/python" "$NL_T/plugin-settings-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the plugin settings page e2e failed (exit $rc)"
nl_ok "Packages page driven in Firefox at 1280/390, light/dark: $(grep -c '^PASS:' <<<"$out") checks"

# --- the API: refusals, masking, clear -> fail closed, restore
nl_api PUT /packages/plugins/setdemo/settings '{"values":{"interval":4}}'
[ "$NL_CODE" = 400 ] && grep -q "between 5 and 3600" "$NL_OUT" || nl_fail "out of range: $NL_CODE $(cat "$NL_OUT")"
nl_api PUT /packages/plugins/setdemo/settings '{"values":{"nosuch":1}}'
[ "$NL_CODE" = 400 ] || nl_fail "unknown key must be refused: $NL_CODE"
nl_api PUT /packages/plugins/setdemo/settings '{"values":{"mode":"turbo"}}'
[ "$NL_CODE" = 400 ] || nl_fail "an enum value outside the list must be refused: $NL_CODE"
nl_api PUT /packages/plugins/nosuch/settings '{"values":{}}'
[ "$NL_CODE" = 404 ] || nl_fail "unknown plugin must be 404: $NL_CODE"
nl_api GET /packages/plugins/setdemo/settings
grep -q "tok-S3CRET" "$NL_OUT" && nl_fail "the API returned the secret"
[ "$(jv '[s["is_set"] for s in d["settings"] if s["key"]=="token"][0]')" = True ] || nl_fail "token should be reported as set"
[ "$(jv '[s["value"] for s in d["settings"] if s["key"]=="token"][0]')" = None ] || nl_fail "token value must be null"
nl_ok "API refuses out-of-range, unknown and bad enum values, 404 for an unknown plugin, and reports a secret only as set"

nl_api PUT /packages/plugins/setdemo/settings '{"clear":["token"]}'
[ "$NL_CODE" = 200 ] || nl_fail "clear token: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 serves_nothing || nl_fail "the service keeps running after its required value was removed"
nl_api PUT /packages/plugins/setdemo/settings '{"values":{"token":"tok-S3CRET-api-1","interval":77}}'
[ "$NL_CODE" = 200 ] || nl_fail "set token: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 serves_has 'tok-S3CRET-api-1' || nl_fail "the service did not come back with the new value"
[ "$(stat -c %a "$FILE")" = 600 ] || nl_fail "settings file mode $(stat -c %a "$FILE")"
nl_ok "removing a required value stops the service; saving it again starts it with the value; file stays 0600"

# --- the config store carries the values, flagged so a diff can hide the secret
[ "$(sqlite3 "$DB" "SELECT secret FROM plugin_settings WHERE setting='token'")" = 1 ] || nl_fail "the stored row is not flagged secret"

# --- update with a narrower limit: the stored 77 no longer fits (max 50) and falls back to the default
nl_api POST /packages/plugins "$(cat "$W/v11.pplug")"
[ "$NL_CODE" = 201 ] || nl_fail "update: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 serves_has '"interval": 60' || { served; nl_fail "the dropped value did not fall back to the default"; }
serves_has 'tok-S3CRET-api-1' || nl_fail "the update lost the secret"
nl_api PUT /packages/plugins/setdemo/settings '{"values":{"interval":51}}'
[ "$NL_CODE" = 400 ] || nl_fail "the new limit must apply: $NL_CODE"
nl_ok "update 1.1.0: a value the narrower schema refuses is dropped (default again), the secret is kept, the new limit applies"

# --- reboot: the store stays, the service gets its file again
nl_web_stop
pkill -f "bin/serve 18081" || true
rm -f /run/patronus/*plugin-setdemo* "$FILE" "${FILE%.json}.env"
nl_boot "$DB"
nl_wait 20 serves_has 'tok-S3CRET-api-1' || nl_fail "after reboot the plugin does not serve its saved settings"
[ "$(stat -c %a "$FILE")" = 600 ] || nl_fail "after reboot the settings file mode is $(stat -c %a "$FILE")"
nl_ok "after reboot (patronus apply) the settings file is written again and the plugin serves it"

# --- remove: values and files go
nl_web_start "$DB"; nl_login
nl_api DELETE /packages/plugins/setdemo; [ "$NL_CODE" = 200 ] || nl_fail "remove $NL_CODE"
[ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM plugin_settings")" = 0 ] || nl_fail "settings rows remain after removal"
[ ! -e "$FILE" ] && [ ! -e "${FILE%.json}.env" ] || nl_fail "settings files remain after removal"
nl_ok "removed: stored values and both settings files are gone"
echo "PASS lane-n-plugin-settings"
