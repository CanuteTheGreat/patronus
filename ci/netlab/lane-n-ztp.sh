#!/usr/bin/env bash
# Lane N: zero-touch provisioning in the shipped binary. A "golden" box makes
# a configuration (a firewall rule) and exports it (plain, and sealed with a
# passphrase) to a provisioning server on the "internet" host. A second, blank
# box whose patronus.toml only says [provisioning] url=... runs `patronus ztp`:
# it fetches, decrypts, imports and applies the bundle, so the rule is in its
# nftables; it runs once (marker), and a wrong/missing passphrase changes nothing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

GOLD=/t/lane-n-ztp-gold.db; BLANK=/t/lane-n-ztp-blank.db; SRV=/tmp/ztp-srv
rm -f "$GOLD" "$BLANK" "$NL_T/nl-jar"; rm -rf "$SRV"; mkdir -p "$SRV"
command -v curl >/dev/null || { apt-get update -qq >/dev/null; apt-get install -y -qq curl >/dev/null; }

nl_write_installer_toml
nl_boot "$GOLD"
nl_web_start "$GOLD"; nl_login
nl_api POST /firewall/rules '{"name":"ztp-block-9000","chain":"forward","action":"reject","interface":"@lan","protocol":"tcp","source":"any","destination":"'$NL_WWW'","port":"9000","description":"ztp-block-9000","enabled":true}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "golden rule: $NL_CODE $(cat "$NL_OUT")"
nl_web_stop
R "$P" --db "$GOLD" config export -o "$SRV/site.json" >/dev/null 2>&1 || nl_fail "export"
cat >"$NL_T/nl-ztp-srv.py" <<'PY'
import http.server, sys, os
os.chdir(sys.argv[1])
http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler, port=8082, bind="0.0.0.0")
PY
nl_bg INET python3 "$NL_T/nl-ztp-srv.py" "$SRV"
sleep 1

echo "=== a blank box provisions itself"
nl_boot "$BLANK"       # fresh namespaces, default ruleset only
nl_assert_nft_lacks ztp-block-9000
cat >>"$NL_TOML" <<EOT

[provisioning]
url = "http://$NL_WWW:8082/site.json"
wait_secs = 30
EOT
out=$(R "$P" --db "$BLANK" ztp 2>&1) || { echo "$out"; nl_fail "patronus ztp failed"; }
grep -q "provisioned from" <<<"$out" || nl_fail "no success line: $out"
nl_assert_nft_has "ztp-block-9000"
nl_ok "the blank box fetched the bundle, imported and applied it (rule is in nftables)"
[ -n "$(sqlite3 "$BLANK" "SELECT value FROM lan_settings WHERE key='ztp.done'")" ] || nl_fail "no marker in the store"
out=$(R "$P" --db "$BLANK" ztp 2>&1) || nl_fail "second run failed"
grep -q "already provisioned" <<<"$out" || nl_fail "second run did not skip: $out"
nl_ok "second run is a no-op (marker)"

echo "=== a reboot keeps it (from the store)"
nl_boot "$BLANK"
nl_assert_nft_has "ztp-block-9000"
nl_ok "after reboot the provisioned rule is applied from the store"

echo "=== an unreachable or bad bundle changes nothing"
rm -f "$NL_T/nl-jar"
BLANK2=/t/lane-n-ztp-blank2.db; rm -f $BLANK2
nl_boot "$BLANK2"
sed -i 's#site.json#missing.json#' "$NL_TOML"
if R "$P" --db "$BLANK2" ztp >"$NL_OUT" 2>&1; then nl_fail "a 404 bundle should fail"; fi
nl_assert_nft_lacks ztp-block-9000
[ -z "$(sqlite3 "$BLANK2" "SELECT value FROM lan_settings WHERE key='ztp.done'" 2>/dev/null)" ] || nl_fail "marker set after a failed run"
nl_ok "404: fails, no marker, firewall untouched"
echo "PASS lane-n-ztp"
