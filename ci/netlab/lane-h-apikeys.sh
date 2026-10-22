#!/usr/bin/env bash
# Lane H: API keys + monitoring hooks, proven against the real binaries.
#
#  - a read-only API key (what a Rustinion collector uses) reads
#    /api/status/summary and /metrics from the LAN, cannot change anything,
#    cannot reach accounts or key management; the token is not in the
#    store (only its digest); revoking it takes effect at once;
#  - gateway events: a gateway monitor target that stops answering ping
#    produces `gateway_down` in /api/events and a signed POST to the
#    webhook on the "internet" host; answering again gives `gateway_up`.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-apikeys.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login

jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
# kreq TOKEN METHOD PATH [JSON]: like nl_web but with an API key, no cookie
kreq() {
  local tok=$1 m=$2 p=$3; shift 3
  local data=(); [ $# -ge 1 ] && data=(-d "$1")
  NL_CODE=$(C curl -sk -o "$NL_OUT" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $tok" \
    -H 'content-type: application/json' "${data[@]}" "$NL_UI$p")
}

echo "=== a read-only key for a collector"
nl_api POST /system/api-keys '{"name":"rustinion","scope":"readonly"}'
[ "$NL_CODE" = 201 ] || nl_fail "create key: $NL_CODE $(cat "$NL_OUT")"
TOK=$(jget 'd["token"]'); KEY_ID=$(jget 'd["key"]["id"]')
case "$TOK" in pat_*) ;; *) nl_fail "token shape: $TOK";; esac
STORED=$(sqlite3 "$DB" "SELECT token_hash FROM api_keys WHERE id=$KEY_ID")
[ -n "$STORED" ] && ! grep -qF "$TOK" <(sqlite3 "$DB" .dump) || nl_fail "the token itself is in the store"
nl_ok "key created (token shown once, only its SHA-256 digest is in the store)"

kreq "$TOK" GET /api/status/summary
[ "$NL_CODE" = 200 ] || nl_fail "summary with the key: $NL_CODE $(cat "$NL_OUT")"
[ "$(jget 'd["product"]')" = patronus ] && [ -n "$(jget 'd["version"]')" ] || nl_fail "summary content: $(cat "$NL_OUT")"
kreq "$TOK" GET /metrics
[ "$NL_CODE" = 200 ] && grep -q '^patronus_uptime_seconds ' "$NL_OUT" && grep -q '^patronus_info{' "$NL_OUT" \
  || nl_fail "metrics: $NL_CODE $(head -5 "$NL_OUT")"
nl_ok "read-only key: /api/status/summary and /metrics (Prometheus text) from the LAN"

kreq "$TOK" POST /api/firewall/rules '{"name":"k","action":"accept","interface":"any","protocol":"tcp","source":"any","destination":"any","port":"9","description":"","enabled":true,"chain":"input"}'
[ "$NL_CODE" = 403 ] || nl_fail "a read-only key changed the firewall: $NL_CODE"
for p in /api/system/users /api/system/api-keys /api/system/backups; do
  kreq "$TOK" GET "$p"
  [ "$NL_CODE" = 403 ] || nl_fail "read-only key reached $p: $NL_CODE"
done
kreq "$TOK" POST /api/system/reboot
[ "$NL_CODE" = 403 ] || nl_fail "a read-only key may not reboot: $NL_CODE"
kreq pat_wrong GET /api/status/summary
[ "$NL_CODE" = 401 ] || nl_fail "bad key: $NL_CODE"
nl_ok "the key cannot write, reach accounts/keys/backups or reboot; a wrong key is 401"

nl_api DELETE "/system/api-keys/$KEY_ID"
[ "$NL_CODE" = 200 ] || nl_fail "revoke: $NL_CODE"
kreq "$TOK" GET /api/status/summary
[ "$NL_CODE" = 401 ] || nl_fail "a revoked key still works: $NL_CODE"
nl_ok "revoking the key takes effect at once"

echo "=== gateway events + signed webhook"
cat > "$NL_T/hook.py" <<'PY'
import http.server, json, sys
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0))).decode()
        with open(LOG, 'a') as f:
            f.write(json.dumps({'sig': self.headers.get('X-Patronus-Signature'),
                                'event': self.headers.get('X-Patronus-Event'), 'body': body}) + '\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
http.server.HTTPServer((sys.argv[2], 9100), H).serve_forever()
PY
rm -f "$NL_T/hook.log"; : > "$NL_T/hook.log"
nl_bg INET python3 "$NL_T/hook.py" "$NL_T/hook.log" 0.0.0.0
for _ in $(seq 1 40); do INET sh -c "exec 3<>/dev/tcp/$NL_WWW/9100" 2>/dev/null && break; sleep 0.25; done
nl_api POST /system/hooks "{\"name\":\"rustinion\",\"url\":\"http://$NL_WWW:9100/hook\",\"secret\":\"s3cret-value\",\"kinds\":\"gateway_down, gateway_up\"}"
[ "$NL_CODE" = 201 ] || nl_fail "add webhook: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /routing/gateways "{\"name\":\"WAN_GW\",\"interface\":\"@wan\",\"monitor_ip\":\"$NL_WWW\"}"
[ "$NL_CODE" = 201 ] || nl_fail "add gateway: $NL_CODE $(cat "$NL_OUT")"
gw_state() { nl_api GET /status/summary; jget '[g["state"] for g in d["gateways"] if g["name"]=="WAN_GW"][0]'; }
for _ in $(seq 1 40); do [ "$(gw_state)" = online ] && break; sleep 1; done
[ "$(gw_state)" = online ] || nl_fail "gateway never came online: $(cat "$NL_OUT")"
nl_ok "gateway WAN_GW online (monitor $NL_WWW)"

ISP nft add table ip nl_icmp
ISP nft "add chain ip nl_icmp f { type filter hook forward priority 0; }"
ISP nft "add rule ip nl_icmp f ip daddr $NL_WWW icmp type echo-request drop"
wait_event() { # KIND: poll /api/events up to 60 s
  for _ in $(seq 1 60); do
    nl_api GET "/events?kind=$1"
    [ "$(jget 'len(d)')" -ge 1 ] && return 0
    sleep 1
  done
  nl_fail "no $1 event: $(cat "$NL_OUT")"
}
wait_event gateway_down
[ "$(jget 'd[-1]["subject"]')" = WAN_GW ] && [ "$(jget 'd[-1]["severity"]')" = critical ] || nl_fail "event content: $(cat "$NL_OUT")"
nl_ok "gateway_down event for WAN_GW in /api/events"
for _ in $(seq 1 30); do grep -q gateway_down "$NL_T/hook.log" && break; sleep 1; done
python3 - "$NL_T/hook.log" <<'PY' || nl_fail "webhook delivery/signature"
import hmac, hashlib, json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
d = [l for l in lines if l['event'] == 'gateway_down']
assert d, lines
l = d[0]
want = 'sha256=' + hmac.new(b's3cret-value', l['body'].encode(), hashlib.sha256).hexdigest()
assert l['sig'] == want, (l['sig'], want)
b = json.loads(l['body'])
assert b['kind'] == 'gateway_down' and b['subject'] == 'WAN_GW', b
PY
nl_ok "webhook got the gateway_down POST with a valid HMAC-SHA256 signature"

ISP nft delete table ip nl_icmp
wait_event gateway_up
nl_ok "gateway_up event after the monitor target answers again"
nl_api GET /system/hooks
[ "$(jget 'd[0]["last_result"]')" = ok ] || nl_fail "hook delivery result: $(cat "$NL_OUT")"
grep -q s3cret "$NL_OUT" && nl_fail "the hook secret is in the API answer"
nl_ok "webhook shows last delivery ok; secret never returned"

nl_web_stop
nl_down
