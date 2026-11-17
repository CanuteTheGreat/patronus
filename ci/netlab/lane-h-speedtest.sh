#!/usr/bin/env bash
# Lane H: internet speed test from the router, against a lab test server on
# the internet side, with the ISP link shaped to known rates (tc tbf on the
# ISP namespace: 20 Mbit/s towards the router, 8 Mbit/s towards the internet).
# Proves:
#   - a manual test measures latency, download (~20 Mbit/s) and upload
#     (~8 Mbit/s) and stores the result in the history;
#   - a second test while one runs is refused (409); bad settings are 400;
#   - an unreachable server gives a stored failed result, not a hang;
#   - an interval runs the test on its own (trigger "schedule").
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-speedtest.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
j() { nl_json "$NL_OUT" "$1"; }

cat > "$NL_T/nl-speed.py" <<'PY'
import http.server, socketserver, sys, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        n = int(q.get('bytes', ['0'])[0])
        self.send_response(200); self.send_header('Content-Length', str(n)); self.end_headers()
        chunk = b'\0' * 65536
        while n > 0:
            k = min(n, len(chunk)); self.wfile.write(chunk[:k]); n -= k
    def do_POST(self):
        n = int(self.headers.get('content-length', 0)); got = 0
        while got < n:
            b = self.rfile.read(min(65536, n - got))
            if not b: break
            got += len(b)
        body = str(got).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
S(('0.0.0.0', 8088), H).serve_forever()
PY

nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-speed.py"
for _ in $(seq 1 40); do INET bash -c "exec 3<>/dev/tcp/$NL_WWW/8088" 2>/dev/null && break; sleep 0.25; done
ISP tc qdisc replace dev up0 root tbf rate 20mbit burst 64kb latency 400ms
ISP tc qdisc replace dev down0 root tbf rate 8mbit burst 32kb latency 400ms
nl_web_start "$DB"; nl_login

echo "=== settings"
for bad in '{"down_url":"ftp://x/y"}' '{"up_url":"https://a b/"}' '{"bytes_down":10}' '{"interval_hours":500}'; do
  nl_api PUT /system/speedtest/settings "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "bad speed test setting accepted ($NL_CODE): $bad"
done
nl_ok "bad URLs, sizes and intervals refused (400)"
nl_api_ok "point at the lab server" PUT /system/speedtest/settings "{\"down_url\":\"http://$NL_WWW:8088/down?bytes={bytes}\",\"up_url\":\"http://$NL_WWW:8088/up\",\"bytes_down\":12000000,\"bytes_up\":5000000}"

echo "=== manual test"
( nl_api POST /system/speedtest; cp "$NL_OUT" "$NL_T/st-first.json"; echo "$NL_CODE" > "$NL_T/st-first.code" ) &
BG=$!
sleep 1
nl_api POST /system/speedtest
[ "$NL_CODE" = 409 ] || nl_fail "a second test while one runs: want 409, got $NL_CODE $(cat "$NL_OUT")"
nl_ok "a second test while one runs is refused (409)"
wait $BG
[ "$(cat "$NL_T/st-first.code")" = 200 ] || nl_fail "speed test: $(cat "$NL_T/st-first.code") $(cat "$NL_T/st-first.json")"
python3 - "$NL_T/st-first.json" <<'PY' || nl_fail "speed test result out of range: $(cat "$NL_T/st-first.json")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r['ok'], r
d, u, l = r['down_bps'] / 1e6, r['up_bps'] / 1e6, r['latency_ms']
print('down %.1f Mbit/s, up %.1f Mbit/s, latency %s ms' % (d, u, l))
assert 14 <= d <= 22, d
assert 5.5 <= u <= 9, u
assert 0 < l < 200, l
PY
nl_ok "manual test: $(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print("down %.1f / up %.1f Mbit/s, %s ms" % (r["down_bps"]/1e6, r["up_bps"]/1e6, r["latency_ms"]))' "$NL_T/st-first.json") (link shaped to 20 / 8)"
nl_api GET /system/speedtest
[ "$(j 'len(d["results"])')" = 1 ] && [ "$(j 'd["results"][0]["trigger"]')" = manual ] || nl_fail "history: $(cat "$NL_OUT")"
nl_ok "the result is in the history"

echo "=== unreachable server"
nl_api_ok "dead server" PUT /system/speedtest/settings "{\"down_url\":\"http://$NL_WWW:8099/down?bytes={bytes}\",\"up_url\":\"\"}"
nl_api POST /system/speedtest
[ "$NL_CODE" = 200 ] && [ "$(j 'd["ok"]')" = False ] && [ "$(j 'd["up_bps"]')" = None ] || nl_fail "dead server: $NL_CODE $(cat "$NL_OUT")"
case "$(j 'd["error"]')" in *download*) ;; *) nl_fail "no download error recorded: $(cat "$NL_OUT")" ;; esac
nl_ok "unreachable server: failed result stored with the reason; empty upload URL skips the upload"

echo "=== schedule"
nl_api_ok "every hour" PUT /system/speedtest/settings "{\"down_url\":\"http://$NL_WWW:8088/down?bytes={bytes}\",\"up_url\":\"http://$NL_WWW:8088/up\",\"bytes_down\":2000000,\"bytes_up\":1000000,\"interval_hours\":1}"
# the last run is a few seconds old: make it look two hours old
sqlite3 "$DB" "UPDATE speedtests SET ts = ts - 7200"
scheduled() { nl_api GET /system/speedtest; [ "$(j 'd["results"][0]["trigger"]')" = schedule ]; }
nl_wait 120 scheduled || nl_fail "no scheduled test within 2 minutes: $(cat "$NL_OUT")"
[ "$(j 'd["results"][0]["ok"]')" = True ] || nl_fail "scheduled test failed: $(cat "$NL_OUT")"
nl_ok "interval: the scheduler ran a test on its own"
nl_api_ok "schedule off" PUT /system/speedtest/settings '{"interval_hours":0}'

ISP tc qdisc del dev up0 root 2>/dev/null || true
ISP tc qdisc del dev down0 root 2>/dev/null || true
nl_web_stop
nl_down
echo "PASS lane-h-speedtest"
