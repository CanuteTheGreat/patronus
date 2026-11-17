#!/usr/bin/env bash
# Lane H: historical statistics and monthly data accounting on the real
# binaries (sampler tick 1 s via PATRONUS_STATS_TICK_SECS). Proves:
#   - a 20 MB download by a LAN client is counted on the router's WAN (in)
#     and LAN (out) interfaces in the current accounting period;
#   - CPU, memory and per-interface throughput history points appear;
#   - a monthly allowance raises one data_cap warning at 80 % and one
#     critical event at 100 %, and no repeats;
#   - the totals survive a restart of the web service; bad settings are 400.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-stats.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
export PATRONUS_STATS_TICK_SECS=1
j() { nl_json "$NL_OUT" "$1"; }

cat > "$NL_T/nl-bytes.py" <<'PY'
import http.server, socketserver, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        n = int(urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('bytes', ['0'])[0])
        self.send_response(200); self.send_header('Content-Length', str(n)); self.end_headers()
        chunk = b'\0' * 65536
        while n > 0:
            k = min(n, len(chunk)); self.wfile.write(chunk[:k]); n -= k
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
S(('0.0.0.0', 8088), H).serve_forever()
PY
fetch() { C curl -s -o /dev/null --max-time 60 "http://$NL_WWW:8088/x?bytes=$1" || nl_fail "LAN download of $1 bytes failed"; }
wan_rx() { nl_api GET /stats/usage; j '[u["rx"] for u in d["periods"][0]["usage"] if u["iface"]=="'"$NL_WAN_IF"'"] or [0]' | tr -d '[]'; }
lan_tx() { nl_api GET /stats/usage; j '[u["tx"] for u in d["periods"][0]["usage"] if u["iface"]=="'"$NL_LAN_IF"'"] or [0]' | tr -d '[]'; }

nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-bytes.py"
for _ in $(seq 1 40); do INET bash -c "exec 3<>/dev/tcp/$NL_WWW/8088" 2>/dev/null && break; sleep 0.25; done
nl_web_start "$DB"; nl_login

echo "=== settings"
for bad in '{"month_start_day":31}' '{"cap_gb":-1}' '{"cap_interface":"eth0; rm"}' '{"retention_days":0}'; do
  nl_api PUT /stats/settings "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "bad stats setting accepted ($NL_CODE): $bad"
done
nl_ok "bad month day, cap, interface and retention refused (400)"

echo "=== accounting"
sleep 3   # the sampler has a baseline
B_WAN=$(wan_rx); B_LAN=$(lan_tx)
fetch 20000000
sleep 3
A_WAN=$(wan_rx); A_LAN=$(lan_tx)
python3 - "$B_WAN" "$A_WAN" "$B_LAN" "$A_LAN" <<'PY' || nl_fail "accounting off: wan rx $B_WAN -> $A_WAN, lan tx $B_LAN -> $A_LAN"
import sys
bw, aw, bl, al = map(int, sys.argv[1:])
for d in (aw - bw, al - bl):
    assert 20_000_000 <= d <= 22_500_000, d
PY
nl_ok "20 MB LAN download counted: WAN in +$((A_WAN - B_WAN)) B, LAN out +$((A_LAN - B_LAN)) B"

echo "=== history"
has_points() { nl_api GET '/stats/history?hours=1'; [ "$(j 'all(k in d["metrics"] for k in ["cpu","mem","rx:'"$NL_WAN_IF"'","tx:'"$NL_LAN_IF"'"])')" = True ]; }
nl_wait 20 has_points || nl_fail "no history points: $(head -c 400 "$NL_OUT")"
PEAK=$(j 'max(p["value"] for p in d["metrics"]["rx:'"$NL_WAN_IF"'"])')
python3 -c "import sys; assert float(sys.argv[1]) > 1e6, sys.argv[1]" "$PEAK" || nl_fail "WAN throughput history never shows the download (peak $PEAK bit/s)"
nl_ok "history has cpu, mem and per-interface throughput (WAN peak $PEAK bit/s)"

echo "=== data cap"
USED=$(wan_rx)
# allowance so that what is used now is ~85 %
CAP=$(python3 -c "import sys; print(round(int(sys.argv[1]) / 0.85 / 1e9, 6))" "$((USED + $(nl_api GET /stats/usage; j 'sum(u["tx"] for u in d["periods"][0]["usage"] if u["iface"]=="'"$NL_WAN_IF"'")')))")
nl_api_ok "cap" PUT /stats/settings "{\"cap_gb\":$CAP,\"cap_interface\":\"$NL_WAN_IF\"}"
cap_events() { nl_api GET '/events?kind=data_cap'; j 'len(d) if isinstance(d, list) else len(d.get("events", []))'; }
warned() { [ "$(cap_events)" -ge 1 ]; }
nl_wait 15 warned || nl_fail "no data_cap warning at ~85 %: $(cat "$NL_OUT")"
grep -F warning "$NL_OUT" >/dev/null || nl_fail "first data_cap event is not a warning: $(cat "$NL_OUT")"
nl_ok "80 % reached: data_cap warning"
fetch 5000000
crit() { [ "$(cap_events)" -ge 2 ]; }
nl_wait 15 crit || nl_fail "no data_cap event at 100 %: $(cat "$NL_OUT")"
grep -F critical "$NL_OUT" >/dev/null || nl_fail "second data_cap event is not critical: $(cat "$NL_OUT")"
fetch 1000000; sleep 4
[ "$(cap_events)" = 2 ] || nl_fail "data_cap repeated: $(cat "$NL_OUT")"
nl_ok "100 % reached: one critical data_cap event, no repeats"

echo "=== restart keeps totals"
BEFORE=$(wan_rx)
nl_web_stop; nl_web_start "$DB"; nl_login
AFTER=$(wan_rx)
[ "$AFTER" -ge "$BEFORE" ] || nl_fail "totals lost on restart: $BEFORE -> $AFTER"
nl_ok "totals kept across a restart ($BEFORE -> $AFTER bytes)"

nl_web_stop
nl_down
echo "PASS lane-h-stats"
