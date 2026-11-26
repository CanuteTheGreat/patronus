#!/usr/bin/env bash
# Lane S (UI): the DNS filtering section of the DNS page driven in a real browser (ci/dns-filter-e2e.py, Playwright +
# Firefox) against the shipped patronus-web in the netlab router, with a real Unbound and a list server on the
# internet side: the catalog with its licences, a custom list added through the form and shown loaded, the list
# switch, the allow list (a bad regular expression is an error), "Block this domain" from the query log, and the
# layout at 1280 and 390 px in light and dark. Needs Playwright + Firefox preinstalled at /opt/pw by ci/netlab/run.sh
# (fails, never skips, when they are missing). The behaviour behind every button is proven with real DNS queries by
# lane-s-dns-filter.sh.
set -Eeuo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-dnsf-ui.db
UP=198.51.100.54
LS=198.51.100.55
L=$NL_T/dnsf-ui-lists
PW=/opt/pw
export PATRONUS_DNSFILTER_TICK_SECS=1
[ -x "$PW/bin/playwright" ] || nl_fail "Playwright/Firefox are not preinstalled at $PW (ci/netlab/run.sh does it before the scenarios start)"
[ -f "$NL_T/dns-filter-e2e.py" ] || { echo "SKIP lane-s-dns-filter-ui: ci/dns-filter-e2e.py was not copied next to the scenarios"; exit 0; }
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
pkill -x unbound 2>/dev/null || true; rm -f /run/unbound.pid
rm -rf /var/lib/patronus/dnsbl /var/log/unbound "$L"; mkdir -p "$L"
trap 'rc=$?; set +e; pkill -x unbound 2>/dev/null; exit $rc' EXIT
printf '0.0.0.0 ads1.adnet.lab.example\n0.0.0.0 ads2.adnet.lab.example\n0.0.0.0 tracker.adnet.lab.example\n' > "$L/ui.hosts"
unbound_alive() { ps -eo stat=,comm= | awk '$2=="unbound" && $1 !~ /^Z/ {f=1} END{exit !f}'; }

cat > "$NL_T/dnsf-http.py" <<'PY'
# static file server for the lists; HTTPServer.server_bind would reverse-resolve the address (slow with no DNS)
import functools, http.server, socketserver, sys
addr, port, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
class S(http.server.ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = addr, port
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
S((addr, port), h).serve_forever()
PY
cat > "$NL_T/dnsf-ask.py" <<'PY'
import socket, struct, sys
name, qtype, server = sys.argv[1], sys.argv[2], sys.argv[3]
q = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(q, (server, 53)); s.recvfrom(4096)
PY
nl_boot "$DB"
INET ip addr add $UP/24 dev inet0; INET ip addr add $LS/24 dev inet0
nl_bg INET dnsmasq --no-daemon --no-resolv --no-hosts --user=root --bind-interfaces \
  --listen-address=$UP --pid-file=/tmp/nl-dnsmasq-up.pid --address=/lab.example/$NL_WWW
nl_bg INET sh -c "exec python3 $NL_T/dnsf-http.py $LS 8000 $L > $NL_T/dnsf-lists.log 2>&1"
for _ in $(seq 1 40); do INET bash -c "exec 3<>/dev/tcp/$LS/8000" 2>/dev/null && break; sleep 0.25; done
nl_web_start "$DB"; nl_login
nl_api_ok "dns settings" PUT /dns/settings "{\"mode\":\"resolver\",\"dnssec\":false,\"upstreams\":\"$UP\",\"log_queries\":true}"
nl_wait 30 unbound_alive || nl_fail "unbound is not running"
# a query so the log has a row to block from
for _ in 1 2 3; do C python3 "$NL_T/dnsf-ask.py" www.lab.example A 192.168.50.1 >/dev/null 2>&1 || true; done
SHOTS=$NL_T/dnsf-shots
out=$(C env BASE_URL="$NL_UI" E2E_USER=admin E2E_PASSWORD="$NL_PASS" E2E_LIST_URL="http://$LS:8000/ui.hosts" \
      E2E_BLOCK_HOST=www.lab.example E2E_SHOTS="$SHOTS" "$PW/bin/python" "$NL_T/dns-filter-e2e.py" firefox 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || nl_fail "the DNS filtering page e2e failed (exit $rc)"
nl_ok "DNS filtering page driven in Firefox: $(grep -c '^PASS:' <<<"$out") checks"
nl_web_stop
echo "PASS lane-s-dns-filter-ui"
