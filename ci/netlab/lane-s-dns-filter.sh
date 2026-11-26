#!/usr/bin/env bash
# Lane S: DNS filtering catalog (docs/DNS-FILTERING.md, claim C1204). Real Unbound with RPZ zones
# (resolver, standard tier) and real dnsmasq (forwarder, router tier), lists served by an HTTP server
# on the internet side, real DNS queries from the LAN client. Proves:
#   - the catalog records a licence for every list; bad input is refused (400);
#   - subscribing downloads the lists, converts hosts/domain lists into RPZ zones, loads a threat-intel
#     zone in RPZ format as it is, and every blocked name answers NXDOMAIN, subdomains per list policy;
#   - per-list status (names, size, time, error) and per-list blocked-answer counts, from Unbound's
#     `rpz: applied [list]` log lines, with the recent-blocked list;
#   - the allow list (domain, wildcard, regular expression) overrides every list, RPZ zones included;
#   - "block this domain" / "allow this domain" from the query log work on real queries;
#   - a dead list server or an HTML error page keeps the last good copy and is reported;
#   - the scheduled refresh picks up a changed list without any UI action;
#   - disabling a list lifts its blocks; the setting survives a reboot (boot apply, no web UI);
#   - router tier: dnsmasq address= lines, capped by the board's RAM (a list that does not fit is
#     skipped with the reason), allow list, per-list counts from the dnsmasq log;
#   - cost: Unbound's memory and reload time for a large list (printed).
set -Eeuo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-s-dnsf.db
UP=198.51.100.54      # upstream DNS: every name under lab.example -> www
LS=198.51.100.55      # list server
L=$NL_T/dnsf-lists
export PATRONUS_DNSFILTER_TICK_SECS=1 PATRONUS_DNSFILTER_DUE_SECS=3
unbound_alive() { ps -eo stat=,comm= | awk '$2=="unbound" && $1 !~ /^Z/ {f=1} END{exit !f}'; }
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
pkill -x unbound 2>/dev/null || true; rm -f /run/unbound.pid
rm -rf /var/lib/patronus/dnsbl /var/log/unbound /var/log/patronus-dnsmasq.log "$L"
mkdir -p "$L"
trap 'rc=$?; set +e; pkill -x unbound 2>/dev/null; pkill -x dnsmasq 2>/dev/null; exit $rc' EXIT

cat > "$L/ads.hosts" <<'EOF'
# hosts format
127.0.0.1 localhost
0.0.0.0 ads1.adnet.lab.example
0.0.0.0 ads2.adnet.lab.example
0.0.0.0 tracker.adnet.lab.example
EOF
cat > "$L/wild.txt" <<'EOF'
# oisd-style wildcard list (subdomains are blocked too)
*.evil-domain.lab.example
other-evil.lab.example
EOF
cat > "$L/thr.rpz" <<'EOF'
$TTL 300
@ SOA localhost. root.localhost. 1 3600 600 86400 300
  NS localhost.
; threat-intelligence zone in RPZ format
bad.threat.lab.example CNAME .
*.bad.threat.lab.example CNAME .
phish.threat.lab.example CNAME .
*.phish.threat.lab.example CNAME .
EOF

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
T = {"A": 1, "AAAA": 28}[qtype]
q = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
for l in name.split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack("!HH", T, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(q, (server, 53)); d, _ = s.recvfrom(4096)
rcode = d[3] & 15; an = struct.unpack("!H", d[6:8])[0]
i = 12
while d[i]: i += d[i] + 1
i += 5
out = []
for _ in range(an):
    if d[i] & 0xC0 == 0xC0: i += 2
    else:
        while d[i]: i += d[i] + 1
        i += 1
    t, _c, _ttl, ln = struct.unpack("!HHIH", d[i:i+10]); i += 10
    if t == 1: out.append(socket.inet_ntoa(d[i:i+4]))
    elif t == 28: out.append(socket.inet_ntop(socket.AF_INET6, d[i:i+16]))
    i += ln
print("rcode=%d answers=%s" % (rcode, ",".join(sorted(out)) or "none"))
PY
ask() { C python3 "$NL_T/dnsf-ask.py" "$1" "${2:-A}" 192.168.50.1 2>&1 || true; }
is_nx() { case "$(ask "$1")" in *rcode=3*) return 0 ;; esac; return 1; }
is_ok() { case "$(ask "$1")" in *rcode=0*answers=198.51.100.10*) return 0 ;; esac; return 1; }
expect_nx() { nl_wait "${2:-15}" is_nx "$1" || nl_fail "$1 should be blocked (NXDOMAIN), got: $(ask "$1")"; nl_ok "$1 -> NXDOMAIN (blocked)"; }
expect_ok() { nl_wait "${2:-15}" is_ok "$1" || nl_fail "$1 should resolve, got: $(ask "$1")"; nl_ok "$1 resolves -> $NL_WWW"; }
jq_t() { [ "$(jq_ "$1")" = True ]; }
jq_() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
fetch_api() { nl_api GET /dns-filter; [ "$NL_CODE" = 200 ] || nl_fail "GET /dns-filter: $NL_CODE $(cat "$NL_OUT")"; }
list_field() { fetch_api; jq_ "[l for l in d['lists'] if l['name']=='$1'][0]$2"; }

start_inet() {
  INET ip addr add $UP/24 dev inet0 2>/dev/null || true
  INET ip addr add $LS/24 dev inet0 2>/dev/null || true
  nl_bg INET dnsmasq --no-daemon --no-resolv --no-hosts --user=root --bind-interfaces \
    --listen-address=$UP --pid-file=/tmp/nl-dnsmasq-up.pid --address=/lab.example/$NL_WWW
  start_lists
}
start_lists() {
  nl_bg INET sh -c "exec python3 $NL_T/dnsf-http.py $LS 8000 $L > $NL_T/dnsf-lists.log 2>&1"
  for _ in $(seq 1 40); do INET bash -c "exec 3<>/dev/tcp/$LS/8000" 2>/dev/null && return 0; sleep 0.25; done
  cat "$NL_T/dnsf-lists.log" 2>/dev/null || true
  nl_fail "list server did not start"
}
stop_lists() { pkill -f "[d]nsf-http.py" 2>/dev/null || true; sleep 0.5; }

echo "=== boot, resolver mode"
nl_boot "$DB"; start_inet
nl_web_start "$DB"; nl_login

echo "=== catalog: licences recorded, bad input refused"
fetch_api
[ "$(jq_ "len(d['catalog'])")" -ge 10 ] || nl_fail "catalog has fewer than 10 lists"
jq_t "all(c['license'] and c['license_url'].startswith('https://') for c in d['catalog'])" || nl_fail "a catalog entry has no licence"
for id in stevenblack oisd-small oisd-big hagezi-light hagezi-multi hagezi-pro hagezi-pro-plus hagezi-ultimate hagezi-tif-mini phishing-army urlhaus; do
  jq_t "any(c['id']=='$id' for c in d['catalog'])" || nl_fail "catalog lacks $id"
done
[ "$(jq_ "[c['license'] for c in d['catalog'] if c['id']=='stevenblack'][0]")" = MIT ] || nl_fail "StevenBlack licence"
[ "$(jq_ "[c['needs_key'] for c in d['catalog'] if c['id']=='urlhaus'][0]")" = True ] || nl_fail "URLhaus must need a key"
nl_ok "catalog: $(jq_ "len(d['catalog'])") free lists, each with a licence and its licence URL"
for bad in '{"name":"bad name","url":"http://x.example/l","format":"domains"}' \
           '{"name":"x","url":"ftp://x.example/l","format":"domains"}' \
           '{"name":"x","url":"http://x.example/l","format":"xml"}' \
           '{"catalog":"no-such-list"}' \
           '{"name":"x","url":"http://x.example/l","format":"domains","action":"launch"}'; do
  nl_api POST /dns-filter/lists "$bad"; [ "$NL_CODE" = 400 ] || nl_fail "bad list accepted ($NL_CODE): $bad"
done
for bad in '{"kind":"regex","pattern":"(unclosed"}' '{"kind":"wildcard","pattern":"example.com"}' \
           '{"kind":"domain","pattern":"*.example.com"}' '{"kind":"glob","pattern":"x"}'; do
  nl_api POST /dns-filter/allow "$bad"; [ "$NL_CODE" = 400 ] || nl_fail "bad allow entry accepted ($NL_CODE): $bad"
done
nl_api PUT /dns-filter/settings '{"refresh_hours":0}'; [ "$NL_CODE" = 400 ] || nl_fail "refresh interval 0 accepted"
nl_ok "bad list, URL, format, action, regex, wildcard, domain and interval are refused (400)"

echo "=== subscribe: hosts list (catalog), wildcard domain list (custom), RPZ threat-intel zone (catalog)"
nl_api_ok "dns settings" PUT /dns/settings "{\"mode\":\"resolver\",\"dnssec\":false,\"upstreams\":\"$UP\",\"log_queries\":true}"
nl_api_ok "stevenblack" POST /dns-filter/lists "{\"catalog\":\"stevenblack\",\"url\":\"http://$LS:8000/ads.hosts\"}"
nl_api_ok "custom domain list" POST /dns-filter/lists "{\"name\":\"wild\",\"url\":\"http://$LS:8000/wild.txt\",\"format\":\"domains\",\"subdomains\":true}"
nl_api_ok "threat zone" POST /dns-filter/lists "{\"catalog\":\"hagezi-tif-mini\",\"url\":\"http://$LS:8000/thr.rpz\"}"
nl_wait 30 unbound_alive || { ps -eo pid,stat,comm,args | grep -i "[u]nbound"; ls -la /var/log/unbound; tail -5 /var/log/unbound/unbound.log; grep -i "dns\|unbound" "$NL_T/nl-web.log" | tail -8; nl_fail "unbound is not running"; }
CONF=/etc/unbound/unbound.conf
[ "$(grep -c '^rpz:' "$CONF")" = 4 ] || { cat "$CONF"; nl_fail "expected the allow zone + 3 list zones in unbound.conf"; }
grep -F 'module-config: "respip iterator"' "$CONF" >/dev/null || nl_fail "respip is not in module-config"
grep -F 'rpz-log-name: "stevenblack"' "$CONF" >/dev/null || nl_fail "no rpz-log-name for the list"
unbound-checkconf "$CONF" >/dev/null || nl_fail "unbound-checkconf rejects the live config"
nl_ok "unbound.conf: 3 list zones + the allow zone, respip loaded, checkconf clean"
fetch_api
[ "$(jq_ "[l['status']['used'] for l in d['lists'] if l['name']=='stevenblack'][0]")" = 3 ] || nl_fail "stevenblack should load 3 names: $(cat "$NL_OUT")"
[ "$(jq_ "[l['status']['used'] for l in d['lists'] if l['name']=='wild'][0]")" = 2 ] || nl_fail "wild should load 2 names"
[ "$(jq_ "[l['status']['used'] for l in d['lists'] if l['name']=='hagezi-tif-mini'][0]")" = 2 ] || nl_fail "RPZ list should load 2 names"
jq_t "all(l['status']['last_error']=='' and l['status']['bytes']>0 and l['status']['last_ok']>0 for l in d['lists'])" || nl_fail "list status has errors: $(cat "$NL_OUT")"
[ "$(jq_ "[l['license'] for l in d['lists'] if l['name']=='stevenblack'][0]")" = MIT ] || nl_fail "subscription lost its licence"
nl_ok "status per list: names loaded (3, 2, 2), size, time, no error; licence kept"

echo "=== real queries"
expect_ok www.lab.example
expect_nx ads1.adnet.lab.example
expect_nx ads2.adnet.lab.example
expect_ok sub.ads1.adnet.lab.example       # a hosts list blocks the name only
expect_nx a.b.evil-domain.lab.example       # a wildcard list blocks the subdomains
expect_nx other-evil.lab.example
expect_nx bad.threat.lab.example            # RPZ zone loaded as it is
expect_nx www.bad.threat.lab.example
expect_ok good.threat.lab.example
nl_ok "hosts list: name only; domain list and RPZ zone: subdomains too; everything else resolves"

echo "=== per-list blocked-answer counts and the recent list"
for i in 1 2 3; do ask ads1.adnet.lab.example >/dev/null; done
ask bad.threat.lab.example >/dev/null
sbc() { fetch_api; [ "$(jq_ "[l['blocked_today'] for l in d['lists'] if l['name']=='stevenblack'][0]")" -ge 4 ]; }
nl_wait 30 sbc || { fetch_api; cat "$NL_OUT"; tail -5 /var/log/unbound/unbound.log; nl_fail "stevenblack blocked-answer count did not reach 4"; }
fetch_api
[ "$(jq_ "[l['blocked_today'] for l in d['lists'] if l['name']=='hagezi-tif-mini'][0]")" -ge 1 ] || nl_fail "the RPZ zone has no count"
[ "$(jq_ "[l['blocked_today'] for l in d['lists'] if l['name']=='wild'][0]")" -ge 2 ] || nl_fail "the wild list has no count"
jq_t "any(r['domain']=='ads1.adnet.lab.example' and r['list']=='stevenblack' for r in d['recent'])" || nl_fail "ads1 not in the recent blocked list"
nl_ok "counts per list from Unbound's rpz log: stevenblack $(jq_ "[l['blocked_today'] for l in d['lists'] if l['name']=='stevenblack'][0]"), wild, threat zone; recent list names the list"

echo "=== query log: block this domain / allow this domain"
nl_api GET "/dns-filter/log?q=ads1"; [ "$NL_CODE" = 200 ] || nl_fail "log: $NL_CODE"
jq_t "any(r['qname']=='ads1.adnet.lab.example' and r['blocked_by']=='stevenblack' for r in d['rows'])" || { cat "$NL_OUT"; nl_fail "the log has no blocked row naming the list"; }
nl_api GET "/dns-filter/log?q=www.lab"
jq_t "any(r['qname']=='www.lab.example' and r['blocked_by']=='' and r['rcode']=='NOERROR' for r in d['rows'])" || { cat "$NL_OUT"; nl_fail "the log has no answered row"; }
nl_ok "query log: blocked row names its list, answered row has the rcode"
nl_api_ok "block from the log" POST /dns/blocklist '{"domain":"www.lab.example","description":"blocked from the query log"}'
expect_nx www.lab.example
mc() { fetch_api; [ "$(jq_ "d['manual_blocked']")" -ge 1 ]; }
nl_wait 30 mc || nl_fail "blocked-by-hand answers are not counted"
nl_ok "block this domain: www.lab.example -> NXDOMAIN, counted as blocked by hand"
nl_api_ok "allow from the log" POST /dns-filter/allow '{"kind":"domain","pattern":"www.lab.example","description":"allowed from the query log"}'
expect_ok www.lab.example
AID=$(jq_ "d['id']")
nl_api_ok "drop the allow" DELETE /dns-filter/allow/"$AID"
expect_nx www.lab.example
nl_api GET /dns; ID=$(jq_ "[b['id'] for b in d['blocklist'] if b['domain']=='www.lab.example'][0]")
nl_api_ok "unblock" DELETE /dns/blocklist/"$ID"
expect_ok www.lab.example
nl_ok "allow this domain beats the hand-made block; removing both restores the answer"

echo "=== allow list: domain, wildcard and regular expression, also over the RPZ zone"
nl_api_ok "allow domain" POST /dns-filter/allow '{"kind":"domain","pattern":"ads2.adnet.lab.example"}'
nl_api_ok "allow wildcard" POST /dns-filter/allow '{"kind":"wildcard","pattern":"phish.*.lab.example"}'
nl_api_ok "allow regex" POST /dns-filter/allow '{"kind":"regex","pattern":"^tracker[0-9]*\\.adnet\\.lab\\.example$"}'
expect_ok ads2.adnet.lab.example
expect_ok phish.threat.lab.example
expect_ok www.phish.threat.lab.example
expect_ok tracker.adnet.lab.example
expect_nx ads1.adnet.lab.example
expect_nx bad.threat.lab.example
nl_ok "allowed by domain, by wildcard (RPZ zone) and by regex; the other names stay blocked"
fetch_api; AIDS=$(jq_ "' '.join(str(a['id']) for a in d['allow'])")
for a in $AIDS; do nl_api_ok "drop allow $a" DELETE /dns-filter/allow/"$a"; done
expect_nx ads2.adnet.lab.example; expect_nx phish.threat.lab.example; expect_nx tracker.adnet.lab.example
nl_ok "removing the allow entries blocks the names again"

echo "=== a dead list server and an HTML error page keep the last good copy"
stop_lists
nl_api_ok "refresh with the server down" POST /dns-filter/refresh '{}'
fetch_api
jq_t "all('download failed' in l['status']['last_error'] for l in d['lists'])" || { cat "$NL_OUT"; nl_fail "a failed download is not reported per list"; }
[ "$(jq_ "[l['status']['used'] for l in d['lists'] if l['name']=='stevenblack'][0]")" = 3 ] || nl_fail "the old copy was dropped"
expect_nx ads1.adnet.lab.example
nl_ok "server down: every list reports the error, the last good copy keeps blocking"
echo '<html><body>503 busy</body></html>' > "$L/ads.hosts.html"
cp "$L/ads.hosts" "$L/ads.hosts.good"; cp "$L/ads.hosts.html" "$L/ads.hosts"
start_lists
nl_api_ok "refresh with an HTML page" POST /dns-filter/refresh '{}'
[ "$(list_field stevenblack "['status']['last_error']")" != "" ] || nl_fail "an HTML error page was accepted as a list"
case "$(list_field stevenblack "['status']['last_error']")" in *"no domain names"*) ;; *) nl_fail "wrong error: $(list_field stevenblack "['status']['last_error']")";; esac
expect_nx ads1.adnet.lab.example
nl_ok "HTML error page refused (no domain names), old copy still blocks"

echo "=== scheduled refresh: a changed list is picked up without any UI action"
cp "$L/ads.hosts.good" "$L/ads.hosts"; echo '0.0.0.0 late.adnet.lab.example' >> "$L/ads.hosts"
sqlite3 "$DB" "UPDATE dnsf_status SET last_ok=1, last_attempt=1, force=0"
expect_nx late.adnet.lab.example 45
[ "$(list_field stevenblack "['status']['used']")" = 4 ] || nl_fail "list not updated to 4 names"
[ "$(list_field stevenblack "['status']['last_error']")" = "" ] || nl_fail "error did not clear"
nl_ok "refresh interval elapsed -> list downloaded, zone reloaded, late.adnet.lab.example blocked"

echo "=== disable / enable a list"
SID=$(list_field stevenblack "['id']")
nl_api_ok "disable" PUT /dns-filter/lists/"$SID" '{"enabled":false}'
expect_ok ads1.adnet.lab.example; expect_nx bad.threat.lab.example
nl_api_ok "enable" PUT /dns-filter/lists/"$SID" '{"enabled":true}'
expect_nx ads1.adnet.lab.example
nl_ok "disabling a list lifts its blocks only, enabling restores them"

echo "=== cost: a large list in Unbound (measured)"
python3 - "$L/big.txt" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    for i in range(150000):
        f.write("n%d.big-list.lab.example\n" % i)
PY
RSS0=$(awk '/VmRSS/ {print $2}' /proc/"$(pgrep -x unbound | head -1)"/status)
T0=$(date +%s.%N)
nl_api_ok "big list" POST /dns-filter/lists "{\"name\":\"big\",\"url\":\"http://$LS:8000/big.txt\",\"format\":\"domains\",\"subdomains\":true}"
T1=$(date +%s.%N)
expect_nx n149999.big-list.lab.example 30
expect_nx sub.n7.big-list.lab.example
RSS1=$(awk '/VmRSS/ {print $2}' /proc/"$(pgrep -x unbound | head -1)"/status)
echo "measured: 150000 names (+ subdomain twins = 300000 RPZ records): subscribe+download+convert+unbound restart $(python3 -c "print(round($T1-$T0,1))") s, unbound RSS $((RSS0/1024)) MB -> $((RSS1/1024)) MB"
[ "$((RSS1-RSS0))" -lt 600000 ] || nl_fail "unbound grew by more than 600 MB for 150000 names"
BID=$(list_field big "['id']")
nl_api_ok "remove the big list" DELETE /dns-filter/lists/"$BID"
expect_ok n7.big-list.lab.example 30
nl_ok "150000-name list: loaded, blocks its last name and its subdomains, memory within budget, unsubscribing frees it"

echo "=== reboot: the lists keep blocking from the boot apply (no web UI)"
nl_web_stop
pkill -x unbound 2>/dev/null || true; rm -f /run/openrc/started/unbound /run/unbound.pid
nl_boot "$DB"; start_inet
nl_wait 30 unbound_alive || nl_fail "unbound not started by the boot apply"
expect_nx ads1.adnet.lab.example 30
expect_nx bad.threat.lab.example
expect_nx a.evil-domain.lab.example
expect_ok www.lab.example
nl_ok "after reboot: lists, RPZ zone and allow zone are back, blocking from the first query"

echo "=== router tier: dnsmasq forwarder, board capped by its RAM"
nl_web_stop
pkill -x unbound 2>/dev/null || true; rm -f /run/openrc/started/unbound /run/unbound.pid
nl_dnsmasq_shim
python3 - "$L/huge.txt" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    for i in range(100000):
        f.write("h%d.huge-list.lab.example\n" % i)
PY
export PATRONUS_DNS_FILTER_MEM_KB=131072     # a 128 MB board
nl_web_start "$DB"; nl_login
nl_api_ok "forwarder" PUT /dns/settings "{\"mode\":\"forwarder\",\"upstreams\":\"$UP\",\"log_queries\":true,\"rebind_protection\":false}"
nl_api_ok "huge list" POST /dns-filter/lists "{\"name\":\"huge\",\"url\":\"http://$LS:8000/huge.txt\",\"format\":\"domains\"}"
fetch_api
[ "$(jq_ "d['cap']")" = 90000 ] || nl_fail "the 128 MB board's cap should be 90000, got $(jq_ "d['cap']")"
case "$(list_field huge "['status']['last_error']")" in *"not loaded"*) ;; *) nl_fail "the list that does not fit is not skipped: $(list_field huge "['status']['last_error']")";; esac
[ "$(list_field huge "['status']['used']")" = 0 ] || nl_fail "the oversized list was loaded"
nl_ok "128 MB board: cap 90000 names, the 100000-name list is skipped and says why"
nl_api_ok "drop the huge list" DELETE /dns-filter/lists/"$(list_field huge "['id']")"
nl_wait 20 grep -q 'address=/ads1.adnet.lab.example/' /etc/dnsmasq.conf || { cat /etc/dnsmasq.conf; nl_fail "no address= line for the hosts list"; }
grep -q 'address=/bad.threat.lab.example/' /etc/dnsmasq.conf || nl_fail "RPZ zone names not loaded for dnsmasq"
grep -q 'huge-list' /etc/dnsmasq.conf && nl_fail "the oversized list leaked into dnsmasq.conf"
grep -q 'log-facility=/var/log/patronus-dnsmasq.log' /etc/dnsmasq.conf || nl_fail "no dnsmasq log file for the counters"
expect_nx ads1.adnet.lab.example 30
expect_nx a.evil-domain.lab.example
expect_ok www.lab.example
nl_api_ok "allow on the router" POST /dns-filter/allow '{"kind":"domain","pattern":"ads2.adnet.lab.example"}'
expect_ok ads2.adnet.lab.example
expect_nx ads1.adnet.lab.example
for i in 1 2 3; do ask ads1.adnet.lab.example >/dev/null; done
rc_() { fetch_api; [ "$(jq_ "[l['blocked_today'] for l in d['lists'] if l['name']=='stevenblack'][0]")" -ge 3 ]; }
nl_wait 30 rc_ || { fetch_api; cat "$NL_OUT"; tail -5 /var/log/patronus-dnsmasq.log; nl_fail "dnsmasq blocked answers not counted per list"; }
nl_ok "dnsmasq: address= lines, allow list, per-list counts from the dnsmasq log"
nl_web_stop

echo "PASS lane-s-dns-filter"
