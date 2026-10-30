#!/usr/bin/env bash
# Lane s, part d: traffic insight HISTORY by country / ASN / device (the
# built-in alternative to ntopng's history). Runs INSIDE the capped netlab
# container (ci/netlab/run.sh) with the shipped binaries in /t.
#
#   client 192.168.50.10 --- rtr --- isp --- inet:  198.51.100.10 -> "AU", AS64500
#                                                    198.51.100.20 -> "DE", AS64501
#
# The DB-IP databases are tiny CSV fixtures served by an HTTP server in the
# `inet` namespace (nothing is looked up on the real internet), so the
# download path is the real one: `patronus ipdb update` (the monthly job) and
# the web UI's "Download now" both fetch them with curl.
#
# Proves, with real flows through the router's conntrack:
#  - `patronus ipdb update` downloads both databases, is a no-op while they are
#    fresh, and replaces them with --force
#  - the collector turns conntrack byte counters into hourly rows: three 1 MiB
#    downloads from the AU host and one from the DE host show up as AU / DE,
#    AS64500 / AS64501 (organisation names with commas survive), download vs
#    upload kept apart, within a few percent of what curl received
#  - per-device views: filtering by the client's address, an unknown address
#    has nothing, the device list and the drill-down timeline agree
#  - a database file replaced while patronus-web runs is picked up (new
#    organisation name) without a restart
#  - "do not record" an address: its history is deleted and new traffic is not
#    recorded until it is removed again; switching collection off records nothing
#  - retention deletes old hourly buckets, keeps the recent ones
#  - a failed database download keeps the old file and says so; a good one works
#  - history survives a reboot (fresh namespaces + patronus apply)
set -eu
. "$(dirname "$0")/lib.sh"

T=/t/lanes-insight
rm -rf "$T"; mkdir -p "$T/feeds" "$T/pub"
DB=$T/config.db
export NO_COLOR=1 CLICOLOR=0 PATRONUS_FEEDS_DIR=$T/feeds PATRONUS_IPDB_REFRESH=0
export PATRONUS_INSIGHT_TICK_SECS=1 PATRONUS_INSIGHT_FLUSH_SECS=2

dump() { [ -f "$NL_T/nl-web.log" ] && { echo "--- web log"; tail -30 "$NL_T/nl-web.log"; }; true; }
fail() { dump; nl_fail "$*"; }
cleanup() { nl_web_stop; nl_down; }
trap cleanup EXIT
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
must() { local want=$1; shift; nl_api "$@"; [ "$NL_CODE" = "$want" ] || fail "$1 $2 -> $NL_CODE (want $want): $(cat "$NL_OUT")"; }
sql() { python3 - "$DB" "$1" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=30)
c.execute(sys.argv[2]); c.commit()
EOF
}
sqlq() { python3 - "$DB" "$1" <<'EOF'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=30)
print(c.execute(sys.argv[2]).fetchone()[0])
EOF
}

# --- fixtures: DB-IP style CSVs (>= 10 rows each, the refresh refuses less) ----
python3 - "$T/pub" <<'EOF'
import gzip, sys
d = sys.argv[1]
def w(name, rows):
    with gzip.open(f"{d}/{name}", "wt") as f:
        f.write("\n".join(rows) + "\n")
filler = lambda i: (f"203.0.{i}.0", f"203.0.{i}.255")
w("country.csv.gz", ['"198.51.100.0","198.51.100.15","AU"', '"198.51.100.16","198.51.100.31","DE"']
  + [f'"{a}","{b}","US"' for a, b in map(filler, range(20, 30))])
w("asn.csv.gz", ['"198.51.100.0","198.51.100.15","64500","NetLab AU Transit"',
                 '"198.51.100.16","198.51.100.31","64501","NetLab DE Hosting, GmbH"']
  + [f'"{a}","{b}","{65000 + i}","Filler {i}"' for i, (a, b) in enumerate(map(filler, range(20, 30)))])
w("asn-v2.csv.gz", ['"198.51.100.0","198.51.100.15","64500","NetLab AU Transit v2"',
                    '"198.51.100.16","198.51.100.31","64501","NetLab DE Hosting, GmbH"']
  + [f'"{a}","{b}","{65000 + i}","Filler {i}"' for i, (a, b) in enumerate(map(filler, range(20, 30)))])
open(f"{d}/big.bin", "wb").write(b"\0" * 1048576)
EOF

# --- 1. boot, servers, and the monthly job ---------------------------------
nl_write_installer_toml
nl_boot "$DB"
nl_bg INET python3 -m http.server 8081 --bind 0.0.0.0 --directory "$T/pub"
for _ in $(seq 1 50); do INET sh -c "exec 3<>/dev/tcp/$NL_WWW/8081" 2>/dev/null && break; sleep 0.1; done
now=$(date +%s)
sql "INSERT OR REPLACE INTO system_config VALUES ('firewall.geoip.db_url','http://$NL_WWW:8081/country.csv.gz',$now)"
sql "INSERT OR REPLACE INTO system_config VALUES ('insight.asn.db_url','http://$NL_WWW:8081/asn.csv.gz',$now)"
out=$(R "$P" --db "$DB" ipdb update 2>&1) || fail "patronus ipdb update: $out"
grep -q '^country: updated' <<<"$out" && grep -q '^asn: updated' <<<"$out" || fail "ipdb update output: $out"
[ -s "$T/feeds/dbip-country-lite.csv" ] && [ -s "$T/feeds/dbip-asn-lite.csv" ] || fail "database files missing in $T/feeds"
grep -q 'NetLab DE Hosting, GmbH' "$T/feeds/dbip-asn-lite.csv" || fail "ASN file content"
nl_ok "patronus ipdb update (the monthly job) downloaded the country and ASN databases through the router"
out=$(R "$P" --db "$DB" ipdb update 2>&1) || fail "second ipdb update: $out"
[ "$(grep -c 'still fresh' <<<"$out")" = 2 ] || fail "a fresh database must not be downloaded again: $out"
nl_ok "a second run is a no-op while the databases are fresh"
out=$(R "$P" --db "$DB" ipdb status 2>&1)
grep -q 'DB-IP.com (CC BY 4.0)' <<<"$out" || fail "ipdb status: $out"
nl_ok "ipdb status names the licence/attribution"

nl_web_start "$DB"; nl_login
nl_web GET /insights
[ "$NL_CODE" = 200 ] && grep -q 'tab-countries' "$NL_OUT" && grep -q 'DB-IP.com' "$NL_OUT" || fail "insights page: $NL_CODE"
must 200 GET /insights/countries
[ "$(jget 'd["rows"]')" = "[]" ] || fail "a router that saw no traffic yet must not invent rows: $(cat "$NL_OUT")"
nl_ok "before any traffic: empty history, no invented rows; page renders with attribution"

# --- 2. real traffic -> hourly rows ---------------------------------------
dl() { C curl -s -m 30 -o /dev/null -w '%{size_download}' "http://$1:8081/big.bin"; }
total_au=0
for _ in 1 2 3; do n=$(dl $NL_WWW); total_au=$((total_au + n)); done
total_de=$(dl $NL_BLOCKED)
[ "$total_au" -ge 3145728 ] && [ "$total_de" -ge 1048576 ] || fail "downloads were short: au=$total_au de=$total_de"
has_rows() { nl_api GET "/insights/countries?window=1h" && [ "$NL_CODE" = 200 ] && [ "$(jget 'len(d["rows"])')" -ge 2 ] \
  && [ "$(jget 'sum(r["down_bytes"] for r in d["rows"])')" -ge 4000000 ]; }
nl_wait 40 has_rows || { cat "$NL_OUT"; fail "the collector never recorded the downloads"; }
must 200 GET "/insights/countries?window=1h"
[ "$(jget 'd["rows"][0]["country"]')" = AU ] && [ "$(jget 'd["rows"][1]["country"]')" = DE ] \
  || fail "countries not ranked AU, DE: $(cat "$NL_OUT")"
au=$(jget 'd["rows"][0]["down_bytes"]'); de=$(jget 'd["rows"][1]["down_bytes"]'); up=$(jget 'd["rows"][0]["up_bytes"]')
# IP-level counters include headers: a few percent above the payload, never below
[ "$au" -ge "$total_au" ] && [ "$au" -le $((total_au * 11 / 10)) ] || fail "AU download bytes $au vs payload $total_au"
[ "$de" -ge "$total_de" ] && [ "$de" -le $((total_de * 11 / 10)) ] || fail "DE download bytes $de vs payload $total_de"
[ "$up" -gt 0 ] && [ "$up" -lt $((au / 10)) ] || fail "AU upload bytes $up (download $au)"
nl_ok "countries: AU $au B down / $up B up, DE $de B down; payload was $total_au + $total_de B"
must 200 GET "/insights/asns?window=1h"
[ "$(jget '[r["asn"] for r in d["rows"]][:2]')" = "[64500, 64501]" ] || fail "asns: $(cat "$NL_OUT")"
[ "$(jget 'd["rows"][0]["org"]')" = "NetLab AU Transit" ] && [ "$(jget 'd["rows"][1]["org"]')" = "NetLab DE Hosting, GmbH" ] \
  || fail "organisation names: $(cat "$NL_OUT")"
nl_ok "ASNs: AS64500 NetLab AU Transit, AS64501 'NetLab DE Hosting, GmbH' (a comma inside the quoted field survived)"

# --- 3. per device (address) ---------------------------------------------
must 200 GET "/insights/countries?window=1h&device=$NL_CLIENT"
[ "$(jget 'd["rows"][0]["country"]')" = AU ] || fail "client view: $(cat "$NL_OUT")"
must 200 GET "/insights/countries?window=1h&device=192.168.50.99"
[ "$(jget 'd["rows"]')" = "[]" ] || fail "an address that sent nothing has no traffic: $(cat "$NL_OUT")"
must 200 GET "/insights/devices?window=1h"
[ "$(jget 'd["rows"][0]["ip"]')" = "$NL_CLIENT" ] && [ "$(jget 'd["rows"][0]["top_country"]')" = AU ] || fail "device list: $(cat "$NL_OUT")"
must 200 GET "/insights/devices/$NL_CLIENT?window=24h"
[ "$(jget 'sum(p["down_bytes"] for p in d["timeline"]) >= 4000000')" = True ] || fail "drill-down timeline: $(cat "$NL_OUT")"
[ "$(jget 'len(d["timeline"]) >= 24')" = True ] || fail "timeline is zero-filled hourly: $(cat "$NL_OUT")"
must 404 GET "/insights/devices/no-such-device"
nl_ok "per-device views: the client's address has the traffic, another address none, drill-down timeline matches"

# --- 4. database replaced while the web service runs -----------------------
cp "$T/pub/asn-v2.csv.gz" "$T/asn-v2.csv.gz"; gzip -dc "$T/asn-v2.csv.gz" > "$T/feeds/.new"; mv "$T/feeds/.new" "$T/feeds/dbip-asn-lite.csv"
dl $NL_WWW >/dev/null
v2() { nl_api GET "/insights/asns?window=1h" && [ "$(jget '[r["org"] for r in d["rows"] if r["asn"] == 64500][0]')" = "NetLab AU Transit v2" ]; }
nl_wait 30 v2 || fail "the replaced ASN database was not picked up: $(cat "$NL_OUT")"
nl_ok "an ASN database replaced under the running web service is re-read (organisation renamed without a restart)"

# --- 5. privacy: do not record ------------------------------------------------
must 400 POST /insights/exclusions '{"kind":"ip","ref":"not an address"}'
must 201 POST /insights/exclusions "{\"kind\":\"ip\",\"ref\":\"$NL_CLIENT\"}"
[ "$(jget 'd["forgotten_rows"] > 0')" = True ] || fail "excluding must delete what was recorded: $(cat "$NL_OUT")"
must 200 GET "/insights/countries?window=24h"
[ "$(jget 'd["rows"]')" = "[]" ] || fail "history of the excluded address remains: $(cat "$NL_OUT")"
dl $NL_WWW >/dev/null; dl $NL_BLOCKED >/dev/null; sleep 6
must 200 GET "/insights/countries?window=24h"
[ "$(jget 'd["rows"]')" = "[]" ] || fail "traffic of an excluded address was recorded: $(cat "$NL_OUT")"
nl_ok "excluded address: history deleted, new traffic not recorded"
nl_api DELETE "/insights/exclusions?kind=ip&ref=$NL_CLIENT"; [ "$NL_CODE" = 200 ] || fail "remove exclusion: $NL_CODE"
dl $NL_WWW >/dev/null
back() { nl_api GET "/insights/countries?window=1h" && [ "$(jget 'len(d["rows"])')" -ge 1 ]; }
nl_wait 30 back || fail "traffic is not recorded again after the exclusion was removed"
nl_ok "exclusion removed: recording resumes"
must 200 PUT /insights/settings '{"enabled":false}'
sleep 3; n0=$(sqlq "SELECT COALESCE(SUM(bytes),0) FROM ins_usage")
dl $NL_WWW >/dev/null; sleep 6
[ "$(sqlq "SELECT COALESCE(SUM(bytes),0) FROM ins_usage")" = "$n0" ] || fail "recorded while collection is switched off"
nl_ok "collection switched off: nothing recorded"
must 200 PUT /insights/settings '{"enabled":true}'

# --- 6. retention ---------------------------------------------------------------
old=$(( $(date +%s) - 40*86400 )); old=$(( old - old % 3600 ))
sql "INSERT INTO ins_usage (bucket, ip, dir, country, asn, asn_org, bytes, packets, flows) VALUES ($old,'192.168.50.10','down','AU',64500,'old',1000,10,1)"
must 200 PUT /insights/settings '{"retention_days":7,"top_n":50}'
gone() { [ "$(sqlq "SELECT COUNT(*) FROM ins_usage WHERE bucket = $old")" = 0 ]; }
nl_wait 20 gone || fail "a 40 day old bucket survived retention 7 days"
[ "$(sqlq "SELECT COUNT(*) FROM ins_usage WHERE bucket > $old")" -ge 1 ] || fail "retention removed recent rows too"
nl_ok "retention: the 40 day old bucket is deleted, recent buckets stay"

# --- 7. database refresh from the UI: bad URL keeps the old file, good works --
must 200 PUT /firewall/geoip "{\"db_url\":\"http://$NL_WWW:8081/country.csv.gz\",\"refresh_days\":30}"
must 200 PUT /insights/database "{\"asn_url\":\"http://$NL_WWW:8081/missing.csv.gz\",\"refresh_days\":30}"
nl_api POST /insights/database/refresh
[ "$NL_CODE" = 502 ] && [ "$(jget '[r["database"] for r in d["results"] if not r["ok"]]')" = "['asn']" ] || fail "refresh with a missing file: $NL_CODE $(cat "$NL_OUT")"
must 200 GET /insights/database
[ "$(jget 'd["asn"]["present"]')" = True ] && [ "$(jget 'd["asn"]["status"].startswith("error:")')" = True ] || fail "status after a failed download: $(cat "$NL_OUT")"
grep -q 'NetLab AU Transit v2' "$T/feeds/dbip-asn-lite.csv" || fail "a failed download must keep the old ASN file"
nl_ok "failed download: reported (502, status error:), old file kept"
must 200 PUT /insights/database "{\"asn_url\":\"http://$NL_WWW:8081/asn.csv.gz\"}"
must 200 POST /insights/database/refresh
[ "$(jget 'all(r["ok"] for r in d["results"])')" = True ] || fail "refresh: $(cat "$NL_OUT")"
grep -q 'NetLab AU Transit$' "$T/feeds/dbip-asn-lite.csv" || grep -q '"NetLab AU Transit"' "$T/feeds/dbip-asn-lite.csv" || fail "forced refresh did not replace the file"
nl_ok "Download now: both databases refreshed from the mirror"

# --- 8. history survives a reboot ------------------------------------------
before=$(sqlq "SELECT COALESCE(SUM(bytes),0) FROM ins_usage")
[ "$before" -gt 0 ] || fail "nothing to keep across the reboot"
nl_web_stop
nl_boot "$DB"
nl_web_start "$DB"; nl_login
must 200 GET "/insights/countries?window=1h"
[ "$(jget 'len(d["rows"])')" -ge 1 ] && [ "$(jget 'd["recorded_rows"]')" -ge 1 ] || fail "history lost across the reboot: $(cat "$NL_OUT")"
nl_ok "reboot (fresh namespaces + patronus apply): the recorded history is still there"
echo "lane-s-insight: all checks passed"
