#!/usr/bin/env bash
# Lane B: router CVE exposure (patronus_network::cve, docs/CVE-EXPOSURE.md) on the real binaries.
#
# The package database, the Gentoo advisory directory, portageq and emerge are fixtures (a netlab container is
# not a Gentoo system); everything else is real: the crate list is read out of the shipped patronus-web and
# patronus binaries, the crate advisory archive is downloaded over real HTTP from a server on the "internet"
# side of the router, and the engine, the API, the CLI and the stored report are the shipped ones.
#
# Proves:
#   - the GLSA match: an installed package in a vulnerable range is reported with the advisory link, the
#     fixing version and "installable now" (the tree offers a fixed version); an unrelated package is not;
#   - the crates compiled into the REAL patronus-web binary are listed (read back from the file), and a
#     downloaded advisory for one of them is matched to that binary;
#   - the download crosses the router (the server sees the router's WAN address), and without the server the
#     last data keeps working and the failed download is logged;
#   - data older than the limit is shown as stale, with its age;
#   - policy "show only" installs nothing; policy "install in the window" installs nothing outside the window
#     and the GLSA fix inside it, and the next scan no longer reports the package;
#   - bad settings are refused with 400, the page and the CLI answer, the report survives a reboot.
set -euo pipefail
set -E
trap 'echo "lane-b-cve: failed at line $LINENO" >&2' ERR
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-cve.db
rm -f "$DB" "$NL_T/nl-jar"
F=/t/cve
rm -rf "$F"
mkdir -p "$F/pkg/dev-python/joblib-1.1.0-r1" "$F/pkg/sys-apps/other-2.0" "$F/glsa" "$F/www" "$F/data"
echo 0 > "$F/pkg/dev-python/joblib-1.1.0-r1/SLOT"
echo 0 > "$F/pkg/sys-apps/other-2.0/SLOT"
cp "$NL_T/fixtures/cve/glsa-202401-01.xml" "$F/glsa/"
cat > "$F/portageq" <<'SH'
#!/bin/sh
# the tree offers joblib 1.3.2 (what `portageq best_visible / dev-python/joblib:0` prints)
case "$*" in *joblib*) echo dev-python/joblib-1.3.2 ;; *) exit 1 ;; esac
SH
cat > "$F/emerge" <<'SH'
#!/bin/sh
# stands in for emerge: records its arguments and "installs" the fixed joblib
echo "$@" >> /t/cve/emerge-args
mv /t/cve/pkg/dev-python/joblib-1.1.0-r1 /t/cve/pkg/dev-python/joblib-1.3.2
echo 0 > /t/cve/pkg/dev-python/joblib-1.3.2/SLOT
SH
chmod +x "$F/portageq" "$F/emerge"
cat > "$F/srv.py" <<'EOF'
import http.server, sys
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *a):
        open("/t/cve/http.log", "a").write("%s %s\n" % (self.client_address[0], fmt % a))
    def __init__(self, *a, **k):
        super().__init__(*a, directory="/t/cve/www", **k)
http.server.test(HandlerClass=H, port=8099, bind=sys.argv[1])
EOF
nl_write_installer_toml

cleanup() { set +e; nl_web_stop; pkill -f '[s]rv.py' 2>/dev/null; }
trap cleanup EXIT

report() { nl_api GET /cve; [ "$NL_CODE" = 200 ] || nl_fail "GET /cve: $NL_CODE $(cat "$NL_OUT")"; }
rq() { # PYTHON EXPRESSION over the last API answer `d`
  python3 - "$NL_OUT" "$1" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))
EOF
}
wait_report() { # PYEXPR DESC: poll GET /api/cve until the expression is true (the engine ticks every second)
  for _ in $(seq 1 40); do
    report
    [ "$(rq "$1" 2>/dev/null || true)" = True ] && { nl_ok "$2"; return 0; }
    sleep 0.5
  done
  head -c 3000 "$NL_OUT"; tail -20 "$NL_T/nl-web.log"; nl_fail "$2"
}
GLSA0="[f for f in d['report']['findings'] if f['source']=='glsa'][0]"

nl_boot "$DB"
nl_web_start "$DB"
nl_login

# --- invalid settings are refused ----------------------------------------------------------------------
nl_api PUT /cve/settings '{"security_updates":"always"}'
[ "$NL_CODE" = 400 ] || nl_fail "a bad policy was accepted: $NL_CODE"
nl_api PUT /cve/settings '{"window":"25:00-26:00"}'
[ "$NL_CODE" = 400 ] || nl_fail "a bad window was accepted: $NL_CODE"
nl_api PUT /cve/settings '{"glsa_dir":"relative/path"}'
[ "$NL_CODE" = 400 ] || nl_fail "a relative path was accepted: $NL_CODE"
nl_ok "invalid settings are refused with 400"

# --- point the engine at the fixtures; the real binaries are the crate sources --------------------------
nl_api PUT /cve/settings "{\"enabled\":true,\"fetch\":false,\"tick_secs\":1,\"scan_interval_secs\":86400,\"security_updates\":\"notify\",
  \"glsa_dir\":\"$F/glsa\",\"pkg_db\":\"$F/pkg\",\"data_dir\":\"$F/data\",\"portageq\":\"$F/portageq\",\"emerge\":\"$F/emerge\",
  \"manifest_path\":\"$F/no-manifest.json\",\"binaries\":[\"$WEB\",\"$P\"]}"
[ "$NL_CODE" = 200 ] || nl_fail "settings: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /cve/scan '{}'
[ "$NL_CODE" = 202 ] || nl_fail "scan request: $NL_CODE"

wait_report "d['report'] is not None and d['report']['verdict']=='affected'" "the first scan finds the installed package affected"
[ "$(rq "[f['subject'] for f in d['report']['findings'] if f['source']=='glsa']")" = "['dev-python/joblib']" ] || nl_fail "wrong GLSA findings: $(rq "d['report']['findings']")"
[ "$(rq "$GLSA0['advisory']")" = "GLSA-202401-01" ] || nl_fail "advisory id"
[ "$(rq "$GLSA0['url']")" = "https://security.gentoo.org/glsa/202401-01" ] || nl_fail "advisory link"
[ "$(rq "$GLSA0['fixed_in']")" = "['1.2.0']" ] || nl_fail "fixed in"
nl_ok "GLSA-202401-01: dev-python/joblib 1.1.0-r1 is affected, fixed in 1.2.0, link to the advisory"
[ "$(rq "$GLSA0['update']")" = "available" ] || nl_fail "update state"
[ "$(rq "$GLSA0['update_version']")" = "1.3.2" ] || nl_fail "update version"
nl_ok "the fix is installable now (the tree offers joblib 1.3.2)"
[ "$(rq "len([f for f in d['report']['findings'] if 'other' in f['subject']])")" = 0 ] || nl_fail "unrelated package reported"
nl_ok "an unrelated installed package is not reported"

# the crates of the REAL shipped binaries, read back from the files
[ "$(rq "'patronus-web' in [b['binary'] for b in d['report']['binaries']]")" = True ] || nl_fail "patronus-web has no embedded crate list: $(rq "d['report']['binaries']")"
NCRATES=$(rq "[len(b['crates']) for b in d['report']['binaries'] if b['binary']=='patronus-web'][0]")
[ "$NCRATES" -gt 50 ] || nl_fail "only $NCRATES crates in patronus-web"
[ "$(rq "any(c[0]=='tokio' for b in d['report']['binaries'] if b['binary']=='patronus-web' for c in b['crates'])")" = True ] || nl_fail "tokio is not in the patronus-web list"
nl_ok "the installed patronus-web lists its $NCRATES crates (tokio among them), read from the binary file"
[ "$(rq "d['report']['osv']['present']")" = False ] || nl_fail "crate data present before any download"
[ "$(rq "any('crate advisory data' in r for r in d['report']['reasons'])")" = True ] || nl_fail "no note about the missing crate data"
nl_ok "without crate data the report says so instead of calling the crates clean"
[ ! -e "$F/emerge-args" ] || nl_fail "policy 'show only' ran emerge"
nl_ok "policy 'show only' installs nothing"

# --- the crate advisory archive over real HTTP, through the router --------------------------------------
CRATE=tokio
python3 - "$F/www/all.zip" "$CRATE" "$NL_T/fixtures/cve/RUSTSEC-2024-0003.json" <<'EOF'
import json, sys, zipfile
rec = {"schema_version": "1.7.3", "id": "LANE-B-CVE-0001", "aliases": ["CVE-2099-0001"],
       "summary": "Synthetic advisory for the netlab: every version of the crate is affected",
       "affected": [{"package": {"name": sys.argv[2], "ecosystem": "crates.io"},
                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}, {"fixed": "999.0.0"}]}]}],
       "references": [{"type": "ADVISORY", "url": "https://rustsec.org/advisories/LANE-B-CVE-0001.html"}]}
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("LANE-B-CVE-0001.json", json.dumps(rec))
    z.writestr("RUSTSEC-2024-0003.json", open(sys.argv[3]).read())
EOF
nl_bg INET python3 "$F/srv.py" "$NL_WWW"
for _ in $(seq 1 30); do INET curl -s -o /dev/null -m 2 "http://$NL_WWW:8099/all.zip" && break; sleep 0.5; done
: > "$F/http.log"
nl_api PUT /cve/settings "{\"fetch\":true,\"osv_url\":\"http://$NL_WWW:8099/all.zip\"}"
[ "$NL_CODE" = 200 ] || nl_fail "osv_url: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /cve/scan '{"fetch":true}'
wait_report "d['report']['osv']['present'] and any(f['source']=='osv' for f in d['report']['findings'])" "the crate data is downloaded and a crate of patronus-web is affected"
OSV0="[f for f in d['report']['findings'] if f['source']=='osv' and f['subject']=='$CRATE'][0]"
[ "$(rq "$OSV0['binary']")" = patronus-web ] || nl_fail "finding is not attributed to patronus-web"
[ "$(rq "$OSV0['advisory']")" = LANE-B-CVE-0001 ] || nl_fail "advisory id"
[ "$(rq "$OSV0['fixed_in']")" = "['999.0.0']" ] || nl_fail "fixed in"
[ "$(rq "$OSV0['update']")" = needs-release ] || nl_fail "crate fix state"
nl_ok "$CRATE in patronus-web: advisory LANE-B-CVE-0001, fixed in 999.0.0, needs a new Patronus release"
grep -q "^$NL_RTR_WAN " "$F/http.log" || { cat "$F/http.log"; nl_fail "the download did not come from the router's WAN address"; }
nl_ok "the archive was fetched over HTTP across the router (the server saw $NL_RTR_WAN)"
[ "$(rq "d['report']['osv']['age_secs'] < 120")" = True ] || nl_fail "age of the fresh data"
nl_ok "the report says the crate data is $(rq "d['report']['osv']['age_secs']") s old"

# --- offline: the last data keeps working, the failed download is logged ----------------------------------
pkill -f '[s]rv.py' || true
sleep 1
python3 - "$F/data/osv-crates.json" <<'EOF'
import json, sys, time
p = sys.argv[1]; d = json.load(open(p)); d["fetched_at"] = int(time.time()) - 2 * 86400 - 3600; json.dump(d, open(p, "w"))
EOF
nl_api PUT /cve/settings '{"osv_refresh_hours":24}'
nl_api POST /cve/scan '{"fetch":true}'
wait_report "any(x['kind']=='fetch' and not x['ok'] for x in d['log'])" "with the server gone the failed download is logged"
[ "$(rq "any(f['source']=='osv' for f in d['report']['findings'])")" = True ] || nl_fail "the cached crate data was dropped"
nl_ok "offline: the report still uses the last crate data"

# --- stale data is said to be stale -----------------------------------------------------------------------
python3 - "$F/data/osv-crates.json" <<'EOF'
import json, sys, time
p = sys.argv[1]; d = json.load(open(p)); d["fetched_at"] = int(time.time()) - 30 * 86400; json.dump(d, open(p, "w"))
EOF
nl_api PUT /cve/settings '{"fetch":false,"osv_stale_days":7}'
nl_api POST /cve/scan '{}'
wait_report "d['report']['osv']['stale'] and any('days old' in r for r in d['report']['reasons'])" "30-day-old crate data is marked stale with its age"

# --- policy: install security updates in the window -------------------------------------------------------
OUT_W=$(python3 -c 'import datetime as d; n=d.datetime.now(); print("%s-%s" % ((n+d.timedelta(hours=2)).strftime("%H:%M"), (n+d.timedelta(hours=3)).strftime("%H:%M")))')
IN_W=$(python3 -c 'import datetime as d; n=d.datetime.now(); print("%s-%s" % ((n-d.timedelta(hours=1)).strftime("%H:%M"), (n+d.timedelta(hours=1)).strftime("%H:%M")))')
nl_api PUT /cve/settings "{\"security_updates\":\"apply\",\"window\":\"$OUT_W\",\"apply_min_interval_secs\":60}"
[ "$NL_CODE" = 200 ] || nl_fail "policy: $NL_CODE $(cat "$NL_OUT")"
BEFORE=$(rq "len(d['history'])")
nl_api POST /cve/scan '{}'
wait_report "len(d['history']) > $BEFORE" "a scan ran with the policy on and the window closed"
[ ! -e "$F/emerge-args" ] || nl_fail "emerge ran outside the update window ($OUT_W)"
nl_ok "policy 'install in the window' installs nothing outside the window ($OUT_W)"
nl_api PUT /cve/settings "{\"window\":\"$IN_W\"}"
nl_api POST /cve/scan '{}'
wait_report "any(x['kind']=='apply' and x['ok'] for x in d['log'])" "inside the window the fix is installed ($IN_W)"
grep -q -- '--oneshot' "$F/emerge-args" && grep -q -- '>=dev-python/joblib-1.2.0' "$F/emerge-args" || { cat "$F/emerge-args"; nl_fail "emerge arguments"; }
grep -q -- '--with-bdeps=y' "$F/emerge-args" || nl_fail "emerge lacks --with-bdeps=y"
nl_ok "emerge was asked for >=dev-python/joblib-1.2.0 (oneshot, update, with-bdeps)"
wait_report "not any(f['source']=='glsa' for f in d['report']['findings'])" "the next scan no longer reports the fixed package"
[ "$(wc -l < "$F/emerge-args")" = 1 ] || nl_fail "emerge ran more than once"
nl_ok "one install, not a loop"

# --- page, CLI, history, reboot ---------------------------------------------------------------------------
nl_web GET /security/cve-exposure
[ "$NL_CODE" = 200 ] && grep -q 'CVE exposure' "$NL_OUT" || nl_fail "page: $NL_CODE"
nl_ok "the CVE exposure page is served"
CLI=$(R "$P" --db "$DB" cve status 2>&1) || nl_fail "cli status: $CLI"
case "$CLI" in
  *"CVE exposure: on"*"security updates: apply"*) nl_ok "patronus cve status answers" ;;
  *) echo "$CLI"; nl_fail "cli status output" ;;
esac
R "$P" --db "$DB" cve status --json > "$F/cli.json" || nl_fail "cli json"
[ "$(python3 -c "import json; print(json.load(open('$F/cli.json'))['report']['tier'])")" = standard ] || nl_fail "cli report tier"
R "$P" --db "$DB" cve set security_updates=notify window=01:00-02:00 >/dev/null || nl_fail "cli set"
report
[ "$(rq "d['settings']['security_updates']")" = notify ] || nl_fail "cli set did not reach the store"
nl_ok "patronus cve set changes the stored settings"
[ "$(rq "len(d['history'])")" -ge 5 ] || nl_fail "scan history"
nl_ok "scan history has $(rq "len(d['history'])") rows"
nl_web_stop
nl_boot "$DB"
nl_web_start "$DB"
nl_login
report
[ "$(rq "d['report'] is not None and d['report']['tier']=='standard'")" = True ] || nl_fail "the report did not survive the reboot"
[ "$(rq "len(d['history'])")" -ge 5 ] || nl_fail "history lost over the reboot"
nl_ok "the report and its history survive a reboot"
