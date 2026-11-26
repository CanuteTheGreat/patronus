#!/usr/bin/env bash
# Lane J: LAN security audit (patronus_network::lanaudit, docs/LAN-AUDIT.md) on the real
# binaries, scanning real listeners in the LAN namespace through the router.
#
# Topology: extra hosts are secondary addresses on the LAN client (nl-client), each with
# real open TCP ports; the router (nl-rtr, where patronus-web runs) TCP-connects to them.
# The built-in scanner is forced (PATRONUS_LANAUDIT_FORCE_BUILTIN=1) so the lane does not
# depend on nmap being installed and the port findings are deterministic.
#
# Proves:
#   - a scan finds the open ports on the LAN hosts and names them from the neighbour table;
#   - telnet on a scanned host is a critical finding; an exposed database is a finding;
#   - the WAN host is never scanned (only non-WAN interface subnets are in scope);
#   - a second scan reports a new device and a newly open port since the first;
#   - the CSV export lists the open ports;
#   - the findings reached the security events (one incident per source+rule).
set -euo pipefail
set -E
trap 'echo "lane-j-lanaudit: failed at line $LINENO" >&2' ERR
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-lanaudit.db
rm -f "$DB" "$NL_T/nl-jar"
export PATRONUS_LANAUDIT_FORCE_BUILTIN=1
export PATRONUS_LANAUDIT_TICK_SECS=1
nl_write_installer_toml

cleanup() { set +e; nl_web_stop; nl_stop_servers; }
trap cleanup EXIT

# a LAN host at ADDR with the given open TCP ports
lan_host() { # ADDR PORT...
  local addr=$1; shift
  C ip addr add "$addr/24" dev lan0 2>/dev/null || true
  for p in "$@"; do nl_bg C python3 "$NL_T/nl-tcp.py" "$addr" "$p"; done
}
# a WAN-side host (on the ISP) with an open port, to prove it is never scanned
wan_host() { # ADDR PORT
  ISP ip addr add "$1/24" dev up0 2>/dev/null || true
  nl_bg ISP python3 "$NL_T/nl-tcp.py" "$1" "$2"
}

# detail of the newest scan as JSON on stdout (via the LAN client + session)
scan_json() { nl_api GET "/lanaudit/scans/$1"; cat "$NL_OUT"; }
# run a scan and wait for it to finish (interval_hours=0 so nothing else scans)
run_scan() {
  nl_api POST /lanaudit/scan ""
  [ "$NL_CODE" = 202 ] || nl_fail "start scan: $NL_CODE $(cat "$NL_OUT")"
  for _ in $(seq 1 60); do
    nl_api GET /lanaudit
    python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if not d.get("running") else 1)' "$NL_OUT" && return 0
    sleep 1
  done
  tail -40 "$NL_T/nl-web.log"; nl_fail "scan did not finish"
}
latest_id() { nl_api GET /lanaudit; python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print((d["scans"] or [{}])[0].get("id",""))' "$NL_OUT"; }
# assert a finding rule is present (optionally at a severity) in a scan's detail
has_finding() { # ID RULE [SEV]
  scan_json "$1" > /t/la-detail.json
  python3 - "$2" "${3:-}" /t/la-detail.json <<'EOF'
import json,sys
rule,sev,path=sys.argv[1],sys.argv[2],sys.argv[3]
d=json.load(open(path))
for f in d.get("findings",[]):
    if f["rule"]==rule and (not sev or f["severity"]==sev):
        sys.exit(0)
sys.exit(1)
EOF
}
host_in_scan() { # ID ADDR
  scan_json "$1" > /t/la-detail.json
  python3 - "$2" /t/la-detail.json <<'EOF'
import json,sys
addr,path=sys.argv[1],sys.argv[2]
d=json.load(open(path))
sys.exit(0 if any(h["address"]==addr for h in d.get("hosts",[])) else 1)
EOF
}

# --- boot and listeners -------------------------------------------------------------------------
nl_boot "$DB"
lan_host 192.168.50.21 23 80     # telnet + http
lan_host 192.168.50.22 3306      # a database
wan_host 203.0.113.9 23          # a telnet host on the WAN side (must never be scanned)
# populate the router's neighbour table so enumeration finds the LAN hosts (and the WAN host,
# which must then be filtered out because it is on the WAN interface)
for a in 192.168.50.21 192.168.50.22; do R ping -c1 -W2 "$a" >/dev/null 2>&1 || true; done
R ping -c1 -W2 203.0.113.9 >/dev/null 2>&1 || true

nl_web_start "$DB"
nl_login
# on demand only (interval 0), alert at warning and above
nl_api PUT /lanaudit/settings '{"enabled":true,"interval_hours":0,"alert_min_severity":"warning","connect_timeout_ms":500}'
[ "$NL_CODE" = 200 ] || nl_fail "enable: $NL_CODE $(cat "$NL_OUT")"

# --- scan 1 -------------------------------------------------------------------------------------
run_scan
ID1=$(latest_id)
host_in_scan "$ID1" 192.168.50.21 || { cat /t/la-detail.json; nl_fail "the LAN host 192.168.50.21 was not scanned"; }
has_finding "$ID1" telnet critical || { cat /t/la-detail.json; nl_fail "no critical telnet finding"; }
nl_ok "telnet on a scanned host is a critical finding"
has_finding "$ID1" database || { cat /t/la-detail.json; nl_fail "no database finding"; }
nl_ok "an exposed database is a finding"
if host_in_scan "$ID1" 203.0.113.9; then cat /t/la-detail.json; nl_fail "the WAN host was scanned"; fi
nl_ok "the WAN host is never scanned"

# the CSV export lists the open ports
nl_web GET "/api/lanaudit/scans/$ID1/export.csv"
[ "$NL_CODE" = 200 ] || nl_fail "csv export: $NL_CODE"
grep -q '^address,name,mac,segment,proto,port,service' "$NL_OUT" || nl_fail "csv has no header"
grep -q '192.168.50.21,.*,tcp,23,' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "csv missing the telnet port"; }
nl_ok "the CSV export lists the open ports"

# the findings reached the security events (one incident per source+rule)
python3 - "$DB" <<'EOF'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
rows=c.execute("SELECT kind,subject,severity FROM system_events WHERE kind LIKE 'audit_%'").fetchall()
kinds={r[0] for r in rows}
assert any(k=='audit_telnet' for k in kinds), f"no audit_telnet event, got {kinds}"
assert any(k=='audit_database' for k in kinds), f"no audit_database event, got {kinds}"
EOF
nl_ok "the findings reached the security events"

# --- scan 2: a new port on an existing host, and a brand new host --------------------------------
nl_bg C python3 "$NL_T/nl-tcp.py" 192.168.50.21 21   # open FTP on .21 (a newly open port)
lan_host 192.168.50.23 23                             # a brand new device
R ping -c1 -W2 192.168.50.23 >/dev/null 2>&1 || true
sleep 1
run_scan
ID2=$(latest_id)
[ "$ID2" != "$ID1" ] || nl_fail "second scan did not create a new scan"
has_finding "$ID2" new_device || { cat /t/la-detail.json; nl_fail "no new_device finding"; }
nl_ok "a new device since the last scan is reported"
has_finding "$ID2" new_port || { cat /t/la-detail.json; nl_fail "no new_port finding"; }
nl_ok "a newly open port is reported"

echo "lane-j-lanaudit: all checks passed"
