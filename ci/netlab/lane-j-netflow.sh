#!/usr/bin/env bash
# Lane J: NetFlow / IPFIX export (USE=netflow). The NetFlow page starts
# softflowd on the WAN interface; real LAN -> internet traffic produces flow
# records that arrive at a UDP collector on the "internet" side, in the
# configured format (v9 and IPFIX/v10 are told apart by the version field of
# the export packet header). Reboot and disable are checked.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-netflow.db
rm -f "$DB" "$NL_T/nl-jar" /tmp/nf-rx
nl_write_installer_toml
nl_kill_daemons softflowd

cat > "$NL_T/nl-nf-rx.py" <<'PY'
# collector: log the NetFlow/IPFIX version of every export datagram
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    d, a = s.recvfrom(65535)
    if len(d) >= 4:
        open(sys.argv[3], "a").write("version=%d from=%s len=%d\n" % (struct.unpack("!H", d[:2])[0], a[0], len(d)))
PY
: > /tmp/nf-rx
# softflowd 1.1.0 hands packets over in ring-buffer blocks (upstream fixed this with
# immediate mode later), so a quiet interface only exports once the block fills:
# push enough bulk traffic (8 MB) through the router to fill it, like a busy link would.
cat > "$NL_T/nl-bulk-sink.py" <<'PY'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(8)
while True:
    c, _ = s.accept()
    while c.recv(1 << 20):
        pass
    c.sendall(b"done\n"); c.close()
PY
cat > "$NL_T/nl-bulk.py" <<'PY'
import socket, sys
n = int(sys.argv[3]); s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=30)
chunk = b"x" * 1400; sent = 0
while sent < n:
    s.sendall(chunk); sent += len(chunk)
s.shutdown(socket.SHUT_WR); s.recv(10)
PY
bulk() { C python3 "$NL_T/nl-bulk.py" "$NL_WWW" 9200 8000000; C curl -s --max-time 3 -o /dev/null "http://$NL_WWW/"; }

nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-nf-rx.py" 0.0.0.0 2055 /tmp/nf-rx
nl_bg INET python3 "$NL_T/nl-bulk-sink.py" 0.0.0.0 9200
sleep 0.5
nl_web_start "$DB"; nl_login

echo "=== off by default, validation"
nl_api_code "enable without a collector" 400 PUT /svc/netflow '{"enabled":true}'
for bad in '{"version":"7"}' '{"port":70000}' '{"collector":"a b"}' '{"interface":"eth0;x"}'; do
  nl_api_code "bad setting $bad" 400 PUT /svc/netflow "$bad"
done
nl_ok "enabling without a collector, bad versions, ports, hosts and interfaces are refused (400)"
pgrep -x softflowd >/dev/null && nl_fail "softflowd running while the export is off"

echo "=== export the WAN interface as NetFlow v9"
nl_api_ok "enable" PUT /svc/netflow "{\"enabled\":true,\"interface\":\"@wan\",\"collector\":\"$NL_WWW\",\"port\":2055,\"version\":\"9\"}"
nl_wait 10 pgrep -x softflowd || nl_fail "softflowd did not start"
nl_ok "softflowd running: $(pgrep -ax softflowd | head -1 | cut -c1-150)"
pgrep -ax softflowd | grep -q -- "-i $NL_WAN_IF .*-n $NL_WWW:2055 .*-v 9" || nl_fail "softflowd command line does not match the settings"
# generate flows: LAN -> internet through the router, then let them expire
bulk
# flows are exported when they end or expire: ask softflowd to expire them now
softflowctl -c /run/patronus/softflowd-$NL_WAN_IF.ctl expire-all >/dev/null 2>&1 || true
nl_wait 20 grep -q 'version=9 ' /tmp/nf-rx || { cat /tmp/nf-rx; nl_fail "the collector received no NetFlow v9 packet"; }
nl_ok "collector received NetFlow v9 export packets: $(head -1 /tmp/nf-rx)"
nl_api GET /svc/netflow
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show the exporter"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["enabled"] and st["installed"], st
assert any(e["running"] for e in st["exporters"]), st
PY
nl_ok "status lists the running exporter"

echo "=== switch to IPFIX"
: > /tmp/nf-rx
nl_api_ok "ipfix" PUT /svc/netflow '{"version":"10"}'
nl_wait 10 pgrep -x softflowd
pgrep -ax softflowd | grep -q -- "-v 10" || nl_fail "softflowd was not restarted with -v 10"
sleep 1
bulk
softflowctl -c /run/patronus/softflowd-$NL_WAN_IF.ctl expire-all >/dev/null 2>&1 || true
nl_wait 20 grep -q 'version=10 ' /tmp/nf-rx || { cat /tmp/nf-rx; nl_fail "no IPFIX (version 10) packet received"; }
grep -q 'version=9 ' /tmp/nf-rx && nl_fail "still exporting v9 after the change"
nl_ok "collector now receives IPFIX (version 10): $(head -1 /tmp/nf-rx)"
nl_web GET /svc/netflow
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "NetFlow page: $NL_CODE"
nl_ok "the NetFlow page renders"

echo "=== reboot: patronus apply restarts the exporter"
nl_web_stop
nl_kill_daemons softflowd
nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-nf-rx.py" 0.0.0.0 2055 /tmp/nf-rx
nl_bg INET python3 "$NL_T/nl-bulk-sink.py" 0.0.0.0 9200
sleep 0.5
nl_wait 10 pgrep -x softflowd || nl_fail "softflowd not started by the boot apply"
: > /tmp/nf-rx
bulk
softflowctl -c /run/patronus/softflowd-$NL_WAN_IF.ctl expire-all >/dev/null 2>&1 || true
nl_wait 20 grep -q 'version=10 ' /tmp/nf-rx || nl_fail "no export after the reboot"
nl_ok "after reboot: flows are exported again"

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable" PUT /svc/netflow '{"enabled":false}'
nl_wait 10 sh -c '! pgrep -x softflowd' || nl_fail "softflowd still running after disabling"
nl_ok "disabled: softflowd stopped"
nl_web_stop
echo "ALL NETFLOW CHECKS PASSED"
