#!/usr/bin/env bash
# Lane J: firewall state table. The Firewall > States tab lists the kernel's
# tracked connections (GET /api/firewall/states) and kills them
# (DELETE /api/firewall/states): two long-lived TCP connections from the LAN
# client to the internet host are listed as ESTABLISHED with the right
# addresses and ports; an empty or malformed kill is refused (400) and kills
# nothing; killing one connection by its source port removes exactly that
# state from the router's conntrack table and leaves the other; killing by
# source address removes the rest; new connections still work afterwards.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-states.db
rm -f "$DB" "$NL_T/nl-jar" /tmp/st-a /tmp/st-b
nl_write_installer_toml
cat > "$NL_T/nl-st-server.py" <<'PY'
# accept connections and hold them open
import socket, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 9100)); s.listen(16)
keep = []
while True:
    c, a = s.accept(); keep.append(c)
PY
cat > "$NL_T/nl-st-holder.py" <<'PY'
# open a TCP connection, record its local port, hold it open
import socket, sys, time
s = socket.create_connection((sys.argv[1], 9100), timeout=5)
open(sys.argv[2], "w").write(str(s.getsockname()[1]))
time.sleep(300)
PY
nl_boot "$DB"
nl_bg INET python3 "$NL_T/nl-st-server.py"
for _ in $(seq 1 30); do INET python3 "$NL_T/nl-conn.py" $NL_WWW 9100 >/dev/null 2>&1 && break; sleep 0.1; done
nl_web_start "$DB"; nl_login

nl_bg C python3 "$NL_T/nl-st-holder.py" $NL_WWW /tmp/st-a
nl_bg C python3 "$NL_T/nl-st-holder.py" $NL_WWW /tmp/st-b
nl_wait 10 test -s /tmp/st-a
nl_wait 10 test -s /tmp/st-b
PA=$(cat /tmp/st-a); PB=$(cat /tmp/st-b)
[ "$PA" != "$PB" ] || nl_fail "both holders share source port $PA"

echo "=== the table lists the connections"
nl_api_ok "list" GET "/firewall/states?q=$NL_WWW%209100&proto=tcp"
[ "$(nl_json "$NL_OUT" 'd["total"] >= d["matched"] >= 2')" = True ] || { cat "$NL_OUT"; nl_fail "the two held connections are not both listed"; }
for p in $PA $PB; do
  [ "$(nl_json "$NL_OUT" "len([x for x in d['states'] if x['sport']==$p and x['dport']==9100 and x['dst']=='$NL_WWW' and x['state']=='ESTABLISHED' and x['proto']=='tcp'])")" = 1 ] \
    || { cat "$NL_OUT"; nl_fail "no ESTABLISHED state for source port $p"; }
done
nl_ok "ports $PA and $PB listed as ESTABLISHED tcp to $NL_WWW:9100"
nl_api_ok "filter by text" GET "/firewall/states?q=no-such-host-zzz"
[ "$(nl_json "$NL_OUT" 'd["matched"]')" = 0 ] || nl_fail "a filter that matches nothing returned states"
nl_ok "the filter narrows the list"

echo "=== refused kills"
nl_api_code "no filter" 400 DELETE /firewall/states
nl_api_code "protocol only" 400 DELETE "/firewall/states?proto=tcp"
nl_api_code "bad address" 400 DELETE "/firewall/states?src=1.2.3.4;reboot"
nl_api_code "bad protocol" 400 DELETE "/firewall/states?src=192.168.50.10&proto=nope"
R conntrack -L 2>/dev/null | grep -q "sport=$PA .*dport=9100" || nl_fail "a refused kill removed a state"
R conntrack -L 2>/dev/null | grep -q "sport=$PB .*dport=9100" || nl_fail "a refused kill removed a state"
nl_ok "empty, protocol-only, malformed address and unknown protocol are 400 and kill nothing"

echo "=== kill one connection"
nl_api_ok "kill A" DELETE "/firewall/states?src=192.168.50.10&sport=$PA&dport=9100&proto=tcp"
[ "$(nl_json "$NL_OUT" 'd["deleted"]')" = 1 ] || { cat "$NL_OUT"; nl_fail "expected exactly 1 state deleted"; }
if R conntrack -L 2>/dev/null | grep -q "sport=$PA .*dport=9100"; then nl_fail "state of port $PA still in conntrack"; fi
R conntrack -L 2>/dev/null | grep -q "sport=$PB .*dport=9100" || nl_fail "killing port $PA also removed port $PB"
nl_api_ok "list after kill" GET "/firewall/states?q=9100"
[ "$(nl_json "$NL_OUT" "len([x for x in d['states'] if x['sport']==$PA])")" = 0 ] || nl_fail "the API still lists port $PA"
[ "$(nl_json "$NL_OUT" "len([x for x in d['states'] if x['sport']==$PB])")" = 1 ] || nl_fail "the API lost port $PB"
nl_ok "port $PA gone from conntrack and the API, port $PB untouched"

echo "=== kill by source address"
nl_api_ok "kill source" DELETE "/firewall/states?src=192.168.50.10&dport=9100"
[ "$(nl_json "$NL_OUT" 'd["deleted"]')" -ge 1 ] || nl_fail "nothing deleted by source"
if R conntrack -L 2>/dev/null | grep -q "sport=$PB .*dport=9100"; then nl_fail "state of port $PB survived a kill by source"; fi
nl_api_ok "kill nothing" DELETE "/firewall/states?src=192.168.50.10&dport=9100"
[ "$(nl_json "$NL_OUT" 'd["deleted"]')" = 0 ] || nl_fail "a second kill still deleted states"
nl_ok "kill by address removes the rest; a repeat kills 0 without error"

echo "=== traffic still works"
C python3 "$NL_T/nl-conn.py" $NL_WWW 9100 >"$NL_OUT" 2>&1 || nl_fail "a new connection fails after the kills"
nl_ok "new connections are accepted again"
nl_web GET /firewall
[ "$NL_CODE" = 200 ] && grep -q 'id="tab-states"' "$NL_OUT" || nl_fail "the Firewall page has no States tab ($NL_CODE)"
nl_ok "the Firewall page has the States tab"
nl_web_stop
echo "ALL STATE TABLE CHECKS PASSED"
