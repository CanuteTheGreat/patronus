#!/usr/bin/env bash
# Lane J: Wake-on-LAN. A host saved on the Wake-on-LAN page (MAC + interface)
# is woken with the Wake button / POST /api/svc/wol/action/wake: the magic
# packet (6 x 0xFF, then the MAC 16 times, 102 bytes) arrives as a UDP broadcast
# on port 9 at a machine on the LAN, sent out of the right interface; a MAC typed
# into the form works too; bad MACs and unknown hosts are refused.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-wol.db
rm -f "$DB" "$NL_T/nl-jar" /tmp/wol-rx
nl_write_installer_toml
cat > "$NL_T/nl-wol-rx.py" <<'PY'
# a sleeping machine's NIC: listen for the magic packet on UDP/9 (broadcast)
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", 9))
while True:
    d, a = s.recvfrom(2048)
    open(sys.argv[1], "a").write("%d %s %s\n" % (len(d), d[:6].hex(), d[6:12].hex() if d[6:] == d[6:12] * 16 else "bad-pattern"))
PY
: > /tmp/wol-rx
nl_boot "$DB"
nl_bg C python3 "$NL_T/nl-wol-rx.py" /tmp/wol-rx
sleep 0.5
nl_web_start "$DB"; nl_login

echo "=== validation"
nl_api_code "bad MAC" 400 POST /svc/wol/hosts '{"name":"nas","mac":"nope"}'
nl_api_code "bad name" 400 POST /svc/wol/hosts '{"name":"a b","mac":"aa:bb:cc:dd:ee:ff"}'
nl_api_code "bad wake MAC" 400 POST /svc/wol/action/wake '{"mac":"zz"}'
nl_api_code "unknown host" 404 POST /svc/wol/action/wake '{"id":999}'
nl_ok "bad MACs and names are refused (400), an unknown saved host answers 404"

echo "=== a saved host is woken"
nl_api_ok "add host" POST /svc/wol/hosts '{"name":"nas","mac":"AA-BB-CC-00-11-22","interface":"@lan"}'
ID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_code "duplicate name" 400 POST /svc/wol/hosts '{"name":"nas","mac":"aa:bb:cc:00:11:33"}'
nl_api_ok "wake" POST /svc/wol/action/wake "{\"id\":$ID}"
grep -q 'rtr-lan: 192.168.50.255:9' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "the answer does not name the LAN interface and its broadcast address"; }
nl_wait 10 grep -q 'aabbcc001122' /tmp/wol-rx || { cat /tmp/wol-rx; nl_fail "the LAN machine never received the magic packet"; }
grep -q '^102 ffffffffffff aabbcc001122$' /tmp/wol-rx || { cat /tmp/wol-rx; nl_fail "the packet is not 6 x FF + the MAC 16 times"; }
nl_ok "magic packet received on the LAN: 102 bytes, ff*6 then aa:bb:cc:00:11:22 sixteen times (sent via rtr-lan to 192.168.50.255:9)"

echo "=== a MAC typed into the form"
: > /tmp/wol-rx
nl_api_ok "wake by MAC" POST /svc/wol/action/wake '{"mac":"de:ad:be:ef:00:01","interface":"@lan"}'
nl_wait 10 grep -q 'deadbeef0001' /tmp/wol-rx || nl_fail "no packet for a typed MAC"
nl_ok "an unsaved MAC wakes as well"
nl_web GET /svc/wol
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "Wake-on-LAN page: $NL_CODE"
nl_api GET /svc/wol
[ "$(nl_json "$NL_OUT" 'd["collections"]["hosts"][0]["mac"]')" = "aa:bb:cc:00:11:22" ] || nl_fail "the saved MAC was not normalised"
nl_ok "the page renders and the saved host's MAC is normalised"

echo "=== the host list survives a reboot; delete"
nl_web_stop
nl_boot "$DB"
nl_web_start "$DB"; nl_login
nl_api GET /svc/wol
[ "$(nl_json "$NL_OUT" 'len(d["collections"]["hosts"])')" = 1 ] || nl_fail "the host list was lost"
nl_api_ok "delete" DELETE "/svc/wol/hosts/$ID"
nl_api_code "delete twice" 404 DELETE "/svc/wol/hosts/$ID"
nl_ok "hosts persist across a reboot and can be deleted"
nl_web_stop
echo "ALL WAKE-ON-LAN CHECKS PASSED"
