#!/usr/bin/env bash
# Lane J: packet capture (Diagnostics). POST /api/system/capture runs tcpdump
# as root through the shipped binaries on one interface and answers the decoded
# packets. A LAN client pings the router while the capture runs on the LAN
# interface: the ICMP packets come back, filtered by the structured fields
# (proto/host/port); injection attempts through any field, out-of-range counts
# and a missing interface are refused; a logged-out request is refused.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-capture.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"

echo "=== not without a login"
CODE=$(C curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  -d "{\"interface\":\"$NL_LAN_IF\"}" "$NL_UI/api/system/capture")
case "$CODE" in 401|403|302|303) ;; *) nl_fail "an anonymous capture answered $CODE";; esac
nl_ok "an anonymous request is refused ($CODE)"

nl_login

echo "=== validation"
nl_api_code "no interface" 400 POST /system/capture '{}'
nl_api_code "option as interface" 400 POST /system/capture '{"interface":"-w /tmp/x"}'
nl_api_code "shell in interface" 400 POST /system/capture "{\"interface\":\"$NL_LAN_IF; id\"}"
nl_api_code "filter injection in host" 400 POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"host\":\"1.2.3.4 or port 22\"}"
nl_api_code "unknown proto" 400 POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"proto\":\"tcp or udp\"}"
nl_api_code "port out of range" 400 POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"port\":70000}"
nl_api_code "too many packets" 400 POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"count\":100000}"
nl_api_code "too long" 400 POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"seconds\":600}"
[ ! -e /tmp/x ] || nl_fail "an option reached tcpdump (-w wrote /tmp/x)"
nl_ok "bad interface names, filter injection and out-of-range limits are all 400"

echo "=== a capture sees the LAN client's ping"
(
  NL_OUT="$NL_T/cap.out"
  nl_api POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"proto\":\"icmp\",\"host\":\"$NL_CLIENT\",\"count\":6,\"seconds\":20}"
  echo "$NL_CODE" > "$NL_T/cap.code"
) &
CAP=$!
sleep 2
C ping -c3 -i0.3 -W2 "$NL_RTR_LAN" >/dev/null 2>&1 || nl_fail "the client cannot ping the router"
wait "$CAP"
[ "$(cat "$NL_T/cap.code")" = 200 ] || { cat "$NL_T/cap.out"; nl_fail "capture answered $(cat "$NL_T/cap.code")"; }
N=$(nl_json "$NL_T/cap.out" 'd["count"]')
[ "$N" = 6 ] || { cat "$NL_T/cap.out"; nl_fail "expected 6 ICMP packets (3 requests, 3 replies), got $N"; }
[ "$(nl_json "$NL_T/cap.out" 'd["filter"]')" = "icmp and host $NL_CLIENT" ] || nl_fail "filter: $(nl_json "$NL_T/cap.out" 'd["filter"]')"
nl_json "$NL_T/cap.out" '"\n".join(d["packets"])' > "$NL_T/cap.txt"
[ "$(grep -c 'ICMP echo request' "$NL_T/cap.txt")" = 3 ] || { cat "$NL_T/cap.txt"; nl_fail "not 3 echo requests"; }
[ "$(grep -c 'ICMP echo reply' "$NL_T/cap.txt")" = 3 ] || { cat "$NL_T/cap.txt"; nl_fail "not 3 echo replies"; }
grep -q "$NL_CLIENT > $NL_RTR_LAN: ICMP echo request" "$NL_T/cap.txt" || { cat "$NL_T/cap.txt"; nl_fail "request not decoded as client > router"; }
[ "$(nl_json "$NL_T/cap.out" 'd["truncated"]')" = True ] || nl_fail "a capture that reached its packet limit is not marked truncated"
nl_ok "6 packets: 3 echo requests + 3 replies between $NL_CLIENT and $NL_RTR_LAN, filter 'icmp and host $NL_CLIENT', marked truncated"

echo "=== the time limit ends a quiet capture; a missing device is an error"
nl_api_ok "quiet capture" POST /system/capture "{\"interface\":\"$NL_LAN_IF\",\"proto\":\"udp\",\"port\":4,\"count\":5,\"seconds\":2}"
[ "$(nl_json "$NL_OUT" 'd["count"]')" = 0 ] && [ "$(nl_json "$NL_OUT" 'd["truncated"]')" = False ] || { cat "$NL_OUT"; nl_fail "a quiet capture should return 0 packets, not truncated"; }
nl_api_code "no such device" 500 POST /system/capture '{"interface":"nope0","seconds":2}'
grep -qi 'nope0' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "the error does not name the device"; }
nl_ok "a 2 s capture on a quiet filter returns 0 packets; an unknown device answers 500 naming it"

nl_web_stop
echo "ALL PACKET CAPTURE CHECKS PASSED"
