#!/usr/bin/env bash
# Lane H: the Diagnostics page's tools on the real binaries, run on the
# router (web UI -> /api/system/diag), checked against what really happens
# in the lab:
#
#  1. ping the internet host from the router: replies counted; an address
#     nobody answers gets 0 replies (not an error page).
#  2. traceroute to the internet host passes the ISP router (203.0.113.1).
#  3. DNS lookup against the lab resolver: A answer, NXDOMAIN, PTR of an
#     address; a dead server gives a clear timeout (504).
#  4. ARP table lists the LAN client's real MAC; routing tables show
#     Patronus' default-route table; listening sockets include the web UI.
#  5. hostile input (shell syntax, option injection, out-of-range counts) is
#     refused with 400 and nothing runs; a read-only account gets 403.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-h-diag.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
j() { nl_json "$NL_OUT" "$1"; }
diag() { nl_api POST /system/diag "$1"; }

echo "=== 1. ping"
diag "{\"tool\":\"ping\",\"target\":\"$NL_WWW\",\"count\":2}"
[ "$NL_CODE" = 200 ] || nl_fail "ping: $NL_CODE $(cat "$NL_OUT")"
[ "$(j 'd["received"]')" = 2 ] || nl_fail "ping replies: $(cat "$NL_OUT")"
nl_ok "router pings $NL_WWW: 2 of 2 replies"
diag '{"tool":"ping","target":"198.51.100.99","count":1}'
[ "$NL_CODE" = 200 ] || nl_fail "ping to a silent address: $NL_CODE"
[ "$(j 'd["received"]')" = 0 ] || nl_fail "silent address answered: $(cat "$NL_OUT")"
nl_ok "an address nobody answers: 0 replies, reported (not an error)"
diag "{\"tool\":\"ping\",\"target\":\"$NL_CLIENT\",\"count\":1,\"interface\":\"$NL_LAN_IF\",\"family\":\"4\"}"
[ "$NL_CODE" = 200 ] && [ "$(j 'd["received"]')" = 1 ] || nl_fail "ping via interface: $(cat "$NL_OUT")"
nl_ok "ping with a source interface and IPv4 forced"

echo "=== 2. traceroute"
# the lab ISP just sent host-unreachables for 198.51.100.99 (step 1), and
# Linux rate-limits ICMP errors per destination (1/s): lift the lab ISP's
# limit so its time-exceeded for hop 1 is not swallowed
ISP sysctl -qw net.ipv4.icmp_ratelimit=0
diag "{\"tool\":\"traceroute\",\"target\":\"$NL_WWW\",\"max_hops\":5}"
[ "$NL_CODE" = 200 ] || nl_fail "traceroute: $NL_CODE $(cat "$NL_OUT")"
OUT=$(j '"\n".join(d["output"])')
grep -F ' 203.0.113.1 ' <<<"$OUT" >/dev/null || nl_fail "traceroute does not pass the ISP hop: $OUT"
grep -F "$NL_WWW" <<<"$OUT" >/dev/null || nl_fail "traceroute does not reach $NL_WWW: $OUT"
nl_ok "traceroute: ISP hop 203.0.113.1 then $NL_WWW"

echo "=== 3. DNS lookup"
diag "{\"tool\":\"dns\",\"name\":\"www.example.test\",\"type\":\"A\",\"server\":\"$NL_DNS\"}"
[ "$NL_CODE" = 200 ] || nl_fail "dns: $NL_CODE $(cat "$NL_OUT")"
[ "$(j 'd["rcode"]')" = NOERROR ] && [ "$(j 'd["answers"][0]["data"]')" = "$NL_WWW" ] \
  || nl_fail "dns answer: $(cat "$NL_OUT")"
nl_ok "www.example.test A $NL_WWW from $NL_DNS"
diag "{\"tool\":\"dns\",\"name\":\"nothing.invalid\",\"server\":\"$NL_DNS\"}"
[ "$NL_CODE" = 200 ] || nl_fail "dns nxdomain: $NL_CODE $(cat "$NL_OUT")"
case "$(j 'd["rcode"]')" in NXDOMAIN|REFUSED) ;; *) nl_fail "unknown name: $(cat "$NL_OUT")" ;; esac
nl_ok "unknown name: $(j 'd["rcode"]') shown"
diag "{\"tool\":\"dns\",\"name\":\"$NL_WWW\",\"server\":\"$NL_DNS\"}"
[ "$NL_CODE" = 200 ] && [ "$(j 'd["type"]')" = PTR ] && [ "$(j 'd["name"]')" = 10.100.51.198.in-addr.arpa ] \
  || nl_fail "address lookup is not a PTR query: $(cat "$NL_OUT")"
nl_ok "an address is looked up as its PTR name"
NL_CURL_MAX=20 diag '{"tool":"dns","name":"www.example.test","server":"198.51.100.99"}'
[ "$NL_CODE" = 504 ] || nl_fail "dead server: $NL_CODE $(cat "$NL_OUT")"
nl_ok "a server that never answers: 504 with the reason"

echo "=== 3b. TCP port test (open / closed / filtered)"
nl_bg INET python3 "$NL_T/nl-sink.py" 0.0.0.0 9100
INET nft add table ip nlt
INET nft add chain ip nlt in '{ type filter hook input priority 0; }'
INET nft add rule ip nlt in tcp dport 9102 drop
tcp() { diag "{\"tool\":\"tcp\",\"host\":\"$NL_WWW\",\"port\":$1$2}"; }
state=""
for _ in $(seq 1 20); do
  tcp 9100 ",\"timeout\":3"
  [ "$NL_CODE" = 200 ] || nl_fail "tcp test: $NL_CODE $(cat "$NL_OUT")"
  state=$(j 'd["state"]'); [ "$state" = open ] && break; sleep 0.5
done
[ "$state" = open ] || nl_fail "listener on $NL_WWW:9100 not reported open: $(cat "$NL_OUT")"
[ "$(j 'd["resolved"]')" = "$NL_WWW" ] || nl_fail "resolved address: $(cat "$NL_OUT")"
nl_ok "a listening port is open (resolved $NL_WWW, $(j 'd["ms"]') ms)"
tcp 9101 ",\"timeout\":3"
[ "$NL_CODE" = 200 ] && [ "$(j 'd["state"]')" = closed ] || nl_fail "refused port not reported closed: $(cat "$NL_OUT")"
nl_ok "a port nobody listens on is closed (connection refused)"
tcp 9102 ",\"timeout\":2"
[ "$NL_CODE" = 200 ] && [ "$(j 'd["state"]')" = filtered ] || nl_fail "dropped port not reported filtered: $(cat "$NL_OUT")"
[ "$(j 'd["ms"]')" -ge 1900 ] || nl_fail "filtered answered before the timeout: $(cat "$NL_OUT")"
nl_ok "a port a firewall drops is filtered after the 2 s timeout"
tcp 9100 ",\"interface\":\"$NL_WAN_IF\",\"family\":\"4\""
[ "$NL_CODE" = 200 ] && [ "$(j 'd["state"]')" = open ] || nl_fail "tcp test through a source interface: $(cat "$NL_OUT")"
nl_ok "the test can be pinned to a source interface and IPv4"
for body in '{"tool":"tcp","host":"x; id","port":80}' '{"tool":"tcp","host":"-x","port":80}' \
            '{"tool":"tcp","host":"198.51.100.10","port":0}' '{"tool":"tcp","host":"198.51.100.10","port":70000}' \
            '{"tool":"tcp","host":"198.51.100.10"}' '{"tool":"tcp","host":"198.51.100.10","port":80,"timeout":99}' \
            '{"tool":"tcp","host":"198.51.100.10","port":80,"source":"x"}' '{"tool":"tcp","host":"198.51.100.10","port":80,"interface":"-i"}'; do
  diag "$body"
  [ "$NL_CODE" = 400 ] || nl_fail "hostile tcp request not refused ($NL_CODE): $body"
done
nl_ok "8 malformed port tests refused with 400"
nl_api PUT /v1/dashboard/settings '{"tcp_tests_per_minute":1}'
[ "$NL_CODE" = 200 ] || nl_fail "set the port-test rate: $NL_CODE $(cat "$NL_OUT")"
tcp 9101 ",\"timeout\":2"
[ "$NL_CODE" = 429 ] || nl_fail "rate limit not applied ($NL_CODE): $(cat "$NL_OUT")"
nl_ok "past the configured rate (1 per minute) the answer is 429"
nl_api PUT /v1/dashboard/settings '{"tcp_tests_per_minute":30}'

echo "=== 4. tables"
C ping -c1 -W2 "$NL_RTR_LAN" >/dev/null
MAC=$(C cat /sys/class/net/lan0/address)
diag '{"tool":"neighbors"}'
[ "$NL_CODE" = 200 ] || nl_fail "neighbors: $NL_CODE"
python3 - "$NL_OUT" "$NL_CLIENT" "$MAC" "$NL_LAN_IF" <<'EOF' || nl_fail "LAN client missing from the ARP table: $(cat "$NL_OUT")"
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if any(n["address"] == sys.argv[2] and n["mac"] == sys.argv[3] and n["device"] == sys.argv[4]
                  for n in d["neighbors"]) else 1)
EOF
nl_ok "ARP table: $NL_CLIENT is $MAC on $NL_LAN_IF"
diag '{"tool":"routes"}'
[ "$NL_CODE" = 200 ] || nl_fail "routes: $NL_CODE"
ROUTES=$(j '"\n".join(d["ipv4"] + d["rules4"])')
[ "$ROUTES" = "$(R sh -c 'ip -4 route show table all | grep -v "table local"; ip -4 rule show')" ] \
  || nl_fail "routing tables differ from the kernel's: $ROUTES"
grep -E '^default via 203\.0\.113\.1 dev '"$NL_WAN_IF" <<<"$ROUTES" >/dev/null || nl_fail "no default route: $ROUTES"
grep -E 'lookup main' <<<"$ROUTES" >/dev/null || nl_fail "no policy rules: $ROUTES"
nl_ok "routing tables + policy rules: exactly the kernel's state (default via the ISP)"
diag '{"tool":"sockets"}'
[ "$NL_CODE" = 200 ] || nl_fail "sockets: $NL_CODE"
grep -E ':8443\b' <<<"$(j '"\n".join(d["sockets"])')" >/dev/null || nl_fail "web UI socket not listed: $(cat "$NL_OUT")"
nl_ok "listening sockets include the web UI on 8443"

echo "=== 5. hostile input"
for body in '{"tool":"ping","target":"198.51.100.10; touch /tmp/pwned"}' \
            '{"tool":"ping","target":"-f"}' \
            '{"tool":"ping","target":"$(touch /tmp/pwned)"}' \
            '{"tool":"ping","target":"198.51.100.10","count":1000}' \
            '{"tool":"ping","target":"198.51.100.10","interface":"-c9"}' \
            '{"tool":"traceroute","target":"x y","max_hops":5}' \
            '{"tool":"dns","name":"a..b"}' \
            '{"tool":"dns","name":"x","type":"ANY"}' \
            '{"tool":"dns","name":"x","server":"not-an-ip"}' \
            '{"tool":"sh"}'; do
  diag "$body"
  [ "$NL_CODE" = 400 ] || nl_fail "hostile input not refused ($NL_CODE): $body"
done
[ ! -e /tmp/pwned ] || nl_fail "an injected command ran"
nl_ok "10 hostile requests refused with 400, nothing ran"
nl_api POST /system/users '{"username":"viewer","password":"Viewer-Passw0rd-1","role":"readonly"}'
[ "$NL_CODE" = 201 ] || nl_fail "create viewer: $NL_CODE"
rm -f "$NL_T/nl-jar"
nl_api POST /auth/login '{"username":"viewer","password":"Viewer-Passw0rd-1"}'
[ "$NL_CODE" = 200 ] || nl_fail "viewer login: $NL_CODE"
diag "{\"tool\":\"ping\",\"target\":\"$NL_WWW\",\"count\":1}"
[ "$NL_CODE" = 403 ] || nl_fail "read-only account ran a diagnostic: $NL_CODE"
nl_web GET /diagnostics
[ "$NL_CODE" = 200 ] || nl_fail "diagnostics page: $NL_CODE"
grep -F 'need an administrator' "$NL_OUT" >/dev/null || nl_fail "read-only page does not explain why"
nl_ok "read-only account: page explains, API answers 403"

nl_web_stop
nl_down
echo "lane-h-diag: all checks passed"
