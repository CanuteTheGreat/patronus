#!/usr/bin/env bash
# Lane N: web proxy (Squid) in the shipped binary. Enabled from the API, a LAN
# client fetches a page through the proxy on the router (and the origin sees the
# router's WAN address); a blocked domain answers 403; with interception on, a
# plain HTTP request from the LAN goes through the proxy without client config;
# a host on the WAN side cannot use the proxy; switching off stops squid.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-proxy.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v squid >/dev/null || apt-get install -y -qq squid >/dev/null
command -v squid >/dev/null || nl_fail "squid not installed"
pkill -x squid 2>/dev/null || true
# a daemon is running: not a zombie (the lab container has no init to reap them)
alive() { ps -eo stat=,comm= | awk -v n="$1" '$2 == n && $1 !~ /^Z/ { f = 1 } END { exit !f }'; }
export -f alive
# the router's resolver in its own namespace: the lab DNS
mkdir -p /etc/netns/nl-rtr; echo "nameserver $NL_DNS" > /etc/netns/nl-rtr/resolv.conf

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

# the LAN port needs a static address for the proxy to bind to
nl_api PUT /interfaces/$NL_LAN_IF "{\"role\":\"lan\",\"ipv4_mode\":\"static\",\"ipv4\":[\"$NL_RTR_LAN/24\"],\"ipv6_mode\":\"none\",\"force\":true}"
[ "$NL_CODE" = 200 ] || nl_fail "LAN address: $NL_CODE $(cat "$NL_OUT")"

nl_api POST /svc/proxy/blocked '{"domain":"blocked.example.test"}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "block domain: $NL_CODE $(cat "$NL_OUT")"
nl_api PUT /svc/proxy '{"enabled":true,"transparent":true,"port":"3128"}'
[ "$NL_CODE" = 200 ] || nl_fail "enable proxy: $NL_CODE $(cat "$NL_OUT")"
nl_wait 30 R sh -c "ss -ltn | grep -q ':3128 '" || { R ss -ltnp || true; nl_fail "squid is not listening on 3128"; }
nl_ok "squid listening on the LAN address"

out=$(C curl -s --max-time 40 -x http://$NL_RTR_LAN:3128 http://$NL_WWW/) || { C curl -sv --max-time 40 -x http://$NL_RTR_LAN:3128 http://$NL_WWW/ 2>&1 | tail -15; R ss -ltnp; nl_fail "fetch through the proxy failed"; }
grep -q "sees $NL_RTR_WAN" <<<"$out" || nl_fail "origin did not see the router's WAN address: $out"
nl_ok "LAN client fetched through the proxy: $out"
code=$(C curl -s -o /dev/null -w '%{http_code}' --max-time 40 -x http://$NL_RTR_LAN:3128 http://blocked.example.test/ || true)
[ "$code" = 403 ] || nl_fail "blocked domain answered $code, want 403"
nl_ok "blocked domain -> 403"

# interception: no proxy configured at the client, TCP 80 to another host is redirected
nl_assert_nft_has "redirect to :3129"
out=$(C curl -s --max-time 40 http://$NL_WWW/) || nl_fail "intercepted fetch failed"
grep -q "sees $NL_RTR_WAN" <<<"$out" || nl_fail "intercepted request: $out"
code=$(C curl -s -o /dev/null -w '%{http_code}' --max-time 40 --resolve blocked.example.test:80:$NL_BLOCKED http://blocked.example.test/ || true)
[ "$code" = 403 ] || nl_fail "intercepted blocked domain answered $code"
nl_ok "interception: plain HTTP from the LAN goes through the proxy (blocked -> 403)"

# not an open proxy: the WAN side cannot use it
nl_expect_no_tcp "WAN -> proxy port" ISP $NL_RTR_WAN 3128

echo "=== switch off"
nl_api PUT /svc/proxy '{"enabled":false}'
[ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE"
nl_wait 20 bash -c '! alive squid' || nl_fail "squid still running"
nl_assert_nft_lacks "web proxy"
nl_ok "off: squid stopped, rules gone"
echo "PASS lane-n-proxy"
