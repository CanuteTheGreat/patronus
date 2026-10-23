#!/usr/bin/env bash
# Lane N: Traffic insights (the built-in alternative to ntopng). A LAN client
# talks to the "internet" hosts; the page API ranks hosts/services/protocols
# from the router's connection-tracking counters and reports the interfaces'
# traffic, and the page renders.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-insights.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
[ "$(R cat /proc/sys/net/netfilter/nf_conntrack_acct)" = 1 ] || nl_fail "patronus apply did not switch conntrack byte accounting on"
nl_ok "patronus apply enabled conntrack byte accounting (nf_conntrack_acct=1)"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_web GET /insights
[ "$NL_CODE" = 200 ] && grep -q "Traffic insights" "$NL_OUT" || nl_fail "page: $NL_CODE"
nl_expect_http "LAN client fetches www" "http://www.example.test/" ""
for _ in 1 2 3; do C curl -s -m 5 -o /dev/null "http://$NL_WWW/" || true; done
nl_wait 10 true
nl_api GET /insights
[ "$NL_CODE" = 200 ] || nl_fail "api: $NL_CODE $(cat "$NL_OUT")"
[ "$(jget 'd["accounting"]')" = True ] || nl_fail "no byte counters: $(cat "$NL_OUT")"
[ "$(jget 'd["top_hosts"][0]["host"]')" = "$NL_CLIENT" ] || nl_fail "the LAN client is not the top host: $(cat "$NL_OUT")"
[ "$(jget 'd["top_hosts"][0]["bytes"] > 0')" = True ] || nl_fail "no bytes counted: $(cat "$NL_OUT")"
[ "$(jget 'any(s["port"] == 80 and s["name"] == "http" for s in d["top_services"])')" = True ] || nl_fail "http not among the top services: $(cat "$NL_OUT")"
[ "$(jget 'd["protocols"][0]["proto"]')" = tcp ] || nl_fail "protocols: $(cat "$NL_OUT")"
nl_ok "top host $NL_CLIENT ($(jget 'd["top_hosts"][0]["bytes"]') bytes), http listed as a service, tcp the leading protocol"
[ "$(jget 'any(i["name"] == "rtr-lan" and i["rx_bytes"] > 0 for i in d["interfaces"])')" = True ] || nl_fail "interface counters: $(cat "$NL_OUT")"
nl_ok "interface counters for rtr-lan are reported"
echo "PASS lane-n-insights"
