#!/usr/bin/env bash
# Lane N: UPnP / NAT-PMP (off by default) in the shipped binary. Off: nothing
# listens and no firewall rule exists. Switched on from the UI/API, miniupnpd
# runs on the LAN side; a real UPnP client (upnpc) on the LAN asks for a port
# mapping and a host on the "internet" then reaches the LAN client through it;
# switching it off again removes the daemon and the rules.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-upnp.db
rm -f "$DB" "$NL_T/nl-jar"
export DEBIAN_FRONTEND=noninteractive
command -v miniupnpd >/dev/null || apt-get install -y -qq miniupnpd-nftables >/dev/null 2>&1 || apt-get install -y -qq miniupnpd >/dev/null
command -v upnpc >/dev/null || apt-get install -y -qq miniupnpc >/dev/null
command -v miniupnpd >/dev/null && command -v upnpc >/dev/null || nl_fail "miniupnpd/upnpc not installed"
pkill -x miniupnpd 2>/dev/null || true
# a daemon is running: not a zombie (the lab container has no init to reap them)
alive() { ps -eo stat=,comm= | awk -v n="$1" '$2 == n && $1 !~ /^Z/ { f = 1 } END { exit !f }'; }
export -f alive

nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api GET /svc/upnp; [ "$NL_CODE" = 200 ] || nl_fail "upnp page API: $NL_CODE"

! alive miniupnpd || nl_fail "miniupnpd runs although UPnP is off by default"
nl_assert_nft_lacks 5351
nl_ok "off by default: no daemon, no firewall rule"

nl_api PUT /svc/upnp '{"enabled":true,"ext_ip":"8.8.4.4","port_min":"1024","port_max":"65535"}'
[ "$NL_CODE" = 200 ] || nl_fail "enable UPnP: $NL_CODE $(cat "$NL_OUT")"
nl_wait 20 alive miniupnpd || nl_fail "miniupnpd did not start"
nl_assert_nft_has "udp dport { 1900, 5351 }"
nl_ok "enabled: miniupnpd runs, firewall opens SSDP/NAT-PMP/control on the LAN side"

# a LAN program asks for a mapping: WAN :9001 -> client :9000 (nl-tcp.py listens there)
UD="http://$NL_RTR_LAN:5000/rootDesc.xml"
nl_wait 15 C upnpc -u "$UD" -l || { C upnpc -u "$UD" -l || true; nl_fail "the UPnP client cannot talk to the router"; }
C upnpc -u "$UD" -a $NL_CLIENT 9000 9001 TCP >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "port mapping request failed"; }
nl_ok "client requested a mapping: $(grep -i 'is redirected\|external' "$NL_OUT" | head -1)"
# the internet host reaches the client through the router's WAN address
ISP ip route replace 192.168.50.0/24 via $NL_RTR_WAN 2>/dev/null || true
nl_expect_tcp "internet host -> WAN:9001 reaches the LAN client" INET $NL_RTR_WAN 9001

# secure mode: a client may not map somebody else's address
if C upnpc -u "$UD" -a 192.168.50.99 9000 9002 TCP >"$NL_OUT" 2>&1 && grep -qi "is redirected" "$NL_OUT"; then nl_fail "secure mode let a client map another host's address"; fi
nl_ok "secure mode refused a mapping for another host's address"

echo "=== switch off"
nl_api PUT /svc/upnp '{"enabled":false}'
[ "$NL_CODE" = 200 ] || nl_fail "disable: $NL_CODE"
nl_wait 20 bash -c '! alive miniupnpd' || nl_fail "miniupnpd still running after switching off"
nl_assert_nft_lacks "UPnP"
nl_ok "off again: daemon stopped, rules gone"
echo "PASS lane-n-upnp"
