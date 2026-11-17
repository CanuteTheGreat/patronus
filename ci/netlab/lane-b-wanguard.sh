#!/usr/bin/env bash
# Lane B: WAN source checks ("block private networks" / "block bogon
# networks" on the WAN). Real traffic through a port forward from the ISP
# side with chosen source addresses. Proves:
#   - off (default): a port forward is reachable from a bogon source (the lab
#     ISP is 203.0.113.1, TEST-NET-3) and from a private one;
#   - bogons on: new connections from 203.0.113.1 die, the LAN still reaches
#     the internet (answers from 198.51.100.10 are established traffic), the
#     router still pings its gateway; private sources still pass;
#   - private on: 10.99.0.5 and 100.64.1.1 die, 203.0.113.1 passes again;
#   - drops show in the firewall log; the settings survive a reboot;
#   - turning both off removes the guard from the ruleset.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-wanguard.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml

cat > "$NL_T/wg-conn.py" <<'EOF'
# connect HOST PORT [SOURCE]: print what the server saw (its first line)
import socket, sys
s = socket.socket(); s.settimeout(3)
if len(sys.argv) > 3: s.bind((sys.argv[3], 0))
s.connect((sys.argv[1], int(sys.argv[2])))
print(s.recv(200).decode().strip())
EOF
reach() { # DESC SOURCE: the forward reaches the LAN host from SOURCE
  local out
  out=$(ISP python3 "$NL_T/wg-conn.py" $NL_RTR_WAN 8022 "$2" 2>&1) || nl_fail "$1: expected reachable, got $out"
  [ "$out" = "$2" ] || nl_fail "$1: LAN host saw $out, want $2"
  nl_ok "$1 (LAN host saw $2)"
}
blocked() { # DESC SOURCE
  local out
  if out=$(ISP python3 "$NL_T/wg-conn.py" $NL_RTR_WAN 8022 "$2" 2>&1); then nl_fail "$1: expected dropped, got $out"; fi
  case "$out" in *"timed out"*) ;; *) nl_fail "$1: expected a silent drop, got $out" ;; esac
  nl_ok "$1 (dropped)"
}
guard() { nl_api_ok "wan guard $1" PUT /firewall/wan-guard "$1"; }
sources() {
  ISP ip addr add 10.99.0.5/32 dev up0 2>/dev/null || true
  ISP ip addr add 100.64.1.1/32 dev up0 2>/dev/null || true
}

echo "=== off by default"
nl_boot "$DB"; sources
nl_web_start "$DB"; nl_login
nl_api_ok "port forward" POST /firewall/nat '{"name":"wg-pf","rule_type":"DNAT","interface":"@wan","protocol":"tcp","external_port":"8022","target":"192.168.50.10:9000","description":"wg-pf","enabled":true}'
nl_api GET /firewall/wan-guard
[ "$(nl_json "$NL_OUT" 'd["block_private"] or d["block_bogons"]')" = False ] || nl_fail "guard is on by default: $(cat "$NL_OUT")"
nl_assert_nft_lacks wan_guard
reach "off: bogon source 203.0.113.1 -> forward" 203.0.113.1
reach "off: private source 10.99.0.5 -> forward" 10.99.0.5

echo "=== bogons on"
guard '{"block_private":false,"block_bogons":true}'
nl_assert_nft_has "jump wan_guard" "saddr @wan_bogon4" "udp sport 67 udp dport 68 return"
nl_assert_nft_lacks wan_private4
blocked "bogons on: 203.0.113.1 -> forward" 203.0.113.1
reach "bogons on: private 10.99.0.5 still passes" 10.99.0.5
nl_expect_tcp "bogons on: LAN -> internet host 198.51.100.10 (answers are established)" C $NL_WWW 9000
R ping -c1 -W2 203.0.113.1 >/dev/null || nl_fail "bogons on: the router cannot ping its gateway"
nl_ok "bogons on: the router still pings its gateway"

echo "=== private on"
guard '{"block_private":true,"block_bogons":false}'
nl_assert_nft_has "saddr @wan_private4"
nl_assert_nft_lacks wan_bogon4
blocked "private on: 10.99.0.5 -> forward" 10.99.0.5
blocked "private on: CGNAT 100.64.1.1 -> forward" 100.64.1.1
reach "private on: 203.0.113.1 passes again" 203.0.113.1
logged() { nl_api GET '/firewall/logs?q=wan-private&minutes=10'; grep -F '10.99.0.5' "$NL_OUT" >/dev/null; }
nl_wait 20 logged || nl_fail "the WAN-private drop is not in the firewall log: $(head -c 600 "$NL_OUT")"
nl_ok "the drop of 10.99.0.5 is in the firewall log"
nl_web_stop

echo "=== reboot keeps it"
nl_boot "$DB"; sources
nl_assert_nft_has "saddr @wan_private4"
blocked "after reboot: 10.99.0.5 still dropped" 10.99.0.5
reach "after reboot: 203.0.113.1 passes" 203.0.113.1

echo "=== both off"
nl_web_start "$DB"; nl_login
guard '{"block_private":false,"block_bogons":false}'
nl_assert_nft_lacks wan_guard
reach "off again: 10.99.0.5 -> forward" 10.99.0.5
nl_web_stop
nl_down
echo "PASS lane-b-wanguard"
