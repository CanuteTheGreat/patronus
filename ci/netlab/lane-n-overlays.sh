#!/usr/bin/env bash
# Lane N: GRE and VXLAN overlay links (Interfaces > Overlays). Created through
# POST /api/interfaces/overlays, addressed through PUT /api/interfaces/:name,
# and proven with real traffic: the LAN "client" namespace terminates the
# other end of each tunnel by hand, and a ping across the inner /30 only
# works if the router's kernel really built the tunnel (key / VNI included).
#
#   rtr gre-t0 10.99.0.1/30 ==GRE key 7== client gre-peer 10.99.0.2/30
#   rtr vx-t0  10.98.0.1/30 ==VXLAN 100== client vx-peer  10.98.0.2/30
#
# Also: bad input is refused (400), changing the key/VNI recreates the
# device, the links come back after a reboot from `patronus apply` alone, a
# delete removes the kernel device.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-overlays.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml

peers() { # the far ends, built by hand in the client namespace
  C ip link del gre-peer 2>/dev/null || true
  C ip link del vx-peer 2>/dev/null || true
  C ip link add gre-peer type gre local $NL_CLIENT remote $NL_RTR_LAN key "$1"
  C ip addr add 10.99.0.2/30 dev gre-peer; C ip link set gre-peer up
  C ip link add vx-peer type vxlan id 100 remote $NL_RTR_LAN local $NL_CLIENT dstport 4789
  C ip addr add 10.98.0.2/30 dev vx-peer; C ip link set vx-peer up
}

nl_boot "$DB"
nl_web_start "$DB"; nl_login

echo "=== validation"
nl_api_code "unknown type" 400 POST /interfaces/overlays '{"name":"o1","kind":"ipip","remote":"192.168.50.10"}'
nl_api_code "bad remote" 400 POST /interfaces/overlays '{"name":"o1","kind":"gre","remote":"not-an-ip"}'
nl_api_code "vxlan without VNI" 400 POST /interfaces/overlays '{"name":"o1","kind":"vxlan","remote":"192.168.50.10"}'
nl_api_code "VNI out of range" 400 POST /interfaces/overlays '{"name":"o1","kind":"vxlan","remote":"192.168.50.10","key":16777216}'
nl_api_code "mixed families" 400 POST /interfaces/overlays '{"name":"o1","kind":"vxlan","remote":"192.168.50.10","local":"fd00::1","key":5}'
nl_api_code "port on GRE" 400 POST /interfaces/overlays '{"name":"o1","kind":"gre","remote":"192.168.50.10","port":4789}'
nl_api_code "delete unknown" 400 DELETE /interfaces/overlays/nope
nl_ok "bad type, address, VNI, family mix and a GRE port are refused (400)"

echo "=== GRE and VXLAN carry traffic"
peers 7
nl_api_ok "add GRE" POST /interfaces/overlays '{"name":"gre-t0","kind":"gre","local":"192.168.50.1","remote":"192.168.50.10","key":7,"ttl":64,"description":"to branch"}'
nl_api_ok "add VXLAN" POST /interfaces/overlays '{"name":"vx-t0","kind":"vxlan","local":"192.168.50.1","remote":"192.168.50.10","key":100}'
nl_api_ok "address GRE" PUT /interfaces/gre-t0 '{"ipv4_mode":"static","ipv4":["10.99.0.1/30"]}'
nl_api_ok "address VXLAN" PUT /interfaces/vx-t0 '{"ipv4_mode":"static","ipv4":["10.98.0.1/30"]}'
R ip -d link show gre-t0 | grep -q 'gre remote 192.168.50.10 local 192.168.50.1' || { R ip -d link show gre-t0 || true; nl_fail "no GRE device with those endpoints in the kernel"; }
R ip -d link show vx-t0 | grep -q 'vxlan.* id 100' || { R ip -d link show vx-t0 || true; nl_fail "no VXLAN device with VNI 100 in the kernel"; }
R ping -c3 -W2 10.99.0.2 >/dev/null 2>&1 || { R ip -d addr show gre-t0 || true; nl_fail "no reply across the GRE tunnel"; }
R ping -c3 -W2 10.98.0.2 >/dev/null 2>&1 || { R ip -d addr show vx-t0 || true; nl_fail "no reply across the VXLAN tunnel"; }
nl_ok "ping crosses the GRE tunnel (key 7) and the VXLAN overlay (VNI 100)"
nl_api GET /interfaces
[ "$(nl_json "$NL_OUT" 'sorted(o["name"] for o in d["overlays"])')" = "['gre-t0', 'vx-t0']" ] || nl_fail "overview does not list both overlays: $(cat "$NL_OUT")"
nl_web GET /interfaces
[ "$NL_CODE" = 200 ] && grep -q 'overlay-form' "$NL_OUT" || nl_fail "Interfaces page has no overlay form ($NL_CODE)"
nl_ok "the overlays are listed by the API and the Interfaces page has the form"

echo "=== changing the key recreates the tunnel"
nl_api_ok "new GRE key" POST /interfaces/overlays '{"name":"gre-t0","kind":"gre","local":"192.168.50.1","remote":"192.168.50.10","key":8,"ttl":64}'
R ip -d link show gre-t0 | grep -Eq 'key (8|0\.0\.0\.8)' || { R ip -d link show gre-t0 || true; nl_fail "the kernel GRE device kept the old key"; }
if R ping -c2 -W1 10.99.0.2 >/dev/null 2>&1; then nl_fail "ping still works with mismatched GRE keys"; fi
C ip link set gre-peer type gre key 8 2>/dev/null || { C ip link del gre-peer; C ip link add gre-peer type gre local $NL_CLIENT remote $NL_RTR_LAN key 8; C ip addr add 10.99.0.2/30 dev gre-peer; C ip link set gre-peer up; }
R ping -c3 -W2 10.99.0.2 >/dev/null 2>&1 || nl_fail "no reply after the peer took the new key"
nl_ok "key 7 -> 8: traffic stops with mismatched keys and returns when the peer matches; the address survived the recreate"

echo "=== the links come back after a reboot"
nl_web_stop
nl_boot "$DB"
peers 8
nl_web_start "$DB"; nl_login
R ping -c3 -W2 10.99.0.2 >/dev/null 2>&1 || nl_fail "GRE did not come back from patronus apply"
R ping -c3 -W2 10.98.0.2 >/dev/null 2>&1 || nl_fail "VXLAN did not come back from patronus apply"
nl_ok "after a reboot 'patronus apply' alone rebuilds both tunnels and their addresses"

echo "=== delete"
nl_api_ok "delete GRE" DELETE /interfaces/overlays/gre-t0
nl_api_ok "delete VXLAN" DELETE /interfaces/overlays/vx-t0
if R ip link show gre-t0 >/dev/null 2>&1; then nl_fail "gre-t0 is still in the kernel after delete"; fi
if R ip link show vx-t0 >/dev/null 2>&1; then nl_fail "vx-t0 is still in the kernel after delete"; fi
nl_api GET /interfaces
[ "$(nl_json "$NL_OUT" 'len(d["overlays"])')" = 0 ] || nl_fail "overlays still listed"
nl_ok "both overlays are gone from the kernel and the API"
nl_web_stop
echo "ALL OVERLAY CHECKS PASSED"
