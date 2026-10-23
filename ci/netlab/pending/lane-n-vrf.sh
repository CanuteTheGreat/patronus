#!/usr/bin/env bash
# Lane N: VRF segmentation in the shipped binary. A VRF with its own routing
# table is created from the API, a LAN interface joins it (the kernel device,
# its table and the enslaved port are checked), the interface's connected route
# moves out of the main table, a bad plan (shared table / unknown VRF) is
# refused, removing the member and the VRF cleans the kernel, and a reboot
# (`patronus apply`) brings it back from the store.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

if ! ip link add pat-vrf-probe type vrf table 999 2>/dev/null; then
  modprobe vrf 2>/dev/null || true
  if ! ip link add pat-vrf-probe type vrf table 999 2>/dev/null; then
    echo "SKIP lane-n-vrf: this host kernel has no VRF support (CONFIG_NET_VRF / vrf.ko missing); the VRF scenario needs a kernel with it"
    exit 0
  fi
fi
ip link del pat-vrf-probe 2>/dev/null || true

DB=/t/lane-n-vrf.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
nl_boot "$DB"
nl_web_start "$DB"; nl_login
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }

nl_api POST /svc/vrf/vrfs '{"name":"red","table_id":100}'
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "add VRF: $NL_CODE $(cat "$NL_OUT")"
nl_api POST /svc/vrf/vrfs '{"name":"blue","table_id":100}'
[ "$NL_CODE" = 400 ] || [ "$NL_CODE" = 500 ] || nl_fail "a shared routing table must be refused, got $NL_CODE"
nl_api GET /svc/vrf
[ "$(jget 'len(d["collections"]["vrfs"])')" = 1 ] || nl_fail "refused VRF was kept: $(cat "$NL_OUT")"
nl_api POST /svc/vrf/members '{"vrf":"nope","interface":"rtr-lan"}'
[ "$NL_CODE" = 400 ] || [ "$NL_CODE" = 500 ] || nl_fail "member of an unknown VRF must be refused, got $NL_CODE"
nl_ok "bad plans refused and rolled back"

R ip -4 route show | grep -q '192.168.50.0/24 dev rtr-lan' || nl_fail "precondition: connected LAN route in main"
nl_api POST /svc/vrf/members "{\"vrf\":\"red\",\"interface\":\"$NL_LAN_IF\"}"
[ "$NL_CODE" = 200 ] || [ "$NL_CODE" = 201 ] || nl_fail "add member: $NL_CODE $(cat "$NL_OUT")"
R ip -d link show vrf-red | grep -q 'vrf table 100' || { R ip -d link; nl_fail "no vrf-red device bound to table 100"; }
R ip link show $NL_LAN_IF | grep -q 'master vrf-red' || nl_fail "$NL_LAN_IF is not enslaved to vrf-red"
nl_ok "vrf-red (table 100) exists and $NL_LAN_IF is enslaved to it"
R ip -4 route show table 100 | grep -q '192.168.50.0/24' || { R ip route show table all; nl_fail "the connected route is not in the VRF table"; }
! R ip -4 route show table main | grep -q '192.168.50.0/24 dev rtr-lan' || nl_fail "the connected route is still in the main table"
nl_ok "the LAN's connected route lives in table 100, not in main"

echo "=== reboot"
nl_web_stop
nl_boot "$DB"
R ip link show $NL_LAN_IF | grep -q 'master vrf-red' || nl_fail "VRF membership lost after reboot"
nl_ok "after reboot the VRF and its member are back (patronus apply from the store)"

echo "=== removal"
nl_web_start "$DB"; nl_login
MID=$(sqlite3 "$DB" "SELECT id FROM vrf_members LIMIT 1"); VID=$(sqlite3 "$DB" "SELECT id FROM vrf_instances LIMIT 1")
nl_api DELETE /svc/vrf/members/$MID; [ "$NL_CODE" = 200 ] || nl_fail "delete member $NL_CODE"
R ip link show $NL_LAN_IF | grep -q 'master vrf-red' && nl_fail "member not released"
nl_api DELETE /svc/vrf/vrfs/$VID; [ "$NL_CODE" = 200 ] || nl_fail "delete VRF $NL_CODE"
! R ip link show vrf-red >/dev/null 2>&1 || nl_fail "vrf-red still exists"
nl_ok "member released, VRF device removed"
echo "PASS lane-n-vrf"
