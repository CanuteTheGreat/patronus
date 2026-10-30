#!/usr/bin/env bash
# Lane J: dynamic routing with FRR (USE=dynamic-routing). The BGP/OSPF page
# writes /etc/frr/frr.conf + /etc/frr/daemons and (re)starts FRR in the router
# namespace; a second, independent FRR (zebra + bgpd + ospfd with its own path
# space) in the ISP namespace is the peer. Proof in both kernels: the router
# learns 198.18.0.0/24 from the ISP over BGP and the ISP learns the LAN
# 192.168.50.0/24 from the router (a LAN client then pings the ISP's loopback
# prefix through the learned route); removing a network withdraws it; OSPF on the
# WAN interface forms a Full adjacency; reboot and disable are checked.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-j-frr.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml

frr_kill() { for n in watchfrr zebra bgpd ospfd staticd; do pkill -x "$n" 2>/dev/null || true; done; sleep 1; rm -rf /run/frr/peer /run/frr/*.pid /run/frr/*.vty /run/frr/zserv.api /var/run/frr/*.pid 2>/dev/null || true; }
frr_kill
nl_kill_daemons nothing
rm -f /etc/frr/frr.conf.pre-patronus
getent passwd frr >/dev/null || nl_fail "the frr package did not create the frr user"
mkdir -p /etc/frr /run/frr /var/log/frr
chown frr:frr /run/frr /var/log/frr
[ -f /etc/frr/frr.conf ] || { echo 'hostname stock' > /etc/frr/frr.conf; chown frr:frr /etc/frr/frr.conf; }
[ -f /etc/frr/vtysh.conf ] || { echo 'service integrated-vtysh-config' > /etc/frr/vtysh.conf; chown frr:frrvty /etc/frr/vtysh.conf 2>/dev/null || true; }
cp -a /etc/frr/frr.conf /t/stock-frr.conf

# --- the peer: independent FRR in the ISP namespace (own path space "peer")
peer_up() {
  mkdir -p /etc/frr/peer /run/frr/peer
  cat > /etc/frr/peer/frr.conf <<EOF
frr defaults traditional
hostname peer
log file /var/log/frr/peer.log
!
interface up0
 ip ospf area 0.0.0.0
!
interface lo
 ip ospf area 0.0.0.0
!
router bgp 65000
 bgp router-id 203.0.113.1
 no bgp ebgp-requires-policy
 neighbor 203.0.113.2 remote-as 65001
 !
 address-family ipv4 unicast
  network 198.18.0.0/24
 exit-address-family
!
router ospf
 ospf router-id 203.0.113.1
!
line vty
EOF
  chown -R frr:frr /etc/frr/peer /run/frr/peer
  ISP ip addr add 198.18.0.1/24 dev lo 2>/dev/null || true
  for d in zebra bgpd ospfd; do
    ISP /usr/lib/frr/$d -d -N peer -f /etc/frr/peer/frr.conf -i /run/frr/peer/$d.pid -A 127.0.0.1 >>/tmp/peer-$d.log 2>&1 || { cat /tmp/peer-$d.log; nl_fail "peer $d did not start"; }
    sleep 1
  done
}
peer_routes() { ISP ip route show proto bgp; }
router_bgp_routes() { R ip route show proto bgp; }

nl_boot "$DB"
peer_up
nl_web_start "$DB"; nl_login

echo "=== validation"
nl_api_code "BGP without a router id" 400 PUT /svc/frr '{"bgp_enabled":true}'
nl_api_code "bad neighbour" 400 POST /svc/frr/bgp_neighbors '{"address":"x","remote_as":1}'
nl_api_code "AS 0" 400 POST /svc/frr/bgp_neighbors '{"address":"203.0.113.1","remote_as":0}'
nl_api_code "bad OSPF interface" 400 POST /svc/frr/ospf_interfaces '{"iface":"wan;x"}'
nl_ok "BGP without a router ID, bad neighbour addresses, AS 0 and bad OSPF interfaces are refused (400)"
[ "$(cat /etc/frr/frr.conf)" = "$(cat /t/stock-frr.conf)" ] || nl_fail "frr.conf changed with BGP off"

echo "=== BGP: neighbour = the ISP, announce the LAN"
nl_api_code "BGP with nothing to do" 400 PUT /svc/frr "{\"bgp_enabled\":true,\"bgp_asn\":65001,\"router_id\":\"$NL_RTR_WAN\"}"
nl_api_ok "neighbour" POST /svc/frr/bgp_neighbors '{"address":"203.0.113.1","remote_as":65000,"description":"isp"}'
NID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_ok "network" POST /svc/frr/bgp_networks '{"prefix":"192.168.50.0/24"}'
GID=$(nl_json "$NL_OUT" 'd["id"]')
nl_api_ok "enable BGP" PUT /svc/frr "{\"bgp_enabled\":true,\"bgp_asn\":65001,\"router_id\":\"$NL_RTR_WAN\"}"
grep -q 'router bgp 65001' /etc/frr/frr.conf && grep -q 'neighbor 203.0.113.1 remote-as 65000' /etc/frr/frr.conf && grep -q 'network 192.168.50.0/24' /etc/frr/frr.conf \
  || { cat /etc/frr/frr.conf; nl_fail "frr.conf lacks the BGP config"; }
[ -f /etc/frr/frr.conf.pre-patronus ] || nl_fail "the hand-written frr.conf was not kept"
grep -q '^bgpd=yes' /etc/frr/daemons || nl_fail "bgpd not enabled in /etc/frr/daemons"
nl_ok "wrote /etc/frr/frr.conf and daemons (bgpd=yes); the previous frr.conf is kept as frr.conf.pre-patronus"
nl_wait 30 pgrep -x bgpd || nl_fail "FRR (bgpd) did not start in the router namespace"
nl_wait 90 bash -c "R ip route show proto bgp | grep '198.18.0.0/24' >/dev/null" || { R vtysh -c 'show bgp summary' || true; tail -20 /var/log/frr/*.log 2>/dev/null; nl_fail "the router never learned 198.18.0.0/24 over BGP"; }
nl_ok "router kernel learned over BGP: $(router_bgp_routes | head -1)"
nl_wait 60 bash -c "ISP ip route show proto bgp | grep '192.168.50.0/24' >/dev/null" || { ISP vtysh -N peer -c 'show bgp summary' || true; nl_fail "the ISP never learned the LAN prefix"; }
nl_ok "ISP kernel learned the announced LAN prefix: $(peer_routes | head -1)"
nl_assert_nft_has "ip saddr 203.0.113.1 tcp dport 179 accept"
C ping -c 3 -W 2 198.18.0.1 >/dev/null || nl_fail "the LAN client cannot reach the ISP prefix through the BGP-learned route"
nl_ok "LAN client pings 198.18.0.1 (only reachable through the BGP route)"
nl_api GET /svc/frr
python3 - "$NL_OUT" <<'PY' || nl_fail "status does not show an Established session"
import json, sys
st = json.load(open(sys.argv[1]))["status"]
assert st["installed"] and st["running"] and st["bgp_enabled"], st
s = [x for x in st["bgp_sessions"] if x["peer"] == "203.0.113.1"]
assert s and s[0]["state"] == "Established" and s[0]["prefixes_received"] >= 1, st["bgp_sessions"]
assert any("198.18.0.0/24" in r for r in st["kernel_bgp_routes"]), st
PY
nl_ok "status: session to 203.0.113.1 Established, prefixes received, kernel BGP route listed"
nl_web GET /svc/frr
[ "$NL_CODE" = 200 ] && grep -q 'svc-settings-form' "$NL_OUT" || nl_fail "BGP/OSPF page: $NL_CODE"
nl_api GET /svc/frr; grep -q 'md5' "$NL_OUT" && nl_fail "secret leaked"

echo "=== withdrawing the network removes it from the ISP"
nl_api_ok "delete network" DELETE "/svc/frr/bgp_networks/$GID"
nl_wait 60 bash -c "! ISP ip route show proto bgp | grep '192.168.50.0/24' >/dev/null" || nl_fail "the ISP still has the withdrawn prefix"
nl_ok "after deleting the network the ISP no longer has 192.168.50.0/24"

echo "=== OSPF on the WAN interface (the ISP side runs ospfd)"
nl_api_ok "ospf interface" POST /svc/frr/ospf_interfaces '{"iface":"@wan","area":"0.0.0.0"}'
nl_api_ok "enable ospf" PUT /svc/frr '{"ospf_enabled":true}'
grep -q '^ospfd=yes' /etc/frr/daemons && grep -q 'ip ospf area 0.0.0.0' /etc/frr/frr.conf || nl_fail "OSPF not in the generated config"
nl_wait 90 bash -c "R vtysh -c 'show ip ospf neighbor' | grep Full >/dev/null" || { R vtysh -c 'show ip ospf neighbor' || true; ISP vtysh -N peer -c 'show ip ospf neighbor' || true; nl_fail "no Full OSPF adjacency with the ISP"; }
nl_ok "OSPF adjacency Full with the ISP router"
# (the prefix also arrives over BGP, which wins in the kernel with its lower distance: ask OSPF's own table)
nl_wait 60 bash -c "R vtysh -c 'show ip ospf route' | grep '198\.18\.0\.' >/dev/null" || { R vtysh -c 'show ip ospf route' || true; nl_fail "the router did not learn the ISP prefix over OSPF"; }
nl_ok "OSPF learned the ISP loopback network (198.18.0.x): $(R vtysh -c 'show ip ospf route' | grep '198\.18\.0\.' | head -1)"

echo "=== reboot: patronus apply restarts FRR with the same config"
nl_web_stop
frr_kill
nl_boot "$DB"
peer_up
nl_wait 30 pgrep -x bgpd || nl_fail "FRR not started by the boot apply"
nl_wait 90 bash -c "R ip route show proto bgp | grep '198.18.0.0/24' >/dev/null" || nl_fail "BGP route not relearned after the reboot"
nl_ok "after reboot: BGP session back, route relearned"

echo "=== disable"
nl_web_start "$DB"; nl_login
nl_api_ok "disable ospf" PUT /svc/frr '{"ospf_enabled":false}'
nl_api_ok "disable bgp" PUT /svc/frr '{"bgp_enabled":false}'
nl_wait 30 bash -c "! R ip route show proto bgp | grep . >/dev/null" || nl_fail "BGP routes still in the router kernel"
grep -q 'router bgp' /etc/frr/frr.conf && nl_fail "router bgp still in frr.conf"
nl_ok "disabled: the BGP/OSPF routes left the router kernel, frr.conf has no routing protocol"
nl_web_stop
frr_kill
echo "ALL FRR CHECKS PASSED"
