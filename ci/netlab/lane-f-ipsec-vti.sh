#!/usr/bin/env bash
# Lane F: route-based IPsec (XFRM interfaces) between two routers, with OSPF over the tunnel.
#
#   LAN client 192.168.50.10 -- router A (Patronus, 203.0.113.2) --- isp --- router B (198.18.0.2) -- 10.2.0.0/24
#
# Router A is Patronus. Router B is a plain strongSwan + FRR in its own namespace
# (an independent implementation, like the road-warrior client of lane-f-ipsec-rw.sh).
# - A route-based tunnel (mode "route") is created through the API: Patronus creates
#   the XFRM interface xfrm1, gives it its address and MTU, binds the child SA to it
#   (if_id_in/if_id_out) and opens the firewall for it.
# - The LAN client reaches B's LAN only over the XFRM interface: a static route first, then
#   OSPF (FRR on both routers, point-to-point over the tunnel) learns the LAN prefixes.
# - The VPN page shows the SA with its byte counters, the kernel security policies and the
#   XFRM interface; Disconnect / Connect take the tunnel down and up again, and the OSPF
#   adjacency and the learned route follow it.
# - Reboot: the interface, the SA and the routes come back from the store; deleting the tunnel
#   removes the interface, the swanctl entry, the charon setting and the firewall rules.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-f-vti.db
rm -f "$DB" "$NL_T/nl-jar"
nl_write_installer_toml
BD=/t/vti-b
rm -rf "$BD"; mkdir -p "$BD/swanctl" /run/frr/b /etc/frr/b
PSK=vti-lane-pre-shared-key-0123456789

api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")";; esac; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
B() { ip netns exec nl-b "$@"; }

frr_kill() {
  for n in watchfrr zebra bgpd ospfd staticd; do pkill -x "$n" 2>/dev/null || true; done
  sleep 1; rm -rf /run/frr/b/* /run/frr/*.pid /run/frr/*.vty /run/frr/zserv.api 2>/dev/null || true
}
cleanup() { frr_kill; [ -s /tmp/charon-rtr.pid ] && { kill "$(cat /tmp/charon-rtr.pid)" 2>/dev/null || true; }; ip netns del nl-b 2>/dev/null || true; }
frr_kill
trap cleanup EXIT
nl_kill_daemons nothing
rm -f /etc/frr/frr.conf.pre-patronus

# --- FRR as a service Patronus can restart (same shim as lane-j-frr.sh)
getent passwd frr >/dev/null || nl_fail "the frr package did not create the frr user"
mkdir -p /etc/frr /run/frr /var/log/frr /etc/init.d
if [ ! -e /etc/init.d/frr ]; then
  cat > /etc/init.d/frr <<'EOF'
#!/bin/sh
case "$1" in
  start|restart|stop|reload|force-reload) /usr/lib/frr/frrinit.sh "$@" </dev/null >>/var/log/frr/initscript.log 2>&1 ;;
  *) /usr/lib/frr/frrinit.sh "$@" </dev/null ;;
esac
EOF
  chmod 755 /etc/init.d/frr
fi
chown frr:frr /run/frr /var/log/frr /run/frr/b /etc/frr/b
[ -f /etc/frr/frr.conf ] || { echo 'hostname stock' > /etc/frr/frr.conf; chown frr:frr /etc/frr/frr.conf; }
[ -f /etc/frr/vtysh.conf ] || { echo 'service integrated-vtysh-config' > /etc/frr/vtysh.conf; chown frr:frrvty /etc/frr/vtysh.conf 2>/dev/null || true; }

# --- router A's charon (the init script the IPsec applier starts/stops it with)
cat > /etc/init.d/strongswan <<'EOF'
#!/bin/sh
P=/tmp/charon-rtr.pid
up() { [ -s $P ] && kill -0 "$(cat $P)" 2>/dev/null; }
case "$1" in
  start) up || { setsid /usr/sbin/charon-systemd </dev/null >/t/charon-rtr.log 2>&1 & echo $! > $P; sleep 1; } ;;
  stop) up && kill "$(cat $P)"; rm -f $P; sleep 1 ;;
  restart) $0 stop; $0 start ;;
  status) up && echo started || echo stopped ;;
esac
exit 0
EOF
chmod +x /etc/init.d/strongswan
rm -f /etc/strongswan.d/patronus-routes.conf

# --- router B: namespace behind the ISP, its own charon, its own FRR
cat > "$BD/strongswan.conf" <<'EOF'
include /etc/strongswan.conf
charon-systemd {
    install_routes = no
    plugins {
        vici {
            socket = unix:///run/charon-b.vici
        }
    }
}
EOF
BS() { # swanctl against B's charon with B's own /etc/swanctl
  ip netns exec nl-b unshare -m --propagation private sh -c \
    'mount --bind /t/vti-b/swanctl /etc/swanctl && exec swanctl "$@" --uri unix:///run/charon-b.vici' sh "$@"
}
b_conf() { # NAME
  cat > "$BD/swanctl/swanctl.conf" <<EOF
connections {
  toa {
    version = 2
    local_addrs = 198.18.0.2
    remote_addrs = 203.0.113.2
    proposals = aes256gcm16-prfsha384-ecp384
    local { auth = psk
      id = 198.18.0.2 }
    remote { auth = psk
      id = 203.0.113.2 }
    children {
      vti {
        local_ts = 0.0.0.0/0,::/0
        remote_ts = 0.0.0.0/0,::/0
        if_id_in = 1
        if_id_out = 1
        esp_proposals = aes256gcm16-ecp384
        start_action = none
      }
    }
  }
}
secrets {
  ike-a { id-1 = 198.18.0.2
    id-2 = 203.0.113.2
    secret = "$PSK" }
}
EOF
}
b_up() {
  ip netns del nl-b 2>/dev/null || true
  ip netns add nl-b; ip -n nl-b link set lo up
  ip link add bisp netns nl-isp type veth peer name b0 netns nl-b
  ISP ip addr add 198.18.0.1/24 dev bisp; ISP ip link set bisp up
  ip -n nl-b addr add 198.18.0.2/24 dev b0; ip -n nl-b link set b0 up
  ip -n nl-b route add default via 198.18.0.1
  # B's LAN
  ip -n nl-b link add blan type dummy; ip -n nl-b addr add 10.2.0.1/24 dev blan; ip -n nl-b link set blan up
  # B's end of the XFRM interface (if_id 1), point-to-point address plan 10.255.0.0/30
  ip -n nl-b link add xfrm1 type xfrm dev lo if_id 1
  ip -n nl-b addr add 10.255.0.2/30 dev xfrm1
  ip -n nl-b link set xfrm1 multicast on; ip -n nl-b link set xfrm1 mtu 1400 up
  B sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  b_conf
  ip netns exec nl-b env STRONGSWAN_CONF=$BD/strongswan.conf /usr/sbin/charon-systemd </dev/null >/t/charon-b.log 2>&1 &
  NL_PIDS+=($!)
  for _ in $(seq 1 40); do BS --stats >/dev/null 2>&1 && break; sleep 0.25; done
  BS --stats >/dev/null 2>&1 || { cat /t/charon-b.log; nl_fail "router B's charon did not start"; }
  BS --load-all --noprompt >/dev/null 2>&1 || { cat "$BD/swanctl/swanctl.conf"; nl_fail "router B cannot load its swanctl config"; }
}
b_ospf() {
  cat > /etc/frr/b/frr.conf <<'EOF'
frr defaults traditional
hostname routerb
log file /var/log/frr/b.log
!
interface xfrm1
 ip ospf area 0.0.0.0
 ip ospf network point-to-point
!
router ospf
 ospf router-id 10.255.0.2
 redistribute connected
!
line vty
EOF
  chown -R frr:frr /etc/frr/b /run/frr/b
  for d in zebra ospfd; do
    B /usr/lib/frr/$d -d -N b -f /etc/frr/b/frr.conf -i /run/frr/b/$d.pid -A 127.0.0.1 >>/tmp/b-$d.log 2>&1 || { cat /tmp/b-$d.log; nl_fail "router B: $d did not start"; }
    sleep 1
  done
}
boot() {
  [ -s /tmp/charon-rtr.pid ] && { kill "$(cat /tmp/charon-rtr.pid)" 2>/dev/null || true; }
  sleep 0.5; rm -f /tmp/charon-rtr.pid /run/charon.vici
  frr_kill
  nl_up; b_up
  nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
  nl_ok "boot: patronus apply"
}
sa_state() { local o; o=$(swanctl --list-sas 2>/dev/null || true); grep -q 'ESTABLISHED' <<<"$o"; }
no_sa() { ! sa_state; }
ospf_full() { local o; o=$(R vtysh -c 'show ip ospf neighbor' 2>/dev/null || true); grep -q 'Full' <<<"$o"; }
ospf_gone() { ! ospf_full; }
ospf_route() { local o; o=$(R ip route show proto ospf 2>/dev/null || true); grep -q '10.2.0.0/24 .*dev xfrm1' <<<"$o"; }
no_ospf_route() { ! ospf_route; }
ping_b() { R ping -c1 -W2 10.255.0.2 >/dev/null 2>&1; }
b_has_lan() { local o; o=$(B ip route show proto ospf 2>/dev/null || true); grep -q '192.168.50.0/24' <<<"$o"; }
page_has() { nl_web GET /vpn; [ "$NL_CODE" = 200 ] && grep -qF -- "$1" "$NL_OUT"; }

boot
nl_web_start "$DB"; nl_login

echo "=== validation"
for body in \
  '{"name":"x","remote_address":"198.18.0.2","mode":"vti"}' \
  '{"name":"x","remote_address":"198.18.0.2","mode":"route","tunnel_address":"10.255.0.1"}' \
  '{"name":"x","remote_address":"198.18.0.2","mode":"route","mtu":100}' \
  '{"name":"x","remote_address":"198.18.0.2","mode":"route","xfrm_dev":"bad dev"}' \
  '{"name":"x","remote_address":"198.18.0.2","mode":"policy"}'; do
  nl_api POST /vpn/ipsec/connections "$body"
  [ "$NL_CODE" = 400 ] || nl_fail "accepted $body: $NL_CODE $(cat "$NL_OUT")"
done
nl_ok "a bad mode, a tunnel address without prefix, a tiny MTU, a bad device and a policy tunnel without networks are refused (400)"

echo "=== 1. route-based tunnel"
api_ok POST /vpn/ipsec/connections "{\"name\":\"siteb\",\"local_address\":\"203.0.113.2\",\"remote_address\":\"198.18.0.2\",\"psk\":\"$PSK\",\"mode\":\"route\",\"tunnel_address\":\"10.255.0.1/30\",\"mtu\":1400,\"ike_proposals\":\"aes256gcm16-prfsha384-ecp384\",\"esp_proposals\":\"aes256gcm16-ecp384\"}"
TID=$(jget 'd["id"]')
CONF=$(cat /etc/swanctl/conf.d/patronus.conf)
for want in 'patronus-siteb {' 'if_id_in = 1' 'if_id_out = 1' 'local_ts = 0.0.0.0/0,::/0' 'remote_ts = 0.0.0.0/0,::/0'; do
  grep -qF -- "$want" <<<"$CONF" || { echo "$CONF"; nl_fail "swanctl config lacks: $want"; }
done
grep -q 'install_routes = no' /etc/strongswan.d/patronus-routes.conf || nl_fail "charon would install routes for the wildcard selectors"
nl_ok "swanctl config binds the child SA to if_id 1; charon is told not to install routes"
nl_wait 60 sa_state || { swanctl --list-sas || true; tail -30 /t/charon-rtr.log; tail -30 /t/charon-b.log; nl_fail "the route-based SA never came up"; }
nl_ok "IKE SA established between Patronus and an independent strongSwan"
R ip -d link show xfrm1 >"$NL_OUT" 2>&1 || nl_fail "no xfrm1 interface: $(cat "$NL_OUT")"
grep -q 'if_id 0x1' "$NL_OUT" || nl_fail "xfrm1 has no if_id 1: $(cat "$NL_OUT")"
XADDR=$(R ip -4 addr show dev xfrm1); XLINK=$(R ip link show xfrm1)
grep -q '10.255.0.1/30' <<<"$XADDR" || nl_fail "xfrm1 has no tunnel address"
grep -q 'mtu 1400' <<<"$XLINK" || nl_fail "xfrm1 MTU is not 1400"
grep -q 'MULTICAST' <<<"$XLINK" || nl_fail "xfrm1 is not multicast-capable (OSPF needs it)"
nl_ok "Patronus created xfrm1 (if_id 1, 10.255.0.1/30, MTU 1400, multicast on)"
nl_assert_nft_has 'iifname "xfrm1" meta nfproto ipv4 accept' 'oifname "xfrm1" accept'
nl_ok "firewall: traffic from xfrm1 is forwarded, nothing routed into it is NATed"
nl_wait 20 ping_b || nl_fail "router A cannot ping router B's tunnel address over the XFRM interface"
nl_ok "10.255.0.1 pings 10.255.0.2 through the XFRM interface"

echo "=== 2. LAN to LAN only over the XFRM interface"
C ping -c1 -W2 10.2.0.1 >/dev/null 2>&1 && nl_fail "the LAN client reached router B's LAN before any route existed"
R ip route replace 10.2.0.0/24 via 10.255.0.2 dev xfrm1 proto static
B ip route replace 192.168.50.0/24 via 10.255.0.1 dev xfrm1
OUT=$(C ping -c3 -W3 10.2.0.1 2>&1) || { echo "$OUT"; R ip route get 10.2.0.1 || true; R nft list ruleset | head -60; nl_fail "LAN client -> router B's LAN over the tunnel failed"; }
RGET=$(R ip route get 10.2.0.1)
grep -q 'dev xfrm1' <<<"$RGET" || nl_fail "the route to 10.2.0.1 does not use xfrm1"
nl_ok "LAN client pings 10.2.0.1 through the XFRM interface (static route)"
R ip route del 10.2.0.0/24 dev xfrm1 2>/dev/null || true
B ip route del 192.168.50.0/24 2>/dev/null || true
C ping -c1 -W2 10.2.0.1 >/dev/null 2>&1 && nl_fail "still reachable without a route"
nl_ok "without the route the LAN is not reachable: the XFRM interface carries only what routing sends into it"

echo "=== 3. status page"
nl_web GET /vpn
[ "$NL_CODE" = 200 ] || nl_fail "GET /vpn: $NL_CODE"
for want in 'id="ipsec-sas"' 'id="ipsec-policies"' 'id="ipsec-xfrm"' 'patronus-siteb' 'xfrm1' 'route-based'; do
  grep -qF -- "$want" "$NL_OUT" || nl_fail "the VPN page lacks: $want"
done
nl_api GET /vpn/ipsec/tunnels
python3 - "$NL_OUT" <<'PY' || nl_fail "SA list has no byte counters"
import json, sys
t = [x for x in json.load(open(sys.argv[1])) if x["name"] == "patronus-siteb"]
assert t and t[0]["status"] == "ESTABLISHED", t
assert t[0]["bytes_in"] is not None and t[0]["bytes_out"] is not None and t[0]["bytes_out"] > 0, t
PY
nl_api GET /vpn/ipsec/policies
python3 - "$NL_OUT" <<'PY' || nl_fail "no kernel policy with if_id 1"
import json, sys
p = json.load(open(sys.argv[1]))
assert any(x["if_id"] == 1 and x["dir"] == "out" and x["peer_dst"] == "198.18.0.2" for x in p), p
PY
nl_api GET /vpn/ipsec/interfaces
python3 - "$NL_OUT" <<'PY' || nl_fail "xfrm1 not in the interface status"
import json, sys
i = {x["name"]: x for x in json.load(open(sys.argv[1]))}
assert i["xfrm1"]["up"] and i["xfrm1"]["if_id"] == 1 and "10.255.0.1/30" in i["xfrm1"]["addresses"], i
assert i["xfrm1"]["tx_bytes"] > 0, i
PY
nl_ok "the page and API show the SA with byte counters, the kernel policy (if_id 1) and the xfrm1 interface with its traffic"

echo "=== 4. OSPF over the tunnel"
api_ok POST /svc/frr/ospf_interfaces '{"iface":"xfrm1","area":"0.0.0.0"}'
api_ok POST /svc/frr/ospf_interfaces '{"iface":"@lan","area":"0.0.0.0","passive":true}'
api_ok PUT /svc/frr '{"ospf_enabled":true,"router_id":"10.255.0.1","ospf_redistribute_connected":true}'
grep -qF 'interface xfrm1' /etc/frr/frr.conf && grep -qF 'ip ospf network point-to-point' /etc/frr/frr.conf || { cat /etc/frr/frr.conf; nl_fail "frr.conf: OSPF on xfrm1 is not point-to-point"; }
nl_assert_nft_has 'iifname "xfrm1" meta l4proto 89 accept'
b_ospf
nl_wait 90 ospf_full || { R vtysh -c 'show ip ospf interface' || true; B vtysh -N b -c 'show ip ospf interface' || true; tail -20 /var/log/frr/b.log || true; nl_fail "no Full OSPF adjacency over the XFRM interface"; }
nl_ok "OSPF adjacency Full over xfrm1 (point-to-point)"
nl_wait 60 ospf_route || { R ip route; R vtysh -c 'show ip route' || true; nl_fail "router A never learned 10.2.0.0/24 over OSPF"; }
nl_ok "router A learned $(R ip route show proto ospf | grep 10.2.0.0 | head -1 | tr -s ' ') over OSPF"
nl_wait 60 b_has_lan || { B ip route; nl_fail "router B never learned the LAN over OSPF"; }
nl_ok "router B learned the LAN 192.168.50.0/24 over OSPF"
C ping -c3 -W3 10.2.0.1 >/dev/null 2>&1 || nl_fail "LAN client -> 10.2.0.1 over the OSPF-learned route"
nl_ok "LAN client pings 10.2.0.1 over the OSPF-learned route"

echo "=== 5. tunnel down and up on the status page"
api_ok POST /vpn/ipsec/connections/$TID/disconnect
nl_wait 30 no_sa || { swanctl --list-sas || true; nl_fail "Disconnect did not take the SA down"; }
page_has 'no SA' || nl_fail "the page does not show the tunnel as down"
nl_ok "Disconnect: the SA is gone and the page says so"
nl_wait 90 ospf_gone || nl_fail "OSPF stayed Full with the tunnel down"
nl_wait 60 no_ospf_route || nl_fail "the OSPF route survived the tunnel going down"
C ping -c1 -W2 10.2.0.1 >/dev/null 2>&1 && nl_fail "LAN still reaches router B with the tunnel down"
nl_ok "with the tunnel down OSPF drops the neighbour and the route"
api_ok POST /vpn/ipsec/connections/$TID/connect
nl_wait 60 sa_state || { tail -20 /t/charon-rtr.log; nl_fail "Connect did not bring the SA up"; }
nl_wait 120 ospf_full || nl_fail "OSPF did not come back after Connect"
nl_wait 60 ospf_route || nl_fail "the OSPF route did not come back"
C ping -c3 -W3 10.2.0.1 >/dev/null 2>&1 || nl_fail "LAN client -> 10.2.0.1 after reconnect"
page_has 'ESTABLISHED' || nl_fail "the page does not show ESTABLISHED after Connect"
nl_ok "Connect: SA, OSPF adjacency, route and LAN traffic are back; the page shows ESTABLISHED"

echo "=== 6. reboot: the interface, SA and routes come back from the store"
nl_web_stop
boot
b_ospf
nl_wait 60 sa_state || nl_fail "after the reboot the SA did not come back"
XD=$(R ip -d link show xfrm1 2>&1 || true)
grep -q 'if_id 0x1' <<<"$XD" || nl_fail "xfrm1 missing after the reboot"
nl_web_start "$DB"; nl_login
nl_wait 120 ospf_full || nl_fail "OSPF after the reboot"
nl_wait 60 ospf_route || nl_fail "the OSPF route after the reboot"
C ping -c3 -W3 10.2.0.1 >/dev/null 2>&1 || nl_fail "LAN client -> 10.2.0.1 after the reboot"
nl_ok "after a reboot: xfrm1, the SA, OSPF and LAN-to-LAN traffic all come back"

echo "=== 7. deleting the tunnel removes everything"
api_ok DELETE /vpn/ipsec/connections/$TID
R ip link show xfrm1 >/dev/null 2>&1 && nl_fail "xfrm1 is still there"
grep -q 'patronus-siteb' /etc/swanctl/conf.d/patronus.conf && nl_fail "the swanctl entry is still there"
[ ! -e /etc/strongswan.d/patronus-routes.conf ] || nl_fail "the charon route setting is still there"
nl_assert_nft_lacks 'xfrm1' 'dport { 500, 4500 }'
nl_ok "tunnel deleted: xfrm1, swanctl entry, charon setting and firewall rules are gone"
nl_web_stop
nl_down
