#!/bin/sh
# Guest-network isolation with real packets (ap-guest): network namespaces stand in for the house.
#   ap (this unit): br-lan 192.0.2.10/24 with ports lan0 (wired LAN), wl24-m (a normal Wi-Fi network), wl24-g (guest)
#   gw: the router, 192.0.2.1, plus 198.51.100.1 standing in for "the internet"
#   lan: a LAN host 192.0.2.50 (a NAS, a printer)
#   m: a client of the normal network 192.0.2.60, g: a guest client 192.0.2.100, g2: a second guest port (wl5-g) client
# Proves: a guest reaches the gateway (DHCP/DNS/ping) and the internet through it, but no LAN host, not the AP itself
# (web/SSH), not another guest; a LAN host cannot reach a guest; normal clients are untouched. Then `ap-guest clear`
# restores full reachability (no stale filter).
# Needs root with CAP_NET_ADMIN + CAP_SYS_ADMIN, nft, ip, ping, nc (busybox or netcat-openbsd). Prints PASS/FAIL lines.
set -u
D=$(cd "$(dirname "$0")/.." && pwd)
G=$D/overlay/usr/libexec/patronus/ap-guest
pass=0 fail=0
ok() { echo "PASS: $1"; pass=$((pass + 1)); }
no() { echo "FAIL: $1"; fail=$((fail + 1)); }
for t in ip nft ping; do command -v $t > /dev/null || { echo "SKIP: no $t"; exit 0; }; done
ip netns add rtg-probe 2> /dev/null || { echo "SKIP: cannot create network namespaces"; exit 0; }; ip netns del rtg-probe
NS="ap gw lan m g g2"
cleanup() { for n in $NS; do ip netns del rtg-$n 2> /dev/null; done; }
cleanup; trap cleanup EXIT
for n in $NS; do ip netns add rtg-$n; ip -n rtg-$n link set lo up; done
X() { n=$1; shift; ip netns exec rtg-$n "$@"; }
X ap ip link add br-lan type bridge; X ap ip link set br-lan up; X ap ip addr add 192.0.2.10/24 dev br-lan
X ap ip route add default via 192.0.2.1
port() { # NS PORTNAME ADDR
  ip link add "$2" netns rtg-ap type veth peer name eth0 netns rtg-$1
  X ap ip link set "$2" master br-lan up; X $1 ip link set eth0 up; X $1 ip addr add "$3" dev eth0
  X $1 ip route add default via 192.0.2.1 2> /dev/null; }
port gw lan0 192.0.2.1/24
X gw ip addr add 198.51.100.1/32 dev lo
X gw sysctl -qw net.ipv4.ip_forward=1
ip link add lan1 netns rtg-ap type veth peer name eth0 netns rtg-lan
X ap ip link set lan1 master br-lan up; X lan ip link set eth0 up; X lan ip addr add 192.0.2.50/24 dev eth0; X lan ip route add default via 192.0.2.1
port m wl24-m 192.0.2.60/24
port g wl24-g 192.0.2.100/24
port g2 wl5-g 192.0.2.101/24
# listeners: the AP's web/SSH stand-in, the LAN host's service, the gateway's DNS stand-in (TCP 53), "the internet" (TCP 443)
srv() { n=$1 a=$2 p=$3; ip netns exec rtg-$n sh -c "while :; do echo hi | nc -l -p $p -s $a 2>/dev/null || echo hi | nc -l $a $p 2>/dev/null || sleep 1; done" > /dev/null 2>&1 & echo $! >> /tmp/rtg-srv.$$; }
: > /tmp/rtg-srv.$$
srv ap 192.0.2.10 443; srv lan 192.0.2.50 445; srv gw 192.0.2.1 53; srv gw 198.51.100.1 443
sleep 1
cleanup2() { for p in $(cat /tmp/rtg-srv.$$); do kill $p 2> /dev/null; done; rm -f /tmp/rtg-srv.$$; pkill -f 'nc -l' 2>/dev/null; cleanup; }
trap cleanup2 EXIT
pg() { X $1 ping -c1 -W1 "$2" > /dev/null 2>&1; }
tc() { r=$(X $1 sh -c "echo | nc -w 2 $2 $3 2>/dev/null"); [ "$r" = hi ]; }
reach() { # NS DST [tcp PORT]
  if [ $# -eq 3 ]; then tc "$1" "$2" "$3"; else pg "$1" "$2"; fi; }
expect() { # yes|no description NS DST [PORT]
  want=$1 d=$2; shift 2
  if reach "$@"; then got=yes; else got=no; fi
  [ "$got" = "$want" ] && ok "$d" || no "$d (reachable=$got)"; }
# baseline: without guest networks everything reaches everything (same L2)
expect yes "baseline: a client reaches a LAN host" g 192.0.2.50
# apply: guest network g = ports wl24-g + wl5-g
printf 'PORTS=""\nAP_SSIDS="m g"\nGUEST_g=1\n' > /tmp/rtg-board.$$
AP_BOARD=/tmp/rtg-board.$$ AP_GUEST_RESOLV=/dev/null X ap sh "$G" apply || no "ap-guest apply"
expect yes "guest -> gateway (ping)" g 192.0.2.1
expect yes "guest -> gateway DNS (tcp 53)" g 192.0.2.1 53
expect yes "guest -> the internet through the gateway (tcp 443)" g 198.51.100.1 443
expect yes "guest -> the internet through the gateway (ping)" g 198.51.100.1
expect no "guest -> LAN host (ping)" g 192.0.2.50
expect no "guest -> LAN host service (tcp 445)" g 192.0.2.50 445
expect no "guest -> this access point's web UI (tcp 443)" g 192.0.2.10 443
expect no "guest -> a normal Wi-Fi client" g 192.0.2.60
expect no "guest -> a guest on the other band" g 192.0.2.101
expect no "LAN host -> guest" lan 192.0.2.100
expect no "normal Wi-Fi client -> guest" m 192.0.2.100
expect yes "normal Wi-Fi client -> LAN host (untouched)" m 192.0.2.50
expect yes "normal Wi-Fi client -> this access point (untouched)" m 192.0.2.10 443
expect yes "LAN host -> this access point (untouched)" lan 192.0.2.10 443
# re-apply is idempotent (one table), clear restores
AP_BOARD=/tmp/rtg-board.$$ AP_GUEST_RESOLV=/dev/null X ap sh "$G" apply > /dev/null
n=$(X ap nft list tables | grep -c patronus_guest); [ "$n" = 1 ] && ok "re-apply keeps one table" || no "re-apply: $n tables"
X ap sh "$G" clear
expect yes "after clear: guest -> LAN host again" g 192.0.2.50
rm -f /tmp/rtg-board.$$
echo "guest isolation: $pass passed, $fail failed"
[ $fail -eq 0 ]
