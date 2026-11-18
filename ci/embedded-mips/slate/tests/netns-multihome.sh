#!/bin/sh
# netns repro of the Slate's two Wi-Fi uplinks in ONE upstream subnet (runs as root in a throwaway privileged container).
# house: bridge with the gateway (.1) and a management host (.60); slate: two links wl5-sta (.141, metric 100) and
# wl24-sta (.173, metric 150) into the same bridge, nft input policy drop + the boot management rule, ssh = TCP 22.
# MODE=old: the shipped scripts (mgmt rule only on wl24-sta, default ARP sysctls, no source routing)
# MODE=new: the fixed scripts from the branch (apply mgmt, board-network sysctls, wifi-follow source routing)
# Prints per-trial results: which MAC the host learned for .173 and whether TCP to .173:22 / .141:22 connected.
set -u
# usage (root, iproute2 + tc + nft + nc): MODE=new sh tests/netns-multihome.sh; SRC=<checkout of an older tree> MODE=old ... for the red run
S=${SRC:-$(cd "$(dirname "$0")/../../../.." && pwd)}/ci/embedded-mips/slate/overlay; MODE=${MODE:?}
ip netns del house 2>/dev/null; ip netns del slate 2>/dev/null; ip netns del mgmt 2>/dev/null
for n in house slate mgmt; do ip netns add $n; ip -n $n link set lo up; done
ip -n house link add br0 type bridge; ip -n house link set br0 up
ip -n house addr add 10.9.9.1/24 dev br0
ip link add m0 netns mgmt type veth peer name m0p netns house
ip link add wl5-sta netns slate address e4:95:6e:00:00:5d type veth peer name s5p netns house
ip link add wl24-sta netns slate address e6:95:6e:00:00:4c type veth peer name s24p netns house
for p in m0p s5p s24p; do ip -n house link set $p master br0; ip -n house link set $p up; done
ip -n mgmt addr add 10.9.9.60/24 dev m0; ip -n mgmt link set m0 up; ip -n mgmt route add default via 10.9.9.1
for i in wl5-sta wl24-sta; do ip -n slate link set $i up; done
# the 2.4 GHz uplink is the slow one (busy channel: the house's 2.4 GHz air is ~75 % busy, 5 GHz answers first)
ip netns exec slate tc qdisc add dev wl24-sta root netem delay ${DELAY24:-15ms} || echo "WARN: no netem"
if [ "$MODE" = new ]; then  # board-network: the same loop as the image
  for u in wl5-sta wl24-sta; do c=/proc/sys/net/ipv4/conf/$u
    ip netns exec slate sh -c "echo 1 > $c/arp_ignore; echo 2 > $c/arp_announce; echo 2 > $c/rp_filter"; done
fi
# the leases (same as udhcpc's script: address + default route with the uplink's metric)
ip -n slate addr add 10.9.9.173/24 dev wl24-sta; ip -n slate route replace default via 10.9.9.1 dev wl24-sta metric 150
ip -n slate addr add 10.9.9.141/24 dev wl5-sta;  ip -n slate route replace default via 10.9.9.1 dev wl5-sta metric 100
# firewall: the Patronus input chain shape seen on the unit (policy drop, LAN only), then the boot management rule
ip netns exec slate nft -f - <<'X'
table inet patronus {
  chain input { type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ct state invalid drop
    iifname "br-lan" accept
  }
}
X
mkdir -p /tmp/t/etc; printf 'WAN_IF=wl24-sta\nWAN5_IF=wl5-sta\nMGMT_NET=10.9.9.0/24\n' > /tmp/t/etc/board.sh; : > /tmp/t/etc/embedded.env
[ "$MODE" = new ] && printf 'UPLINKS="wl5-sta wl24-sta"\nUPLINK_TABLES="wl5-sta:4241:30241 wl24-sta:4242:30242"\n' >> /tmp/t/etc/board.sh
sed -e "s#/etc/patronus/embedded.env#/tmp/t/etc/embedded.env#; s#/etc/patronus/board.sh#/tmp/t/etc/board.sh#" $S/usr/libexec/patronus/apply > /tmp/t/apply
ip netns exec slate sh /tmp/t/apply mgmt
if [ "$MODE" = new ]; then
  sed -e "s#/etc/patronus/board.sh#/tmp/t/etc/board.sh#g" $S/usr/libexec/patronus/wifi-follow > /tmp/t/wifi-follow
  ip netns exec slate env RUN=/tmp/t/run FOLLOW= HEALTH_STA= sh /tmp/t/wifi-follow once
fi
echo "== slate rules/routes ($MODE)"; ip -n slate rule; ip -n slate route; ip -n slate route show table 4242 2>/dev/null
ip netns exec slate nft list chain inet patronus input | grep -E 'iifname|policy'
# "ssh" on the slate: a TCP listener on 22 answering every connection
ip netns exec slate sh -c 'while :; do echo SSH-2.0-test | nc -l -p 22 >/dev/null 2>&1; done' & L=$!
sleep 1
ok173=0; ok141=0; wrong=0; N=${N:-20}
for k in $(seq 1 $N); do
  ip -n mgmt neigh flush all; ip -n house neigh flush all 2>/dev/null
  # the house gateway also talks to both addresses (the upstream router ARPs for its reservation), as on the real LAN
  ip netns exec house ping -c1 -W1 10.9.9.141 >/dev/null 2>&1 &
  r173=$(ip netns exec mgmt sh -c 'echo | timeout 3 nc -w 2 10.9.9.173 22' 2>/dev/null | head -c 7)
  r141=$(ip netns exec mgmt sh -c 'echo | timeout 3 nc -w 2 10.9.9.141 22' 2>/dev/null | head -c 7)
  mac=$(ip -n mgmt neigh show 10.9.9.173 | awk '{print $5}')
  [ "$r173" = SSH-2.0 ] && ok173=$((ok173+1)); [ "$r141" = SSH-2.0 ] && ok141=$((ok141+1))
  [ "$mac" = e6:95:6e:00:00:4c ] || wrong=$((wrong+1))
  echo "trial $k: .173 mac=$mac tcp=${r173:-FAIL} | .141 tcp=${r141:-FAIL}"
done
kill $L 2>/dev/null
echo "RESULT $MODE: .173 reachable $ok173/$N, .141 reachable $ok141/$N, .173 resolved to the wrong MAC $wrong/$N"
ip netns del house; ip netns del slate; ip netns del mgmt
[ "$MODE" = old ] || [ "$ok173" = "$N" -a "$ok141" = "$N" -a "$wrong" = 0 ]
