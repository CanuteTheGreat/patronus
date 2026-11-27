#!/bin/sh
# netns proof of the management address failover (docs/embedded-routers.md 6i; runs as root in a throwaway privileged container
# or on a CI host: needs iproute2, nft, nc, python3). Same topology as netns-multihome.sh: a house bridge with the gateway (.1)
# and a management host (.60); the slate has two clients in the SAME subnet, wl24-sta (.173, the reserved address, the primary) and
# wl5-sta (.141). The REAL wifi-follow runs as the daemon in the slate namespace; only `iw` (association state) and `arping`
# (gratuitous ARP sender) are stubs.
#   phase A  both uplinks up                : .173 answers on wl24-sta's MAC
#   phase B  wl24-sta loses its Wi-Fi link  : .173 must answer again (now on wl5-sta's MAC) within LIMIT s, .141 keeps working
#   phase C  wl24-sta comes back            : .173 is back on wl24-sta's MAC, the alias and the extra rule are gone
#   phase D  wl5-sta down instead           : .173 and .141's absence do not disturb the primary
# MODE=off runs the same with MGMT_FAILOVER=off: phase B must FAIL (the red run that proves the test sees the bug).
set -u
S=${SRC:-$(cd "$(dirname "$0")/../../../.." && pwd)}/ci/embedded-mips/slate/overlay; MODE=${MODE:-on}; LIMIT=${LIMIT:-12}
T=$(mktemp -d /tmp/mgmt-fo.XXXX)
cleanup() { kill $(cat $T/*.pid 2>/dev/null) 2>/dev/null; ip netns del house 2>/dev/null; ip netns del slate 2>/dev/null; ip netns del mgmt 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
for n in house slate mgmt; do ip netns del $n 2>/dev/null; ip netns add $n; ip -n $n link set lo up; done
ip -n house link add br0 type bridge; ip -n house link set br0 up; ip -n house addr add 10.9.9.1/24 dev br0
ip link add m0 netns mgmt type veth peer name m0p netns house
ip link add wl5-sta netns slate address e4:95:6e:00:00:5d type veth peer name s5p netns house
ip link add wl24-sta netns slate address e6:95:6e:00:00:4c type veth peer name s24p netns house
for p in m0p s5p s24p; do ip -n house link set $p master br0; ip -n house link set $p up; done
ip -n mgmt addr add 10.9.9.60/24 dev m0; ip -n mgmt link set m0 up; ip -n mgmt route add default via 10.9.9.1
for i in wl5-sta wl24-sta; do ip -n slate link set $i up; c=/proc/sys/net/ipv4/conf/$i
  ip netns exec slate sh -c "echo 1 > $c/arp_ignore; echo 2 > $c/arp_announce; echo 2 > $c/rp_filter"; done
ip -n slate addr add 10.9.9.173/24 dev wl24-sta; ip -n slate route replace default via 10.9.9.1 dev wl24-sta metric 150
ip -n slate addr add 10.9.9.141/24 dev wl5-sta;  ip -n slate route replace default via 10.9.9.1 dev wl5-sta metric 100
ip netns exec slate nft -f - <<'X'
table inet patronus {
  chain input { type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ct state invalid drop
    iifname "br-lan" accept
    iifname { "wl5-sta", "wl24-sta" } ip saddr 10.9.9.0/24 tcp dport { 22, 80, 443 } accept comment "patronus-boot-mgmt"
  }
}
X
# stubs: iw (Connected while a state file says so and the link is up), arping (gratuitous ARP via a raw socket)
mkdir -p $T/bin $T/run $T/data; echo up > $T/wl5-sta.state; echo up > $T/wl24-sta.state
cat > $T/bin/iw <<X
#!/bin/sh
[ "\$1" = dev ] && [ "\$3" = link ] && [ "\$(cat $T/\$2.state)" = up ] && echo "Connected to aa:bb:cc:dd:ee:ff (on \$2)"
exit 0
X
cat > $T/bin/arping <<'X'
#!/usr/bin/env python3
# arping -U -q -c N -w S -I IF -s SRC DST : N gratuitous ARP requests (sender = target = SRC) out of IF
import socket, struct, sys
a = sys.argv[1:]; n = 1; ifc = src = None; i = 0
while i < len(a):
    if a[i] == "-c": n = int(a[i+1]); i += 2
    elif a[i] == "-w": i += 2
    elif a[i] == "-I": ifc = a[i+1]; i += 2
    elif a[i] == "-s": src = a[i+1]; i += 2
    else: i += 1
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((ifc, 0)); mac = s.getsockname()[4]
ip = socket.inet_aton(src or a[-1])
f = b"\xff" * 6 + mac + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + ip + b"\x00" * 6 + ip
for _ in range(n): s.send(f.ljust(60, b"\0"))
X
chmod +x $T/bin/iw $T/bin/arping
printf 'WAN_IF=wl24-sta\nUPLINKS="wl5-sta wl24-sta"\nUPLINK_TABLES="wl5-sta:4241:30241 wl24-sta:4242:30242"\nMGMT_FAILOVER=%s\nMGMT_FAILOVER_AFTER=${AFTER:-3}\n' "$MODE" > $T/board.sh
sed -e "s#/etc/patronus/board.sh#$T/board.sh#g" $S/usr/libexec/patronus/wifi-follow > $T/wifi-follow
ip netns exec slate sh -c 'while :; do echo SSH-2.0-test | nc -l -p 22 >/dev/null 2>&1; done' & echo $! > $T/nc.pid
ip netns exec slate env RUN=$T/run MGMT_STATE=$T/data IW=$T/bin/iw ARPING=$T/bin/arping POLL=1 FOLLOW=dummy-sta:dummy-ap:none HEALTH_STA= RADIO_WATCH= MGMT_APPLY=/nonexistent \
  BOARD_SETTINGS=/nonexistent sh $T/wifi-follow > $T/wf.log 2>&1 & echo $! > $T/wf.pid
sleep 3
fails=0
ssh_ok() { ip netns exec mgmt sh -c "echo | timeout 3 nc -w 2 $1 22" 2>/dev/null | head -c 7 | grep SSH-2.0 >/dev/null; }
mac_of() { ip -n mgmt neigh show 10.9.9.173 | awk '{print $5}'; }
# wait <seconds> until .173:22 answers; prints the seconds it took or FAIL
wait_ssh() { s0=$(date +%s); while [ $(( $(date +%s) - s0 )) -lt "$1" ]; do ssh_ok 10.9.9.173 && { echo "$(( $(date +%s) - s0 ))"; return 0; }; sleep 0.3; done; echo FAIL; return 1; }
check() { if [ "$2" = "$3" ]; then echo "ok: $1"; else echo "FAIL: $1 (got '$2', want '$3')"; fails=$((fails+1)); fi; }
r=$(wait_ssh 10); check "A: .173 answers with both uplinks up" "$([ "$r" = FAIL ] && echo no || echo yes)" yes
check "A: .173 resolves to the primary's MAC" "$(mac_of)" e6:95:6e:00:00:4c
# phase B: the house AP restarts the 2.4 GHz radio: the client loses its link (no carrier, not associated)
echo down > $T/wl24-sta.state; ip -n slate link set wl24-sta down
ip -n mgmt neigh flush all; ip -n house neigh flush all
r=$(wait_ssh $LIMIT)
if [ "$MODE" = off ]; then
  check "B(off): without failover .173 stays unreachable" "$r" FAIL
else
  check "B: .173 answers again within ${LIMIT}s while wl24-sta is down (took ${r}s)" "$([ "$r" = FAIL ] && echo no || echo yes)" yes
  check "B: .173 is now served by wl5-sta's MAC" "$(mac_of)" e4:95:6e:00:00:5d
  check "B: the second uplink's own address .141 still answers" "$(ssh_ok 10.9.9.141 && echo yes || echo no)" yes
  check "B: alias on wl5-sta, rule one below its source rule" "$(ip -n slate -4 -o addr show dev wl5-sta | grep -c '10.9.9.173/32'),$(ip -n slate rule list pref 30240 | grep -c 'from 10.9.9.173 lookup 4241')" 1,1
  check "B: replies leave by wl5-sta" "$(ip -n slate route get 10.9.9.60 from 10.9.9.173 2>/dev/null | grep -o 'dev [a-z0-9-]*' | head -n 1)" "dev wl5-sta"
  sleep 12
  check "B: still reachable 12 s later (announcements repeat, alias kept)" "$(ssh_ok 10.9.9.173 && echo yes || echo no)" yes
  # phase C: the primary is back (link up, associated, address kept by its DHCP client)
  echo up > $T/wl24-sta.state; ip -n slate link set wl24-sta up
  ip -n slate route replace default via 10.9.9.1 dev wl24-sta metric 150
  sleep 4; ip -n mgmt neigh flush all; ip -n house neigh flush all
  r=$(wait_ssh 10)
  check "C: .173 answers after the primary returns" "$([ "$r" = FAIL ] && echo no || echo yes)" yes
  check "C: .173 is back on the primary's MAC" "$(mac_of)" e6:95:6e:00:00:4c
  check "C: alias and extra rule removed" "$(ip -n slate -4 -o addr show dev wl5-sta | grep -c '10.9.9.173/32'),$(ip -n slate rule list pref 30240 | wc -l)" 0,0
  check "C: .141 unaffected" "$(ssh_ok 10.9.9.141 && echo yes || echo no)" yes
  # phase D: the OTHER uplink goes down: nothing moves, the primary keeps its address
  echo down > $T/wl5-sta.state; ip -n slate link set wl5-sta down; sleep 6
  check "D: wl5-sta down: .173 still answers on the primary" "$(ssh_ok 10.9.9.173 && echo yes || echo no)" yes
  check "D: no alias anywhere" "$(ip -n slate -4 -o addr show | grep -c '10.9.9.173/32')" 0
  # phase E: both down, then only the backup returns: the address is carried again
  echo down > $T/wl24-sta.state; ip -n slate link set wl24-sta down
  echo up > $T/wl5-sta.state; ip -n slate link set wl5-sta up; ip -n slate route replace default via 10.9.9.1 dev wl5-sta metric 100
  ip -n mgmt neigh flush all; ip -n house neigh flush all
  r=$(wait_ssh $LIMIT)
  check "E: only the backup returns: .173 carried by it (took ${r}s)" "$([ "$r" = FAIL ] && echo no || echo yes)" yes
fi
echo "--- wifi-follow log"; cat $T/wf.log
[ "$fails" = 0 ] && echo "RESULT mode=$MODE: all checks passed" || echo "RESULT mode=$MODE: $fails failed"
if [ "$MODE" = off ]; then [ "$fails" = 0 ]; else [ "$fails" = 0 ]; fi
