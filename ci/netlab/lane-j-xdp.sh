#!/usr/bin/env bash
# Lane J: the eBPF/XDP data plane (crates/patronus-ebpf). The shipped XDP
# program (xdp_firewall.bpf.c) is compiled with clang exactly as
# XdpFirewall::compile_bpf_program does, loaded into the kernel with libbpf,
# attached to the router's LAN interface, and real packets from the LAN client
# are handled: IPv4 passes and is counted (packets, bytes, a conntrack entry),
# a source address on the blocklist is dropped at the driver hook (ping and TCP
# both die, the dropped counter moves), and unblocking restores traffic.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

for t in clang gcc; do command -v $t >/dev/null || nl_fail "$t is not installed in the netlab image"; done

echo "=== compile the shipped program and the loader"
MA=/usr/include/$(uname -m)-linux-gnu
clang -g -O2 -target bpf -I"$MA" -c "$NL_T/xdp_firewall.bpf.c" -o "$NL_T/xdp_firewall.o" || nl_fail "xdp_firewall.bpf.c does not compile with clang -target bpf"
nl_ok "xdp_firewall.bpf.c compiles to a BPF object (clang -g -O2 -target bpf)"
gcc -O1 -o "$NL_T/xdp-loader" "$NL_T/fixtures/xdp-loader.c" -lbpf || nl_fail "loader does not build against libbpf"

nl_up
rm -f /tmp/xdp.ctl /tmp/xdp.out /tmp/xdp.err
mkfifo /tmp/xdp.ctl
ip netns exec nl-rtr "$NL_T/xdp-loader" "$NL_T/xdp_firewall.o" "$NL_LAN_IF" <>/tmp/xdp.ctl >/tmp/xdp.out 2>/tmp/xdp.err &
NL_PIDS+=($!)
nl_wait 20 grep -q "attached $NL_LAN_IF" /tmp/xdp.out || { cat /tmp/xdp.err /tmp/xdp.out; nl_fail "the kernel did not load/attach the XDP program"; }
XDP_LINK=$(R ip -d link show "$NL_LAN_IF")
grep -q 'xdpgeneric' <<<"$XDP_LINK" || { echo "$XDP_LINK"; nl_fail "rtr-lan has no XDP program attached"; }
nl_ok "program loaded by the kernel verifier and attached (xdpgeneric) to $NL_LAN_IF"

xdp() { # CMD [ARG]: one loader command; the answer is its last output line
  local n; n=$(wc -l < /tmp/xdp.out)
  echo "$*" > /tmp/xdp.ctl
  nl_wait 5 test "$(wc -l < /tmp/xdp.out)" -gt "$n" || nl_fail "loader did not answer '$*'"
  tail -1 /tmp/xdp.out
}
field() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }

echo "=== allowed traffic passes and is counted"
C ping -c3 -W2 "$NL_RTR_LAN" >/dev/null 2>&1 || nl_fail "ping through the XDP program failed"
[ "$(C python3 "$NL_T/nl-conn.py" "$NL_RTR_LAN" 22)" = "$NL_CLIENT" ] || nl_fail "TCP through the XDP program failed"
S=$(xdp stats)
[ "$(field "$S" packets)" -ge 5 ] || nl_fail "packet counter did not move: $S"
[ "$(field "$S" bytes)" -gt 0 ] || nl_fail "byte counter did not move: $S"
[ "$(field "$S" dropped)" = 0 ] || nl_fail "packets dropped with an empty blocklist: $S"
[ "$(field "$S" conntrack)" -ge 1 ] || nl_fail "no conntrack entry for the LAN client: $S"
nl_ok "ping + TCP pass; $S"

echo "=== a blocklisted source is dropped at the XDP hook"
[ "$(xdp block "$NL_CLIENT")" = "block $NL_CLIENT rc=0" ] || nl_fail "could not add $NL_CLIENT to the blocklist"
B=$(field "$(xdp stats)" dropped)
if C ping -c3 -W1 "$NL_RTR_LAN" >/dev/null 2>&1; then nl_fail "ping from the blocked source still answered"; fi
if C python3 "$NL_T/nl-conn.py" "$NL_RTR_LAN" 22 >/dev/null 2>&1; then nl_fail "TCP from the blocked source still connected"; fi
A=$(field "$(xdp stats)" dropped)
[ "$A" -gt "$B" ] || nl_fail "dropped counter did not move ($B -> $A)"
nl_ok "ping and TCP from $NL_CLIENT are dead while blocked; dropped counter $B -> $A (no nftables involved)"

echo "=== unblocking restores traffic"
[ "$(xdp unblock "$NL_CLIENT")" = "unblock $NL_CLIENT rc=0" ] || nl_fail "could not remove the blocklist entry"
C ping -c2 -W2 "$NL_RTR_LAN" >/dev/null 2>&1 || nl_fail "ping did not recover after unblock"
[ "$(C python3 "$NL_T/nl-conn.py" "$NL_RTR_LAN" 22)" = "$NL_CLIENT" ] || nl_fail "TCP did not recover after unblock"
nl_ok "unblocked source passes again"

echo "=== non-IPv4 and other sources are untouched"
xdp block 192.168.50.99 >/dev/null
C ping -c2 -W2 "$NL_RTR_LAN" >/dev/null 2>&1 || nl_fail "blocking another address broke this client"
nl_ok "ARP/other sources unaffected by an unrelated blocklist entry"

echo quit > /tmp/xdp.ctl
nl_down
echo "PASS lane-j-xdp"
