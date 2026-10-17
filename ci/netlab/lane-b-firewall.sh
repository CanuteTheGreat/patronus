#!/usr/bin/env bash
# Lane B (firewall & NAT) netlab test. Everything is configured through the
# shipped web UI's API (what the Firewall page's forms call), from the LAN
# client, and every step asserts real traffic plus the router's kernel
# state (`nft list ruleset`).
#
# Topology: ci/netlab/lib.sh (client -- rtr -- isp -- inet), plus IPv6:
#   client fd00:50::10 -- rtr-lan fd00:50::1 [rtr] rtr-wan 2001:db8:113::2
#   -- isp 2001:db8:113::1 / 2001:db8:100::1 -- inet 2001:db8:100::10
# IPv6 is routed (the ISP routes fd00:50::/64 back to the router), not NATed.
#
# Proves:
#  1. per-rule allow/block from the LAN to the internet; reject (TCP reset,
#     refused at once) vs drop (silent, times out); logging in the ruleset
#  2. rule order: a user allow placed below a block does nothing, moved
#     above it wins; the anti-lockout system rule can't be moved; the order
#     survives a reboot
#  3. IPv6: `ip6 daddr` rules enforce on v6 only; v6 is not masqueraded
#  4. aliases are nft sets: changing an alias changes enforcement live,
#     without reloading the ruleset (an out-of-band marker set survives)
#  5. schedules toggle a rule at a mocked time (PATRONUS_FAKE_TIME_FILE),
#     live (patronus-web's schedule task) and at boot
#  6. a port forward reaches the LAN host on the right port only, matched on
#     the inbound (WAN) interface; NAT reflection lets the LAN use the WAN
#     address
#  7. masquerade: the internet host sees the router's WAN address
#     (automatic outbound NAT); manual mode without rules stops NAT; a manual
#     rule restores it
#  8. 1:1 NAT: inbound to the external address reaches the internal host,
#     and the internal host's outbound connections leave as the external
#     address
#  9. reboot: aliases, port forward, 1:1, order and schedules come back from
#     the store via `patronus apply`
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b.db
rm -f "$DB"
nl_write_installer_toml
FAKE=/t/lane-b-fake-now
export PATRONUS_FAKE_TIME_FILE=$FAKE PATRONUS_SCHEDULE_TICK_SECS=1
echo "2026-10-12 10:00" > "$FAKE"   # a Monday morning

cat > "$NL_T/lb-tcp6.py" <<'EOF'
# IPv6 TCP server: reply with the client's source address.
import socket, sys
s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(64)
while True:
    c, a = s.accept(); c.sendall((a[0] + "\n").encode()); c.close()
EOF

V6_CLIENT=fd00:50::10
V6_INET=2001:db8:100::10
add_v6() {
  R ip -6 addr add fd00:50::1/64 dev $NL_LAN_IF nodad
  R ip -6 addr add 2001:db8:113::2/64 dev $NL_WAN_IF nodad
  R ip -6 route add default via 2001:db8:113::1
  C ip -6 addr add $V6_CLIENT/64 dev lan0 nodad
  C ip -6 route add default via fd00:50::1
  ISP ip -6 addr add 2001:db8:113::1/64 dev up0 nodad
  ISP ip -6 addr add 2001:db8:100::1/64 dev down0 nodad
  ISP ip -6 route add fd00:50::/64 via 2001:db8:113::2
  ISP sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
  INET ip -6 addr add $V6_INET/64 dev inet0 nodad
  INET ip -6 route add default via 2001:db8:100::1
  nl_bg INET python3 "$NL_T/lb-tcp6.py" :: 9000
  for _ in $(seq 1 30); do INET python3 "$NL_T/nl-conn.py" $V6_INET 9000 >/dev/null 2>&1 && break; sleep 0.1; done
}
boot() { nl_up; add_v6; nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }; nl_ok "boot: patronus apply"; }

# conn NS HOST PORT -> output in $NL_OUT, status 0 if connected
conn() { "$1" python3 "$NL_T/nl-conn.py" "$2" "$3" >"$NL_OUT" 2>&1; }
expect_refused() { # DESC NS HOST PORT: rejected with a TCP reset, not silently dropped
  local d=$1; shift
  local t0; t0=$(date +%s%N)
  if conn "$@"; then nl_fail "$d: expected rejected, got $(cat "$NL_OUT")"; fi
  grep -q 'refused' "$NL_OUT" || nl_fail "$d: expected 'connection refused' (reject), got $(cat "$NL_OUT")"
  local ms=$(( ($(date +%s%N) - t0) / 1000000 ))
  [ "$ms" -lt 1500 ] || nl_fail "$d: reject took ${ms} ms"
  nl_ok "$d (refused in ${ms} ms: rejected)"
}
expect_timeout() { # DESC NS HOST PORT: silently dropped
  local d=$1; shift
  if conn "$@"; then nl_fail "$d: expected dropped, got $(cat "$NL_OUT")"; fi
  grep -q 'timed out' "$NL_OUT" || nl_fail "$d: expected a timeout (drop), got $(cat "$NL_OUT")"
  nl_ok "$d (timed out: dropped)"
}
expect_sees() { # DESC NS HOST PORT WANT-SOURCE
  local d=$1 ns=$2 h=$3 p=$4 want=$5
  conn "$ns" "$h" "$p" || { cat "$NL_OUT"; nl_fail "$d: expected reachable"; }
  [ "$(cat "$NL_OUT")" = "$want" ] || nl_fail "$d: server saw $(cat "$NL_OUT"), want $want"
  nl_ok "$d (server saw $want)"
}
api_ok() { # METHOD PATH [JSON] -- expect 2xx
  nl_api "$@"
  case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")" ;; esac
}
json_id() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT"; }
rule() { # NAME ACTION DEST PORT [extra json]
  printf '{"name":"%s","chain":"forward","action":"%s","interface":"@lan","protocol":"tcp","source":"any","destination":"%s","port":"%s","description":"%s","enabled":true%s}' \
    "$1" "$2" "$3" "$4" "$1" "${5:-}"
}
forward_chain() { R nft list chain inet patronus forward; }

echo "=== boot + web UI"
boot
nl_expect_online
nl_web_start "$DB"
nl_login
nl_web GET /firewall
[ "$NL_CODE" = 200 ] || nl_fail "firewall page: $NL_CODE"
for f in rule-form pf-form outbound-form onetoone-form alias-form schedule-form outbound-mode; do
  grep -q "id=\"$f\"" "$NL_OUT" || nl_fail "firewall page lacks the $f form"
done
for ep in "'/firewall/rules'" "'/move'" "'/firewall/nat'" "'/firewall/nat/outbound'" "'/firewall/aliases'" "'/firewall/schedules'"; do
  grep -qF "$ep" "$NL_OUT" || nl_fail "firewall page script never calls $ep"
done
nl_ok "firewall page has the rule, port-forward, outbound, 1:1, alias and schedule forms"

echo "=== 1. allow/block per rule; reject vs drop; logging"
expect_sees "LAN -> internet :9000 before any rule" C $NL_WWW 9000 $NL_RTR_WAN
api_ok POST /firewall/rules "$(rule lb-block-9000 reject $NL_WWW 9000 ',"log":true')"
BLOCK=$(json_id)
nl_assert_nft_has "ip daddr $NL_WWW tcp dport 9000 log prefix \"patronus[$BLOCK] reject: \" reject with tcp reset"
expect_refused "LAN -> internet :9000 with a reject rule" C $NL_WWW 9000
nl_expect_http "LAN -> internet :80 (not matched) still allowed" "http://$NL_WWW/" "sees $NL_RTR_WAN"
api_ok PUT /firewall/rules/$BLOCK "$(rule lb-block-9000 drop $NL_WWW 9000)"
nl_assert_nft_has "ip daddr $NL_WWW tcp dport 9000 drop"
nl_assert_nft_lacks "patronus[$BLOCK]"
expect_timeout "LAN -> internet :9000 with the rule edited to drop" C $NL_WWW 9000

echo "=== 2. rule order"
api_ok POST /firewall/rules "$(rule lb-allow-9000 accept $NL_WWW 9000)"
ALLOW=$(json_id)
FC=$(forward_chain)
[ "$(grep -n 'lb-block-9000' <<<"$FC" | cut -d: -f1)" -lt "$(grep -n 'lb-allow-9000' <<<"$FC" | cut -d: -f1)" ] \
  || { echo "$FC"; nl_fail "new allow rule was not placed after the existing block rule"; }
[ "$(grep -n 'lb-allow-9000' <<<"$FC" | cut -d: -f1)" -lt "$(grep -n 'LAN may reach any destination' <<<"$FC" | cut -d: -f1)" ] \
  || { echo "$FC"; nl_fail "user rule placed after the seeded 'Allow LAN to any'"; }
nl_ok "new user rule placed after the earlier user rule, before the seeded defaults"
expect_timeout "allow below the block: still blocked" C $NL_WWW 9000
api_ok POST /firewall/rules/$ALLOW/move '{"direction":"up"}'
FC=$(forward_chain)
[ "$(grep -n 'lb-allow-9000' <<<"$FC" | cut -d: -f1)" -lt "$(grep -n 'lb-block-9000' <<<"$FC" | cut -d: -f1)" ] \
  || { echo "$FC"; nl_fail "move up did not reorder the kernel rules"; }
expect_sees "allow moved above the block: allowed" C $NL_WWW 9000 $NL_RTR_WAN
ANTI=$(python3 -c 'import json,sys; print([r["id"] for r in json.load(open(sys.argv[1])) if r["origin"]=="system"][0])' <(nl_api GET /firewall/rules; cat "$NL_OUT"))
nl_api POST /firewall/rules/$ANTI/move '{"direction":"down"}'
[ "$NL_CODE" = 400 ] || nl_fail "moving the anti-lockout rule: HTTP $NL_CODE"
nl_ok "the anti-lockout system rule cannot be moved (400)"
IN=$(R nft list chain inet patronus input)
grep -m1 -E 'accept|drop|reject' <<<"$(grep -v -E 'iifname "lo"|ct state|icmp|policy' <<<"$IN")" | grep -q 'Anti-lockout' \
  || { echo "$IN"; nl_fail "anti-lockout is not the first user-visible input rule"; }
nl_ok "anti-lockout stays first in the input chain"

echo "=== 3. IPv6"
expect_sees "LAN -> internet over IPv6 (routed, not NATed)" C $V6_INET 9000 $V6_CLIENT
api_ok POST /firewall/rules "$(rule lb-block-v6 drop $V6_INET 9000)"
nl_assert_nft_has "ip6 daddr $V6_INET tcp dport 9000 drop"
nl_assert_nft_lacks "ip daddr $V6_INET"
expect_timeout "LAN -> [$V6_INET]:9000 blocked by an IPv6 rule" C $V6_INET 9000
expect_sees "IPv4 to the same port unaffected" C $NL_WWW 9000 $NL_RTR_WAN
nl_api POST /firewall/rules "$(rule lb-mixed drop $V6_INET 9000 ',"source":"10.0.0.0/8"' | sed 's/"source":"any",//')"
[ "$NL_CODE" = 400 ] || nl_fail "mixed-family rule: HTTP $NL_CODE $(cat "$NL_OUT")"
nl_ok "a rule mixing IPv4 and IPv6 addresses is refused (400)"

echo "=== 4. aliases = nft sets, updated live"
api_ok POST /firewall/aliases '{"name":"lb_bad","type":"host","entries":["198.51.100.20"]}'
api_ok POST /firewall/aliases '{"name":"lb_web","type":"port","entries":["80","8080"]}'
api_ok POST /firewall/rules "$(rule lb-alias-block drop '$lb_bad' '$lb_web')"
ALIAS_RULE=$(json_id)
nl_assert_nft_has "set alias_lb_bad_v4" "ip daddr @alias_lb_bad_v4 tcp dport @alias_lb_web_ports drop" \
  "ip6 daddr @alias_lb_bad_v6 tcp dport @alias_lb_web_ports drop"
nl_expect_http_blocked "LAN -> 198.51.100.20:80 (in \$lb_bad)" "http://$NL_BLOCKED/"
nl_expect_http "LAN -> 198.51.100.10:80 (not in \$lb_bad)" "http://$NL_WWW/" "sees $NL_RTR_WAN"
R nft add set inet patronus netlab_reload_marker '{ type ipv4_addr; }'
api_ok PUT /firewall/aliases/lb_bad '{"type":"host","entries":["198.51.100.10","2001:db8:100::10"]}'
grep -q '"live":true' "$NL_OUT" || nl_fail "alias update was not applied live: $(cat "$NL_OUT")"
nl_assert_nft_has netlab_reload_marker
nl_ok "alias change applied without reloading the ruleset (out-of-band marker set survived)"
nl_expect_http "LAN -> 198.51.100.20:80 after removing it from \$lb_bad" "http://$NL_BLOCKED/" "sees $NL_RTR_WAN"
nl_expect_http_blocked "LAN -> 198.51.100.10:80 after adding it to \$lb_bad" "http://$NL_WWW/"
api_ok PUT /firewall/aliases/lb_web '{"type":"port","entries":["8080"]}'
nl_assert_nft_has netlab_reload_marker
nl_expect_http "LAN -> 198.51.100.10:80 after dropping 80 from \$lb_web" "http://$NL_WWW/" "sees $NL_RTR_WAN"
nl_expect_http_blocked "LAN -> 198.51.100.10:8080 (still in \$lb_web)" "http://$NL_WWW:8080/"
nl_api DELETE /firewall/aliases/lb_bad
[ "$NL_CODE" = 400 ] || nl_fail "deleting an alias in use: HTTP $NL_CODE"
nl_ok "an alias in use cannot be deleted (400)"
api_ok DELETE /firewall/rules/$ALIAS_RULE
api_ok DELETE /firewall/aliases/lb_bad
nl_assert_nft_lacks alias_lb_bad_v4
nl_expect_online

echo "=== 5. schedules at a mocked time"
api_ok DELETE /firewall/rules/$ALLOW
api_ok DELETE /firewall/rules/$BLOCK
expect_sees "LAN -> internet :9000 with the rules deleted" C $NL_WWW 9000 $NL_RTR_WAN
api_ok POST /firewall/schedules '{"name":"lb_work","days":["mon","tue","wed","thu","fri"],"start":"09:00","end":"17:00"}'
api_ok POST /firewall/rules "$(rule lb-sched-block drop $NL_WWW 9000 ',"schedule":"lb_work"')"
nl_assert_nft_has lb-sched-block
expect_timeout "Mon 10:00 (inside lb_work): scheduled block active" C $NL_WWW 9000
echo "2026-10-12 18:30" > "$FAKE"
for _ in $(seq 1 20); do R nft list ruleset | grep -q lb-sched-block || break; sleep 0.5; done
nl_assert_nft_lacks lb-sched-block
expect_sees "Mon 18:30 (outside lb_work): rule lifted by the schedule task" C $NL_WWW 9000 $NL_RTR_WAN
echo "2026-10-13 09:05" > "$FAKE"
for _ in $(seq 1 20); do R nft list ruleset | grep -q lb-sched-block && break; sleep 0.5; done
nl_assert_nft_has lb-sched-block
expect_timeout "Tue 09:05: the block is back" C $NL_WWW 9000
echo "2026-10-17 10:00" > "$FAKE"   # Saturday
for _ in $(seq 1 20); do R nft list ruleset | grep -q lb-sched-block || break; sleep 0.5; done
expect_sees "Sat 10:00 (not a scheduled day): allowed" C $NL_WWW 9000 $NL_RTR_WAN

echo "=== 6. port forward + NAT reflection"
api_ok POST /firewall/nat '{"name":"lb-pf","rule_type":"DNAT","interface":"@wan","protocol":"tcp","external_port":"8022","target":"192.168.50.10:9000","description":"lb-pf","enabled":true}'
PF=$(json_id)
nl_assert_nft_has "iifname \"$NL_WAN_IF\" tcp dport 8022 dnat ip to 192.168.50.10:9000" \
  "ct status dnat ip daddr 192.168.50.10 tcp dport 9000 accept"
nl_assert_nft_lacks "oifname \"$NL_WAN_IF\" tcp dport 8022"
expect_sees "WAN -> router:8022 forwarded to the LAN host :9000" ISP $NL_RTR_WAN 8022 203.0.113.1
nl_expect_no_tcp "WAN -> router:8023 (not forwarded)" ISP $NL_RTR_WAN 8023
nl_expect_no_tcp "WAN -> router:9000 (the inner port is not exposed)" ISP $NL_RTR_WAN 9000
ISP ip route replace 192.168.50.0/24 via $NL_RTR_WAN
nl_expect_no_tcp "WAN -> LAN host :9000 directly (only the forward is let in)" ISP $NL_CLIENT 9000
ISP ip route del 192.168.50.0/24 via $NL_RTR_WAN
nl_expect_no_tcp "LAN -> WAN address :8022 without reflection" C $NL_RTR_WAN 8022
api_ok PUT /firewall/nat/$PF '{"name":"lb-pf","rule_type":"DNAT","interface":"@wan","protocol":"tcp","external_port":"8022","target":"192.168.50.10:9000","description":"lb-pf","enabled":true,"reflection":true}'
nl_assert_nft_has "iifname != \"$NL_WAN_IF\" ip daddr $NL_RTR_WAN tcp dport 8022 dnat ip to 192.168.50.10:9000"
expect_sees "LAN -> WAN address :8022 with NAT reflection (hairpin, source = router LAN)" C $NL_RTR_WAN 8022 $NL_RTR_LAN
expect_sees "WAN -> router:8022 still forwarded" ISP $NL_RTR_WAN 8022 203.0.113.1

echo "=== 7. masquerade / outbound NAT modes"
nl_assert_nft_has "meta nfproto ipv4 oifname \"$NL_WAN_IF\" masquerade"
nl_expect_http "masquerade: the internet host sees the router's WAN address" "http://$NL_WWW/" "sees $NL_RTR_WAN"
api_ok GET /firewall/nat/outbound
grep -q '"mode":"hybrid"' "$NL_OUT" && grep -q "$NL_WAN_IF" "$NL_OUT" || nl_fail "outbound mode: $(cat "$NL_OUT")"
api_ok PUT /firewall/nat/outbound '{"mode":"manual"}'
nl_assert_nft_lacks "Automatic outbound NAT"
nl_expect_http_blocked "manual outbound NAT without rules: LAN is not NATed (ISP has no route back)" "http://$NL_WWW/"
api_ok POST /firewall/nat '{"name":"lb-manual","rule_type":"MASQUERADE","interface":"@wan","source":"192.168.50.0/24","target":"masquerade","description":"lb-manual","enabled":true}'
MANUAL=$(json_id)
nl_expect_http "manual masquerade rule: online again" "http://$NL_WWW/" "sees $NL_RTR_WAN"
api_ok PUT /firewall/nat/outbound '{"mode":"hybrid"}'
api_ok DELETE /firewall/nat/$MANUAL
nl_expect_online

echo "=== 8. 1:1 NAT"
ISP ip route add 203.0.113.50/32 via $NL_RTR_WAN
api_ok POST /firewall/nat '{"name":"lb-1to1","rule_type":"1:1","interface":"@wan","external_address":"203.0.113.50","target":"192.168.50.10","description":"lb-1to1","enabled":true}'
api_ok POST /firewall/rules '{"name":"lb-allow-1to1","chain":"forward","action":"accept","interface":"@wan","protocol":"tcp","source":"any","destination":"192.168.50.10","port":"9000","description":"lb-allow-1to1","enabled":true}'
nl_assert_nft_has "ip daddr 203.0.113.50 dnat ip to 192.168.50.10" "ip saddr 192.168.50.10 snat ip to 203.0.113.50"
expect_sees "WAN -> 203.0.113.50:9000 reaches the internal host" ISP 203.0.113.50 9000 203.0.113.1
expect_sees "internal host -> internet leaves as 203.0.113.50" C $NL_WWW 9000 203.0.113.50

echo "=== 9. reboot: everything comes back from the store"
api_ok POST /firewall/aliases '{"name":"lb_keep","type":"host","entries":["198.51.100.20"]}'
api_ok POST /firewall/rules "$(rule lb-keep-block drop '$lb_keep' 80)"
nl_web_stop
echo "2026-10-14 11:00" > "$FAKE"   # Wednesday, inside lb_work
boot
ISP ip route add 203.0.113.50/32 via $NL_RTR_WAN
nl_assert_nft_has "elements = { 198.51.100.20 }" lb-sched-block "dnat ip to 192.168.50.10:9000" "snat ip to 203.0.113.50"
nl_expect_http_blocked "after reboot: alias block rule" "http://$NL_BLOCKED/"
expect_timeout "after reboot (Wed 11:00): scheduled block active" C $NL_WWW 9000
expect_sees "after reboot: port forward" ISP $NL_RTR_WAN 8022 203.0.113.1
expect_sees "after reboot: 1:1 inbound" ISP 203.0.113.50 9000 203.0.113.1
expect_timeout "after reboot: IPv6 block rule" C $V6_INET 9000
echo "2026-10-14 20:00" > "$FAKE"
nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "apply"; }
nl_assert_nft_lacks lb-sched-block
nl_ok "boot apply outside the window leaves the scheduled rule out"
echo "--- nft list ruleset at the end:"; nl_ruleset

nl_down
echo "LANE B FIREWALL & NAT: ALL CHECKS PASSED"
