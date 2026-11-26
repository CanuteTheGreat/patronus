#!/usr/bin/env bash
# Lane B (firewall parity): floating rules, interface groups, per-rule state
# limits with an overload table, per-rule limiters and categories. Everything
# is configured through the shipped web UI's API (what the Firewall page's
# forms call) and every step asserts real traffic plus the router's kernel
# state (`nft list ...`).
#
# Topology: ci/netlab/lib.sh plus a second LAN-side network
#   client  192.168.50.10 -- rtr-lan [rtr] rtr-wan -- isp -- inet
#   client2 192.168.60.10 -- rtr-opt [rtr]
#
# Proves:
#  1. a floating rule on two interfaces blocks on both, an interface it does
#     not name is unaffected, and a quick floating rule sits before the
#     interface rules while a non-quick one yields to them
#  2. a floating rule with direction out matches what leaves an interface
#  3. an interface group is an nft set; a rule on the group follows a new
#     member (set swapped live, rule untouched, no ruleset reload)
#  4. max-src-conn caps simultaneous connections per source, max-states caps
#     them for the rule in total
#  5. max-src-rate puts a flooding client into the overload table, which
#     drops that client only, and releasing it restores access
#  6. a per-rule limiter caps one client's rate (counted by the server) and
#     leaves the other client alone; a shared limiter caps them together
#  7. categories are listed; an unknown group / limiter / bad name is refused
#  8. everything comes back from the store after a reboot
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-b-floating.db
rm -f "$DB"
nl_write_installer_toml
C2() { ip netns exec nl-c2 "$@"; }
export -f C2
C2_NET=192.168.60
cleanup() { nl_stop_servers 2>/dev/null || true; ip netns del nl-c2 2>/dev/null || true; }
trap cleanup EXIT

cat > "$NL_T/lb-hold.py" <<'EOF'
# Holding TCP server: accepts, keeps every connection open for 8 s, says "hi".
import socket, sys, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(128)
def h(c):
    try:
        c.sendall(b"hi\n"); time.sleep(8)
    finally:
        c.close()
while True:
    c, a = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
EOF
cat > "$NL_T/lb-open.py" <<'EOF'
# Open N connections at once and hold them; print how many connected.
import socket, sys, time
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks, ok = [], 0
for _ in range(n):
    try:
        c = socket.create_connection((host, port), timeout=1.5); c.recv(8); socks.append(c); ok += 1
    except OSError:
        pass
print(ok)
time.sleep(0.5)
EOF
cat > "$NL_T/lb-sink.py" <<'EOF'
# Upload sink: for every connection count the bytes received for 5 s and
# append "<client address> <bytes>" to the file in argv[3].
import socket, sys, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
out = sys.argv[3]
def h(c, peer):
    n, t0 = 0, time.time()
    c.settimeout(1)
    while time.time() - t0 < 5:
        try:
            d = c.recv(65536)
            if not d: break
            n += len(d)
        except socket.timeout:
            pass
    c.close()
    open(out, "a").write(f"{peer} {n}\n")
while True:
    c, a = s.accept(); threading.Thread(target=h, args=(c, a[0]), daemon=True).start()
EOF
cat > "$NL_T/lb-push.py" <<'EOF'
# Upload as fast as possible for 5 s.
import socket, sys, time
c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
buf = b"x" * 65536; t0 = time.time()
c.settimeout(2)
while time.time() - t0 < 5:
    try: c.sendall(buf)
    except OSError: break
c.close()
EOF

boot() {
  nl_up
  ip netns add nl-c2; ip -n nl-c2 link set lo up
  ip link add rtr-opt netns nl-rtr type veth peer name lan0 netns nl-c2
  R ip addr add $C2_NET.1/24 dev rtr-opt; R ip link set rtr-opt up
  C2 ip addr add $C2_NET.10/24 dev lan0; C2 ip link set lan0 up
  C2 ip route add default via $C2_NET.1
  nl_bg INET python3 "$NL_T/lb-hold.py" 0.0.0.0 9100
  : > /tmp/lb-sink.txt
  nl_bg INET python3 "$NL_T/lb-sink.py" 0.0.0.0 9200 /tmp/lb-sink.txt
  nl_apply "$DB" || { cat "$NL_OUT"; nl_fail "boot: patronus apply failed"; }
  nl_ok "boot: patronus apply"
}

conn() { "$1" python3 "$NL_T/nl-conn.py" "$2" "$3" >"$NL_OUT" 2>&1; }
expect_sees() { # DESC NS HOST PORT
  local d=$1; shift
  conn "$@" || { cat "$NL_OUT"; nl_fail "$d: expected reachable"; }
  nl_ok "$d"
}
expect_blocked() { # DESC NS HOST PORT
  local d=$1; shift
  if conn "$@"; then nl_fail "$d: expected blocked, got $(cat "$NL_OUT")"; fi
  nl_ok "$d (blocked)"
}
api_ok() { nl_api "$@"; case "$NL_CODE" in 2??) ;; *) nl_fail "$1 $2: HTTP $NL_CODE $(cat "$NL_OUT")" ;; esac; }
api_code() { # WANT METHOD PATH [JSON]
  local want=$1; shift
  nl_api "$@"
  [ "$NL_CODE" = "$want" ] || nl_fail "$1 $2: HTTP $NL_CODE (want $want) $(cat "$NL_OUT")"
}
json_id() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$NL_OUT"; }
forward_chain() { R nft list chain inet patronus forward; }
lineno() { grep -n -m1 -- "$2" <<<"$1" | cut -d: -f1; }
# a pass/drop rule JSON: NAME ACTION IFACE DPORT [extra json]
rj() {
  printf '{"name":"%s","chain":"forward","action":"%s","interface":"%s","protocol":"tcp","source":"any","destination":"%s","port":"%s","description":"%s","enabled":true%s}' \
    "$1" "$2" "$3" "$NL_WWW" "$4" "$1" "${5:-}"
}
floating() { # NAME ACTION QUICK DIRECTION IFACES-JSON DPORT [extra]
  printf '{"name":"%s","chain":"forward","action":"%s","interface":"any","floating":true,"quick":%s,"direction":"%s","interfaces":%s,"protocol":"tcp","source":"any","destination":"%s","port":"%s","description":"%s","enabled":true%s}' \
    "$1" "$2" "$3" "$4" "$5" "$NL_WWW" "$6" "$1" "${7:-}"
}
mbps() { # bytes in 5 s -> kB/s
  echo $(( $1 / 5 / 1000 ))
}
sink_bytes() { # CLIENT-ADDR: total bytes the sink counted for that client
  awk -v c="$1" '$1==c {s+=$2} END {print s+0}' /tmp/lb-sink.txt
}

echo "=== boot + web UI"
boot
nl_expect_online
nl_web_start "$DB"
nl_login
# the second LAN network may pass, like the seeded LAN rule does for @lan
api_ok POST /firewall/rules "$(rj lb-opt-allow accept rtr-opt any | sed 's/"protocol":"tcp"/"protocol":"any"/; s/"destination":"[^"]*"/"destination":"any"/')"
expect_sees "client 1 reaches the internet :9000" C $NL_WWW 9000
expect_sees "client 2 reaches the internet :9000" C2 $NL_WWW 9000
nl_web GET /firewall
[ "$NL_CODE" = 200 ] || nl_fail "firewall page: $NL_CODE"
for f in floating-form group-form limiter-form; do
  grep -q "id=\"$f\"" "$NL_OUT" || nl_fail "firewall page lacks the $f form"
done
nl_ok "firewall page has the floating-rule, interface-group and limiter forms"

echo "=== 1. floating rule on two interfaces; quick and not quick"
api_ok POST /firewall/rules "$(floating lb-float-block drop true in '["rtr-lan","rtr-opt"]' 9000)"
FLOAT=$(json_id)
nl_assert_nft_has "iifname { \"rtr-lan\", \"rtr-opt\" } meta l4proto" 'tcp dport 9000 drop' 2>/dev/null \
  || nl_assert_nft_has "iifname { \"rtr-lan\", \"rtr-opt\" }" "tcp dport 9000 drop"
expect_blocked "floating block: client 1 (rtr-lan)" C $NL_WWW 9000
expect_blocked "floating block: client 2 (rtr-opt)" C2 $NL_WWW 9000
expect_sees "floating block is port-specific: :80 passes" C $NL_WWW 80
FC=$(forward_chain)
[ "$(lineno "$FC" 'lb-float-block')" -lt "$(lineno "$FC" 'lb-opt-allow')" ] \
  || { echo "$FC"; nl_fail "a quick floating rule is not ahead of the interface rules"; }
nl_ok "the quick floating rule sits before the interface rules in the kernel"
# an interface the rule does not name is not affected: a third network
ip netns add nl-c3; ip -n nl-c3 link set lo up
ip link add rtr-opt2 netns nl-rtr type veth peer name lan0 netns nl-c3
R ip addr add 192.168.70.1/24 dev rtr-opt2; R ip link set rtr-opt2 up
ip netns exec nl-c3 ip addr add 192.168.70.10/24 dev lan0
ip netns exec nl-c3 ip link set lan0 up
ip netns exec nl-c3 ip route add default via 192.168.70.1
api_ok POST /firewall/rules "$(rj lb-opt2-allow accept rtr-opt2 any | sed 's/"protocol":"tcp"/"protocol":"any"/; s/"destination":"[^"]*"/"destination":"any"/')"
C3() { ip netns exec nl-c3 "$@"; }
conn C3 $NL_WWW 9000 || { cat "$NL_OUT"; nl_fail "an interface the floating rule does not name was blocked"; }
nl_ok "a third interface the floating rule does not name still passes"
ip netns del nl-c3 2>/dev/null || true
# not quick: the interface rules are evaluated first and win
api_ok PUT /firewall/rules/$FLOAT "$(floating lb-float-block drop false in '["rtr-lan","rtr-opt"]' 9000)"
FC=$(forward_chain)
[ "$(lineno "$FC" 'lb-float-block')" -gt "$(lineno "$FC" 'lb-opt-allow')" ] \
  || { echo "$FC"; nl_fail "a non-quick floating rule is not after the interface rules"; }
expect_sees "not quick: the interface pass rule wins for client 2" C2 $NL_WWW 9000
expect_sees "not quick: the seeded LAN pass rule wins for client 1" C $NL_WWW 9000
api_ok PUT /firewall/rules/$FLOAT "$(floating lb-float-block drop true in '["rtr-lan","rtr-opt"]' 9000)"
expect_blocked "quick again: client 1" C $NL_WWW 9000
api_ok DELETE /firewall/rules/$FLOAT
expect_sees "floating rule removed: client 1 passes" C $NL_WWW 9000
expect_sees "floating rule removed: client 2 passes" C2 $NL_WWW 9000

echo "=== 2. floating rule, direction out"
api_ok POST /firewall/rules "$(floating lb-float-out drop true out '["rtr-wan"]' 9000)"
FOUT=$(json_id)
nl_assert_nft_has "oifname \"rtr-wan\""
expect_blocked "direction out on rtr-wan: client 1" C $NL_WWW 9000
expect_blocked "direction out on rtr-wan: client 2" C2 $NL_WWW 9000
expect_sees "direction out is port-specific: :80 passes" C $NL_WWW 80
api_ok DELETE /firewall/rules/$FOUT
expect_sees "direction out rule removed" C $NL_WWW 9000

echo "=== 3. interface group follows a new member"
api_ok POST /firewall/interface-groups '{"name":"trusted","members":["rtr-lan"],"description":"first network"}'
nl_assert_nft_has "set ifgrp_trusted" "type ifname"
R nft list set inet patronus ifgrp_trusted | grep -q '"rtr-lan"' || nl_fail "the group set lacks rtr-lan"
api_ok POST /firewall/rules "$(rj lb-group-block drop group:trusted 9000)"
GRULE=$(json_id)
nl_assert_nft_has "iifname @ifgrp_trusted" "tcp dport 9000 drop"
expect_blocked "group rule: client 1 (member)" C $NL_WWW 9000
expect_sees "group rule: client 2 (not a member) passes" C2 $NL_WWW 9000
R nft add set inet patronus netlab_reload_marker '{ type ipv4_addr; }'
RULES_BEFORE=$(R nft list chain inet patronus forward | sha256sum)
api_ok PUT /firewall/interface-groups/trusted '{"members":["rtr-lan","rtr-opt"]}'
grep -q '"applied_live":true' "$NL_OUT" || nl_fail "group change was not applied live: $(cat "$NL_OUT")"
nl_assert_nft_has netlab_reload_marker
[ "$RULES_BEFORE" = "$(R nft list chain inet patronus forward | sha256sum)" ] \
  || nl_fail "the rule chain changed when only the group's members did"
expect_blocked "a new member follows the rule: client 2 now blocked" C2 $NL_WWW 9000
nl_ok "the group rule followed the new member without editing the rule or reloading the ruleset"
api_code 400 DELETE /firewall/interface-groups/trusted
nl_ok "a group in use cannot be deleted (400)"
api_ok PUT /firewall/interface-groups/trusted '{"members":["rtr-opt"]}'
expect_sees "member removed: client 1 passes again" C $NL_WWW 9000
expect_blocked "member kept: client 2 still blocked" C2 $NL_WWW 9000
api_ok DELETE /firewall/rules/$GRULE
api_ok DELETE /firewall/interface-groups/trusted
nl_assert_nft_lacks ifgrp_trusted
expect_sees "group rule removed: client 2 passes" C2 $NL_WWW 9000

echo "=== 4. max-src-conn and max-states"
nl_expect_online
api_ok POST /firewall/rules "$(rj lb-conn accept @lan 9100 ',"max_src_conn":3,"category":"limits"')"
CONN_PLAIN=$(json_id)
nl_assert_nft_has "ct state new add @sc${CONN_PLAIN}_v4 { ip saddr ct count over 3 }"
N=$(C python3 "$NL_T/lb-open.py" $NL_WWW 9100 8)
[ "$N" = 3 ] || nl_fail "max-src-conn 3: $N connections got through"
nl_ok "max-src-conn 3: exactly 3 of 8 simultaneous connections from one source got through"
api_ok DELETE /firewall/rules/$CONN_PLAIN
sleep 9  # the holding server frees its sockets
api_ok POST /firewall/rules "$(rj lb-states accept @lan 9100 ',"max_states":4')"
STATES=$(json_id)
api_ok POST /firewall/rules "$(rj lb-states2 accept rtr-opt 9100)"
N1=$(C python3 "$NL_T/lb-open.py" $NL_WWW 9100 3)
[ "$N1" = 3 ] || nl_fail "max-states 4: first source got $N1 of 3"
nl_ok "max-states 4: 3 connections open, within the limit"
N2=$( (C python3 "$NL_T/lb-open.py" $NL_WWW 9100 3 & sleep 0.3; wait) )
[ "$N2" -le 4 ] || nl_fail "max-states 4: $N2 connections"
api_ok DELETE /firewall/rules/$STATES
api_ok DELETE /firewall/rules/$(nl_api GET /firewall/rules >/dev/null; python3 -c 'import json,sys; print([r["id"] for r in json.load(open(sys.argv[1])) if r["name"]=="lb-states2"][0])' "$NL_OUT")
sleep 9

echo "=== 5. max-src-rate puts a flooding client into the overload table"
api_ok POST /firewall/rules "$(rj lb-flood accept @lan 80 ',"max_src_rate":5,"max_src_rate_secs":10,"overload":"flooders","overload_secs":120,"category":"limits"')"
FLOOD=$(json_id)
nl_assert_nft_has "set ov_flooders_v4" "ip saddr @ov_flooders_v4 drop"
cat > "$NL_T/lb-flood.py" <<'EOF'
import socket, sys
ok = 0
for _ in range(40):
    try:
        c = socket.create_connection((sys.argv[1], 80), timeout=0.4); c.close(); ok += 1
    except OSError:
        pass
print(ok)
EOF
OKN=$(C python3 "$NL_T/lb-flood.py" $NL_WWW)
[ "$OKN" -lt 40 ] && [ "$OKN" -ge 3 ] || nl_fail "flood: $OKN of 40 connections got through (want a few, not all)"
nl_ok "flood: $OKN of 40 new connections got through before the rate limit bit"
R nft list set inet patronus ov_flooders_v4 | grep -q "$NL_CLIENT" || { R nft list set inet patronus ov_flooders_v4; nl_fail "the flooding client is not in the overload table"; }
nl_ok "the flooding client is in the overload table"
nl_api GET /firewall/overload
grep -q "$NL_CLIENT" "$NL_OUT" || nl_fail "the overload API does not list the client: $(cat "$NL_OUT")"
nl_ok "the overload API lists the blocked source"
expect_blocked "an overloaded client is blocked on this rule's interface" C $NL_WWW 80
expect_sees "another client (client 2) is unaffected" C2 $NL_WWW 80
api_ok DELETE /firewall/overload/flooders/$NL_CLIENT
expect_sees "released from the overload table: client 1 reaches it again" C $NL_WWW 80
api_ok DELETE /firewall/rules/$FLOOD

echo "=== 6. per-rule limiter"
api_ok PUT /firewall/limiters/cap4m '{"rate_kbit":4000,"burst_kb":128,"per_source":true}'
api_code 400 PUT /firewall/limiters/bad '{"rate_kbit":0}'
api_ok POST /firewall/rules "$(rj lb-up-free accept @lan 9200 ',"category":"limits"')"
FREE=$(json_id)
api_ok POST /firewall/rules "$(rj lb-up-opt accept rtr-opt 9200)"
OPTR=$(json_id)
: > /tmp/lb-sink.txt
C python3 "$NL_T/lb-push.py" $NL_WWW 9200; sleep 1.5
FREE_BPS=$(sink_bytes $NL_CLIENT)
nl_ok "unlimited upload: $(mbps "$FREE_BPS") kB/s"
api_ok PUT /firewall/rules/$FREE "$(rj lb-up-free accept @lan 9200 ',"limiter":"cap4m","category":"limits"')"
nl_assert_nft_has "chain lim_forward" "limit rate over 500000 bytes/second burst 128 kbytes drop"
: > /tmp/lb-sink.txt
C python3 "$NL_T/lb-push.py" $NL_WWW 9200 &
C2 python3 "$NL_T/lb-push.py" $NL_WWW 9200 &
wait; sleep 1.5
LIM1=$(sink_bytes $NL_CLIENT); LIM2=$(sink_bytes $C2_NET.10)
nl_ok "limited upload: client 1 $(mbps "$LIM1") kB/s (cap 500), client 2 (no limiter) $(mbps "$LIM2") kB/s"
[ "$(mbps "$LIM1")" -le 800 ] || nl_fail "the limiter did not hold: client 1 sent $(mbps "$LIM1") kB/s against a 500 kB/s cap"
[ "$(mbps "$LIM1")" -ge 150 ] || nl_fail "the limiter strangled the flow: $(mbps "$LIM1") kB/s"
[ "$LIM2" -gt $((LIM1 * 3)) ] || nl_fail "client 2 should be unaffected by client 1's limiter ($(mbps "$LIM2") vs $(mbps "$LIM1") kB/s)"
nl_ok "the limiter caps one client's rate and leaves the other alone (server-side byte count)"
api_code 400 DELETE /firewall/limiters/cap4m
nl_ok "a limiter in use cannot be deleted (400)"
api_code 400 POST /firewall/rules "$(rj lb-bad accept @lan 9200 ',"limiter":"nope"')"
nl_ok "a rule naming an unknown limiter is refused (400)"
api_code 400 POST /firewall/rules "$(rj lb-bad drop @lan 9200 ',"max_states":3')"
nl_ok "state limits on a block rule are refused (400)"
api_code 400 POST /firewall/rules "$(rj lb-bad accept group:nogroup 9200)"
nl_ok "a rule on an unknown interface group is refused (400)"
api_code 400 POST /firewall/rules "$(rj lb-bad accept @lan 9200 ',"category":"x\"; flush ruleset"')"
nl_ok "a category with quotes is refused (400)"
nl_assert_nft_lacks "flush ruleset"

echo "=== 7. categories"
nl_api GET /firewall/categories
grep -q '"limits"' "$NL_OUT" || nl_fail "categories lack 'limits': $(cat "$NL_OUT")"
nl_ok "the category list names 'limits' with its rule count"

echo "=== 8. reboot: everything returns from the store"
api_ok POST /firewall/interface-groups '{"name":"edge","members":["rtr-lan","rtr-opt"]}'
api_ok POST /firewall/rules "$(floating lb-float-persist drop true in '["group:edge","rtr-wan"]' 9000)"
nl_web_stop
nl_stop_servers
ip netns del nl-c2 2>/dev/null || true
boot
nl_assert_nft_has "set ifgrp_edge" "iifname @ifgrp_edge" "limit rate over 500000 bytes/second"
R nft list set inet patronus ifgrp_edge | grep -q '"rtr-opt"' || nl_fail "group members did not return after the reboot"
expect_blocked "after reboot: floating rule on the group blocks client 1" C $NL_WWW 9000
expect_blocked "after reboot: floating rule on the group blocks client 2" C2 $NL_WWW 9000
nl_ok "floating rules, groups and limiters came back from the store alone"
echo "lane-b-floating: all checks passed"
