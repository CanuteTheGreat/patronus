#!/usr/bin/env bash
# Lane S (device segmentation), per-device / per-group DNS policy and query
# logs. Runs INSIDE the capped Gentoo container started by
# ci/netlab/lan-services.sh (real Unbound, real OpenRC/systemd, patronus-web
# as user patronus + applyd as root), as root, shipped binaries in /t.
# $1 = openrc | systemd.
#
#   kid, kid2 (group kids), teen (group teens), parent (group home),
#   guest (not a device) --- [br rtr-lan 192.168.50.1/24]
#   upstream resolver (dnsmasq, 127.0.0.3) answers the test names
#
# Proves, with dig from client namespaces: DNS answers per group, a device
# policy overriding its group's, block / allow / override rules, the family
# preset (adult + malware lists, safe-search CNAME, DoH canary), global
# block lists still applying (view-first) and an allow rule beating them,
# DNS bypass attempts redirected to the resolver and DoT refused, per-device
# query logs (only for policies that log) with search / blocked filter / CSV,
# and that the views come back after a reboot-equivalent `patronus apply`.
set -euo pipefail
INIT=${1:?openrc|systemd}
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }
N() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
svc() { if [ "$INIT" = openrc ]; then rc-service "$2" "$1"; else systemctl "$1" "$2"; fi; }
running() { if [ "$INIT" = openrc ]; then rc-service "$1" status >/dev/null 2>&1; else systemctl is-active --quiet "$1"; fi; }
expect_running() { for s in "$@"; do running "$s" || fail "$s is not running ($INIT)"; done; ok "running under $INIT: $*"; }
has() { grep -qF -- "$2" "$1" || { echo "--- $1"; cat "$1" 2>/dev/null || true; fail "$1 lacks: $2"; }; }
DB=/var/lib/patronus/config.db

echo "=== 0. install the shipped binaries and $INIT service files"
install -m755 /t/patronus-cli /usr/bin/patronus-cli
ln -sf patronus-cli /usr/bin/patronus
install -m755 /t/patronus-web /usr/bin/patronus-web
getent group patronus >/dev/null || groupadd -r patronus
getent passwd patronus >/dev/null || useradd -r -g patronus -d /var/lib/patronus -s /sbin/nologin patronus
install -d -o patronus -g patronus /var/lib/patronus /var/log/patronus
install -d -o root -g patronus -m 0750 /etc/patronus
install -d -o patronus -g patronus -m 0700 /etc/patronus/tls
printf '[network]\nwan_interface = "rtr-wan"\nlan_interface = "rtr-lan"\n' > /etc/patronus/patronus.toml
if [ "$INIT" = openrc ]; then
  sed -i 's/^#\?rc_sys=.*/rc_sys="docker"/' /etc/rc.conf
  printf 'rc_provide="loopback net"\nrc_depend_strict="NO"\n' >> /etc/rc.conf
  mkdir -p /run/openrc && touch /run/openrc/softlevel
  for s in applyd web firewall; do install -m755 "/t/patronus-$s.initd" "/etc/init.d/patronus-$s"; done
else
  for s in applyd web firewall; do install -m644 "/t/patronus-$s.service" /etc/systemd/system/; done
  systemctl daemon-reload
fi
command -v unbound dig nft python3 >/dev/null

echo "=== 1. topology"
ip link add rtr-lan type bridge; ip link set rtr-lan up; ip addr add 192.168.50.1/24 dev rtr-lan
ip link add rtr-wan type dummy; ip link set rtr-wan up; ip addr add 203.0.113.2/24 dev rtr-wan
client() { # ns last-octet
  ip netns add "$1"; ip link add "$1-eth" type veth peer name "$1-br"
  ip link set "$1-eth" netns "$1"; ip link set "$1-br" master rtr-lan up
  ip -n "$1" link set lo up; ip -n "$1" link set "$1-eth" up
  ip -n "$1" addr add "192.168.50.$2/24" dev "$1-eth"; ip -n "$1" route add default via 192.168.50.1
}
client kid 31; client kid2 35; client teen 32; client parent 33; client guest 34; client adm 5
ip addr add 127.0.0.3/8 dev lo 2>/dev/null || true
sleep 1
# the "internet" resolver Unbound forwards to
dnsmasq --conf-file=/dev/null --port=53 --listen-address=127.0.0.3 --bind-interfaces --no-resolv --no-hosts \
  --user=root --pid-file=/run/updns.pid \
  --address=/games.example/198.51.100.7 --address=/ads.example/198.51.100.8 --address=/ok.example/198.51.100.9 \
  --address=/adult.example/198.51.100.10 --address=/malware.example/198.51.100.11 \
  --address=/www.google.com/142.250.0.1 --address=/forcesafesearch.google.com/216.239.38.120 \
  --address=/social.example/198.51.100.12 --address=/extra.example/198.51.100.13
printf '# adult list (hosts format)\n0.0.0.0 adult.example\n' > /t/adult.txt
printf 'malware.example\n' > /t/malware.txt
printf '0.0.0.0 extra.example\n' > /t/extra.txt
ok "clients kid/kid2/teen/parent/guest on rtr-lan, upstream resolver 127.0.0.3"

echo "=== 2. boot: patronus apply, then applyd + web as user patronus"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply"; }
expect_running unbound
svc start patronus-applyd; svc start patronus-web
for i in $(seq 1 60); do N adm curl -sk -o /dev/null https://192.168.50.1:8443/login && break; sleep 0.5; done
N adm curl -sk -o /dev/null https://192.168.50.1:8443/login || fail "web UI not reachable"
PASS=$(tr -d '\n' < /var/lib/patronus/initial-admin-password)
api() { local data=(); [ $# -ge 3 ] && data=(-d "$3")
  N adm curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" -H 'content-type: application/json' "${data[@]}" "https://192.168.50.1:8443$2"; }
want() { local w=$1; shift; local code; code=$(api "$@"); [ "$code" = "$w" ] || fail "$1 $2 -> $code (want $w): $(cat /tmp/api.out)"; }
jget() { python3 -c 'import json,sys; d=json.load(open("/tmp/api.out")); print(eval(sys.argv[1]))' "$1"; }
want 200 POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"

echo "=== 3. groups and devices (foundation API), DNS upstream and the global block list"
mac() { ip -n "$1" -br link show "$1-eth" | awk '{print $3}'; }
want 201 POST /api/segmentation/groups '{"name":"kids"}'
want 201 POST /api/segmentation/groups '{"name":"teens"}'
for spec in "kid:31:kids" "kid2:35:kids" "teen:32:teens" "parent:33:home"; do
  IFS=: read -r n ip g <<<"$spec"
  want 201 POST /api/segmentation/devices "{\"name\":\"$n\",\"mac\":\"$(mac $n)\",\"group\":\"$g\",\"kind\":\"wired\",\"segment\":\"@lan\",\"ip4\":\"192.168.50.$ip\"}"
done
# the family preset's lists point at local files (no internet in CI)
python3 - <<'EOF'
import sqlite3
c = sqlite3.connect("/var/lib/patronus/config.db", timeout=10)
c.execute("INSERT OR REPLACE INTO lan_settings (key, value, updated_at) VALUES ('dns.family_lists', 'file:///t/adult.txt file:///t/malware.txt', 0)")
c.commit()
EOF
want 200 PUT /api/dns/settings '{"upstreams":"127.0.0.3","dnssec":false}'
want 201 POST /api/dns/blocklist '{"domain":"ads.example"}'
d() { # ns name [type] [server]  -> prints the whole answer
  N "$1" dig +time=3 +tries=1 "@${4:-192.168.50.1}" "$2" "${3:-A}"
}
a() { N "$1" dig +short +time=3 +tries=1 "@${4:-192.168.50.1}" "$2" "${3:-A}"; }
expect_a() { local r; r=$(a "$1" "$2" A | tail -1); [ "$r" = "$3" ] || fail "$1: $2 -> '$r' (want $3)"; ok "$1 resolves $2 -> $3"; }
expect_nx() { d "$1" "$2" | grep 'status: NXDOMAIN' >/dev/null || { d "$1" "$2"; fail "$1: $2 should be NXDOMAIN"; }; ok "$1: $2 -> NXDOMAIN"; }
for ns in kid kid2 teen parent guest; do expect_a $ns ok.example 198.51.100.9; done
expect_a parent games.example 198.51.100.7
expect_nx guest ads.example
ok "no policy yet: every client resolves, the global block list applies to all"

echo "=== 4. policies through the API (what the UI sends)"
want 201 POST /api/segmentation/dns/policies '{"name":"kids","family":true,"log_queries":true,"log_retention_days":3,"blocklist_urls":"file:///t/extra.txt"}'
KIDS=$(jget 'd["id"]')
want 201 POST /api/segmentation/dns/policies '{"name":"teens","log_queries":false}'
TEENS=$(jget 'd["id"]')
want 201 POST /api/segmentation/dns/policies '{"name":"plain"}'
PLAIN=$(jget 'd["id"]')
want 400 POST /api/segmentation/dns/policies '{"name":"bad name"}'
want 400 POST /api/segmentation/dns/policies '{"name":"x","blocklist_urls":"javascript:alert(1)"}'
want 201 POST /api/segmentation/dns/policies/$KIDS/rules '{"action":"block","domain":"games.example"}'
want 201 POST /api/segmentation/dns/policies/$TEENS/rules '{"action":"allow","domain":"ads.example"}'
want 201 POST /api/segmentation/dns/policies/$TEENS/rules '{"action":"block","domain":"social.example"}'
want 201 POST /api/segmentation/dns/policies/$TEENS/rules '{"action":"override","domain":"printer.lan","address":"10.0.0.9"}'
want 400 POST /api/segmentation/dns/policies/$TEENS/rules '{"action":"override","domain":"x.lan"}'
want 400 POST /api/segmentation/dns/policies/$TEENS/rules '{"action":"block","domain":"a\"; local-zone: \".\" always_nxdomain"}'
GK=$(python3 -c "import sqlite3;print(sqlite3.connect('$DB').execute(\"SELECT id FROM seg_groups WHERE name='kids'\").fetchone()[0])")
GT=$(python3 -c "import sqlite3;print(sqlite3.connect('$DB').execute(\"SELECT id FROM seg_groups WHERE name='teens'\").fetchone()[0])")
K2=$(python3 -c "import sqlite3;print(sqlite3.connect('$DB').execute(\"SELECT id FROM seg_devices WHERE name='kid2'\").fetchone()[0])")
want 200 POST /api/segmentation/dns/assign "{\"kind\":\"group\",\"id\":$GK,\"policy_id\":$KIDS}"
want 200 POST /api/segmentation/dns/assign "{\"kind\":\"group\",\"id\":$GT,\"policy_id\":$TEENS}"
want 200 POST /api/segmentation/dns/assign "{\"kind\":\"device\",\"id\":$K2,\"policy_id\":$PLAIN}"
want 404 POST /api/segmentation/dns/assign '{"kind":"group","id":9999,"policy_id":null}'
has /etc/unbound/unbound.conf 'access-control-view: 192.168.50.31/32 "seg_kids"'
has /etc/unbound/unbound.conf 'access-control-view: 192.168.50.32/32 "seg_teens"'
has /etc/unbound/unbound.conf 'access-control-view: 192.168.50.35/32 "seg_plain"'
if grep -q 'access-control-view: 192.168.50.35/32 "seg_kids"' /etc/unbound/unbound.conf; then fail "device policy did not override its group's"; fi
expect_running unbound
sleep 1

echo "=== 5. answers per group / device"
# kids: family preset + rules + extra list, global list still applies (view-first)
expect_nx kid games.example
expect_nx kid adult.example
expect_nx kid malware.example
expect_nx kid extra.example
expect_nx kid ads.example
expect_nx kid use-application-dns.net
expect_a kid ok.example 198.51.100.9
r=$(d kid www.google.com A); grep -q 'forcesafesearch.google.com' <<<"$r" && grep -q '216.239.38.120' <<<"$r" || { echo "$r"; fail "kid: www.google.com is not forced to safe search"; }
ok "kid: www.google.com -> CNAME forcesafesearch.google.com -> 216.239.38.120 (safe search enforced)"
# a device policy beats the group's: kid2 is in group kids but has "plain"
expect_a kid2 games.example 198.51.100.7
expect_a kid2 adult.example 198.51.100.10
expect_nx kid2 ads.example
r=$(d kid2 www.google.com A); grep -q 'CNAME' <<<"$r" && fail "kid2 (plain policy) must not get safe search"
ok "kid2 (device policy plain) is not filtered like its group kids"
# teens: allow beats the global list, own block, override
expect_a teen ads.example 198.51.100.8
expect_nx teen social.example
expect_a teen printer.lan 10.0.0.9
expect_a teen games.example 198.51.100.7
expect_a teen adult.example 198.51.100.10
# parent (no policy) and guest (not a device): global behaviour only
expect_nx parent ads.example
expect_a parent games.example 198.51.100.7
expect_a parent social.example 198.51.100.12
expect_a guest games.example 198.51.100.7
expect_a guest www.google.com 142.250.0.1
if a parent printer.lan | grep 10.0.0.9 >/dev/null; then fail "override leaked to a device without the policy"; fi
ok "parent/guest: global policy only (ads blocked, no overrides, no safe search)"

echo "=== 6. bypass: hard-coded resolver is redirected, DNS-over-TLS refused"
T=$(nft list table inet patronus_dnspol)   # (capture first: grep -q would SIGPIPE nft under pipefail)
grep -q 'policed_v4' <<<"$T" || fail "no inet patronus_dnspol table"
grep -q '192.168.50.31' <<<"$T" || { echo "$T"; fail "kid not in policed_v4"; }
ok "table inet patronus_dnspol lists the policed devices"
expect_nx kid games.example   # via the router
r=$(N kid dig +time=3 +tries=1 @198.51.100.99 games.example A) || true
grep -q 'status: NXDOMAIN' <<<"$r" || { echo "$r"; fail "kid asking 198.51.100.99 directly was not redirected to the policy resolver"; }
ok "kid -> @198.51.100.99 (hard-coded resolver) is redirected: games.example still NXDOMAIN"
r=$(N guest dig +time=2 +tries=1 @198.51.100.99 games.example A 2>&1) || true
grep -q 'status: NOERROR' <<<"$r" && fail "guest has no policy: its query to a non-existent resolver must not be answered"
ok "guest (no policy) is not redirected"
if N kid timeout 3 python3 -c "import socket;socket.create_connection(('198.51.100.99',853),2)" 2>/dev/null; then fail "DoT reachable"; fi
ok "kid -> tcp 853 (DNS-over-TLS) refused"

echo "=== 7. per-device query logs"
sleep 1
for n in games.example ok.example adult.example; do a kid $n >/dev/null; done
a teen social.example >/dev/null; a parent ok.example >/dev/null; a kid2 ok.example >/dev/null
[ -s /var/log/unbound/unbound.log ] || fail "unbound wrote no query log"
ok "unbound logs replies to /var/log/unbound/unbound.log ($(wc -l < /var/log/unbound/unbound.log) lines)"
KIDID=$(python3 -c "import sqlite3;print(sqlite3.connect('$DB').execute(\"SELECT id FROM seg_devices WHERE name='kid'\").fetchone()[0])")
got=
for i in $(seq 1 30); do
  code=$(api GET "/api/segmentation/dns/log?device=$KIDID")
  [ "$code" = 200 ] && [ "$(jget 'len(d["rows"])')" -ge 3 ] && { got=1; break; }
  sleep 1
done
[ -n "$got" ] || fail "kid's queries never reached the log API: $(cat /tmp/api.out)"
[ "$(jget 'sorted(set(r["device"] for r in d["rows"]))')" = "['kid']" ] || fail "log rows of other devices: $(cat /tmp/api.out)"
[ "$(jget 'any(r["qname"]=="games.example" and r["blocked"] and r["rcode"]=="NXDOMAIN" for r in d["rows"])')" = True ] || fail "blocked query not flagged: $(cat /tmp/api.out)"
[ "$(jget 'any(r["qname"]=="ok.example" and not r["blocked"] and r["rcode"]=="NOERROR" for r in d["rows"])')" = True ] || fail "allowed query missing: $(cat /tmp/api.out)"
ok "kid's log: games.example blocked/NXDOMAIN, ok.example NOERROR, adult.example"
want 200 GET /api/segmentation/dns/log
[ "$(jget 'sorted(set(r["device"] for r in d["rows"]))')" = "['kid']" ] || fail "only the policy that logs may be stored (teen/parent/kid2 must not appear): $(cat /tmp/api.out)"
ok "teen (policy without logging), parent (no policy) and kid2 (plain, no logging) are not in the log"
want 200 GET "/api/segmentation/dns/log?q=GAMES"
[ "$(jget 'len(d["rows"]) >= 1 and all("games" in r["qname"] for r in d["rows"])')" = True ] || fail "name search: $(cat /tmp/api.out)"
want 200 GET "/api/segmentation/dns/log?blocked=true"
[ "$(jget 'all(r["blocked"] for r in d["rows"]) and len(d["rows"]) >= 2')" = True ] || fail "blocked filter: $(cat /tmp/api.out)"
ok "search by name and 'blocked only' filter work"
N adm curl -sk -b /t/jar -o /tmp/log.csv -D /tmp/log.hdr "https://192.168.50.1:8443/api/segmentation/dns/log.csv"
grep -qi 'text/csv' /tmp/log.hdr && head -1 /tmp/log.csv | grep '^time,device,client,name' >/dev/null && grep -q 'games.example' /tmp/log.csv || { cat /tmp/log.hdr /tmp/log.csv; fail "CSV export"; }
ok "CSV export works"
code=$(api GET /segmentation/dns); [ "$code" = 200 ] && grep -q "DNS policy" /tmp/api.out || fail "/segmentation/dns page: $code"
ok "page /segmentation/dns renders"

echo "=== 8. reboot: configs deleted, daemons stopped, patronus apply brings the views back"
svc stop unbound
rm -f /etc/unbound/unbound.conf
nft delete table inet patronus_dnspol
patronus apply >/tmp/apply2.out 2>&1 || { cat /tmp/apply2.out; fail "patronus apply after the reboot"; }
has /etc/unbound/unbound.conf 'access-control-view: 192.168.50.31/32 "seg_kids"'
expect_running unbound
sleep 1
expect_nx kid games.example
expect_a teen ads.example 198.51.100.8
expect_a kid2 games.example 198.51.100.7
T=$(nft list table inet patronus_dnspol); grep -q '192.168.50.31' <<<"$T" || fail "enforcement table not restored by apply"
ok "after the reboot the per-group answers and the enforcement table are back"

echo "=== 9. detaching and deleting"
want 200 POST /api/segmentation/dns/assign "{\"kind\":\"group\",\"id\":$GK,\"policy_id\":null}"
sleep 1
expect_a kid games.example 198.51.100.7
want 200 DELETE /api/segmentation/dns/policies/$TEENS
sleep 1
expect_nx teen ads.example
want 404 DELETE /api/segmentation/dns/policies/$TEENS
ok "detaching / deleting a policy returns the clients to the global policy"
echo "PASS segmentation-dns ($INIT)"
