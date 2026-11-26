#!/usr/bin/env bash
# Lane G phase 2 netlab: HA configuration sync between TWO Patronus routers (run by
# `NETLAB_TEST=ha-sync-test.sh ci/netlab/lan-services.sh openrc|systemd`).
#
#   A = this container (rtr-lan 192.168.50.2): the sync SOURCE, patronus-web as user patronus,
#       applyd as root, started through OpenRC / systemd like in production
#   B = netns hb (hb0 192.168.50.3): a second complete Patronus (own store, own nftables) in a
#       private mount namespace, TARGET
#   client = netns lan, only used to reach both web UIs
#
# Proves: a firewall rule added on A appears in B's nftables; the API key never goes to a server
# whose TLS key does not match the pin; a switched-off section is untouched on B (B keeps its own
# NAT rule, A's NAT rule never arrives); a push B cannot apply (rule uses an alias that is not
# synced) is refused, undone on B (B's nftables unchanged) and reported on A with B's reason;
# a node that does not accept refuses; push and accept on one node are refused; B keeps a
# revision of what it received.
set -euo pipefail
INIT=${1:?openrc|systemd}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }
N() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
has() { grep -qF -- "$2" <<<"$1" || fail "$3: $1"; }
wait_for() { # DESC SECONDS cmd...
  local d=$1 s=$2; shift 2
  for i in $(seq 1 $((s * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for: $d"
}

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
case "$INIT" in
openrc)
  sed -i 's/^#\?rc_sys=.*/rc_sys="docker"/' /etc/rc.conf
  printf 'rc_provide="loopback net"\nrc_depend_strict="NO"\n' >> /etc/rc.conf
  mkdir -p /run/openrc && touch /run/openrc/softlevel
  for s in applyd web firewall; do install -m755 "/t/patronus-$s.initd" "/etc/init.d/patronus-$s"; done
  ;;
systemd)
  for s in applyd web firewall; do install -m644 "/t/patronus-$s.service" /etc/systemd/system/; done
  systemctl daemon-reload
  ;;
fake)
  # no init system: an OpenRC look-alike for keepalived and conntrackd
  mkdir -p /run/openrc /etc/init.d
  for s in keepalived conntrackd; do printf '#!/bin/sh\n' > /etc/init.d/$s; chmod +x /etc/init.d/$s; done
  cat > /usr/local/sbin/rc-service <<'EOF2'
#!/bin/sh
case "$1" in
  keepalived) CMD="/usr/sbin/keepalived -n -l -D"; ;;
  conntrackd) CMD="/usr/sbin/conntrackd -C /etc/conntrackd/conntrackd.conf"; ;;
  *) exit 1 ;;
esac
P=/tmp/svc-$1.pid
up() { [ -f $P ] && kill -0 "$(cat $P)" 2>/dev/null; }
start() { up || { setsid $CMD >/tmp/svc-$1.log 2>&1 & echo $! > $P; sleep 1; }; }
stop() { up && kill "$(cat $P)"; rm -f $P; sleep 0.5; }
case "$2" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) up && echo " * status: started" || echo " * status: stopped" ;;
esac
EOF2
  chmod +x /usr/local/sbin/rc-service
  printf '#!/bin/sh\nexit 0\n' > /usr/local/sbin/rc-update; chmod +x /usr/local/sbin/rc-update
  ;;
esac


echo "=== 1. topology: A (this container), B (netns hb), a client, one LAN segment"
ip netns add sw; ip netns add hb; ip netns add lan
ip link add rtr-lan type veth peer name sw-a netns sw
ip link add hb0 netns hb type veth peer name sw-b netns sw
ip link add lan0 netns lan type veth peer name sw-c netns sw
N sw ip link add br0 type bridge
for p in sw-a sw-b sw-c; do N sw ip link set $p master br0; N sw ip link set $p up; done
N sw ip link set br0 up
ip link add rtr-wan type dummy; ip addr add 203.0.113.2/24 dev rtr-wan; ip link set rtr-wan up
N hb ip link add hb-wan type dummy; N hb ip addr add 203.0.113.3/24 dev hb-wan; N hb ip link set hb-wan up
ip addr add 192.168.50.2/24 dev rtr-lan; ip link set rtr-lan up
N hb ip link set lo up; N hb ip addr add 192.168.50.3/24 dev hb0; N hb ip link set hb0 up
N lan ip link set lo up; N lan ip addr add 192.168.50.10/24 dev lan0; N lan ip link set lan0 up
ok "A 192.168.50.2, B 192.168.50.3, client 192.168.50.10"

echo "=== 2. A: boot + applyd + web as user patronus"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply on A"; }
case "$INIT" in
  openrc) rc-service patronus-applyd start; rc-service patronus-web start ;;
  systemd) systemctl start patronus-applyd patronus-web ;;
esac
for i in $(seq 1 60); do N lan curl -sk -o /dev/null https://192.168.50.2/login && break; sleep 0.5; done
getent group patronus-admin >/dev/null || groupadd -r patronus-admin
id nladmin >/dev/null 2>&1 || useradd -m -G patronus-admin -s /bin/sh nladmin
PASS="Nl-$(head -c9 /dev/urandom | base64 | tr -d '/+=')-1a"
echo "nladmin:$PASS" | chpasswd -c SHA512
# api HOST METHOD PATH [DATA] [extra curl args via CURL_EXTRA]: jar per host
api() { # HOST METHOD PATH [DATA]
  local h=$1 m=$2 p=$3; shift 3
  local data=(); [ $# -ge 1 ] && data=(-d "$1")
  N lan curl -sk -b /t/jar-$h -c /t/jar-$h -o /tmp/api.out -w '%{http_code}' -X "$m" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.$h$p"
}
want() { local w=$1; shift; local code; code=$(api "$@"); [ "$code" = "$w" ] || fail "$2 $3 -> $code (want $w): $(cat /tmp/api.out)"; }
jget() { python3 -c "import json,sys; d=json.load(open('/tmp/api.out')); print($1)"; }
want 200 2 POST /api/auth/login "{\"username\":\"nladmin\",\"password\":\"$PASS\"}"
ok "A is up"

echo "=== 3. B: a second Patronus with its own store in a private mount namespace"
rm -rf /t/b; mkdir -p /t/b/etc/tls /t/b/var /t/b/run /t/b/log
printf '[network]\nwan_interface = "hb-wan"\nlan_interface = "hb0"\n' > /t/b/etc/patronus.toml
cat > /t/b/boot.sh <<'SH'
#!/bin/sh
mount --bind /t/b/etc /etc/patronus
mount --bind /t/b/var /var/lib/patronus
mount --bind /t/b/run /run/patronus
chmod 755 /run/patronus
patronus apply >/t/b/log/apply.log 2>&1 || { echo "B apply failed" >&2; cat /t/b/log/apply.log >&2; exit 1; }
patronus applyd >/t/b/log/applyd.log 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -S /run/patronus/applyd.sock ] && break; sleep 0.5; done
exec patronus-web >/t/b/log/web.log 2>&1
SH
chmod +x /t/b/boot.sh
ip netns exec hb unshare -m --propagation private /t/b/boot.sh &
B_PID=$!
for i in $(seq 1 90); do N lan curl -sk -o /dev/null https://192.168.50.3/login && break; sleep 0.5; done
N lan curl -sk -o /dev/null https://192.168.50.3/login || { cat /t/b/log/*.log; fail "B's web UI did not come up"; }
want 200 3 POST /api/auth/login "{\"username\":\"nladmin\",\"password\":\"$PASS\"}"
ok "B is up (own store, own nftables, 192.168.50.3)"

echo "=== 4. B accepts pushes: a dedicated operator key, its TLS pin"
want 200 3 GET /api/ha/sync
PIN_B=$(jget "d['own_pin']")
case "$PIN_B" in sha256//*) ;; *) fail "B shows no TLS pin: $PIN_B" ;; esac
want 201 3 POST /api/system/api-keys '{"name":"ha-sync","scope":"operator"}'
KEY=$(jget "d['token']")
NB_RULES_BEFORE=$(N hb nft list ruleset | md5sum | cut -c1-12)
want 200 3 PUT /api/ha/sync/settings '{"accept":true}'
ok "B: accept on, operator key made, pin $PIN_B"

echo "=== 5. A: push-and-accept on one node is refused; a missing pin / key is refused"
want 200 2 GET /api/ha/sync
has "$(cat /tmp/api.out)" '"own_pin"' "A shows its own pin"
code=$(api 2 PUT /api/ha/sync/settings '{"push":true,"accept":true}'); [ "$code" = 400 ] || fail "push+accept -> $code"
has "$(cat /tmp/api.out)" "not both" "no reason for push+accept"
code=$(api 2 PUT /api/ha/sync/settings '{"push":true}'); [ "$code" = 400 ] || fail "push without key -> $code"
code=$(api 2 PUT /api/ha/sync/settings "{\"push\":true,\"api_key\":\"$KEY\"}"); [ "$code" = 400 ] || fail "push without pin -> $code"
has "$(cat /tmp/api.out)" "pin" "no mention of the pin"
ok "invalid sync settings are refused with the reason"

echo "=== 6. a wrong pin: the key is never sent, the failure is reported"
want 201 2 POST /api/firewall/rules '{"name":"sync-a","action":"accept","interface":"any","protocol":"tcp","source":"any","destination":"any","port":"9876","description":"","enabled":true,"chain":"input"}'
WRONG='sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
want 200 2 PUT /api/ha/sync/settings "{\"push\":true,\"api_key\":\"$KEY\",\"peer_pin\":\"$WRONG\",\"peer_url\":\"https://192.168.50.3\",\"check_secs\":5,\"retry_secs\":10}"
code=$(api 2 POST /api/ha/sync/push); [ "$code" = 502 ] || fail "push with a wrong pin -> $code: $(cat /tmp/api.out)"
has "$(cat /tmp/api.out)" "cannot reach the peer" "wrong-pin failure not reported"
[ "$(N hb nft list ruleset | md5sum | cut -c1-12)" = "$NB_RULES_BEFORE" ] || fail "B changed although the pin did not match"
want 200 3 GET /api/ha/sync/history
[ "$(jget 'len([r for r in d if r["direction"]=="receive"])')" = 0 ] || fail "B received something through a wrong pin"
ok "wrong pin: curl refused the connection before any data, B untouched, A recorded the failure"

echo "=== 7. the right pin: a rule added on A appears in B's nftables"
want 200 2 PUT /api/ha/sync/settings "{\"peer_pin\":\"$PIN_B\"}"
wait_for "the rule on B" 40 sh -c "ip netns exec hb nft list ruleset | grep -F 'dport 9876' >/dev/null"
want 200 2 GET /api/ha/sync
has "$(cat /tmp/api.out)" '"last_push_ok":{' "A shows no good push"
want 200 3 GET /api/ha/sync/history
[ "$(jget 'len([r for r in d if r["direction"]=="receive" and r["ok"]])')" -ge 1 ] || fail "B recorded no receive"
REV=$(python3 -c "import sqlite3; print(sqlite3.connect('/t/b/var/config.db').execute(\"select count(*) from config_revisions where summary like '%HA sync%'\").fetchone()[0])")
[ "$REV" -ge 1 ] || fail "B kept no revision of what it received"
ok "rule sync-a: A -> B nftables over pinned HTTPS, B kept a revision"
# a second, unchanged look pushes nothing
sleep 12; want 200 3 GET /api/ha/sync/history
N1=$(jget 'len(d)'); sleep 12; want 200 3 GET /api/ha/sync/history
[ "$(jget 'len(d)')" = "$N1" ] || fail "an unchanged configuration was pushed again"
ok "unchanged configuration is not pushed again"

echo "=== 8. a switched-off section stays untouched"
want 200 2 PUT /api/ha/sync/settings '{"sections":{"nat":false}}'
want 201 3 POST /api/firewall/nat '{"rule_type":"SNAT","interface":"@wan","source":"192.168.77.0/24","destination":"any","target":"203.0.113.3","description":"b-own-nat","enabled":true}'
want 201 2 POST /api/firewall/nat '{"rule_type":"SNAT","interface":"@wan","source":"192.168.60.0/24","destination":"any","target":"203.0.113.2","description":"a-nat","enabled":true}'
want 201 2 POST /api/firewall/rules '{"name":"sync-b","action":"accept","interface":"any","protocol":"tcp","source":"any","destination":"any","port":"9877","description":"","enabled":true,"chain":"input"}'
wait_for "the second rule on B" 40 sh -c "ip netns exec hb nft list ruleset | grep -F 'dport 9877' >/dev/null"
RS=$(N hb nft list ruleset)
has "$RS" "192.168.77.0/24" "B lost its own NAT rule"
if grep -qF "192.168.60.0/24" <<<"$RS"; then fail "A's NAT rule reached B although the nat section is off"; fi
ok "nat off: B keeps its own NAT rule, A's NAT rule never arrives, the firewall section still syncs"

echo "=== 9. a push B cannot apply is refused, undone on B and reported on A"
want 201 2 POST /api/firewall/aliases '{"name":"websrv","type":"host","entries":["10.1.1.5"]}'
want 201 2 POST /api/firewall/rules '{"name":"sync-alias","action":"accept","interface":"any","protocol":"tcp","source":"$websrv","destination":"any","port":"9878","description":"","enabled":true,"chain":"input"}'
before=$(N hb nft list ruleset | md5sum | cut -c1-12)
has_fail() { api 2 GET /api/ha/sync >/dev/null && grep -q '"last_push":{[^}]*"ok":false' /tmp/api.out; }
wait_for "A reports the failed push" 40 has_fail
has "$(cat /tmp/api.out)" "websrv" "A does not show B's reason"
[ "$(N hb nft list ruleset | md5sum | cut -c1-12)" = "$before" ] || fail "B's nftables changed although its apply was refused"
if N hb nft list ruleset | grep -F 'dport 9878' >/dev/null; then fail "the refused rule is live on B"; fi
want 200 3 GET /api/ha
want 200 3 GET /api/ha/sync
has "$(cat /tmp/api.out)" '"last_receive":{' "B recorded nothing"
ok "refused push: B undid it (nftables identical), A shows the failure with B's reason (unknown alias)"
want 200 2 PUT /api/ha/sync/settings '{"sections":{"aliases":true}}'
wait_for "the alias rule on B once aliases sync too" 40 sh -c "ip netns exec hb nft list ruleset | grep -F 'dport 9878' >/dev/null"
ok "with the aliases section on the same rule syncs"

echo "=== 10. a node that does not accept refuses"
want 200 2 PUT /api/ha/sync/settings '{"push":false}'
want 200 3 PUT /api/ha/sync/settings '{"accept":false}'
code=$(N lan curl -sk -o /tmp/api.out -w '%{http_code}' -X POST -H "Authorization: Bearer $KEY" -H 'content-type: application/json' -d '{"source":"x","config":{}}' https://192.168.50.3/api/ha/sync/receive)
[ "$code" = 403 ] || fail "B accepted a push with accept off -> $code: $(cat /tmp/api.out)"
has "$(cat /tmp/api.out)" "does not accept" "no reason"
ok "accept off: HTTP 403 with the reason"

kill "$B_PID" 2>/dev/null || true
echo "ALL HA SYNC NETLAB CHECKS PASSED"
