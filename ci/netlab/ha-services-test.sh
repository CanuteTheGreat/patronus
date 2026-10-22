#!/usr/bin/env bash
# Lane G (high availability) netlab in a real Gentoo stage3 (run by
# `NETLAB_TEST=ha-services-test.sh ci/netlab/lan-services.sh openrc|systemd`),
# with the shipped binaries and init files: patronus-web runs as the
# unprivileged `patronus` user and every privileged step goes through
# `patronus applyd` (root); keepalived and conntrackd are the distro's own
# services started through OpenRC / systemd.
#
#   lan 192.168.50.10 --+                        +-- rtr-wan 203.0.113.2 -- inet 203.0.113.9
#                       |  bridge (netns sw)     |
#   A = this container: rtr-lan 192.168.50.2 (Patronus, priority 100)
#   B = netns hb:       hb0     192.168.50.3 (plain keepalived + conntrackd, priority 200)
#   VIP 192.168.50.254 (the client's default gateway); A<->B sync link sync-a/sync-b 10.9.9.0/24
#
# Proves: VIPs configured through the API become a keepalived config that
# really negotiates VRRP with an independent peer (the firewall opens
# protocol 112 for it); A is BACKUP next to the higher-priority B, takes the
# VIP within seconds when B dies, hands it back when B preempts; client
# traffic through the VIP flows via the new master; state sync: a long-lived
# connection through A shows up in B's conntrackd cache and in B's kernel
# table once B becomes master (maintenance mode on A forces that);
# `patronus apply` keeps the VIP; alias VIPs; reboot; HA off.
#
# INIT=fake: a Debian container without an init system (local debugging):
# a stand-in `rc-service` runs keepalived/conntrackd.
set -euo pipefail
INIT=${1:?openrc|systemd|fake}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok - $*"; }
N() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
has() { grep -qF -- "$2" <<<"$1" || fail "$3: $1"; }

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

SVC=keepalived
# processes of A (this netns) only: B runs the same daemons in netns hb
a_pids() { local p; for p in $(pgrep -x "$1" || true); do [ "$(readlink /proc/$p/ns/net)" = "$(readlink /proc/self/ns/net)" ] && echo "$p"; done; return 0; }
a_first_pid() { local x; x=$(a_pids "$1"); echo "${x%%$'\n'*}"; }
a_running() { [ -n "$(a_pids "$1")" ]; }
a_stopped() { [ -z "$(a_pids "$1")" ]; }
HASH_PW=hapass12
wait_for() { # DESC SECONDS cmd...: poll until the command succeeds
  local d=$1 s=$2; shift 2
  for i in $(seq 1 $((s * 2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for: $d"
}
a_has_vip() { ip -4 -br addr show dev rtr-lan | grep -q ' 192.168.50.254/24'; }
a_no_vip() { ! a_has_vip; }
b_has_vip() { N hb ip -4 -br addr show dev hb0 | grep -q ' 192.168.50.254/24'; }
b_no_vip() { ! b_has_vip; }
ha_state() { # state as the API reports it
  api GET /api/ha >/dev/null; python3 -c 'import json; print(json.load(open("/tmp/api.out"))["status"]["state"])'
}
state_is() { [ "$(ha_state 2>/dev/null)" = "$1" ]; }
file_state() { cut -d' ' -f1 /run/patronus/ha-state 2>/dev/null; }
file_state_is() { [ "$(file_state)" = "$1" ]; }

echo "=== 1. topology: A (this container) and B on one LAN segment, a client, an internet host"
ip netns add sw; ip netns add hb; ip netns add lan; ip netns add inet
ip link add rtr-lan type veth peer name sw-a netns sw
ip link add hb0 netns hb type veth peer name sw-b netns sw
ip link add lan0 netns lan type veth peer name sw-c netns sw
N sw ip link add br0 type bridge
for p in sw-a sw-b sw-c; do N sw ip link set $p master br0; N sw ip link set $p up; done
N sw ip link set br0 up
ip link add sync-a type veth peer name sync-b netns hb
ip link add rtr-wan type veth peer name in0 netns inet
ip addr add 192.168.50.2/24 dev rtr-lan; ip link set rtr-lan up
ip addr add 10.9.9.1/24 dev sync-a; ip link set sync-a up
ip addr add 203.0.113.2/24 dev rtr-wan; ip link set rtr-wan up
N hb ip link set lo up; N hb ip addr add 192.168.50.3/24 dev hb0; N hb ip link set hb0 up
N hb ip addr add 10.9.9.2/24 dev sync-b; N hb ip link set sync-b up
N lan ip link set lo up; N lan ip addr add 192.168.50.10/24 dev lan0; N lan ip link set lan0 up
N lan ip route add default via 192.168.50.254
N inet ip link set lo up; N inet ip addr add 203.0.113.9/24 dev in0; N inet ip link set in0 up
N inet ip route add default via 203.0.113.2
cat > /t/hold.py <<'PY'
import socket, sys, threading, time

def drain(c):
    while c.recv(100):
        pass

if sys.argv[1] == 'server':   # echo the peer address once, then keep the connection open
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[2], int(sys.argv[3]))); s.listen(16)
    while True:
        c, a = s.accept(); c.sendall((a[0] + "\n").encode())
        threading.Thread(target=drain, args=(c,), daemon=True).start()
else:                          # client: connect, report, then keep the flow alive for N seconds
    s = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=5)
    print(s.recv(100).decode().strip(), flush=True)
    end = time.time() + float(sys.argv[4]); n = 0
    while time.time() < end:
        try:
            s.sendall(b'x'); time.sleep(0.5); n += 1
        except OSError as e:
            print('broken after', n, e, flush=True); sys.exit(1)
    print('alive', n, flush=True)
PY
ip netns exec inet python3 /t/hold.py server 203.0.113.9 9000 & HOLD=$!
ok "A (rtr-lan 192.168.50.2) and B (hb0 192.168.50.3) share a LAN with the client; sync link 10.9.9.0/24; internet host 203.0.113.9"

echo "=== 2. B: a plain keepalived + conntrackd peer (priority 200), the VIP is 192.168.50.254"
rm -rf /t/hb; mkdir -p /t/hb
cat > /t/hb/notify.sh <<'SH'
#!/bin/sh
echo "$3" > /t/hb/state
CT="conntrackd -C /t/hb/ct.conf"
case "$3" in
  MASTER) $CT -c; $CT -f; $CT -R; $CT -B ;;
  BACKUP|FAULT) $CT -t; $CT -n ;;
esac
exit 0
SH
chmod +x /t/hb/notify.sh
cat > /t/hb/ct.conf <<'CF'
Sync {
    Mode FTFW {
        DisableExternalCache Off
    }
    UDP {
        IPv4_address 10.9.9.2
        IPv4_Destination_Address 10.9.9.1
        Port 3780
        Interface sync-b
        Checksum on
    }
}
General {
    Nice -20
    HashSize 32768
    HashLimit 131072
    LogFile /t/hb/ct.log
    LockFile /t/hb/ct.lock
    UNIX {
        Path /t/hb/ct.ctl
        Backlog 20
    }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept {
            TCP
            UDP
            ICMP
        }
        Address Ignore {
            IPv4_address 127.0.0.1
            IPv4_address 10.9.9.1
            IPv4_address 10.9.9.2
        }
    }
}
CF
b_keepalived_conf() { # PRIORITY
  cat > /t/hb/keepalived.conf <<CF
global_defs {
    router_id hb
    enable_script_security
    script_user root
}
vrrp_instance PAT_B {
    state BACKUP
    interface hb0
    virtual_router_id 51
    priority $1
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass $HASH_PW
    }
    unicast_src_ip 192.168.50.3
    unicast_peer {
        192.168.50.2
    }
    virtual_ipaddress {
        192.168.50.254/24 dev hb0
    }
    notify /t/hb/notify.sh
}
CF
}
B_PID=
b_start() { # PRIORITY
  b_keepalived_conf "$1"; rm -f /t/hb/state
  # a plain command (not the N function), so $! is keepalived itself
  ip netns exec hb keepalived -n -P -l -D -f /t/hb/keepalived.conf -p /t/hb/ka.pid -r /t/hb/vrrp.pid >/t/hb/ka.log 2>&1 &
  B_PID=$!
}
b_stop() {
  [ -n "$B_PID" ] && kill "$B_PID" 2>/dev/null
  kill $(cat /t/hb/ka.pid /t/hb/vrrp.pid 2>/dev/null) 2>/dev/null || true
  wait "$B_PID" 2>/dev/null || true; B_PID=; rm -f /t/hb/ka.pid /t/hb/vrrp.pid
  sleep 0.5
  N hb ip addr del 192.168.50.254/24 dev hb0 2>/dev/null || true
}
N hb conntrackd -C /t/hb/ct.conf -d || { cat /t/hb/ct.log 2>/dev/null; fail "B's conntrackd did not start (kernel without nfnetlink_conntrack?)"; }
b_start 200
wait_for "B becomes MASTER and holds the VIP" 15 b_has_vip
ok "B (priority 200) is MASTER and holds 192.168.50.254"

echo "=== 3. boot + patronus-applyd + patronus-web (as user patronus)"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply"; }
case "$INIT" in
  openrc) rc-service patronus-applyd start; rc-service patronus-web start ;;
  systemd) systemctl start patronus-applyd patronus-web ;;
  fake)
    patronus applyd >/t/applyd.log 2>&1 &
    for i in $(seq 1 20); do [ -S /run/patronus/applyd.sock ] && break; sleep 0.25; done
    setpriv --reuid patronus --regid patronus --init-groups \
      --inh-caps +net_admin,+net_raw --ambient-caps +net_admin,+net_raw \
      env HOME=/var/lib/patronus patronus-web >/t/web.log 2>&1 &
    ;;
esac
for i in $(seq 1 60); do N lan curl -sk -o /dev/null https://192.168.50.2:8443/login && break; sleep 0.5; done
PASS=$(tr -d '\n' < /var/lib/patronus/initial-admin-password)
api() {
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  N lan curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.2:8443$2"
}
want() { local w=$1; shift; local code; code=$(api "$@"); [ "$code" = "$w" ] || fail "$1 $2 -> $code (want $w): $(cat /tmp/api.out)"; }
want 200 POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"
# the client reaches the UI on A's own address; its default gateway is the VIP
ok "web UI up (as patronus), applyd as root"

echo "=== 4. HA from the API: refused without a virtual IP / with bad input, then configured"
want 400 POST /api/ha/vips '{"name":"x","interface":"@lan","address":"192.168.50.0/24"}'
want 400 PUT /api/ha/settings '{"priority":0}'
want 201 POST /api/ha/vips '{"name":"lan-gw","interface":"@lan","address":"192.168.50.254/24","vrid":51}'
want 200 PUT /api/ha/settings "{\"enabled\":true,\"priority\":100,\"preempt\":true,\"password\":\"$HASH_PW\",\"peer\":\"192.168.50.3\"}"
KA=$(cat /etc/keepalived/keepalived.conf)
has "$KA" "Managed by Patronus" "keepalived.conf not Patronus-managed"
has "$KA" "vrrp_instance PAT_rtr_lan_51" "no VRRP instance for rtr-lan"
has "$KA" "192.168.50.254/24 dev rtr-lan" "VIP missing from keepalived.conf"
has "$KA" "unicast_peer" "peer not configured"
has "$KA" "track_interface" "no tracked links"
has "$(cat /etc/patronus/ha-notify.sh)" "conntrackd" "notify script missing"
[ -x /etc/patronus/ha-notify.sh ] || fail "notify script not executable"
nft list ruleset | grep -Eq 'l4proto (112|vrrp) accept comment "HA VRRP"' || fail "firewall does not accept VRRP"
ok "keepalived.conf + notify script written, VRRP opened in nftables"
wait_for "A's keepalived is running (via $INIT)" 20 a_running keepalived
wait_for "A reports BACKUP (B is the master)" 20 state_is BACKUP
a_no_vip || fail "A holds the VIP although B (priority 200) is master"
b_has_vip || fail "B lost the VIP"
file_state_is BACKUP || fail "state file says $(file_state)"
ok "A (priority 100) is BACKUP next to B (200): VRRP adverts from B reach A through the firewall; the VIP stays on B"
want 200 GET /api/ha
has "$(cat /tmp/api.out)" '"keepalived":true' "API does not show keepalived running"
want 200 GET /ha
has "$(cat /tmp/api.out)" 'id="ha-form"' "HA page missing"
ok "API + HA page"

echo "=== 5. failover: B dies, A takes the VIP within seconds, traffic flows through A"
b_stop
wait_for "A becomes MASTER" 15 state_is MASTER
a_has_vip || fail "A is MASTER but 192.168.50.254 is not on rtr-lan"
file_state_is MASTER || fail "state file says $(file_state)"
OUT=$(N lan python3 /t/hold.py client 203.0.113.9 9000 1) || fail "client -> internet through the VIP: $OUT"
has "$OUT" "203.0.113.2" "the internet host did not see A's WAN address (NAT through the new master)"
ok "A is MASTER with 192.168.50.254 on rtr-lan; client (gateway = the VIP) reaches the internet host via A (seen as 203.0.113.2)"
# the watcher records the change and the summary shows it
has_ha_event() { N lan curl -sk -b /t/jar -o /tmp/ev.out 'https://192.168.50.2:8443/api/events?kind=ha_state' && grep -q MASTER /tmp/ev.out; }
wait_for "an ha_state event" 40 has_ha_event
want 200 GET /api/status/summary
has "$(cat /tmp/api.out)" '"state":"MASTER"' "summary lacks the HA state"
want 200 GET /metrics
has "$(cat /tmp/api.out)" 'patronus_ha_master 1' "metrics lack patronus_ha_master"
ok "ha_state event logged, /api/status/summary and /metrics report MASTER"

echo "=== 6. 'patronus apply' (boot) never takes the VIP off the master's interface"
PID_BEFORE=$(a_first_pid keepalived)
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply: $APPLY"; }
a_has_vip || fail "patronus apply removed the virtual IP from rtr-lan"
[ "$(a_first_pid keepalived)" = "$PID_BEFORE" ] || fail "an unchanged apply restarted keepalived"
ok "apply keeps the VIP and leaves keepalived alone when nothing changed"

echo "=== 7. B returns with the higher priority and preempts"
b_start 200
wait_for "B takes the VIP back" 15 b_has_vip
wait_for "A is BACKUP again" 15 state_is BACKUP
a_no_vip || fail "A still holds the VIP after B preempted"
ok "preemption: B is MASTER again, A drops the VIP and reports BACKUP"

echo "=== 8. state sync: A's conntrackd feeds B, which commits the flows when it becomes master"
b_stop
want 200 PUT /api/ha/settings '{"sync":true,"sync_interface":"sync-a","sync_peer":"10.9.9.2"}'
has "$(cat /etc/conntrackd/conntrackd.conf)" "IPv4_Destination_Address 10.9.9.2" "conntrackd.conf lacks the peer"
has "$(nft list ruleset)" 'iifname "sync-a" ip saddr 10.9.9.2 udp dport 3780 accept' "sync port not open"
wait_for "A's conntrackd is running" 20 a_running conntrackd
wait_for "A is MASTER (B is down)" 15 state_is MASTER
b_start 50
sleep 3
state_is MASTER || fail "A lost MASTER to a lower-priority B"
# a long-lived flow through A
N lan python3 /t/hold.py client 203.0.113.9 9000 40 >/t/flow.out 2>&1 &
FLOW=$!
wait_for "the flow is in A's conntrack table" 10 sh -c "conntrack -L 2>/dev/null | grep -q 'dst=203.0.113.9.*dport=9000'"
wait_for "B's external cache has the flow (state sync over UDP 3780)" 20 sh -c "conntrackd -C /t/hb/ct.conf -e 2>/dev/null | grep -q 'dst=203.0.113.9'"
ok "the flow client -> 203.0.113.9:9000 (through A) appears in B's conntrackd external cache"
echo "=== 9. maintenance mode on A: B takes over and commits the synced flow into its kernel table"
want 200 POST /api/ha/maintenance '{"enabled":true}'
wait_for "B becomes MASTER" 15 b_has_vip
wait_for "A is BACKUP" 15 state_is BACKUP
has "$(cat /etc/keepalived/keepalived.conf)" "priority 1" "maintenance priority missing"
wait_for "B's kernel table has the flow (notify -> conntrackd -c)" 15 sh -c "ip netns exec hb conntrack -L 2>/dev/null | grep -q 'dst=203.0.113.9.*dport=9000'"
ok "B (new master) committed the replicated connection into its own conntrack table"
want 200 POST /api/ha/maintenance '{"enabled":false}'
wait_for "A preempts again" 15 a_has_vip
wait_for "A is MASTER" 15 state_is MASTER
ok "leaving maintenance mode: A (priority 100 > 50) takes the VIP back"
kill "$FLOW" 2>/dev/null || true

echo "=== 10. alias virtual IPs are plain extra addresses and survive 'patronus apply'"
want 201 POST /api/ha/vips '{"name":"mgmt-alias","interface":"@lan","address":"192.168.50.77/24","mode":"alias"}'
ip -4 -br addr show dev rtr-lan | grep -q ' 192.168.50.77/24' || fail "alias address not on rtr-lan"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply: $APPLY"; }
ip -4 -br addr show dev rtr-lan | grep -q ' 192.168.50.77/24' || fail "patronus apply removed the alias"
ip -4 -br addr show dev rtr-lan | grep -q ' 192.168.50.254/24' || fail "patronus apply removed the CARP VIP"
ok "alias 192.168.50.77 is on rtr-lan and untouched by an interfaces apply"
api GET /api/ha >/dev/null
ALIAS_ID=$(python3 -c 'import json; print([v["id"] for v in json.load(open("/tmp/api.out"))["vips"] if v["name"]=="mgmt-alias"][0])')
want 200 DELETE "/api/ha/vips/$ALIAS_ID"
ip -4 -br addr show dev rtr-lan | grep -q ' 192.168.50.77/24' && fail "deleted alias still on rtr-lan"
ok "deleting the alias removes the address"

echo "=== 11. reboot: daemons stopped, configs gone, 'patronus apply' brings HA back"
b_stop
case "$INIT" in
  systemd) systemctl stop keepalived conntrackd ;;
  *) rc-service keepalived stop >/dev/null 2>&1 || true; rc-service conntrackd stop >/dev/null 2>&1 || true ;;
esac
wait_for "keepalived stopped" 15 a_stopped keepalived
ip addr del 192.168.50.254/24 dev rtr-lan 2>/dev/null || true
rm -f /etc/keepalived/keepalived.conf /etc/conntrackd/conntrackd.conf /etc/patronus/ha-notify.sh /run/patronus/ha-state
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply after reboot: $APPLY"; }
has "$(cat /etc/keepalived/keepalived.conf)" "192.168.50.254/24 dev rtr-lan" "keepalived.conf not rewritten"
wait_for "keepalived running again" 20 a_running keepalived
wait_for "A is MASTER again (B is down) and holds the VIP" 20 a_has_vip
ok "after reboot: files rewritten from the store, keepalived + conntrackd started, VIP back on A"

echo "=== 12. turning HA off stops the daemons and clears the addresses"
want 200 PUT /api/ha/settings '{"enabled":false,"sync":false}'
wait_for "keepalived stopped" 20 a_stopped keepalived
wait_for "conntrackd stopped" 20 a_stopped conntrackd
a_no_vip || fail "the VIP is still on rtr-lan after HA was turned off"
has "$(cat /etc/keepalived/keepalived.conf)" "Managed by Patronus" "idle file lost the marker"
if grep -q 192.168.50.254 /etc/keepalived/keepalived.conf; then fail "idle keepalived.conf still lists the VIP"; fi
has "$(nft list ruleset)" 'input' "ruleset gone?"
if nft list ruleset | grep -q 'HA VRRP'; then fail "VRRP is still open with HA off"; fi
ok "HA off: keepalived + conntrackd stopped, VIP removed, configs idle, VRRP/sync ports closed again"

kill "$HOLD" 2>/dev/null || true
b_stop; conntrackd -C /t/hb/ct.conf -k 2>/dev/null || true
echo "ALL HA NETLAB CHECKS PASSED"
