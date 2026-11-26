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
# DHCP failover (10b): A runs Kea with the HA hook from the stored settings,
# B is an independent Kea (hot-standby secondary) in netns hb; a client gets
# a lease from A, A fails, the client rebinds the SAME address from B within
# seconds, a new client gets a lease from B (gateway = the LAN VIP, which B
# holds), A returns and both lease databases agree. Services follow the VIP
# (10c): a WireGuard tunnel dialled at the WAN VIP re-establishes on B when A
# loses the VIP and comes back to A when it returns; A holds wg0 down while
# BACKUP and the HA page/API says why.
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
a_has_vip() { ip -4 -br addr show dev rtr-lan | grep ' 192.168.50.254/24' >/dev/null; }
a_no_vip() { ! a_has_vip; }
b_has_vip() { N hb ip -4 -br addr show dev hb0 | grep ' 192.168.50.254/24' >/dev/null; }
b_no_vip() { ! b_has_vip; }
ha_state() { # state as the API reports it
  api GET /api/ha >/dev/null; python3 -c 'import json; print(json.load(open("/tmp/api.out"))["status"]["state"])'
}
state_is() { [ "$(ha_state 2>/dev/null)" = "$1" ]; }
file_state() { cut -d' ' -f1 /run/patronus/ha-state 2>/dev/null; }
file_state_is() { [ "$(file_state)" = "$1" ]; }

echo "=== 1. topology: A (this container) and B on one LAN segment, a client, an internet host"
ip netns add sw; ip netns add hb; ip netns add lan; ip netns add inet; ip netns add cl
ip link add rtr-lan type veth peer name sw-a netns sw
ip link add hb0 netns hb type veth peer name sw-b netns sw
ip link add lan0 netns lan type veth peer name sw-c netns sw
ip link add cl0 netns cl type veth peer name sw-d netns sw
N sw ip link add br0 type bridge
for p in sw-a sw-b sw-c sw-d; do N sw ip link set $p master br0; N sw ip link set $p up; done
N sw ip link set br0 up
ip link add sync-a type veth peer name sync-b netns hb
ip link add rtr-wan type veth peer name in0 netns inet
ip link add hb-wan netns hb type veth peer name in1 netns inet
ip addr add 192.168.50.2/24 dev rtr-lan; ip link set rtr-lan up
ip addr add 10.9.9.1/24 dev sync-a; ip link set sync-a up
ip addr add 203.0.113.2/24 dev rtr-wan; ip link set rtr-wan up
N hb ip link set lo up; N hb ip addr add 192.168.50.3/24 dev hb0; N hb ip link set hb0 up
N hb ip addr add 10.9.9.2/24 dev sync-b; N hb ip link set sync-b up
N lan ip link set lo up; N lan ip addr add 192.168.50.10/24 dev lan0; N lan ip link set lan0 up
N lan ip route add default via 192.168.50.254
N cl ip link set lo up; N cl ip link set cl0 up
# the internet side is a bridge: A's WAN leg (in0), B's WAN leg (in1) and the host 203.0.113.9
N inet ip link set lo up; N inet ip link add bri type bridge
for p in in0 in1; do N inet ip link set $p master bri; N inet ip link set $p up; done
N inet ip addr add 203.0.113.9/24 dev bri; N inet ip link set bri up
N hb ip addr add 203.0.113.3/24 dev hb-wan; N hb ip link set hb-wan up
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
cat > /t/dhc.py <<'PY'
# minimal DHCPv4 client for the netlab: `dhc.py lease MAC SECONDS` (DISCOVER, REQUEST) and
# `dhc.py rebind MAC IP SECONDS` (what a client broadcasts at T2: REQUEST with ciaddr, no server id).
# Prints: ip=... server=... lease=... router=... dns=...
import socket, struct, sys, time, random
DEV = b'cl0'

def build(mac, xid, mtype, ciaddr='0.0.0.0', extra=b''):
    hw = bytes.fromhex(mac.replace(':', ''))
    pkt = struct.pack('!BBBBIHH4s4s4s4s16s64s128s4s', 1, 1, 6, 0, xid, 0, 0x8000,
                      socket.inet_aton(ciaddr), b'\0' * 4, b'\0' * 4, b'\0' * 4,
                      hw.ljust(16, b'\0'), b'', b'', b'\x63\x82\x53\x63')
    return pkt + bytes([53, 1, mtype]) + extra + b'\xff'

def parse(data, xid):
    if len(data) < 240 or struct.unpack('!I', data[4:8])[0] != xid:
        return None
    r = {'yiaddr': socket.inet_ntoa(data[16:20])}
    i = 240
    while i < len(data) and data[i] != 255:
        if data[i] == 0:
            i += 1; continue
        t, l = data[i], data[i + 1]; v = data[i + 2:i + 2 + l]; i += 2 + l
        if t == 53: r['type'] = v[0]
        elif t == 54: r['server'] = socket.inet_ntoa(v)
        elif t == 51: r['lease'] = struct.unpack('!I', v)[0]
        elif t == 3: r['router'] = socket.inet_ntoa(v[:4])
        elif t == 6: r['dns'] = socket.inet_ntoa(v[:4])
    return r

def frames(rs):
    # the interface has no address yet, so the kernel UDP stack would drop the broadcast reply:
    # read it from a packet socket like a real DHCP client does
    d = rs.recv(4096)
    if d[12:14] != b'\x08\x00' or d[23] != 17:
        return None
    ihl = (d[14] & 15) * 4
    sp, dp = struct.unpack('!HH', d[14 + ihl:18 + ihl])
    return d[14 + ihl + 8:] if (sp, dp) == (67, 68) else None

def exchange(s, rs, pkt, xid, want, secs):
    end = time.time() + secs
    while time.time() < end:
        s.sendto(pkt, ('255.255.255.255', 67))
        stop = time.time() + 2
        while time.time() < stop:
            rs.settimeout(max(0.1, stop - time.time()))
            try:
                d = frames(rs)
            except socket.timeout:
                break
            r = parse(d, xid) if d else None
            if r and r.get('type') in want:
                return r
    print('timeout', flush=True); sys.exit(2)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, DEV)
s.bind(('0.0.0.0', 68))
rs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rs.bind((DEV.decode(), 0))
mode, mac = sys.argv[1], sys.argv[2]
xid = random.getrandbits(32)
if mode == 'lease':
    secs = float(sys.argv[3])
    o = exchange(s, rs, build(mac, xid, 1), xid, (2,), secs)
    req = bytes([50, 4]) + socket.inet_aton(o['yiaddr']) + bytes([54, 4]) + socket.inet_aton(o['server'])
    r = exchange(s, rs, build(mac, xid, 3, extra=req), xid, (5, 6), secs)
else:
    ip, secs = sys.argv[3], float(sys.argv[4])
    r = exchange(s, rs, build(mac, xid, 3, ciaddr=ip), xid, (5, 6), secs)
if r['type'] == 6:
    print('nak', flush=True); sys.exit(3)
print('ip=%s server=%s lease=%s router=%s dns=%s' % (r['yiaddr'], r.get('server'), r.get('lease'), r.get('router'), r.get('dns')), flush=True)
PY
cat > /t/kea_state.py <<'PY'
# Kea's own HA state through its HA listener: kea_state.py URL dhcp4 -> hot-standby, partner-down, ...
import json, sys, urllib.request
req = urllib.request.Request(sys.argv[1], json.dumps({'command': 'ha-heartbeat', 'service': [sys.argv[2]]}).encode(),
                             {'Content-Type': 'application/json'})
try:
    print(json.load(urllib.request.urlopen(req, timeout=3))[0]['arguments']['state'])
except Exception as e:
    print('error', e); sys.exit(1)
PY
cat > /t/leases.py <<'PY'
# live leases of a Kea memfile (ip,hwaddr): the last row per address wins, expired/declined rows are dropped
import csv, sys, time
rows = {}
for r in csv.DictReader(open(sys.argv[1])):
    rows[r['address']] = r
for a, r in sorted(rows.items()):
    if int(r['state']) == 0 and int(r['expire']) > time.time():
        print(a, r['hwaddr'])
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
cat > /t/hb/notify-wan.sh <<'SH'
#!/bin/sh
# B's WAN instance: B's own WireGuard follows the WAN VIP
echo "$3" > /t/hb/wan-state
case "$3" in
  MASTER) ip link set wg0 up 2>/dev/null ;;
  *) ip link set wg0 down 2>/dev/null ;;
esac
exit 0
SH
chmod +x /t/hb/notify-wan.sh
B_WAN=0
b_wan_instance() { # PRIORITY
  [ "$B_WAN" = 1 ] || return 0
  cat <<CF
vrrp_instance PAT_B_WAN {
    state BACKUP
    interface hb-wan
    virtual_router_id 52
    priority $1
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass $HASH_PW
    }
    virtual_ipaddress {
        203.0.113.254/24 dev hb-wan
    }
    notify /t/hb/notify-wan.sh
}
CF
}
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
$(b_wan_instance "$1")
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
  N hb ip addr del 203.0.113.254/24 dev hb-wan 2>/dev/null || true
  N hb ip link set wg0 down 2>/dev/null || true
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
for i in $(seq 1 60); do N lan curl -sk -o /dev/null https://192.168.50.2/login && break; sleep 0.5; done
# web login = system users: a real group + user in the container, password in shadow (sha512; applyd checks it)
getent group patronus-admin >/dev/null || groupadd -r patronus-admin
id nladmin >/dev/null 2>&1 || useradd -m -G patronus-admin -s /bin/sh nladmin
PASS="Nl-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')-Pw1"
echo "nladmin:$PASS" | chpasswd -c SHA512
api() {
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  N lan curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.2$2"
}
want() { local w=$1; shift; local code; code=$(api "$@"); [ "$code" = "$w" ] || fail "$1 $2 -> $code (want $w): $(cat /tmp/api.out)"; }
want 200 POST /api/auth/login "{\"username\":\"nladmin\",\"password\":\"$PASS\"}"
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
nft list ruleset | grep -E 'l4proto (112|vrrp|carp) accept comment "HA VRRP"' >/dev/null || { nft list chain inet patronus input; fail "firewall does not accept VRRP"; }
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
has_ha_event() { N lan curl -sk -b /t/jar -o /tmp/ev.out 'https://192.168.50.2/api/events?kind=ha_state' && grep -q MASTER /tmp/ev.out; }
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
wait_for "the flow is in A's conntrack table" 10 sh -c "conntrack -L 2>/dev/null | grep 'dst=203.0.113.9.*dport=9000' >/dev/null"
wait_for "B's external cache has the flow (state sync over UDP 3780)" 20 sh -c "conntrackd -C /t/hb/ct.conf -e 2>/dev/null | grep 'dst=203.0.113.9' >/dev/null"
ok "the flow client -> 203.0.113.9:9000 (through A) appears in B's conntrackd external cache"
echo "=== 9. maintenance mode on A: B takes over and commits the synced flow into its kernel table"
want 200 POST /api/ha/maintenance '{"enabled":true}'
wait_for "B becomes MASTER" 15 b_has_vip
wait_for "A is BACKUP" 15 state_is BACKUP
has "$(cat /etc/keepalived/keepalived.conf)" "priority 1" "maintenance priority missing"
wait_for "B's kernel table has the flow (notify -> conntrackd -c)" 15 sh -c "ip netns exec hb conntrack -L 2>/dev/null | grep 'dst=203.0.113.9.*dport=9000' >/dev/null"
ok "B (new master) committed the replicated connection into its own conntrack table"
want 200 POST /api/ha/maintenance '{"enabled":false}'
wait_for "A preempts again" 15 a_has_vip
wait_for "A is MASTER" 15 state_is MASTER
ok "leaving maintenance mode: A (priority 100 > 50) takes the VIP back"
kill "$FLOW" 2>/dev/null || true

echo "=== 10. alias virtual IPs are plain extra addresses and survive 'patronus apply'"
want 201 POST /api/ha/vips '{"name":"mgmt-alias","interface":"@lan","address":"192.168.50.77/24","mode":"alias"}'
ip -4 -br addr show dev rtr-lan | grep ' 192.168.50.77/24' >/dev/null || fail "alias address not on rtr-lan"
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply: $APPLY"; }
ip -4 -br addr show dev rtr-lan | grep ' 192.168.50.77/24' >/dev/null || fail "patronus apply removed the alias"
ip -4 -br addr show dev rtr-lan | grep ' 192.168.50.254/24' >/dev/null || fail "patronus apply removed the CARP VIP"
ok "alias 192.168.50.77 is on rtr-lan and untouched by an interfaces apply"
api GET /api/ha >/dev/null
ALIAS_ID=$(python3 -c 'import json; print([v["id"] for v in json.load(open("/tmp/api.out"))["vips"] if v["name"]=="mgmt-alias"][0])')
want 200 DELETE "/api/ha/vips/$ALIAS_ID"
ip -4 -br addr show dev rtr-lan | grep ' 192.168.50.77/24' >/dev/null && fail "deleted alias still on rtr-lan"
ok "deleting the alias removes the address"

echo "=== 10b. DHCP failover: A (Patronus + Kea HA hook) and B (plain Kea, hot-standby secondary)"
want 200 PUT /api/dhcp/settings '{"backend":"kea"}'
want 400 PUT /api/ha/settings '{"dhcp_mode":"round-robin"}'
want 400 PUT /api/ha/settings '{"dhcp_port4":80}'
want 200 PUT /api/ha/settings '{"dhcp_failover":true,"dhcp_mode":"hot-standby","dhcp_role":"primary","dhcp_heartbeat_ms":1000,"dhcp_max_response_delay_ms":4000,"dhcp_max_unacked":0}'
want 201 POST /api/dhcp/pools '{"interface":"@lan","range_start":"192.168.50.100","range_end":"192.168.50.150","lease_time":600}'
POOL=$(python3 -c 'import json; print(json.load(open("/tmp/api.out"))["id"])')
KEA=$(cat /etc/kea/kea-dhcp4.conf)
has "$KEA" "libdhcp_ha.so" "kea-dhcp4.conf lacks the HA hook"
has "$KEA" "libdhcp_lease_cmds.so" "kea-dhcp4.conf lacks lease_cmds"
has "$KEA" '"this-server-name": "patronus-primary"' "this server's name"
has "$KEA" '"mode": "hot-standby"' "HA mode"
has "$KEA" 'http://10.9.9.1:8000/' "this node's HA URL (its address on the sync network)"
has "$KEA" 'http://10.9.9.2:8000/' "the peer's HA URL (the sync peer)"
has "$KEA" '"max-unacked-clients": 0' "typed takeover setting"
has "$KEA" '"heartbeat-delay": 1000' "typed heartbeat"
has "$KEA" "rtr-lan/192.168.50.2" "Kea must bind the router's own address, not the VIP"
python3 - <<'PY' || fail "kea-dhcp4.conf: the default gateway is not the LAN VIP"
import json, re
j = json.loads("".join(l for l in open("/etc/kea/kea-dhcp4.conf") if not l.startswith("//")))
opts = {o["name"]: o["data"] for o in j["Dhcp4"]["subnet4"][0]["option-data"]}
assert opts["routers"] == "192.168.50.254", opts
if "domain-name-servers" in opts:
    assert opts["domain-name-servers"] == "192.168.50.254", opts
PY
nft list chain inet patronus input | grep 'iifname "sync-a" ip saddr 10.9.9.2 tcp dport { 8000, 8001 } accept comment "HA DHCP failover"' >/dev/null \
  || { nft list chain inet patronus input; fail "firewall does not open the DHCP failover ports to the peer"; }
ok "kea-dhcp4.conf carries the HA hook, both peers, the typed timers, the VIP as gateway; the peer's failover port is open on the sync link only"
cat > /t/hb/kea4.conf <<CF
{"Dhcp4": {
  "interfaces-config": {"interfaces": ["hb0/192.168.50.3"]},
  "lease-database": {"type": "memfile", "persist": true, "name": "/t/hb/leases4.csv", "lfc-interval": 3600},
  "multi-threading": {"enable-multi-threading": true},
  "hooks-libraries": [
    {"library": "libdhcp_lease_cmds.so"},
    {"library": "libdhcp_ha.so", "parameters": {"high-availability": [{
      "this-server-name": "patronus-secondary", "mode": "hot-standby",
      "heartbeat-delay": 1000, "max-response-delay": 4000, "max-ack-delay": 4000, "max-unacked-clients": 0,
      "send-lease-updates": true, "sync-leases": true, "sync-timeout": 60000,
      "multi-threading": {"enable-multi-threading": true, "http-dedicated-listener": true, "http-listener-threads": 2, "http-client-threads": 2},
      "peers": [
        {"name": "patronus-primary", "url": "http://10.9.9.1:8000/", "role": "primary", "auto-failover": true},
        {"name": "patronus-secondary", "url": "http://10.9.9.2:8000/", "role": "standby", "auto-failover": true}
      ]}]}}
  ],
  "subnet4": [{"id": $POOL, "subnet": "192.168.50.0/24", "interface": "hb0",
    "pools": [{"pool": "192.168.50.100 - 192.168.50.150"}], "valid-lifetime": 600,
    "option-data": [{"name": "routers", "data": "192.168.50.254"}]}],
  "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "/t/hb/kea4.log"}], "severity": "INFO"}]
}}
CF
rm -f /t/hb/leases4.csv
# Kea 3 only writes pid/lock/log/lease files below its own directories unless told otherwise
KEA_B_ENV="KEA_PIDFILE_DIR=/t/hb KEA_LOCKFILE_DIR=/t/hb KEA_LOG_FILE_DIR=/t/hb KEA_DHCP_DATA_DIR=/t/hb"
# A's kea runs as user dhcp (not dumpable): /proc/PID/ns is unreadable in the container, so A's Kea is
# every kea-dhcp4 except B's (started below; exec keeps the PID the shell reported)
a_kea_pids() { pgrep -x kea-dhcp4 | grep -vx "${B_KEA:-0}" || true; }
a_kea_running() { [ -n "$(a_kea_pids)" ]; }
a_kea_stopped() { [ -z "$(a_kea_pids)" ]; }
ip netns exec hb env $KEA_B_ENV kea-dhcp4 -t /t/hb/kea4.conf >/t/hb/kea4.check 2>&1 || { cat /t/hb/kea4.check; fail "B's Kea config does not validate"; }
ip netns exec hb env $KEA_B_ENV kea-dhcp4 -c /t/hb/kea4.conf >/t/hb/kea4.out 2>&1 &
B_KEA=$!
wait_for "A's kea-dhcp4 is running (via $INIT)" 30 a_kea_running
kea_state_a() { api GET /api/ha >/dev/null; python3 -c 'import json; d=json.load(open("/tmp/api.out"))["status"]["dhcp"]; print(d.get("dhcp4",{}).get("state"))'; }
kea_state_b() { python3 /t/kea_state.py http://10.9.9.2:8000/ dhcp4; }
state_a_is() { [ "$(kea_state_a 2>/dev/null)" = "$1" ]; }
state_b_is() { [ "$(kea_state_b 2>/dev/null)" = "$1" ]; }
wait_for "A's Kea reaches hot-standby with B (the HA page reports it)" 60 state_a_is hot-standby
wait_for "B's Kea reaches hot-standby with A" 30 state_b_is hot-standby
ok "both Kea servers are in hot-standby with each other (A as primary: the HA page shows its state)"

echo "--- a client gets a lease from A (primary)"
OUT1=$(N cl python3 /t/dhc.py lease 02:00:00:00:00:01 20) || fail "client 1 got no lease: $OUT1"
IP1=${OUT1#ip=}; IP1=${IP1%% *}
has "$OUT1" "server=192.168.50.2" "client 1 was not served by A"
has "$OUT1" "router=192.168.50.254" "default gateway is not the LAN VIP"
has "$OUT1" "lease=600" "lease time"
wait_for "B has client 1's lease (lease update from A)" 20 sh -c "grep -q '^$IP1,' /t/hb/leases4.csv"
ok "client 1 leased $IP1 from A (server id = A's own address, gateway = the VIP), B received the lease"

echo "--- A fails: the VIP moves to B, A's Kea stops; client 1 rebinds the SAME address from B"
want 200 POST /api/ha/maintenance '{"enabled":true}'
wait_for "B holds the VIP" 15 b_has_vip
case "$INIT" in
  systemd) systemctl stop kea-dhcp4 ;;
  *) rc-service kea-dhcp4 stop >/dev/null 2>&1 || true ;;
esac
wait_for "A's Kea is stopped" 15 a_kea_stopped
T0=$(date +%s)
wait_for "B's Kea takes over (partner-down)" 30 state_b_is partner-down
OUT2=$(N cl python3 /t/dhc.py rebind 02:00:00:00:00:01 "$IP1" 20) || fail "client 1 could not rebind from B: $OUT2"
has "$OUT2" "ip=$IP1 " "the rebind returned another address"
has "$OUT2" "server=192.168.50.3" "the rebind was not answered by B"
T1=$(date +%s)
[ $((T1 - T0)) -lt 60 ] || fail "failover took $((T1 - T0)) s"
ok "A stopped: B declared the partner down and renewed $IP1 to client 1 within $((T1 - T0)) s (lease time 600 s)"
echo "--- a new client gets a lease from B and reaches its gateway (the VIP, now on B)"
OUT3=$(N cl python3 /t/dhc.py lease 02:00:00:00:00:02 20) || fail "client 2 got no lease from B: $OUT3"
IP2=${OUT3#ip=}; IP2=${IP2%% *}
has "$OUT3" "server=192.168.50.3" "client 2 was not served by B"
[ "$IP2" != "$IP1" ] || fail "client 2 got client 1's address"
N cl ip addr add "$IP2/24" dev cl0
N cl ping -c1 -W3 192.168.50.254 >/dev/null || fail "client 2 cannot reach its gateway (the VIP) through B"
N cl ip addr del "$IP2/24" dev cl0
ok "client 2 leased $IP2 from B, its default gateway 192.168.50.254 answers (held by B)"

echo "--- A returns: the VIP comes back, A's Kea restarts, syncs B's leases, and the two databases agree"
want 200 POST /api/ha/maintenance '{"enabled":false}'
wait_for "A holds the VIP again" 20 a_has_vip
wait_for "A's Kea is running again" 30 a_kea_running
wait_for "A's Kea back in hot-standby" 60 state_a_is hot-standby
leases_agree() {
  python3 /t/leases.py /var/lib/kea/kea-leases4.csv > /t/hb/la.txt 2>/dev/null &&
  python3 /t/leases.py /t/hb/leases4.csv > /t/hb/lb.txt 2>/dev/null &&
  cmp -s /t/hb/la.txt /t/hb/lb.txt && grep -q "^$IP1 " /t/hb/la.txt && grep -q "^$IP2 " /t/hb/la.txt
}
wait_for "A's and B's lease databases agree (both clients on both)" 40 leases_agree
OUT4=$(N cl python3 /t/dhc.py lease 02:00:00:00:00:03 20) || fail "client 3 got no lease: $OUT4"
has "$OUT4" "server=192.168.50.2" "A (primary) did not serve again after it returned"
wait_for "the databases still agree" 20 sh -c "python3 /t/leases.py /var/lib/kea/kea-leases4.csv > /t/hb/la.txt && python3 /t/leases.py /t/hb/leases4.csv > /t/hb/lb.txt && cmp -s /t/hb/la.txt /t/hb/lb.txt"
ok "A is primary again, both lease databases list the same $(wc -l < /t/hb/la.txt) leases, client 3 was served by A"

echo "=== 10c. services follow the VIP: a WireGuard tunnel dialled at the WAN VIP moves with it"
want 201 POST /api/ha/vips '{"name":"wan-vip","interface":"@wan","address":"203.0.113.254/24","vrid":52}'
has "$(cat /etc/keepalived/keepalived.conf)" "203.0.113.254/24 dev rtr-wan" "WAN VIP missing from keepalived.conf"
WANBLK=$(sed -n '/vrrp_instance PAT_rtr_wan_52/,/^}/p' /etc/keepalived/keepalived.conf)
if grep -q unicast_peer <<<"$WANBLK"; then fail "the WAN VIP instance uses the LAN peer as unicast VRRP peer: $WANBLK"; fi
b_stop; B_WAN=1; b_start 50
wait_for "A holds both VIPs next to B (priority 50)" 20 sh -c "ip -4 -br addr show dev rtr-wan | grep ' 203.0.113.254/24'"
want 201 POST /api/vpn/wireguard/tunnels '{"addresses":"10.99.0.1/24","endpoint":"203.0.113.254","client_allowed_ips":"10.99.0.0/24"}'
SERVER_PUB=$(python3 -c 'import json; print(json.load(open("/tmp/api.out"))["public_key"])')
want 201 POST /api/vpn/wireguard/peers '{"name":"road","interface":"wg0","persistent_keepalive":2}'
PEER_ID=$(python3 -c 'import json; print(json.load(open("/tmp/api.out"))["id"])')
wait_for "wg0 is up on A (MASTER)" 20 sh -c "ip -br link show wg0 | grep -E 'UP|UNKNOWN'"
want 200 GET "/api/vpn/wireguard/config/$PEER_ID"
cp /tmp/api.out /t/road.conf
has "$(cat /t/road.conf)" "Endpoint = 203.0.113.254:51820" "client config does not dial the WAN VIP"
grep -vE '^(Address|DNS) =' /t/road.conf > /t/road.setconf
N inet ip link add wgc type wireguard
N inet wg setconf wgc /t/road.setconf
N inet ip addr add 10.99.0.2/32 dev wgc; N inet ip link set wgc up; N inet ip route add 10.99.0.0/24 dev wgc
N inet ping -c2 -W3 10.99.0.1 >/dev/null || { wg show; fail "the client cannot ping the tunnel address through A"; }
has "$(wg show wg0 latest-handshakes)" "$(N inet wg show wgc public-key 2>/dev/null | head -c0)" "x" 2>/dev/null || true
hs_of() { # NETNS(or -) DEV: newest handshake epoch of its (only) peer
  if [ "$1" = - ]; then wg show "$2" latest-handshakes; else N "$1" wg show "$2" latest-handshakes; fi | awk '{print $2}' | sort -n | tail -1
}
[ "$(hs_of - wg0)" -gt 0 ] || fail "A has no handshake with the client"
ok "the client dials the WAN VIP 203.0.113.254, A (MASTER) answers: handshake + ping through the tunnel"
# B: the same server identity (this is what config sync carries in production) and the same peer, held down
SK=$(python3 -c 'import sqlite3; print(sqlite3.connect("/var/lib/patronus/config.db").execute("select private_key from wg_interfaces where name=\"wg0\"").fetchone()[0])')
CLIENT_PUB=$(N inet wg show wgc public-key)
echo "$SK" > /t/hb/wg.key; chmod 600 /t/hb/wg.key
N hb ip link add wg0 type wireguard
N hb wg set wg0 private-key /t/hb/wg.key listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.99.0.2/32
N hb ip addr add 10.99.0.1/24 dev wg0
N hb ip link set wg0 down
rm -f /t/hb/wg.key
api GET /api/ha >/dev/null
python3 - <<'PY' || fail "the HA status does not list WireGuard as running here"
import json
d = json.load(open("/tmp/api.out"))["status"]["follow"]
w = [x for x in d if x["service"] == "wireguard"][0]
assert w["running_here"] is True and w["held"] is None, w
PY
echo "--- A loses the VIPs (maintenance): A holds wg0 down, B brings its wg0 up, the client's tunnel re-establishes through the VIP"
HS_A=$(hs_of - wg0)
want 200 POST /api/ha/maintenance '{"enabled":true}'
wait_for "B holds the WAN VIP" 20 sh -c "ip netns exec hb ip -4 -br addr show dev hb-wan | grep ' 203.0.113.254/24'"
wait_for "A reports BACKUP" 20 state_is BACKUP
wait_for "A holds wg0 down (follows the VIP)" 30 sh -c "ip -br link show wg0 | grep -E ' DOWN '"
wait_for "B's wg0 is up" 20 sh -c "ip netns exec hb ip -br link show wg0 | grep -E 'UP|UNKNOWN'"
api GET /api/ha >/dev/null
python3 - <<'PY' || fail "the HA status does not say why WireGuard is held"
import json
d = json.load(open("/tmp/api.out"))["status"]["follow"]
w = [x for x in d if x["service"] == "wireguard"][0]
assert w["running_here"] is False and "MASTER" in w["held"], w
PY
want 200 GET /ha
has "$(cat /tmp/api.out)" 'id="ha-follow-card"' "HA page lacks the follow-the-VIP card"
has "$(cat /tmp/api.out)" 'id="ha-dhcp-card"' "HA page lacks the DHCP failover card"
tunnel_on_b() { N inet ping -c1 -W2 10.99.0.1 >/dev/null 2>&1 && [ "$(hs_of hb wg0)" -gt 0 ]; }
wait_for "the client's tunnel is back, answered by B (handshake with the VIP)" 90 tunnel_on_b
has "$(N inet wg show wgc endpoints)" "203.0.113.254:51820" "the client roamed away from the virtual IP"
has "$(nft list chain inet patronus postrouting)" "ip saddr set 203.0.113.254" "WireGuard is not pinned to the WAN VIP"
ok "A went BACKUP: its wg0 is down (with the reason on the HA page), B took the VIP and the client's tunnel re-established on B within the keepalive window"
echo "--- A returns: wg0 comes back on A, B's goes down, the tunnel moves back"
want 200 POST /api/ha/maintenance '{"enabled":false}'
wait_for "A holds the WAN VIP" 20 sh -c "ip -4 -br addr show dev rtr-wan | grep ' 203.0.113.254/24'"
wait_for "A is MASTER" 20 state_is MASTER
wait_for "A's wg0 is up again" 30 sh -c "ip -br link show wg0 | grep -E 'UP|UNKNOWN'"
wait_for "B's wg0 is down" 20 sh -c "ip netns exec hb ip -br link show wg0 | grep -E ' DOWN '"
tunnel_on_a() { N inet ping -c1 -W2 10.99.0.1 >/dev/null 2>&1 && [ "$(hs_of - wg0)" -gt "$HS_A" ]; }
wait_for "the tunnel is back on A (a newer handshake than before the failover)" 90 tunnel_on_a
has "$(N inet wg show wgc endpoints)" "203.0.113.254:51820" "the client roamed away from the virtual IP"
ok "A is MASTER again: wg0 up on A, down on B, the client's tunnel ping works through A with a fresh handshake"
N inet ip link del wgc 2>/dev/null || true
want 200 DELETE "/api/vpn/wireguard/tunnels/wg0"
api GET /api/ha >/dev/null
VID=$(python3 -c 'import json; print([v["id"] for v in json.load(open("/tmp/api.out"))["vips"] if v["name"]=="wan-vip"][0])')
want 200 DELETE "/api/ha/vips/$VID"
b_stop; B_WAN=0; b_start 50
sleep 3

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
if nft list ruleset | grep 'HA VRRP' >/dev/null; then fail "VRRP is still open with HA off"; fi
if grep -q libdhcp_ha /etc/kea/kea-dhcp4.conf; then fail "Kea still loads the HA hook with HA off"; fi
if nft list ruleset | grep 'HA DHCP failover' >/dev/null; then fail "the DHCP failover port is still open with HA off"; fi
ok "HA off: keepalived + conntrackd stopped, VIP removed, configs idle, VRRP/sync/DHCP-failover ports closed again, Kea runs alone without the HA hook"

kill "$HOLD" "$B_KEA" 2>/dev/null || true
b_stop; conntrackd -C /t/hb/ct.conf -k 2>/dev/null || true
echo "ALL HA NETLAB CHECKS PASSED"
