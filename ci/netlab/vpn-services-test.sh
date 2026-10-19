#!/usr/bin/env bash
# Lane F (IPsec + WireGuard) and lane H (service control) netlab in a real
# Gentoo stage3 (run by `NETLAB_TEST=vpn-services-test.sh
# ci/netlab/lan-services.sh openrc|systemd`), with the shipped binaries and
# init files: patronus-web runs as the unprivileged `patronus` user and every
# privileged step goes through `patronus applyd` (root) -- the shipped setup.
#
#   lan (192.168.50.10) --- rtr-lan [ router = container netns ] rtr-wan --- siteb 203.0.113.9
#                           192.168.50.1               203.0.113.2          10.2.0.1/24 behind it
#                                                                           (own charon, own /run)
#
# Proves: an IKEv2 PSK tunnel configured through the API comes up
# (ESTABLISHED in swanctl, in the API and on the VPN page, read as root via
# applyd), LAN <-> remote-LAN traffic flows both ways through ESP with the
# LAN source address kept (NAT exemption), the distro strongSwan service is
# started through OpenRC/systemd; a reboot (charon stopped, config deleted,
# xfrm flushed, `patronus apply`) brings it back; service stop/start from
# the web API works through applyd; a WireGuard tunnel created by the
# unprivileged web UI exists in the kernel.
#
# INIT=fake: a Debian container without an init system (local debugging):
# a stand-in `rc-service` runs charon-systemd for the `ipsec` service.
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
  # no init system: an OpenRC look-alike for the strongSwan service only
  mkdir -p /run/openrc /etc/init.d
  printf '#!/bin/sh\n' > /etc/init.d/ipsec; chmod +x /etc/init.d/ipsec
  CHARON_BIN=$(command -v charon-systemd || echo /usr/lib/ipsec/charon)
  cat > /usr/local/sbin/rc-service <<EOF
#!/bin/sh
[ "\$1" = ipsec ] || exit 1
P=/tmp/charon-rtr.pid
up() { [ -f \$P ] && kill -0 "\$(cat \$P)" 2>/dev/null; }
start() { up || { setsid $CHARON_BIN >/tmp/charon-rtr.log 2>&1 & echo \$! > \$P; sleep 1; }; }
stop() { up && kill "\$(cat \$P)"; rm -f \$P; sleep 0.5; }
case "\$2" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) up && echo " * status: started" ;;
esac
EOF
  chmod +x /usr/local/sbin/rc-service
  printf '#!/bin/sh\nexit 0\n' > /usr/local/sbin/rc-update; chmod +x /usr/local/sbin/rc-update
  ;;
esac
SVC=ipsec
[ "$INIT" = systemd ] && SVC=strongswan
# the router's charon answers on its VICI socket (Gentoo's OpenRC `ipsec`
# status prints `ipsec statusall`, not started/stopped)
charon_up() { swanctl --stats >/dev/null 2>&1; }

echo "=== 1. topology"
ip netns add lan; ip netns add siteb
ip link add rtr-lan type veth peer name lan0 netns lan
ip link add rtr-wan type veth peer name sb0 netns siteb
ip addr add 192.168.50.1/24 dev rtr-lan; ip link set rtr-lan up
ip addr add 203.0.113.2/24 dev rtr-wan; ip link set rtr-wan up
ip route add 10.2.0.0/24 via 203.0.113.9 dev rtr-wan
N lan ip link set lo up; N lan ip addr add 192.168.50.10/24 dev lan0; N lan ip link set lan0 up
N lan ip route add default via 192.168.50.1
N siteb ip link set lo up; N siteb ip addr add 203.0.113.9/24 dev sb0; N siteb ip link set sb0 up
N siteb ip link add sb-lan type dummy; N siteb ip addr add 10.2.0.1/24 dev sb-lan; N siteb ip link set sb-lan up
N siteb ip route add default via 203.0.113.2
# echo servers: they answer with the address they saw
cat > /t/echo.py <<'EOF'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
while True:
    c, a = s.accept(); c.sendall((a[0] + "\n").encode()); c.close()
EOF
cat > /t/conn.py <<'EOF'
import socket, sys
s = socket.socket(); s.settimeout(3)
if len(sys.argv) > 3:
    s.bind((sys.argv[3], 0))
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); print(s.recv(100).decode().strip())
except OSError as e:
    print("unreachable:", e); sys.exit(1)
EOF
N siteb python3 /t/echo.py 10.2.0.1 9000 & ECHO1=$!
N lan python3 /t/echo.py 192.168.50.10 9000 & ECHO2=$!
ok "lan 192.168.50.10 -- router -- siteb 203.0.113.9 (10.2.0.0/24 behind it)"

echo "=== 2. the other site: its own charon in its own netns + /run"
mkdir -p /t/siteb/swanctl/conf.d
cat > /t/siteb/swanctl/swanctl.conf <<'EOF'
connections {
    to-hq {
        version = 2
        local_addrs = 203.0.113.9
        remote_addrs = 203.0.113.2
        proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048
        local {
            auth = psk
            id = 203.0.113.9
        }
        remote {
            auth = psk
            id = 203.0.113.2
        }
        children {
            hq-lan {
                local_ts = 10.2.0.0/24
                remote_ts = 192.168.50.0/24
                esp_proposals = aes256gcm16-ecp384,aes256-sha256-modp2048
                start_action = none
            }
        }
    }
}
secrets {
    ike-hq {
        id-1 = 203.0.113.9
        id-2 = 203.0.113.2
        secret = "netlab-site-b-shared-secret-0123"
    }
}
EOF
CHARON=
for c in /usr/libexec/ipsec/charon /usr/lib/ipsec/charon /usr/sbin/charon-systemd; do
  [ -x "$c" ] && { CHARON=$c; break; }
done
[ -n "$CHARON" ] || fail "no charon binary"
# its own strongswan.conf: log to stderr (the log below), stay root
cat > /t/siteb/strongswan.conf <<'EOF'
charon {
    user = root
    group = root
    filelog {
        stderr {
            default = 1
            ike = 2
        }
    }
    plugins {
        include strongswan.d/charon/*.conf
    }
}
include strongswan.d/*.conf
EOF
cat > /t/siteb-charon.sh <<EOF
#!/bin/sh
# inside siteb's netns, in a private mount namespace: own /run, own config
mount -t tmpfs tmpfs /run || exit 10
chmod 1777 /run
mount --bind /t/siteb/swanctl /etc/swanctl || exit 11
mount --bind /t/siteb/strongswan.conf /etc/strongswan.conf || exit 12
exec $CHARON
EOF
chmod +x /t/siteb-charon.sh
ip netns exec siteb unshare -m --propagation private /t/siteb-charon.sh >/t/charon-siteb.log 2>&1 &
SITEB_CHARON=$!
SBNS=$(ip netns exec siteb readlink /proc/self/ns/net)
SBPID=
for i in $(seq 1 20); do
  for p in $(pgrep -f "^$CHARON" || true); do
    [ "$(readlink "/proc/$p/ns/net" 2>/dev/null)" = "$SBNS" ] && SBPID=$p
  done
  [ -n "$SBPID" ] && break; sleep 0.25
done
if [ -z "$SBPID" ]; then
  echo "--- charon-siteb.log"; cat /t/charon-siteb.log
  echo "--- processes"; ps -eo pid,user,args | grep -E '[c]haron|[u]nshare' || true
  if kill -0 "$SITEB_CHARON" 2>/dev/null; then echo "launcher $SITEB_CHARON still running"
  else rc=0; wait "$SITEB_CHARON" || rc=$?; echo "launcher exited with $rc"; fi
  fail "siteb charon did not start"
fi
SB() { nsenter -t "$SBPID" -m -n "$@"; }
LOADED=
for i in $(seq 1 20); do LOADED=$(SB swanctl --load-all --noprompt 2>&1) && break; sleep 0.5; done
has "$LOADED" "loaded connection 'to-hq'" "siteb config not loaded"
ok "siteb charon (pid $SBPID) responds for 10.2.0.0/24"

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
for i in $(seq 1 60); do N lan curl -sk -o /dev/null https://192.168.50.1:8443/login && break; sleep 0.5; done
WEBUSER=$(ps -o user=,stat= -C patronus-web | awk '$2 !~ /Z/ {print $1; exit}')
[ "$WEBUSER" = patronus ] || fail "patronus-web runs as $WEBUSER, expected patronus"
[ -S /run/patronus/applyd.sock ] || fail "no applyd socket"
PASS=$(tr -d '\n' < /var/lib/patronus/initial-admin-password)
api() {
  local data=()
  [ $# -ge 3 ] && data=(-d "$3")
  N lan curl -sk -b /t/jar -c /t/jar -o /tmp/api.out -w '%{http_code}' -X "$1" \
     -H 'content-type: application/json' "${data[@]}" "https://192.168.50.1:8443$2"
}
want() { local w=$1; shift; local code; code=$(api "$@"); [ "$code" = "$w" ] || fail "$1 $2 -> $code (want $w): $(cat /tmp/api.out)"; }
want 200 POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PASS\"}"
ok "web UI up as user patronus, applyd as root"

echo "=== 4. IPsec tunnel through the API"
want 400 POST /api/vpn/ipsec/connections '{"name":"bad name","remote_address":"203.0.113.9","local_ts":"192.168.50.0/24","remote_ts":"10.2.0.0/24"}'
want 201 POST /api/vpn/ipsec/connections '{"name":"site-b","local_address":"203.0.113.2","remote_address":"203.0.113.9","psk":"netlab-site-b-shared-secret-0123","local_ts":"192.168.50.0/24","remote_ts":"10.2.0.0/24","start_action":"start"}'
has "$(cat /etc/swanctl/conf.d/patronus.conf)" patronus-site-b "no swanctl conf"
[ "$(stat -c %a /etc/swanctl/conf.d/patronus.conf)" = 600 ] || fail "swanctl conf mode $(stat -c %a /etc/swanctl/conf.d/patronus.conf)"
charon_up || fail "strongSwan service $SVC not started through $INIT"
established() {
  local sas=
  for i in $(seq 1 40); do
    sas=$(swanctl --list-sas 2>/dev/null || true)
    if grep -qE 'patronus-site-b: #[0-9]+, ESTABLISHED' <<<"$sas" && grep -q 'INSTALLED, TUNNEL' <<<"$sas"; then
      return 0
    fi
    sleep 0.5
  done
  echo "$sas"; swanctl --list-conns 2>&1 | head -30 || true
  return 1
}
established || fail "tunnel did not come up"
ok "$SVC started via $INIT, patronus-site-b ESTABLISHED with an installed CHILD_SA"
OUT=$(N lan python3 /t/conn.py 10.2.0.1 9000) || fail "LAN -> remote LAN through the tunnel: $OUT"
[ "$OUT" = 192.168.50.10 ] || fail "remote host saw $OUT, want 192.168.50.10 (NAT exemption)"
ok "LAN -> 10.2.0.1 through ESP; the remote side sees 192.168.50.10 (not NATed)"
OUT=$(N siteb python3 /t/conn.py 192.168.50.10 9000 10.2.0.1) || fail "remote LAN -> LAN through the tunnel: $OUT"
[ "$OUT" = 10.2.0.1 ] || fail "LAN host saw $OUT"
ok "remote LAN -> LAN host through the tunnel (meta ipsec rule), source 10.2.0.1"
has "$(ip -s xfrm state)" "proto esp" "no ESP SAs in the kernel"
has "$(nft list ruleset)" 'meta ipsec exists ip saddr 10.2.0.0/24 ip daddr 192.168.50.0/24 accept' "no IPsec forward rule"
want 200 GET /api/vpn/ipsec/tunnels
has "$(cat /tmp/api.out)" '"name":"patronus-site-b","status":"ESTABLISHED"' "API does not show the SA (read via applyd)"
want 200 GET /vpn
PAGE=$(cat /tmp/api.out)
has "$PAGE" 'data-ipsec="site-b"' "VPN page lacks the tunnel"
has "$PAGE" '<span class="ok">ESTABLISHED' "VPN page does not show it established"
if grep -q 'netlab-site-b-shared-secret' <<<"$PAGE"; then fail "the VPN page shows the PSK"; fi
ok "API + VPN page show site-b ESTABLISHED (as root via applyd); PSK never shown"

echo "=== 5. reboot: charon stopped, config deleted, xfrm flushed, 'patronus apply'"
case "$INIT" in systemd) systemctl stop "$SVC" ;; *) rc-service "$SVC" stop >/dev/null 2>&1 || true ;; esac
for i in $(seq 1 20); do charon_up || break; sleep 0.5; done
rm -f /etc/swanctl/conf.d/patronus.conf
ip xfrm state flush; ip xfrm policy flush
APPLY=$(patronus apply 2>&1) || { echo "$APPLY"; fail "patronus apply after reboot"; }
has "$(cat /etc/swanctl/conf.d/patronus.conf)" patronus-site-b "config not rewritten"
established || fail "tunnel not back after reboot"
OUT=$(N lan python3 /t/conn.py 10.2.0.1 9000) || fail "after reboot: $OUT"
ok "after reboot: config rewritten, $SVC started, tunnel ESTABLISHED, traffic flows"

echo "=== 6. service control from the web UI (through applyd, as root)"
want 200 GET /api/system/services
has "$(cat /tmp/api.out)" "\"name\":\"$SVC\"" "services list lacks $SVC"
svc_status() { python3 -c 'import json,sys; print(next(s["status"] for s in json.load(open("/tmp/api.out")) if s["name"]==sys.argv[1]))' "$SVC"; }
# Gentoo's OpenRC `ipsec` script answers `status` with `ipsec statusall`
# output (no started/stopped word): it used to be listed as "Unknown".
if [ "$INIT" != fake ]; then
  [ "$(svc_status)" = Running ] || fail "System page lists running $SVC as '$(svc_status)'"
  ok "System page lists $SVC as Running"
fi
want 200 POST "/api/system/services/$SVC/stop"
for i in $(seq 1 20); do charon_up || break; sleep 0.5; done
if charon_up; then fail "$SVC still running after stop from the web UI"; fi
want 200 GET /api/system/services
if [ "$INIT" != fake ]; then
  [ "$(svc_status)" = Stopped ] || fail "System page lists stopped $SVC as '$(svc_status)'"
fi
ok "web UI stopped $SVC (patronus-web is unprivileged: applyd did it)"
want 200 POST "/api/system/services/$SVC/start"
for i in $(seq 1 20); do charon_up && break; sleep 0.5; done
charon_up || fail "$SVC not running after start from the web UI"
want 200 POST /api/vpn/ipsec/apply
established || fail "tunnel not back after start + re-apply"
ok "web UI started $SVC again; re-apply re-established the tunnel"
if [ "$INIT" != fake ]; then
  want 400 POST /api/system/services/patronus-web/stop
  ok "patronus-web cannot be stopped from its own UI"
fi
want 404 POST /api/system/services/not-a-service/restart

echo "=== 7. WireGuard from the unprivileged web UI"
want 201 POST /api/vpn/wireguard/tunnels '{"addresses":"10.99.0.1/24","endpoint":"203.0.113.2"}'
has "$(ip -d link show wg0 2>&1)" wireguard "wg0 not created through applyd"
[ "$(wg show wg0 listen-port)" = 51820 ] || fail "wg0 port"
want 201 POST /api/vpn/wireguard/peers '{"name":"phone"}'
has "$(wg show wg0 allowed-ips)" 10.99.0.2/32 "peer not in the kernel"
ok "wg0 + peer created by the unprivileged web UI through applyd"

echo "=== 8. deleting the last IPsec tunnel unloads it and stops charon"
want 200 GET /api/vpn
SID=$(python3 -c 'import json; print(json.load(open("/tmp/api.out"))["ipsec"][0]["id"])')
want 200 DELETE "/api/vpn/ipsec/connections/$SID"
sas() { swanctl --list-sas 2>/dev/null || true; }
for i in $(seq 1 20); do grep -q patronus-site-b <<<"$(sas)" || break; sleep 0.5; done
if grep -q patronus-site-b <<<"$(sas)"; then fail "SA still up after delete"; fi
for i in $(seq 1 20); do charon_up || break; sleep 0.5; done
if charon_up; then fail "$SVC still running with no tunnel left"; fi
ok "last tunnel deleted: SA gone, $SVC stopped"

kill "$ECHO1" "$ECHO2" "$SITEB_CHARON" 2>/dev/null || true
echo "=== lane F/H netlab ($INIT): all checks passed"
