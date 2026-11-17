#!/bin/bash
# qemu-gate.sh <openrc|systemd> <image-dir>: boot a GL-AX1800 Patronus root on QEMU aarch64 (virt, Cortex-A53, 512 MB,
# TCG or KVM) with OpenWrt's armsr/armv8 kernel of the same release, and test the userland over ssh + HTTPS.
# The IPQ6018 itself cannot be emulated: this proves the root (init system, services, ETPhoneHome, web UI, settings
# persistence, the flash guards on a real busybox/loop-mount userland), not the board drivers. The early boot skips the
# board's kmods and Wi-Fi calibration off-board (marker not-on-board).
# Inside the builder image. Env: VIRT_KERNEL (armsr kernel), UNIT_DIR (ci-unit.sh output: ci_ed25519), RESULTS (dir),
#   BOOT_TIMEOUT (s, default 1200). Two boots with the same settings disk; between them a staged upgrade is planted that
#   the early boot must reject (not this board) without stopping the boot.
# Prints PASS/FAIL per check, ends with "FAILED: none" when all passed. Exit 0 = all passed.
set -uo pipefail
INIT=${1:?usage: qemu-gate.sh <openrc|systemd> <image-dir>}; I=$(readlink -f "${2:?image dir}")
K=${VIRT_KERNEL:?VIRT_KERNEL}; KEY=${UNIT_DIR:?UNIT_DIR}/ci_ed25519
RES=${RESULTS:-/out/qemu-$INIT}; mkdir -p "$RES"; : > "$RES/results.txt"
TMO=${BOOT_TIMEOUT:-1200}
SQ=$(ls "$I"/root.squashfs); TAR=$(ls "$I"/patronus-*-sysupgrade.tar)
QP=; SLP=; W=$(mktemp -d "${TMPDIR:-/tmp}/ax-qemu.XXXX"); trap 'kill $QP $SLP 2>/dev/null; rm -rf "$W"' EXIT
# test copy of the root: the board's kmods replaced by the same pinned netfilter packages built for the virt kernel
# (kmods.pin "virt"), so the firewall applies for real; everything else is the shipped image byte for byte
unsquashfs -q -d "$W/r" "$SQ" >/dev/null || { echo "unsquashfs failed"; exit 1; }
KV=$(ls "$W/r/lib/modules"); rm -rf "$W/r/lib/modules/$KV" "$W/r/etc/modules.d"; mkdir -p "$W/r/etc/modules.d"
sh "$(dirname "$0")/fetch-kmods.sh" virt "$W/r" "${KMOD_CACHE:-/cache/kmods}" || exit 1
depmod -b "$W/r" "$KV"; : > "$W/r/etc/patronus/qemu-kmods"
mksquashfs "$W/r" "$W/root.img" -comp xz -b 256K -noappend -no-xattrs -all-root -quiet >/dev/null; rm -rf "$W/r"
truncate -s 256M "$W/data.img"; mkfs.ext4 -q -F -L patronus_data "$W/data.img"
SSHP=2222; WEBP=8443; NTPP=11123; QP=
fails=()
pass() { echo "PASS: $*" | tee -a "$RES/results.txt"; }
fail() { echo "FAIL: $*" | tee -a "$RES/results.txt"; fails+=("$1"); }
check() { n=$1; shift; if out=$("$@" 2>&1); then pass "$n"; else fail "$n"; echo "$out" | tail -15 | sed 's/^/    /' | tee -a "$RES/results.txt"; fi; }
SSHO=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15)
R() { ssh "${SSHO[@]}" -p $SSHP root@127.0.0.1 "$@"; }
ACCEL=tcg; [ -w /dev/kvm ] && [ "$(uname -m)" = aarch64 ] && ACCEL=kvm
boot() { # n
  n=$1; t0=$(date +%s)
  qemu-system-aarch64 -M virt -accel $ACCEL -cpu $([ $ACCEL = kvm ] && echo host || echo cortex-a53) -smp 2 -m 512 \
    -kernel "$K" -append "root=/dev/vda rootfstype=squashfs ro console=ttyAMA0 patronus.data=/dev/vdb panic=-1" \
    -drive file="$W/root.img",if=virtio,format=raw,readonly=on -drive file="$W/data.img",if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSHP-:22,hostfwd=tcp:127.0.0.1:$WEBP-:443,hostfwd=udp:127.0.0.1:$NTPP-:123 -device virtio-net-pci,netdev=n0 \
    -display none -monitor none -serial file:"$RES/serial-boot$n.txt" -no-reboot &
  QP=$!
  until R true 2>/dev/null; do
    kill -0 $QP 2>/dev/null || { fail "boot $n: QEMU exited"; return 1; }
    [ $(( $(date +%s) - t0 )) -gt "$TMO" ] && { fail "boot $n: no ssh after ${TMO}s"; tail -30 "$RES/serial-boot$n.txt"; return 1; }
    sleep 10
  done
  # services settle: the web UI answers
  until [ "$(curl -sk -o /dev/null -w '%{http_code}' -m 20 https://127.0.0.1:$WEBP/ 2>/dev/null)" != 000 ]; do
    [ $(( $(date +%s) - t0 )) -gt "$TMO" ] && break; sleep 10; done
  pass "boot $n: ssh + web reachable after $(( $(date +%s) - t0 ))s ($ACCEL)"
}
poweroff_vm() { R sync 2>/dev/null; sleep 2; kill $QP 2>/dev/null; wait $QP 2>/dev/null; QP=; }

SERVICES_OPENRC="patronus-syslogd patronus-klogd patronus-board patronus-etph dropbear chronyd patronus-apply patronus-applyd patronus-web"
SERVICES_SYSTEMD="patronus-syslogd patronus-klogd patronus-network patronus-etph patronus-dropbear chronyd patronus-apply patronus-applyd patronus-web"
services_up() {
  if [ "$INIT" = openrc ]; then
    for s in $SERVICES_OPENRC; do st=$(R "rc-service $s status" 2>&1); case "$st" in *started*) ;; *) echo "$s: $st"; return 1;; esac; done
  else
    for s in $SERVICES_SYSTEMD; do st=$(R "systemctl is-active $s.service" 2>&1); [ "$st" = active ] || { echo "$s: $st"; return 1; }; done
    f=$(R "systemctl --failed --no-legend --plain" 2>&1); [ -z "$f" ] || { echo "failed units: $f"; return 1; }
  fi
}
pid1() { p=$(R 'readlink /proc/1/exe'); case "$INIT:$p" in openrc:/sbin/openrc-init|systemd:/usr/lib/systemd/systemd) echo "$p";; *) echo "PID 1 is $p"; return 1;; esac; }
etph() { R 'test -x /usr/sbin/etphonehome && pgrep -f "^/usr/sbin/etphonehome --router" >/dev/null && grep -q "^ETPH=" /etc/patronus-release'; }
web() { c=$(curl -sk -o "$W/web.html" -w '%{http_code}' -m 30 https://127.0.0.1:$WEBP/); case "$c" in 200|30[0-9]) ;; *) echo "HTTP $c"; return 1;; esac
        c=$(curl -sk -o "$W/fr.html" -w '%{http_code}' -m 30 https://127.0.0.1:$WEBP/first-run); [ "$c" = 200 ] && grep -qi patronus "$W/fr.html" || { echo "first-run HTTP $c"; return 1; }; }
syslog() { R 'test -s /var/log/messages && tail -3 /var/log/messages'; }
offboard() { R 'grep -q not-on-board /tmp/boot-times && ! grep -q caldata /tmp/boot-times && ! test -s /tmp/insmod.log && lsmod | grep "^nf_tables " >/dev/null'; }
firewall() { t=$(R 'nft list tables') && [ -n "$t" ] && echo "$t"; }
release() { R "grep -qx BOARD=glinet,gl-ax1800 /etc/patronus-release && grep -qx INIT=$INIT /etc/patronus-release && cat /etc/patronus-release"; }
no_dhcp_server() { R '! pgrep -x dnsmasq >/dev/null && ! pgrep -x udhcpd >/dev/null'; }
no_ft() { R '! grep -rqs "^ieee80211r=1" /run/hostapd /etc'; }
# first run: the setup code is root-only, nobody claims the unit without it, the owner does with it; an AP records
# setup as complete at its first start (no "not set up yet" banner, no router wizard)
FRPW='Ci-Gate-Passw0rd-2026'
fr_post() { curl -sk -o "$W/fr-post.json" -w '%{http_code}' -m 60 -H 'content-type: application/json' \
  -d "{\"username\":\"cigate\",\"password\":\"$FRPW\",\"confirm\":\"$FRPW\",\"setup_code\":\"$1\"}" https://127.0.0.1:$WEBP/api/first-run; }
fr_code_file() { m=$(R 'test -s /run/patronus/first-run-code && ls -l /run/patronus/first-run-code') || return 1; case "$m" in "-rw------- "*) ;; *) echo "$m"; return 1;; esac; }
fr_no_code() { c=$(fr_post ''); [ "$c" = 403 ] || { echo "no code: HTTP $c $(cat "$W/fr-post.json")"; return 1; }
  c=$(fr_post 'AAAA-BBBB-CCCC'); [ "$c" = 403 ] || { echo "wrong code: HTTP $c"; return 1; }; }
fr_claim() { code=$(R 'cat /run/patronus/first-run-code') || return 1; c=$(fr_post "$code")
  [ "$c" = 200 ] || { echo "with code: HTTP $c $(cat "$W/fr-post.json")"; return 1; }; R '! test -e /run/patronus/first-run-code'; }
setup_ap() { R 'grep -q "setup recorded as complete (role ap)" /var/log/web.log' || { echo "no provisioned line in web.log"; return 1; }
  rm -f "$W/jar"; c=$(curl -sk -c "$W/jar" -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' \
    -d "{\"username\":\"cigate\",\"password\":\"$FRPW\"}" https://127.0.0.1:$WEBP/api/auth/login); [ "$c" = 200 ] || { echo "login HTTP $c"; return 1; }
  s=$(curl -sk -b "$W/jar" -m 60 https://127.0.0.1:$WEBP/api/setup/status); case "$s" in *'"completed":true'*'"role":"ap"'*'"wizard":false'*) ;; *) echo "status: $s"; return 1;; esac
  c=$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' -d '{"wan_interface":"a","lan_interface":"b","lan_ipv4":"192.168.9.1/24"}' https://127.0.0.1:$WEBP/api/setup/apply)
  [ "$c" = 409 ] || { echo "wizard apply on an AP: HTTP $c"; return 1; }; }
web_claimed() { c=$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' -m 30 https://127.0.0.1:$WEBP/first-run); case "$c" in 30?*/login) ;; *) echo "first-run: $c"; return 1;; esac; }

# the features this build has (FEATURES= in /etc/patronus-release): their checks run only when built in
FEATURES=$(unsquashfs -cat "$SQ" etc/patronus-release 2>/dev/null | sed -n 's/^FEATURES=//p')
has_feature() { case ",$FEATURES," in *",$1,"*) return 0;; esac; return 1; }
login() { rm -f "$W/jar"; c=$(curl -sk -c "$W/jar" -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' \
    -d "{\"username\":\"cigate\",\"password\":\"$FRPW\"}" https://127.0.0.1:$WEBP/api/auth/login); [ "$c" = 200 ] || { echo "login HTTP $c"; return 1; }; }
# api METHOD PATH [JSON]: the admin's session (login), body in $W/api.json, prints the HTTP code
api() { curl -sk -b "$W/jar" -o "$W/api.json" -w '%{http_code}' -m 180 -X "$1" -H 'content-type: application/json' ${3:+-d "$3"} "https://127.0.0.1:$WEBP$2"; }
jget() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); [v:=v[k] for k in sys.argv[2:]]; print(v)' "$W/api.json" "$@"; }
# WireGuard (vpn-wireguard), all through the web API: a server tunnel wg0 (51820) and a client tunnel wg1 (51821) whose
# peer is wg0 at 127.0.0.1:51820, so the kernel module, `wg syncconf`, the routes and the firewall's listen-port rules
# are exercised by a real handshake; plus a road-warrior peer whose key pair Patronus generates (client config export)
wg_create() { login || return 1
  c=$(api POST /api/vpn/wireguard/tunnels '{"name":"wg0","listen_port":51820,"addresses":"10.99.0.1/24","endpoint":"203.0.113.10","description":"ci server"}')
  [ "$c" = 201 ] || { echo "wg0: HTTP $c $(cat "$W/api.json")"; return 1; }; k0=$(jget public_key)
  c=$(api POST /api/vpn/wireguard/tunnels '{"name":"wg1","listen_port":51821,"addresses":"10.98.0.1/24","description":"ci client"}')
  [ "$c" = 201 ] || { echo "wg1: HTTP $c $(cat "$W/api.json")"; return 1; }; k1=$(jget public_key)
  c=$(api POST /api/vpn/wireguard/peers "{\"interface\":\"wg0\",\"name\":\"ci-client\",\"public_key\":\"$k1\",\"allowed_ips\":\"10.98.0.1/32\"}")
  [ "$c" = 201 ] || { echo "peer ci-client: HTTP $c $(cat "$W/api.json")"; return 1; }
  c=$(api POST /api/vpn/wireguard/peers "{\"interface\":\"wg1\",\"name\":\"ci-server\",\"public_key\":\"$k0\",\"allowed_ips\":\"10.99.0.1/32\",\"endpoint\":\"127.0.0.1:51820\",\"persistent_keepalive\":5}")
  [ "$c" = 201 ] || { echo "peer ci-server: HTTP $c $(cat "$W/api.json")"; return 1; }
  c=$(api POST /api/vpn/wireguard/peers '{"interface":"wg0","name":"ci-roadwarrior","preshared_key":true}')
  [ "$c" = 201 ] || { echo "peer ci-roadwarrior: HTTP $c $(cat "$W/api.json")"; return 1; }; id=$(jget id)
  c=$(api GET "/api/vpn/wireguard/config/$id"); [ "$c" = 200 ] || { echo "client config: HTTP $c"; return 1; }
  for w in '[Interface]' PrivateKey PresharedKey "PublicKey = $k0" 'Endpoint = 203.0.113.10:51820'; do
    grep -F "$w" "$W/api.json" >/dev/null || { echo "client config lacks '$w'"; return 1; }; done; }
wg_kernel() { o=$(R 'wg show wg0 listen-port; wg show wg0 peers | wc -l; wg show wg1 listen-port; wg show wg1 endpoints; ip -o -4 addr show dev wg0; ip link show wg0; ip route show proto 249') || { echo "$o"; return 1; }
  echo "$o"; set -- $o
  [ "$1" = 51820 ] && [ "$2" = 2 ] && [ "$3" = 51821 ] || { echo "listen ports / peer count wrong"; return 1; }
  case "$o" in *127.0.0.1:51820*) ;; *) echo "wg1 has no endpoint 127.0.0.1:51820"; return 1;; esac
  case "$o" in *10.99.0.1/24*) ;; *) echo "wg0 has no 10.99.0.1/24"; return 1;; esac
  case "$o" in *patronus-wg*) ;; *) echo "wg0 not tagged patronus-wg"; return 1;; esac
  case "$o" in *"10.98.0.1 dev wg0"*) ;; *) echo "no peer route 10.98.0.1 via wg0 (proto 249)"; return 1;; esac; }
wg_handshake() { i=0; while [ $i -lt 24 ]; do
    h=$(R 'wg show wg1 latest-handshakes' | awk '{print $2}'); [ "${h:-0}" -gt 0 ] 2>/dev/null && { R 'wg show wg0 | head -12'; return 0; }
    i=$((i+1)); sleep 5; done; echo "no handshake wg1 -> wg0 in 120 s"; R 'wg show; nft list ruleset | grep -n 518' 2>&1 | tail -30; return 1; }
wg_module() { R 'grep -q "^wireguard " /proc/modules && grep -qx wireguard /etc/modules.d/wireguard'; }
# NTP: chrony keeps the clock (as user chrony), and the NTP server page makes it serve the LAN (here: QEMU's user net,
# 10.0.2.0/24 on br-lan; the query arrives from 10.0.2.2 through the udp hostfwd)
ntp_query() { python3 - "$NTPP" "${1:-12}" <<'PY'
import socket, sys, time
for _ in range(int(sys.argv[2])):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    try:
        s.sendto(b"\x23" + 47 * b"\0", ("127.0.0.1", int(sys.argv[1])))
        d, _ = s.recvfrom(512)
        if d[0] & 7 == 4 and 0 < d[1] < 16:
            print("NTP reply: mode 4, stratum", d[1]); sys.exit(0)
        print("reply mode", d[0] & 7, "stratum", d[1])
    except OSError as e:
        print("no reply:", e)
    time.sleep(5)
sys.exit(1)
PY
}
ntp_client() { R 'p=$(pgrep -x chronyd) && ps -o user,comm | grep -E "^ *chrony +chronyd" >/dev/null && chronyc -n sources && test -d /var/lib/chrony' || { R 'ps; tail -20 /var/log/messages'; return 1; }; }
ntp_quiet() { o=$(ntp_query 1) && { echo "answered before the NTP server was switched on: $o"; return 1; }; return 0; }
ntp_enable() { login || return 1
  c=$(api PUT /api/ntp '{"enabled":true,"servers":"pool.ntp.org","interfaces":"@lan"}'); [ "$c" = 200 ] || { echo "PUT /api/ntp: HTTP $c $(cat "$W/api.json")"; return 1; }
  R 'cat /etc/chrony/chrony.conf' > "$W/chrony.conf"; cat "$W/chrony.conf"
  grep -x 'allow 10.0.2.0/24' "$W/chrony.conf" >/dev/null && grep -x 'local stratum 10' "$W/chrony.conf" >/dev/null || { echo "chrony.conf does not serve the LAN"; return 1; }
  i=0; while :; do c=$(api GET /api/ntp)
    case "$(cat "$W/api.json")" in *'"enabled":true'*'"available":true'*'"running":true'*) return 0;; esac
    i=$((i+1)); [ $i -ge 12 ] && { echo "status: $(cat "$W/api.json")"; return 1; }; sleep 5; done; }
# Syslog (feature syslog, busybox backend): a UDP collector added on the Syslog page (10.0.2.2 = this container through
# QEMU's user net, a listener on 127.0.0.1:5514), the page's test message must arrive there; TCP is refused (UDP only)
SYSLP=5514
syslog_listen() { rm -f "$W/syslog-rx.txt"; python3 - "$SYSLP" "$W/syslog-rx.txt" "${1:-120}" <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", int(sys.argv[1]))); s.settimeout(2)
end = time.time() + int(sys.argv[3])
with open(sys.argv[2], "ab", buffering=0) as f:
    while time.time() < end:
        try:
            f.write(s.recv(4096) + b"\n")
        except OSError:
            pass
PY
  SLP=$!; sleep 1; }
syslog_wait() { # pattern: up to 60 s for it to arrive at the listener
  i=0; while [ $i -lt 30 ]; do grep -a "$1" "$W/syslog-rx.txt" 2>/dev/null && return 0; i=$((i+1)); sleep 2; done
  echo "nothing matching '$1' arrived at 127.0.0.1:$SYSLP"; R 'cat /etc/patronus/syslogd-remote.conf; ps | grep [s]yslogd; tail -5 /var/log/messages'; return 1; }
syslog_enable() { login || return 1
  c=$(api POST /api/svc/syslog/targets "{\"host\":\"10.0.2.2\",\"port\":$SYSLP,\"proto\":\"udp\",\"severity\":\"info\",\"description\":\"ci collector\"}")
  case "$c" in 200|201) ;; *) echo "add collector: HTTP $c $(cat "$W/api.json")"; return 1;; esac
  i=0; while :; do o=$(R "cat /etc/patronus/syslogd-remote.conf; cat /proc/\$(pgrep -x syslogd)/cmdline | tr '\\0' ' '" 2>&1)
    case "$o" in *"-R 10.0.2.2:$SYSLP"*"-L"*) break;; esac
    i=$((i+1)); [ $i -ge 10 ] && { echo "$o"; echo "syslogd does not forward to 10.0.2.2:$SYSLP"; return 1; }; sleep 3; done; echo "$o"
  c=$(api GET /api/svc/syslog); case "$(cat "$W/api.json")" in *'"backend":"busybox"'*) ;; *) echo "status: $(cat "$W/api.json" | head -c 600)"; return 1;; esac; }
syslog_test_msg() { c=$(api POST /api/svc/syslog/action/test '{}'); [ "$c" = 200 ] || { echo "test action: HTTP $c $(cat "$W/api.json")"; return 1; }
  syslog_wait 'Patronus syslog test message'; }
syslog_boot2() { R "logger -t ci-gate forwarded-after-restart-$INIT" && syslog_wait "forwarded-after-restart-$INIT"; }
syslog_tcp_refused() { c=$(api POST /api/svc/syslog/targets '{"host":"10.0.2.2","port":6514,"proto":"tcp"}')
  [ "$c" = 400 ] && grep -F 'UDP only' "$W/api.json" >/dev/null || { echo "TCP collector: HTTP $c $(cat "$W/api.json")"; return 1; }
  R '! grep -q 6514 /etc/patronus/syslogd-remote.conf'; }

# fake UBI + board for the flash-guard checks (QEMU has no UBI and is not a GL-AX1800)
FAKES='mkdir -p /tmp/fk && printf "glinet,gl-ax1800\0qcom,ipq6018\0" > /tmp/fk/compat && cat > /tmp/fk/ubinfo <<"EOF"
#!/bin/sh
case "${2:-}" in
  -N) case "$3" in kernel) echo "Volume ID:   0 (on ubi0)"; echo "Size:  42 LEBs (5332992 bytes)";; rootfs) echo "Volume ID:   1 (on ubi0)"; echo "Size:  250 LEBs (31744000 bytes)";; *) exit 1;; esac;;
  *) echo "Amount of available logical eraseblocks: 264 (33521664 bytes)";;
esac
EOF
chmod +x /tmp/fk/ubinfo'
FENV='PATRONUS_DT_COMPAT=/tmp/fk/compat FW_UBINFO=/tmp/fk/ubinfo'

: > "$RES/summary.txt"
boot 1 || { echo "FAILED: ${fails[*]}"; exit 1; }
check "PID 1 is $INIT (not busybox init)" pid1
check "all services up ($INIT)" services_up
check "ETPhoneHome baked in and running" etph
check "web UI: HTTPS answers, first-run page served" web
check "system log (/var/log/messages) written" syslog
check "off-board: Wi-Fi calibration skipped, netfilter kmods (virt build of the pinned set) loaded without errors" offboard
check "firewall applied by patronus-web (nftables tables present)" firewall
check "patronus-release: board + init" release
check "AP role: no DHCP/DNS server running" no_dhcp_server
check "no 802.11r in any config" no_ft
check "first run: setup code written root-only (/run/patronus/first-run-code)" fr_code_file
check "first run: refused without / with a wrong setup code (403)" fr_no_code
check "first run: the setup code claims the unit, then the code file is gone" fr_claim
check "AP role: setup recorded complete at first start, status completed/ap/no wizard, wizard apply refused (409)" setup_ap
check "clock: chronyd (the one NTP daemon) runs as user chrony" ntp_client
if has_feature vpn-wireguard; then
  check "WireGuard: kernel module loaded at boot (/etc/modules.d)" wg_module
  check "WireGuard: server + client tunnels and peers created through the web API, road-warrior config exported" wg_create
  check "WireGuard: wg show has the listen ports and peers, address, ifalias, peer route (proto 249)" wg_kernel
  check "WireGuard: the client tunnel completes a handshake with the server tunnel" wg_handshake
else echo "SKIP: WireGuard (not in FEATURES=$FEATURES)" | tee -a "$RES/results.txt"; fi
if has_feature ntp-server; then
  check "NTP server off by default: no answer on the LAN" ntp_quiet
  check "NTP server page: switched on through the web API, chrony.conf serves the LAN subnet, status running" ntp_enable
  check "NTP server: answers an NTP query from the LAN" ntp_query
else echo "SKIP: NTP server (not in FEATURES=$FEATURES)" | tee -a "$RES/results.txt"; fi
if has_feature syslog; then
  syslog_listen 900
  check "Syslog page: a UDP collector added through the web API, busybox syslogd restarted with -R ... -L" syslog_enable
  check "Syslog page: the test message arrives at the collector" syslog_test_msg
  check "Syslog page: a TCP collector is refused (busybox forwards over UDP only), nothing written" syslog_tcp_refused
else echo "SKIP: Syslog (not in FEATURES=$FEATURES)" | tee -a "$RES/results.txt"; fi
scp -O -q "${SSHO[@]}" -P $SSHP "$TAR" root@127.0.0.1:/data/up.tar || fail "scp image into the guest"
refuse_board() { o=$(R 'patronus-flash check /data/up.tar' 2>&1) && { echo "accepted: $o"; return 1; }; case "$o" in *"image is for glinet,gl-ax1800"*) ;; *) echo "$o"; return 1;; esac; }
check "flash guard: refuses on a non-GL-AX1800 board" refuse_board
R "$FAKES"
check "flash check: the real image passes every guard (loop-mounted root, busybox)" R "$FENV patronus-flash check /data/up.tar"
check "flash guard: a corrupt image is refused" R "cp /data/up.tar /tmp/bad.tar && printf 'XXXXXXXX' | dd of=/tmp/bad.tar bs=1 seek=3000000 conv=notrunc 2>/dev/null && ! $FENV patronus-flash check /tmp/bad.tar; rm -f /tmp/bad.tar"
check "flash sysupgrade: stages the image" R "$FENV patronus-flash sysupgrade /data/up.tar && test -f /data/.upgrade/ready"
check "upgrade-install verify accepts it (with the board's identity)" R "$FENV /usr/libexec/patronus/upgrade-install verify"
check "persistence marker written (/etc overlay, /root)" R 'echo ci-$$ > /etc/patronus/ci-marker && echo ok > /root/ci-marker && rm -f /data/up.tar && sync'
# an older image's /etc/passwd in the overlay (no chrony user): the next boot must add the image's system account
check "an account missing from the persisted /etc/passwd (as an older image left it)" R "sed -i '/^chrony:/d' /etc/passwd && ! grep -q '^chrony:' /etc/passwd && sync"
R 'free -k; cat /tmp/boot-times; ps -o rss,comm | sort -n | tail -8' > "$RES/boot1-stats.txt" 2>&1
poweroff_vm
boot 2 || { echo "FAILED: ${fails[*]}"; exit 1; }
check "boot 2: the staged upgrade was rejected at boot (wrong board) and the box came up" R 'test -d /data/.upgrade-rejected && ! test -e /data/.upgrade && grep -q upgrade-rejected /tmp/boot-times'
check "boot 2: settings persisted (/etc overlay, /root)" R 'test -s /etc/patronus/ci-marker && test -s /root/ci-marker'
check "boot 2: PID 1 is $INIT" pid1
check "boot 2: all services up" services_up
check "boot 2: ETPhoneHome running" etph
check "boot 2: web UI answers" web_claimed
check "boot 2: setup not recorded again (once only), no first-run code" R '! grep -q "setup recorded as complete" /var/log/web.log && ! test -e /run/patronus/first-run-code'
check "boot 2: the image's system account (chrony) was added back to the persisted /etc/passwd" R 'grep -q "account-added passwd chrony" /tmp/boot-times && grep -q "^chrony:x:980:" /etc/passwd'
check "boot 2: chronyd runs as user chrony" ntp_client
if has_feature vpn-wireguard; then
  check "boot 2: WireGuard module loaded" wg_module
  check "boot 2: both tunnels re-created from the store at boot (listen ports, peers, address, route)" wg_kernel
  check "boot 2: the client tunnel handshakes again" wg_handshake
fi
if has_feature ntp-server; then
  check "boot 2: NTP server still on (chrony.conf persisted), answers on the LAN" ntp_query
fi
if has_feature syslog; then
  kill $SLP 2>/dev/null; syslog_listen 300
  check "boot 2: collector list persisted, syslogd forwards from boot (a logger message arrives)" syslog_boot2
fi
R 'free -k; cat /tmp/boot-times; ps -o rss,comm | sort -n | tail -8; df -k /data' > "$RES/boot2-stats.txt" 2>&1
{ echo "init=$INIT accel=$ACCEL"; grep -E '^Mem:' "$RES/boot2-stats.txt"; grep -E 'exec-|patronus-started|network-up' "$RES/boot2-stats.txt"; } >> "$RES/summary.txt"
poweroff_vm
cat "$RES/summary.txt"
if [ ${#fails[@]} = 0 ]; then echo "FAILED: none" | tee -a "$RES/results.txt"; exit 0; fi
echo "FAILED: ${fails[*]}" | tee -a "$RES/results.txt"; exit 1
