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
HERE=$(cd "$(dirname "$0")" && pwd)
INIT=${1:?usage: qemu-gate.sh <openrc|systemd> <image-dir>}; I=$(readlink -f "${2:?image dir}")
K=${VIRT_KERNEL:?VIRT_KERNEL}; KEY=${UNIT_DIR:?UNIT_DIR}/ci_ed25519
RES=${RESULTS:-/out/qemu-$INIT}; mkdir -p "$RES"; : > "$RES/results.txt"
TMO=${BOOT_TIMEOUT:-1200}
SQ=$(ls "$I"/root.squashfs 2>/dev/null || true); TAR=$(ls "$I"/patronus-*-sysupgrade.tar)
QP=; SLP=; W=$(mktemp -d "${TMPDIR:-/tmp}/ax-qemu.XXXX"); trap 'kill $QP $SLP ${FEEDPID:-} 2>/dev/null; rm -rf "$W"' EXIT
# test copy of the root: the board's kmods replaced by the same pinned netfilter packages built for the virt kernel
# (kmods.pin "virt"), so the firewall applies for real; everything else is the shipped image byte for byte
# GATE_ROOT_IMG=<file>: a test root prepared earlier (qemu-bundle.sh, GATE_PREP_ONLY below) so a small test host needs neither the
# squashfs tools nor the kmod download; GATE_PREP_ONLY=<file>: prepare that test root, copy it there and stop
if [ -n "${GATE_ROOT_IMG:-}" ]; then cp "$GATE_ROOT_IMG" "$W/root.img"
else
unsquashfs -q -d "$W/r" "$SQ" >/dev/null || { echo "unsquashfs failed"; exit 1; }
KV=$(ls "$W/r/lib/modules"); rm -rf "$W/r/lib/modules/$KV" "$W/r/etc/modules.d"; mkdir -p "$W/r/etc/modules.d"
sh "$(dirname "$0")/fetch-kmods.sh" virt "$W/r" "${KMOD_CACHE:-/cache/kmods}" || exit 1
depmod -b "$W/r" "$KV"; : > "$W/r/etc/patronus/qemu-kmods"
mksquashfs "$W/r" "$W/root.img" -comp xz -b 256K -noappend -no-xattrs -all-root -quiet >/dev/null; rm -rf "$W/r"
fi
if [ -n "${GATE_PREP_ONLY:-}" ]; then cp "$W/root.img" "$GATE_PREP_ONLY"; echo "prepared $GATE_PREP_ONLY"; exit 0; fi
truncate -s 256M "$W/data.img"; mkfs.ext4 -q -F -L patronus_data "$W/data.img"
# the address trial moves the unit from its DHCP address (10.0.2.15) to a static one (10.0.2.78): slirp forwards each
# host port to ONE guest address, so the static address gets its own ssh/web ports (RP = the ssh port R uses now)
SSHP=${GATE_SSHP:-2222}; WEBP=${GATE_WEBP:-8443}; SSHP2=${GATE_SSHP2:-$((SSHP + 1))}; WEBP2=${GATE_WEBP2:-$((WEBP + 1))}; RP=$SSHP; NTPP=${GATE_NTPP:-11123}; FEEDP=${GATE_FEEDP:-18080}; QP=
# GATE_BIND=0.0.0.0 publishes the web UI port beyond the container (browser e2e against the running unit);
# GATE_HOLD=<s> keeps the unit running that long after the boot-2 checks (for those e2e runs)
BIND=${GATE_BIND:-127.0.0.1}; INJP=${GATE_INJP:-12224}
# an update feed that is NOT signed by the release key (the online check must refuse it), served to the guest at 10.0.2.2
mkdir -p "$W/feed/glinet_gl-ax1800/$INIT"; printf '{"build":"ci-feed","image":"x-sysupgrade.tar","sha256":"%064d","size":1}' 0 > "$W/feed/glinet_gl-ax1800/$INIT/latest.json"
printf 'not a signature' > "$W/feed/glinet_gl-ax1800/$INIT/latest.json.sig"
(cd "$W/feed" && exec python3 -m http.server -b 127.0.0.1 $FEEDP >/dev/null 2>&1) & FEEDPID=$!
fails=()
pass() { echo "PASS: $*" | tee -a "$RES/results.txt"; }
fail() { echo "FAIL: $*" | tee -a "$RES/results.txt"; fails+=("$1"); }
check() { n=$1; shift; if out=$("$@" 2>&1); then pass "$n"; else fail "$n"; echo "$out" | tail -15 | sed 's/^/    /' | tee -a "$RES/results.txt"; fi; }
SSHO=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15)
R() { ssh "${SSHO[@]}" -p $RP root@127.0.0.1 "$@"; }
ACCEL=tcg; [ -w /dev/kvm ] && [ "$(uname -m)" = aarch64 ] && ACCEL=kvm
boot() { # n
  n=$1; t0=$(date +%s)
  qemu-system-aarch64 -M virt -accel $ACCEL -cpu $([ $ACCEL = kvm ] && echo host || echo cortex-a53) -smp 2 -m 512 \
    -kernel "$K" -append "root=/dev/vda rootfstype=squashfs ro console=ttyAMA0 patronus.data=/dev/vdb panic=-1" \
    -drive file="$W/root.img",if=virtio,format=raw,readonly=on -drive file="$W/data.img",if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSHP-:22,hostfwd=tcp:$BIND:$WEBP-:443,hostfwd=udp:127.0.0.1:$NTPP-:123,hostfwd=tcp:127.0.0.1:$SSHP2-10.0.2.78:22,hostfwd=tcp:127.0.0.1:$WEBP2-10.0.2.78:443 -device virtio-net-pci,netdev=n0 \
    -netdev socket,id=n1,listen=127.0.0.1:$INJP -device virtio-net-pci,netdev=n1,mac=02:c1:9a:7e:00:fe \
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
# Wi-Fi page backend (the access-point file the boot uses), AP-role pages, the "not available" list
# JSON objects come back with their keys sorted: match each fragment on its own
has_all() { s=$1; shift; for p in "$@"; do case "$s" in *"$p"*) ;; *) return 1;; esac; done; }
login() { rm -f "$W/jar"; c=$(curl -sk -c "$W/jar" -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' \
    -d "{\"username\":\"cigate\",\"password\":\"$FRPW\"}" https://127.0.0.1:$WEBP/api/auth/login); [ "$c" = 200 ] || { echo "login HTTP $c"; return 1; }; }
wapi() { curl -sk -b "$W/jar" -m 90 -o "$W/api.json" -w '%{http_code}' -H 'content-type: application/json' "$@"; }
features_ap() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/features); f=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$f" '"role":"ap"' '"wifi_backend":true' || { echo "features: $c $f"; return 1; }
  case "$f" in *'"absent":['*'"feature":"ha"'*'not included in this router-tier image'*) ;; *) echo "no absent list: $f"; return 1;; esac
  case "$f" in *'"feature":"dhcp"'*'access point'*) ;; *) echo "dhcp not explained as the main router's job: $f"; return 1;; esac
  # the guest network is the main router's job: listed with that reason, never silently missing
  case "$f" in *'"feature":"guest"'*'access point'*) ;; *) echo "guest network not explained as the main router's job: $f"; return 1;; esac; }
ap_pages() { c=$(wapi https://127.0.0.1:$WEBP/dhcp); grep -q 'This unit is an access point' "$W/api.json" && [ "$c" = 200 ] || { echo "/dhcp: $c"; return 1; }
  c=$(wapi -X POST -d '{"start":"192.0.2.100","end":"192.0.2.150"}' https://127.0.0.1:$WEBP/api/dhcp/pools); [ "$c" = 409 ] || { echo "dhcp pool on an AP: HTTP $c"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/svc/guest); grep -q 'This unit is an access point' "$W/api.json" && [ "$c" = 200 ] || { echo "/svc/guest: $c"; return 1; }
  c=$(wapi -X PUT -d '{"enabled":true}' https://127.0.0.1:$WEBP/api/svc/guest); [ "$c" = 409 ] || { echo "guest network change on an AP: HTTP $c"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/wifi); [ "$c" = 200 ] && grep -q 'id="wifi-networks"' "$W/api.json" || { echo "/wifi page: $c"; return 1; }; }
WIFI_SET='{"country":"US","chan24":"6","chan5":"36","width5":80,"wifi6":true,"networks":[{"ssid":"CI Gate Net","key":"ci-gate-wifi-pass","security":"wpa2+3","enabled":true},{"ssid":"CI Gate IoT","key":"ci-gate-iot-pass","bands":"24","isolate":true,"enabled":true}]}'
wifi_set() { c=$(wapi -X PUT -d "$WIFI_SET" https://127.0.0.1:$WEBP/api/wifi); r=$(cat "$W/api.json")
  [ "$c" = 200 ] || { echo "PUT /api/wifi: $c $r"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  case "$g" in *ci-gate-wifi-pass*|*ci-gate-iot-pass*) echo "GET /api/wifi leaks a key"; return 1;; esac
  has_all "$g" '"ssid":"CI Gate Net"' '"security":"wpa2+3"' '"ssid":"CI Gate IoT"' '"bands":"24"' '"isolate":true' '"chan24":"6"' || { echo "GET after PUT: $g"; return 1; }
  m=$(R 'ls -l /etc/patronus/ap.env; . /etc/patronus/board.sh; echo "SSIDS=$AP_SSIDS CH=$AP_CHAN24/$AP_CHAN5 HE=$AP_HE"') || return 1
  case "$m" in "-rw------- "*"SSIDS=cigatene cigateio CH=6/36 HE=1"*) ;; *) echo "ap.env on the unit: $m"; return 1;; esac
  c=$(wapi -X PUT -d '{"chan5":"150"}' https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "bad channel: HTTP $c"; return 1; }
  c=$(wapi -X POST https://127.0.0.1:$WEBP/api/wifi/networks/cigatene/reveal); grep -q ci-gate-wifi-pass "$W/api.json" || { echo "reveal: $c"; return 1; }; }
# configuration backup carries the access-point file; restoring it puts the Wi-Fi settings back (chan24 6 -> 11 -> 6)
wifi_backup() { c=$(wapi -X POST https://127.0.0.1:$WEBP/api/system/backups); b=$(cat "$W/api.json")
  n=$(printf '%s' "$b" | sed -n 's/.*"name":"\(patronus-config-[^"]*\.json\)".*/\1/p'); [ "$c" = 201 ] && [ -n "$n" ] || { echo "backup: $c $b"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/system/backups/$n); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"access_point"' 'AP_CHAN24=6' 'CI Gate Net' || { echo "backup has no access-point file: $c"; return 1; }
  c=$(wapi -X PUT -d '{"chan24":"11"}' https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 200 ] || { echo "PUT chan24 11: $c"; return 1; }
  m=$(R '. /etc/patronus/board.sh; echo "CH=$AP_CHAN24"'); [ "$m" = CH=11 ] || { echo "after PUT: $m"; return 1; }
  c=$(wapi -X POST https://127.0.0.1:$WEBP/api/system/backups/$n/restore); r=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$r" 'access-point settings restored' || { echo "restore: $c $r"; return 1; }
  m=$(R 'ls -l /etc/patronus/ap.env; . /etc/patronus/board.sh; echo "CH=$AP_CHAN24 SSIDS=$AP_SSIDS"')
  case "$m" in "-rw------- "*"CH=6 SSIDS=cigatene cigateio"*) ;; *) echo "after restore: $m"; return 1;; esac; }
# channel plan: a unit without channel settings runs automatic channel selection on both radios (2.4 GHz among 1/6/11,
# no DFS); every part of the plan is a setting (API -> ap.env), bad values refused; then the declarative CLI document
wifi_chanplan() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"chan24":"auto"' '"chan5":"auto"' '"chanlist24":[1,6,11]' '"chanlist5":[]' '"dfs":false' '"unii4":false' '"width24":20' \
    '"width5":80' '"acs_scans":5' '"coord5":true' '"coord24":true' '"coord_peers":[]' '"coord_min_signal":-90' '"coord_delay":120' \
    '"coord_interval":3600' '"coord_quiet":"1-5"' '"coord_scan_secs":25' || { echo "defaults: $c $g"; return 1; }
  c=$(wapi -X PUT -d '{"width24":40,"dfs":true,"unii4":true,"chanlist5":[36,40,52],"chanlist24":[],"acs_scans":3,"coord5":false,"coord_peers":["AA:BB:CC:DD:EE:FF"],"coord_min_signal":-80,"coord_interval":0,"coord_quiet":""}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT plan: $c $(cat "$W/api.json")"; return 1; }
  m=$(R '. /etc/patronus/board.sh; echo "HT24=$AP_HT24 DFS=$AP_DFS U4=$AP_UNII4 L5=$AP_CHANLIST5 L24=[$AP_CHANLIST24] S=$AP_ACS_SCANS C5=$AP_COORD5 CP=$AP_COORD_PEERS CS=$AP_COORD_MIN_SIGNAL CI=$AP_COORD_INTERVAL CQ=[$AP_COORD_QUIET]"')
  [ "$m" = "HT24=40 DFS=1 U4=1 L5=36 40 52 L24=[] S=3 C5=0 CP=aa:bb:cc:dd:ee:ff CS=-80 CI=0 CQ=[]" ] || { echo "ap.env after PUT: $m"; return 1; }
  for bad in '{"width24":80}' '{"chanlist24":[14]}' '{"chanlist5":[150]}' '{"acs_scans":0}' '{"coord_peers":["nope"]}' '{"coord_min_signal":-10}' '{"coord_quiet":"25-3"}' '{"coord_interval":30}' '{"coord_scan_secs":2}'; do
    c=$(wapi -X PUT -d "$bad" https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "$bad: HTTP $c"; return 1; }; done
  c=$(wapi -X PUT -d '{"width24":20,"dfs":false,"unii4":false,"chanlist5":[],"chanlist24":[1,6,11],"acs_scans":5,"coord5":true,"coord_peers":[],"coord_min_signal":-90,"coord_interval":3600,"coord_quiet":"1-5"}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT back: $c"; return 1; }; }
# steering + misbehaving-station limits (docs 12.18): defaults in GET, a steering change is live (no radio restart) and
# lands in ap.env, bad values 400, the hostapd limits are settings too; ap-steer is installed executable and `status` runs
wifi_steer() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"steer":"auto"' '"steer_signal":-65' '"steer_after":600' '"steer_idle":64' '"steer_block":30' \
    '"steer_retry":21600' '"steer_max":2' '"steer_interval":30' '"steer_exempt":[]' '"authfail_max":10' '"authfail_window":60' \
    '"authfail_hold":60' '"authfail_hold_max":3600' '"xbss_max":6' '"xbss_window":60' '"xbss_hold":30' \
    '"steer_kick":"quiet"' '"steer_quiet":"01:00-05:00"' '"steer_legacy":"quiet"' '"steer_report":"active"' '"steer_margin":8' \
    '"steer_btm_every":1800' '"steer_quiet_idle":1800' '"steer_kick_every":86400' '"bss_transition":true' '"rrm":true' '"wnm_sleep":false' \
    '"timezone":"UTC0"' '"steer_history":[' || { echo "defaults: $c $g"; return 1; }
  # the soft-steering switches and the time zone are live too (each group ALONE: a restart key would hide a live bug)
  c=$(wapi -X PUT -d '{"steer_kick":"never","steer_quiet":"23:30-04:00","steer_report":"table","timezone":"PST8PDT,M3.2.0,M11.1.0"}' https://127.0.0.1:$WEBP/api/wifi)
  r=$(cat "$W/api.json"); [ "$c" = 200 ] || { echo "PUT soft steer: $c $r"; return 1; }
  case "$r" in *'"restarted":true'*|*'"changed":false'*) echo "soft-steering change restarted the radios or was not written: $r"; return 1;; esac
  m=$(R '. /etc/patronus/board.sh; echo "K=$AP_STEER_KICK Q=$AP_STEER_QUIET R=$AP_STEER_REPORT TZ=$TZ"')
  [ "$m" = "K=never Q=23:30-04:00 R=table TZ=PST8PDT,M3.2.0,M11.1.0" ] || { echo "ap.env after soft PUT: $m"; return 1; }
  for bad in '{"steer_kick":"always"}' '{"steer_quiet":"1-5"}' '{"timezone":"$(id)"}' '{"steer_margin":99}'; do
    c=$(wapi -X PUT -d "$bad" https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "$bad: HTTP $c"; return 1; }; done
  c=$(wapi -X PUT -d '{"steer_kick":"quiet","steer_quiet":"01:00-05:00","steer_report":"active","timezone":"UTC0"}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT soft back: $c"; return 1; }
  # band steering (docs 12.18b): defaults, live (no radio restart, written to ap.env), bad values 400 (ALONE, no restart key)
  has_all "$g" '"bandsteer":true' '"band_signal":-60' '"band_min5":-70' '"band_busy":0' '"band_after":120' || { echo "band defaults: $g"; return 1; }
  c=$(wapi -X PUT -d '{"bandsteer":false,"band_busy":40,"band_min5":-65}' https://127.0.0.1:$WEBP/api/wifi)
  r=$(cat "$W/api.json"); [ "$c" = 200 ] || { echo "PUT band: $c $r"; return 1; }
  case "$r" in *'"restarted":true'*|*'"changed":false'*) echo "band-steering change restarted the radios or was not written: $r"; return 1;; esac
  m=$(R '. /etc/patronus/board.sh; echo "B=$AP_BANDSTEER U=$AP_BANDSTEER_BUSY M=$AP_BANDSTEER_MIN5"')
  [ "$m" = "B=0 U=40 M=-65" ] || { echo "ap.env after band PUT: $m"; return 1; }
  for bad in '{"band_busy":101}' '{"band_signal":-10}' '{"band_after":-1}'; do
    c=$(wapi -X PUT -d "$bad" https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "$bad: HTTP $c"; return 1; }; done
  c=$(wapi -X PUT -d '{"bandsteer":true,"band_busy":0,"band_min5":-70}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT band back: $c"; return 1; }
  # the image's hostapd configs carry 802.11v/k (never 802.11r) on every BSS the unit renders
  k=$(R 'for f in /run/hostapd/ap5.conf /run/hostapd/ap24.conf; do [ -f "$f" ] && grep -c "^bss_transition=1" "$f"; done; grep -l "^ieee80211r\|^mobility_domain" /run/hostapd/ap*.conf 2>/dev/null; echo end')
  case "$k" in *ap5.conf*|*ap24.conf*) echo "802.11r in the hostapd config: $k"; return 1;; esac
  c=$(wapi -X PUT -d '{"steer":"on","steer_signal":-70,"steer_retry":3600,"steer_exempt":["AA:BB:CC:DD:EE:01"]}' https://127.0.0.1:$WEBP/api/wifi)
  r=$(cat "$W/api.json"); [ "$c" = 200 ] || { echo "PUT steer: $c $r"; return 1; }
  case "$r" in *'"restarted":true'*) echo "a steering change restarted the radios: $r"; return 1;; esac
  m=$(R '. /etc/patronus/board.sh; echo "S=$AP_STEER SIG=$AP_STEER_SIGNAL R=$AP_STEER_RETRY X=$AP_STEER_EXEMPT"')
  [ "$m" = "S=1 SIG=-70 R=3600 X=aa:bb:cc:dd:ee:01" ] || { echo "ap.env after PUT: $m"; return 1; }
  for bad in '{"steer":"maybe"}' '{"steer_signal":-20}' '{"steer_after":5}' '{"steer_exempt":["nope"]}' '{"xbss_hold":90000}' '{"authfail_hold_max":10}'; do
    c=$(wapi -X PUT -d "$bad" https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "$bad: HTTP $c"; return 1; }; done
  c=$(wapi -X PUT -d '{"authfail_max":12,"xbss_hold":45}' https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 200 ] || { echo "PUT limits: $c $(cat "$W/api.json")"; return 1; }
  m=$(R '. /etc/patronus/board.sh; echo "A=$AP_AUTHFAIL_MAX H=$AP_XBSS_HOLD"'); [ "$m" = "A=12 H=45" ] || { echo "ap.env limits: $m"; return 1; }
  s=$(R 'ls -l /usr/libexec/patronus/ap-steer; /usr/libexec/patronus/ap-steer status; echo rc=$?') || { echo "ap-steer status: $s"; return 1; }
  has_all "$s" '-rwx' 'steering: ' 'band steering (2.4 -> 5 GHz of this unit): on' 'rc=0' || { echo "ap-steer status: $s"; return 1; }
  c=$(wapi -X PUT -d '{"steer":"auto","steer_signal":-65,"steer_retry":21600,"steer_exempt":[],"authfail_max":10,"xbss_hold":30}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT back: $c"; return 1; }; }
# channel choice by measurement (docs 12.19): defaults in GET, a change is live (no radio restart) and lands in ap.env, bad
# values 400; ap-chan is installed executable and scores a measurement; GET carries channels + history
wifi_chan() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"chan_smart5":true' '"chan_smart24":true' '"chan_recheck5":true' '"chan_recheck24":true' \
    '"chan_time":"03:30"' '"chan_csa":"auto"' '"chan_hyst":20' '"chan_min_gain":10' '"chan_confirm":3' '"chan_dwell":105' \
    '"chan_wait":90' '"chan_sync_wait":90' '"chan_stagger":1800' '"steer_retry_max":604800' || { echo "defaults: $c $g"; return 1; }
  c=$(wapi -X PUT -d '{"chan_time":"02:45","chan_hyst":30,"chan_smart24":false,"steer_retry_max":86400}' https://127.0.0.1:$WEBP/api/wifi)
  r=$(cat "$W/api.json"); [ "$c" = 200 ] || { echo "PUT chan: $c $r"; return 1; }
  case "$r" in *'"restarted":true'*) echo "a channel-choice change restarted the radios: $r"; return 1;; esac
  m=$(R '. /etc/patronus/board.sh; echo "T=$AP_CHAN_TIME H=$AP_CHAN_HYST S=$AP_CHAN_SMART24 M=$AP_STEER_RETRY_MAX"')
  [ "$m" = "T=02:45 H=30 S=0 M=86400" ] || { echo "ap.env after PUT: $m"; return 1; }
  for bad in '{"chan_time":"25:00"}' '{"chan_hyst":95}' '{"chan_csa":"maybe"}' '{"chan_dwell":1}' '{"steer_retry_max":60}'; do
    c=$(wapi -X PUT -d "$bad" https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "$bad: HTTP $c"; return 1; }; done
  s=$(R 'ls -l /usr/libexec/patronus/ap-chan; printf "S 1 400 40\nS 6 400 200\nS 11 400 120\n" | /usr/libexec/patronus/ap-chan score 24 "1 6 11"; echo rc=$?')
  has_all "$s" '-rwx' '1 10.0 10.0 0' 'rc=0' || { echo "ap-chan score: $s"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"channels":' '"channel_history":' || { echo "status: $c $g"; return 1; }
  c=$(wapi -X PUT -d '{"chan_time":"03:30","chan_hyst":20,"chan_smart24":true,"steer_retry_max":604800}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT back: $c"; return 1; }; }
wifi_cli() { d=$(R 'patronus-cli ap-wifi export --json') || { echo "export failed: $d"; return 1; }
  case "$d" in *ci-gate-wifi-pass*) echo "export leaks a key"; return 1;; esac
  has_all "$d" '"apiVersion": "patronus.ap-wifi/v1"' '"chan24": "6"' '"ssid": "CI Gate Net"' || { echo "export: $d"; return 1; }
  p=$(R 'patronus-cli ap-wifi export > /tmp/apw.yaml && sed -i "s/^chan24: .*/chan24: auto/" /tmp/apw.yaml && patronus-cli ap-wifi plan /tmp/apw.yaml') || { echo "plan: $p"; return 1; }
  has_all "$p" '"setting": "chan24"' '"to": "auto"' || { echo "plan: $p"; return 1; }
  case "$p" in *'"setting": "networks'*) echo "plan shows unchanged networks as changed: $p"; return 1;; esac
  a=$(R 'patronus-cli ap-wifi apply /tmp/apw.yaml; rm -f /tmp/apw.yaml; . /etc/patronus/board.sh; echo "CH=$AP_CHAN24"')
  has_all "$a" '"changed": true' 'CH=auto' || { echo "apply: $a"; return 1; }
  c=$(wapi -X PUT -d '{"chan24":"6"}' https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 200 ] || { echo "PUT chan24 6: $c"; return 1; }; }
wifi_persisted() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"ssid":"CI Gate Net"' '"chan24":"6"' '"ssid":"CI Gate IoT"' || { echo "after restart: $c $g"; return 1; }; }

# the features this build has (FEATURES= in /etc/patronus-release): their checks run only when built in
FEATURES=$(unsquashfs -cat "$W/root.img" etc/patronus-release 2>/dev/null | sed -n 's/^FEATURES=//p')
has_feature() { case ",$FEATURES," in *",$1,"*) return 0;; esac; return 1; }
login() { rm -f "$W/jar"; c=$(curl -sk -c "$W/jar" -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' \
    -d "{\"username\":\"cigate\",\"password\":\"$FRPW\"}" https://127.0.0.1:$WEBP/api/auth/login); [ "$c" = 200 ] || { echo "login HTTP $c"; return 1; }; }
# api METHOD PATH [JSON]: the admin's session (login), body in $W/api.json, prints the HTTP code
api() { curl -sk -b "$W/jar" -o "$W/api.json" -w '%{http_code}' -m 180 -X "$1" -H 'content-type: application/json' ${3:+-d "$3"} "https://127.0.0.1:$WEBP$2"; }
jget() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); [v:=v[k] for k in sys.argv[2:]]; print(v)' "$W/api.json" "$@"; }
# access log: the router tier's env caps the history (2000 rows, embedded.env); a 5000-request burst must leave at most the cap,
# the writer accounts for every request (written + dropped), and patronus-web's RSS after the burst is recorded
gap_accesslog() { login || return 1
  c=$(api GET /api/system/access-log/settings); [ "$c" = 200 ] || { echo "settings: HTTP $c"; return 1; }
  [ "$(jget settings retention_rows)" = 2000 ] || { echo "env cap not applied: $(cat "$W/api.json")"; return 1; }
  w0=$(jget writer written); d0=$(jget writer queued_dropped)
  curl -sk -m 1500 -o /dev/null "https://127.0.0.1:$WEBP/alog-burst-[1-5000]" || { echo "burst failed"; return 1; }
  t=0; while [ $t -lt 120 ]; do c=$(api GET /api/system/access-log/settings); w1=$(jget writer written); d1=$(jget writer queued_dropped)
    [ $((w1 + d1 - w0 - d0)) -ge 5000 ] && break; sleep 3; t=$((t + 3)); done
  [ $((w1 + d1 - w0 - d0)) -ge 5000 ] || { echo "writer accounted only $((w1 + d1 - w0 - d0)) of 5000 requests"; return 1; }
  c=$(api GET /api/system/access-log/stats); [ "$c" = 200 ] || { echo "stats: HTTP $c"; return 1; }
  n=$(jget requests); [ "$n" -le 2000 ] && [ "$n" -ge 100 ] || { echo "rows after the burst: $n (cap 2000)"; return 1; }
  c=$(api GET '/api/system/access-log?limit=5'); [ "$c" = 200 ] || { echo "list: HTTP $c"; return 1; }
  grep -F 'alog-burst' "$W/api.json" >/dev/null && { echo "a raw path was stored"; return 1; }
  rss=$(R 'for p in $(pidof patronus-web); do sed -n "s/^VmRSS:[[:space:]]*//p" /proc/$p/status; done' | head -1)
  echo "GATEMETRIC accesslog_rows_after_burst=$n written=$((w1 - w0)) dropped=$((d1 - d0)) web_rss_after_burst=$rss" | tee -a "$RES/results.txt" "$RES/summary.txt"
  c=$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' -m 60 https://127.0.0.1:$WEBP/system/access-log); [ "$c" = 200 ] || { echo "page: HTTP $c"; return 1; }; }
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
ntp_client() { o=$(R 'pidof chronyd && ps -o user,comm | grep -E "^ *chrony +chronyd" && chronyc -n sources && ls -ld /var/lib/chrony' 2>&1) || { echo "$o"; R 'ps -o pid,user,args | grep [c]hrony; ls -l /dev/urandom'; return 1; }; echo "$o"; }
# /dev from mdev (no devtmpfs): the standard nodes are world-usable, so daemons that drop root work
dev_modes() { o=$(R 'ls -l /dev/null /dev/zero /dev/urandom /dev/random') || return 1; echo "$o"; n=$(echo "$o" | grep -c '^crw-rw-rw-'); [ "$n" = 4 ]; }
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
  echo "nothing matching '$1' arrived at 127.0.0.1:$SYSLP"; R 'cat /etc/patronus/syslogd-remote.conf; ps -o args | grep [s]yslogd; tail -5 /var/log/messages'; return 1; }
syslog_enable() { login || return 1
  c=$(api POST /api/svc/syslog/targets "{\"host\":\"10.0.2.2\",\"port\":$SYSLP,\"proto\":\"udp\",\"severity\":\"info\",\"description\":\"ci collector\"}")
  case "$c" in 200|201) ;; *) echo "add collector: HTTP $c $(cat "$W/api.json")"; return 1;; esac
  i=0; while :; do o=$(R 'cat /etc/patronus/syslogd-remote.conf; ps -o args | grep "[/]bin/syslogd"' 2>&1)
    case "$o" in *"-R 10.0.2.2:$SYSLP"*"-L"*) break;; esac
    i=$((i+1)); [ $i -ge 10 ] && { echo "$o"; echo "syslogd does not forward to 10.0.2.2:$SYSLP"; return 1; }; sleep 3; done; echo "$o"
  c=$(api GET /api/svc/syslog); case "$(cat "$W/api.json")" in *'"backend":"busybox"'*) ;; *) echo "status: $(cat "$W/api.json" | head -c 600)"; return 1;; esac; }
syslog_test_msg() { c=$(api POST /api/svc/syslog/action/test '{}'); [ "$c" = 200 ] || { echo "test action: HTTP $c $(cat "$W/api.json")"; return 1; }
  syslog_wait 'Patronus syslog test message'; }
syslog_boot2() { R "logger -t ci-gate forwarded-after-restart-$INIT" && syslog_wait "forwarded-after-restart-$INIT"; }
syslog_tcp_refused() { c=$(api POST /api/svc/syslog/targets '{"host":"10.0.2.2","port":6514,"proto":"tcp"}')
  [ "$c" = 400 ] && grep -F 'UDP only' "$W/api.json" >/dev/null || { echo "TCP collector: HTTP $c $(cat "$W/api.json")"; return 1; }
  R '! grep -q 6514 /etc/patronus/syslogd-remote.conf'; }

# firmware upload from the web UI: status shows the running build; a file that is not an image for this board is
# refused by patronus-flash's own guards (400) and not kept; nothing gets staged
fw_web() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/system/firmware); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"available":true' '"build":"' '"staged":null' || { echo "status: $c $g"; return 1; }
  head -c 4096 /dev/urandom > "$W/junk.tar"
  c=$(curl -sk -b "$W/jar" -m 120 -o "$W/api.json" -w '%{http_code}' -H 'content-type: application/octet-stream' \
    --data-binary @"$W/junk.tar" https://127.0.0.1:$WEBP/api/system/firmware); g=$(cat "$W/api.json")
  [ "$c" = 400 ] && has_all "$g" 'Invalid image' || { echo "junk upload: $c $g"; return 1; }
  R '! test -e /tmp/patronus-firmware.tar && ! test -e /data/.upgrade' || { echo "junk image left behind"; return 1; }; }
# --- router-tier gaps (docs/router-tier-ui.md "Device settings"): each check drives the web API like the page does
# Wi-Fi page: crash protection (wifi-guard) and the guest filter's availability are reported
gap_state() { login || return 1; c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"guard":{' '"mode":"' '"guest_filter":{' || { echo "GET /api/wifi: $c $g"; return 1; }
  o=$(R '/usr/libexec/patronus/ap-guest status') || return 1; case "$o" in *available=yes*) ;; *) echo "ap-guest status: $o"; return 1;; esac; }
# guest network: GUEST_<id>=1 written, the nftables bridge filter loads in this kernel with the guest ports
gap_guest() { c=$(wapi -X PUT -d '{"networks":[{"id":"cigatene","ssid":"CI Gate Net","enabled":true},{"id":"cigateio","ssid":"CI Gate IoT","bands":"24","isolate":true,"enabled":true},{"ssid":"CI Gate Guest","key":"ci-gate-guest-pass","guest":true,"enabled":true}]}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT guest: $c $(cat "$W/api.json")"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json"); has_all "$g" '"guest":true' '"ssid":"CI Gate Guest"' || { echo "GET: $g"; return 1; }
  o=$(R 'grep -E "(^| )GUEST_cigategu=1( |\$)" /etc/patronus/ap.env && /usr/libexec/patronus/ap-guest apply && nft list table bridge patronus_guest') || { echo "$o"; return 1; }
  has_all "$o" '"wl24-cigategu"' '"wl5-cigategu"' 'ip daddr @lan4 drop' 'meta l4proto { tcp, udp } drop' || { echo "$o"; return 1; }
  # and back: without a guest network the filter goes away
  c=$(wapi -X PUT -d '{"networks":[{"id":"cigatene","ssid":"CI Gate Net","enabled":true},{"id":"cigateio","ssid":"CI Gate IoT","bands":"24","isolate":true,"enabled":true}]}' https://127.0.0.1:$WEBP/api/wifi)
  [ "$c" = 200 ] || { echo "PUT without guest: $c"; return 1; }
  R '/usr/libexec/patronus/ap-guest apply; ! nft list table bridge patronus_guest >/dev/null 2>&1' || { echo "filter left behind"; return 1; }; }
# block list: per network and unit-wide, live (no restart), unblock removes it, bad MAC refused
gap_block() { c=$(wapi -X POST -d '{"mac":"02:CI:00:00:00:01"}' https://127.0.0.1:$WEBP/api/wifi/block); [ "$c" = 400 ] || { echo "bad MAC: $c"; return 1; }
  c=$(wapi -X POST -d '{"mac":"02:C1:00:00:00:01"}' https://127.0.0.1:$WEBP/api/wifi/block); [ "$c" = 200 ] || { echo "block: $c $(cat "$W/api.json")"; return 1; }
  c=$(wapi -X POST -d '{"mac":"02:c1:00:00:00:02","network":"cigateio"}' https://127.0.0.1:$WEBP/api/wifi/block); [ "$c" = 200 ] || { echo "block net: $c $(cat "$W/api.json")"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/wifi); g=$(cat "$W/api.json")
  has_all "$g" '"blocked":["02:c1:00:00:00:01"]' '"blocked":["02:c1:00:00:00:02"]' || { echo "GET: $g"; return 1; }
  o=$(R 'grep -oE "(AP_DENY|DENY_cigateio)=[^ ]*" /etc/patronus/ap.env') || return 1; has_all "$o" 'AP_DENY=02:c1:00:00:00:01' 'DENY_cigateio=02:c1:00:00:00:02' || { echo "$o"; return 1; }
  c=$(wapi -X POST -d '{"mac":"02:c1:00:00:00:01","block":false}' https://127.0.0.1:$WEBP/api/wifi/block); [ "$c" = 200 ] || { echo "unblock: $c"; return 1; }
  R '! grep -q "^AP_DENY=" /etc/patronus/ap.env && grep -q " DENY_cigateio=" /etc/patronus/ap.env' || { echo "unblock did not remove only the global entry"; return 1; }; }
# transmit power: live setting (no radio restart), validated
gap_txpower() { c=$(wapi -X PUT -d '{"txpower5":"17","txpower24":"auto"}' https://127.0.0.1:$WEBP/api/wifi); r=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$r" '"changed":true' '"restarted":false' || { echo "PUT txpower: $c $r"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/wifi); has_all "$(cat "$W/api.json")" '"txpower5":"17"' '"txpower24":"auto"' || { echo "GET: $(cat "$W/api.json")"; return 1; }
  c=$(wapi -X PUT -d '{"txpower5":"40"}' https://127.0.0.1:$WEBP/api/wifi); [ "$c" = 400 ] || { echo "40 dBm: $c"; return 1; }; }
# channel survey: read-only, answers without radios (says why)
gap_survey() { c=$(wapi "https://127.0.0.1:$WEBP/api/wifi/survey?fresh=true"); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"radios":[]' 'nothing to survey' || { echo "survey: $c $g"; return 1; }; }
# client names: a DHCP client on the bridge (veth, the QEMU network's DHCP server answers) with a host name; the
# snoop in patronus applyd records MAC, address and name
gap_names() { R 'ip link set eth1 up && ip link set eth1 master br-lan' || { echo "second NIC"; return 1; }
  python3 - "$INJP" <<'PY' || { echo "inject failed"; R 'ip link set eth1 nomaster; ip link set eth1 down'; return 1; }
import socket, struct, sys
mac = bytes.fromhex("02c19a7e0001")
opts = bytes([53, 1, 3, 50, 4, 10, 0, 2, 99, 12, 13]) + b"ci-gate-phone" + bytes([255])
bootp = struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, 0x1c9a7e01, 0, 0x8000, 0, 0, 0, 0) + mac + bytes(10) + bytes(192) + b"\x63\x82\x53\x63" + opts
udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0) + bootp
h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(4), b"\xff" * 4)
c = sum(struct.unpack("!10H", h)); c = (c & 0xFFFF) + (c >> 16); c = (c & 0xFFFF) + (c >> 16)
ip = h[:10] + struct.pack("!H", ~c & 0xFFFF) + h[12:]
frame = b"\xff" * 6 + mac + b"\x08\x00" + ip + udp
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 10)
for _ in range(3):
    s.sendall(struct.pack("!I", len(frame)) + frame)
s.close()
PY
  sleep 3; o=$(R 'cat /run/patronus/dhcp-names; ip link set eth1 nomaster; ip link set eth1 down') || { echo "$o"; return 1; }
  has_all "$o" '02:c1:9a:7e:00:01 10.0.2.99' 'ci-gate-phone' || { echo "names file: $o"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/wifi/clients); [ "$c" = 200 ] || { echo "clients: $c"; return 1; }; }
# SSH keys: add/remove through the API (audited); root's last key is protected (root has no password)
CIKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZCN3GeRyG77PKWc5YUW/XNmwrh ci-gate-extra'
gap_keys() { c=$(wapi https://127.0.0.1:$WEBP/api/device/ssh-keys); g=$(cat "$W/api.json"); [ "$c" = 200 ] && has_all "$g" '"user":"root"' '"fingerprint":"SHA256:' || { echo "GET keys: $c $g"; return 1; }
  rootfp=$(printf '%s' "$g" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([u for u in d["users"] if u["user"]=="root"][0]["keys"][0]["fingerprint"])')
  c=$(wapi -X POST -d '{"user":"root","key":"ssh-dss AAAA x"}' https://127.0.0.1:$WEBP/api/device/ssh-keys); [ "$c" = 400 ] || { echo "dss accepted: $c"; return 1; }
  c=$(wapi -X POST -d "{\"user\":\"root\",\"key\":\"$CIKEY\"}" https://127.0.0.1:$WEBP/api/device/ssh-keys); r=$(cat "$W/api.json"); [ "$c" = 200 ] || { echo "add: $c $r"; return 1; }
  fp=$(printf '%s' "$r" | python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])')
  R 'grep -q ci-gate-extra /root/.ssh/authorized_keys && [ "$(stat -c %a /root/.ssh/authorized_keys)" = 600 ]' || { echo "key not in authorized_keys (0600)"; return 1; }
  e=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$fp")
  c=$(wapi -X DELETE "https://127.0.0.1:$WEBP/api/device/ssh-keys/root/$e"); [ "$c" = 200 ] || { echo "delete: $c $(cat "$W/api.json")"; return 1; }
  R '! grep -q ci-gate-extra /root/.ssh/authorized_keys' || { echo "still there"; return 1; }
  # the gate's own key is root's last one and root has no password: refused, and ssh still works afterwards
  e=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$rootfp")
  c=$(wapi -X DELETE "https://127.0.0.1:$WEBP/api/device/ssh-keys/root/$e"); r=$(cat "$W/api.json")
  [ "$c" = 400 ] && has_all "$r" 'lock' || { echo "last root key: $c $r"; return 1; }
  R true || { echo "ssh lost"; return 1; }
  sqlite3 -version >/dev/null 2>&1 || return 0
  R 'cp /var/lib/patronus/config.db /tmp/a.db' && scp -O -q "${SSHO[@]}" -P $SSHP root@127.0.0.1:/tmp/a.db "$W/a.db" && R 'rm -f /tmp/a.db'
  a=$(sqlite3 "$W/a.db" "select action||':'||entity_type from audit_log where entity_type='ssh_key'"); has_all "$a" 'add:ssh_key' 'delete:ssh_key' 'delete-refused:ssh_key' || { echo "audit: $a"; return 1; }; }
# LEDs: QEMU has no /sys/class/leds: shown unavailable with the reason, a change is refused
gap_leds() { c=$(wapi https://127.0.0.1:$WEBP/api/device/leds); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"available":false' '/sys/class/leds is empty' || { echo "leds: $c $g"; return 1; }
  c=$(wapi -X PUT -d '{"on":false}' https://127.0.0.1:$WEBP/api/device/leds); [ "$c" = 400 ] || { echo "PUT leds: $c"; return 1; }; }
# scheduled restart: off by default (unit disabled); weekly -> the init system's unit enabled with that schedule; off again
gap_restart() { c=$(wapi https://127.0.0.1:$WEBP/api/device/restart-schedule); g=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$g" '"mode":"off"' '"enabled":"disabled"' || { echo "default: $c $g"; return 1; }
  c=$(wapi -X PUT -d '{"mode":"weekly","day":"wed","time":"03:17"}' https://127.0.0.1:$WEBP/api/device/restart-schedule); g=$(cat "$W/api.json")
  if [ "$INIT" = systemd ]; then has_all "$g" '"enabled":"enabled"' '"active":"active"' '"calendar":"Wed *-*-* 03:17:00"' || { echo "weekly: $c $g"; return 1; }
    n=$(R 'systemctl show -p NextElapseUSecRealtime --value patronus-restart.timer'); case "$n" in Wed*03:17*) ;; *) echo "next: $n"; return 1;; esac
  else has_all "$g" '"enabled":"enabled"' '"active":"active"' '"calendar":"17 3 * * 3"' || { echo "weekly: $c $g"; return 1; }
    R 'pgrep -f "crond -f -c /etc/crontabs" >/dev/null' || { echo "crond not running"; return 1; }; fi
  c=$(wapi -X PUT -d '{"mode":"hourly"}' https://127.0.0.1:$WEBP/api/device/restart-schedule); [ "$c" = 400 ] || { echo "hourly: $c"; return 1; }
  c=$(wapi -X PUT -d '{"mode":"off"}' https://127.0.0.1:$WEBP/api/device/restart-schedule); g=$(cat "$W/api.json")
  has_all "$g" '"mode":"off"' '"enabled":"disabled"' || { echo "off: $g"; return 1; }; }
# address trial: an unconfirmed change reverts by itself; a confirmed one (from the new address) stays; back to DHCP
jar_cookie() { awk -F'\t' 'NF >= 7 { printf "%s%s=%s", (n++ ? "; " : ""), $6, $7 }' "$W/jar"; }
addr_put() { wapi -X PUT -d "$1" https://127.0.0.1:$WEBP/api/device/address; }
addr_wait_idle() { i=0; while [ $i -lt 30 ]; do o=$(R '/usr/libexec/patronus/ap-addr status'); case "$o" in *pending=no*) R 'test ! -e /etc/patronus/ap.env.addr-prev' && return 0;; esac; sleep 3; i=$((i + 1)); done; echo "$o"; return 1; }
gap_address() { c=$(wapi https://127.0.0.1:$WEBP/api/device/address); g=$(cat "$W/api.json"); has_all "$g" '"mode":"dhcp"' '"available":true' || { echo "GET: $c $g"; return 1; }
  c=$(addr_put '{"mode":"static","address":"10.0.2.77/24","gateway":"10.9.9.9"}'); [ "$c" = 400 ] || { echo "gateway outside: $c"; return 1; }
  # 1) wrong gateway, nobody confirms: back to DHCP by itself, ssh never lost
  c=$(addr_put '{"mode":"static","address":"10.0.2.77/24","gateway":"10.0.2.254","confirm_within":30}'); [ "$c" = 200 ] || { echo "PUT: $c $(cat "$W/api.json")"; return 1; }
  sleep 8; o=$(R 'ip -4 -o addr show dev br-lan; /usr/libexec/patronus/ap-addr status'); has_all "$o" '10.0.2.77/24' '10.0.2.15/24' 'pending=yes' || { echo "trial: $o"; return 1; }
  sleep 30; addr_wait_idle || return 1
  o=$(R 'ip -4 -o addr show dev br-lan; grep -c "^AP_ADDR=." /etc/patronus/ap.env; ip route show default; grep -c "PATRONUS-AP-ADDR reverted" /var/log/messages')
  case "$o" in *10.0.2.77*) echo "address left: $o"; return 1;; esac; has_all "$o" '10.0.2.15/24' 'default via 10.0.2.2' || { echo "after revert: $o"; return 1; }
  # 2) right settings, confirmed over the new address: stays
  c=$(addr_put '{"mode":"static","address":"10.0.2.78/24","gateway":"10.0.2.2","dns":"10.0.2.3","confirm_within":120}'); [ "$c" = 200 ] || { echo "PUT 2: $c"; return 1; }
  sleep 8; R 'ping -c1 -W2 -I 10.0.2.78 10.0.2.2 >/dev/null' || { echo "new address does not reach the gateway"; return 1; }
  c=$(wapi -X POST https://127.0.0.1:$WEBP/api/device/address/confirm); [ "$c" = 400 ] || { echo "confirm from the old address accepted: $c"; return 1; }
  # the browser reaches the unit at its NEW address: https://10.0.2.78 (forwarded to the guest's 10.0.2.78)
  c=$(wapi -X POST --connect-to 10.0.2.78:443:127.0.0.1:$WEBP2 -H "cookie: $(jar_cookie)" https://10.0.2.78/api/device/address/confirm); [ "$c" = 200 ] || { echo "confirm: $c $(cat "$W/api.json")"; return 1; }
  RP=$SSHP2; addr_wait_idle || return 1
  o=$(R 'ip -4 -o addr show dev br-lan; grep "^AP_ADDR=" /etc/patronus/ap.env; cat /tmp/resolv.conf.auto'); has_all "$o" '10.0.2.78/24' 'AP_ADDR=10.0.2.78/24' 'nameserver 10.0.2.3' || { echo "confirmed: $o"; return 1; }
  # 3) back to DHCP (confirmed from the DHCP address)
  c=$(wapi -X PUT --connect-to 10.0.2.78:443:127.0.0.1:$WEBP2 -H "cookie: $(jar_cookie)" -d '{"mode":"dhcp","confirm_within":120}' https://10.0.2.78/api/device/address); [ "$c" = 200 ] || { echo "PUT dhcp: $c $(cat "$W/api.json")"; return 1; }
  sleep 12; c=$(wapi -X POST --connect-to 10.0.2.15:443:127.0.0.1:$WEBP -H "cookie: $(jar_cookie)" https://10.0.2.15/api/device/address/confirm); [ "$c" = 200 ] || { echo "confirm dhcp: $c $(cat "$W/api.json")"; return 1; }
  RP=$SSHP; addr_wait_idle || return 1
  o=$(R 'ip -4 -o addr show dev br-lan; grep -c "^AP_ADDR=." /etc/patronus/ap.env'); case "$o" in *10.0.2.78*) echo "static left: $o"; return 1;; esac
  has_all "$o" '10.0.2.15/24' || { echo "dhcp: $o"; return 1; }; }
# online firmware check: a feed signed by another key is refused; nothing is downloaded or staged
gap_feed() { c=$(wapi -X PUT -d '{"feed":"ftp://x"}' https://127.0.0.1:$WEBP/api/system/firmware/feed); [ "$c" = 400 ] || { echo "ftp feed: $c"; return 1; }
  c=$(wapi -X PUT -d "{\"feed\":\"http://10.0.2.2:$FEEDP\"}" https://127.0.0.1:$WEBP/api/system/firmware/feed); [ "$c" = 200 ] || { echo "feed set: $c"; return 1; }
  c=$(wapi -X POST https://127.0.0.1:$WEBP/api/system/firmware/feed/check); r=$(cat "$W/api.json")
  [ "$c" = 400 ] || [ "$c" = 500 ] || { echo "foreign feed accepted: $c $r"; return 1; }
  case "$r" in *"not by the release key"*|*"no release keyring"*|*"signature is missing or bad"*) ;; *) echo "check: $c $r"; return 1;; esac
  c=$(wapi -X POST https://127.0.0.1:$WEBP/api/system/firmware/feed/download); [ "$c" != 200 ] || { echo "download of a foreign feed: 200"; return 1; }
  R '! test -e /tmp/patronus-firmware.tar && ! test -e /data/.upgrade' || { echo "image left behind"; return 1; }; }
# Diagnostics stays usable on an access point: ping, traceroute and a DNS lookup through the web API (busybox tools)
gap_diag() { c=$(wapi -X POST -d '{"tool":"ping","target":"10.0.2.2","count":2}' https://127.0.0.1:$WEBP/api/system/diag); r=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$r" '"received":2' || { echo "ping: $c $r"; return 1; }
  c=$(wapi -X POST -d '{"tool":"traceroute","target":"10.0.2.2"}' https://127.0.0.1:$WEBP/api/system/diag); r=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$r" '10.0.2.2' || { echo "traceroute: $c $r"; return 1; }
  c=$(wapi -X POST -d '{"tool":"routes"}' https://127.0.0.1:$WEBP/api/system/diag); [ "$c" = 200 ] || { echo "routes: $c $(cat "$W/api.json")"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/diagnostics); [ "$c" = 200 ] || { echo "/diagnostics page: $c"; return 1; }; }
# system accounts in backups: the web admin's passwd/shadow/group lines are in the backup; after losing them, a restore
# brings the login back
gap_accounts() { c=$(wapi -X POST https://127.0.0.1:$WEBP/api/system/backups); b=$(cat "$W/api.json")
  n=$(printf '%s' "$b" | sed -n 's/.*"name":"\(patronus-config-[^"]*\.json\)".*/\1/p'); [ "$c" = 201 ] && [ -n "$n" ] || { echo "backup: $c $b"; return 1; }
  c=$(wapi https://127.0.0.1:$WEBP/api/system/backups/$n); g=$(cat "$W/api.json")
  has_all "$g" '"system_accounts"' '"name": "cigate"' '"shadow": "cigate:$' 'patronus-admin:x:' || { echo "backup has no accounts: $c"; return 1; }
  R "cp /etc/passwd /tmp/p.bak; sed -i '/^cigate:/d' /etc/passwd /etc/shadow; sed -i 's/,cigate//; s/:cigate\$/:/' /etc/group; ! grep -q '^cigate:' /etc/passwd" || return 1
  # the restore runs through the web API with the session that is still open (sessions end after a restore)
  c=$(wapi -X POST https://127.0.0.1:$WEBP/api/system/backups/$n/restore); r=$(cat "$W/api.json")
  [ "$c" = 200 ] && has_all "$r" 'system account cigate restored' || { echo "restore: $c $r"; return 1; }
  login || { echo "login after restore failed"; return 1; }; }

# systemd: the Wi-Fi page restarts hostapd through `systemd-run --scope`, so the radios live in a transient scope of
# their own and not in the web UI's unit (a web UI restart would otherwise kill them); prove that placement works here
wifi_scope() { [ "$INIT" = systemd ] || { echo "openrc: n/a"; return 0; }
  o=$(R 'systemd-run --scope --quiet --collect -- sh -c "sleep 300 >/dev/null 2>&1 < /dev/null & echo \$!"') || { echo "systemd-run: $o"; return 1; }
  cg=$(R "cat /proc/$o/cgroup; kill $o") || return 1; case "$cg" in *"/run-"*".scope"*) ;; *) echo "pid $o cgroup: $cg"; return 1;; esac; }
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
# a yescrypt ($y$) account, the hash Gentoo/Horcrux hosts write: musl's crypt() behind pam_unix cannot check it, so the web
# login reads the shadow file itself (PATRONUS_AUTH_BACKEND=shadow). The CI image carries tests/ci-accounts (ciacct, yescrypt hash
# of a public test password, applied by accounts-sync at boot); the gate makes it an admin for the test and takes it back.
accounts_sync() { R 'grep -q "^ciacct:x:61000:61000:" /etc/passwd && grep -q "^ciacct:[$]y[$]" /etc/shadow && grep -q ciacct@ci /data/home/ciacct/.ssh/authorized_keys && grep -q "account-added\|accounts-sync: ciacct" /tmp/boot-times'; }
yescrypt_login() { R 'sed -i "s/^patronus-admin:x:\([0-9]*\):\(.*\)$/patronus-admin:x:\1:\2,ciacct/; s/,,/,/; s/:,ciacct/:ciacct/" /etc/group' || return 1
  rm -f "$W/jar2"; c=$(curl -sk -c "$W/jar2" -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' \
    -d '{"username":"ciacct","password":"correct horse battery"}' https://127.0.0.1:$WEBP/api/auth/login); r1=$c
  c=$(curl -sk -o /dev/null -w '%{http_code}' -m 60 -H 'content-type: application/json' -d '{"username":"ciacct","password":"correct horse batterY"}' https://127.0.0.1:$WEBP/api/auth/login); r2=$c
  R 'sed -i "s/,ciacct\b//; s/:ciacct$/:/" /etc/group'
  [ "$r1" = 200 ] && [ "$r2" = 401 ] || { echo "yescrypt login: right password HTTP $r1 (want 200), wrong password HTTP $r2 (want 401)"; return 1; }; }
check "package-managed account (yescrypt hash, key, home) applied by accounts-sync at boot" accounts_sync
check "web login accepts a yescrypt password and refuses a wrong one" yescrypt_login
check "/dev (mdev): null, zero, random, urandom are 0666" dev_modes
check "clock: chronyd (the one NTP daemon) runs as user chrony, chronyc answers" ntp_client
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
check "features: role ap, Wi-Fi backend, \"not available\" list with reasons" features_ap
check "AP role: router-only pages explain the main router, their APIs refuse changes (409); Wi-Fi page served" ap_pages
check "Wi-Fi channel plan: automatic channel (ACS) by default on both radios, width/DFS/channel lists/survey rounds settable, bad values 400" wifi_chanplan
check "Wi-Fi page API: networks + radios written to the access-point file (0600), no key in GET, bad channel 400, admin reveal" wifi_set
check "Wi-Fi restart path: hostapd started into its own transient scope (systemd)" wifi_scope
check "backup includes the access-point Wi-Fi file; restoring the backup puts it back" wifi_backup
check "patronus ap-wifi: declarative export (no keys), plan shows only the edited setting, apply writes it" wifi_cli
check "Wi-Fi steering + misbehaving-station limits: defaults, live steering change in ap.env, bad values 400, ap-steer status runs" wifi_steer
check "Wi-Fi channel choice: defaults, live change in ap.env, bad values 400, ap-chan scores, channels + history in GET" wifi_chan
check "firmware page API: running build shown, a non-image upload refused by patronus-flash and not kept" fw_web
check "Wi-Fi page: crash protection (wifi-guard) and guest-filter availability reported" gap_state
check "guest network: GUEST_ flag written, nftables bridge filter loads with the guest ports, removed without guests" gap_guest
check "block list: unit-wide + per network via the API, written to the access-point file, unblock, bad MAC 400" gap_block
check "transmit power: per radio, applied live without a radio restart, out of range 400" gap_txpower
check "channel survey: read-only API answers and says why when no radio is up" gap_survey
check "client names: a DHCP client's host name on the bridge is recorded by the snoop (MAC, name)" gap_names
check "SSH keys: add/remove through the API (0600, audited), DSS refused, root's last key protected" gap_keys
check "LEDs: no LEDs in QEMU -> shown unavailable with the reason, change refused" gap_leds
check "scheduled restart: off by default, weekly enables the $INIT unit with that schedule, off disables it" gap_restart
check "address: an unconfirmed change reverts by itself, a confirmed one (from the new address) stays, back to DHCP" gap_address
check "online firmware check: a feed not signed by the release key is refused, nothing downloaded or staged" gap_feed
check "access log: env row cap holds under a 5000-request burst, every request accounted for, no raw path stored, page served, RSS recorded" gap_accesslog
check "Diagnostics on an access point: page served, ping/traceroute/routes through the web API" gap_diag
check "backup includes the system login accounts; a restore brings a lost login back" gap_accounts
scp -O -q "${SSHO[@]}" -P $SSHP "$TAR" root@127.0.0.1:/data/up.tar || fail "scp image into the guest"
refuse_board() { o=$(R 'patronus-flash check /data/up.tar' 2>&1) && { echo "accepted: $o"; return 1; }; case "$o" in *"image is for glinet,gl-ax1800"*) ;; *) echo "$o"; return 1;; esac; }
check "flash guard: refuses on a non-GL-AX1800 board" refuse_board
R "$FAKES"
check "flash check: the real image passes every guard (loop-mounted root, busybox)" R "$FENV patronus-flash check /data/up.tar"
# release signature on the real board firmware (gpgv + the keyring in the image, busybox): the CI image itself is release-signed;
# an UNSIGNED copy and a TAMPERED copy (root changed, patronus.sha256 re-made, the original signature kept: what an attacker
# without the key can do) must both be refused with the signature message, and nothing may be staged
mk_bad_images() {
  bd=$(mktemp -d); tar xf "$TAR" -C "$bd" 2>/dev/null; dd=$(ls -d "$bd"/sysupgrade-*); dn=$(basename "$dd")
  python3 - "$TAR" "$HERE/fwmeta.py" "$bd/meta.json" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("fwmeta", sys.argv[2]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
json.dump(m.read(open(sys.argv[1], "rb").read()), open(sys.argv[3], "w"))
PY
  remeta() { python3 - "$1" "$HERE/fwmeta.py" "$bd/meta.json" "$2" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("fwmeta", sys.argv[2]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
meta = json.load(open(sys.argv[3]))
if sys.argv[4] == "unsigned":
    meta.pop("patronus_sig", None)
data = open(sys.argv[1], "rb").read(); payload = b"\0" * 8 + (json.dumps(meta) + "\n").encode()
open(sys.argv[1], "ab").write(payload + m.trailer_for(data, payload))
PY
  }
  (cd "$bd" && tar cf "$bd/unsigned.tar" --sort=name "$dn") && remeta "$bd/unsigned.tar" unsigned
  printf 'tampered' >> "$dd/root"; (cd "$dd" && sha256sum kernel root > patronus.sha256)
  (cd "$bd" && tar cf "$bd/tampered.tar" --sort=name "$dn") && remeta "$bd/tampered.tar" keep
  grep -q patronus_sig "$bd/meta.json" || { echo "the CI image carries no release signature"; return 1; }
  scp -O -q "${SSHO[@]}" -P $SSHP "$bd/unsigned.tar" "$bd/tampered.tar" root@127.0.0.1:/data/ || return 1
  rm -rf "$bd"
}
check "release signature: the CI image is signed; unsigned + tampered copies built and copied in" mk_bad_images
refuse_sig() { o=$(R "$FENV patronus-flash sysupgrade /data/$1.tar" 2>&1) && { echo "ACCEPTED $1: $o"; return 1; }
  case "$o" in *"$2"*) ;; *) echo "$o"; return 1;; esac; R 'test ! -e /data/.upgrade && test ! -e /data/.upgrade.new' || { echo "something was staged"; return 1; }; }
check "flash guard: an UNSIGNED image is refused, nothing staged" refuse_sig unsigned "not signed"
check "flash guard: a TAMPERED image (root changed, sha256 re-made) is refused, nothing staged" refuse_sig tampered "signature check FAILED"
R 'rm -f /data/unsigned.tar /data/tampered.tar'
check "flash guard: a corrupt image is refused" R "cp /data/up.tar /tmp/bad.tar && printf 'XXXXXXXX' | dd of=/tmp/bad.tar bs=1 seek=3000000 conv=notrunc 2>/dev/null && ! $FENV patronus-flash check /tmp/bad.tar; rm -f /tmp/bad.tar"
# boot rollback (12.16): this VM has no GL bootloader environment, so an upgrade that cannot be rolled back is refused
# by default (GUARD_REQUIRE=1) and installed only with --no-rollback; the rollback itself is proven by rollback-gate.sh
refuse_norb() { o=$(R "$FENV patronus-flash sysupgrade /data/up.tar" 2>&1) && { echo "ACCEPTED: $o"; return 1; }
  case "$o" in *"no rollback possible"*) ;; *) echo "$o"; return 1;; esac; R 'test ! -e /data/.upgrade && test ! -e /data/.upgrade.new' || { echo "something was staged"; return 1; }; }
check "flash guard: no bootloader rollback possible here -> refused by default, nothing staged" refuse_norb
check "patronus-flash status --json reports the boot guard (no bootloader script)" R 'o=$(patronus-flash status --json); case "$o" in *"\"installed\":false"*) ;; *) echo "$o"; exit 1;; esac'
check "flash sysupgrade --no-rollback: stages the image" R "$FENV patronus-flash sysupgrade /data/up.tar --no-rollback && test -f /data/.upgrade/ready && test -f /data/.upgrade/no-rollback"
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
check "boot 2: Wi-Fi settings from the web UI persisted" wifi_persisted
check "boot 2: transmit power and block list persisted, no address trial pending, address from DHCP" R 'grep -q "^AP_TXPOWER5=17" /etc/patronus/ap.env && grep -q " DENY_cigateio=" /etc/patronus/ap.env && ! test -e /etc/patronus/ap.env.addr-pending && ip -4 -o addr show dev br-lan | grep 10.0.2.15/24 >/dev/null'
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
sleep 60   # idle: let the boot's apply/ETPhoneHome settle before reading memory
if [ -n "${GATE_HOLD:-}" ]; then echo "HOLD: unit up for ${GATE_HOLD}s (web on $BIND:$WEBP, user cigate)" | tee -a "$RES/results.txt"; touch "$RES/holding"
  t=0; while [ $t -lt "$GATE_HOLD" ] && [ ! -e "$RES/release" ]; do sleep 5; t=$((t + 5)); done; rm -f "$RES/holding"; fi
R 'free -k; cat /tmp/boot-times; ps -o rss,comm | sort -n | tail -8; df -k /data; for p in $(pidof patronus-web patronus-cli chronyd syslogd); do echo "rss $(sed -n "s/^Name:[[:space:]]*//p" /proc/$p/status) $(sed -n "s/^VmRSS:[[:space:]]*//p" /proc/$p/status)"; done' > "$RES/boot2-stats.txt" 2>&1
{ echo "init=$INIT accel=$ACCEL"; grep -E '^Mem:' "$RES/boot2-stats.txt"; grep -E 'exec-|patronus-started|network-up|^rss ' "$RES/boot2-stats.txt"; } >> "$RES/summary.txt"
poweroff_vm
cat "$RES/summary.txt"
if [ ${#fails[@]} = 0 ]; then echo "FAILED: none" | tee -a "$RES/results.txt"; exit 0; fi
echo "FAILED: ${fails[*]}" | tee -a "$RES/results.txt"; exit 1
