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
QP=; W=$(mktemp -d "${TMPDIR:-/tmp}/ax-qemu.XXXX"); trap 'kill $QP 2>/dev/null; rm -rf "$W"' EXIT
# test copy of the root: the board's kmods replaced by the same pinned netfilter packages built for the virt kernel
# (kmods.pin "virt"), so the firewall applies for real; everything else is the shipped image byte for byte
unsquashfs -q -d "$W/r" "$SQ" >/dev/null || { echo "unsquashfs failed"; exit 1; }
KV=$(ls "$W/r/lib/modules"); rm -rf "$W/r/lib/modules/$KV" "$W/r/etc/modules.d"; mkdir -p "$W/r/etc/modules.d"
sh "$(dirname "$0")/fetch-kmods.sh" virt "$W/r" "${KMOD_CACHE:-/cache/kmods}" || exit 1
depmod -b "$W/r" "$KV"; : > "$W/r/etc/patronus/qemu-kmods"
mksquashfs "$W/r" "$W/root.img" -comp xz -b 256K -noappend -no-xattrs -all-root -quiet >/dev/null; rm -rf "$W/r"
truncate -s 256M "$W/data.img"; mkfs.ext4 -q -F -L patronus_data "$W/data.img"
SSHP=2222; WEBP=8443; QP=
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
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSHP-:22,hostfwd=tcp:127.0.0.1:$WEBP-:443 -device virtio-net-pci,netdev=n0 \
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

SERVICES_OPENRC="patronus-syslogd patronus-klogd patronus-board patronus-etph dropbear patronus-ntpd patronus-apply patronus-applyd patronus-web"
SERVICES_SYSTEMD="patronus-syslogd patronus-klogd patronus-network patronus-etph patronus-dropbear patronus-ntpd patronus-apply patronus-applyd patronus-web"
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
scp -O -q "${SSHO[@]}" -P $SSHP "$TAR" root@127.0.0.1:/data/up.tar || fail "scp image into the guest"
refuse_board() { o=$(R 'patronus-flash check /data/up.tar' 2>&1) && { echo "accepted: $o"; return 1; }; case "$o" in *"image is for glinet,gl-ax1800"*) ;; *) echo "$o"; return 1;; esac; }
check "flash guard: refuses on a non-GL-AX1800 board" refuse_board
R "$FAKES"
check "flash check: the real image passes every guard (loop-mounted root, busybox)" R "$FENV patronus-flash check /data/up.tar"
check "flash guard: a corrupt image is refused" R "cp /data/up.tar /tmp/bad.tar && printf 'XXXXXXXX' | dd of=/tmp/bad.tar bs=1 seek=3000000 conv=notrunc 2>/dev/null && ! $FENV patronus-flash check /tmp/bad.tar; rm -f /tmp/bad.tar"
check "flash sysupgrade: stages the image" R "$FENV patronus-flash sysupgrade /data/up.tar && test -f /data/.upgrade/ready"
check "upgrade-install verify accepts it (with the board's identity)" R "$FENV /usr/libexec/patronus/upgrade-install verify"
check "persistence marker written (/etc overlay, /root)" R 'echo ci-$$ > /etc/patronus/ci-marker && echo ok > /root/ci-marker && rm -f /data/up.tar && sync'
R 'free -k; cat /tmp/boot-times; ps -o rss,comm | sort -n | tail -8' > "$RES/boot1-stats.txt" 2>&1
poweroff_vm
boot 2 || { echo "FAILED: ${fails[*]}"; exit 1; }
check "boot 2: the staged upgrade was rejected at boot (wrong board) and the box came up" R 'test -d /data/.upgrade-rejected && ! test -e /data/.upgrade && grep -q upgrade-rejected /tmp/boot-times'
check "boot 2: settings persisted (/etc overlay, /root)" R 'test -s /etc/patronus/ci-marker && test -s /root/ci-marker'
check "boot 2: PID 1 is $INIT" pid1
check "boot 2: all services up" services_up
check "boot 2: ETPhoneHome running" etph
check "boot 2: web UI answers" web
R 'free -k; cat /tmp/boot-times; ps -o rss,comm | sort -n | tail -8; df -k /data' > "$RES/boot2-stats.txt" 2>&1
{ echo "init=$INIT accel=$ACCEL"; grep -E '^Mem:' "$RES/boot2-stats.txt"; grep -E 'exec-|patronus-started|network-up' "$RES/boot2-stats.txt"; } >> "$RES/summary.txt"
poweroff_vm
cat "$RES/summary.txt"
if [ ${#fails[@]} = 0 ]; then echo "FAILED: none" | tee -a "$RES/results.txt"; exit 0; fi
echo "FAILED: ${fails[*]}" | tee -a "$RES/results.txt"; exit 1
