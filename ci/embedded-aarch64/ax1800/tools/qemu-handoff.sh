#!/bin/bash
# qemu-handoff.sh <image-dir> (builder container, after ci-build.sh): boot the CI image (openrc) in QEMU, stage its own signed sysupgrade, run handoff.sh arm,
# and show that PID 1 reaches upgrade-install install -> RAM root -> stage2 (which then refuses: QEMU has no UBI),
# and the box restarts. Then boot again: the old system comes up with its settings.
set -uo pipefail
HX=/w/src/ci/embedded-aarch64/ax1800
I=$(readlink -f "$1"); K=/out/stock/virt-kernel.bin; KEY=/out/unit/ci_ed25519; RES=/out/handoff; mkdir -p $RES
W=$(mktemp -d /tmp/ho.XXXX); SQ=$I/root.squashfs; TAR=$(ls $I/patronus-*-sysupgrade.tar)
unsquashfs -q -d $W/r $SQ >/dev/null; KV=$(ls $W/r/lib/modules); rm -rf $W/r/lib/modules/$KV $W/r/etc/modules.d; mkdir -p $W/r/etc/modules.d
sh $HX/fetch-kmods.sh virt $W/r /cache/kmods >/dev/null || exit 1; depmod -b $W/r $KV 2>/dev/null; : > $W/r/etc/patronus/qemu-kmods
mksquashfs $W/r $W/root.img -comp xz -b 256K -noappend -no-xattrs -all-root -quiet >/dev/null; rm -rf $W/r
truncate -s 256M $W/data.img; mkfs.ext4 -q -F -L patronus_data $W/data.img
SSHO=(-i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
R() { ssh "${SSHO[@]}" -p 2422 root@127.0.0.1 "$@"; }
boot() {
  qemu-system-aarch64 -M virt -accel tcg -cpu cortex-a53 -smp 2 -m 512 -kernel $K \
    -append "root=/dev/vda rootfstype=squashfs ro console=ttyAMA0 patronus.data=/dev/vdb panic=-1" \
    -drive file=$W/root.img,if=virtio,format=raw,readonly=on -drive file=$W/data.img,if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2422-:22 -device virtio-net-pci,netdev=n0 \
    -display none -monitor none -serial file:$RES/serial-$1.txt -no-reboot &
  QP=$!; t0=$(date +%s)
  until R true 2>/dev/null; do kill -0 $QP 2>/dev/null || { echo "QEMU exited"; return 1; }; [ $(( $(date +%s) - t0 )) -gt 1200 ] && return 1; sleep 10; done
  echo "boot $1 up after $(( $(date +%s) - t0 ))s"; }
boot 1 || exit 1
R 'mkdir -p /tmp/fk && printf "glinet,gl-ax1800\0qcom,ipq6018\0" > /tmp/fk/compat && cat > /tmp/fk/ubinfo <<"EOF"
#!/bin/sh
case "${2:-}" in
  -N) case "$3" in kernel) echo "Volume ID:   0 (on ubi0)"; echo "Size:  42 LEBs (5332992 bytes)";; rootfs) echo "Volume ID:   1 (on ubi0)"; echo "Size:  250 LEBs (31744000 bytes)";; *) exit 1;; esac;;
  *) echo "Amount of available logical eraseblocks: 264 (33521664 bytes)";;
esac
EOF
chmod +x /tmp/fk/ubinfo; echo marker-$$ > /etc/patronus/ho-marker; sync'
FENV='PATRONUS_DT_COMPAT=/tmp/fk/compat FW_UBINFO=/tmp/fk/ubinfo'
scp -O -q "${SSHO[@]}" -P 2422 $TAR /w/src/ci/embedded-aarch64/ax1800/tools/handoff-install.sh root@127.0.0.1:/data/ || exit 1
R "$FENV patronus-flash sysupgrade /data/$(basename $TAR) 2>&1 | tail -2; rm -f /data/$(basename $TAR); ls /data/.upgrade"
R "cp /data/handoff-install.sh /tmp/handoff-install.sh; $FENV sh /tmp/handoff-install.sh arm" ; echo "arm rc=$?"
t0=$(date +%s); while kill -0 $QP 2>/dev/null; do [ $(( $(date +%s) - t0 )) -gt 900 ] && { echo "QEMU still running after 900s"; kill $QP; break; }; sleep 5; done
echo "QEMU exited after $(( $(date +%s) - t0 ))s (restart with -no-reboot)"
grep -a -E "handoff:|upgrade:" $RES/serial-1.txt | tail -20
boot 2 || exit 1
R 'cat /etc/patronus/ho-marker; tail -12 /data/upgrade.log; ls -d /data/.upgrade*; readlink /proc/1/exe; rc-status default 2>/dev/null | grep -c started'
R sync; kill $QP; wait $QP 2>/dev/null; rm -rf $W
echo HANDOFF-DONE
