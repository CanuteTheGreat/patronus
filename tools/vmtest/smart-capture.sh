#!/bin/bash
# Capture real `smartctl --json` output from QEMU-emulated disks (IDE/AHCI, NVMe, virtio-blk).
# Runs inside `agent-workdir run`: $AGENT_WORKDIR is the scratch dir.
set -eu
cd "$AGENT_WORKDIR"
mkdir -p out root
cat > build-root.sh <<'EOS'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends smartmontools linux-image-amd64 kmod busybox-static cpio xz-utils >/dev/null
KVER=$(ls /lib/modules | head -1)
R=/root-out
mkdir -p $R/bin $R/sbin $R/usr/sbin $R/proc $R/sys $R/dev $R/lib/modules/$KVER $R/etc $R/lib64 $R/tmp $R/usr/share
cp /bin/busybox $R/bin/busybox
for a in sh mount umount mkdir sleep cat echo ls insmod poweroff dmesg; do ln -sf busybox $R/bin/$a; done
copyl() { for f in "$@"; do mkdir -p "$R$(dirname "$f")"; cp -L "$f" "$R$f"; done; }
copyl /usr/sbin/smartctl /sbin/modprobe /usr/bin/kmod 2>/dev/null || true
cp -L /sbin/modprobe $R/sbin/modprobe 2>/dev/null || ln -sf /usr/bin/kmod $R/sbin/modprobe
for b in /usr/sbin/smartctl /usr/bin/kmod; do
  ldd $b | awk '/=> \//{print $3} /^\t\//{print $1}' | sort -u | while read l; do copyl "$l"; done
done
ln -sf /usr/bin/kmod $R/sbin/modprobe
# modules: only what the guest needs (+ deps)
for m in ahci libahci libata ata_piix ata_generic sd_mod scsi_mod nvme nvme_core virtio_blk virtio_pci virtio_ring virtio virtio_scsi sr_mod; do
  modprobe -S $KVER --show-depends $m 2>/dev/null | awk '/^insmod/{print $2}'
done | sort -u | while read ko; do copyl "$ko"; done
cp /lib/modules/$KVER/modules.* $R/lib/modules/$KVER/ 2>/dev/null || true
cp /boot/vmlinuz-$KVER /out/vmlinuz
cat > $R/init <<'EOI'
#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
for m in virtio_pci virtio_blk virtio_scsi ahci ata_piix ata_generic sd_mod nvme; do modprobe $m 2>/dev/null; done
sleep 4
echo "=== LS"; ls /dev | tr '\n' ' '; echo
S=/usr/sbin/smartctl
run() { n=$1; shift; echo "=== BEGIN $n"; "$@"; echo "=== EXIT $?"; echo "=== END $n"; }
run version $S --version
run scan $S --scan --json
for d in /dev/sda /dev/nvme0n1 /dev/nvme0 /dev/vda; do
  b=$(echo $d | tr / _)
  [ -e $d ] || continue
  run "info$b" $S -a --json $d
  run "health$b" $S -H --json $d
done
# self-test on the ATA disk: start, wait, read the log
run test_start_short $S -t short --json /dev/sda
sleep 6
run "info_after_test_sda" $S -a --json /dev/sda
run test_start_long $S -t long --json /dev/sda
run test_start_bad $S -t short --json /dev/vda
run test_start_nvme $S -t short --json /dev/nvme0
sleep 4
run "info_after_test_nvme" $S -a --json /dev/nvme0
echo "=== DONE"
poweroff -f
EOI
chmod +x $R/init
cd $R && find . | cpio -o -H newc 2>/dev/null | xz --check=crc32 -9 > /out/initrd.xz
ls -la /out
EOS
docker run --rm --memory=4g --memory-swap=4g --cpus=2 -v "$PWD/out:/out" -v "$PWD/build-root.sh:/b.sh:ro" -v "$PWD/root:/root-out" debian:bookworm bash /b.sh
for f in a.img n.img v.img; do truncate -s 256M $f; done
timeout 280 qemu-system-x86_64 -machine q35,accel=kvm:tcg -cpu max -m 1024 -smp 2 -nographic -no-reboot \
  -kernel out/vmlinuz -initrd out/initrd.xz -append "console=ttyS0 rdinit=/init quiet" \
  -drive file=a.img,if=none,id=d0,format=raw -device ide-hd,drive=d0,bus=ide.0,serial=VMTESTATA0001,model=QEMU\ HARDDISK \
  -drive file=n.img,if=none,id=d1,format=raw -device nvme,drive=d1,serial=VMTESTNVME01 \
  -drive file=v.img,if=virtio,format=raw \
  > serial.log 2>&1 || true
cp serial.log /var/tmp/smart-capture-serial.log
echo captured: $(wc -c < serial.log) bytes
