#!/bin/bash
# in pembed-q: boot squashfs rootfs on QEMU malta BE, run measurement commands over serial
IMG=${1:-/out/rootfs-base.squashfs}
( sleep 25; cat /out/cmds.txt; sleep 20 ) | timeout 150 qemu-system-mips -M malta -cpu 24Kc -m ${MEM:-128} -kernel /out/vmlinux-malta-be -drive file=$IMG,format=raw,if=virtio,readonly=on -append "root=/dev/vda rootfstype=squashfs ro console=ttyS0 init=/sbin/init" -nographic -nic user -no-reboot > /out/boot.log 2>&1
echo qemu rc=$?
