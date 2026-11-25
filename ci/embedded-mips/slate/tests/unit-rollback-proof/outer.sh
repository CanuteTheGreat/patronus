#!/bin/sh
# outer.sh: run on the Slate (running root = hx). Sets up a THROWAWAY UBI (ubi1 on mtdram), mounts the staged NEW root
# (ubi0 volume rootfs_new) read-only through ubiblock, chroots into it and runs proof.sh with the new image's own tools.
# Never changes ubi0 (only reads rootfs_new). Everything is undone at the end.  usage: outer.sh  (output: /tmp/pt/proof.out)
P=/tmp/pt; cd $P || exit 2
exec > $P/proof.out 2>&1
set -u
vidof() { for d in /sys/class/ubi/$1_*; do [ "$(cat $d/name 2>/dev/null)" = "$2" ] && { echo "${d##*_}"; return 0; }; done; }
mkn() { [ -c "$1" ] || [ -b "$1" ] || { m=$(cat "$2"); mknod "$1" "$3" "${m%:*}" "${m#*:}"; }; }
cleanup() {
  for m in $P/nr/mnt $P/nr/tmp/pt $P/nr/tmp $P/nr/sys $P/nr/proc $P/nr/dev $P/nr; do umount "$m" 2>/dev/null; done
  [ -n "${NV:-}" ] && ./ubiblock.mips --remove /dev/ubi0_$NV 2>/dev/null
  ubidetach -d 1 2>/dev/null; rmmod mtdram 2>/dev/null
  rm -f /dev/ubi1 /dev/ubi1_* 2>/dev/null
  echo "== cleanup: $(grep -c mtdram /proc/modules) mtdram module(s), ubi1 $( [ -e /sys/class/ubi/ubi1 ] && echo present || echo gone), ubiblock $(ls /sys/block | grep -c ubiblock0_${NV:-x})"
}
trap cleanup EXIT
chmod 755 ubiblock.mips proof.sh
echo "== running root: $(grep ^BUILD= /etc/patronus-release)"
NV=$(vidof ubi0 rootfs_new); [ -n "$NV" ] || { echo "no rootfs_new on ubi0"; exit 2; }
mkn /dev/ubi0_$NV /sys/class/ubi/ubi0_$NV/dev c
./ubiblock.mips --create /dev/ubi0_$NV || { echo "ubiblock create failed"; exit 2; }
mkn /dev/ubiblock0_$NV /sys/block/ubiblock0_$NV/dev b
mkdir -p $P/nr; mount -t squashfs -o ro /dev/ubiblock0_$NV $P/nr || { echo "mount new root failed"; exit 2; }
echo "== staged new root: $(grep ^BUILD= $P/nr/etc/patronus-release)"
insmod ./mtdram.ko total_size=8192 erase_size=128 || { echo "insmod mtdram failed"; exit 2; }
M=$(grep '"mtdram test device"' /proc/mtd | cut -d: -f1); [ -n "$M" ] || { echo "no mtdram mtd"; exit 2; }
ubiattach -m ${M#mtd} -d 1 /dev/ubi_ctrl || { echo "ubiattach failed"; exit 2; }
mkn /dev/ubi1 /sys/class/ubi/ubi1/dev c
echo "== test UBI: $M -> ubi1, $(cat /sys/class/ubi/ubi1/avail_eraseblocks) free LEBs of $(cat /sys/class/ubi/ubi1/eraseblock_size) B"
mount --bind /dev $P/nr/dev; mount -t proc proc $P/nr/proc; mount --bind /sys $P/nr/sys; mount -t tmpfs -o size=4m tmpfs $P/nr/tmp
mkdir -p $P/nr/tmp/pt; for f in A.sq B.sq OWRT.sq cfg.tgz proof.sh; do cp $P/$f $P/nr/tmp/pt/; done
PATH=/usr/sbin:/usr/bin:/sbin:/bin chroot $P/nr /bin/sh /tmp/pt/proof.sh
echo "== proof exit $?"
