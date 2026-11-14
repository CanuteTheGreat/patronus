#!/bin/bash
# inside the gentoo container with /rootfs populated: add init, config, strip, make squashfs, measure sizes
set -uo pipefail
T=mips-unknown-linux-musl; SYS=/usr/$T
exec > >(tee -a /out/assemble.log) 2>&1
R=/rootfs
cd $R
echo "== libc present in ROOT?"; ls $R/lib/ld-musl* $R/usr/lib/libc.so 2>&1 | head
[ -e $R/lib/ld-musl-mips-sf.so.1 ] || { echo "-> copying musl from sysroot (crossdev installs it there)"; mkdir -p $R/lib; cp -a $SYS/usr/lib/libc.so $R/lib/ld-musl-mips-sf.so.1 2>/dev/null || cp -a $SYS/lib/ld-musl-mips-sf.so.1 $R/lib/; }
mkdir -p proc sys dev tmp run var/log var/run etc/init.d etc/patronus overlay mnt root lib/modules
# libs that rust binary + nft need
for l in libmnl libnftnl; do cp -a $SYS/usr/lib/$l.so* $R/usr/lib/ 2>/dev/null; done
# strip everything
find $R -type f \( -perm -u+x -o -name '*.so*' \) -exec $T-strip --strip-unneeded {} + 2>/dev/null
rm -rf $R/usr/share/{doc,man,info,locale,gtk-doc} $R/usr/include $R/usr/lib/pkgconfig $R/usr/lib/*.a $R/var/db $R/var/cache $R/var/lib/portage $R/usr/share/portage 2>/dev/null
# busybox applet links
if [ -x $R/bin/busybox ]; then (cd $R && for a in $(chroot . /bin/busybox --list 2>/dev/null || true); do :; done); fi
BB=bin/busybox; [ -x $R/$BB ] || BB=$(cd $R && ls bin/busybox* usr/bin/busybox* 2>/dev/null | head -1)
echo "busybox at: $BB"
for a in sh ash cat ls mount umount mkdir echo sleep ps free grep awk sed cut head tail cp rm mv ln chmod chown dmesg ip ifconfig route ping nc wget udhcpc udhcpd uname hostname poweroff reboot halt init mdev modprobe insmod lsmod sync df du sysctl poweroff tee date seq kill killall top printf test true false wc sort xz tar zcat gunzip stat readlink basename dirname id tr nproc usleep; do
  for d in bin sbin usr/bin usr/sbin; do [ -e $R/$d/$a ] && continue 2; done
  ln -sf /$BB $R/bin/$a
done
ln -sf /$BB $R/sbin/init 2>/dev/null
cat > $R/etc/inittab <<'EOF'
::sysinit:/etc/init.d/rcS
ttyS0::respawn:/bin/sh -l
::ctrlaltdel:/bin/poweroff
::shutdown:/bin/umount -a -r
EOF
cat > $R/etc/init.d/rcS <<'EOF'
#!/bin/sh
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs -o size=8m tmpfs /tmp; mount -t tmpfs -o size=4m tmpfs /run; mkdir -p /run /var/log
# writable overlay: lower=squashfs (/), upper=tmpfs here (UBIFS on the slate)
mount -t tmpfs -o size=8m tmpfs /overlay 2>/dev/null
echo 1 > /proc/sys/net/ipv4/ip_forward
ip link set lo up; ip addr add 10.0.2.15/24 dev eth0 2>/dev/null; ip link set eth0 up
EOF
chmod +x $R/etc/init.d/rcS
echo "== rootfs tree size (uncompressed, stripped)"; du -sh $R; du -s $R/* 2>/dev/null | sort -rn | head -12
which mksquashfs >/dev/null || emerge -q sys-fs/squashfs-tools >/dev/null 2>&1
mksquashfs $R /out/rootfs-base.squashfs -comp xz -b 256K -noappend -no-xattrs -quiet
ls -l /out/rootfs-base.squashfs
echo "== binaries"; for f in $R/bin/busybox $R/usr/sbin/nft $R/usr/sbin/dnsmasq $R/usr/bin/nft $R/usr/sbin/hostapd $R/usr/sbin/wpa_supplicant $R/usr/bin/wg $R/sbin/ip $R/lib/ld-musl-mips-sf.so.1; do [ -e $f ] && ls -l $f | awk '{print $5, $9}'; done
