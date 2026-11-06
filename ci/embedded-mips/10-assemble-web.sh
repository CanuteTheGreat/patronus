#!/bin/bash
# in the gentoo cross container (pembed-g4): take the proven CLI rootfs, add patronus-web (+init glue), build squashfs, print sizes
# usage: 10-assemble-web.sh <web-binary> <out-squashfs> [extra-file-dir]
set -eu
WEB=$1; OUT=$2; EXTRA=${3:-}
T=mips-unknown-linux-musl
rm -rf /tmp/rf; unsquashfs -q -d /tmp/rf /out/rootfs-patronus.squashfs
R=/tmp/rf
mkdir -p $R/var/lib/patronus $R/var/lib/misc $R/data $R/etc/patronus/tls
install -m755 $WEB $R/usr/bin/patronus-web
[ -n "${CLI:-}" ] && install -m755 $CLI $R/usr/bin/patronus-cli
# rust's 64-bit atomics on mips32 come from libatomic (dynamic)
LA=$($T-gcc -print-file-name=libatomic.so.1); cp -L "$LA" $R/usr/lib/libatomic.so.1; $T-strip --strip-unneeded $R/usr/lib/libatomic.so.1
grep -q '^nobody:' $R/etc/passwd || echo 'nobody:x:65534:65534:nobody:/:/bin/false' >> $R/etc/passwd
grep -q '^nobody:' $R/etc/group || echo 'nobody:x:65534:' >> $R/etc/group
grep -q '^patronus:' $R/etc/group || echo 'patronus:x:900:' >> $R/etc/group
[ -n "$EXTRA" ] && cp -a $EXTRA/. $R/
cat > $R/etc/init.d/rcS <<'EOF'
#!/bin/sh
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs -o size=8m tmpfs /tmp; mount -t tmpfs -o size=4m tmpfs /run; mount -t tmpfs -o size=4m tmpfs /var/log; mkdir -p /run /var/log /var/lib/patronus /etc/patronus
# persistent partition (UBIFS overlay on the slate; ext4 on a virtio disk here)
mkdir -p /data; for d in /dev/sda /dev/vdb; do mount -t ext4 $d /data 2>/dev/null && break; done; mountpoint -q /data || echo "NO DATA PARTITION"
# /etc is an overlay (squashfs lower, persistent upper) exactly like OpenWrt's overlayfs: config files written by appliers persist
mkdir -p /data/tls
for d in etc var/lib; do n=$(echo $d | tr / -); mkdir -p /data/overlay/$n /data/overlay/.work-$n
  mount -t overlay overlay -o lowerdir=/$d,upperdir=/data/overlay/$n,workdir=/data/overlay/.work-$n /$d || echo "NO OVERLAY $d"; done
mkdir -p /var/lib/patronus /var/lib/misc

ip link set lo up
echo 1 > /proc/sys/net/ipv4/ip_forward
[ -x /etc/init.d/patronus ] && /etc/init.d/patronus start
EOF
chmod +x $R/etc/init.d/rcS
if [ ! -x $R/etc/init.d/patronus ]; then
cat > $R/etc/init.d/patronus <<'EOF'
#!/bin/sh
export PATRONUS_DB=/var/lib/patronus/config.db PATRONUS_TLS_DIR=/data/tls PATH=$PATH:/usr/sbin:/sbin
export PATRONUS_HTTPS_PORT=443 PATRONUS_HTTP_REDIRECT_PORT=80 PATRONUS_ADMIN_PASSWORD=${PATRONUS_ADMIN_PASSWORD:-Qemu-Test-Passw0rd}
patronus-cli apply > /tmp/apply.log 2>&1
patronus-cli applyd > /var/log/applyd.log 2>&1 &
sleep 2
patronus-web > /var/log/web.log 2>&1 &
EOF
chmod +x $R/etc/init.d/patronus
fi
find $R/usr/bin/patronus-web -exec $T-strip --strip-unneeded {} + 2>/dev/null || true
mksquashfs $R $OUT -comp xz -b 256K -noappend -no-xattrs -quiet
ls -l $OUT
