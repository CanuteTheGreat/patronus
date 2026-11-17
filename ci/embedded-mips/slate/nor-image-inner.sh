#!/bin/bash
# INSIDE a gentoo/stage3 arm64 container (build-nor-image.sh): builds everything the NOR-budget CI image needs.
# /w = this directory (scripts), /out = scratch with stage markers (not part of the image). Result lives in the container
# filesystem: crossdev mips-unknown-linux-musl, /rootfs (router rootfs), /rootfs-openrc, rust nightly, /opt/pembed.
set -uo pipefail
cd /w
T=mips-unknown-linux-musl; SYS=/usr/$T; P=/opt/pembed
. /w/stock.env
bash /w/stage-all.sh || exit 1
for m in crossdev rootfs openssl rust; do [ -f /out/stage-$m.ok ] || { echo "stage $m failed"; exit 1; }; done
# stage-all's `--keep-going` emerge silently drops wpa_supplicant, dropbear and mtd-utils on some days (the image once came out
# without them and a Slate flashed from it had no ssh and no uplink): build them explicitly and refuse an image that lacks them
bash /w/cbuild.sh || exit 1
ROOT=/rootfs $T-emerge --root-deps=rdeps -q sys-fs/mtd-utils || exit 1
for f in /rootfs/usr/sbin/wpa_supplicant /rootfs/usr/sbin/dropbearmulti /rootfs/usr/sbin/hostapd /rootfs/usr/sbin/dnsmasq /rootfs/usr/sbin/ubinfo /rootfs/usr/sbin/ubirename /rootfs/sbin/nft /rootfs/bin/busybox; do
  [ -x "$f" ] || { echo "builder image: $f missing"; exit 1; }; done
bash /w/stage-openrc.sh || exit 1
[ -f /out/stage-openrc.ok ] || { echo "stage openrc failed"; exit 1; }
# libucontext (systemd on musl/mips): distfile via portage, built by hand for mips
echo 'sys-libs/libucontext *' >> $SYS/etc/portage/package.accept_keywords/e
mkdir -p /var/cache/distfiles; [ -e /var/cache/distfiles/libucontext-1.5.1.tar.xz ] || curl -fsSL -o /var/cache/distfiles/libucontext-1.5.1.tar.xz https://distfiles.ariadne.space/libucontext/libucontext-1.5.1.tar.xz || exit 1
bash /w/ucx.sh && bash /w/ucx2.sh || exit 1
bash /w/stage-systemd.sh || exit 1
[ -f /out/stage-systemd.ok ] || { echo "stage systemd failed"; exit 1; }
bash /w/ucx2.sh   # stage-systemd's libucontext emerge must not leave a different lib behind
mkdir -p $P
cp -L $SYS/usr/lib/libucontext.so.1 $P/
S=/tmp/sdstrip; rm -rf $S; cp -a /out/systemd-root $S
find $S -type f -exec sh -c 'file "$1" | grep ELF >/dev/null && '$T'-strip --strip-unneeded "$1"' _ {} \; 2>/dev/null
tar cf $P/systemd-strip.tar -C $S .; rm -rf $S
# the stock OpenWrt sysupgrade image whose kernel the NOR budget measures (sha256 from the device profile)
curl -fsSL -o $P/$STOCK_NAME "$STOCK_URL" || exit 1
echo "$STOCK_SHA256  $P/$STOCK_NAME" | sha256sum -c - || exit 1
# what nor-ci.sh needs at job time: patronus' own host deps already present (nftnl for host build-deps)
emerge -q --noreplace net-libs/libmnl net-libs/libnftnl 2>&1 | tail -3
command -v git mksquashfs unsquashfs python3 >/dev/null || { echo "missing git/squashfs-tools/python3"; exit 1; }
rm -rf /var/cache/distfiles/* /tmp/* /var/tmp/portage 2>/dev/null
touch /out/IMAGE-READY; echo IMAGE-READY
