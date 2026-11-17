#!/bin/bash
# INSIDE the builder image: the userland of both variants from Alpine 3.24 packages (musl, aarch64: no cross compiling),
# installed into /out/rootfs with `apk --root` (no scripts, no package database kept). OpenRC is built from source by
# stage-openrc.sh (Alpine's package has no openrc-init/openrc-shutdown).
# The kernel, its modules and the IPQ6018 firmware are NOT from Alpine: assemble.sh takes them from OpenWrt 25.12.6.
# Marker /out/stage-rootfs.ok. Package choice (docs/embedded-routers.md, GL-AX1800): a wired AP needs hostapd + iw + the
# iproute2 `ip` + a DHCP client (busybox udhcpc) + dropbear + the UBI tools; PAM for the web login; libmnl/libnftnl for
# patronus-cli's nftables backend; wireless-regdb for the regulatory database; libucontext for systemd (musl) and libmount, which systemd dlopen()s to mount
# the API filesystems (without it PID 1 freezes: "Failed to mangle mount options ... Not supported").
# WireGuard VPN (feature vpn-wireguard): `wg` (wireguard-tools-wg, the applier runs `wg syncconf`; the kernel module is a pinned
# OpenWrt kmod, kmods.pin). Clock and NTP server: chrony (non-NTS build, no GnuTLS), the one NTP daemon of the image: it keeps
# the clock and, with the NTP server page (feature ntp-server), serves the LAN.
set -euo pipefail
R=/out/rootfs; rm -rf $R; mkdir -p $R
COMMON="alpine-baselayout-data busybox busybox-binsh musl libgcc libcap2 linux-pam libmnl libnftnl ca-certificates-bundle \
  hostapd iw iproute2-minimal dropbear dropbear-scp mtd-utils-ubi nftables wireless-regdb libnl3 libssl3 libcrypto3 zlib libucontext libmount \
  wireguard-tools-wg chrony"
APK="apk --initdb --no-scripts --no-cache --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories"
$APK --root $R add $COMMON
rm -rf $R/lib/apk $R/var/cache/apk $R/etc/apk
# Alpine puts the loader in /lib: keep, plus the name the aarch64 musl ELF interpreter expects
[ -e $R/lib/ld-musl-aarch64.so.1 ] || ln -sf ../usr/lib/libc.musl-aarch64.so.1 $R/lib/ld-musl-aarch64.so.1
ls -l $R/usr/sbin/hostapd $R/usr/bin/wg $R/usr/sbin/chronyd $R/usr/sbin/dropbear $R/usr/sbin/ubinfo $R/bin/busybox $R/sbin/ip | sed 's/^/  /'
du -sh $R
[ -x $R/usr/sbin/hostapd ] && touch /out/stage-rootfs.ok
