#!/bin/bash
# INSIDE the builder image: the userland of both variants from Alpine 3.24 packages (musl, aarch64: no cross compiling),
# installed into /out/rootfs with `apk --root` (no scripts, no package database kept). OpenRC is built from source by
# stage-openrc.sh (Alpine's package has no openrc-init/openrc-shutdown).
# The kernel, its modules and the IPQ6018 firmware are NOT from Alpine: assemble.sh takes them from OpenWrt 25.12.6.
# Marker /out/stage-rootfs.ok. Package choice (docs/embedded-routers.md, GL-AX1800): a wired AP needs hostapd + iw + the
# iproute2 `ip` + a DHCP client (busybox udhcpc) + dropbear + the UBI tools; PAM for the web login; libmnl/libnftnl for
# patronus-cli's nftables backend; wireless-regdb for the regulatory database; libucontext for systemd (musl) and libmount, which systemd dlopen()s to mount
# the API filesystems (without it PID 1 freezes: "Failed to mangle mount options ... Not supported"); fw_printenv/fw_setenv (u-boot-tools) keep
# the bootloader's rollback script and trial counters (patronus-guard); gpgv checks the release
# signature of every upgrade image before patronus-flash stages it (fwcheck.sh).
# WireGuard VPN (feature vpn-wireguard): `wg` (wireguard-tools-wg, the applier runs `wg syncconf`; the kernel module is a pinned
# OpenWrt kmod, kmods.pin). Clock and NTP server: chrony (non-NTS build, no GnuTLS), the one NTP daemon of the image: it keeps
# the clock and, with the NTP server page (feature ntp-server), serves the LAN.
# Online firmware check (web UI): gpgv verifies the update feed's release signature, ssl_client gives busybox wget https.
# hostapd is NOT Alpine's package: stage-hostapd.sh builds hostapd/APKBUILD (Alpine's 2.11 + patronus-xbss.diff, the
# synchronous cross-BSS station removal the IPQ6018 firmware needs, docs 12.6d) and it is installed from that local file.
set -euo pipefail
R=/out/rootfs; rm -rf $R; mkdir -p $R
COMMON="alpine-baselayout-data busybox busybox-binsh musl libgcc libcap2 linux-pam libmnl libnftnl ca-certificates-bundle \
  iw iproute2-minimal dropbear dropbear-scp mtd-utils-ubi nftables wireless-regdb libnl3 libssl3 libcrypto3 zlib libucontext libmount \
  wireguard-tools-wg chrony gpgv ssl_client u-boot-tools"
APK="apk --initdb --no-scripts --no-cache --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories"
HOSTAPD_APK=$(ls /out/hostapd/*/hostapd-2.11-r1[0-9][0-9].apk 2>/dev/null | sort -V | tail -1)
[ -n "$HOSTAPD_APK" ] || { echo "stage-rootfs: no Patronus hostapd package in /out/hostapd (run stage-hostapd.sh first)"; exit 1; }
$APK --root $R add --allow-untrusted $COMMON "$HOSTAPD_APK"
rm -rf $R/lib/apk $R/var/cache/apk $R/etc/apk
# u-boot-tools: only the environment tools (boot rollback, patronus-guard); mkimage & co. are build-host tools
for f in dumpimage fit_check_sign fit_info gdbcont gdbsend gen_eth_addr gen_ethaddr_crc img2srec kwboot mkenvimage mkimage mkeficapsule mksunxiboot ubsha1 xway-swap-bytes ifwitool fdtgrep sunxi-spl-image-builder dtc; do rm -f $R/usr/bin/$f; done
# Alpine puts the loader in /lib: keep, plus the name the aarch64 musl ELF interpreter expects
[ -e $R/lib/ld-musl-aarch64.so.1 ] || ln -sf ../usr/lib/libc.musl-aarch64.so.1 $R/lib/ld-musl-aarch64.so.1
ls -l $R/usr/sbin/hostapd $R/usr/bin/wg $R/usr/sbin/chronyd $R/usr/sbin/dropbear $R/usr/sbin/ubinfo $R/bin/busybox $R/sbin/ip | sed 's/^/  /'
du -sh $R
[ -x $R/usr/sbin/hostapd ] && touch /out/stage-rootfs.ok
