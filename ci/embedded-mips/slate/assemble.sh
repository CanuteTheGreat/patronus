#!/bin/bash
# Assemble the Patronus root squashfs + an OpenWrt-format sysupgrade tar for the GL-AR750S (packaging only, no compiling).
# usage: assemble.sh <pack-dir> <tag>
#   <pack-dir> = pack.sh output: rootfs.tar, patronus-cli (multi-call: also the web UI), libatomic.so.1, openrc.tar
# Inputs (environment; everything per-unit or secret stays outside the repo):
#   STOCK_ROOT        unpacked root of the stock OpenWrt 25.12.6 ath79/nand image (kmods for 6.12.112, Wi-Fi firmware, swconfig)
#   STOCK_SYSUPGRADE  openwrt-25.12.6-ath79-nand-glinet_gl-ar750s-nor-nand-squashfs-sysupgrade.bin (its kernel + CONTROL are reused)
#   RECOVERY_ROOT     stock root squashfs embedded as the guard's way back (usually the unit's own ubi0_0 dump)
#   RECOVERY_CFG      optional: OpenWrt sysupgrade -b tarball restored when the guard reverts
#   UNIT_DIR          per-unit private files: shadow-root, authorized_keys, dropbear_*_host_key, wpa_supplicant.conf,
#                     unit.conf (see overlay/etc/patronus/unit.conf.example), hostapd/*.conf (see ap5.conf.example)
#   OUT_DIR           where <tag>/root.squashfs and the sysupgrade tar go
#   SOURCE_REV        optional: recorded in /etc/patronus-release
#   Init system, exactly one (both variants are first-class; busybox only provides applets):
#   OPENRC_TREE       tar of the cross-built OpenRC (stage-openrc.sh: /out/pack/openrc.tar) -> the OpenRC variant:
#                     overlay-openrc/ on top, openrc-init as PID 1 after /usr/sbin/patronus-init's early boot
#   SYSTEMD_TREE      tar of the cross-built systemd install (stage-systemd.sh + sdsize.sh) -> the systemd variant:
#                     overlay-systemd/ on top, systemd as PID 1 after the same early boot
#   SYSTEMD_LIBS      with SYSTEMD_TREE: extra runtime libraries it needs (libucontext.so.1)
#   NOR_PROFILE=1     the 16 MiB NOR-only tier: no embedded OpenWrt recovery root (the NOR layout keeps stock OpenWrt
#                     out of the root image) and no NAND-only pieces; see nor-budget.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
B=$(readlink -f "$1"); TAG=$2
if [ -n "${OPENRC_TREE:-}" ] && [ -n "${SYSTEMD_TREE:-}" ]; then echo "assemble.sh: set OPENRC_TREE or SYSTEMD_TREE, not both"; exit 2; fi
if [ -z "${OPENRC_TREE:-}${SYSTEMD_TREE:-}" ]; then echo "assemble.sh: set OPENRC_TREE (OpenRC variant) or SYSTEMD_TREE (systemd variant)"; exit 2; fi
for v in STOCK_ROOT STOCK_SYSUPGRADE UNIT_DIR OUT_DIR ${NOR_PROFILE:+} $([ -n "${NOR_PROFILE:-}" ] || echo RECOVERY_ROOT); do [ -n "${!v:-}" ] || { echo "assemble.sh: $v is not set"; exit 2; }; done
OUTD=$OUT_DIR/$TAG; mkdir -p "$OUTD"; chmod 700 "$OUTD"
R=$(mktemp -d "${TMPDIR:-/tmp}/slate-rootfs.XXXX"); trap 'chmod -R u+w "$R"; rm -rf "$R"' EXIT
tar xf "$B/rootfs.tar" -C "$R" --exclude='./dev/*' 2>/dev/null || tar xf "$B/rootfs.tar" -C "$R"
chmod -R u+rwX "$R"
# drop build-only junk
rm -f "$R"/etc/hostapd/hostapd.* "$R"/etc/wpa_supplicant/*.conf
rm -rf "$R"/usr/include "$R"/usr/share/{man,doc,info,gtk-doc,locale} "$R"/var/db/pkg "$R"/var/cache "$R"/usr/lib/pkgconfig "$R"/etc/portage
find "$R" -name '*.a' -delete
rm -f "$R"/etc/init.d/busybox-* "$R"/etc/conf.d/busybox-*   # USE=syslog's scripts: the image runs patronus-syslogd/-klogd
rm -f "$R"/usr/lib/libgmpxx.so* "$R"/usr/lib/*.o
# util-linux/iproute2 tools the router never runs (busybox covers mount/umount/unshare/nsenter)
while read -r f; do [ -n "$f" ] && rm -rf "$R"/$f; done < "$HERE/prune.txt"
# musl loader where every binary expects it
[ -e "$R/lib/ld-musl-mips-sf.so.1" ] || ln -sf ../usr/lib/libc.so "$R/lib/ld-musl-mips-sf.so.1"
mkdir -p "$R"/{proc,sys,dev,tmp,run,data,mnt,root/.ssh,var/log,var/lib/patronus,var/lib/misc,etc/dropbear,usr/lib/openwrt,usr/share/patronus-recovery,etc/patronus/tls,etc/hostapd,etc/wpa_supplicant}
install -m755 "$B/patronus-cli" "$R/usr/bin/patronus-cli"
# multi-call build (default): patronus-web is the same binary under another name; a separate build is still accepted
if [ -f "$B/patronus-web" ]; then install -m755 "$B/patronus-web" "$R/usr/bin/patronus-web"; else ln -sf patronus-cli "$R/usr/bin/patronus-web"; fi
install -m644 "$B/libatomic.so.1" "$R/usr/lib/libatomic.so.1"
# OpenWrt pieces for this exact kernel: kmods, their load order, Wi-Fi firmware + regdb, swconfig (+libs)
S=$STOCK_ROOT; KV=$(ls "$S/lib/modules")
cp -a "$S/lib/modules" "$R/lib/"; mkdir -p "$R/etc/modules.d"; cp -a "$S"/etc/modules.d/. "$R/etc/modules.d/"
cp -a "$S/lib/firmware" "$R/lib/"
{ /sbin/depmod -b "$R" "$KV" || depmod -b "$R" "$KV"; } 2>/dev/null || true
[ -s "$R/lib/modules/$KV/modules.dep" ] || { echo "depmod failed"; exit 1; }
for f in services protocols; do [ -e "$R/etc/$f" ] || cp "$S/etc/$f" "$R/etc/$f"; done   # busybox wget/nc resolve service names (p4: wget: bad port 'http')
cp -a "$S/sbin/swconfig" "$S/usr/lib/libnl-tiny.so.1" "$S"/lib/libuci.so.* "$S"/lib/libubox.so.* "$S/lib/libgcc_s.so.1" "$R/usr/lib/openwrt/"
# the safety net's payload: stock OpenWrt root + the unit's config backup (not on the NOR tier: see NOR_PROFILE)
if [ -z "${NOR_PROFILE:-}" ]; then
  cp "$RECOVERY_ROOT" "$R/usr/share/patronus-recovery/openwrt-root.squashfs"
  if [ -n "${RECOVERY_CFG:-}" ]; then cp "$RECOVERY_CFG" "$R/usr/share/patronus-recovery/sysupgrade.tgz"; fi
fi
# overlay (early boot, board glue, guard, flash tool, Patronus config); examples stay out of the image
cp -a "$HERE"/overlay/. "$R/"; rm -f "$R"/etc/patronus/*.example
ln -sf /usr/sbin/patronus-init "$R/sbin/init"
# web login of system users through PAM (service patronus): local accounts only, pam_unix against /etc/shadow
mkdir -p "$R/etc/pam.d"
printf '#%%PAM-1.0\n# Patronus web UI login (embedded tier): system users in /etc/passwd + /etc/shadow\nauth     required pam_unix.so\naccount  required pam_unix.so\n' > "$R/etc/pam.d/patronus"
printf '#%%PAM-1.0\nauth     required pam_deny.so\naccount  required pam_deny.so\npassword required pam_deny.so\nsession  required pam_deny.so\n' > "$R/etc/pam.d/other"
find "$R/lib/security" -name 'pam_*.so' ! -name pam_unix.so ! -name pam_deny.so ! -name pam_permit.so -delete 2>/dev/null; rm -rf "$R/lib/security/pam_filter"
rm -f "$R"/usr/lib/libpamc.so* "$R"/usr/lib/libpam_misc.so* "$R"/sbin/{faillock,pam_namespace_helper,pam_timestamp_check,pwhistory_helper,unix_update,mkhomedir_helper} "$R"/usr/lib/systemd/system/pam_namespace.service
GENTOO_FILES="$HERE/../../../gentoo/net-firewall/patronus/files"
if [ -n "${SYSTEMD_TREE:-}" ]; then
  # udev (no devtmpfs in this kernel; mdev does /dev), the journal message catalog, networkd/resolved leftovers,
  # headers and docs are not used by the router: kept out of the image (measured in docs/embedded-routers.md 6b)
  tar xf "$SYSTEMD_TREE" -C "$R" --exclude='./usr/lib/udev' --exclude='./usr/lib/systemd/catalog' --exclude='./usr/include' \
      --exclude='./usr/share/man' --exclude='./usr/share/doc' --exclude='./usr/share/locale' --exclude='./usr/lib/pkgconfig' \
      --exclude='./usr/share/pkgconfig' --exclude='./usr/lib/systemd/network' --exclude='./usr/share/zsh' --exclude='./usr/share/bash-completion' --exclude='./etc/X11' --exclude='./etc/xdg' --exclude='./etc/ssh' --exclude='./usr/sbin/init' --exclude='./'
  # tools and libraries no unit or Patronus code path runs on the router (docs/embedded-routers.md 6c, NOR budget):
  # udev (no hotplug/devtmpfs here), libsystemd for clients (none links it), and the interactive/debug tools
  for f in usr/bin/udevadm usr/lib/libudev.so* usr/lib/libsystemd.so* usr/bin/busctl usr/bin/systemd-run usr/bin/systemd-analyze \
           usr/bin/systemd-cgtop usr/bin/systemd-cgls usr/bin/systemd-creds usr/bin/systemd-mount usr/bin/systemd-umount usr/bin/systemd-vpick \
           usr/bin/systemd-mstack usr/bin/storagectl usr/bin/varlinkctl usr/bin/systemd-socket-activate usr/bin/systemd-pty-forward \
           usr/bin/systemd-delta usr/bin/systemd-id128 usr/bin/systemd-cat usr/bin/systemd-stdio-bridge usr/bin/systemd-inhibit \
           usr/bin/systemd-path usr/bin/systemd-detect-virt usr/bin/systemd-confext usr/bin/systemd-sysext usr/bin/systemd-dissect \
           usr/bin/systemd-repart usr/bin/bootctl usr/bin/kernel-install usr/bin/systemd-cryptenroll usr/bin/systemd-keyutil \
           usr/lib/systemd/systemd-socket-proxyd usr/lib/systemd/systemd-ssh-issue usr/lib/systemd/systemd-storage-fs \
           usr/lib/systemd/systemd-network-generator usr/lib/systemd/systemd-sleep usr/lib/systemd/systemd-report \
           usr/lib/systemd/systemd-udevd usr/lib/systemd/systemd-bsod usr/lib/systemd/systemd-pcrextend usr/lib/systemd/systemd-pcrlock \
           usr/bin/run0 usr/bin/systemd-ac-power usr/bin/systemd-mute-console usr/lib/systemd/systemd-report-* usr/lib/systemd/systemd-battery-check \
           usr/lib/systemd/systemd-clonesetup usr/lib/systemd/systemd-ssh-proxy usr/lib/systemd/systemd-growfs usr/lib/systemd/systemd-makefs \
           usr/sbin/mount.mstack usr/sbin/mount.storage; do
    rm -f "$R"/$f; done
  for l in ${SYSTEMD_LIBS:-}; do install -m755 "$l" "$R/usr/lib/"; done
  cp -a "$HERE"/overlay-systemd/. "$R/"
  # Patronus' own template units (the Gentoo ebuild's): `patronus apply` starts per-instance daemons through them on
  # systemd (patronus-dhcpc@wl24-sta etc.); without them the WAN DHCP client never started (sd3 on the real unit)
  install -m644 "$GENTOO_FILES"/*@.service "$R/usr/lib/systemd/system/"
  for t in mount umount; do [ -e "$R/usr/bin/$t" ] || ln -sf /bin/$t "$R/usr/bin/$t"; done   # systemd runs /usr/bin/mount for .mount units
  echo "INIT=systemd" > "$R/etc/patronus-init"
else
  # OpenRC: openrc-init is PID 1; the stock scripts for mounts/devices/consoles are replaced by the early boot
  # (no fstab, no devtmpfs, read-only squashfs root), so only the shutdown runlevel's scripts are kept
  tar xf "$OPENRC_TREE" -C "$R" --exclude='./usr/share/man' --exclude='./usr/share/doc' --exclude='./usr/include' --exclude='./usr/lib/pkgconfig' --exclude='./sbin/init' --exclude='./'
  # kept from the package set: dnsmasq/hostapd/nftables (Patronus drives them with rc-service)
  for f in "$R"/etc/init.d/*; do case "${f##*/}" in functions.sh|killprocs|mount-ro|savecache|dnsmasq|hostapd|nftables) ;; *) rm -f "$f";; esac; done
  rm -rf "$R"/etc/runlevels/{sysinit,boot,default,nonetwork} "$R"/etc/conf.d/{agetty,consolefont,devfs,dmesg,fsck,hostname,hwclock,keymaps,localmount,modules,netmount,swap,termencoding,bootmisc,seedrng,net-online} \
         "$R"/etc/{csh.env,logrotate.d,sysctl.d,environment.d} "$R"/usr/share/openrc/support
  cp -a "$HERE"/overlay-openrc/. "$R/"
  # Patronus' own multiplexed scripts (the Gentoo ebuild's): `patronus apply` starts per-instance daemons through
  # them on OpenRC (patronus-dhcpc.wl24-sta etc.), the same set as the systemd variant's template units
  for t in "$GENTOO_FILES"/*@.service; do n=$(basename "$t" @.service); [ -f "$GENTOO_FILES/$n.initd" ] && install -m755 "$GENTOO_FILES/$n.initd" "$R/etc/init.d/$n"; done
  mkdir -p "$R"/etc/runlevels/{sysinit,boot,default,shutdown}
  for s in patronus-syslogd patronus-klogd patronus-board dropbear patronus-ntpd patronus-apply patronus-applyd patronus-web; do
    [ -x "$R/etc/init.d/$s" ] || { echo "missing OpenRC service $s"; exit 1; }; ln -sf /etc/init.d/$s "$R/etc/runlevels/default/$s"; done
  : > "$R/etc/fstab"
  echo "INIT=openrc" > "$R/etc/patronus-init"
fi
# busybox applet links for every applet the image has no real tool for (ash runs what PATH finds:
# the busybox build has FEATURE_PREFER_APPLETS off, see busybox.portage-env)
while read -r a; do
  [ -n "$a" ] || continue
  for d in bin sbin usr/bin usr/sbin; do if [ -e "$R/$d/$a" ] || [ -L "$R/$d/$a" ]; then continue 2; fi; done
  ln -sf /bin/busybox "$R/bin/$a"; done < "$HERE/busybox-applets.txt"
# accounts + per-unit secrets
grep -q '^root:' "$R/etc/passwd" 2>/dev/null || echo 'root:x:0:0:root:/root:/bin/sh' >> "$R/etc/passwd"
sed -i 's#^root:[^:]*:0:0:.*#root:x:0:0:root:/root:/bin/sh#' "$R/etc/passwd"   # Gentoo ships root:!:...:/bin/bash; dropbear rejects a missing shell
for u in 'nobody:x:65534:65534:nobody:/:/bin/false' 'dnsmasq:x:453:453:dnsmasq:/:/bin/false'; do grep -q "^${u%%:*}:" "$R/etc/passwd" || echo "$u" >> "$R/etc/passwd"; done
for g in 'root:x:0:' 'nobody:x:65534:' 'dnsmasq:x:453:' 'patronus:x:900:'; do grep -q "^${g%%:*}:" "$R/etc/group" 2>/dev/null || echo "$g" >> "$R/etc/group"; done
U=$UNIT_DIR
{ cat "$U/shadow-root"; grep -v '^root:' "$R/etc/shadow" 2>/dev/null || true; } > "$R/etc/shadow.new"; mv "$R/etc/shadow.new" "$R/etc/shadow"; chmod 600 "$R/etc/shadow"
install -m600 "$U/authorized_keys" "$R/root/.ssh/authorized_keys"; chmod 700 "$R/root/.ssh"
install -m600 "$U"/dropbear_*_host_key "$R/etc/dropbear/"
install -m600 "$U/wpa_supplicant.conf" "$R/etc/wpa_supplicant/wpa_supplicant.conf"
if [ -f "$U/unit.conf" ]; then install -m644 "$U/unit.conf" "$R/etc/patronus/unit.conf"; fi
for c in "$U"/hostapd/*.conf; do if [ -f "$c" ]; then install -m600 "$c" "$R/etc/hostapd/"; fi; done
echo "slate" > "$R/etc/hostname"; printf '127.0.0.1 localhost\n' > "$R/etc/hosts"
ln -sf /tmp/resolv.conf.auto "$R/etc/resolv.conf"
ln -sf /proc/self/mounts "$R/etc/mtab"   # df/mount -o remount need it
rm -rf "$R/var/run"; ln -s ../run "$R/var/run"   # FHS; the systemd variant's dnsmasq.service writes /var/run/dnsmasq.pid
cat > "$R/etc/patronus-release" <<EOF
PATRONUS_TIER=embedded
BOARD=glinet,gl-ar750s-nor-nand
BUILD=$TAG
SOURCE=patronus ${SOURCE_REV:-unknown}
KERNEL=OpenWrt 25.12.6 ath79/nand $KV (stock, unchanged)
EOF
chmod 755 "$R"; chmod 1777 "$R/tmp"
"$HERE/check-rootfs.sh" "$R"
P=(-p "/dev/console c 600 0 0 5 1" -p "/dev/null c 666 0 0 1 3" -p "/dev/ttyS0 c 600 0 0 4 64")
# NOR tier: 1 MiB xz blocks (5.5 % smaller than 256 KiB, measured: what makes the systemd variant fit 16 MiB NOR; a few MB
# more page-cache decompression buffers); NAND tier: 256 KiB like OpenWrt
SQ_BLOCK=${SQ_BLOCK:-$([ -n "${NOR_PROFILE:-}" ] && echo 1M || echo 256K)}
mksquashfs "$R" "$OUTD/root.squashfs" -comp xz -b $SQ_BLOCK -noappend -no-xattrs -all-root -quiet "${P[@]}"
# OpenWrt sysupgrade-tar: stock kernel (identical bytes to what is in NOR) + our root, then fwtool metadata
W=$(mktemp -d); D=$W/sysupgrade-glinet_gl-ar750s-nor-nand; mkdir -p "$D"
tar xf "$STOCK_SYSUPGRADE" -C "$W" --wildcards '*/kernel' '*/CONTROL'
cp "$OUTD/root.squashfs" "$D/root"
(cd "$W" && tar cf "$OUTD/patronus-$TAG-glinet_gl-ar750s-nor-nand-sysupgrade.tar" --owner=0 --group=0 --sort=name sysupgrade-glinet_gl-ar750s-nor-nand)
"$HERE/fwmeta.py" add "$OUTD/patronus-$TAG-glinet_gl-ar750s-nor-nand-sysupgrade.tar" glinet,gl-ar750s-nor-nand --version "$TAG"   # sysupgrade -T needs it
rm -rf "$W"
ls -l "$OUTD"; unsquashfs -s "$OUTD/root.squashfs" | grep -E 'Filesystem size|Compression|Block size'
