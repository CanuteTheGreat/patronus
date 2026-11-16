#!/bin/bash
# Assemble the Patronus root squashfs + an OpenWrt-format sysupgrade tar for the GL.iNet GL-AX1800 (packaging only).
# usage: assemble.sh <pack-dir> <tag>
# Output in OUT_DIR/<tag>: root.squashfs, patronus-<tag>-glinet_gl-ax1800-sysupgrade.tar (upgrade from OpenWrt or Patronus),
#   -factory.ubi (U-Boot web recovery: the ONLY format GL's U-Boot takes besides GL's own .img), -factory.bin (the GL stock
#   firmware's web UI: factory.ubi + fwtool metadata, as OpenWrt ships it), sha256sums, sizes.txt.
#   <pack-dir> = pack.sh output: rootfs.tar (Alpine userland), openrc.tar, patronus-cli (multi-call: also the web UI)
# Inputs (environment; everything per-unit or secret stays outside the repo):
#   STOCK_ROOT        unpacked root of the stock OpenWrt 25.12.6 qualcommax/ipq60xx GL-AX1800 image (fetch-stock.sh): the
#                     kmods for its 6.12.112 kernel, the IPQ6018 Wi-Fi firmware, the ath11k board data
#   STOCK_SYSUPGRADE  that image's sysupgrade tar: its FIT kernel (kernel + the board's device tree) and CONTROL are reused
#   UNIT_DIR          per-unit private files: shadow-root, authorized_keys, dropbear_*_host_key, ap.env (ap.env.example)
#   OUT_DIR           where <tag>/root.squashfs and the sysupgrade tar go
#   SOURCE_REV        optional: recorded in /etc/patronus-release
#   Init system, exactly one (both variants are first-class; busybox only provides applets):
#   OPENRC_TREE       tar of OpenRC (stage-openrc.sh -> pack.sh: openrc.tar): openrc-init as PID 1 after patronus-init's early boot
#   SYSTEMD_TREE      tar of the systemd install (stage-systemd.sh: /out/systemd-root as a tar): systemd as PID 1, same early boot
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
B=$(readlink -f "$1"); TAG=$2
# every device value comes from the hardware profile (board id, aliases, hostname, kernel label, NAND geometry)
PROFILE=${HW_PROFILE:-$HERE/../../../profiles/hw/qualcommax-gl-ax1800.toml}
eval "$(python3 "$HERE/../../hw-profile/hwprofile.py" env "$PROFILE")"
BOARD=$HW_DEVICE_OPENWRT_BOARD; BOARD_DIR=$HW_BOARD_ID
if [ -n "${OPENRC_TREE:-}" ] && [ -n "${SYSTEMD_TREE:-}" ]; then echo "assemble.sh: set OPENRC_TREE or SYSTEMD_TREE, not both"; exit 2; fi
if [ -z "${OPENRC_TREE:-}${SYSTEMD_TREE:-}" ]; then echo "assemble.sh: set OPENRC_TREE (OpenRC variant) or SYSTEMD_TREE (systemd variant)"; exit 2; fi
for v in STOCK_ROOT STOCK_SYSUPGRADE UNIT_DIR OUT_DIR; do [ -n "${!v:-}" ] || { echo "assemble.sh: $v is not set"; exit 2; }; done
OUTD=$OUT_DIR/$TAG; mkdir -p "$OUTD"; chmod 700 "$OUTD"
R=$(mktemp -d "${TMPDIR:-/tmp}/ax1800-rootfs.XXXX"); trap 'chmod -R u+w "$R"; rm -rf "$R"' EXIT
tar xf "$B/rootfs.tar" -C "$R" --exclude='./dev/*' 2>/dev/null || tar xf "$B/rootfs.tar" -C "$R"
chmod -R u+rwX "$R"
rm -rf "$R"/usr/include "$R"/usr/share/{man,doc,info,locale,apk} "$R"/var/cache "$R"/usr/lib/pkgconfig "$R"/etc/apk "$R"/lib/apk
find "$R" -name '*.a' -delete
mkdir -p "$R"/{proc,sys,dev,tmp,run,data,mnt,root/.ssh,var/log,var/lib/patronus,var/lib/misc,etc/dropbear,etc/patronus/tls}
install -m755 "$B/patronus-cli" "$R/usr/bin/patronus-cli"
ln -sf patronus-cli "$R/usr/bin/patronus-web"          # multi-call build
# OpenWrt pieces for this exact kernel: kmods, their load order, Wi-Fi firmware (+ board data, regdb)
S=$STOCK_ROOT; KV=$(ls "$S/lib/modules")
cp -a "$S/lib/modules" "$R/lib/"; mkdir -p "$R/etc/modules.d"; cp -a "$S"/etc/modules.d/. "$R/etc/modules.d/"
cp -a "$S/lib/firmware" "$R/lib/"
# netfilter kmods from the pinned OpenWrt packages of this exact kernel (the stock root has no nfnetlink_log, which the
# firewall's NFLOG `log group` rules need); same release + kmods hash as the stock FIT
sh "$HERE/fetch-kmods.sh" board "$R" "${KMOD_CACHE:-$OUT_DIR/.kmod-cache}"
{ /sbin/depmod -b "$R" "$KV" || depmod -b "$R" "$KV"; } 2>/dev/null || true
[ -s "$R/lib/modules/$KV/modules.dep" ] || { echo "depmod failed (kmod's depmod is needed in the builder)"; exit 1; }
for f in services protocols; do [ -e "$R/etc/$f" ] || cp "$S/etc/$f" "$R/etc/$f"; done
# overlay (early boot, board glue, ath11k caldata, AP renderer, flash tool, Patronus config); examples stay out of the image
cp -a "$HERE"/overlay/. "$R/"; rm -f "$R"/etc/patronus/*.example
ln -sf /usr/sbin/patronus-init "$R/sbin/init"
# ETPhoneHome router client (every variant, owner rule): the pinned release package (etph.pin), sha256-verified, client only
. "$HERE/etph.pin"
E=${ETPH_IPK_FILE:-$(sh "$HERE/fetch-etph.sh" "${ETPH_CACHE:-$OUT_DIR/.etph-cache}")}
echo "$ETPH_SHA256  $E" | sha256sum -c - >/dev/null || { echo "assemble.sh: $E is not the pinned ETPhoneHome $ETPH_VERSION"; exit 1; }
EX=$(mktemp -d "${TMPDIR:-/tmp}/etph-ipk.XXXX"); tar xzf "$E" -C "$EX" ./data.tar.gz 2>/dev/null || tar xzf "$E" -C "$EX" data.tar.gz
tar xzf "$EX/data.tar.gz" -C "$R" ./usr/sbin/etphonehome 2>/dev/null || tar xzf "$EX/data.tar.gz" -C "$R" usr/sbin/etphonehome; rm -rf "$EX"
chmod 755 "$R/usr/sbin/etphonehome"; mkdir -p "$R/etc/etph"; chmod 700 "$R/etc/etph"
# web login of system users through PAM: local accounts only
mkdir -p "$R/etc/pam.d"
printf '#%%PAM-1.0\n# Patronus web UI login (embedded tier): system users in /etc/passwd + /etc/shadow\nauth     required pam_unix.so\naccount  required pam_unix.so\n' > "$R/etc/pam.d/patronus"
printf '#%%PAM-1.0\nauth     required pam_deny.so\naccount  required pam_deny.so\npassword required pam_deny.so\nsession  required pam_deny.so\n' > "$R/etc/pam.d/other"
for d in "$R/usr/lib/security" "$R/lib/security"; do [ -d "$d" ] || continue; find "$d" -name 'pam_*.so' ! -name pam_unix.so ! -name pam_deny.so ! -name pam_permit.so -delete; done
if [ -n "${SYSTEMD_TREE:-}" ]; then
  tar xf "$SYSTEMD_TREE" -C "$R" --exclude='./usr/lib/udev' --exclude='./usr/lib/systemd/catalog' --exclude='./usr/include' \
      --exclude='./usr/share/man' --exclude='./usr/share/doc' --exclude='./usr/share/locale' --exclude='./usr/lib/pkgconfig' \
      --exclude='./usr/share/pkgconfig' --exclude='./usr/lib/systemd/network' --exclude='./usr/share/zsh' --exclude='./usr/share/bash-completion' \
      --exclude='./etc/X11' --exclude='./etc/xdg' --exclude='./usr/sbin/init'
  # udev/devtmpfs: the OpenWrt kernel has devtmpfs and the early boot needs no udev; interactive/debug tools stay out
  for f in usr/bin/udevadm usr/lib/libudev.so* usr/bin/busctl usr/bin/systemd-analyze usr/bin/systemd-cgtop usr/bin/systemd-creds \
           usr/bin/varlinkctl usr/bin/systemd-dissect usr/bin/systemd-repart usr/bin/bootctl usr/bin/kernel-install usr/bin/systemd-cryptenroll \
           usr/lib/systemd/systemd-udevd usr/lib/systemd/systemd-bsod usr/lib/systemd/systemd-pcrextend usr/lib/systemd/systemd-pcrlock; do
    rm -f "$R"/$f; done
  # udev: removed above (devtmpfs does /dev, the early boot needs no udev), so its units and their wants links go too;
  # ldconfig.service is glibc's linker cache (musl has none: it fails on every boot)
  for u in ldconfig.service systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket systemd-udevd-varlink.socket \
           systemd-udev-settle.service systemd-udev-trigger.service systemd-udev-load-credentials.service systemd-hwdb-update.service; do
    rm -f "$R/usr/lib/systemd/system/$u"; find "$R/usr/lib/systemd/system" -name "$u" -type l -delete; done
  cp -a "$HERE"/overlay-systemd/. "$R/"
  GENTOO_FILES="$HERE/../../../gentoo/net-firewall/patronus/files"
  install -m644 "$GENTOO_FILES"/*@.service "$R/usr/lib/systemd/system/"
  for t in mount umount; do [ -e "$R/usr/bin/$t" ] || ln -sf /bin/busybox "$R/usr/bin/$t"; done   # systemd runs /usr/bin/mount for mount units
  echo "INIT=systemd" > "$R/etc/patronus-init"
else
  tar xf "$OPENRC_TREE" -C "$R" --exclude='./usr/share/man' --exclude='./usr/share/doc' --exclude='./usr/include' --exclude='./usr/lib/pkgconfig' --exclude='./sbin/init'
  # stock scripts for mounts/devices/consoles are replaced by the early boot (no fstab, read-only squashfs root): keep functions + shutdown
  for f in "$R"/etc/init.d/*; do case "${f##*/}" in functions.sh|killprocs|mount-ro|savecache|hostapd) ;; *) rm -f "$f";; esac; done
  rm -rf "$R"/etc/runlevels/{sysinit,boot,default,nonetwork} "$R"/etc/conf.d/* "$R"/usr/share/openrc/support 2>/dev/null || true
  cp -a "$HERE"/overlay-openrc/. "$R/"
  GENTOO_FILES="$HERE/../../../gentoo/net-firewall/patronus/files"
  for t in "$GENTOO_FILES"/*@.service; do n=$(basename "$t" @.service); [ -f "$GENTOO_FILES/$n.initd" ] && install -m755 "$GENTOO_FILES/$n.initd" "$R/etc/init.d/$n"; done
  mkdir -p "$R"/etc/runlevels/{sysinit,boot,default,shutdown}
  for s in patronus-syslogd patronus-klogd patronus-board patronus-etph dropbear patronus-ntpd patronus-apply patronus-applyd patronus-web; do
    [ -x "$R/etc/init.d/$s" ] || { echo "missing OpenRC service $s"; exit 1; }; ln -sf /etc/init.d/$s "$R/etc/runlevels/default/$s"; done
  : > "$R/etc/fstab"
  # reboot/halt/poweroff go through openrc-shutdown (busybox's would signal openrc-init to HALT instead)
  for c in reboot:-r halt:-H poweroff:-p; do printf '#!/bin/sh\nexec /sbin/openrc-shutdown %s now "$@"\n' "${c#*:}" > "$R/sbin/${c%%:*}"; chmod 755 "$R/sbin/${c%%:*}"; done
  echo "INIT=openrc" > "$R/etc/patronus-init"
fi
# busybox applet links for every applet the image has no real tool for
while read -r a; do
  [ -n "$a" ] || continue
  for d in bin sbin usr/bin usr/sbin; do if [ -e "$R/$d/$a" ] || [ -L "$R/$d/$a" ]; then continue 2; fi; done
  ln -sf /bin/busybox "$R/bin/$a"; done < "$HERE/busybox-applets.txt"
# accounts + per-unit secrets
grep -q '^root:' "$R/etc/passwd" 2>/dev/null || echo 'root:x:0:0:root:/root:/bin/sh' >> "$R/etc/passwd"
sed -i 's#^root:[^:]*:0:0:.*#root:x:0:0:root:/root:/bin/sh#' "$R/etc/passwd"
for u in 'nobody:x:65534:65534:nobody:/:/bin/false'; do grep -q "^${u%%:*}:" "$R/etc/passwd" || echo "$u" >> "$R/etc/passwd"; done
for g in 'root:x:0:' 'nobody:x:65534:' 'patronus:x:900:' 'shadow:x:42:'; do grep -q "^${g%%:*}:" "$R/etc/group" 2>/dev/null || echo "$g" >> "$R/etc/group"; done
U=$UNIT_DIR
{ cat "$U/shadow-root"; grep -v '^root:' "$R/etc/shadow" 2>/dev/null || true; } > "$R/etc/shadow.new"; mv "$R/etc/shadow.new" "$R/etc/shadow"; chmod 600 "$R/etc/shadow"
install -m600 "$U/authorized_keys" "$R/root/.ssh/authorized_keys"; chmod 700 "$R/root/.ssh"
install -m600 "$U"/dropbear_*_host_key "$R/etc/dropbear/"
if [ -f "$U/ap.env" ]; then install -m600 "$U/ap.env" "$R/etc/patronus/ap.env"; fi
echo "$HW_DEVICE_HOSTNAME" > "$R/etc/hostname"; printf '127.0.0.1 localhost\n' > "$R/etc/hosts"
ln -sf /tmp/resolv.conf.auto "$R/etc/resolv.conf"
ln -sf /proc/self/mounts "$R/etc/mtab"
rm -rf "$R/var/run"; ln -s ../run "$R/var/run"
. "$R/etc/patronus-init"
cat > "$R/etc/patronus-release" <<EOT
PATRONUS_TIER=embedded
ETPH=$ETPH_VERSION
BOARD=$BOARD
BUILD=$TAG
INIT=$INIT
SOURCE=patronus ${SOURCE_REV:-unknown}
KERNEL=$HW_KERNEL_LABEL $KV (stock FIT, unchanged)
EOT
chmod 755 "$R"; chmod 1777 "$R/tmp"
"$HERE/check-rootfs.sh" "$R"
P=(-p "/dev/console c 600 0 0 5 1" -p "/dev/null c 666 0 0 1 3" -p "/dev/ttyMSM0 c 600 0 0 248 0")
mksquashfs "$R" "$OUTD/root.squashfs" -comp xz -b 256K -noappend -no-xattrs -all-root -quiet "${P[@]}"
# OpenWrt sysupgrade tar: the stock FIT kernel (identical bytes) + our root + patronus-release + sha256 of both (what
# patronus-flash checks), then fwtool metadata (what OpenWrt's `sysupgrade -T` checks)
W=$(mktemp -d); D=$W/sysupgrade-$BOARD_DIR; mkdir -p "$D"
tar xf "$STOCK_SYSUPGRADE" -C "$W" --wildcards '*/kernel' '*/CONTROL'
[ "$(head -c4 "$D/kernel" | od -An -tx1 | tr -d ' ')" = d00dfeed ] || { echo "assemble.sh: the stock kernel is not a FIT"; exit 1; }
cp "$OUTD/root.squashfs" "$D/root"; cp "$R/etc/patronus-release" "$D/patronus-release"
(cd "$D" && sha256sum kernel root > patronus.sha256)
OUT_TAR=$OUTD/patronus-$TAG-$BOARD_DIR-sysupgrade.tar
(cd "$W" && tar cf "$OUT_TAR" --owner=0 --group=0 --sort=name sysupgrade-$BOARD_DIR)
ALSO=$(echo "$HW_DEVICE_BOARD_ALIASES" | tr ' ' ',')
"$HERE/fwmeta.py" add "$OUT_TAR" "$BOARD" --version "$TAG" ${ALSO:+--also "$ALSO"}
# factory.ubi: the UBI image GL's U-Boot web recovery writes to mtd "rootfs" (layout = OpenWrt's factory.ubi for this
# board: kernel id 0, rootfs id 1, rootfs_data id 2 with autoresize; checked by nand-budget.sh/ubi-layout.py below)
cat > "$W/ubinize.cfg" <<EOT
[kernel]
mode=ubi
vol_id=0
vol_type=dynamic
vol_name=kernel
image=$D/kernel

[rootfs]
mode=ubi
vol_id=1
vol_type=dynamic
vol_name=rootfs
image=$D/root

[rootfs_data]
mode=ubi
vol_id=2
vol_type=dynamic
vol_name=rootfs_data
vol_size=1MiB
vol_flags=autoresize
EOT
OUT_UBI=$OUTD/patronus-$TAG-$BOARD_DIR-factory.ubi; OUT_BIN=$OUTD/patronus-$TAG-$BOARD_DIR-factory.bin
ubinize -o "$OUT_UBI" -p "$HW_NAND_PEB_BYTES" -m "$HW_NAND_MIN_IO" -s "$HW_NAND_MIN_IO" -Q "${UBI_IMAGE_SEQ:-$(date +%s)}" "$W/ubinize.cfg"
# factory.bin: for the GL stock firmware's upgrade page ("keep settings" off) = factory.ubi + fwtool metadata, like OpenWrt's
cp "$OUT_UBI" "$OUT_BIN"; "$HERE/fwmeta.py" add "$OUT_BIN" "$BOARD" --version "$TAG" ${ALSO:+--also "$ALSO"}
cp "$D/kernel" "$OUTD/.kernel"; rm -rf "$W"
(cd "$OUTD" && sha256sum root.squashfs patronus-$TAG-* > sha256sums)
unsquashfs -s "$OUTD/root.squashfs" | grep -E 'Filesystem size|Compression|Block size'
rc=0; sh "$HERE/nand-budget.sh" "$OUTD/root.squashfs" "$OUTD/.kernel" "$OUT_UBI" > "$OUTD/nand-budget.txt" 2>&1 || rc=$?; cat "$OUTD/nand-budget.txt"
{ echo "build=$TAG init=$INIT"; for f in $(cd "$OUTD" && ls root.squashfs patronus-$TAG-*); do awk -v f="$f" -v n="$(stat -c%s "$OUTD/$f")" 'BEGIN{printf "%s %d bytes (%.2f MiB)\n", f, n, n/1048576}'; done
  echo "rootfs_unpacked_kib=$(du -sk "$R" | cut -f1)"; } > "$OUTD/sizes.txt"
cat "$OUTD/sizes.txt"; ls -l "$OUTD"
rm -f "$OUTD/.kernel"; exit "$rc"
