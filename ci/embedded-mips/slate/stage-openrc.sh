#!/bin/bash
# INSIDE the build container (after stage-all.sh): the pieces both embedded variants (OpenRC, systemd) share on top of
# the router rootfs, and OpenRC itself.
#   /rootfs         += linux-pam (web login of system users, /etc/pam.d/patronus) + dhcpcd (DHCPv6 / prefix delegation;
#                      built from the release tarball by dhcpcd-build.sh, without OpenSSL)
#   /rootfs-openrc   = sys-apps/openrc (openrc-init as PID 1 via USE=sysv-utils, openrc-run, supervise-daemon)
# Log /out/stage-openrc.log, marker /out/stage-openrc.ok; pack.sh then writes /out/pack/openrc.tar.
set -uo pipefail
exec > >(tee -a /out/stage-openrc.log) 2>&1
T=mips-unknown-linux-musl; SYS=/usr/$T
step() { echo "== $(date -u +%T) $*"; }
U=$SYS/etc/portage/package.use/embedded-openrc
cat > $U <<'EOF'
# openrc-init is PID 1 (sysv-utils: /sbin/init, reboot, halt, poweroff); busybox only provides applets
sys-apps/openrc -netifrc -newnet -pam -audit -selinux -bash -unicode -s6 -sysvinit sysv-utils -debug
sys-libs/pam -berkdb -nis -audit -selinux -examples -debug -elogind -systemd -nls
# privsep needs a seccomp filter for this ABI and its own user; OpenWrt's odhcp6c has none either (docs 6b)
net-misc/dhcpcd -udev -privsep embedded ipv6 -debug
EOF
step pam + dhcpcd into /rootfs
# pam_unix's unix_chkpwd is installed root:shadow (fowners resolves it in the sysroot)
for g in $SYS/etc/group /rootfs/etc/group; do grep -q '^shadow:' $g 2>/dev/null || echo 'shadow:x:42:' >> $g; done
# --nodeps: libxcrypt/musl are in /rootfs already; pambase/passwdqc are not used (the image ships its own /etc/pam.d/patronus)
ROOT=/rootfs $T-emerge --nodeps -q sys-libs/pam 2>&1 | tail -30
emerge -q --fetchonly net-misc/dhcpcd >/dev/null 2>&1; bash /w/dhcpcd-build.sh
step openrc into /rootfs-openrc
mkdir -p /rootfs-openrc
# runtime deps (musl, libcrypt) come from /rootfs; virtual/tmpfiles is only for opentmpfiles units the router does not use
[ -x /rootfs-openrc/sbin/openrc-init ] || ROOT=/rootfs-openrc $T-emerge --nodeps -q sys-apps/openrc 2>&1 | tail -30
# supervise-daemon links libcap (without it every supervised service fails to start: o3 on the real unit)
[ -e /rootfs-openrc/usr/lib/libcap.so.2 ] || [ -e /rootfs-openrc/lib/libcap.so.2 ] || ROOT=/rootfs-openrc $T-emerge --nodeps -q sys-libs/libcap 2>&1 | tail -10
ls -l /rootfs/usr/lib/libpam.so* /rootfs/lib/libpam.so* /rootfs/sbin/dhcpcd /rootfs/usr/sbin/dhcpcd /rootfs-openrc/sbin/openrc-init /rootfs-openrc/sbin/openrc 2>&1
du -sh /rootfs-openrc
[ -x /rootfs-openrc/sbin/openrc-init ] && { [ -x /rootfs/sbin/dhcpcd ] || [ -x /rootfs/usr/sbin/dhcpcd ]; } && touch /out/stage-openrc.ok
step done
