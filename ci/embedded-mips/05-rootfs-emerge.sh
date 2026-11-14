#!/bin/bash
# inside pembed-gentoo AFTER crossdev finished: cross-emerge the embedded tier into ROOT=/rootfs, cross-build Patronus daemons.
set -uo pipefail
T=mips-unknown-linux-musl
SYS=/usr/$T
exec > >(tee -a /out/rootfs.log) 2>&1
echo "== $(date) profile/config"
ls $SYS/etc/portage; cat $SYS/etc/portage/make.conf | head -30
readlink $SYS/etc/portage/make.profile
# ---- embedded-tier USE flags (no eBPF, no pam, no docs, no python, no nls)
mkdir -p $SYS/etc/portage/package.use $SYS/etc/portage/package.accept_keywords $SYS/etc/portage/package.env $SYS/etc/portage/env
cat > $SYS/etc/portage/package.use/embedded <<'EOF'
*/* -pam -nls -doc -man -selinux -audit -ipv6 -python -test -static-libs -tests -caps
sys-apps/busybox -pam -static mdev -syslog -make-symlinks
virtual/tmpfiles -systemd
sys-apps/openrc -netifrc
sys-apps/openrc -pam -ncurses -audit -selinux -newnet -sysv-utils -unicode -bash
net-firewall/nftables -python -json -xtables -readline -libedit -gmp -doc
net-dns/dnsmasq -dbus -idn -conntrack -nls -dhcp-tools -script -ipset -nettlehash -dnssec -tftp -lua -auth-dns
net-wireless/hostapd -ssl internal-tls
net-wireless/wpa_supplicant -dbus -qt5 -ssl -readline -tkip -wps -ap -fils -p2p -mesh -smartcard -uncommon-eap-types -eap-sim-aka internal-tls
sys-apps/iproute2 -iptables -berkdb -elf -bpf -atm -minimal -tipc
net-vpn/wireguard-tools -wg-quick
sys-fs/mtd-utils -ubifs -lzo -zstd -xattr
sys-fs/squashfs-tools -lz4 -lzo -zstd -xattr lzma xz
net-misc/dhcpcd -udev -ipv6 -embedded
dev-libs/openssl -asm -sctp -ktls -tls-compression -quic
EOF
mkdir -p $SYS/etc/portage/package.mask; echo 'net-misc/netifrc' > $SYS/etc/portage/package.mask/nosystemd
echo 'sys-apps/systemd-utils -udev -acl -kmod -sysctl tmpfiles' >> $SYS/etc/portage/package.use/embedded
echo "net-wireless/hostapd *" >> $SYS/etc/portage/package.accept_keywords/e
cat > $SYS/etc/portage/env/small.conf <<'EOF'
CFLAGS="-Os -pipe -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections"
LDFLAGS="-Wl,--gc-sections -Wl,-O1 -Wl,--as-needed"
EOF
echo '*/* small.conf' >> $SYS/etc/portage/package.env/small
export SYSROOT=$SYS PORTAGE_CONFIGROOT=$SYS
EM="emerge --root-deps=rdeps --keep-going --usepkg=n -q"
echo "== $(date) libs into sysroot (needed by cargo build: libmnl/libnftnl)"
ROOT=$SYS $T-emerge -v --keep-going -q net-libs/libmnl net-libs/libnftnl 2>&1 | tail -15
echo "== $(date) rootfs emerge"
mkdir -p /rootfs
ROOT=/rootfs $T-emerge --root-deps=rdeps -v --keep-going -q \
  sys-apps/busybox net-firewall/nftables net-dns/dnsmasq sys-apps/iproute2 net-vpn/wireguard-tools net-wireless/hostapd net-wireless/wpa_supplicant 2>&1 | tail -80
echo "== openrc attempt"; PYTHON_SINGLE_TARGET=python3_13 ROOT=/rootfs $T-emerge --root-deps=rdeps -v --keep-going -q sys-apps/openrc 2>&1 | tail -30
ls /rootfs /rootfs/usr/sbin /rootfs/sbin 2>/dev/null | head -60
du -sh /rootfs
echo "== $(date) done rootfs emerge"
