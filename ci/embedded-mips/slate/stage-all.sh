#!/bin/bash
# Runs INSIDE gentoo/stage3 (rw-man-07, arm64 host) as container pembed-slate-g.
# 1) crossdev mips-unknown-linux-musl (BE, soft-float, mips32r2)  2) sysroot libs
# 3) static OpenSSL  4) router rootfs (busybox, nft, dnsmasq, iproute2, wg, hostapd,
#    wpa_supplicant, dropbear, mtd-utils/ubi tools)  5) rust nightly.  Markers in /out/stage-*.ok
set -uo pipefail
exec > >(tee -a /out/stage-all.log) 2>&1
T=mips-unknown-linux-musl; SYS=/usr/$T
step() { echo "== $(date -u +%T) $*"; }
if [ ! -f /out/stage-crossdev.ok ]; then
  step webrsync; emerge-webrsync -q || { echo FAIL webrsync; exit 1; }
  echo "MAKEOPTS=-j4" >> /etc/portage/make.conf
  echo 'FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox -sandbox -usersandbox parallel-fetch"' >> /etc/portage/make.conf
  echo 'ACCEPT_LICENSE="*"' >> /etc/portage/make.conf
  step host tools; emerge -q --noreplace dev-vcs/git sys-devel/crossdev app-eselect/eselect-repository sys-fs/squashfs-tools dev-build/meson dev-util/gperf dev-python/jinja2 || exit 1
  mkdir -p /etc/portage/repos.conf /var/db/repos/crossdev/{profiles,metadata}
  echo crossdev > /var/db/repos/crossdev/profiles/repo_name
  echo 'masters = gentoo' > /var/db/repos/crossdev/metadata/layout.conf
  printf '[crossdev]\nlocation = /var/db/repos/crossdev\npriority = 10\nmasters = gentoo\nauto-sync = no\n' > /etc/portage/repos.conf/crossdev.conf
  mkdir -p /etc/portage/env /etc/portage/package.env
  echo 'EXTRA_ECONF="--with-float=soft --with-arch=mips32r2 --disable-libsanitizer --disable-libgomp --disable-libquadmath --disable-libssp"' > /etc/portage/env/cross-sf-gcc.conf
  echo 'CFLAGS="-O2 -pipe -march=mips32r2 -msoft-float -mabi=32"' > /etc/portage/env/cross-sf-musl.conf
  echo "cross-$T/gcc cross-sf-gcc.conf" >> /etc/portage/package.env/cross
  echo "cross-$T/musl cross-sf-musl.conf" >> /etc/portage/package.env/cross
  step crossdev; crossdev -t $T --ov-output /var/db/repos/crossdev > /out/crossdev-full.log 2>&1; rc=$?; echo "crossdev rc=$rc"; tail -20 /out/crossdev-full.log
  echo 'int main(){return 0;}' > /tmp/t.c && $T-gcc /tmp/t.c -o /tmp/t.out && file /tmp/t.out && touch /out/stage-crossdev.ok || exit 1
fi
if [ ! -f /out/stage-rootfs.ok ]; then
  mkdir -p $SYS/etc/portage/package.use $SYS/etc/portage/package.accept_keywords $SYS/etc/portage/package.env $SYS/etc/portage/env $SYS/etc/portage/package.mask
  cat > $SYS/etc/portage/package.use/embedded <<'EOF'
*/* -pam -nls -doc -man -selinux -audit -python -test -static-libs -tests -caps
sys-apps/busybox -pam -static mdev -syslog -make-symlinks
virtual/tmpfiles -systemd
net-firewall/nftables -python -json -xtables -readline -libedit -gmp -doc
net-dns/dnsmasq -dbus -idn -conntrack -nls -dhcp-tools -script -ipset -nettlehash -dnssec -tftp -lua -auth-dns
net-wireless/hostapd -ssl internal-tls
net-wireless/wpa_supplicant -dbus -qt5 -qt6 -ssl -readline -tkip -wps -ap -fils -p2p -mesh -smartcard -uncommon-eap-types -eap-sim-aka internal-tls
sys-apps/iproute2 -iptables -berkdb -elf -bpf -atm -minimal -tipc
net-vpn/wireguard-tools -wg-quick
sys-fs/mtd-utils -lzo -zstd -xattr
net-misc/dropbear -pam -shadow -syslog -zlib minimal
sys-apps/systemd-utils -udev -acl -kmod -sysctl tmpfiles
sys-apps/util-linux -cramfs -ncurses -readline -python -su -suid -logger -tty-helpers -udev -systemd -cryptsetup -audit -nls -pam -selinux -magic -rtas -uuidd -kill -hardlink -caps
sys-libs/libcap -pam -tools
EOF
  echo 'net-misc/netifrc' > $SYS/etc/portage/package.mask/nosystemd
  printf "net-wireless/hostapd **\nnet-wireless/wpa_supplicant **\nsys-fs/mtd-utils **\nnet-wireless/iw **\nnet-misc/dropbear **\nsys-libs/libucontext **\n" >> $SYS/etc/portage/package.accept_keywords/e
  cat > $SYS/etc/portage/env/small.conf <<'EOF'
CFLAGS="-Os -pipe -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections"
CXXFLAGS="-Os -pipe -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections"
LDFLAGS="-Wl,--gc-sections -Wl,-O1 -Wl,--as-needed"
EOF
  echo '*/* small.conf' >> $SYS/etc/portage/package.env/small
  mkdir -p $SYS/etc/portage/env/sys-apps; cp /w/busybox.portage-env $SYS/etc/portage/env/sys-apps/busybox   # FEATURE_PREFER_APPLETS off
  step sysroot libs; ROOT=$SYS $T-emerge -q --keep-going net-libs/libmnl net-libs/libnftnl 2>&1 | tail -15
  step rootfs emerge; mkdir -p /rootfs
  ROOT=/rootfs $T-emerge --root-deps=rdeps --keep-going -q sys-apps/busybox net-firewall/nftables net-dns/dnsmasq sys-apps/iproute2 net-vpn/wireguard-tools net-wireless/hostapd net-wireless/wpa_supplicant net-misc/dropbear sys-fs/mtd-utils net-wireless/iw 2>&1 | tail -60
  ls /rootfs/usr/sbin /rootfs/sbin /rootfs/usr/bin 2>/dev/null | tr '\n' ' '; echo; du -sh /rootfs
  [ -x /rootfs/bin/busybox ] && [ -x /rootfs/usr/sbin/hostapd ] && touch /out/stage-rootfs.ok
fi
if [ ! -f /out/stage-openssl.ok ]; then
  step openssl; (cd /tmp && rm -rf ossl && mkdir ossl && cd ossl && curl -sfLO https://github.com/openssl/openssl/releases/download/openssl-3.6.5/openssl-3.6.5.tar.gz || curl -sfLO https://www.openssl.org/source/openssl-3.6.5.tar.gz; ls -l; tar xf openssl-3.6.5.tar.gz && cd openssl-3.6.5 && \
  ./Configure linux-generic32 --cross-compile-prefix=$T- --prefix=$SYS/usr --libdir=lib no-shared no-asm no-tests no-docs no-apps no-engine no-legacy no-comp no-ssl3 no-dtls no-sctp no-quic no-idea no-seed no-rc2 no-rc4 no-bf no-cast no-md2 no-md4 no-mdc2 no-whirlpool no-camellia no-aria no-sm2 no-sm3 no-sm4 no-srp no-ocsp no-cms no-ct no-ts no-dso -Os -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections >/out/openssl.log 2>&1 && make -j4 build_libs >>/out/openssl.log 2>&1 && make install_dev >>/out/openssl.log 2>&1) && ls -l $SYS/usr/lib/libssl.a && touch /out/stage-openssl.ok
fi
if [ ! -f /out/stage-rust.ok ]; then
  step rust; command -v rustup >/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal >/dev/null 2>&1
  . "$HOME/.cargo/env"; rustup toolchain install nightly-2026-10-18 --profile minimal -c rust-src 2>&1 | tail -2 && touch /out/stage-rust.ok
fi
step all-done
