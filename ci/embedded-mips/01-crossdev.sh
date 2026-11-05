#!/bin/bash
# Runs INSIDE gentoo/stage3:amd64-openrc: crossdev mips BE soft-float musl toolchain + ROOT emerge of the embedded tier.
set -uo pipefail
exec > >(tee -a /out/gentoo-cross.log) 2>&1
T=mips-unknown-linux-musl
echo "== $(date) start"
emerge-webrsync -q || { echo FAIL webrsync; exit 1; }
echo "MAKEOPTS=-j3" >> /etc/portage/make.conf
echo 'FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox -sandbox -usersandbox"' >> /etc/portage/make.conf
echo 'ACCEPT_LICENSE="*"' >> /etc/portage/make.conf
emerge -q --noreplace dev-vcs/git sys-devel/crossdev app-eselect/eselect-repository || exit 1
mkdir -p /etc/portage/repos.conf /var/db/repos/crossdev/{profiles,metadata}
echo crossdev > /var/db/repos/crossdev/profiles/repo_name
echo 'masters = gentoo' > /var/db/repos/crossdev/metadata/layout.conf
printf '[crossdev]\nlocation = /var/db/repos/crossdev\npriority = 10\nmasters = gentoo\nauto-sync = no\n' > /etc/portage/repos.conf/crossdev.conf
# soft-float (QCA9563 has no FPU; OpenWrt mips_24kc is soft-float, musl loader ld-musl-mips-sf.so.1)
mkdir -p /etc/portage/env /etc/portage/package.env
cat > /etc/portage/env/cross-sf-gcc.conf <<'EOF'
EXTRA_ECONF="--with-float=soft --with-arch=mips32r2 --disable-libsanitizer --disable-libgomp --disable-libquadmath --disable-libssp"
EOF
cat > /etc/portage/env/cross-sf-musl.conf <<'EOF'
CFLAGS="-O2 -pipe -march=mips32r2 -msoft-float -mabi=32"
EOF
echo "cross-$T/gcc cross-sf-gcc.conf" >> /etc/portage/package.env/cross
echo "cross-$T/musl cross-sf-musl.conf" >> /etc/portage/package.env/cross
echo "== $(date) crossdev"
crossdev -t $T --ov-output /var/db/repos/crossdev > /out/crossdev-full.log 2>&1; echo "crossdev rc=$? $(date)"; tail -30 /out/crossdev-full.log
which $T-gcc && $T-gcc -v 2>&1 | tail -3
echo 'int main(){return 0;}' > /tmp/t.c && $T-gcc -static /tmp/t.c -o /tmp/t.out && file /tmp/t.out
