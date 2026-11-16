#!/bin/bash
# INSIDE the builder image: OpenRC built from source into /out/rootfs-openrc (musl, native aarch64).
# Alpine's openrc package is built for busybox init and ships no openrc-init / openrc-shutdown, so it cannot be PID 1;
# the OpenRC variant needs both (patronus-init execs openrc-init; reboot/halt/poweroff call openrc-shutdown).
# Same layout as Alpine/Gentoo: /sbin/openrc-run, /lib/rc, /etc/init.d. Marker /out/stage-openrc.ok.
set -euo pipefail
V=${OPENRC_VERSION:-0.63.2}
SHA=${OPENRC_SHA256:-a8a890338952202b5893c53b639b098850279a7149e2fc4d42515283facd00e8}
O=/out/rootfs-openrc; rm -rf "$O"; mkdir -p /tmp/orc "$O"; cd /tmp/orc
[ -f openrc-$V.tgz ] || curl -sfL "https://github.com/OpenRC/openrc/archive/refs/tags/$V.tar.gz" -o openrc-$V.tgz
echo "$SHA  openrc-$V.tgz" | sha256sum -c - >/dev/null || { echo "stage-openrc: sha256 mismatch for openrc $V"; rm -f openrc-$V.tgz; exit 1; }
rm -rf openrc-$V; tar xzf openrc-$V.tgz; cd openrc-$V
export CFLAGS="-Os -ffunction-sections -fdata-sections" LDFLAGS="-Wl,--gc-sections"
meson setup build --prefix=/usr --sbindir=/sbin --libexecdir=/lib --sysconfdir=/etc --localstatedir=/var \
  -Dpam=false -Dselinux=disabled -Daudit=disabled -Dsysvinit=false -Dnewnet=false -Dpkgconfig=false \
  -Dbash-completions=false -Dzsh-completions=false -Dpkg_prefix=/usr -Dbranding='"Patronus"' > /out/openrc-meson.log 2>&1 \
  || { tail -30 /out/openrc-meson.log; exit 1; }
ninja -C build > /out/openrc-ninja.log 2>&1 || { tail -30 /out/openrc-ninja.log; exit 1; }
DESTDIR="$O" meson install -C build --no-rebuild > /out/openrc-install.log 2>&1
rm -rf "$O"/usr/share/man "$O"/usr/share/doc "$O"/usr/include "$O"/usr/lib/pkgconfig
find "$O" -type f -perm -u+x -exec sh -c 'head -c4 "$1" | grep ELF >/dev/null && strip --strip-unneeded "$1"' _ {} \; 2>/dev/null
ls -l "$O"/sbin/openrc-init "$O"/sbin/openrc-shutdown "$O"/sbin/openrc-run "$O"/sbin/supervise-daemon
du -sh "$O"; touch /out/stage-openrc.ok
