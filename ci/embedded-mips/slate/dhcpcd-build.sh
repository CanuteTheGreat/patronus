#!/bin/bash
# dhcpcd for the router tier from the release tarball (the sysroot emerge linked the static OpenSSL libcrypto for its HMAC: 2.7 MB; --without-openssl uses dhcpcd's own)
exec > /out/dhcpcd-build.log 2>&1
set -ex
T=mips-unknown-linux-musl
DF=$(ls /var/cache/distfiles/dhcpcd-10.5.2.tar.xz)
rm -rf /tmp/dh && mkdir /tmp/dh && cd /tmp/dh && tar xf $DF && cd dhcpcd-10.5.2
CC=$T-gcc CFLAGS="-Os -pipe -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections" LDFLAGS="-Wl,--gc-sections -Wl,-O1" \
  ./configure --host=$T --prefix=/usr --sbindir=/sbin --libexecdir=/lib/dhcpcd --dbdir=/var/lib/dhcpcd --rundir=/run/dhcpcd \
  --sysconfdir=/etc --disable-privsep --without-udev --without-dev --disable-debug --without-openssl
make -j4
$T-strip --strip-unneeded src/dhcpcd
ls -l src/dhcpcd; $T-readelf -SW src/dhcpcd | grep -E " .text| .rodata"
make install DESTDIR=/tmp/dh/inst
install -m755 src/dhcpcd /rootfs/sbin/dhcpcd
rm -rf /rootfs/lib/dhcpcd && cp -a /tmp/dh/inst/lib/dhcpcd /rootfs/lib/dhcpcd
ls -l /rootfs/sbin/dhcpcd; ls -R /rootfs/lib/dhcpcd
echo DHCPCD-DONE
