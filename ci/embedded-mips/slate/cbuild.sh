#!/bin/bash
# INSIDE pembed-slate-c: small C daemons the cross-emerge could not produce (wpa_supplicant 9999 + openssl; dropbear + libtool),
# built from release tarballs with the crossdev toolchain into /rootfs.
set -x
T=mips-unknown-linux-musl; SYS=/usr/$T; CF="-Os -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections"
mkdir -p /tmp/cb && cd /tmp/cb
# --- wpa_supplicant 2.11 (WPA-PSK/SAE client only, nl80211, internal crypto, no EAP/TLS library)
[ -f wpa_supplicant-2.11.tar.gz ] || curl -sfLO https://w1.fi/releases/wpa_supplicant-2.11.tar.gz
rm -rf wpa_supplicant-2.11 && tar xzf wpa_supplicant-2.11.tar.gz && cd wpa_supplicant-2.11/wpa_supplicant
cat > .config <<'EOF'
CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y
CONFIG_CTRL_IFACE=y
CONFIG_BACKEND=file
CONFIG_SME=y
CONFIG_TLS=internal
CONFIG_CRYPTO=internal
CONFIG_INTERNAL_LIBTOMMATH=y
CONFIG_INTERNAL_LIBTOMMATH_FAST=y
CONFIG_NO_CONFIG_WRITE=y
CONFIG_IEEE80211N=y
CONFIG_IEEE80211AC=y
CONFIG_NO_RANDOM_POOL=y
CONFIG_GETRANDOM=y
EOF
make -j4 CC=$T-gcc CFLAGS="$CF -I$SYS/usr/include/libnl3 -MMD -O2 -Wall -g" LDFLAGS="-L$SYS/usr/lib -Wl,--gc-sections" wpa_supplicant wpa_cli > /out/wpa-build.log 2>&1; echo "wpa rc=$?"
$T-strip wpa_supplicant wpa_cli && install -m755 wpa_supplicant wpa_cli /rootfs/usr/sbin/ && ls -l /rootfs/usr/sbin/wpa_supplicant
cd /tmp/cb
# --- dropbear (bundled libtom, no zlib)
DV=2026.94; cp /var/cache/distfiles/dropbear-$DV.tar.bz2 . 2>/dev/null
[ -f dropbear-$DV.tar.bz2 ] || curl -sfLO https://matt.ucc.asn.au/dropbear/releases/dropbear-$DV.tar.bz2 || curl -sfLO https://dropbear.nl/mirror/releases/dropbear-$DV.tar.bz2
rm -rf dropbear-$DV && tar xjf dropbear-$DV.tar.bz2 && cd dropbear-$DV
./configure --host=$T --prefix=/usr --disable-zlib --enable-bundled-libtom --disable-pam --disable-lastlog --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx --disable-syslog CFLAGS="$CF" > /out/dropbear-build.log 2>&1 && \
make -j4 PROGRAMS="dropbear dbclient dropbearkey scp" MULTI=1 >> /out/dropbear-build.log 2>&1; echo "dropbear rc=$?"
$T-strip dropbearmulti && install -m755 dropbearmulti /rootfs/usr/sbin/dropbearmulti && for l in dropbear dbclient dropbearkey scp; do ln -sf dropbearmulti /rootfs/usr/sbin/$l; done
ls -l /rootfs/usr/sbin/dropbear* /rootfs/usr/sbin/scp
echo CBUILD-DONE
