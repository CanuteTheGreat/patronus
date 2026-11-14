set -ex
T=mips-unknown-linux-musl; SYS=/usr/$T
cd /tmp && rm -rf ossl && mkdir ossl && cd ossl
tar xf /var/cache/distfiles/openssl-3.6.5.tar.gz 2>/dev/null || tar xf $(ls /var/cache/distfiles/openssl-3.6.5* | head -1)
cd openssl-3.6.5
./Configure linux-generic32 --cross-compile-prefix=$T- --prefix=$SYS/usr --libdir=lib no-shared no-asm no-tests no-docs no-apps no-engine no-legacy no-comp no-ssl3 no-dtls no-sctp no-quic no-idea no-seed no-rc2 no-rc4 no-bf no-cast no-md2 no-md4 no-mdc2 no-whirlpool no-camellia no-aria no-sm2 no-sm3 no-sm4 no-srp no-ocsp no-cms no-ct no-ts no-dso -Os -march=mips32r2 -msoft-float -ffunction-sections -fdata-sections
make -j8 build_libs
make install_dev
ls -l $SYS/usr/lib/libssl.a $SYS/usr/lib/libcrypto.a
