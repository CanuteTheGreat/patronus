#!/bin/bash
# INSIDE pembed-slate-g after stage-all.sh: cross-build patronus-cli + patronus-web (router feature set) for mips musl.
set -uo pipefail
exec > >(tee -a /out/patronus-build.log) 2>&1
T=mips-unknown-linux-musl; SYS=/usr/$T
emerge -q --noreplace net-libs/libmnl net-libs/libnftnl 2>&1 | tail -3   # nftnl-sys is also a host build-dependency
. "$HOME/.cargo/env"
mkdir -p /tmp/static-unwind
ln -sf "$($T-gcc -print-file-name=libgcc_eh.a)" /tmp/static-unwind/libgcc_s.a
cp -a $SYS/usr/lib/libmnl.so* $SYS/usr/lib/libnftnl.so* /tmp/static-unwind/
rm -rf /tmp/b; cp -r /w/src /tmp/b; cd /tmp/b
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/out/target-s} CARGO_BUILD_JOBS=4
export PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_SYSROOT_DIR_mips_unknown_linux_musl=$SYS PKG_CONFIG_LIBDIR_mips_unknown_linux_musl=$SYS/usr/lib/pkgconfig:$SYS/usr/share/pkgconfig
export CC_mips_unknown_linux_musl=$T-gcc AR_mips_unknown_linux_musl=$T-ar CFLAGS_mips_unknown_linux_musl="-Os -march=mips32r2 -msoft-float"
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER=$T-gcc
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-L native=/tmp/static-unwind -C force-unwind-tables=no -C link-arg=-lgcc -C target-feature=-crt-static ${SIZE_RUSTFLAGS--Zlocation-detail=none}"
# std built for size (nightly build-std feature) unless SIZE_STD= is set empty; panics lose file:line (location-detail)
STD_FEATURES=${SIZE_STD-optimize_for_size}
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort CARGO_PROFILE_RELEASE_STRIP=true
export OPENSSL_DIR=$SYS/usr OPENSSL_STATIC=1 OPENSSL_LIB_DIR=$SYS/usr/lib OPENSSL_INCLUDE_DIR=$SYS/usr/include
# Default: ONE multi-call binary (patronus-cli with web-multicall; /usr/bin/patronus-web is a link to it), 1.4 MiB xz
# smaller than separate patronus-cli + patronus-web (docs/embedded-routers.md 6c). SPECS overrides (e.g. the old pair:
# SPECS="patronus-cli:nftables,cli,dhcp-server,dns-server,uci-import patronus-web:dhcp,dns,tls-openssl").
for spec in ${SPECS:-"patronus-cli:${CLI_FEATURES:-nftables,cli,dhcp-server,dns-server,uci-import,web-multicall}"}; do
  pkg=${spec%%:*}; feat=${spec#*:}
  echo "== $(date -u +%T) cargo build $pkg ($feat)"
  cargo +nightly-2026-10-18 build --release --target $T -Z build-std=std,panic_abort ${STD_FEATURES:+-Z build-std-features=$STD_FEATURES} -p $pkg --no-default-features --features $feat > /out/build-$pkg.log 2>&1
  echo "rc=$? $(date -u +%T)"; tail -5 /out/build-$pkg.log
done
ls -l $CARGO_TARGET_DIR/$T/release/patronus-cli && touch /out/stage-patronus.ok
