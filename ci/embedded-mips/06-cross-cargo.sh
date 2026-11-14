#!/bin/bash
# inside a Gentoo container that has the crossdev mips musl toolchain + libmnl/libnftnl in the sysroot
set -uo pipefail
T=mips-unknown-linux-musl
SYS=/usr/$T
exec > >(tee -a /out/rust-g.log) 2>&1
echo "== $(date) rustup"
command -v rustup >/dev/null || { curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal >/dev/null 2>&1; }
. "$HOME/.cargo/env"
rustup toolchain install nightly-2026-10-18 --profile minimal -c rust-src 2>&1 | tail -2
mkdir -p /tmp/static-unwind
ln -sf "$($T-gcc -print-file-name=libgcc_eh.a)" /tmp/static-unwind/libgcc_s.a
cp -a $SYS/usr/lib/libmnl.so* $SYS/usr/lib/libnftnl.so* /tmp/static-unwind/; ls -l /tmp/static-unwind
rm -rf /tmp/b; cp -r /w/src /tmp/b; cd /tmp/b
export CARGO_TARGET_DIR=/out/target-g CARGO_BUILD_JOBS=3
export PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_SYSROOT_DIR_mips_unknown_linux_musl=$SYS PKG_CONFIG_LIBDIR_mips_unknown_linux_musl=$SYS/usr/lib/pkgconfig:$SYS/usr/share/pkgconfig
export CC_mips_unknown_linux_musl=$T-gcc CFLAGS_mips_unknown_linux_musl="-Os -march=mips32r2 -msoft-float"
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER=$T-gcc
export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-L native=/tmp/static-unwind -C force-unwind-tables=no -C link-arg=-lgcc"
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort CARGO_PROFILE_RELEASE_STRIP=true
echo "== $(date) cargo $*"
cargo +nightly-2026-10-18 "$@"
echo "== rc=$? $(date)"
