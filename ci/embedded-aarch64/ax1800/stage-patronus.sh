#!/bin/bash
# INSIDE the builder image: native build of the multi-call patronus-cli (CLI + web UI: /usr/bin/patronus-web is a link) for
# aarch64-unknown-linux-musl (Rust tier 2, stable toolchain, no build-std). Dynamic against Alpine's musl (-crt-static:
# PAM and the other system libraries are shared). Output: $CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/patronus-cli
# Source in /w/src (the CI job copies the checkout there), log /out/patronus-build.log, marker /out/stage-patronus.ok.
set -uo pipefail
exec > >(tee -a /out/patronus-build.log) 2>&1
T=aarch64-unknown-linux-musl
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/out/target}
export RUSTFLAGS="-C target-feature=-crt-static"
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort CARGO_PROFILE_RELEASE_STRIP=true
export OPENSSL_STATIC=1 OPENSSL_DIR=/usr CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
FEATURES=${CLI_FEATURES:-nftables,cli,dhcp-server,dns-server,uci-import,wifi-ap,web-multicall,vpn-wireguard,ntp-server}
cd /w/src
echo "== $(date -u +%T) cargo build patronus-cli ($FEATURES)"
cargo build --release --target $T -p patronus-cli --no-default-features --features "$FEATURES" > /out/build-patronus-cli.log 2>&1
rc=$?; tail -3 /out/build-patronus-cli.log
[ $rc -eq 0 ] && ls -l $CARGO_TARGET_DIR/$T/release/patronus-cli && echo "$FEATURES" > /out/patronus-features && touch /out/stage-patronus.ok
exit $rc
