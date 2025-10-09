#!/usr/bin/env bash
# Build script for Patronus with architecture-specific optimizations

set -e

ARCH="${1:-$(uname -m)}"
FEATURES="${2:-web,cli,nftables}"

echo "Building Patronus for architecture: $ARCH"
echo "Features: $FEATURES"

case "$ARCH" in
    x86_64|amd64)
        echo "Optimizing for x86_64..."
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3"
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        echo "Optimizing for ARM64..."
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3"
        TARGET="aarch64-unknown-linux-gnu"
        ;;
    riscv64)
        echo "Optimizing for RISC-V 64..."
        export RUSTFLAGS="-C target-cpu=generic-rv64 -C opt-level=3"
        TARGET="riscv64gc-unknown-linux-gnu"
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        echo "Supported: x86_64, aarch64, riscv64"
        exit 1
        ;;
esac

# Enable LTO and aggressive optimization
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3

# Build with specified features
cargo build \
    --release \
    --target "$TARGET" \
    --no-default-features \
    --features "$FEATURES" \
    -Z unstable-options \
    --bin patronus

echo "Build complete: target/$TARGET/release/patronus"
