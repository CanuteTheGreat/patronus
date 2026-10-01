#!/bin/bash
# Build Patronus LiveCD ISO using Docker
# This script builds the ISO in a Gentoo container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION="${VERSION:-0.1.0}"
TIMESTAMP=$(date +%Y%m%d)
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/output}"
# "bin" (default): prebuilt dev-lang/rust-bin -- fast, good for local/dev/CI
# test builds. "source": dev-lang/rust compiled from source through Portage
# like every other package here -- slower (hours under emulation) but this
# is what a tagged production/release ISO should use.
RUST_VARIANT="${RUST_VARIANT:-bin}"
IMAGE_TAG="patronus-iso-builder:rust-${RUST_VARIANT}"

echo "============================================"
echo "  Patronus LiveCD ISO Builder"
echo "============================================"
echo "Version: ${VERSION}"
echo "Timestamp: ${TIMESTAMP}"
echo "Rust variant: ${RUST_VARIANT} ($( [[ "${RUST_VARIANT}" == bin ]] && echo 'prebuilt -- dev/test only, NOT for release' || echo 'from-source -- OK for production/release' ))"
echo ""

# Check if running as root (required for some operations)
if [[ $EUID -ne 0 ]]; then
    echo "Warning: Running as non-root user"
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required but not installed"
    exit 1
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Build the Docker image
echo "[1/4] Building Docker image (RUST_VARIANT=${RUST_VARIANT})..."
docker build -t "${IMAGE_TAG}" \
    --build-arg RUST_VARIANT="${RUST_VARIANT}" \
    -f "${SCRIPT_DIR}/Dockerfile.iso-builder" \
    "${REPO_ROOT}/gentoo"

# Note: patronus-install is built natively INSIDE the container by the
# entrypoint (gentoo/docker/build-iso-docker-entrypoint.sh), not here on
# the host -- the host arch (e.g. arm64 on an Apple Silicon/Jetson build
# machine) would produce a binary useless on the x86_64 LiveCD.

# Run the ISO build in container
echo "[2/3] Building ISO in container..."
docker run --rm \
    --privileged \
    -v "${REPO_ROOT}:/build/patronus:ro" \
    -v "${OUTPUT_DIR}:/output" \
    -e VERSION="${VERSION}" \
    -e TIMESTAMP="${TIMESTAMP}" \
    "${IMAGE_TAG}"

# Verify output
echo "[3/3] Verifying output..."
ISO_FILE="${OUTPUT_DIR}/patronus-${VERSION}-amd64-${TIMESTAMP}.iso"

if [[ -f "${ISO_FILE}" ]]; then
    echo ""
    echo "============================================"
    echo "  Build Complete!"
    echo "============================================"
    echo "ISO: ${ISO_FILE}"
    echo "Size: $(du -h "${ISO_FILE}" | cut -f1)"
    echo ""
    echo "Test with QEMU:"
    echo "  qemu-system-x86_64 -cdrom ${ISO_FILE} -m 2048 -enable-kvm"
else
    echo "Error: ISO build failed"
    exit 1
fi
