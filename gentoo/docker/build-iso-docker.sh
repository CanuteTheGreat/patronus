#!/bin/bash
# Build Patronus LiveCD ISO using Docker
# This script builds the ISO in a Gentoo container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION="${VERSION:-0.1.0}"
TIMESTAMP=$(date +%Y%m%d)
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/output}"

echo "============================================"
echo "  Patronus LiveCD ISO Builder"
echo "============================================"
echo "Version: ${VERSION}"
echo "Timestamp: ${TIMESTAMP}"
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
echo "[1/4] Building Docker image..."
docker build -t patronus-iso-builder:latest \
    -f "${SCRIPT_DIR}/Dockerfile.iso-builder" \
    "${REPO_ROOT}/gentoo"

# Build installer binary first (on host)
echo "[2/4] Building patronus-install binary..."
cd "${REPO_ROOT}"
cargo build -p patronus-installer --release

# Run the ISO build in container
echo "[3/4] Building ISO in container..."
docker run --rm \
    --privileged \
    -v "${REPO_ROOT}:/build/patronus:ro" \
    -v "${OUTPUT_DIR}:/output" \
    -e VERSION="${VERSION}" \
    -e TIMESTAMP="${TIMESTAMP}" \
    patronus-iso-builder:latest

# Verify output
echo "[4/4] Verifying output..."
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
