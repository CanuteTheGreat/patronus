#!/usr/bin/env bash
# Build Patronus Live ISO using Catalyst

set -e

ARCH="${1:-amd64}"
VERSION="0.1.0"
TIMESTAMP=$(date +%Y%m%d)

echo "Building Patronus Live ISO for ${ARCH}"
echo "Version: ${VERSION}"
echo "Timestamp: ${TIMESTAMP}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Check if catalyst is installed
if ! command -v catalyst &> /dev/null; then
    echo "Error: catalyst not found. Please install dev-util/catalyst"
    exit 1
fi

# Create working directory
WORK_DIR="/var/tmp/catalyst/patronus-${TIMESTAMP}"
mkdir -p "${WORK_DIR}"

# Prepare spec files
echo "Preparing catalyst specs..."
sed "s/@TIMESTAMP@/${TIMESTAMP}/g; s/@VERSION@/${VERSION}/g" \
    patronus-firewall.spec > "${WORK_DIR}/patronus-stage3.spec"

sed "s/@TIMESTAMP@/${TIMESTAMP}/g; s/@VERSION@/${VERSION}/g" \
    livecd-stage1.spec > "${WORK_DIR}/patronus-livecd-stage1.spec"

sed "s/@TIMESTAMP@/${TIMESTAMP}/g; s/@VERSION@/${VERSION}/g" \
    livecd-stage2.spec > "${WORK_DIR}/patronus-livecd-stage2.spec"

# Build stage3 (optional, use existing if available)
if [[ ! -f "/var/tmp/catalyst/builds/default/stage3-${ARCH}-systemd-${TIMESTAMP}.tar.xz" ]]; then
    echo "Building custom stage3..."
    catalyst -f "${WORK_DIR}/patronus-stage3.spec"
fi

# Build LiveCD stage1
echo "Building LiveCD stage1..."
catalyst -f "${WORK_DIR}/patronus-livecd-stage1.spec"

# Build LiveCD stage2 (final ISO)
echo "Building LiveCD stage2 (creating ISO)..."
catalyst -f "${WORK_DIR}/patronus-livecd-stage2.spec"

# Copy ISO to output directory
OUTPUT_DIR="./output"
mkdir -p "${OUTPUT_DIR}"

ISO_PATH="/var/tmp/catalyst/builds/patronus-${ARCH}-${TIMESTAMP}.iso"
if [[ -f "${ISO_PATH}" ]]; then
    cp "${ISO_PATH}" "${OUTPUT_DIR}/patronus-${VERSION}-${ARCH}-${TIMESTAMP}.iso"
    echo ""
    echo "✓ Build complete!"
    echo "  ISO: ${OUTPUT_DIR}/patronus-${VERSION}-${ARCH}-${TIMESTAMP}.iso"
    echo ""
    echo "Test with QEMU:"
    echo "  qemu-system-x86_64 -cdrom ${OUTPUT_DIR}/patronus-${VERSION}-${ARCH}-${TIMESTAMP}.iso -m 2048 -enable-kvm"
else
    echo "Error: ISO not found at ${ISO_PATH}"
    exit 1
fi
