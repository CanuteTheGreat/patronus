#!/bin/bash
# Build a minimal Patronus installer ISO for testing
# This creates a bootable ISO with just the installer binary
# For full LiveCD, use build-iso.sh with Catalyst

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${VERSION:-0.1.0}"
TIMESTAMP=$(date +%Y%m%d)
BUILD_DIR="/tmp/patronus-iso-build-$$"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/output}"
ISO_NAME="patronus-installer-${VERSION}-${TIMESTAMP}.iso"

cleanup() {
    echo "Cleaning up..."
    rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

echo "============================================"
echo "  Patronus Minimal Installer ISO Builder"
echo "============================================"
echo "Version: ${VERSION}"
echo "Output: ${OUTPUT_DIR}/${ISO_NAME}"
echo ""

# Check dependencies - require mkisofs OR xorriso, and mksquashfs
if ! command -v mksquashfs &> /dev/null; then
    echo "Error: mksquashfs is required but not installed"
    echo "Install with: emerge sys-fs/squashfs-tools"
    exit 1
fi

if ! command -v mkisofs &> /dev/null && ! command -v xorriso &> /dev/null; then
    echo "Error: mkisofs or xorriso is required but not installed"
    echo "Install with: emerge app-cdr/cdrtools or app-cdr/xorriso"
    exit 1
fi

# Create build directories
mkdir -p "${BUILD_DIR}"/{iso,rootfs}
mkdir -p "${OUTPUT_DIR}"

# Step 1: Build the installer
echo "[1/5] Building patronus-install binary..."
cd "${REPO_ROOT}"
cargo build -p patronus-installer --release
INSTALLER_BIN="${REPO_ROOT}/target/release/patronus-install"

if [[ ! -f "${INSTALLER_BIN}" ]]; then
    echo "Error: Failed to build installer binary"
    exit 1
fi
echo "  Binary size: $(du -h "${INSTALLER_BIN}" | cut -f1)"

# Step 2: Create minimal rootfs structure
echo "[2/5] Creating minimal rootfs..."
mkdir -p "${BUILD_DIR}/rootfs"/{bin,sbin,lib,lib64,usr/{bin,lib,lib64,share},etc,dev,proc,sys,tmp,root,var/{log,run}}

# Copy installer binary
cp "${INSTALLER_BIN}" "${BUILD_DIR}/rootfs/usr/bin/"
chmod +x "${BUILD_DIR}/rootfs/usr/bin/patronus-install"

# Create symlinks
ln -s usr/bin "${BUILD_DIR}/rootfs/bin" 2>/dev/null || true
ln -s usr/lib "${BUILD_DIR}/rootfs/lib" 2>/dev/null || true
ln -s usr/lib64 "${BUILD_DIR}/rootfs/lib64" 2>/dev/null || true

# Create init script
cat > "${BUILD_DIR}/rootfs/init" << 'INIT'
#!/bin/sh
# Minimal init for Patronus installer ISO

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

# Create device nodes if needed
mknod -m 600 /dev/console c 5 1 2>/dev/null || true
mknod -m 666 /dev/null c 1 3 2>/dev/null || true
mknod -m 666 /dev/zero c 1 5 2>/dev/null || true

# Display welcome
cat << 'WELCOME'

  ____       _
 |  _ \ __ _| |_ _ __ ___  _ __  _   _ ___
 | |_) / _` | __| '__/ _ \| '_ \| | | / __|
 |  __/ (_| | |_| | | (_) | | | | |_| \__ \
 |_|   \__,_|\__|_|  \___/|_| |_|\__,_|___/

 Patronus Installer Disk

 Commands:
   patronus-install --list-disks    - List available disks
   patronus-install --tui           - Start interactive installer
   patronus-install --help          - Show all options

WELCOME

# Start shell
exec /bin/sh
INIT
chmod +x "${BUILD_DIR}/rootfs/init"

# Copy ldd dependencies for the installer
echo "[3/5] Copying library dependencies..."
copy_deps() {
    local binary="$1"
    local dest="$2"

    # Use ldd to find dependencies
    ldd "$binary" 2>/dev/null | while read -r line; do
        local lib=$(echo "$line" | grep -oE '/[^ ]+')
        if [[ -n "$lib" && -f "$lib" ]]; then
            local dir=$(dirname "$lib")
            mkdir -p "${dest}${dir}"
            cp -n "$lib" "${dest}${lib}" 2>/dev/null || true
        fi
    done
}

# Copy shell and basic utilities
if command -v busybox &> /dev/null; then
    cp "$(command -v busybox)" "${BUILD_DIR}/rootfs/usr/bin/busybox"
    chmod +x "${BUILD_DIR}/rootfs/usr/bin/busybox"

    # Create busybox symlinks
    for cmd in sh ash ls cat echo mount umount mknod mkdir rm cp mv ln grep sed awk; do
        ln -sf busybox "${BUILD_DIR}/rootfs/usr/bin/$cmd" 2>/dev/null || true
    done
else
    # Fallback: Copy individual binaries from host
    echo "  (busybox not found, copying individual utilities)"
    for cmd in sh bash ls cat echo mount umount mknod mkdir rm cp mv ln grep; do
        if command -v "$cmd" &> /dev/null; then
            cp "$(command -v "$cmd")" "${BUILD_DIR}/rootfs/usr/bin/" 2>/dev/null || true
        fi
    done
fi

# Copy required libraries
copy_deps "${INSTALLER_BIN}" "${BUILD_DIR}/rootfs"
if [[ -f "${BUILD_DIR}/rootfs/usr/bin/busybox" ]]; then
    copy_deps "${BUILD_DIR}/rootfs/usr/bin/busybox" "${BUILD_DIR}/rootfs"
elif [[ -f "${BUILD_DIR}/rootfs/usr/bin/bash" ]]; then
    copy_deps "${BUILD_DIR}/rootfs/usr/bin/bash" "${BUILD_DIR}/rootfs"
fi

# Copy dependencies for all copied utilities
for util in "${BUILD_DIR}/rootfs/usr/bin"/*; do
    if [[ -f "$util" && -x "$util" ]]; then
        copy_deps "$util" "${BUILD_DIR}/rootfs"
    fi
done

# Copy ld-linux loader if needed
if [[ -f /lib64/ld-linux-x86-64.so.2 ]]; then
    mkdir -p "${BUILD_DIR}/rootfs/lib64"
    cp /lib64/ld-linux-x86-64.so.2 "${BUILD_DIR}/rootfs/lib64/"
fi

# Step 4: Create squashfs
echo "[4/5] Creating squashfs image..."
mksquashfs "${BUILD_DIR}/rootfs" "${BUILD_DIR}/iso/rootfs.squashfs" \
    -comp zstd -Xcompression-level 19 -noappend -quiet

# Step 5: Create bootable ISO structure
echo "[5/5] Creating bootable ISO..."

# Create EFI boot structure
mkdir -p "${BUILD_DIR}/iso"/{boot/grub,EFI/BOOT}

# Create GRUB config
cat > "${BUILD_DIR}/iso/boot/grub/grub.cfg" << 'GRUB'
set timeout=5
set default=0

menuentry "Patronus Installer" {
    linux /boot/vmlinuz quiet
    initrd /boot/initrd.img
}

menuentry "Patronus Installer (verbose)" {
    linux /boot/vmlinuz
    initrd /boot/initrd.img
}
GRUB

# Note: For a full bootable ISO, we would need:
# 1. A Linux kernel (vmlinuz)
# 2. An initramfs that can mount the squashfs
# 3. syslinux/grub binaries for BIOS/UEFI boot

# For now, create a data ISO that shows the structure
echo "Note: Creating data ISO (kernel not included)"
echo "For bootable ISO, use Catalyst: ./catalyst/build-iso.sh"

# Create ISO with available tool
if command -v xorriso &> /dev/null; then
    xorriso -as mkisofs \
        -volid "PATRONUS_INSTALL" \
        -output "${OUTPUT_DIR}/${ISO_NAME}" \
        "${BUILD_DIR}/iso"
elif command -v mkisofs &> /dev/null; then
    mkisofs -o "${OUTPUT_DIR}/${ISO_NAME}" \
        -V "PATRONUS_INSTALL" \
        -R -J \
        "${BUILD_DIR}/iso"
elif command -v genisoimage &> /dev/null; then
    genisoimage -o "${OUTPUT_DIR}/${ISO_NAME}" \
        -V "PATRONUS_INSTALL" \
        -R -J \
        "${BUILD_DIR}/iso"
else
    echo "Error: No ISO creation tool found"
    exit 1
fi

echo ""
echo "============================================"
echo "  Build Complete!"
echo "============================================"
echo ""
echo "ISO created: ${OUTPUT_DIR}/${ISO_NAME}"
echo "Size: $(du -h "${OUTPUT_DIR}/${ISO_NAME}" | cut -f1)"
echo ""
echo "Contents:"
echo "  - /rootfs.squashfs - Compressed root filesystem with installer"
echo "  - /boot/grub/grub.cfg - GRUB configuration"
echo ""
echo "Note: This is a minimal installer ISO for testing."
echo "For a full bootable LiveCD, use Catalyst on a Gentoo system:"
echo "  cd gentoo/catalyst && sudo ./build-iso.sh"
echo ""
