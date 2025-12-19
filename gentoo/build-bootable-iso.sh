#!/bin/bash
#
# Quick Testing Script - NOT FOR PRODUCTION
#
# This script creates a minimal bootable ISO for testing purposes using the
# host system's kernel and utilities. It has several limitations:
#
# LIMITATIONS:
# - Uses the host system's kernel (may have module dependencies)
# - Host's glibc may require specific CPU features (AVX, etc.)
# - Not reproducible across different build hosts
# - Missing some utilities that the full system would have
#
# FOR PRODUCTION ISO:
# Use the Catalyst-based build in a Gentoo chroot:
#
#   # Set up Gentoo chroot
#   emerge -a sys-apps/catalyst
#
#   # Build the ISO
#   cd gentoo/catalyst
#   sudo ./build-iso.sh
#
# The Catalyst build:
# - Uses gentoo-kernel-bin (broad hardware support, built-in drivers)
# - Builds in isolation (reproducible)
# - Properly installs all packages from the overlay
# - Creates a production-ready LiveCD
#
# This script is for quick development testing only.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${VERSION:-0.1.0}"
TIMESTAMP=$(date +%Y%m%d)
BUILD_DIR="/tmp/patronus-bootable-iso-$$"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/output}"
ISO_NAME="patronus-${VERSION}-${TIMESTAMP}.iso"

# Use the latest available kernel
KERNEL_VERSION="${KERNEL_VERSION:-$(uname -r)}"
KERNEL_PATH="/boot/vmlinuz-${KERNEL_VERSION}"

cleanup() {
    echo "Cleaning up..."
    rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

echo "============================================"
echo "  Patronus Bootable ISO Builder"
echo "============================================"
echo "Version: ${VERSION}"
echo "Kernel: ${KERNEL_VERSION}"
echo "Output: ${OUTPUT_DIR}/${ISO_NAME}"
echo ""

# Check dependencies
MISSING_DEPS=()
for cmd in mksquashfs grub-mkrescue xorriso; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_DEPS+=("$cmd")
    fi
done

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo "Error: Missing dependencies: ${MISSING_DEPS[*]}"
    echo "Install with: emerge sys-fs/squashfs-tools sys-boot/grub app-cdr/xorriso"
    exit 1
fi

# Check for kernel
if [[ ! -f "${KERNEL_PATH}" ]]; then
    echo "Error: Kernel not found at ${KERNEL_PATH}"
    echo "Available kernels:"
    ls /boot/vmlinuz-* 2>/dev/null || echo "  None found"
    echo ""
    echo "Set KERNEL_VERSION to use a different kernel"
    exit 1
fi

# Create build directories
mkdir -p "${BUILD_DIR}"/{iso/{boot/grub,EFI/BOOT,live},rootfs,initramfs}
mkdir -p "${OUTPUT_DIR}"

# ============================================
# Step 1: Build the installer binary
# ============================================
echo "[1/6] Building patronus-install binary..."
cd "${REPO_ROOT}"

# Build with generic x86-64 target (baseline SSE2, no AVX) for maximum compatibility
# This ensures the ISO works on any x86-64 machine, not just those with AVX
echo "  Building for generic x86-64 (maximum compatibility)..."
RUSTFLAGS="-C target-cpu=x86-64" cargo build -p patronus-installer --release
INSTALLER_BIN="${REPO_ROOT}/target/release/patronus-install"

if [[ ! -f "${INSTALLER_BIN}" ]]; then
    echo "Error: Failed to build installer binary"
    exit 1
fi
echo "  Binary size: $(du -h "${INSTALLER_BIN}" | cut -f1)"

# ============================================
# Step 2: Create the root filesystem
# ============================================
echo "[2/6] Creating root filesystem..."

# Create directory structure (no symlinks initially)
mkdir -p "${BUILD_DIR}/rootfs"/{bin,sbin,dev,etc/init.d,lib64,mnt,proc,root,run,sys,tmp,usr/{bin,lib64,sbin,share},var/{log,run,tmp}}

# Function to copy binary with all dependencies
copy_with_deps() {
    local binary="$1"
    local dest_root="$2"
    local dest_bin_dir="${3:-usr/bin}"

    if [[ ! -f "$binary" ]]; then
        return 1
    fi

    # Copy the binary itself
    local bin_name=$(basename "$binary")
    mkdir -p "${dest_root}/${dest_bin_dir}"
    cp -f "$binary" "${dest_root}/${dest_bin_dir}/${bin_name}" 2>/dev/null || return 1
    chmod +x "${dest_root}/${dest_bin_dir}/${bin_name}"

    # Copy all library dependencies using for loop (avoids subshell issues)
    local lib
    for lib in $(ldd "$binary" 2>/dev/null | grep -oE '/[^ ]+'); do
        if [[ -f "$lib" ]]; then
            # Determine destination based on lib path
            if [[ "$lib" == /lib64/* ]]; then
                mkdir -p "${dest_root}/lib64"
                cp -n "$lib" "${dest_root}/lib64/" 2>/dev/null || true
            elif [[ "$lib" == /usr/lib64/* ]]; then
                mkdir -p "${dest_root}/usr/lib64"
                cp -n "$lib" "${dest_root}/usr/lib64/" 2>/dev/null || true
            elif [[ "$lib" == /usr/lib/gcc/* ]]; then
                local gcc_dir=$(dirname "$lib" | sed "s|^/|${dest_root}/|")
                mkdir -p "$gcc_dir"
                cp -n "$lib" "$gcc_dir/" 2>/dev/null || true
            else
                mkdir -p "${dest_root}/lib64"
                cp -n "$lib" "${dest_root}/lib64/" 2>/dev/null || true
            fi
        fi
    done
    return 0
}

# Copy installer binary first
echo "  Copying installer..."
copy_with_deps "${INSTALLER_BIN}" "${BUILD_DIR}/rootfs" "usr/bin"

# Copy essential utilities - prefer busybox for maximum compatibility
echo "  Copying shell utilities..."

# Check for busybox (prefer static busybox if available for max compatibility)
BUSYBOX_PATH=""
if [[ -f /bin/busybox-static ]]; then
    BUSYBOX_PATH="/bin/busybox-static"
elif command -v busybox &>/dev/null; then
    BUSYBOX_PATH="$(command -v busybox)"
fi

if [[ -n "$BUSYBOX_PATH" ]]; then
    echo "  Using busybox from $BUSYBOX_PATH"
    cp "$BUSYBOX_PATH" "${BUILD_DIR}/rootfs/usr/bin/busybox"
    chmod +x "${BUILD_DIR}/rootfs/usr/bin/busybox"

    # Copy deps only if not static
    if ldd "$BUSYBOX_PATH" 2>/dev/null | grep -q "not a dynamic"; then
        echo "  (static busybox - no library dependencies)"
    else
        copy_with_deps "$BUSYBOX_PATH" "${BUILD_DIR}/rootfs" "usr/bin"
    fi

    # Create symlinks for common commands
    for cmd in sh ash ls cat cp mv rm mkdir rmdir mount umount mknod ln grep sed awk cut head tail tr wc sort uniq tee chmod chown echo printf sleep; do
        ln -sf busybox "${BUILD_DIR}/rootfs/usr/bin/$cmd" 2>/dev/null || true
    done

    # Also copy bash for better shell experience
    util_path=$(command -v bash 2>/dev/null)
    if [[ -n "$util_path" && -f "$util_path" ]]; then
        copy_with_deps "$util_path" "${BUILD_DIR}/rootfs" "usr/bin"
    fi
else
    # No busybox - copy individual utilities from host
    echo "  (busybox not found, copying individual utilities)"
    for util in bash sh ls cat cp mv rm mkdir rmdir mount umount mknod ln grep sed awk cut head tail tr wc sort uniq tee chmod chown echo printf sleep hostname clear; do
        util_path=$(command -v "$util" 2>/dev/null)
        if [[ -n "$util_path" && -f "$util_path" ]]; then
            copy_with_deps "$util_path" "${BUILD_DIR}/rootfs" "usr/bin"
        fi
    done
fi

# Copy disk utilities needed by installer
echo "  Copying disk utilities..."
for util in lsblk blkid fdisk parted mkfs.ext4 mkfs.vfat mkswap sfdisk; do
    util_path=$(command -v "$util" 2>/dev/null)
    if [[ -n "$util_path" && -f "$util_path" ]]; then
        copy_with_deps "$util_path" "${BUILD_DIR}/rootfs" "usr/sbin"
    fi
done

# Make sure ld-linux is in place
if [[ -f /lib64/ld-linux-x86-64.so.2 ]]; then
    cp -f /lib64/ld-linux-x86-64.so.2 "${BUILD_DIR}/rootfs/lib64/"
fi

# Create bin -> usr/bin symlink for compatibility
cd "${BUILD_DIR}/rootfs"
rm -rf bin sbin lib 2>/dev/null || true
ln -sf usr/bin bin
ln -sf usr/sbin sbin
ln -sf lib64 lib
ln -sf lib64 usr/lib
cd "${REPO_ROOT}"

# Create essential device nodes script (will be run at boot)
mkdir -p "${BUILD_DIR}/rootfs/etc/init.d"
cat > "${BUILD_DIR}/rootfs/etc/init.d/devices" << 'EOF'
#!/bin/sh
mknod -m 600 /dev/console c 5 1 2>/dev/null
mknod -m 666 /dev/null c 1 3 2>/dev/null
mknod -m 666 /dev/zero c 1 5 2>/dev/null
mknod -m 666 /dev/tty c 5 0 2>/dev/null
mknod -m 666 /dev/random c 1 8 2>/dev/null
mknod -m 666 /dev/urandom c 1 9 2>/dev/null
EOF
chmod +x "${BUILD_DIR}/rootfs/etc/init.d/devices"

# Create /etc/passwd and /etc/group
cat > "${BUILD_DIR}/rootfs/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/bash
EOF

cat > "${BUILD_DIR}/rootfs/etc/group" << 'EOF'
root:x:0:
EOF

# Create shell profile
cat > "${BUILD_DIR}/rootfs/root/.profile" << 'EOF'
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export HOME=/root
export TERM=linux
alias ll='ls -la'
EOF

# ============================================
# Step 3: Create the init script for live boot
# ============================================
echo "[3/6] Creating init system..."

cat > "${BUILD_DIR}/rootfs/init" << 'INIT'
#!/bin/sh
# Patronus Live Init

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null || {
    # Fallback: create essential devices manually
    /etc/init.d/devices
}
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp

# Create device symlinks
ln -sf /proc/self/fd /dev/fd
ln -sf /proc/self/fd/0 /dev/stdin
ln -sf /proc/self/fd/1 /dev/stdout
ln -sf /proc/self/fd/2 /dev/stderr

# Set hostname
hostname patronus-live

# Clear screen and show welcome
clear
cat << 'WELCOME'

  ____       _
 |  _ \ __ _| |_ _ __ ___  _ __  _   _ ___
 | |_) / _` | __| '__/ _ \| '_ \| | | / __|
 |  __/ (_| | |_| | | (_) | | | | |_| \__ \
 |_|   \__,_|\__|_|  \___/|_| |_|\__,_|___/

 Patronus Firewall/SD-WAN - Live Installer
 ==========================================

 Commands:
   patronus-install              - Start interactive TUI installer
   patronus-install --list-disks - List available disks
   patronus-install --help       - Show all options

 Type 'patronus-install' to begin installation.

WELCOME

# Start shell - try bash first, fall back to sh (busybox) for compatibility
cd /root
if [ -x /bin/bash ]; then
    exec /bin/bash --login 2>/dev/null || exec /bin/sh
else
    exec /bin/sh
fi
INIT
chmod +x "${BUILD_DIR}/rootfs/init"

# ============================================
# Step 4: Create squashfs
# ============================================
echo "[4/6] Creating squashfs filesystem..."

# Debug: Show what's in rootfs (use stat for actual sizes due to ZFS compression)
echo "  Rootfs contents:"
echo "    Files: $(find "${BUILD_DIR}/rootfs" -type f | wc -l)"
# Use stat to get real file sizes (du -sh shows compressed size on ZFS)
ROOTFS_BYTES=$(find "${BUILD_DIR}/rootfs" -type f -exec stat -c%s {} + 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "    Size: $(numfmt --to=iec-i --suffix=B $ROOTFS_BYTES 2>/dev/null || echo "${ROOTFS_BYTES} bytes")"

mksquashfs "${BUILD_DIR}/rootfs" "${BUILD_DIR}/iso/live/filesystem.squashfs" \
    -comp zstd -Xcompression-level 19 -noappend -quiet

# Use stat for real size (du shows compressed size on ZFS)
SQUASHFS_SIZE=$(stat -c%s "${BUILD_DIR}/iso/live/filesystem.squashfs")
echo "  Squashfs size: $(numfmt --to=iec-i --suffix=B $SQUASHFS_SIZE 2>/dev/null || echo "${SQUASHFS_SIZE} bytes")"

# ============================================
# Step 5: Copy kernel and create initramfs
# ============================================
echo "[5/6] Setting up kernel and initramfs..."

# Copy kernel
cp "${KERNEL_PATH}" "${BUILD_DIR}/iso/boot/vmlinuz"
echo "  Kernel: ${KERNEL_PATH}"

# Create a minimal initramfs that loads the squashfs
INITRD_DIR="${BUILD_DIR}/initramfs"
mkdir -p "${INITRD_DIR}"/{bin,dev,etc,lib,lib64,mnt/live,proc,sys,sbin,run,newroot}

# Copy busybox if available, otherwise copy individual tools
if command -v busybox &> /dev/null; then
    cp "$(command -v busybox)" "${INITRD_DIR}/bin/busybox"
    chmod +x "${INITRD_DIR}/bin/busybox"

    # Create busybox symlinks
    for cmd in sh ash cat ls mount umount mkdir mknod switch_root sleep echo; do
        ln -sf busybox "${INITRD_DIR}/bin/$cmd"
    done
else
    # Copy individual utilities including all needed for init
    for util in sh bash mount umount mkdir mknod ls cat echo sleep; do
        util_path=$(command -v "$util" 2>/dev/null)
        if [[ -n "$util_path" && -f "$util_path" ]]; then
            cp "$util_path" "${INITRD_DIR}/bin/"
            chmod +x "${INITRD_DIR}/bin/$(basename $util_path)"
        fi
    done
    # Copy switch_root from util-linux
    if command -v switch_root &> /dev/null; then
        cp "$(command -v switch_root)" "${INITRD_DIR}/bin/"
    fi
fi

# Copy dependencies for all initramfs utilities
echo "  Copying initramfs library dependencies..."
for util in "${INITRD_DIR}/bin"/*; do
    if [[ -f "$util" && -x "$util" ]]; then
        for lib in $(ldd "$util" 2>/dev/null | grep -oE '/[^ ]+'); do
            if [[ -f "$lib" ]]; then
                if [[ "$lib" == /lib64/* ]]; then
                    mkdir -p "${INITRD_DIR}/lib64"
                    cp -n "$lib" "${INITRD_DIR}/lib64/" 2>/dev/null || true
                elif [[ "$lib" == /usr/lib64/* ]]; then
                    mkdir -p "${INITRD_DIR}/lib64"
                    cp -n "$lib" "${INITRD_DIR}/lib64/" 2>/dev/null || true
                fi
            fi
        done
    fi
done

# Ensure ld-linux is present
if [[ -f /lib64/ld-linux-x86-64.so.2 ]]; then
    mkdir -p "${INITRD_DIR}/lib64"
    cp -n /lib64/ld-linux-x86-64.so.2 "${INITRD_DIR}/lib64/" 2>/dev/null || true
fi

# Copy kernel modules needed for booting
echo "  Copying kernel modules for initramfs..."
KVER="${KERNEL_VERSION}"
MODDIR="/lib/modules/${KVER}"
if [[ -d "${MODDIR}" ]]; then
    mkdir -p "${INITRD_DIR}/lib/modules/${KVER}"

    # Copy essential modules for storage and CD-ROM
    for mod in ahci ata_piix sr_mod cdrom isofs squashfs loop; do
        modpath=$(find "${MODDIR}" -name "${mod}.ko*" 2>/dev/null | head -1)
        if [[ -n "$modpath" && -f "$modpath" ]]; then
            modname=$(basename "$modpath")
            cp "$modpath" "${INITRD_DIR}/lib/modules/${KVER}/${modname}"
            echo "    Copied: $mod"
        fi
    done

    # Copy module dependencies
    cp "${MODDIR}/modules.dep" "${INITRD_DIR}/lib/modules/${KVER}/" 2>/dev/null || true
    cp "${MODDIR}/modules.alias" "${INITRD_DIR}/lib/modules/${KVER}/" 2>/dev/null || true
fi

# Copy insmod for module loading
if command -v insmod &>/dev/null; then
    cp "$(command -v insmod)" "${INITRD_DIR}/bin/"
fi

# Create initramfs init script
cat > "${INITRD_DIR}/init" << 'INITRAMFS'
#!/bin/sh
# Patronus Initramfs Init

export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sys /sys

# Mount devtmpfs
mount -t devtmpfs dev /dev 2>/dev/null || {
    echo "devtmpfs mount failed, creating basic device nodes..."
    mknod -m 600 /dev/console c 5 1
    mknod -m 666 /dev/null c 1 3
}

# Load kernel modules for storage devices
echo "Loading kernel modules..."
# Kernel version is baked in at build time
MODPATH="/lib/modules/KERNEL_VERSION_PLACEHOLDER"
if [ -d "$MODPATH" ]; then
    # Load modules in dependency order
    for modfile in "$MODPATH"/*.ko*; do
        if [ -f "$modfile" ]; then
            modname=$(basename "$modfile" | sed 's/\.ko.*$//')
            insmod "$modfile" 2>/dev/null && echo "  Loaded: $modname"
        fi
    done
fi

# Wait for devices to settle after module loading
sleep 3

echo ""
echo "Patronus: Loading live system..."
echo ""

# Debug: Show what's in /dev
echo "  /dev contents:"
ls /dev 2>/dev/null
echo ""
echo "  Block devices from /sys:"
ls /sys/class/block 2>/dev/null || echo "    No /sys/class/block"
echo ""
echo "  Available block devices:"
ls -la /dev/sr* /dev/sd* /dev/hd* 2>/dev/null || echo "    None found via ls"

# Create mount points
mkdir -p /mnt/live /newroot

# Find the CD/DVD/USB device with our filesystem
FOUND=0

# First, try the most likely devices for a CD-ROM boot
for dev in /dev/sr0 /dev/sr1 /dev/hda /dev/hdb /dev/sda /dev/sdb /dev/sdc; do
    if [ ! -b "$dev" ]; then
        continue
    fi
    echo "  Trying $dev..."
    if mount -t iso9660 -o ro "$dev" /mnt/live 2>/dev/null; then
        if [ -f /mnt/live/live/filesystem.squashfs ]; then
            echo "  Found live filesystem on $dev"
            FOUND=1
            break
        fi
        umount /mnt/live 2>/dev/null
    fi
done

# Try with auto-detect filesystem if iso9660 failed
if [ "$FOUND" = "0" ]; then
    for dev in /dev/sr0 /dev/sr1 /dev/sda /dev/sdb; do
        if [ ! -b "$dev" ]; then
            continue
        fi
        echo "  Retry $dev (auto fs)..."
        if mount -o ro "$dev" /mnt/live 2>/dev/null; then
            if [ -f /mnt/live/live/filesystem.squashfs ]; then
                echo "  Found live filesystem on $dev"
                FOUND=1
                break
            fi
            umount /mnt/live 2>/dev/null
        fi
    done
fi

if [ "$FOUND" = "1" ] && [ -f /mnt/live/live/filesystem.squashfs ]; then
    echo "  Mounting squashfs..."

    # Need loop device for squashfs
    if [ ! -e /dev/loop0 ]; then
        mknod /dev/loop0 b 7 0
    fi

    if mount -t squashfs /mnt/live/live/filesystem.squashfs /newroot 2>/dev/null || \
       mount -t squashfs -o loop /mnt/live/live/filesystem.squashfs /newroot 2>/dev/null; then

        if [ -x /newroot/init ]; then
            echo "  Switching to live system..."

            # Move mounts to new root
            mkdir -p /newroot/mnt/cdrom
            mount --move /mnt/live /newroot/mnt/cdrom 2>/dev/null || true

            # Cleanup
            umount /proc 2>/dev/null
            umount /sys 2>/dev/null
            umount /dev 2>/dev/null

            # Switch to the real root
            exec switch_root /newroot /init
        else
            echo "ERROR: /newroot/init not found or not executable"
        fi
    else
        echo "ERROR: Failed to mount squashfs"
    fi
else
    echo "ERROR: Could not find live filesystem"
    echo "Available block devices:"
    ls -la /dev/sd* /dev/sr* /dev/hd* /dev/vd* 2>/dev/null || echo "  None found"
fi

echo ""
echo "Dropping to emergency shell..."
echo "You can try manually mounting with:"
echo "  mount -t iso9660 /dev/sr0 /mnt/live"
echo "  mount -t squashfs /mnt/live/live/filesystem.squashfs /newroot"
echo ""
exec /bin/sh
INITRAMFS
chmod +x "${INITRD_DIR}/init"

# Replace kernel version placeholder in init script
sed -i "s/KERNEL_VERSION_PLACEHOLDER/${KERNEL_VERSION}/g" "${INITRD_DIR}/init"

# Create the initramfs cpio archive
echo "  Creating initramfs..."
cd "${INITRD_DIR}"
find . | cpio -o -H newc 2>/dev/null | gzip -9 > "${BUILD_DIR}/iso/boot/initrd.img"
cd "${REPO_ROOT}"

INITRD_SIZE=$(du -h "${BUILD_DIR}/iso/boot/initrd.img" | cut -f1)
echo "  Initramfs size: ${INITRD_SIZE}"

# ============================================
# Step 6: Create GRUB configuration and bootable ISO
# ============================================
echo "[6/6] Creating bootable ISO with GRUB..."

# Create GRUB configuration
cat > "${BUILD_DIR}/iso/boot/grub/grub.cfg" << 'GRUB'
set timeout=10
set default=0

# Serial console support
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

# Search for the boot device by label or file
insmod part_gpt
insmod part_msdos
insmod iso9660
insmod fat

# Try to find the CD-ROM with our files
search --no-floppy --set=root --file /boot/vmlinuz

menuentry "Patronus Installer" {
    linux /boot/vmlinuz console=tty0 console=ttyS0,115200 quiet
    initrd /boot/initrd.img
}

menuentry "Patronus Installer (verbose)" {
    linux /boot/vmlinuz console=tty0 console=ttyS0,115200
    initrd /boot/initrd.img
}

menuentry "Patronus Installer (safe mode)" {
    linux /boot/vmlinuz console=tty0 console=ttyS0,115200 nomodeset
    initrd /boot/initrd.img
}
GRUB

# Create GRUB EFI image with embedded config
echo "  Creating GRUB EFI bootloader..."
grub-mkstandalone \
    --format=x86_64-efi \
    --output="${BUILD_DIR}/iso/EFI/BOOT/BOOTX64.EFI" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=${BUILD_DIR}/iso/boot/grub/grub.cfg"

EFI_SIZE=$(du -b "${BUILD_DIR}/iso/EFI/BOOT/BOOTX64.EFI" | cut -f1)
echo "  EFI bootloader size: $(du -h "${BUILD_DIR}/iso/EFI/BOOT/BOOTX64.EFI" | cut -f1)"

# Create EFI boot image - this MUST be a valid FAT filesystem
echo "  Creating EFI boot image..."
EFI_IMG="${BUILD_DIR}/efi.img"

# Calculate size needed (EFI binary + directory overhead, minimum 2.88MB for FAT12)
EFI_IMG_SIZE_KB=$(( (EFI_SIZE / 1024) + 512 ))
if [[ $EFI_IMG_SIZE_KB -lt 2880 ]]; then
    EFI_IMG_SIZE_KB=2880
fi

# Create and format EFI image
dd if=/dev/zero of="${EFI_IMG}" bs=1K count=${EFI_IMG_SIZE_KB} 2>/dev/null
mkfs.vfat -F 12 -n "EFISYS" "${EFI_IMG}" >/dev/null 2>&1

# Populate EFI image - we need to write the directory structure and file
# Use a simple approach: create FAT12 structure with debugfs or direct write
echo "  Populating EFI boot image..."

# Create a temporary directory for building the EFI structure
EFI_CONTENT="${BUILD_DIR}/efi_content"
mkdir -p "${EFI_CONTENT}/EFI/BOOT"
cp "${BUILD_DIR}/iso/EFI/BOOT/BOOTX64.EFI" "${EFI_CONTENT}/EFI/BOOT/"

# Use mcopy if available, otherwise try other methods
if command -v mcopy &>/dev/null; then
    # mtools approach
    mmd -i "${EFI_IMG}" ::/EFI 2>/dev/null || true
    mmd -i "${EFI_IMG}" ::/EFI/BOOT 2>/dev/null || true
    mcopy -i "${EFI_IMG}" "${EFI_CONTENT}/EFI/BOOT/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
    echo "  EFI image populated via mtools"
elif command -v fatcat &>/dev/null; then
    # fatcat approach
    fatcat -w "${EFI_IMG}" -m -d /EFI 2>/dev/null || true
    fatcat -w "${EFI_IMG}" -m -d /EFI/BOOT 2>/dev/null || true
    fatcat -w "${EFI_IMG}" -a -f "${EFI_CONTENT}/EFI/BOOT/BOOTX64.EFI" -d /EFI/BOOT/ 2>/dev/null || true
else
    # Last resort: use dd to write raw FAT structure
    # This is a simplified FAT12 writer for the EFI bootloader
    echo "  Using built-in FAT12 writer..."

    # Create a small script to use Python if available
    if command -v python3 &>/dev/null; then
        python3 << PYEOF
import os
import struct

efi_img = "${EFI_IMG}"
efi_file = "${EFI_CONTENT}/EFI/BOOT/BOOTX64.EFI"

# Read EFI file
with open(efi_file, 'rb') as f:
    efi_data = f.read()

# Read existing FAT image
with open(efi_img, 'rb') as f:
    img_data = bytearray(f.read())

# Parse boot sector
bytes_per_sector = struct.unpack('<H', img_data[11:13])[0]
sectors_per_cluster = img_data[13]
reserved_sectors = struct.unpack('<H', img_data[14:16])[0]
num_fats = img_data[16]
root_entries = struct.unpack('<H', img_data[17:19])[0]
sectors_per_fat = struct.unpack('<H', img_data[22:24])[0]

# Calculate offsets
fat_start = reserved_sectors * bytes_per_sector
root_dir_start = fat_start + (num_fats * sectors_per_fat * bytes_per_sector)
data_start = root_dir_start + (root_entries * 32)

cluster_size = sectors_per_cluster * bytes_per_sector

# Helper to write directory entry
def write_dir_entry(offset, name, ext, attr, cluster, size):
    entry = bytearray(32)
    entry[0:8] = name.ljust(8).encode()[:8]
    entry[8:11] = ext.ljust(3).encode()[:3]
    entry[11] = attr
    entry[26:28] = struct.pack('<H', cluster)
    entry[28:32] = struct.pack('<I', size)
    img_data[offset:offset+32] = entry

# Helper to write FAT entry
def write_fat12_entry(cluster, value):
    offset = fat_start + (cluster * 3) // 2
    if cluster % 2 == 0:
        img_data[offset] = value & 0xFF
        img_data[offset+1] = (img_data[offset+1] & 0xF0) | ((value >> 8) & 0x0F)
    else:
        img_data[offset] = (img_data[offset] & 0x0F) | ((value & 0x0F) << 4)
        img_data[offset+1] = (value >> 4) & 0xFF

# Create EFI directory in root
write_dir_entry(root_dir_start, "EFI", "", 0x10, 2, 0)  # Directory at cluster 2
write_fat12_entry(2, 0xFFF)  # End of chain

# Create BOOT directory in EFI directory
efi_dir_offset = data_start + (2 - 2) * cluster_size
write_dir_entry(efi_dir_offset, ".", "", 0x10, 2, 0)
write_dir_entry(efi_dir_offset + 32, "..", "", 0x10, 0, 0)
write_dir_entry(efi_dir_offset + 64, "BOOT", "", 0x10, 3, 0)  # BOOT at cluster 3
write_fat12_entry(3, 0xFFF)

# Create BOOTX64.EFI in BOOT directory
boot_dir_offset = data_start + (3 - 2) * cluster_size
write_dir_entry(boot_dir_offset, ".", "", 0x10, 3, 0)
write_dir_entry(boot_dir_offset + 32, "..", "", 0x10, 2, 0)

# Calculate clusters needed for EFI file
clusters_needed = (len(efi_data) + cluster_size - 1) // cluster_size
start_cluster = 4

write_dir_entry(boot_dir_offset + 64, "BOOTX64", "EFI", 0x20, start_cluster, len(efi_data))

# Write FAT chain for EFI file
for i in range(clusters_needed - 1):
    write_fat12_entry(start_cluster + i, start_cluster + i + 1)
write_fat12_entry(start_cluster + clusters_needed - 1, 0xFFF)

# Write EFI file data
file_offset = data_start + (start_cluster - 2) * cluster_size
img_data[file_offset:file_offset + len(efi_data)] = efi_data

# Also write to second FAT
fat2_start = fat_start + sectors_per_fat * bytes_per_sector
fat_size = sectors_per_fat * bytes_per_sector
img_data[fat2_start:fat2_start + fat_size] = img_data[fat_start:fat_start + fat_size]

# Write back
with open(efi_img, 'wb') as f:
    f.write(img_data)

print("  FAT12 image created with EFI bootloader")
PYEOF
    else
        echo "  Warning: Cannot populate EFI image (need mtools or python3)"
    fi
fi

# Copy the EFI image to the ISO directory for El Torito boot
cp "${EFI_IMG}" "${BUILD_DIR}/iso/boot/efi.img"

# Create UEFI-bootable ISO using xorriso
echo "  Creating ISO image (UEFI boot)..."
xorriso -as mkisofs \
    -o "${OUTPUT_DIR}/${ISO_NAME}" \
    -R -J -joliet-long \
    -V "PATRONUS_LIVE" \
    -eltorito-alt-boot \
    -e boot/efi.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    "${BUILD_DIR}/iso" 2>&1 | grep -v "^xorriso" || true

# Get final ISO info
ISO_SIZE=$(du -h "${OUTPUT_DIR}/${ISO_NAME}" | cut -f1)

echo ""
echo "============================================"
echo "  Build Complete!"
echo "============================================"
echo ""
echo "ISO: ${OUTPUT_DIR}/${ISO_NAME}"
echo "Size: ${ISO_SIZE}"
echo ""
echo "Boot support:"
echo "  - UEFI (GPT) - x86_64"
echo "  - USB boot"
echo "  - CD/DVD boot"
echo ""
echo "Test with QEMU (UEFI):"
echo "  qemu-system-x86_64 -cdrom ${OUTPUT_DIR}/${ISO_NAME} -m 2048 \\"
echo "    -bios /usr/share/edk2-ovmf/OVMF_CODE.fd -enable-kvm"
echo ""
echo "Write to USB:"
echo "  dd if=${OUTPUT_DIR}/${ISO_NAME} of=/dev/sdX bs=4M status=progress"
echo ""
