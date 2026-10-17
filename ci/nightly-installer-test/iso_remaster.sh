#!/usr/bin/env bash
# Remaster a stock Alpine Extended x86_64 ISO so it boots straight into
# our unattended Patronus installer harness: the apkovl goes onto the ISO root
# (Alpine's init picks up a *.apkovl.tar.gz from the boot media by itself, no
# network needed in the initramfs - the Extended initramfs has no DHCP client,
# "ERROR: DHCP requested but not present in initrd") and the ISO's own GRUB
# config gets our kernel cmdline appended. (Extended, not Standard:
# its modloop ships zfs.ko/spl.ko built for the ISO's own kernel.) Reuses the
# ISO's existing (known-good) BIOS+UEFI hybrid boot catalog via xorriso's
# "-boot_image any replay" so we don't have to regenerate El Torito/EFI
# boot images ourselves.
set -euo pipefail

SRC_ISO="${1:?usage: iso_remaster.sh <src.iso> <apkovl.tar.gz> <out.iso>}"
APKOVL="${2:?missing apkovl file}"
OUT_ISO="${3:?missing output iso path}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/extract"
xorriso -osirrox on -indev "$SRC_ISO" -extract / "$WORK/extract" >/dev/null

CMDLINE="modules=loop,squashfs,sd-mod,usb-storage,virtio_pci,virtio_ring,virtio_net,virtio_blk,virtio_scsi,virtio_console console=tty0 console=ttyS0,115200 loglevel=8"
# x86_64 guest under QEMU/KVM on rw-man-01 (the kvm-x86_64 runner). History:
# the guest ran x86_64 under pure TCG on beauxbatons (Apple Silicon) and never
# finished booting, then aarch64 under UTM/HVF; both retired 2026-10-16 when
# the test moved to real KVM on an x86_64 host.
#
# modules=...,virtio_*: nlplug-findfs's explicit early-modprobe list (the last
# "modules=" on the cmdline wins), so the virtio disk/net drivers load
# deterministically instead of depending on mdev coldplug timing.
# console=ttyS0 LAST so it becomes /dev/console: QEMU's -serial file: is our
# only window into the guest. loglevel=8 overrides the ISO's own "quiet".

patch_grub_cfg() {
  f="$1"
  [ -f "$f" ] || return 0
  # Append our params to every "linux /boot/..." kernel line.
  sed -i -E "s#^([[:space:]]*linux[[:space:]]+/boot/[^ ]+.*)\$#\1 ${CMDLINE}#" "$f"
  echo "patched: $f"
}

# BUG FIXED HERE (was the real root cause of every "noapic"/"acpi=off"/
# "nolapic" cmdline flag never actually reaching the booted kernel,
# across 7+ prior commits: 071fa5f9 .. 9892f3a0): this find loop patches
# *every* grub.cfg discovered anywhere in the extracted ISO tree (Alpine
# Standard ships more than one -- at minimum the BIOS-path
# /boot/grub/grub.cfg, but also an arch-specific EFI one such as
# /boot/grub/x86_64-efi/grub.cfg and/or /efi/boot/grub.cfg depending on
# the release), but the old xorriso invocation below only ever mapped
# the single hardcoded /boot/grub/grub.cfg path back into the output
# ISO. Every other grub.cfg this loop patched on disk (including
# whichever one the real UEFI boot path -- confirmed by the "BdsDxe:"
# firmware messages in every captured serial log -- actually reads)
# was silently discarded, so the booted kernel always ran with the
# *original*, un-patched Alpine default cmdline. This is why the
# "Linux lts" GRUB menu entry name (untouched by our sed, since it only
# rewrites the "linux ..." line, not "menuentry ...") always matched,
# while the kernel panic/hang persisted completely unchanged no matter
# which cmdline flag was tried. Fixed by collecting every patched file
# and -map'ing each one back individually, by its real path relative to
# the extraction root, instead of a single hardcoded guess.
GRUB_CFGS=()
while IFS= read -r -d '' f; do
  patch_grub_cfg "$f"
  GRUB_CFGS+=("$f")
done < <(find "$WORK/extract" -iname 'grub.cfg' -print0)

# Also patch isolinux (BIOS-only legacy path) as a belt-and-braces fallback.
SYSLINUX_CFGS=()
while IFS= read -r f; do
  sed -i -E "s#^([[:space:]]*append[[:space:]]+.*)\$#\1 ${CMDLINE}#I" "$f" || true
  SYSLINUX_CFGS+=("$f")
done < <(find "$WORK/extract" \( -iname 'syslinux.cfg' -o -iname 'isolinux.cfg' \) 2>/dev/null)

XORRISO_MAP_ARGS=()
for f in "${GRUB_CFGS[@]}" "${SYSLINUX_CFGS[@]}"; do
  iso_path="/${f#"$WORK/extract/"}"
  XORRISO_MAP_ARGS+=(-map "$f" "$iso_path")
done

if [ "${#XORRISO_MAP_ARGS[@]}" -eq 0 ]; then
  echo "ERROR: no grub.cfg/syslinux.cfg found to patch in $SRC_ISO - refusing to produce an unmodified ISO" >&2
  exit 1
fi
XORRISO_MAP_ARGS+=(-map "$APKOVL" "/patronus.apkovl.tar.gz")

xorriso -indev "$SRC_ISO" \
        -outdev "$OUT_ISO" \
        "${XORRISO_MAP_ARGS[@]}" \
        -boot_image any replay

echo "Built remastered ISO: $OUT_ISO ($(du -h "$OUT_ISO" | cut -f1))"
