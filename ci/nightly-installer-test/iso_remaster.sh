#!/usr/bin/env bash
# Remaster a stock Alpine Standard x86_64 ISO so it boots straight into
# our unattended Patronus installer harness, by rewriting the ISO's own
# GRUB config to append our kernel cmdline (apkovl=/modloop=/alpine_repo=)
# instead of doing a fragile direct-kernel-boot config in UTM. Reuses the
# ISO's existing (known-good) BIOS+UEFI hybrid boot catalog via xorriso's
# "-boot_image any replay" so we don't have to regenerate El Torito/EFI
# boot images ourselves.
set -euo pipefail

SRC_ISO="${1:?usage: iso_remaster.sh <src.iso> <apkovl-url> <modloop-url> <out.iso>}"
APKOVL_URL="${2:?missing apkovl url}"
MODLOOP_URL="${3:?missing modloop url}"
OUT_ISO="${4:?missing output iso path}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/extract"
xorriso -osirrox on -indev "$SRC_ISO" -extract / "$WORK/extract" >/dev/null

CMDLINE="ip=dhcp alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v3.20/main modloop=${MODLOOP_URL} apkovl=${APKOVL_URL} console=ttyS0,115200 console=tty0 nolapic loglevel=8"
# Root cause (finally identified, not another blind flag guess): this
# VM's "System.Architecture" in vm_orchestrate.py is "x86_64" while the
# beauxbatons runner host is Apple Silicon (arm64) - there is no
# hardware accelerator for a foreign-ISA guest here (Apple's
# Hypervisor.framework / UTM's "Hypervisor" toggle only accelerates
# same-ISA arm64-on-arm64), so this is unavoidably running under pure
# QEMU TCG (full software instruction emulation). IO-APIC timer
# calibration racing against host scheduling jitter under TCG is a
# known, well-documented source of exactly this panic and exactly this
# flavor of non-determinism (same config sometimes panics, sometimes
# silently hangs with zero kernel output - confirmed directly, see
# 03aa659 and the run history around cf9fdf8/8cff65d/25de4d0). noapic,
# acpi=off, no_timer_check, and CPU=max were each tried and each
# insufficient or counterproductive (see prior history in this file's
# git blame) - none of them disable the actual Local APIC that
# setup_IO_APIC's calibration path depends on.
#
# nolapic (not noapic): disables the per-CPU Local APIC entirely,
# forcing the kernel onto the much simpler/older PIT-driven interrupt
# and timer path instead of IO-APIC+LAPIC routing - specifically
# documented upstream as the fix for buggy/emulated APIC
# implementations where IO-APIC calibration fails, which is a
# materially different (and stronger) change than noapic alone, which
# only changes IRQ routing after IO-APIC setup already ran.
#
# loglevel=8: the original image's own kernel line already carries
# "quiet" (confirmed directly in the real upstream ISO), which
# suppresses normal printk output - but not panics (KERN_EMERG forces
# through regardless), which is exactly why the only serial output we
# ever saw before this was either nothing at all, or a panic with no
# surrounding context. loglevel wins last-specified, so this appended
# "loglevel=8" overrides "quiet" and restores full kernel boot
# logging on our only real diagnostic channel into this guest.

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

xorriso -indev "$SRC_ISO" \
        -outdev "$OUT_ISO" \
        "${XORRISO_MAP_ARGS[@]}" \
        -boot_image any replay

echo "Built remastered ISO: $OUT_ISO ($(du -h "$OUT_ISO" | cut -f1))"

# Modloop filename varies by kernel flavor (lts/virt) -- hand the caller
# whatever this ISO actually ships, don't hardcode it.
MODLOOP_SRC="$(find "$WORK/extract/boot" -maxdepth 1 -iname 'modloop-*' | head -1)"
if [ -n "$MODLOOP_SRC" ]; then
  cp "$MODLOOP_SRC" "$(dirname "$OUT_ISO")/$(basename "$MODLOOP_SRC")"
  echo "Extracted modloop: $(basename "$MODLOOP_SRC")"
else
  echo "WARNING: no modloop-* found under /boot in source ISO" >&2
fi
