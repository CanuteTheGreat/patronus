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

CMDLINE="ip=dhcp alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v3.20/main modloop=${MODLOOP_URL} apkovl=${APKOVL_URL} console=ttyS0,115200 console=tty0 no_timer_check loglevel=8"
# no_timer_check: noapic alone (4bdbc71) did not stop the panic (3
# retried attempts all hit it identically). acpi=off on top of noapic
# (f194e4a) DID stop the panic, but then all 3 attempts hung
# completely silent instead - plausibly acpi=off disabling device
# detection paths that this UEFI/OVMF setup actually needs. Replaced
# both with no_timer_check, a kernel parameter built for exactly this
# symptom ("IO-APIC + timer doesn't work") - it skips the specific
# IO-APIC timer-interrupt validation that panics, without disabling
# ACPI or IO-APIC routing at all, so nothing else should break.
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

find "$WORK/extract" -iname 'grub.cfg' -print0 | while IFS= read -r -d '' f; do
  patch_grub_cfg "$f"
done

# Also patch isolinux (BIOS-only legacy path) as a belt-and-braces fallback.
find "$WORK/extract" -iname 'syslinux.cfg' -o -iname 'isolinux.cfg' 2>/dev/null | while read -r f; do
  sed -i -E "s#^([[:space:]]*append[[:space:]]+.*)\$#\1 ${CMDLINE}#I" "$f" || true
done

xorriso -indev "$SRC_ISO" \
        -outdev "$OUT_ISO" \
        -map "$WORK/extract/boot/grub/grub.cfg" /boot/grub/grub.cfg \
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
