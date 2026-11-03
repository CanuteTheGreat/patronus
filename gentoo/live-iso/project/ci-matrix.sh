# Patronus QEMU matrix additions (sourced by common/ci-run.sh after the shared matrix; owner rules 2026-10-29 / 2026-11-03):
#   ZFS is the default root file system from 8 GB RAM; below that (or without a ZFS module) plain XFS; ext4 only by hand.
#   Encryption: only with a working TPM 2.0 (swtpm), unlocked by the initramfs with nobody at the console; without a TPM: not encrypted, no prompt.
if [ "$ARCH" = x86_64 ]; then
  MATRIX+=(
    # >= 8 GB, working TPM: default = ZFS, encrypted, TPM-unlocked; two guest restarts (boot service ordering) + a blank TPM must NOT release the key
    "uefi-usb-auto-zfs-default-tpm|--mode uefi --media usb --flow auto --mem 8192 --tpm swtpm --tpm-negative --restarts 2"
    # >= 8 GB, no TPM: default = ZFS, NOT encrypted, boots unattended
    "bios-cdrom-auto-zfs-default-notpm|--mode bios --media cdrom --flow auto --mem 8192 --restarts 1"
    # < 8 GB with a TPM: XFS fallback (plain XFS: LUKS would need a prompt), boots unattended
    "uefi-usb-auto-xfs-fallback-lowram-tpm|--mode uefi --media usb --flow auto --mem 4096 --tpm swtpm --restarts 1"
    # ZFS mirror, two disks, guided installer on the serial line
    "uefi-usb-auto-zfs-mirror|--mode uefi --media usb --flow auto --fs zfs --zfs-raid mirror --mem 8192 --tpm swtpm"
    # ext4 stays reachable as a manual choice, never the default
    "bios-cdrom-auto-ext4-manual|--mode bios --media cdrom --flow auto --fs ext4"
  )
else
  MATRIX+=(
    "uefi-usb-auto-zfs-default-notpm|--mode uefi --media usb --flow auto --mem 8192"
    "uefi-cdrom-auto-xfs-fallback-lowram|--mode uefi --media cdrom --flow auto --mem 4096"
  )
fi
