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
  # aarch64 (QEMU TCG, no KVM): the job is already at its 178-minute limit (run 8653 hit it with every test passed), so NO run is added: the
  # first shared entry becomes the ZFS-default run (>= 8 GB) and the serial-TUI cdrom run stays the < 8 GB XFS fallback (default mem 4096).
  # The TPM-unlock path is gated on x86_64 only (edk2-aarch64 + swtpm under TCG would not fit the budget).
  # ... and the open-console run (identical code path, proven on x86_64) is dropped to give the ZFS install ~19 min of room.
  _m=(); for _e in "${MATRIX[@]}"; do case "$_e" in uefi-cdrom-auto-openconsole\|*) ;; *) _m+=("$_e");; esac; done; MATRIX=("${_m[@]}")
  MATRIX[0]="uefi-usb-auto-zfs-default-notpm|--mode uefi --media usb --flow auto --mem 8192 --ssh-password-opt-in"
fi

# HEADLESS-FIRST gates (owner 2026-11-03: Patronus is a headless appliance first; console + SSH + web UI; no desktop). `--headless-gates` adds to a run, with
# no extra boot: every boot starts with an RTC 120 days off, the installed system boots with its NIC links DOWN until the login prompt, then they come
# up (late network); gated: boot never waits for the network, chrony steps the clock, WAN DHCP lease follows, web UI answers, no GUI package/process/
# service in the Portage database, no empty password / console autologin, the web admin password is not root's. Put on the first answer-file runs of
# every architecture (aarch64 = TCG with a full time budget: only its first run, the extra time is the late-link wait inside the existing boot).
_m=()
for _e in "${MATRIX[@]}"; do
  case "$_e" in
    bios-cdrom-auto-sshpw\|*|uefi-usb-auto-zfs-default-tpm\|*|bios-cdrom-auto-zfs-default-notpm\|*|uefi-usb-auto-zfs-default-notpm\|*) _m+=("$_e --headless-gates") ;;
    *) _m+=("$_e") ;;
  esac
done
MATRIX=("${_m[@]}")
