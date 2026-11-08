# Patronus QEMU matrix additions (sourced by common/ci-run.sh after the shared matrix; owner rules 2026-10-29 / 2026-11-03):
#   ZFS is the default root file system from 8 GB RAM; below that (or without a ZFS module) plain XFS; ext4 only by hand.
#   Encryption: only with a working TPM 2.0 (swtpm), unlocked by the initramfs with nobody at the console; without a TPM: not encrypted, no prompt.
if [ "$ARCH" = x86_64 ]; then
  # 2026-11-08: guests are 5120 MB + explicit --fs zfs, not --mem 8192: rw-man-01's kvm-x86_64 job cap is 6g (shared host budget, unchanged), and qemu with an
  # 8 GB guest + the unsquashfs/ZFS page cache got the guest OOM-killed mid-extract (runs 811..851, 'installer-finished timeout' at 'Copying the system').
  # Assertions are unchanged; the "ZFS is the default from 8 GB" choice is asserted by test_patronus_fs_policy.test_default_matrix (hwprofile.choose_fs, 8192 -> zfs).
  MATRIX+=(
    # >= 8 GB, working TPM: default = ZFS, encrypted, TPM-unlocked; two guest restarts (boot service ordering) + a blank TPM must NOT release the key
    "uefi-usb-auto-zfs-default-tpm|--mode uefi --media usb --flow auto --fs zfs --zfs-raid single --mem 5120 --tpm swtpm --tpm-negative --restarts 2"
    # >= 8 GB, no TPM: default = ZFS, NOT encrypted, boots unattended
    "bios-cdrom-auto-zfs-default-notpm|--mode bios --media cdrom --flow auto --fs zfs --zfs-raid single --mem 5120 --restarts 1"
    # < 8 GB with a TPM: XFS fallback (plain XFS: LUKS would need a prompt), boots unattended.
    # NAME LENGTH MATTERS: the harness puts QEMU unix sockets at <out>/<name>/2-installed.serial and AF_UNIX paths are capped at 107 bytes; in the job
    # (/workspace/CanuteTheGreat/patronus/iso-out/evidence/) the old name 'uefi-usb-auto-xfs-fallback-lowram-tpm' made that path 108 bytes, so the installed
    # boot never got a serial socket (runs 851, 855: "QEMU never created its serial socket in 3 tries"). Keep entry names <= 36 characters.
    "uefi-usb-auto-xfs-lowram-tpm|--mode uefi --media usb --flow auto --mem 4096 --tpm swtpm --restarts 1"
    # ZFS mirror, two disks, guided installer on the serial line
    "uefi-usb-auto-zfs-mirror|--mode uefi --media usb --flow auto --fs zfs --zfs-raid mirror --mem 5120 --tpm swtpm"
    # ext4 stays reachable as a manual choice, never the default
    "bios-cdrom-auto-ext4-manual|--mode bios --media cdrom --flow auto --fs ext4"
  )
else
  # aarch64 (QEMU TCG, no KVM): the job is already at its 178-minute limit (run 8653 hit it with every test passed), so NO run is added: the
  # first shared entry becomes the ZFS-default run (>= 8 GB) and the serial-TUI cdrom run stays the < 8 GB XFS fallback (default mem 4096).
  # The TPM-unlock path is gated on x86_64 only (edk2-aarch64 + swtpm under TCG would not fit the budget).
  # ... and the open-console run (identical code path, proven on x86_64) is dropped to give the ZFS install ~19 min of room.
  _m=(); for _e in "${MATRIX[@]}"; do case "$_e" in uefi-cdrom-auto-openconsole\|*) ;; *) _m+=("$_e");; esac; done; MATRIX=("${_m[@]}")
  # 2026-11-06: 4096 MB guest + explicit single-disk ZFS, not --mem 8192: nightly-arm64 jobs run in a 6 GiB cgroup (no swap), qemu with an 8 GB guest
# sat at the cap, the guest got soft lockups (migration/N, spl_delay_taskq) and unsquashfs onto ZFS was at 41% after 85 min (runs 726, 747). The
# "ZFS is the installer's default from 8 GB" decision is asserted by the x86_64 default runs (same installer code); this run proves the ZFS install on aarch64.
MATRIX[0]="uefi-usb-auto-zfs-default-notpm|--mode uefi --media usb --flow auto --fs zfs --zfs-raid single --ssh-password-opt-in"
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
