# Hardware support plan

Goal: Patronus runs on every device that can be supported, not on a hand-picked few. The first router (GL.iNet GL-AR750S, see
[embedded-routers.md](embedded-routers.md)) was built by hand; this document turns that work into a repeatable pipeline where a
new device is **a data file**, not a new set of scripts.

Rule of thumb: Patronus reuses OpenWrt's *hardware enablement* (kernel, device tree, Wi-Fi/switch kmods and firmware, flash
layout, sysupgrade format) and replaces its *userland* (musl root with the Patronus multi-call binary, OpenRC or systemd, web UI).
Where OpenWrt supports a board, the hardware part is already done and tested by thousands of users.

## 1. Tier minimums

Source of truth: [`profiles/tiers.toml`](../profiles/tiers.toml). `hwprofile.py validate` rejects a device profile that sits in a tier
it does not meet.

| Tier | RAM | Flash / disk | Arch | libc / userland | Update | Basis |
|---|---|---|---|---|---|---|
| embedded | >= 128 MB | >= 16 MB (NOR) or NAND/eMMC | mips, mipsel, arm, arm64, x86_64 | musl, one multi-call binary, no eBPF/VPN/HA | sysupgrade, A/B root | **Measured** on the GL-AR750S: OpenRC 46 MB RAM used (68 MB free), root 9.4 MiB on 16 MiB NOR; systemd root does not fit 16 MiB NOR once ETPhoneHome is baked in (CI tracks it) |
| standard | >= 512 MB | >= 4 GB disk/eMMC/SD | arm, arm64, x86_64 | glibc, Gentoo binhost, full web UI | emerge | Design target (not yet measured on a small device) |
| full | >= 4 GB | >= 32 GB | arm64, x86_64 | glibc, Gentoo binhost, everything incl. eBPF, HA, VPN, containers | emerge | Design target; ZFS default needs >= 8 GB RAM (installer storage rules), XFS below |

64 MB RAM devices are not in any tier: the measured embedded footprint leaves too little headroom with the web UI. A CLI-only
profile for them is possible later; it needs its own measurement first.

Tiers are tightened or relaxed from measurements, never from guesses: when a smaller device is measured, change the number in
`tiers.toml` and the table above in the same commit.

## 2. Mapping OpenWrt targets to Patronus

OpenWrt groups devices by `target/subtarget` (kernel, DTS, flash drivers) and by **`arch_packages`** (the ABI: one package feed, one
musl userland). Patronus mirrors both levels:

* **`arch_packages` -> one Patronus musl userland**, built once and shared by every device of the group.
  [`profiles/arch.toml`](../profiles/arch.toml) holds one row per group: Patronus arch, CHOST, Rust target, musl loader name, default
  tier, the OpenWrt targets that use it, and whether it is `verified` (built and run) or `planned`.
* **`target/subtarget` + board id -> the kernel and modules**, taken unchanged from OpenWrt's stock sysupgrade image for that board
  (its kernel, `CONTROL`, kmods, firmware), exactly as for the GL-AR750S.
* **board id -> one device profile** (`profiles/hw/<target>-<slug>.toml`), described in section 3.

Mechanical (no new code, only a profile) when **all** hold: the board is in OpenWrt `profiles.json` with a `sysupgrade` image; its
`arch_packages` row is `verified`; its flash layout class (below) already has a packager; RAM/flash meet the tier.

| OpenWrt target | arch_packages | Typical devices | Patronus arch / default tier | Mechanical today? |
|---|---|---|---|---|
| `ath79/*` | mips_24kc | TP-Link Archer C7, GL-AR300M/AR750S | mips / embedded | yes: same userland as the reference router, new profile + layout check |
| `ramips/mt7621` | mipsel_24kc | Xiaomi/Netgear/Ubiquiti ER-X class | mipsel / embedded | needs the mipsel userland (musl `mipsel-sf`) |
| `mediatek/filogic` | aarch64_cortex-a53 | GL-MT6000, Banana Pi BPI-R3, many Wi-Fi 6 routers | arm64 / embedded (standard if eMMC >= 4 GB and RAM >= 512 MB) | needs the aarch64 userland + eMMC/UBI packager |
| `qualcommax/ipq60xx`, `ipq807x` | aarch64_cortex-a53 | GL-AX1800, Xiaomi AX3600, Linksys MX4200 | arm64 / embedded | shares the aarch64 userland with filogic; UBI-NAND packager as for the reference router |
| `ipq40xx/*` | arm_cortex-a7_neon-vfpv4 | GL-B1300, Linksys EA8300, FritzBox 4040 | arm / embedded | needs the armhf userland |
| `x86/64` | x86_64 | any PC, VM, mini-PC appliance | x86_64 / standard or full | the standard tier already builds here: needs only a profile + QEMU gate |
| `bcm27xx/bcm2711`, `bcm2710` | aarch64_cortex-a72 / a53 | Raspberry Pi 3/4/5 class | arm64 / standard | SD/disk image, shares the arm64 userland |
| `realtek/*` | mips_24kc | managed switches running OpenWrt | mips / embedded | later: needs a switch-oriented feature set |

Not supportable: boards with no OpenWrt (or equivalent mainline Linux) port, closed switch/modem firmware, and anything whose
bootloader cannot be reflashed without a hardware programmer. Those are listed in the device index as "not capable" rather than
silently omitted.

### Flash layout classes

The part that is *not* pure data is how the image is written and how rollback works. There are only a few classes; each gets one
packager (+ guard and flash tool), and every device of that class is only data:

| Class | Layout | Used by | Packager |
|---|---|---|---|
| `ubi-nand` | kernel in NOR or UBI, root as a UBI volume, own data volume | reference router (NAND), IPQ60xx/807x | exists (`ci/embedded-mips/slate`), to be generalised per arch |
| `nor-sysupgrade` | kernel + squashfs + jffs2 in one SPI NOR "firmware" partition | 16 MB NOR boards | size gate exists (`nor-budget.sh`); packager = root swap into the stock sysupgrade tar |
| `emmc-gpt` / `sdcard` | GPT disk image, A/B root partitions | filogic eMMC boards, Raspberry Pi | planned |
| `x86-disk` | the standard installer image | x86_64 | exists (installer ISO) |

A new class is the only thing that needs engineering; a new device of an existing class is a profile plus its test status.

## 3. The device-profile format (schema 1)

One TOML file per device, `profiles/hw/<openwrt-target>-<slug>.toml`, validated by `ci/hw-profile/hwprofile.py`. Image scripts read
it (`eval "$(hwprofile.py env PROFILE)"` gives `HW_*` variables) and never hard-code a board, hostname, stock image name, loader name
or NOR layout. The reference is [`profiles/hw/ath79-gl-ar750s.toml`](../profiles/hw/ath79-gl-ar750s.toml).

| Section / key | Meaning |
|---|---|
| `schema`, `tier`, `arch`, `libc`, `chost`, `ram_mb`, `flash_mb`, `init` (list: `openrc`, `systemd`) | what the device is; checked against `tiers.toml` |
| `[device]` `id`, `vendor`, `model`, `variant`, `openwrt_board`, `hostname` | identity; `openwrt_board` is the sysupgrade/fwtool board id |
| `[openwrt]` `release`, `target`, `subtarget`, `arch_packages`, `kernel`, `stock_sha256` | the OpenWrt build whose kernel and kmods are reused; pins the stock image by checksum |
| `[cargo.*]`, `use`, `[caps]`, `[web]` | feature set and memory caps for the tier |
| `[nor]` (NOR boards) `firmware_kib`, `data_min_kib`, `margin_kib` | size budget enforced by `nor-budget.sh` |
| `[limits]` (generated) | OpenWrt's `file_size_limits` for the board |
| `[status]` `level`, `evidence` | `tested` / `builds` / `untested` (section 5); `tested` requires evidence text |

Derived by the tool (so no script rebuilds a name by hand): `HW_BOARD_ID`, `HW_SYSUPGRADE_DIR`, `HW_STOCK_SYSUPGRADE`,
`HW_KERNEL_LABEL`, and every `arch.toml` field as `HW_ARCH_*` (musl loader, Rust target, ...).

Commands: `validate`, `env`, `get`, `list [--json]`, `matrix [--status builds,tested]`, and
`gen <profiles.json|URL> <board-id>`, which writes a skeleton profile from OpenWrt's own per-target metadata
(`https://downloads.openwrt.org/releases/<release>/targets/<target>/<subtarget>/profiles.json`: vendor/model, supported device ids,
stock image name and sha256, kernel version, `arch_packages`, size limits). RAM and flash are *not* in that metadata; `gen` writes the
tier minimum with a TODO, and the profile stays `untested` until someone fills it in with evidence.

Adding a device: `gen` (or copy a profile of the same layout class) -> fill RAM/flash -> `validate` -> CI builds it (section 4).

## 4. Build matrix that scales to many devices

Cost grows with **architectures**, not devices:

1. **Userland per `arch_packages`** (the expensive step: cross toolchain, musl rootfs, Rust multi-call binary, OpenRC and systemd
   trees). One job per row of `arch.toml`; output is a pack directory artifact keyed by arch + source revision. Today: mips_24kc.
2. **Image per device** (cheap, packaging only, no compiling): a matrix generated by `hwprofile.py matrix` (one entry per device and
   init variant) downloads that arch's userland pack, fetches the stock sysupgrade image named in the profile, verifies
   `stock_sha256`, runs the layout class's assembler, then the size/layout gate (`nor-budget.sh` for NOR boards, a partition budget
   from `[limits]` for the others) and `check-rootfs.sh`-style image checks.
3. **Arch gate** (section 5): booted once per arch, not per device.
4. **Publish**: downloads page and release notes generated from `hwprofile.py list --json`.

The matrix is data: adding the 30th device adds one job of step 2, and no compile. Runners: userland jobs on the arm64/x86 builders
(never a developer workstation); device jobs are small enough for any runner. CI path filters watch `profiles/**` and
`ci/hw-profile/**`.

## 5. Test strategy and status levels

* **QEMU gate per architecture** (the gate that decides `builds`): mips = `malta` big-endian (exists: `t_e2e.py`, the OpenWrt
  `malta/be` kernel for NOR roots), mipsel = `malta` little-endian, arm = `virt` armv7, arm64 = `virt` aarch64, x86_64 = q35 (KVM or
  TCG). Each boots the arch's userland with OpenRC and with systemd, then runs the same checks: all services up, web login, `patronus
  apply` ruleset, DHCP/DNS, RSS and root-size ceilings.
* **Real hardware gate** (decides `tested`): a device run on a physical board: flash through the board's sysupgrade path with the
  boot guard armed (auto-revert to stock unless the boot is confirmed), LAN client tests, Wi-Fi, reboot persistence, rollback. The
  maintainers' own boards come first; each result is recorded in the profile's `evidence` field.
* **Community reports**: a user can open an issue with the device id and a `patronus-hwreport` output (board id, kernel, boot log,
  flash layout, test checklist). A maintainer who reproduces the evidence in the report can raise `status.level`.

| Level | Meaning | Promotion rule |
|---|---|---|
| `tested` | Run on real hardware with recorded evidence | real-board checklist passed |
| `builds` | CI built the image for the device and its arch passed the QEMU gate; never run on the board | device job + arch gate green |
| `untested` | Profile exists (maybe generated), no image gate yet | default of `gen` |

The downloads page shows the level beside each device and image, with a short caution for `builds` and `untested`. A level is
**downgraded automatically** when its gate is red on main (a `tested` device whose image no longer builds shows `builds` until fixed),
so the page never claims more than CI can currently prove. No device is offered for download without a QEMU-passed arch.

## 6. Prioritised targets

Owner-supplied hardware comes first (it is the only hardware where `tested` can be earned directly), then the OpenWrt targets with the
most devices per architecture, ordered by how much of the previous work they reuse.

| # | Target | Why | Reuses | New work |
|---|---|---|---|---|
| 0 | `qualcommax/ipq60xx` (GL-AX1800 class) | maintainer hardware; in progress | aarch64 userland starts here | arm64 userland, UBI-NAND packager for arm64 |
| 1 | `x86/64` | maintainer hardware (VMs, test machines, appliance boxes); tier already exists | the standard-tier build | profile + QEMU gate + `tiers` measurement |
| 2 | `bcm27xx` (Raspberry Pi 3/4/5) | maintainer hardware; most common hobbyist board | arm64 userland (#0) | SD/disk packager, `virt` aarch64 gate |
| 3 | `ath79/*` siblings (Archer C7, GL-AR300M) | cheapest: same musl userland and packager as the reference router | everything | profiles + per-board flash-layout check |
| 4 | `ramips/mt7621` | the most widely deployed OpenWrt SoC family | NOR/NAND packagers | mipsel userland + `malta` LE gate |
| 5 | `mediatek/filogic` | current-generation Wi-Fi 6/7 routers (GL-MT6000, BPI-R3) | aarch64 userland (#0), eMMC packager (#2) | filogic kmod set, eMMC A/B |
| 6 | `ipq40xx`, `qualcommax/ipq807x` | popular older/newer Qualcomm routers | ipq807x = aarch64 (#0); ipq40xx needs armhf | armhf userland |

The "next five" after the in-progress device are rows 1-5: x86_64, Raspberry Pi, ath79 siblings, ramips mt7621, mediatek filogic.

## 7. Open items

* Generalise the reference router's packager (`ci/embedded-mips/slate`) into per-class assemblers selected by the profile's layout class;
  today the scripts read the profile but the packaging logic is still specific to the `ubi-nand`/NOR layout of that board.
* Per-arch userland jobs parameterised by `arch.toml` (the mips build scripts still hard-code the MIPS crossdev).
* `patronus-hwreport` and the status-aware downloads page.
* Measure a standard-tier device (Raspberry Pi) and a 512 MB router to replace the design targets in section 1.
