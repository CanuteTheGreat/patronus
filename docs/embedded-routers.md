# Patronus on embedded routers (GL-AR750S "Slate" first)

Status: plan + feasibility spike, 2026-11-05. Nothing here has touched the real Slate.
Spike scripts: `ci/embedded-mips/` (numbered in run order). Measured numbers are marked **[measured]**,
numbers taken from other repos' docs **[documented]**, guesses **[estimate]**.

Owner order: do the Slate first, then a test VM on azkaban, then replace kingscross.
Patronus has to be "smart" enough to fit on the Slate.

## 1. Verdict

**GO for a CLI-only embedded tier on the Slate; NO-GO for the full default Patronus (web UI, eBPF, glibc) on it.**

| Question | Result |
|---|---|
| Cross-build a Gentoo MIPS BE soft-float musl toolchain + rootfs | works (crossdev stage1+stage2, `mips-unknown-linux-musl`, mips32r2 soft-float, `ld-musl-mips-sf.so.1`) |
| Cross-compile Patronus core (`patronus-cli`: store, appliers, `apply`, `applyd`) | works, **after two small source fixes** (section 8) |
| Boot it in QEMU malta (MIPS 24Kc BE) | boots, `patronus-cli apply` seeds the store and installs the nftables ruleset (`inet patronus`, 30 lines), `applyd` runs |
| ath79 GL-AR750S kernel from OpenWrt's patch set | builds: 520/520 patches apply on 6.12.113, DTS `qca9563_glinet_gl-ar750s-nor-nand.dtb`, uImage 2.28 MiB. **Not booted** (QEMU has no QCA9563 machine) |
| Fits flash | yes: kernel+rootfs 8.38 MiB vs the stock OpenWrt 25.12.6 sysupgrade 7.49 MiB (7,854,387 B); 128 MB NAND, A/B slots use about 40 MiB of reservation |
| Fits RAM | yes: 10.9 MB used after `apply` + 7.0 MB `applyd`; agents add about 20 MB **[documented budget]**; 118 MB usable |

## 2. The Slate (what we have to fit)

- GL.iNet GL-AR750S, board id `glinet,gl-ar750s-nor-nand` on official OpenWrt 25.12.x (kernel 6.12.x, ath79, `apk`),
  QCA9563 (MIPS 24Kc **big-endian**, soft-float, no FPU, **no 64-bit atomics**), 128 MB RAM (118 MB `MemTotal` in the 128 MB QEMU twin),
  16 MB NOR + 128 MB NAND, QCA9563 2.4 GHz (ath9k) + QCA9887 5 GHz (ath10k), 1 USB port.
- Hostname `slate`, MAC `e6:95:6e:49:a6:4c`, LAN 10.0.66.1, usually a **Wi-Fi client (repeater)** of the home router. It lives in the owner's bag.
- Already runs: ETPhoneHome router client (mips package 4.0 MiB installed, RSS about 3 MB **[documented]**) and the Rustinion agent
  (router build; it was OOM-killed on this unit on 2026-10-21, so the agent has a CI memory gate: `scripts/ci/agent-memory-budget/run.py`, peak anon RSS <= 12 MiB on a 128 MB OpenWrt malta/be QEMU).
- A bad `network restart` leaves it unreachable until a power cycle. Every change we make has an on-device rollback armed first.

Flash map (from OpenWrt's DTS and `glinet.sh`): NOR: U-Boot, `kernel` 4 MiB at `0x60000` (U-Boot `bootm 0x9f060000`), `nor_reserved`, ART (Wi-Fi calibration, **never overwrite**), U-Boot env.
NAND: one `ubi` MTD (128 MB). OpenWrt picks NOR or NAND with the U-Boot env `bootcount` (3 = NOR, 0 = NAND) unless the `boot_dev` switch is on.

## 3. Smart build: a hardware profile drives the component set

One input, `profiles/hw/<name>.toml`, selects the Portage profile, the USE set, the Cargo features, the init and the memory caps.
The same repo builds the 64-bit appliance and the Slate.

```toml
# profiles/hw/ath79-gl-ar750s.toml   (new; none of this exists yet)
tier        = "embedded"             # embedded | standard | full
arch        = "mips"                 # big-endian, soft-float, mips32r2
libc        = "musl"
chost       = "mips-unknown-linux-musl"
ram_mb      = 128
flash_mb    = 128                    # NAND (kernel 4 MiB slots on NOR/UBI)
init        = "busybox"              # busybox init | openrc | systemd (tier default)
rootfs      = "squashfs-xz+overlayfs"
cargo       = { features = ["nftables", "cli"], no_default_features = true,
                profile = "release-small", target = "mips-unknown-linux-musl", toolchain = "nightly + build-std" }
use         = ["-ebpf", "-pam", "-nls", "-doc", "-python", "-ipv6?", "nftables", "wireguard", "hostapd", "dnsmasq"]
caps        = { applyd_rss_mb = 10, web = "off", logs_in_ram_kb = 512, conntrack_max = 4096 }
kernel      = { source = "openwrt-patches", version = "6.12.x", dts = "qca9563_glinet_gl-ar750s-nor-nand" }
```

Tiers:

| | embedded (Slate) | standard (small x86/arm64 boxes) | full (today) |
|---|---|---|---|
| libc / init | musl, busybox init (OpenRC once its cross-emerge works) | glibc, OpenRC | glibc, systemd or OpenRC |
| Binaries | `patronus-cli` only; `apply` at boot, `applyd` root broker | + `patronus-web` | everything incl. eBPF/XDP, IDS, HA, SD-WAN |
| Firewall | nftables via libnftnl, no eBPF | nftables + eBPF where the kernel has it | same |
| DHCP/DNS | dnsmasq (or Patronus' own) | Patronus appliers + unbound/kea | same |
| Wi-Fi | hostapd, wpa_supplicant (repeater) | hostapd | hostapd |
| Storage | squashfs + overlay (UBIFS) | ZFS/XFS per the installer rules | ZFS/XFS |

Graceful degradation (all driven by the profile, not by runtime guessing):
- A feature the tier does not ship answers **501 "not available on this hardware"** in the CLI/API and is hidden in the UI. It never fakes success (same honesty rule as the web crate's `honesty_tests`).
- Each applier checks the kernel capability it needs at apply time (`nf_tables` inet family, conntrack, wireguard, vrf) and reports `unsupported` instead of failing the whole `apply`. The spike showed why: with `CONFIG_NF_TABLES_INET` off, `apply` failed with "Could not process rule" on every `ct state` line.
- Memory caps are enforced, not hoped for: cgroup `memory.max` per daemon from `caps`, bounded in-RAM log ring, conntrack cap, SQLite `cache_size`/`journal_mode` set small, no whole-file downloads in memory (the Rustinion self-update OOM on this unit was exactly that).
- eBPF is a Cargo/USE feature that is off by default for `tier != full`.

## 4. Kernel, firmware, bootloader

- **Kernel:** vanilla 6.12.113 + OpenWrt's `generic/{backport,pending,hack}-6.12` + `ath79/patches-6.12` + `files/` (GPL-2.0), the DTS from `target/linux/ath79/dts`. Mainline alone does not carry the GL-AR750S board, ath79 SoC glue for QCA9563 NAND/NOR layouts or several drivers, so we track OpenWrt's patch set per release (pinned to the OpenWrt release tag; bump with OpenWrt's kernel bump). Spike: **520 applied, 0 failed**.
- Config: OpenWrt's `config-6.12` (generic + ath79) plus `NF_TABLES_INET`, `NFT_CT/NAT/MASQ/LIMIT/LOG/REJECT`, `ATH9K`, `ATH10K_PCI`, `WIREGUARD`, no iptables, no BPF.
- **Built [measured]:** `uImage` (lzma, load/entry `0x80060000`, DTB appended) **2,385,899 B = 2.28 MiB** (stock OpenWrt 25.12.6 kernel: 3,046,454 B). 31 stripped modules (mac80211, cfg80211, ath9k, ath10k_core/pci, nf_tables, nf_conntrack, nf_nat, wireguard, ...) = 2.86 MB raw, 0.83 MB as `xz` tar. Fits the 4 MiB kernel slot with headroom.
- **ath10k firmware:** `ath10k-firmware-qca9887-ct` (Candela Tech, redistributable) from OpenWrt's feed, into `/lib/firmware/ath10k/QCA9887/hw1.0/`. ath9k needs none; calibration comes from the ART partition (DTS reads it).
- Bootloader: the stock GL.iNet U-Boot stays. We boot it the way OpenWrt does (`bootm` of a uImage), so U-Boot, ART and the env are never rewritten.

## 5. Image layout on 128 MB NAND

One UBI device (`ubi` MTD), volumes:

| Volume | Size | Purpose |
|---|---|---|
| `kernel_a`, `kernel_b` | 4 MiB each | uImage |
| `rootfs_a`, `rootfs_b` | 16 MiB each (squashfs xz, 256 K blocks; used 6.1 MiB today) | read-only system |
| `config` | 8 MiB, UBIFS | the Patronus store (`/etc/patronus`, SQLite, keys). Survives every upgrade; this is what `patronus gitops`/the importer writes |
| `overlay` | rest (about 60 MiB), UBIFS | writable overlay on `/` (logs to RAM, state here) |

A/B fits easily (about 40 MiB reserved of 128 MiB). Slot switch: U-Boot env `bootcount`/`active_slot`, rolled back automatically if the new slot does not mark itself good (an `apply` + a reachability probe) before `bootcount` reaches its limit.

**Sysupgrade compatibility:** the image is the OpenWrt `sysupgrade-tar` layout, `sysupgrade-glinet_gl-ar750s-nor-nand/{CONTROL,kernel,root}` with `BOARD=glinet_gl-ar750s-nor-nand`, plus OpenWrt's `fwtool` metadata (`supported_devices`), so OpenWrt's own `sysupgrade -n` (NAND path in `glinet.sh`/`nand_do_upgrade`) accepts it. The spike assembled such a tar (`patronus-spike-sysupgrade-*`, 8.5 MB) but only checked the format against the stock image's tar; it has **no fwtool metadata, an unbooted ath79 kernel and a demo (malta) init, so it must never be flashed**.
Recovery: the GL.iNet U-Boot failsafe (section 9). Going back to OpenWrt = flash the stock sysupgrade from either side.

## 6. Footprint budget

Flash **[measured]** (squashfs xz):

| Item | Size |
|---|---|
| kernel uImage (ath79, DTB included) | 2.28 MiB |
| rootfs base: musl, busybox 1.36, nft 1.1.7, dnsmasq 2.93, hostapd 2.11, wireguard-tools, iproute bits, libnftnl/libmnl | 3.2 MiB (3,358,720 B) |
| + `patronus-cli` (mips-musl, `-Oz`, fat LTO, panic=abort, stripped; 5,061,704 B raw) | rootfs 6.1 MiB (6,119,424 B) |
| kernel modules (xz) | 0.8 MiB |
| **Patronus core total (kernel + rootfs + modules)** | **about 9.2 MiB**; stock OpenWrt 25.12.6 sysupgrade = 7.49 MiB (kernel 2.91 + root 4.58) |
| ETPhoneHome mips client **[documented]** | about 2.4-3.1 MB binary (4.0 MiB installed package seen on this unit) |
| Rustinion agent (router build, `--no-default-features`) **[estimate]** | 4-6 MB, to be measured from the signed `mips` release |
| ath10k-ct firmware **[estimate]** | under 1 MB |
| **Total in `rootfs_a`** | about 17-20 MiB, in a 16 MiB slot **too small: make the slots 24 MiB** (still 2 x 28 MiB incl. kernel = 56 of 128 MiB) |

RAM, QEMU malta BE, 128 MB machine, 6.12.113 **[measured]**:

| State | used (`free`) |
|---|---|
| booted, busybox only | 8.8 MB |
| after `patronus-cli apply` (store created, 776 KB SQLite file, ruleset installed) | 10.9 MB (+2.1) |
| `patronus-cli applyd` resident | RSS **6.99 MB** (HWM 6.99) |
| dnsmasq idle | about +0.4 MB |
| ETPhoneHome RSS **[documented]** | about 3 MB (needs 8 MB free) |
| Rustinion agent peak anon RSS **[documented gate]** | <= 12 MiB |
| **Sum** | about 10.9 + 7 + 3 + 12 + 1 = **about 34 MB of 118 MB** |

Honest caveats: the QEMU kernel is the malta config, not the ath79 one (the real kernel plus ath9k/ath10k buffers and DMA pools costs more, not measured; leave 2x headroom: plan for under 70 MB of 118 MB and measure `free` on the real Slate in step B); QEMU says nothing about speed (775 MHz 24Kc; Rust fat-LTO binaries are fine, SQLite writes to NAND are the thing to watch).
`patronus-web` is **not in the embedded tier**: it is not built for mips yet and the axum + sqlx + rustls stack will not be cheap. A `web-lite` measurement is phase-1 work; until then the Slate is managed by CLI, gitops and the importer.

## 7. OpenWrt config importer (carry over the Slate's setup)

`patronus import-uci <tarball|dir>` reads a `sysupgrade -b` tarball (`etc/config/*`) offline and writes Patronus store resources (so it is also the gitops source):

| UCI file | Patronus |
|---|---|
| `network` (`interface`, `device`, `route`, bridge/VLAN, `proto dhcp/static/pppoe`) | interfaces, routes, VLANs, roles (`wan`/`lan` mapped from the `firewall` zones) |
| `wireless` (`wifi-device`, `wifi-iface` mode `sta`/`ap`, ssid, encryption, `network`) | wifi-ap + client (repeater) resources; STA entries keep their order/priority and **disabled** state (the Slate has two STA networks on radio1, one with a wrong key: import as-is, never "fix") |
| `firewall` (`zone`, `forwarding`, `rule`, `redirect`) | firewall zones/rules/NAT; `masq` -> outbound NAT |
| `dhcp` (`dnsmasq`, `dhcp`, `host`, `domain`) | DHCP/DNS applier, static leases |
| `network` `proto wireguard` + `wireguard_*` | WireGuard tunnels/peers |
| `system` | hostname, timezone, ntp |

Rules: unknown sections are listed in an `unmapped` report (never dropped silently); secrets are copied into the store's secret table, not into logs; `--dry-run` prints the `patronus apply` diff. Proof order: (1) run it on `router-slate.tar.gz` offline, (2) apply in the malta QEMU twin, (3) only then on the device. Status: **not written** (this PR is plan + spike).

## 8. Spike results and blockers (real runs on rw-man-03)

Setup: one capped container each (`--cpus 3 --memory 6-8g`), Gentoo stage3 amd64 + crossdev, Debian 12 + qemu-system-mips 7.2.

1. **Toolchain/rootfs:** crossdev `mips-unknown-linux-musl` with `--with-float=soft --with-arch=mips32r2`, then `ROOT=/rootfs mips-unknown-linux-musl-emerge` of busybox, nftables, dnsmasq, iproute2, wireguard-tools, hostapd (all OK). **Blocker (open): `sys-apps/openrc` does not cross-emerge** (needs `virtual/tmpfiles` + python for the build ROOT); `wpa_supplicant` was not part of the emerge set. The spike used busybox init. Fix: keyword/USE the python deps in the cross profile, or ship OpenRC prebuilt from a Gentoo musl binhost.
2. **Rust on MIPS32 BE:** tier-3 target, so nightly + `-Zbuild-std`. Four real blockers, all fixed or understood:
   - `patronus-cli` has an **unused** dependency on `patronus-dashboard` (nothing in `patronus-cli/src` uses it) which drags in `opentelemetry_sdk`, which needs `AtomicU64`: MIPS32 has none. Fix in this branch: drop the dependency line.
   - `patronus-network/src/sysops.rs` used an `AtomicI64` job counter. Fix in this branch: `AtomicI32`.
   - cross `pkg-config` must use the target-suffixed variables (`PKG_CONFIG_SYSROOT_DIR_mips_unknown_linux_musl`, `..._LIBDIR_...`); the unsuffixed ones also hit host build scripts (`nftnl-sys` is a build-dependency), plus the host needs native libnftnl/libmnl.
   - rustflags with the target sysroot's `-L` must be `CARGO_TARGET_<T>_RUSTFLAGS` only (a global `RUSTFLAGS` broke host build scripts: "libc.so is incompatible with elf_x86_64").
   Result: `cargo build --release --target mips-unknown-linux-musl -Zbuild-std -p patronus-cli --no-default-features --features nftables,cli` = ELF 32-bit MSB, mips32r2, o32, links only `libc.so`. Build time 34 s for the last step after deps, with `CARGO_PROFILE_RELEASE_{OPT_LEVEL=z,LTO=fat,CODEGEN_UNITS=1,PANIC=abort,STRIP=true}`.
   Not yet built for mips: `patronus-web`, any default-feature set (eBPF/libbpf, `ring`/`aws-lc-rs` TLS, libelf), the `gitops`, `wifi-ap`, `vpn-wireguard` and `dhcp/dns-server` features (each needs its own cross check).
3. **Kernel (malta):** the first malta config lacked `NF_TABLES_INET`: `patronus-cli apply` exited 1 (`apply failed for: firewall`, "Could not process rule: No such file or directory" at each `ct state`). After enabling `NF_TABLES_INET/IPV4/IPV6`, `NFT_NAT`, `NFT_FIB_INET`, `apply` succeeded and nft shows the full `inet patronus` table (input/forward/output, prerouting/postrouting NAT). The ath79 config already had `NF_TABLES_INET=y`. Lesson: the embedded kernel config is part of the profile and is gated in CI by running `patronus apply` in QEMU.
4. **ath79 kernel:** With OpenWrt's config the build failed in `fs/jffs2/compr_lzma.o` (`stddef.h` not found by the cross compiler for the bundled LZMA); set `CONFIG_JFFS2_LZMA=n` (we do not use JFFS2). The DTS Makefile needs one added line for the GL-AR750S dtb.
5. **Not proven:** the ath79 kernel booting on QCA9563 (no QEMU machine; real-board proof = the initramfs serial test in section 9, step B), Wi-Fi radios, NAND/UBI attach, the sysupgrade path, `patronus-web`, OpenRC.

## 9. Rollout and exact owner steps

Principle: the Slate stays on OpenWrt for ETPhoneHome QA until step D passes. Patronus development uses the malta QEMU twin and (phase 2) an azkaban VM. Nothing below is run without the owner.

**Safety net already in place:** `backups/router-config-pull.sh` pulls `sysupgrade -b` of the Slate (by MAC, hostname-verified) into the nightly restic job whenever it is on the LAN; last good copy is `router-slate.tar.gz`. Stock OpenWrt 25.12.6 image staged at `~/.hermes/state/patronus-embedded/openwrt-25.12.6-ath79-nand-glinet_gl-ar750s-nor-nand-squashfs-sysupgrade.bin` (sha256 `3d58b599daca2a239f745cf5d739d624d6262302000df1615295ca03c594ed03`, matches the downloads.openwrt.org `sha256sums`).

A. **Back up (owner, 10 minutes, Slate on the home Wi-Fi):**
 1. `ssh root@<slate> 'sysupgrade -b -' > slate-config-$(date +%F).tgz` (and compare with the staged one).
 2. Full flash dumps, especially ART and U-Boot env: `ssh root@<slate> 'cat /proc/mtd'`, then for each NOR partition `ssh root@<slate> 'cat /dev/mtdblockN' > mtdN-<label>.bin` (u-boot, u-boot-env, art, kernel). ART is the Wi-Fi calibration; without it the radios are lost. Keep copies on crystalcave and B2.
 3. `ssh root@<slate> 'fw_printenv' > uboot-env.txt`.
B. **Boot-test without flashing (one reboot, nothing written):** from the U-Boot console (serial, 115200 8N1, 3.3 V, hold any key at boot) `tftpboot 0x81000000 patronus-initramfs.bin; bootm 0x81000000` against a TFTP server on the LAN port. Proves the kernel/DTS/Wi-Fi/NAND attach with the OpenWrt install untouched; a power cycle returns to OpenWrt.
C. **Flash Patronus (only after B passes and a QA sign-off):** `scp` the sysupgrade image to `/tmp`, `sysupgrade -T` (test), then `sysupgrade -n /tmp/patronus-...sysupgrade.bin` (`-n`: do not keep OpenWrt's config; Patronus imports it from the saved tarball). Arm the rollback first: an on-device timer that reflashes nothing but reverts the slot (`bootcount`) if the new slot is not marked good in 5 minutes.
D. **Import the repeater config:** `patronus import-uci slate-config-*.tgz --dry-run`, review the report (two STA networks, the wrong-key one stays disabled), then apply. Never run a full network restart without the guard from the ETPhoneHome QA notes.
E. **Recovery (if it does not come up):**
 1. Unplug, hold **Reset**, plug in, release after about 5-6 s (LED pattern per GL.iNet docs; confirm on this unit when we do B): U-Boot's failsafe web page answers on `http://192.168.1.1` (static IP 192.168.1.2 on the laptop). Upload the staged stock OpenWrt `*-squashfs-sysupgrade.bin` (NOR/NAND build). Wait for the reboot (about 3-5 min).
 2. If the web failsafe does not answer: serial console (as in B), `tftpboot` the initramfs of OpenWrt 25.12.6 from the same download page, boot it, then `sysupgrade -n` the stock image from it.
 3. Wi-Fi dead after any flash: restore ART from the dump in A.2 from a booted system (`mtd write art.bin art`). Do not do this unless the radios really have no calibration.
 4. If SSH is gone but the box boots: power-cycle (70 s), the previous slot comes back by the rollback timer.
 The GL.iNet web failsafe and exact button timing are **per GL.iNet documentation and not yet verified on this unit**; step B/E will verify them before C.

What ETPhoneHome QA uses meanwhile: the Slate unchanged on OpenWrt 25.12 (router-realphone.sh, USB tests as today) plus the isolated OpenWrt container/VM path (`router-usb-realphone.sh`, `openwrt.yml` VMs). Once Patronus runs on the Slate the same scripts run against it; until then the Patronus embedded tier is exercised in QEMU malta (CI) with `patronus apply` + the nft/dnsmasq/wireguard checks.

## 10. Phases

1. **Slate (this document):** hardware profile + embedded tier, musl cross rootfs, kernel from OpenWrt patches, sysupgrade image + QEMU gate in CI, importer, web-lite measurement, A-E above.
   Exit: `patronus apply` green in malta QEMU on every push (kernel config, nft inet, wireguard, dnsmasq), a booted initramfs on the real Slate (B), then flash (C).
2. **azkaban test VM:** `standard` tier (glibc, x86_64, OpenRC, full web UI) imported from kingscross' OpenWrt config (`kingscross` is OpenWrt VM 100; its config tarball is about 10 MB and is covered by the nightly vzdump, not the router pull). Same importer, run in a VM that mirrors kingscross' interfaces on a spare bridge with test clients. Exit: LAN/WAN/VPN parity checklist passes for 7 days.
3. **kingscross replacement:** cut over in a maintenance window with the VM already proven: snapshot VM 100, switch the bridge/VLANs to the Patronus VM, keep the OpenWrt VM powered off for instant rollback for 2 weeks.

## 11. Next work items

1. Land the two source fixes (this branch) and add the `embedded` Cargo/USE profile + `profiles/hw/*.toml` loader.
2. CI job `embedded-mips` (kvm-less, QEMU TCG): crossdev (cached binhost), cross build, boot malta, `patronus-cli apply`, assert the ruleset and an RSS ceiling (applyd <= 10 MB, idle used <= 16 MB).
3. Cross-emerge OpenRC and wpa_supplicant; produce the real sysupgrade-tar with fwtool metadata.
4. Measure the signed Rustinion `mips` agent and ETPhoneHome RSS together with Patronus on the malta twin.
5. Write `patronus import-uci`; replay `router-slate.tar.gz` offline.
6. `patronus-web` mips build + memory cap, or a deliberate "CLI-only" decision for the embedded tier.
