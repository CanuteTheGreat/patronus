# Patronus on embedded routers (GL-AR750S "Slate" first)

Status: plan + feasibility spike, 2026-11-05; local web UI proven in QEMU 2026-11-06. Nothing here has touched the real Slate.
Spike scripts: `ci/embedded-mips/` (numbered in run order). Measured numbers are marked **[measured]**,
numbers taken from other repos' docs **[documented]**, guesses **[estimate]**.

Owner order: do the Slate first, then a test VM on azkaban, then replace kingscross.
Patronus has to be "smart" enough to fit on the Slate.

## 1. Verdict

**GO for an embedded tier on the Slate with the real local web UI (LuCI equivalent: the same `patronus-web`, same look); NO-GO for the full default Patronus (eBPF, VPN/HA/QoS pages, glibc) on it.**

The first version of this document called the web UI "out" (build effort, axum + sqlx + rustls). That was a guess. The measurements below replace it: `patronus-web` cross-builds for MIPS musl with a few small source changes, fits the rootfs slot and stays under 25 MB RSS in the malta twin. A separate `web-lite` was **not needed** and was not written.

| Question | Result |
|---|---|
| Cross-build a Gentoo MIPS BE soft-float musl toolchain + rootfs | works (crossdev stage1+stage2, `mips-unknown-linux-musl`, mips32r2 soft-float, `ld-musl-mips-sf.so.1`) |
| Cross-compile Patronus core (`patronus-cli`: store, appliers, `apply`, `applyd`) | works, **after two small source fixes** (section 8) |
| Boot it in QEMU malta (MIPS 24Kc BE) | boots, `patronus-cli apply` seeds the store and installs the nftables ruleset (`inet patronus`, 30 lines), `applyd` runs |
| ath79 GL-AR750S kernel from OpenWrt's patch set | builds: 520/520 patches apply on 6.12.113, DTS `qca9563_glinet_gl-ar750s-nor-nand.dtb`, uImage 2.28 MiB. **Not booted** (QEMU has no QCA9563 machine) |
| Fits flash | yes: rootfs with CLI **and web UI** is 9.99 MiB (10,477,568 B) in a 16 MiB slot; kernel 2.28 MiB + modules 0.8 MiB on top; stock OpenWrt 25.12.6 sysupgrade is 7.49 MiB. Adding ETPhoneHome and the Rustinion agent needs 24 MiB slots (section 6) |
| Fits RAM | yes: whole router incl. web UI uses 17.4 MB (`free`) idle and 24-26 MB after login + 14 pages; `patronus-web` RSS 16.4 MB idle, **peak 24.8 MB**; agents add about 20 MB **[documented budget]**; 118 MB usable |
| Local web UI | **works in QEMU malta**: HTTPS (self-signed) + HTTP->HTTPS redirect, first-run password page (no shipped password), login, 14 pages, firewall rule change -> `nft` changed, backup/restore, reboot from the UI, everything persists (section 6a) |

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

The profile is `profiles/hw/ath79-gl-ar750s.toml` (this branch; the loader/CI that consumes it is still work item 1). Core of it:

```toml
tier        = "embedded"
arch        = "mips"                 # big-endian, soft-float, mips32r2
libc        = "musl"
init        = "busybox"
rootfs      = "squashfs-xz+overlayfs"
[cargo.cli] package = "patronus-cli"; features = ["nftables", "cli", "dhcp-server", "dns-server"]
[cargo.web] package = "patronus-web"; features = ["dhcp", "dns", "tls-openssl"]   # no eBPF, no VPN/HA/QoS, no threat feeds
[web]  mode = "on"; https_port = 443; http_redirect = 80; lan_ip = "192.168.1.1/24"; password = "first-run"
       argon2_mem_kib = 8192; rss_mb_idle = 20; rss_mb_peak = 30; cloud_dependency = "none"
[caps] applyd_rss_mb = 10; logs_in_ram_kb = 512; conntrack_max = 4096
```

Tiers:

| | embedded (Slate) | standard (small x86/arm64 boxes) | full (today) |
|---|---|---|---|
| libc / init | musl, OpenRC or systemd (busybox = applets only) | glibc, OpenRC | glibc, systemd or OpenRC |
| Binaries | `patronus-cli` (`apply` at boot, `applyd` root broker) **+ `patronus-web`** with the router feature set (section 6a) | same, more features | everything incl. eBPF/XDP, IDS, HA, SD-WAN |
| Firewall | nftables via libnftnl, no eBPF | nftables + eBPF where the kernel has it | same |
| DHCP/DNS | dnsmasq (or Patronus' own) | Patronus appliers + unbound/kea | same |
| Wi-Fi | hostapd, wpa_supplicant (repeater) | hostapd | hostapd |
| Storage | squashfs + overlay (UBIFS) | ZFS/XFS per the installer rules | ZFS/XFS |

Graceful degradation (all driven by the profile, not by runtime guessing):
- A feature the tier does not ship answers **501 "not available on this hardware"** in the CLI/API and is hidden in the UI (done for the web UI: unbuilt pages and `/api/system/updates/*` answer 501, `GET /api/features` lists what is built and the sidebar hides the rest; proven in QEMU). It never fakes success (same honesty rule as the web crate's `honesty_tests`).
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
| + `patronus-cli` (mips-musl, `-Oz`, fat LTO, panic=abort, stripped; 5,061,704 B raw, 5,323,884 B with the dhcp/dns features) | rootfs 6.1 MiB (6,119,424 B); with dhcp/dns features and the init glue 6.2 MiB (6,225,920 B) |
| + **`patronus-web`** (12,700,016 B stripped, 3.8 MB as xz; static OpenSSL; 69 KB `libatomic.so.1`) | **rootfs 9.99 MiB (10,477,568 B): +4.05 MiB (4,251,648 B)** |
| kernel modules (xz) | 0.8 MiB |
| **Patronus total with web UI (kernel + rootfs + modules)** | **about 13.1 MiB** (2.28 + 9.99 + 0.8); CLI-only was about 9.2 MiB; stock OpenWrt 25.12.6 sysupgrade = 7.49 MiB (kernel 2.91 + root 4.58) |
| ETPhoneHome mips client **[documented]** | about 2.4-3.1 MB binary (4.0 MiB installed package seen on this unit) |
| Rustinion agent (router build, `--no-default-features`) **[estimate]** | 4-6 MB, to be measured from the signed `mips` release |
| ath10k-ct firmware **[estimate]** | under 1 MB |
| **Total in `rootfs_a`** (Patronus + web + the two agents + firmware) | about 17.5-20 MiB **[estimate for the agents]**: Patronus alone (9.99 MiB) fits a 16 MiB slot, with the agents it does not: **make the slots 24 MiB** (2 x 28 MiB incl. kernel = 56 of 128 MiB) |

RAM, QEMU malta BE, 128 MB machine, 6.12.113 **[measured]**:

| State | used (`free`) |
|---|---|
| booted, busybox only | 8.8 MB |
| after `patronus-cli apply` (store created, 776 KB SQLite file, ruleset installed) | 10.9 MB (+2.1) |
| `patronus-cli applyd` resident | RSS **6.99 MB** (HWM 6.99); 7.8 MB with the dhcp/dns features |
| dnsmasq idle | about +0.4 MB (RSS 1.0 MB) |
| **`patronus-web` idle after boot** (store open, TLS up, first-run page) | RSS **16.4 MB** |
| `patronus-web` after login + 14 pages + 4 parallel logins + 96 page loads (8 parallel) | HWM **25.0 MB**, RSS back to 17.7 MB |
| whole box (`free` used) idle with web + applyd + dnsmasq | **17.4 MB**; 24-26 MB after the page run |
| ETPhoneHome RSS **[documented]** | about 3 MB (needs 8 MB free) |
| Rustinion agent peak anon RSS **[documented gate]** | <= 12 MiB |
| **Sum** (box 26 + ETPhoneHome 3 + Rustinion 12) | **about 41 MB of 118 MB**; RSS counts shared mapped binary pages, so `free` is the lower, real number |

Honest caveats: the QEMU kernel is the malta config, not the ath79 one (the real kernel plus ath9k/ath10k buffers and DMA pools costs more, not measured; leave 2x headroom: plan for under 70 MB of 118 MB and measure `free` on the real Slate in step B); QEMU says nothing about speed (775 MHz 24Kc; Rust fat-LTO binaries are fine, SQLite writes to NAND are the thing to watch).
Speed is not measured: QEMU TCG on a fast host answered 96 page loads in 5 s; the real 775 MHz 24Kc will be slower, and the first TLS handshake/login (ECDSA signature, argon2 with 8 MiB x 4 passes) has to be timed on the real board.

## 6b. Real GL-AR750S results (2026-11-13, tooling in `ci/embedded-mips/slate/`)

Layout on the real unit: the stock OpenWrt 25.12.6 kernel (6.12.112, NOR) is untouched; the Patronus root is a squashfs in the
UBI volume `rootfs` on the NAND, settings in its own volume `patronus_data`, the previous root in `rootfs_prev`. First install
goes through `sysupgrade` (the tar carries OpenWrt fwtool metadata, `fwmeta.py`), later upgrades through `patronus-flash root`.
`patronus-guard` reverts to stock OpenWrt (its root and config are inside the image) when a boot is not confirmed within 600 s;
it fired once for real (a systemd build that froze as PID 1) and brought the unit back with no human.

| Test | busybox init (p7) | systemd v262 (sd5) |
|---|---|---|
| Web/API suite (`t_slate.py`), after a factory reset (first-run flow) and again | PASS (19 / 6 checks) | PASS (6 checks) |
| LAN client (test phone on the 5 GHz AP): lease, gateway, DNS via the router, ping/DNS/HTTP through NAT, masquerade, API drop rule enforced and removed, WAN-side closed ports | PASS 17/17 | PASS 17/17 |
| Wi-Fi WAN lease installs `default via ... proto dhcp` + resolver | PASS | PASS |
| UCI import of the unit's stock backup (network, dhcp, firewall, wireless), apply, idempotent re-run, restore the web backup | PASS (see below) | not repeated |
| A/B: `patronus-flash root` keeps settings; `rollback` p7 -> sd5 -> p7 kept `/data` and the store | PASS | PASS |
| Factory reset: settings overlay + TLS wiped, `/first-run` served again, guard confirms | PASS | not repeated |

Measured (squashfs xz; RAM = `free` / MemAvailable of 118 MB, 3 min after boot, idle with web + applyd + dnsmasq + hostapd + wpa_supplicant):

| | busybox init | systemd | delta |
|---|---|---|---|
| root squashfs | 17,839,772 B (17.01 MiB) | 20,956,296 B (19.99 MiB) | **+2.97 MiB** |
| of which the stock OpenWrt recovery root | 4.60 MiB | 4.60 MiB | |
| Patronus proper | 12.4 MiB | 15.4 MiB | |
| RAM used / available | 40.0 / 75.1 MB | 41.6 / 72.6 MB | **+1.6 MB used, -2.5 MB available** (PID 1 RSS 8.3 MB, journald 4.9 MB, mostly shared pages) |
| boot: kernel + rcS early (kmods loaded) | 25.6 s | 25.6 s | |
| boot: services up (`patronus-started` marker) | 37.9 s | 48.9 s | **+11 s** |
| restart request -> HTTPS answering | 57 s | 67 s | +10 s |

**systemd verdict: fits and works on the Slate** (128 MiB NAND, 118 MB RAM): both init systems pass the same tests, and both are offered.
It does **not** fit a 16 MiB NOR-only router: kernel 2.3 MiB + Patronus 15.4 MiB = 17.7 MiB, **1.7 MiB over** (busybox: 14.7 MiB, fits).
What would make systemd fit 16 MiB NOR: keep the OpenWrt recovery root out of the root image (own volume / NOR partition, it is already not
counted above), drop udevadm + libudev (0.25 MiB xz; no udev on this kernel anyway), libsystemd.so.0 (0.37 MiB; no client links it),
the non-essential tools (systemd-run, busctl, analyze, ...: 0.5 MiB xz) and journald with Storage=none (0.06 MiB): about 1.2 MiB, still
about 0.5 MiB short, so a NOR-only systemd build would also need `patronus-web` slimmed (it is 3.8 MiB xz). **Done 2026-11-14: both
variants fit 16 MiB NOR, and OpenRC replaced busybox init (section 6c).**

Gotchas found on the real unit (all fixed in the tree):
- busybox ash `FEATURE_PREFER_APPLETS` ran busybox's `ip` in the DHCP hook, which rejects `proto dhcp`: no default route. busybox is
  built without PREFER_APPLETS/SH_STANDALONE/SH_NOFORK (`busybox.portage-env`); the hook also retries without `proto`.
- The WAN lease wrote `<dev>.resolv` that nothing read, and `dns.mode auto` without Unbound = disabled: the WAN hook now sets the
  system resolver and router images start with `[firstboot] dns_mode = "forwarder"`.
- `sysupgrade -T` wants fwtool metadata (`fwmeta.py`); `/tmp` is small (remount 40 MiB before copying a root); busybox wget needs
  `/etc/services`; no RTC (ntpd at boot).
- After an OpenWrt sysupgrade `rootfs_data` holds all free UBI space: `patronus-flash root` drops it first (it used to delete the
  rollback root and then fail with ENOSPC).
- systemd on this kernel: no devtmpfs (tmpfs + mdev before exec), libmount must be built in (else PID 1 freezes on `mode=01777`),
  the rootfs is not merged-usr (DefaultEnvironment PATH), Patronus' template units (`patronus-dhcpc@` ...) must be installed,
  `/var/run -> ../run`, no hotplug helper creates `/dev/ubi0_N` (patronus-flash mknods it from sysfs), `/usr/sbin/reboot` is systemctl.
- The kernel reboots 1 s after a panic, so a broken init loops: the systemd wrapper counts unconfirmed boots and rolls back on the third.

UCI import (stock backup of this unit): wrote 3 interfaces (lan static 10.0.66.1/24, wwan/wan DHCP), the LAN pool, the custom
"Allow SSH" rule (as two nft rules, one per WAN interface); 10 stock rules reported as covered by defaults; open (no-encryption) APs
and Wi-Fi client networks are reported/parked, not applied; 27 items listed as not imported. Second run: "already present".
An imported `wan6` (dhcp6) now applies: both variants ship dhcpcd (section 6c).

### 6c. OpenRC + systemd as the two router variants (2026-11-14)

busybox init is no longer an image variant; busybox only provides the applets. Both variants boot through the same
`/usr/sbin/patronus-init` (`/usr/libexec/patronus/early`: mounts, mdev, kmods, the data volume and the overlays, the
factory-reset marker), then exec `openrc-init` or systemd (`/etc/patronus-init` names which); from the third unconfirmed boot the
wrapper rolls back to the previous root. Every Patronus service has an OpenRC script and a systemd unit (the tooling tests
check the pairs): patronus-board, patronus-apply, patronus-applyd, patronus-web, dropbear, patronus-ntpd, patronus-syslogd, patronus-klogd, plus the ebuild's
multiplexed per-interface scripts (patronus-dhcpc, -pppoe, -hostapd). Both carry linux-pam (`pam_unix`) for the web login,
dhcpcd 10.5.2 for DHCPv6/PD (built without OpenSSL: 332 KB) and one multi-call `patronus-cli` (`patronus-web` is a link).

Web login on the router tier = system users through PAM: there is no built-in admin. The first run (`/first-run`, while
`PATRONUS_FIRST_RUN_SETUP=1` and no account in the admin group exists) creates the first administrator as a system user
(sha512 in `/etc/shadow`, group `patronus-admin`) and then logs in through PAM like any other account. Claiming it needs
proof of ownership (since 2026-11-17, section 12.9): the one-time setup code the web service prints on the console and
writes to the root-only `/run/patronus/first-run-code`, or the unit's existing root password, within an hour of the web
service starting.

Real GL-AR750S, same build of everything else (o6 = OpenRC, sd9 = systemd, both with the per-instance supervisor lock and
the system log; o4/o5/sd8 = the same images before those two changes; p7 = the old busybox-init image, older binaries):

| | busybox init (p7) | OpenRC (o6; o4/o5) | systemd (sd9; sd8) |
|---|---|---|---|
| `t_slate.py` "first" after a factory reset (first-run creates a system user, PAM login, rules, backup/restore, syslog, load) | PASS (19) | PASS (22) | PASS (23) |
| `t_slate.py` "again" with the other variant's settings (sd9 -> o6, `/data` kept) | | PASS (9) | PASS (7, sd8) |
| LAN client (test phone on the 5 GHz AP), 17 checks | 17/17 | 17/17 | 17/17 |
| A/B: `patronus-flash root` across the variants and `rollback`, `/data` and the store kept | | PASS | PASS |
| boot-loop stop: 3 unconfirmed boots -> previous root (seen on the unit: o6 -> sd9) | | PASS | |
| system log: syslogd + klogd -> `/var/log/messages` (kernel, daemon, `logger` lines), shown on `/monitoring` | none | PASS | PASS (+ journald forwarding) |
| UCI import incl. `wan6` (dhcp6): dhcpcd runs under the init system (`dhcpcd: eth0.2 [ip4] [ip6]`) | warned (no dhcpcd) | PASS (o5) | same code path |
| root squashfs, NAND image (incl. 4.6 MiB stock recovery root) | 17.01 MiB | **14.55 MiB** | 16.45 MiB |
| 16 MiB NOR budget (kernel 2.94 MiB + root + 1 MiB settings, 16000 KiB) | | root 9.44 MiB, **2.25 MiB free** | root 11.25 MiB, **448 KiB free** |
| NOR-profile root booted in QEMU malta BE (OpenWrt 25.12.6 malta kernel 6.12.112) | | all services started | multi-user.target, all units started |
| RAM used / available, idle | 40.0 / 75.1 MB | 46.0 / 68.3 MB | 45.2 / 68.3 MB |
| boot: `patronus-started` marker | 37.9 s | 43.4 s (44.7 s after a factory reset) | 54.9 s (51.7 s after a factory reset) |

System log (both variants): busybox (USE=syslog) `syslogd -n -O /var/log/messages -s 256 -b 1` on the tmpfs `/var/log` plus
`klogd -n`, as `patronus-syslogd`/`patronus-klogd` (OpenRC scripts and systemd units). On systemd, `systemd-journald-dev-log.socket`
is masked so busybox owns `/dev/log`; journald keeps a 1 MiB volatile journal and forwards unit output and systemd's own messages
(`ForwardToSyslog=yes`) to `/run/systemd/journal/syslog`, a link to `/dev/log`, so both variants fill the same file. journald does
not forward kernel messages, so klogd runs on both. The web UI's log viewer (`/monitoring`, `$PATRONUS_SYSLOG`) and
patronus-guard's revert log read that file. Cost: a few KiB of squashfs (o5 -> o6: +4 KiB); the NOR free space is unchanged (2304 / 448 KiB).

OpenRC itself costs about 0.37 MiB xz (openrc-init, supervise-daemon, librc/libeinfo, libcap) and no resident memory beyond the
`supervise-daemon` per service (about 1 MB each, mostly shared); the rest of the RAM difference to p7 is the newer, larger binary
(PAM, multi-call). What closed the NOR gap: no embedded recovery root on NOR, 1 MiB xz blocks for the NOR root (-5.5 %), the
multi-call binary (-1.4 MiB xz), std built for size with `location-detail=none`, the login logo as WebP (388 KB PNG -> 58 KB),
the systemd tools nobody calls (udevadm, libudev, libsystemd, busctl, analyze, run0, ...), the mtd-utils test suite, libgmp and tc.
CI checks the budget for both variants on every change (`nor-ci.sh`, job "NOR tier size budget"); the per-unit Slate tests stay
manual (`t_slate.py`, `slate-lan-client.sh`).

Failsafe path C (GL U-Boot web recovery, reset button held at power-on) is **documented, not exercised**: it needs a person at the
unit. The stock GL 4.3.25 and OpenWrt 25.12.6 images are staged with verified sha256 next to the unit's mtd backups.

## 6a. Local web UI (the LuCI equivalent)

**Yes: the Slate keeps a local web UI, and it is the real Patronus UI**, not a lite copy. Decision rule that was applied: try the straight port first; fall back to a `web-lite` only if it missed the 16 MiB slot or a 25-30 MB RSS cap. It met both, so no second UI exists to maintain.

What the router build contains (`patronus-web --no-default-features --features dhcp,dns,tls-openssl`): Dashboard, Firewall (rules, NAT, aliases, logs), Interfaces (WAN/LAN roles, static/DHCP, VLAN pages are present but VLAN/PPPoE features are off), Network, Routing (static), DHCP, DNS, Monitoring, Insights, Setup wizard, System (users, backups/restore, services, reboot/shutdown), API keys, first-run page. **Hidden and 501** on this tier: VPN, HA, QoS, segmentation/time limits/DNS policy, packages (plugins), NTP page, `svc/*` pages, Portage updates. Wi-Fi AP pages need the `wifi-ap` feature (needs `segmentation`): **not built yet**, so Wi-Fi is not in the router UI today (open item).
**Not there at all yet:** firmware update/rollback from the UI (the Updates page is Portage-only and answers 501; an A/B image upload + `sysupgrade` + bootcount rollback page is open item 7), and `clients` (a connected-devices page; the DHCP page shows leases).

### Source changes this needed (all behind features; the default build is unchanged)

| Problem | Fix |
|---|---|
| `rcgen 0.11` -> `ring 0.16` and `aws-lc-rs` (axum-server `tls-rustls`) have **no MIPS support** | new web feature `tls-openssl` (axum-server `tls-openssl`, `openssl` crate, self-signed ECDSA cert via the same library); `tls-rustls` stays default; patronus-cli's `web` feature now names `patronus-web/tls-rustls` |
| OpenSSL for the target | Gentoo's `dev-libs/openssl` ebuild picks `-m64` for this crossdev target; the spike builds OpenSSL 3.6.5 itself (`ci/embedded-mips/09a-openssl-static.sh`: `linux-generic32 no-shared no-asm`, minimal ciphers) and links it statically (no `libssl.so` on the rootfs) |
| `patronus-ai` (reqwest 0.11 -> native-tls) and `patronus-monitoring` (prometheus, reqwest) pulled OpenSSL-sys + a hourly threat-feed fetcher into the web crate | new features `threat-feeds`, `journal` (default on); off on the router: threat widget honestly empty, logs read from `$PATRONUS_SYSLOG` (default `/var/log/messages`) |
| 64-bit atomics on mips32 | `libatomic.so.1` (69 KB) in the rootfs, `-C link-arg=-lgcc` |
| login hashing needed 19 MiB (argon2 default) | `PATRONUS_ARGON2_MEM_KIB=8192` (4 passes) for new hashes; verification uses each hash's own parameters, so existing hashes keep working. Without it the login peak was **37.9 MB** instead of 24.8 MB |
| anti-lockout only opened 22 + 8443 | `PATRONUS_ANTI_LOCKOUT_PORTS=22,80,443` at first-boot seeding |
| Gentoo init scripts are `openrc-run` | the router rootfs ships two 10-line sysv scripts (dnsmasq, hostapd) until OpenRC cross-emerges |

### First boot (OpenWrt-like, no cloud)

1. **Default LAN IP `192.168.1.1/24`** with DHCP `.100-.249`, WAN port as DHCP client: `[firstboot]` in `/etc/patronus/patronus.toml` is applied once by `patronus-cli apply` (store key `firstboot.lan_seeded`), after which the Interfaces/DHCP pages own the settings.
2. **HTTPS on 443 with a self-signed certificate** generated on the box at first start (ECDSA P-256, valid 10 years, back-dated so a 1970 router clock does not matter; SANs `patronus`, `patronus.local`, the LAN IP). **HTTP on 80 only answers `308` to the https URL** (no page, no login, no cookie). Browsers warn once; there is no ACME/cloud step.
3. **No shipped password.** With `PATRONUS_FIRST_RUN_SETUP=1` and no `admin` account, every page redirects to `/first-run` and every API answers 403 until the owner chooses a password (12+ characters, known defaults refused, entered twice) and enters the setup code from the console or `/run/patronus/first-run-code` (or the root password; section 12.9). Then `/first-run` redirects to the login. `admin/admin` is refused before and after (tested). Until it is set the UI is reachable only from the LAN side (input policy drop on the WAN); the password is chosen over TLS and never leaves the box. Recovery of a lost password: set `PATRONUS_ADMIN_PASSWORD` in the init script (re-applied at every web start while set), as on every other tier; removing the store from the console starts over with the first-run page (not tested).
4. No outbound connection is needed to use the UI: no CDN assets (static files are compiled in), no update check, no threat feed.

### Relation to central management (decision)

The local UI is **always on and always sufficient**; central management is additive and can never be the only way in.
- Source of truth: the router's own config store. The UI, the REST API and `patronus gitops` all write that same store through the same appliers; the audit log records which one changed what.
- Central **pull** (preferred; needs no inbound path to the Slate, which lives in a bag behind someone else's NAT): `patronus gitops watch` against the main Patronus' repo. Resources it manages are re-applied at the next sync, so a local edit of a gitops-managed resource is overwritten; everything else the owner sets locally stays. A local "pause gitops" switch is part of the contract.
- Central **push** (from the main Patronus UI): its API client talks to the router's REST API with a per-router **API key** (role-limited; keys cannot manage accounts, keys, factory reset or backup targets by design) over the LAN or a WireGuard management tunnel; port 443 is never opened to the WAN.
- Status: the pieces (store, API keys, gitops engine) exist and are proven on x86; **on the MIPS build `gitops` is not compiled in yet and no main-UI fleet page exists**. This paragraph is the contract to build against, not a proven feature.

### QEMU end-to-end proof (`ci/embedded-mips/t_e2e.py`, kernel 6.12.113 malta BE, 128 MB, squashfs + ext4 overlay)

All of these passed in one run, then again after a reboot **triggered from the web UI** (`POST /api/system/reboot`): default LAN IP up; `/` -> 303 `/first-run`; API 403 before a password; `admin/admin` refused; weak and mismatched passwords refused; password set; second set refused (409); login; 14 pages (200 or 501 for unbuilt); firewall rule added through the API, `apply`, `nft list chain inet patronus input` shows `tcp dport 8080 accept`; backup created, rule deleted (nft: gone), backup restored (nft: back); `/qos` and `/api/system/updates/check` answer 501; `GET /api/features` = `dhcp,dns`; after the reboot: rule still in nftables, login with the same password, no first-run page, LAN IP and DHCP pool intact, backup file present. Load check (`t_load.py`): 4 parallel logins + 96 page loads at 8 parallel, 96 x 200, web HWM 25.0 MB.

### Not proven

The real QCA9563 board (speed of TLS/argon2 on the 24Kc, ath79 kernel boot, UBIFS overlay instead of the ext4 stand-in), Wi-Fi pages, a real browser session (the proof used `curl` against the real HTML/JS; the page JS runs in the browser only), `gitops`/central management on MIPS, firmware update/rollback from the UI, long-run memory (hours, many sessions), and the 24 MiB slot layout with both agents installed.

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

Rules: unknown sections are listed in an `unmapped` report (never dropped silently); secrets are copied into the store's secret table, not into logs; `--dry-run` prints the `patronus apply` diff. Proof order: (1) run it on `router-slate.tar.gz` offline, (2) apply in the malta QEMU twin, (3) only then on the device. Status: **written** for `network` interfaces (static/dhcp/dhcpv6), `dhcp` pools + static hosts, `firewall` zones/ACCEPT rules/redirects (stock OpenWrt rules are reported as covered by default) and `wireless` (AP -> Wi-Fi network with `wifi-ap`; STA entries parked in order with their `disabled` flag). Usage: `patronus import-uci <tarball|dir> [--dry-run] --map lan=br-lan --map wwan=wl24-sta` (UCI device names differ from Patronus ones, hence `--map`). Not yet imported, listed in the `unmapped` report: bridges/switch/VLAN/routes, pppoe, WireGuard, dnsmasq options, hostname/timezone/ntp (no store settings), custom zones, DROP/REJECT rules.

## 8. Spike results and blockers (real runs on rw-man-03)

Setup: one capped container each (`--cpus 3 --memory 6-8g`), Gentoo stage3 amd64 + crossdev, Debian 12 + qemu-system-mips 7.2.

1. **Toolchain/rootfs:** crossdev `mips-unknown-linux-musl` with `--with-float=soft --with-arch=mips32r2`, then `ROOT=/rootfs mips-unknown-linux-musl-emerge` of busybox, nftables, dnsmasq, iproute2, wireguard-tools, hostapd (all OK). OpenRC 0.64.1 + libcap cross-emerge into their own ROOT (`stage-openrc.sh`, `--nodeps`), linux-pam 1.7.3 into the router root (needs a `shadow` group for unix_chkpwd), dhcpcd from its release tarball (`dhcpcd-build.sh`).
2. **Rust on MIPS32 BE:** tier-3 target, so nightly + `-Zbuild-std`. Four real blockers, all fixed or understood:
   - `patronus-cli` has an **unused** dependency on `patronus-dashboard` (nothing in `patronus-cli/src` uses it) which drags in `opentelemetry_sdk`, which needs `AtomicU64`: MIPS32 has none. Fix in this branch: drop the dependency line.
   - `patronus-network/src/sysops.rs` used an `AtomicI64` job counter. Fix in this branch: `AtomicI32`.
   - cross `pkg-config` must use the target-suffixed variables (`PKG_CONFIG_SYSROOT_DIR_mips_unknown_linux_musl`, `..._LIBDIR_...`); the unsuffixed ones also hit host build scripts (`nftnl-sys` is a build-dependency), plus the host needs native libnftnl/libmnl.
   - rustflags with the target sysroot's `-L` must be `CARGO_TARGET_<T>_RUSTFLAGS` only (a global `RUSTFLAGS` broke host build scripts: "libc.so is incompatible with elf_x86_64").
   Result: `cargo build --release --target mips-unknown-linux-musl -Zbuild-std -p patronus-cli --no-default-features --features nftables,cli` = ELF 32-bit MSB, mips32r2, o32, links only `libc.so`. Build time 34 s for the last step after deps, with `CARGO_PROFILE_RELEASE_{OPT_LEVEL=z,LTO=fat,CODEGEN_UNITS=1,PANIC=abort,STRIP=true}`.
   Built for mips since the web spike (2026-11-06): `patronus-cli` with `dhcp-server,dns-server` (5.3 MB) and `patronus-web` with `dhcp,dns,tls-openssl` (section 6a). Still not built for mips: any default-feature set (eBPF/libbpf, libelf), `ring`/`aws-lc-rs` TLS (cannot: no MIPS support), and the `gitops`, `wifi-ap`, `vpn-wireguard` features (each needs its own cross check).
3. **Kernel (malta):** the first malta config lacked `NF_TABLES_INET`: `patronus-cli apply` exited 1 (`apply failed for: firewall`, "Could not process rule: No such file or directory" at each `ct state`). After enabling `NF_TABLES_INET/IPV4/IPV6`, `NFT_NAT`, `NFT_FIB_INET`, `apply` succeeded and nft shows the full `inet patronus` table (input/forward/output, prerouting/postrouting NAT). The ath79 config already had `NF_TABLES_INET=y`. Lesson: the embedded kernel config is part of the profile and is gated in CI by running `patronus apply` in QEMU.
4. **ath79 kernel:** With OpenWrt's config the build failed in `fs/jffs2/compr_lzma.o` (`stddef.h` not found by the cross compiler for the bundled LZMA); set `CONFIG_JFFS2_LZMA=n` (we do not use JFFS2). The DTS Makefile needs one added line for the GL-AR750S dtb.
5. **Not proven:** the ath79 kernel booting on QCA9563 (no QEMU machine; real-board proof = the initramfs serial test in section 9, step B), Wi-Fi radios, NAND/UBI attach, the sysupgrade path, OpenRC. (`patronus-web` is proven in QEMU: section 6a.)
6. **Web spike notes (2026-11-06):** QEMU malta needed `-device pcnet,romfile=` (the Debian image lacks the option ROMs) and the data disk on `if=ide` (a third virtio PCI device failed to probe, `-28`); busybox `ip` has no `-br`; `/etc` and `/var/lib` must be overlays or the dnsmasq/lease/DB writes hit the read-only squashfs. A fat-LTO web build takes about 1 min after the dependencies, a cold one 2-3 min on 16 cores.

## 9. Rollout and exact owner steps

Principle: the Slate stays on OpenWrt for ETPhoneHome QA until step D passes. Patronus development uses the malta QEMU twin and (phase 2) an azkaban VM. Nothing below is run without the owner.

**Safety net already in place:** `backups/router-config-pull.sh` pulls `sysupgrade -b` of the Slate (by MAC, hostname-verified) into the nightly restic job whenever it is on the LAN; last good copy is `router-slate.tar.gz`. Stock OpenWrt 25.12.6 image staged at `~/.hermes/state/patronus-embedded/openwrt-25.12.6-ath79-nand-glinet_gl-ar750s-nor-nand-squashfs-sysupgrade.bin` (sha256 `3d58b599daca2a239f745cf5d739d624d6262302000df1615295ca03c594ed03`, matches the downloads.openwrt.org `sha256sums`).

A. **Back up (owner, 10 minutes, Slate on the home Wi-Fi):**
 1. `ssh root@<slate> 'sysupgrade -b -' > slate-config-$(date +%F).tgz` (and compare with the staged one).
 2. Full flash dumps, especially ART and U-Boot env: `ssh root@<slate> 'cat /proc/mtd'`, then for each NOR partition `ssh root@<slate> 'cat /dev/mtdblockN' > mtdN-<label>.bin` (u-boot, u-boot-env, art, kernel). ART is the Wi-Fi calibration; without it the radios are lost. Keep copies on the control host and B2.
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
6. ~~`patronus-web` mips build + memory cap, or a deliberate CLI-only decision~~ **Done 2026-11-06: the web UI ships on the router tier** (section 6a, measured: +4.05 MiB squashfs, 16.4 MB idle / 25.0 MB peak RSS, e2e green in QEMU). Remaining web items:
7. Firmware update + rollback page: upload the sysupgrade-tar, verify (fwtool metadata + signature), write the inactive slot, flip `bootcount`, arm the on-device 5-minute rollback; honest 501 until then.
8. Wi-Fi in the router UI: cross-build `wifi-ap` (+ `segmentation`) and `wpa_supplicant` (repeater mode), add the radios to the QEMU twin or test on the real board in step B.
9. Connected-clients page (DHCP leases + ARP/neighbour table + Wi-Fi stations) and a syslog ring (`logread` equivalent: busybox `syslogd -C` feeding `$PATRONUS_SYSLOG`).
10. Central management: `gitops` feature on MIPS, a per-router API-key client + fleet page in the main Patronus UI, the "pause gitops" switch; then prove push and pull against the malta twin.
11. CI: run `ci/embedded-mips/t_e2e.py` on every push (QEMU TCG, about 8 min) with RSS ceilings (web idle <= 20 MB, peak <= 30 MB, rootfs <= 16 MiB without agents); real-board timing of the first login and TLS handshake in step B.
12. Merge the web changes back into the default build's gates (`cargo test -p patronus-web` with default features and with `--no-default-features --features dhcp,dns,tls-openssl`): the spike compiled and exercised the router build, it did not re-run the full x86 unit-test suites.

## 12. GL.iNet GL-AX1800 "Flint" (IPQ6018, aarch64): the second embedded target (2026-11-15)

Profile `profiles/hw/qualcommax-gl-ax1800.toml` (status `builds`), tooling `ci/embedded-aarch64/ax1800/`, CI
`.forgejo/workflows/embedded-aarch64.yml`. Role: wired access point (every Ethernet port bridged into `br-lan`, address by
DHCP, no DHCP/DNS server, no routing), Wi-Fi from a per-unit `ap.env`. Both init systems, ETPhoneHome baked in and enabled
on both. First real-unit install 2026-11-16 (OpenRC, from OpenWrt 25.12.6, as a home access point): see 12.3 and 12.6a.

### 12.1 Build

- Native aarch64 musl, no cross toolchain: an Alpine 3.24 builder (`Dockerfile.builder`) on the arm64 runners. The userland
  comes from Alpine packages (`stage-rootfs.sh`: busybox, hostapd, iw, iproute2, dropbear, mtd-utils UBI tools, nftables, PAM,
  wireless-regdb, libucontext and libmount for systemd); `patronus-cli` is one multi-call binary (`patronus-web` is a link)
  built with the stable toolchain for `aarch64-unknown-linux-musl` (14 MB stripped, features
  `nftables,cli,dhcp-server,dns-server,uci-import,wifi-ap,web-multicall,vpn-wireguard,ntp-server,syslog`; 12.10).
- OpenRC is built from source (`stage-openrc.sh`, 0.63.2, sha256-pinned): Alpine's package is built for busybox init and has
  no `openrc-init`/`openrc-shutdown`, so it cannot be PID 1. systemd 262.2 is built as for the Slate (`stage-systemd.sh`).
  systemd `dlopen()`s libmount to mount the API filesystems: without `libmount.so.1` PID 1 freezes with "Failed to mangle
  mount options ... Not supported" (found by the QEMU gate; `check-rootfs.sh` now refuses such an image). glibc's
  `ldconfig.service` and the udev units are removed from the systemd variant (devtmpfs board, musl).
- Kernel: the stock OpenWrt 25.12.6 FIT (kernel 6.12.112 + the board's device tree, `root=/dev/ubiblock0_1` in its
  `bootargs-append`) byte for byte, its kmods, the IPQ6018 firmware and the ath11k board data (`stock.pin`). The netfilter
  kmods come from the pinned OpenWrt packages of the same kernel build (`kmods.pin`, `fetch-kmods.sh`): the stock root has
  no `nfnetlink_log`, which the firewall's NFLOG `log group` rules need, so without it the firewall would not apply and the
  web UI (fail-closed on the firewall) would not start.
- Outputs per variant (`assemble.sh`): `root.squashfs`; `…-sysupgrade.tar` (OpenWrt layout + `patronus-release` +
  `patronus.sha256`, fwtool metadata); `…-factory.ubi` (ubinize, the board's layout, for U-Boot recovery); `…-factory.bin`
  (= factory.ubi + fwtool metadata, for the GL stock web UI, the same construction as OpenWrt's); `sha256sums`, `sizes.txt`.

Sizes **[measured]**, CI-unit images of 2026-11-15:

| | OpenRC | systemd |
|---|---|---|
| root.squashfs (xz, 256 KiB blocks) | 16.00 MiB (133 LEBs) | 18.68 MiB (155 LEBs) |
| sysupgrade tar | 21.07 MiB | 23.75 MiB |
| factory.ubi / factory.bin | 22.12 MiB | 24.88 MiB |
| unpacked root | 51.3 MiB | 61.3 MiB |
| NAND left after kernel + root + 16 MiB settings | 71.2 MiB | 68.5 MiB |

### 12.2 NAND/UBI layout (checked against OpenWrt's own factory.ubi)

`ubi-layout.py` reads a UBI image (EC/VID headers, volume table) without external tools. OpenWrt 25.12.4 and 25.12.6
`factory.ubi` for this board: PEB 128 KiB, LEB 126976 B (VID header at 2048, data at 4096: SPI-NAND without sub-pages),
volumes `kernel`=0, `rootfs`=1, `rootfs_data`=2 (autoresize, 1 MiB). The sysupgrade kernel and root are byte prefixes of
the factory volumes, and `ceil(bytes / LEB)` gives exactly the factory image's `reserved_pebs` (25.12.6: kernel 5305856 B =
42, root 7344128 B = 58). The mtd `rootfs` partition is 0x7300000 = 920 PEBs; UBI keeps 24 back (layout 2, wear-levelling
1, atomic LEB change 1, bad-block reserve 20 per 1024 PEBs of the 128 MiB chip). `nand-budget.sh` takes these numbers from
the profile, checks our factory.ubi with the same layout check, and demands 16 MiB of settings + 8 MiB margin. CI also runs
the layout check on OpenWrt's 25.12.6 factory.ubi (`stock.pin`) so a wrong assumption fails on the reference image first.

Settings live on the UBIFS volume `patronus_data` (`/etc`, `/var/lib`, `/root` overlays). On first boot `ubi-data` replaces
OpenWrt's `rootfs_data` (which after factory.ubi has autoresized over the whole flash) with `patronus_data` sized to leave
32 MiB free, so later upgrades can grow the kernel/root volumes in place without touching the settings.

### 12.3 Installing and recovering (tested on a real unit with GL.iNet 4.8.3 and U-Boot "uboot2.0 21.08.31", 2026-11-15)

- **From the GL.iNet stock firmware (4.x, QSDK):** the stock web upgrade does NOT work for third-party images. Stock
  `platform_check_image` accepts only a sysupgrade tar, and stock `platform_do_upgrade` always runs `nand_upgrade_tar`,
  which writes kernel and root into GL.iNet's own UBI volumes (`kernel`, `ubi_rootfs`, `rootfs_data`). An OpenWrt or
  Patronus image written that way does not boot (solid LED, no network). The method that works, over SSH on the stock
  firmware:
  1. `cp /lib/upgrade/platform.sh /tmp/` and change the `glinet,ax1800` case in `platform_do_upgrade` to
     `nand_do_upgrade "$1"` (it detects the UBI magic and runs `nand_upgrade_ubinized`, i.e. `ubiformat` of the `rootfs`
     MTD with the image's own layout);
  2. `mount --bind /tmp/platform.sh /lib/upgrade/platform.sh`;
  3. `sysupgrade -F -n <factory.ubi>`.
  The result is the same flash layout a U-Boot factory.ubi install produces. Verified with OpenWrt 25.12.6's factory.ubi.
- **GL U-Boot web recovery** (hold reset while powering on, release after about 5 LED flashes, http://192.168.1.1 from a
  PC with a static 192.168.1.x address): on this U-Boot version it accepts ONLY GL.iNet's own U-Boot `.img`. An OpenWrt
  `factory.ubi` is rejected ("update failed"), and a `factory.bin` soft-bricks the unit. (Newer GL U-Boot builds are reported
  to accept factory.ubi; not verified.) Recovery is therefore: GL `.img` via U-Boot, then the SSH method above.
- **Afterwards:** upgrade with the sysupgrade image: from OpenWrt with `sysupgrade -n <patronus…-sysupgrade.tar>` (OpenWrt
  checks the fwtool metadata), from Patronus with `patronus-flash sysupgrade` (12.4).
- **First real-unit install (2026-11-16):** a unit running OpenWrt 25.12.6 took the Patronus OpenRC sysupgrade tar with
  `sysupgrade -n` (fwtool metadata accepted) and booted it: NSS Ethernet ports, br-lan with a DHCP lease, ssh, the web UI,
  ETPhoneHome and no DHCP/DNS server worked on the first boot. Wi-Fi did not (three bugs, fixed in 12.6a); later images
  are installed from Patronus itself with `patronus-flash sysupgrade` (12.4).
- A fresh OpenWrt or GL image runs a DHCP server on its LAN ports even when another DHCP server is present. On an existing
  network, connect it only to the WAN port or set `dhcp.lan.ignore=1` right after first boot.
- Automatic rollback of a bad upgrade: 12.16 (`patronus-guard`). The kernel command line pins volume 1 as the root, so
  there is no A/B root as on the Slate; instead the bootloader itself copies the previous image back.

### 12.4 Upgrades from Patronus: `patronus-flash`, guarded and fail-closed

- `patronus-flash check|sysupgrade <image.tar> [--now]`, `cancel`, `factory-reset`, `status`. Raw kernels or squashfs files
  are refused; only the sysupgrade tar carries the metadata. Guards (`fwcheck.sh`, each fails closed): the box is a GL-AX1800
  (device tree compatible); fwtool metadata present, lists this board, dist Patronus (OpenWrt images are refused: use U-Boot
  recovery); only the board's tar members; kernel/root sha256 match `patronus.sha256`; kernel is a FIT; root is a squashfs
  whose own `/etc/patronus-release` names this board and matches the tar's, with OpenRC or systemd recorded and
  `patronus-init`, `patronus-flash` and ETPhoneHome inside (loop-mounted on the box); kernel + root fit the UBI device and
  volumes 0/1 really are `kernel`/`rootfs`.
- The running root (ubiblock on volume 1) cannot be rewritten in place, so `sysupgrade` only stages the verified parts on
  `patronus_data`. The next boot re-verifies them in the early boot (bad -> moved to `.upgrade-rejected`, normal boot goes
  on), then PID 1 copies the parts, busybox and the UBI tools to a tmpfs, unmounts everything, `pivot_root`s into RAM and
  writes root then kernel (volumes keep their IDs, grown with `ubirsvol` when needed), reads both back, records the result
  on `patronus_data` and restarts (`upgrade-install`). Any failure before the write leaves the old system untouched; a power
  cut during the write needs U-Boot recovery. Same code path for both init systems (it runs before either starts).
- Proof **[measured]**: host tests (`tests/run.sh`, 167 checks: every guard against synthetic images and a fake UBI);
  the QEMU gate runs the real guards on the real image (busybox, loop mount); `nandsim-proof.sh` ran the UBI paths against
  the Linux UBI driver on a simulated 128 MiB NAND with the board's geometry and an exact 0x7300000 partition: ubiformat with
  our OpenRC factory.ubi (the U-Boot path), attach, first-boot `patronus_data` creation (455 LEBs, 264 left free), settings
  written, then `check` + `sysupgrade` + `verify` + `ubi-write` of the systemd image (rootfs grown 133 -> 155 LEBs, ubiblock
  released, both volumes read back equal), settings file intact: all passed. Not run in CI (loading nandsim is a host change).
- **Release signature (2026-11-17).** `assemble.sh` signs `patronus.sha256` (which binds the kernel and root hashes) with the
  Errant Solutions release key (fingerprint `5439 3549 39B9 C055 2A68  E9BB E323 A6A3 AC0A 6506`, `keys/release-signing.asc`)
  and stores the binary signature base64 in the fwtool metadata as `patronus_sig`. The tar keeps exactly the members older
  `patronus-flash` builds accept, and OpenWrt's `sysupgrade -T` ignores the extra JSON key. The image ships `gpgv` and the
  keyring `/usr/share/openpgp-keys/errantsolutions.gpg`; `fwcheck.sh` checks the signature right after the sha256 and before
  the root image is opened, `upgrade-install` checks it again at boot and once more on the RAM copy it is about to write.
  Unsigned, foreign-signed or modified images are refused (`REFUSED: the image is not signed` / `release signature check
  FAILED`). Every output file also gets a detached `.asc`. `assemble.sh` refuses to build without `RELEASE_SIGNING_KEY`
  (`ALLOW_UNSIGNED=1` makes a test image that no Patronus box installs). Units still on a build from before this change don't
  check signatures yet; they start doing so once they run a signed build. Proof: host tests (unsigned, foreign key, tampered root
  with a re-made sha256, missing keyring, staged-then-modified) and the QEMU gate (an unsigned and a tampered copy of the CI
  image are refused on the real firmware, nothing is staged; the signed image is accepted and staged).

### 12.5 QEMU aarch64 gate (`qemu-gate.sh`, both init systems, every push)

OpenWrt's armsr/armv8 kernel of the same release (pinned) boots the Patronus root on QEMU `virt` (Cortex-A53, 512 MB,
TCG on the arm64 runners). The test copy of the root only swaps the board's kmods for the same pinned netfilter packages
built for the virt kernel (`kmods.pin` "virt") and sets `/etc/patronus/qemu-kmods`; everything else is the shipped image.
Checks over ssh (throwaway CI key) and HTTPS: PID 1 is `openrc-init` / systemd; every service up (no failed systemd unit);
ETPhoneHome running; web UI and first-run page; system log; netfilter kmods loaded and the firewall applied by patronus-web;
board/init in `patronus-release`; no DHCP/DNS server; no 802.11r anywhere; the flash guards (refused on a non-GL-AX1800
board, the real image passes with the board identity, a corrupt image is refused, staging + early-boot verify); then a
power cut and a second boot from the same settings disk: the staged upgrade is rejected at boot (wrong board) without
stopping the boot, settings persisted, everything up again. Local results 2026-11-15 (TCG on an arm64 build host): both
variants `FAILED: none` (24 checks each); patronus-web up 22.5 s (OpenRC) / 24.3 s (systemd) after power-on under TCG;
RAM used after boot 32.2 MiB (OpenRC) / 34.8 MiB (systemd) of 482 MiB.
The board drivers (NSS Ethernet, ath11k, caldata) cannot be emulated and are not covered.

### 12.6 Wi-Fi: 802.11r is never enabled or imported

On this SoC's ath11k firmware lineage, 802.11r fast transition is what crashes the Wi-Fi firmware (and then the kernel in
`ath11k_core_ssr_notifier_cb`), observed with OpenWrt on a unit. Patronus therefore never writes `ieee80211r` unless the
unit's `ap.env` sets `AP_FT=1` (testing only), `check-rootfs.sh` refuses an image whose shipped config enables it, and
`patronus import-uci` reports an OpenWrt wifi-iface with `ieee80211r '1'` (and its `mobility_domain`, `ft_over_ds`, ...)
as NOT imported: the AP comes up with fast transition off and roaming falls back to plain re-association. The importer
also recognises the IPQ6018 radio (`c000000.wifi`) and keeps `htmode` in its plan (fixture `tests/fixtures/uci-ax1800`).

### 12.6c Wi-Fi: 802.11ax (HE) settings

802.11ax is on by default (`AP_HE=0` in `ap.env` limits both radios to 802.11n/ac). The first image wrote only
`ieee80211ax=1` plus the HE channel width. With that, clients in power save (phones with the screen off) lost 50-100 %
of the frames sent to them, with round trips up to 1.2 s, and re-associated every few minutes; always-awake clients on
the same AP saw no loss, and the same radios with 802.11ax off delivered every frame. The same unit had run OpenWrt
25.12.6 with HE80/HE40 without this, on the same kernel, ath11k modules and firmware, so the renderer now writes what
OpenWrt's `mac80211.sh`/`hostapd.sh` generate for this board:

- radio: the board's full HT and VHT capabilities (`AP_HTCAPS24`, `AP_HTCAPS5`, `AP_VHTCAPS5` in `board.sh`, as OpenWrt
  derives them from `iw phy info`), `beacon_int=100`, `stationary_ap=1`, short preamble, no 802.11b rates on 2.4 GHz,
  `tx_queue_data2_burst=2.0` on 5 GHz;
- 802.11ax: SU/MU beamforming, a BSS color (hostapd leaves BSS color disabled unless `he_bss_color` is set; the
  renderer derives 1-63 from the radio MAC, so the two radios differ), spatial reuse (`he_spr_sr_control=3`), a 16 us
  PE duration, the TXOP RTS threshold off (1023) and the MU EDCA parameter set;
- every BSS: U-APSD advertised, low-ACK disassociation, the inactivity poll, BSS load reporting, and its own control
  socket (so `ap-event` sees every BSS).

Band moves: each radio runs its own hostapd, so a station that moves to the other band stayed listed on the old radio
until its inactivity timeout. `ap-event` (`hostapd_cli -a` per BSS) removes it there, without sending a frame, when it
connects on the other radio. It never touches BSSes of the same radio: hostapd already disconnects a station from its
other BSSes on that radio when it authenticates.

### 12.6d Wi-Fi: one MAC on two SSIDs of a radio (firmware assert) and crash containment

The IPQ6018 firmware (WLAN.HK.2.5.0.1, also seen on OpenWrt and GL stock) asserts (`ar_wal_peer.c:2462 Assertion
is_graceful_to_handle failed`, remoteproc "fatal error") the moment one MAC is a peer on two BSSes of the same radio, and
the unit restarts. Stock hostapd does exactly that when a client with a FIXED MAC that is still listed on one SSID (it left
without a goodbye: roamed to the other AP, walked out of range, or is a weak IoT device whose authentication frames go to
both SSIDs within milliseconds) authenticates on the other SSID of the radio: it adds the station to the driver on the new
BSS at authentication and removes it from the old BSS only after a timer (`ap_sta_disconnect`, about a second). Phones use
a private MAC per SSID and do not hit it. In the field this put two units into a ~45 s restart loop: a 2.4 GHz-only
smart-home device with a weak link authenticated to both SSIDs in turn right after every boot.

The image therefore ships its own hostapd: `ci/embedded-aarch64/ax1800/hostapd/APKBUILD` is Alpine 3.24's hostapd 2.11
package plus `patronus-xbss.diff`, built by `stage-hostapd.sh` and installed by `stage-rootfs.sh` instead of Alpine's
(`check-rootfs.sh` refuses an image whose hostapd lacks the patch):

- before a station is added to the driver on a BSS (authentication and association), it is removed from every other BSS
  of that radio, from hostapd's table and from the driver, synchronously (no frame is sent: the client has already left);
- a MAC that hops between the SSIDs of one radio more than 6 times a minute is refused on the new BSS for 30 s and stays
  where it is (hostapd logs `patronus-xbss: hopped between SSIDs ...`).

Proof without hardware: `tests/xbss-hwsim.sh` (CI job `xbss-hwsim`, mac80211_hwsim on an x86_64 runner) associates a
station on SSID A and a second station with the same MAC on SSID B of the same radio, and reads the kernel's station
events: Alpine's hostapd creates the peer on B before deleting it on A (the overlap the firmware asserts on), the Patronus
build deletes it on A first; the flap limit is exercised too.

Band moves (the other radio) are still handled after the association by `ap-event` (above).

Crash containment (`/usr/libexec/patronus/wifi-guard`, started by `ap start` on both inits): it follows the kernel log and,
on every firmware crash, logs `PATRONUS-WIFI-CRASH` (daemon.err) and records it on /data at once (the unit may restart
within a second); 20 s later every BSS must be up again, otherwise the access points are restarted (never a driver
unload: `rmmod ath11k_ahb` crashes this board). Safe mode keeps only the FIRST SSID of `AP_SSIDS` on each radio
(`PATRONUS-AP-SAFE-MODE on|off` in the log, state in `/var/lib/patronus/wifi-guard/`, `wifi-guard status`). It is entered
after 3 crashes within 10 minutes, or at boot when a firmware crash was recorded in each of the 2 previous boots (a
restart loop, broken before hostapd starts), and ends after an hour without a crash (each new entry within a day doubles
the hold, at most 24 h).

`ht_coex` is not written: it is an OpenWrt hostapd patch and the stock hostapd rejects it. Any test of the Wi-Fi
settings must use a REAL phone in power save (screen off, deep idle) and check downstream loss over at least 60 s: a
client that never sleeps, or a laptop radio with `iw ... set power_save on`, does not show the problem.

### 12.6a Wi-Fi bring-up on the real unit (found on the first install, 2026-11-16)

The first real boot had wired networking but no Wi-Fi. Three bugs, each reproduced on the unit and fixed in the image:

1. **Calibration never loaded.** `ath11k-caldata` wrote `cal-ahb-c000000.wifi.bin` into `/lib/firmware`, which is the
   read-only squashfs root, so it exited (silently, under `set -e`). It also ran after the kmods: the OpenWrt kernel has the
   firmware user-helper fallback and nothing answers it on this root, so every missing firmware file stalled the boot for
   the 60 s fallback timeout (modules loaded after about 71 s, the Q6 remoteproc after about 131 s) and the radios never
   registered. Now the early boot points `firmware_class.path` at a tmpfs (`/run/firmware`), generates the calibration
   there BEFORE loading the kmods, lowers the fallback timeout to 3 s, and logs any failure to `/tmp/caldata.log`
   (boot mark `caldata-ok` / `caldata-FAILED`). `ap start` waits in the background for both radios to register.
   Running before the kmods has one more consequence, found on the first boot of the fixed image: the label MAC (the
   radios get label + 3 and label + 2) is not yet in the device tree, because OpenWrt's kernel adds the label device's
   `mac-address` property only when the Ethernet driver probes, and `local-mac-address` is an all-zero placeholder. That
   boot patched zeros in and the radios came up as 00:00:00:00:00:02/03. `ath11k-caldata` now reads the MAC from the
   label device's nvmem cell itself (phandle -> fixed-layout cell -> its mtd partition, here the ART at offset 0), and it
   refuses an all-zero or multicast label.
2. **5 GHz hostapd refused two SSIDs** ("Invalid BSSID mask ff:ff:ff:ff:ff:fe for start address ..."): the 5 GHz radio's
   MAC is odd and hostapd's automatic addressing needs an aligned start address; its automatic address for a second
   2.4 GHz BSS (radio MAC + 1) was the 5 GHz radio's own MAC. The renderer now writes an explicit `bssid=` for every BSS:
   the radio's MAC for the first, locally administered variants for the rest, unique across both radios (as OpenWrt does).
3. **5 GHz at 80 MHz failed to start** ("DFS chan_idx seems wrong", interface initialization failed): no
   `vht_oper_centr_freq_seg0_idx`. For a fixed channel the renderer now writes the HT40 direction and the VHT/HE centre
   channel (80 MHz: 42, 58, 106, 122, 138, 155, 171 by channel block; 40 MHz: the pair's centre); channel `auto` (ACS)
   leaves them to hostapd.

Also: the box has no RTC, so OpenRC recorded service start times at 1970 until ntpd synced ("20773 day(s)"). The early boot
now starts the clock at the last synced time saved on the data volume (then `ntp-sync`, busybox ntpd's `-S` hook; since
12.10 chrony's drift file, rewritten hourly) or the image's build time. Host tests cover the BSSIDs (fake odd radio MAC), the centre channels, the calibration
path, and `check-rootfs.sh` refuses calibration on the read-only root or an early boot that unloads ath11k.

**Never unload `ath11k_ahb` on this board** (`rmmod`, or a "reload the driver" step in a script): on a live unit it
crashed the Wi-Fi firmware and the box restarted. The early boot no longer has the old unload/reload fallback.

### 12.6b Wi-Fi clients on the real unit, and a stock GL.iNet AP on the same LAN (2026-11-16)

Measured with a real client (an Intel AX211 laptop radio in its own network namespace, wpa_supplicant + udhcpc) against
the unit running the image with real radio MACs (label + 3 / + 2 = the 5 GHz / 2.4 GHz BSSIDs of the first SSID, their
locally administered variants for the second): on all four BSSes (two SSIDs x two bands) association took 0.6 s, the DHCP lease from the
LAN's DHCP server 0.3-2.4 s, ping to the gateway and to the Internet and a DNS lookup passed, and 10-20 s of pings
afterwards lost nothing; the same after a restart of the unit (Wi-Fi up 26 s after boot with no manual step), and with
the client in power-save mode. The first one or two packets after association are often late or lost (the client logs
retries while its uplink rate settles), so a first DNS query can need the resolver's 5 s retry.

The unit itself was not what cut clients off. The site had a second AP on the same LAN running GL.iNet stock firmware
4.8.3 with the same SSIDs, and that AP does not deliver downstream unicast to a station that roams to it from another
AP for 2.3-4.4 minutes (reproduced seven times with the test client: associate to this unit, leave, associate to the
stock AP: DHCP offers were sent by the server and never arrived at the client; the frames do not come back to this unit
either; a control with no visit to this unit for 5 minutes got its lease at once). Any frame the stock AP sees from the
station on its Ethernet side starts it: the 802.2 L2 update frame alone (sent when a station associates here) and, with
that frame filtered out, the station's own broadcasts alone both did. Moving the other way (stock AP -> this unit) works
at once, because the Linux bridge here relearns the station on the first frame. So in a mixed deployment every roam
toward the stock AP, and every hostapd restart here (all stations move at once), costs the affected clients a few
minutes without network. Nothing sent from this side can clear the other AP's state; run the same firmware family on
both APs.

### 12.7 Not proven yet

Proven on a real unit (OpenRC, 2026-11-16): the NSS Ethernet ports, install from OpenWrt with `sysupgrade -n`, ath11k
calibration from the ART partition, hostapd on both radios with two SSIDs each, real clients on all four BSSes (12.6b). Not yet: the systemd variant on the board,
the U-Boot recovery and stock-UI installs of a Patronus image, RAM and boot time on the IPQ6018 beyond the first unit, and
the early-boot upgrade installer end to end (its UBI write step is proven on nandsim; the first real run is the
`patronus-flash sysupgrade` from the fixed image).

### 12.8 Signing in from a browser that used the old firmware's web page (2026-11-16)

A router that replaces another firmware keeps its address, so the browser of whoever administered it still holds that
firmware's state for the address: GL.iNet 4.x sets an `Admin-Token` cookie at `Path=/`, LuCI a `sysauth_https` cookie
under `/cgi-bin/luci/`, and either may have left cached pages. Found on a real unit migrated from GL.iNet stock: in the
browser that had used the GL.iNet page, every sign-in was accepted by the router (the audit log shows a successful
`login` each time), the session cookie was stored, and the browser was sent straight back to the login page; a private
window, or clearing the cookies for the address, worked at once.

Cause: over HTTP/2 a browser sends each cookie as its own `cookie` header field (RFC 9113 8.2.3). patronus-web read only
the first field, which held the old firmware's cookie, so the session cookie in the second field was never seen and every
page answered `303 /login`. With only the session cookie stored (fresh profile, private window) there was one field and
it worked. Reproduced with Firefox and Chromium and with curl (`-H 'cookie: a=b' -H 'cookie: session_id=...'` -> 401).

Since then:
- every `cookie` field is read, a cookie with non-ASCII bytes is skipped on its own instead of hiding the rest, and a
  stale duplicate session cookie in front of the current one is passed over;
- the login page deletes (at `Path=/`) every cookie Patronus does not set and sends `Clear-Site-Data: "cache"` (no
  stale cached page for `/`); its script removes service workers and Cache Storage (Patronus uses neither). The session
  cookie and the theme choice in local storage are left alone. A successful sign-in deletes foreign cookies too;
- after the password is accepted the login page checks that the browser sends the session back before leaving, and
  otherwise says so (clear the site data for the address) instead of bouncing silently;
- refusals say what they are: "Too many failed sign-in attempts for this account; try again in 1 minute." (per-name
  back-off: 5 failures in 10 minutes pause that name for 60 s, also for the right password and for names that do not
  exist) and "... from this address; try again in N minutes." (per-address lockout: 5 failures, 15 minutes), never
  "Invalid username or password";
- every sign-in, failure (with its reason) and refusal is written to the web log (`/var/log/web.log` on the router,
  tracing target `patronus::audit`, logged whatever `RUST_LOG` says) as well as the store's audit log.

Fixed in 3c1a84d4 (CI run 18032 green, including the browser test). Proof: `ci/stale-origin-login-e2e.sh` (CI, image as built: Firefox and Chromium over HTTP/2 with the GL.iNet and LuCI
cookies seeded, sign-in must reach the dashboard and stay signed in, the old cookies must be gone, a lockout must say so
and be in the web log), unit tests `auth::cookie_tests` and `routes::auth_gate_tests` (split cookie fields, non-ASCII
neighbour, stale duplicate, foreign-cookie deletion, back-off message). The same script can be pointed at a unit:
`BASE_URL=https://<unit> E2E_USER=<test account> E2E_PASSWORD=... ci/stale-origin-login-e2e.py firefox,chromium`.

### 12.9 First start of an access point, and claiming a unit on the first-run page (2026-11-17)

Two problems found on units migrated from GL.iNet stock and OpenWrt:

- **"This router has not been set up yet. Run the setup wizard"** on every page after the first sign-in. The wizard is the
  router one (WAN port, LAN address, DHCP pool); a GL-AX1800 is a wired access point configured by its image (bridge,
  Wi-Fi from `ap.env`), so nothing ever recorded setup as done, and running the wizard there would have turned it into a
  router with its own DHCP server on the house LAN.
  Now the image says what the unit is: `PATRONUS_DEVICE_ROLE=ap` in `/etc/patronus/embedded.env` (`check-rootfs.sh`
  refuses an image where it does not match `ROLE=ap` in `board.sh`). The web service's first start on such a unit records
  setup as complete (store key `setup.completed`, one audit row `provisioned`, web log line `setup recorded as complete
  (role ap)`); `/api/setup/status` answers `completed: true, role: "ap", wizard: false` whatever the store says; `/setup`
  shows what an AP is and links to Interfaces, Monitoring and System instead of the wizard; `POST /api/setup/apply` answers
  409. A router image whose network is provisioned at build time sets `PATRONUS_SETUP_PROVISIONED=1` for the same result.
  A router-mode unit without either (the Slate, a fresh router) still shows the banner until the wizard runs or is skipped.
- **The first-run page could be claimed by anyone on the LAN.** A unit with no web administrator served "Welcome / Create
  administrator" to the first visitor, who became its administrator. Now the page needs proof of ownership:
  - a one-time **setup code** (`XXXX-XXXX-XXXX`, 60 bits, no look-alike characters) generated at every start of the web
    service while no administrator exists. It is printed on the system console (serial) and written to
    `/run/patronus/first-run-code` (mode 0600, tmpfs; `cat` it over ssh as root). The file is removed once the
    administrator exists;
  - or the unit's existing **root password** (a unit moved over from OpenWrt or the vendor firmware keeps its root login;
    a locked root never counts);
  - within a **window** of one hour after the web service starts (`PATRONUS_FIRST_RUN_WINDOW_SECS`), and for at most ten
    wrong codes. After that the page says the window is closed; restarting the router or its web service opens a new one
    with a new code. Code checks are constant-time; an empty or wrong proof is refused with 403 before any account is made.
  - Units that already have an administrator (any non-root member of `patronus-admin`) never see the page; their accounts
    and PAM sign-in are unchanged.
- New accounts made on the first-run page get the lowest free uid from 1000 and gid from 2000. Before, `nobody` (65534) in
  `/etc/passwd` pushed them to 65535/65536 (the overflow range); existing accounts keep their ids.

Proof: unit tests `routes::api::setup::tests` (AP records setup at first start once, router keeps the banner, explicit
provisioning), `routes::first_run::tests` (no claim without the code, lower-case/no-dash code accepted, ten wrong codes
lock the window and a restart opens a new one, expiry, root password as proof, locked root refused),
`sysauth::tests::new_accounts_get_regular_ids_even_with_nobody_present`; `qemu-gate.sh` on every embedded-aarch64 push
(both init systems): code file root-only, claim refused without and with a wrong code, claimed with the code and the file
removed, web log line, status `completed/ap/no wizard`, wizard apply 409, and after a restart no second record and no code.
The MIPS harnesses (`t_e2e.py`, `t_slate.py`) read the code over the console/ssh.

### 12.10 Router-tier features: WireGuard, the NTP server and remote syslog (2026-11-17)

The GL-AX1800 image builds `patronus-cli` with `nftables,cli,dhcp-server,dns-server,uci-import,wifi-ap,web-multicall,
vpn-wireguard,ntp-server,syslog` (`stage-patronus.sh`; the list is recorded as `FEATURES=` in `/etc/patronus-release` and
`check-rootfs.sh` requires each feature's runtime pieces). The web UI shows the VPN (WireGuard), NTP and Syslog pages
because `/api/features` now lists `wireguard`, `ntp` and `syslog`.

- **WireGuard (client and server).** The lane F applier (`wg_interfaces` / `wg_peers`, the VPN page) runs unchanged: the
  kernel module is OpenWrt's `kmod-wireguard` of the same 6.12.112 kernel build with its dependency closure (`udptunnel4/6`,
  `crypto-lib-chacha20poly1305`, `-curve25519`, `-chacha20`, `-poly1305`, `crypto-kpp`), sha256-pinned in `kmods.pin` for the
  board and for the QEMU gate's armsr kernel, loaded at boot from its `/etc/modules.d` line; `wg` is Alpine's
  `wireguard-tools-wg` (`wg syncconf` from the applier's 0600 files). `check-rootfs.sh` fails the build without `wg`, the
  module or its modules.d line when the feature is on.
- **NTP server: chrony is the one NTP daemon.** busybox ntpd is gone: chrony (Alpine `chrony`, the non-NTS build, so no
  GnuTLS) keeps the clock and, when the NTP server page is switched on, serves the subnets of the chosen interfaces
  (`allow`, `local stratum 10`). It is the service the applier controls, `chronyd`, on both init systems (OpenRC
  `/etc/init.d/chronyd`, systemd `chronyd.service`), running as its own `chrony` user. The image ships a client-only
  `/etc/chrony/chrony.conf` (pool, `driftfile /var/lib/chrony/drift`); the page replaces it with its own. The board has no
  RTC: `chronyd -s` starts the clock at the drift file's time (chrony rewrites it hourly and at exit) and the early boot does
  the same from that file, the old `/data/.clock` or the build time, whichever is newest. A busybox-backend applier was the
  alternative; it was not taken because busybox ntpd has no `allow` lists and stops answering (stratum 16) whenever the
  upstreams are unreachable, while chrony costs 64 KiB of binary and 0.3 MiB of root.
- **Remote syslog: busybox syslogd is the backend.** rsyslog is 2.5 MiB installed (Alpine, before its libraries) and would have to
  replace the size-capped `/var/log/messages` on tmpfs that busybox keeps, so the Syslog page's applier
  (`patronus-network/src/syslog.rs`) now has a second backend: without `rsyslogd`, and with the image's launcher
  `/usr/libexec/patronus/syslogd` present, it writes the enabled collectors to `/etc/patronus/syslogd-remote.conf` (one
  `host:port` per line, managed file) and restarts `patronus-syslogd`; the launcher runs `syslogd ... -R host:port ... -L`
  (UDP, the local log is kept). busybox forwards over UDP only, so a TCP collector is refused with a 400 ("forwards over UDP
  only") instead of being sent over UDP, and it has no per-collector severity filter, so every severity is forwarded and the
  apply report says so.
- **System accounts on upgrade.** `/etc` is an overlay on the data volume, so a unit upgraded from an older image keeps the
  old `/etc/passwd`; the early boot now adds the image's system accounts that the persisted files lack (here `chrony`,
  logged as `account-added passwd chrony` in `/tmp/boot-times`), without touching existing lines.
- **`/dev` modes.** The board's and the armsr kernels have no devtmpfs, so the early boot builds `/dev` with `mdev`; without a
  config every node was `root:root 0660`, and no daemon that drops root could open `/dev/null` or `/dev/urandom` (found by
  the gate: `chronyc` segfaulted after dropping to `chrony`). `/etc/mdev.conf` gives the standard nodes 0666;
  `check-rootfs.sh` requires it.

Sizes **[measured]**, CI-unit images built from the same tree with and without these changes (2026-11-17, rw-man-04):

| | before (main 43797117) | with WireGuard + chrony + syslog | delta |
|---|---|---|---|
| `patronus-cli` stripped | 14,147,528 B | 14,540,840 B | +384 KiB |
| root.squashfs, OpenRC | 16.04 MiB (133 LEBs) | 16.44 MiB (136 LEBs) | +412 KiB |
| root.squashfs, systemd | 18.71 MiB (155 LEBs) | 19.11 MiB (158 LEBs) | +412 KiB |
| NAND left after kernel + root + 16 MiB settings (OpenRC / systemd) | 71.2 / 68.5 MiB | 70.8 / 68.2 MiB | -3 LEBs |

Per feature (`patronus-cli` alone, same builder, xz -9e of the binary in brackets as a guide to the squashfs cost):
`vpn-wireguard` +320 KiB (+135 KiB), `ntp-server` +64 KiB (+8 KiB), `syslog` +64 KiB (+12 KiB); all three together +320 KiB
(+142 KiB) on the main tree (segments are page-aligned, so small features can share a page). Packages: `wg` 67 KiB, chrony
(`chronyd` 258 KiB + `chronyc` 130 KiB + libseccomp), the eight WireGuard kmods 204 KiB unpacked.
Idle RAM on the QEMU gate (OpenRC, second boot, 60 s idle, VmRSS): patronus-web 20.4 -> 21.4 MiB (+1.0 MiB, with the gate's two
WireGuard tunnels, NTP server and collector configured), applyd 11.7 -> 11.9 MiB, chronyd 1.0 MiB in place of busybox ntpd 0.8 MiB; RAM used by
the whole box 34.7 -> 35.0 MiB of 482 MiB (systemd 37.2 MiB). The IPQ6018 units have 512 MiB.

Proof: `qemu-gate.sh` (both init systems, TCG): `/dev` node modes; chronyd running as `chrony` and `chronyc sources`;
WireGuard through the web API: server tunnel `wg0` (51820) and client tunnel `wg1` (51821) whose peer is `wg0` at
127.0.0.1:51820, plus a road-warrior peer with a generated key pair and PSK whose client config is exported; `wg show` has the
listen ports, two peers on `wg0`, the endpoint, the address, the `patronus-wg` ifalias and the peer route (protocol 249);
the client completes a real handshake. NTP: no answer before the page is switched on; `PUT /api/ntp` writes `allow
10.0.2.0/24` and `local stratum 10`, status running, and an NTP query from the LAN side (QEMU user net) gets a mode-4 reply.
Syslog: a UDP collector added on the page restarts syslogd with `-R 10.0.2.2:5514 -L`, the page's test message arrives at a
listener outside the VM, a TCP collector is refused. Second boot: the module is loaded, both tunnels are re-created from the
store and handshake again, the NTP server still answers, a message logged after the restart reaches the collector, and the
`chrony` account removed from the persisted `/etc/passwd` before the restart is back. Unit tests
`syslog::tests::busybox_backend_writes_udp_collectors_and_refuses_tcp`, `rsyslog_wins_over_busybox_when_both_exist`; host
tests (`tests/run.sh`) for every new `check-rootfs.sh` refusal.

Left out of the router-tier image, and why: IPsec (strongSwan), OpenVPN, L2TP, HA, traffic shaping, multi-WAN, PPPoE,
VLANs, NetFlow, IGMP proxy, NAT64, UPnP, VRFs, web proxy, IDS (Suricata), BGP/OSPF, SD-WAN, LDAP, TOTP and plugins. Each
needs daemons or libraries the image does not carry, and on these units the role is an access point, where the routing
features belong to the main router; the System page lists each missing feature with its reason. Flash is not the limit
(about 70 MiB of NAND stays free after the 16 MiB settings reserve); RAM and what an upgrade has to write are, so further
features are added one at a time with their measured cost, as here. The Slate (`ci/embedded-mips`, 16 MiB NOR) keeps its own
smaller set and is unchanged.

### 12.11 Accounts on a router image: yescrypt logins and package-managed users (2026-11-17)

Web login on the router tier reads `/etc/passwd`, `/etc/group` and `/etc/shadow` in-process (`PATRONUS_AUTH_BACKEND=shadow` in
`embedded.env`, enforced by `check-rootfs.sh`) instead of going through `pam_unix`. Reason: the image's libc is musl, whose
`crypt()` cannot check yescrypt (`$y$`), the hash Gentoo, Debian and Fedora write, so a password copied from a Horcrux or
Gentoo host was refused. The shadow backend verifies md5-crypt, sha256/512-crypt, bcrypt and yescrypt in pure Rust (the
RustCrypto `yescrypt` crate; a `$y$j9T$` hash needs about 16 MiB while it is checked, inside the root broker, one at a time).
Locked, empty, expired, damaged and unknown-scheme hashes never verify. Unit tests use hashes made by libxcrypt's `crypt(3)`;
the QEMU gate logs in through the web API with a yescrypt account and expects a wrong password to get 401. SSH password
logins still go through dropbear's `crypt()` and so need a hash musl can check; key logins work with any hash.

Accounts come from packages, not from copied shadow lines. An image carries `/usr/share/patronus/accounts.d/<user>/`
(`passwd`, `shadow`, `group`, `member-of`, `authorized_keys`), put there by `assemble.sh` from `ACCOUNTS_DIR` (the owner's
account lives in the private overlay package `net-misc/ctg-router-accounts`, which is where the build takes the directory from).
`/usr/libexec/patronus/accounts-sync` (run by the early boot after the `/etc` overlay is mounted, every boot) reconciles it into
the live files: adds or corrects the passwd line, creates the groups, joins them, sets the password hash and installs the key
into the account's home (on the data volume, dropbear's strict-modes ownership). Units whose `/etc` already holds the account
(made by the first-run page) are corrected in place. A password the user changed on the box is kept: the hash is only applied
when the account has none, still has the one this script set last time, or already equals the package's. A uid that belongs to
another name is refused. Host tests: `ci/embedded-common/tests/accounts-sync.sh` (23 checks, run by both tiers' `tests/run.sh`);
`check-rootfs.sh` refuses an image without the script, or with accounts that the early boot never applies. The CI image carries
a test account (`tests/ci-accounts`, public test password) that the QEMU gate checks after boot. The same script and account
directory serve the Slate (`ci/embedded-mips`), whose early boot runs it too.

The Slate (`ci/embedded-mips/slate/README.md`, "Before a real flash") runs the same `accounts-sync` from its early boot. A real flash
of a Slate image built in a builder without wpa_supplicant/dropbear/mtd-utils stranded the unit once (no ssh, no uplink, and the
guard could not revert); the image checks, the sysfs volume lookup and the builder's explicit build steps listed there close that.
### 12.12 The Wi-Fi page, access-point menus and "not available on this device" (2026-11-17)

Before this, an access point's web UI had no Wi-Fi entry at all (the radios came only from the access-point file
`/etc/patronus/ap.env`), offered router pages that do nothing useful on an AP (Routing, DHCP, DNS, segmentation,
traffic insights: the main router does those, and DHCP/DNS there could even start a second server on the LAN), and hid
the features the router-tier build leaves out (VPN, NTP, syslog, ...) without saying why. Coverage against LuCI and the
vendor firmware, and what is still missing: docs/router-tier-ui.md.

- **Wi-Fi** (`/wifi`, `GET/PUT /api/wifi`): country, 2.4/5 GHz channel, 5 GHz width, Wi-Fi 6 (on by default); networks
  with name, bands (both / 2.4 / 5), WPA2 / WPA2+WPA3 / WPA3, password (write-only; an admin can reveal one, audited),
  hidden, client isolation (`ISOLATE_<id>=1` -> `ap_isolate=1`), on/off, add/remove (at most 4 per band); connected
  clients with band, signal, rates and connected time, and "Disconnect" (`hostapd_cli deauthenticate`). It edits the
  same `ap.env` the boot reads (every line it does not manage is kept: address settings, test switches, comments),
  writes it atomically (0600, previous copy `ap.env.prev`), restarts the radios with `ap stop` / `ap start` and checks
  every expected network with `hostapd_cli status` (`ENABLED`, or `DFS` during the radar check); if one does not come
  up, the previous file is restored and the radios restarted, and the page says so. A unit without radios (QEMU) saves
  and reports that nothing was restarted. Under systemd the radios are started into their own transient scope, so a
  restart of the web UI never takes Wi-Fi down.
- **Access-point role** (`PATRONUS_DEVICE_ROLE=ap`): the router-only pages answer with an explanation naming the main
  router (the unit's gateway); changes to their APIs (`/api/dhcp`, `/api/dns`, `/api/ddns`, `/api/routing`,
  `/api/segmentation`) answer 409. The dashboard shows the uplink (bridge address, DHCP/static, gateway reachability, DNS,
  wired ports with link and speed) and a Wi-Fi summary; the VPN tile is hidden when no VPN is built.
- **System > Firmware** (`GET/POST/DELETE /api/system/firmware`, `POST /api/system/firmware/install`, admins): upload
  a `...-sysupgrade.tar` (up to 64 MiB, kept in RAM under /tmp); it is checked at once by `patronus-flash check` (the same
  guards as the console: board, fwtool metadata, kernel/root sha256, UBI sizes) and refused with the tool's reason
  otherwise; Install runs `patronus-flash sysupgrade` (staged on the settings volume, settings kept) and restarts the
  box; Discard drops the upload and any staged image. Every upload and install is in the audit log.
- **Backups** (System > Backups) of an access point also carry its Wi-Fi file (`"access_point": {"ap_env": ...}` in the
  export, 0600, admin download only, like the rest of the backup); restoring such a backup writes it back, restarts the
  radios and verifies every network, rolling the radios back (and saying so) if they don't come up.
- **System > Not available on this device**: `/api/features` adds `role`, `tier`, `board`, `wifi_backend` and `absent`
  (feature, label, reason: not in this router-tier image / not built (USE flag) / the main router does this on an AP).

Proof: unit tests `apwifi::tests` (shell quoting round trip, unmanaged lines kept, password change/keep, add/delete/
disable, validation, ids fit interface names, station dump, atomic write without radios) and
`routes::api::wifi::tests`; host test `ap: ISOLATE_<id>=1 ...`; `qemu-gate.sh` (both init systems): features + absent
list, AP pages and 409s, Wi-Fi PUT -> file 0600 and the boot's own `board.sh` sees the new values, no key in GET, bad
channel 400, admin reveal, settings kept across a restart, systemd scope placement; `ci/wifi-page-e2e.py` (Firefox +
Chromium, with `E2E_WRITE=1` add + remove a network through the page) run against a real unit: all checks passed, both
radios restarted and verified twice in 12 s, the unit's Wi-Fi variables identical afterwards.

### 12.13 Guest networks, block list, transmit power, client names, survey, Device page, online check (2026-11-17)

The follow-up to 12.12 closes the remaining gaps of the router-tier table (docs/router-tier-ui.md section 5 has the
details and the API):

- **Wi-Fi page**: crash-protection state (`wifi-guard status`, 12.6d: normal, or safe mode with its reason); per
  network "Guest" (`GUEST_<id>=1`: client isolation plus the `patronus_guest` nftables bridge table on `br-lan`, loaded
  by `ap start` before any radio comes up; if it cannot load, guest networks are not started at all); block list per
  network (`DENY_<id>`) or unit-wide (`AP_DENY`) as hostapd `deny_mac_file`s, reloaded live with `DENY_ACL` (`ap acl`);
  transmit power per radio (`AP_TXPOWER24`/`AP_TXPOWER5`, `ap txpower`); client names from the DHCP requests seen on
  the bridge (`patronus applyd` snoop, `/run/patronus/dhcp-names`) or the router's reverse DNS (`AP_NAMES`); channel
  survey (`iw survey dump` + scan results, least crowded channel). Power, names and block lists never restart the
  radios.
- **Device page** (`/device`, router tier): SSH keys per login account (validated, audited, root's last key protected
  while root has no password); lights on/off (`/usr/libexec/patronus/leds`, `LEDS=` in `/etc/patronus/device.env`);
  scheduled restart, off by default (OpenRC `patronus-crond` + root crontab, systemd `patronus-restart.timer` +
  `OnCalendar` drop-in, the unit state shown); on an access point its own address with `ap-addr`: the new address runs
  next to the old one and is undone unless confirmed from the new address in time (also across a restart, the boot runs
  `ap-addr boot` first).
- **System > Firmware > Check for updates**: `latest.json` + `latest.json.sig` under `<feed>/<board>/<init>/`, verified
  with `gpgv` against the release keyring in the image (fingerprint 5439354939B9C0552A68E9BBE323A6A3AC0A6506 required);
  "Download and check" fetches the listed image into the upload slot, checks size and sha256 against the signed list and
  runs `patronus-flash check`; installing stays a separate button. The image now carries `gpgv` and busybox
  `ssl_client` (https for `wget`).
- **Backups** carry the login accounts (`system_accounts`: passwd/shadow/group lines of every person's account,
  `authorized_keys`, root's keys) and a restore puts them back.

Proof: unit tests (`apwifi`, `apdev`, `apnames`, `apsurvey`), host tests `tests/run.sh` section 3c (deny files, guest
render, live txpower/acl, LEDs, restart schedule both inits, address revert at boot), real-packet tests
`tests/guest-netns.sh` (17) and `tests/addr-netns.sh` (9), the QEMU gate (both init systems: every item through the web
API, including an unconfirmed address change reverting by itself and a lost login coming back from a backup) and the
browser check `ci/device-page-e2e.py`. Real radios (block/guest with a phone, transmit power on air) are proven on the
house access points separately.


### 12.14 Channel plan: automatic channel selection by default (2026-11-17)

Every unit and every image now starts both radios on **automatic channel selection** (hostapd ACS): at each radio
start hostapd surveys the allowed channels (busy time per channel from the driver's survey, `acs_num_scans` rounds)
and takes the least busy one. No channel is baked into an image or a unit file; a fixed channel is a choice made on
the Wi-Fi page, never a default. Why: one house unit had its 2.4 GHz radio pinned to channel 1, which measured 70-75 %
busy, and 2.4 GHz roams into that unit failed (no association within 20 s, or 11-22 s to recover), while the other unit
on automatic channel 11 and every 5 GHz path were fine.

The plan is a set of settings, per band, in `/etc/patronus/ap.env` (defaults in `board.sh`), `GET/PUT /api/wifi`, the
Wi-Fi page and `patronus ap-wifi export|plan|apply` (a declarative YAML/JSON document of the same settings, passphrases
never exported):

| Setting | ap.env | API | Default |
|---|---|---|---|
| 2.4 GHz channel | `AP_CHAN24` | `chan24` | `auto` (or 1-13) |
| 5 GHz channel | `AP_CHAN5` | `chan5` | `auto` (or 36-48, 52-144 DFS, 149-165) |
| 2.4 GHz width | `AP_HT24` | `width24` | 20 (or 40) |
| 5 GHz width | `AP_HT5` | `width5` | 80 (or 20, 40) |
| channels ACS may pick, 2.4 GHz | `AP_CHANLIST24` | `chanlist24` | `1 6 11` (empty = all the country allows) |
| channels ACS may pick, 5 GHz | `AP_CHANLIST5` | `chanlist5` | empty = 36-48 and 149-165 (+ DFS / 5.9 GHz when allowed) |
| ACS may use DFS channels 52-144 | `AP_DFS` | `dfs` | off |
| ACS may use the 5.9 GHz channels 169-177 (U-NII-4) | `AP_UNII4` | `unii4` | off |
| ACS survey rounds | `AP_ACS_SCANS` | `acs_scans` | 5 (1-20) |

- 2.4 GHz ACS is limited to the three channels that do not overlap, so two units never end up half on top of each other.
- 5 GHz ACS leaves the radar (DFS) channels out by default: a DFS channel costs a 1-minute radar check (10 minutes on
  the weather channels 120-128) at every radio start, and a radar hit moves the radio. `AP_DFS=1` lets ACS use them;
  the Wi-Fi page's save then accepts the `DFS` state while the check runs.
- 5.9 GHz (U-NII-4, 169-177) is left out by default: the first live run of ACS on a house unit (regulatory domain
  US, OpenWrt 25.12 regdb) picked channel 177, which many phones and laptops cannot see at all. hostapd's ACS checks only
  the PRIMARY channel against `chanlist`, so a list ending in 165 still let it run 80 MHz on 165-177. The renderer
  therefore offers ACS only the primaries whose whole 40/80 MHz block is allowed (default at 80 MHz:
  `chanlist=36 40 44 48 149 153 157 161`); a list with no complete block is used as given, with a message.
- With ACS at 40/80 MHz the renderer writes only the width (`[HT40+]`, `vht/he_oper_chwidth`); hostapd sets the HT40
  direction and the VHT/HE centre channel for the channel it picks (proven in hwsim, below). A fixed channel
  still gets both from the renderer (12.6a).
- The radio cards on the Wi-Fi page show what the radio really runs (`hostapd_cli status`: channel, frequency, width,
  centre) and "picked automatically" or "fixed"; while ACS measures they say so. `patronus ap-wifi show` prints the same.
- ACS does not coordinate between access points: after both house units restarted on the defaults they picked the same
  5 GHz block (36-48) and the busier unit's 5 GHz went from 7-9 % to 38 % busy. Units of one network now coordinate
  (12.16); disjoint channel lists on the Wi-Fi page remain the manual alternative.
- `ap stop` waits until each hostapd has exited (it needs ~0.8 s to release the radio): a start right after a stop
  failed with "Match already configured" and crashed, so a Wi-Fi page save rolled back now and then.
- A save or `apply` that only spells out defaults (`AP_HT24=20` written or left out) is no change and restarts nothing;
  any channel-plan change restarts both radios (ACS only runs at hostapd start).

Proof: renderer host tests (`tests/run.sh`: defaults, DFS, channel lists, fixed channel without ACS lines, 2.4 GHz
HT40 direction, invalid values fall back to auto with a message), unit tests (`apwifi`: defaults, round trip,
validation, live width, export/plan/apply), the QEMU gate (`wifi_chanplan`, `wifi_cli`, both init systems), the
mac80211_hwsim scenario `tests/acs-scenario.sh` run by `tests/xbss-hwsim.sh` in CI with the image's own hostapd and the
`ap render` configs (default plan: 2.4 GHz lands on 1/6/11 at 20 MHz, 5 GHz at 80 MHz with the centre channel and HT40
direction right in hostapd AND the kernel, a station associates; 5 GHz 40 MHz; 2.4 GHz 40 MHz; DFS excluded from a
mixed list; DFS allowed: radar check, then ENABLED and a station joins) and the browser check `ci/wifi-page-e2e.py`
(form = API, radio cards = live state; `E2E_CHAN=1` changes the plan through the page and reverts it).


### 12.15 Signed upgrades refused at boot on builds before dca34699 (no clock at early boot), and the handoff install

The board has no RTC. The early boot re-verifies a staged upgrade (`upgrade-install verify` -> `fwcheck.sh`) before
anything sets the clock, so it runs at 1970: gpgv saw the release key (created 2026) and its signature as "created in
the future" and refused EVERY signed image (`/data/upgrade.log`: "release signature check FAILED", then "staged upgrade
failed verification"; the unit comes back up on the old build). A unit on a signed build before the fix could not
install any upgrade, through `patronus-flash`, the web Firmware page or the online update. The same staged files
verify at runtime. CI missed it because QEMU's virt machine has an RTC. Fix: gpgv runs with `--ignore-time-conflict`
(the time of a release signature proves nothing on this board); host test in `tests/run.sh` (a key and signature newer
than the clock still verify; fails without the fix).

Units still on an affected build (a signed build without the fix) get onto a fixed build ONCE with
`tools/handoff-install.sh`, which does not go through the early-boot verifier: stage the image with
`patronus-flash sysupgrade <img>` (no `--now`), copy the script to the unit, `sh handoff-install.sh arm`. It checks the
staged parts at runtime (board, sha256, release signature), bind-mounts itself over `/sbin/openrc-init` and runs
`openrc-shutdown --reexec`, so PID 1 becomes the script: it stops every process, unmounts the /etc, /var/lib and /root
overlays (the early-boot state) and execs `upgrade-install install`, which copies the parts to RAM, checks sha256 and
the signature again, pivots to the RAM root, writes root + kernel with read-back and restarts. Any failure before
writing restarts into the old system. OpenRC only (both house units). Proof: `tools/qemu-handoff.sh` (QEMU: PID 1
reaches the installer, the RAM root and stage2, the box restarts with its settings) and the first house unit
(hogs10-a14d1263 -> hogs10-dca34699: handoff, install, back up in ~60 s).

### 12.16 Boot rollback: a failed upgrade puts the previous image back by itself (2026-11-17)

**Constraint.** The stock OpenWrt FIT pins the root to UBI volume 1 (`root=/dev/ubiblock0_1` in its device tree's
`bootargs-append`, which wins over U-Boot's `root=`), and GL's U-Boot (`U-Boot 2016.01`, "uboot2.0 21.12.01" on the
house units) boots with `bootipq`, which reads the volume named `kernel`. A second root volume would need a rebuilt FIT
per slot, and a trial image whose kernel panics never reaches userspace, so the rollback must happen *before* Linux.

**What the units really have** (read on 10.66.69.10, read-only, 2026-11-17): the U-Boot environment is ONE copy at offset
0 of the NAND partition `0:appsblenv` (0x80000 bytes, 128 KiB blocks), CRC32 over 0x40000 bytes (`fw_env.config`:
`/dev/mtdN 0x0 0x40000 0x20000 4`); `bootcmd=bootipq; ping 192.168.1.2; run lfq; bootipq; run lf; bootipq; httpd
192.168.1.1; reset`, so U-Boot runs `bootcmd` from its environment and has hush (`if`/`test`/`&&`), `setexpr`,
`itest`, `saveenv`, `mw`, `reset` and `ubi part/read/write` (its own recovery code writes UBI volumes with
`ubi write`); the help texts are stripped. The flash is qcom_nand (U-Boot `nand device 0`); UBI lives on MTD `rootfs`
(0x7300000 bytes at 0xa00000; read from sysfs, never typed in). No fastmap. The APCS watchdog (`qcom,kpss-wdt`,
0xb017000, 32768 Hz, max 32 s) is built into the kernel (`qcom_wdt`, `handle_boot_enabled=Y`), `panic=1` is the
kernel default (`/proc/sys/kernel/panic`), RAM 0x44000000-0x4a0fffff is clear of the SoC's reserved regions. 254 free
LEBs (31 MiB) on a unit with `patronus_data` from `ubi-data`: room for a full previous kernel + root.

**Design.**
- `upgrade-install` (stage 2, RAM root) first copies the *running* kernel (FIT `totalsize`) and root (squashfs
  `bytes_used`, 4 KiB-padded) into the UBI volumes `kernel_prev`/`rootfs_prev` and reads them back, then arms a trial in
  the U-Boot environment (`pat_state=trial`, `pat_left=<attempts>`, `pat_boots=0`, `pat_prev`, `pat_new`, `pat_ksz`,
  `pat_rsz`) and only then writes the new image. From that moment a power cut during the write, a kernel that does not
  start, a root that panics or hangs and a system that never becomes healthy all end the same way.
- The bootloader script is installed by the image itself (`patronus-guard env-install`, every boot, writes only what
  differs): `bootcmd` becomes `run pat_boot; bootipq; run pat_failed; <stock rest>` (`pat_orig_bootcmd` keeps the stock
  one; `patronus-guard env-remove` restores it; any other `bootcmd` is left alone and the unit reports "no rollback").
  On a trial (`pat_boot` -> `pat_trial`) U-Boot counts the boot down and saves BEFORE booting, adds
  `patronus.trial=<n> watchdog.handle_boot_enabled=0` to the kernel command line for this boot only and arms the
  hardware watchdog (`pat_wdt`, `GUARD_WATCHDOG_TIMEOUT` x 32768 ticks), then the unchanged `bootipq` boots. With no
  boots left it sets `pat_state=revert`, saves, reads `rootfs_prev` and `kernel_prev` into RAM (both before writing
  anything), writes them over `rootfs`/`kernel` with `ubi write`, sets `pat_state=reverted`, saves and boots the old
  image normally. A boot command that returns during a trial or revert (unbootable kernel) resets at once
  (`pat_failed`); a power cut during the copy repeats it (the previous volumes are untouched).
- Linux side (`patronus-guard boot`, from `patronus-init` before the init system, so it covers OpenRC and systemd
  alike): on a trial it starts the watchdog feeder (busybox `watchdog`, the kernel no longer feeds it, so a userspace
  that never gets this far is reset) and the checks: `network` (an IPv4 address and the default gateway answers ping),
  `ssh` (tcp/22 listening), `web` (patronus-web running and its HTTPS answering), `hostapd` (the binary runs; when Wi-Fi
  is configured every radio's hostapd is `ENABLED`). `GUARD_PASS_ROUNDS` passing rounds in a row confirm the image
  (`pat_state=ok`, watchdog released with the magic close). If the window ends first the failure is written to
  `/data/boot-guard/last-failure`, the feeder is killed without the magic close (backstop) and the box restarts; U-Boot
  counts. After a revert the old image reports it (`reverted`, with the trial's own failure report, or "never reached its
  health checks" for a panic/hang/unbootable kernel) and sets `pat_state=idle`.
- Settings (nothing fixed in code): `/etc/patronus/boot-guard.board` (image: environment location, stock boot command,
  UBI MTD and U-Boot nand index, copy RAM addresses and limits, watchdog registers/clock, kernel arguments) and
  `/etc/patronus/boot-guard.conf` (unit policy, the web UI writes it): `GUARD_ENABLED`, `GUARD_REQUIRE` (refuse an
  upgrade that cannot be rolled back; `patronus-flash sysupgrade --no-rollback` overrides), `GUARD_ATTEMPTS` (2),
  `GUARD_WINDOW` (300 s), `GUARD_INTERVAL` (5 s), `GUARD_PASS_ROUNDS` (2), `GUARD_CHECKS`, `GUARD_NET_PING`
  (gateway/none/address), `GUARD_HOSTAPD` (auto/require/off), `GUARD_WATCHDOG` (1), `GUARD_WATCHDOG_TIMEOUT` (30 s),
  `GUARD_REBOOT_GRACE` (90 s).
- Where it shows: `patronus-flash status` (and `--json`), `patronus-guard status`, System > Firmware > "Boot rollback"
  (state, previous image, last failure, last events, settings form, "Confirm this image now", "Go back to the previous
  image"), `GET /api/system/firmware` (`boot_guard`), `PUT /api/system/firmware/boot-guard`, `POST
  /api/system/firmware/rollback|confirm`, and the audit log (every guard event once, user `boot-guard`, action
  `boot-<event>`; settings changes, rollbacks and confirmations under the admin's name). `patronus-flash rollback
  [--now]` puts the previous image back by hand (the bootloader copies it at the next restart).

**Proof.**
- Host tests (`tests/run.sh` 3b): the script written into a real U-Boot-format environment file with u-boot-tools
  (bootcmd, count-and-save-before-boot, read-both-before-write, watchdog ticks), idempotence (no write when nothing
  changed), a setting change rewrites it, arm/confirm/status JSON, env-remove, a non-stock `bootcmd` left untouched.
- `rollback-gate.sh` (both init systems): the shipped root under a REAL U-Boot (Alpine `u-boot-qemu`, qemu_arm64) on
  QEMU: the image installs its own script on first boot; a good image confirms (`patronus.trial=1` on its command line,
  counters cleared); bad images revert by themselves to the good one, byte for byte, healthy, with the right reason
  and exactly `GUARD_ATTEMPTS` trial boots: init exits (kernel panic), no network, web UI dead (with a power cut in the
  middle of the trial: counters survive), hostapd broken, kernel not bootable. Board facts that differ are settings in
  the test copy's `boot-guard.board`: virtio disks instead of UBI volumes (`virtio read/write` copy primitives),
  `run qboot` (virtio read + booti) instead of `bootipq`, environment on a virtio disk (`env export -c` + `virtio
  write`, a 3-line pflash bootstrap imports it), no hardware watchdog.
- `nandsim-proof.sh` (Linux UBI driver, simulated NAND of the board's geometry): env-install into a stock environment,
  `can-arm`, `save-prev` + `arm` as stage 2 runs them, the upgrade write, then the revert copy with the sizes from the
  environment gives back the old kernel and root byte for byte.
- Real unit: section 12.16 results below (hardware-only parts: `bootipq` after our prefix, U-Boot's own `ubi write`
  revert, the watchdog arm, ath11k/Wi-Fi after a revert).


### 12.16 Channel coordination between the access points of one network (2026-11-18)

Automatic channel selection (12.14) measures only what the unit hears while it decides, so two units with the same
SSIDs that start together, or one after the other with the first not yet on air, can both land on the same 80 MHz block
and share its airtime. UniFi, Aruba Instant and Omada plan channels across their access points; Patronus does the same
without a controller, from what each unit can hear. Default ON, per band.

- **Peers.** A peer is any BSS in a scan that broadcasts one of this unit's SSIDs (units are told apart from the
  neighbours' networks by SSID) or whose BSSID matches an entry of `AP_COORD_PEERS` (MAC of any BSSID of the other unit;
  needed only for hidden networks), is heard at `AP_COORD_MIN_SIGNAL` dBm or better, and is not this unit's own. Each
  peer's blocks are read from its beacon (HT operation secondary-channel offset, VHT operation width and centre): an
  80 MHz BSS covers four 20 MHz channels, a 40 MHz one two, a 2.4 GHz BSS every channel it overlaps (primary +-4).
- **At start** (`ap start`, also a Wi-Fi page save, `ap restart-band`): before hostapd is configured, `ap-coord plan` makes
  a temporary managed interface on each radio, scans the channels ACS may use (both bands at once, at most
  `AP_COORD_SCAN_SECS`), and writes the peers' channels to `/run/hostapd/coord-<band>`. The `ap` renderer drops every
  candidate channel whose 20/40/80 MHz block overlaps one of them from the ACS `chanlist` ("whole block" rule of 12.14
  still applies) and says so in its output. When no whole block would remain, the list is left alone and ACS decides
  (a third unit on a two-block band). A fixed channel is not planned.
- **Later** (`ap-coord run`, started by `ap start`): `AP_COORD_DELAY` seconds after start and then every
  `AP_COORD_INTERVAL` seconds (0 = once) the unit compares its own block (`hostapd_cli status`) with the peers it can hear.
  When one overlaps, the unit with the HIGHER key restarts that radio (`ap restart-band 5|24`, which plans again, so
  ACS lands elsewhere); the other stays. The key is the last five octets of the radio's own MAC (the first octet differs
  between a radio's BSSes, and both units compute the same ordering). This repairs the case the start-time scan cannot
  see: both units starting at the same second hear nobody. A move that would drop stations waits for the quiet hours
  `AP_COORD_QUIET` ("1-5", empty = any time); the first check after a start is not delayed (the clients just
  reconnected anyway).
- **Settings** (all typed, default in `board.sh`, `ap.env`, `/api/wifi`, the Wi-Fi page, `patronus ap-wifi export|plan|apply`):
  `AP_COORD5` / `AP_COORD24` (`coord5`, `coord24`, true), `AP_COORD_PEERS` (`coord_peers`, empty),
  `AP_COORD_MIN_SIGNAL` (`coord_min_signal`, -90 dBm, -100..-30), `AP_COORD_DELAY` (`coord_delay`, 120 s, 0..3600),
  `AP_COORD_INTERVAL` (`coord_interval`, 3600 s, 0 or 60..86400), `AP_COORD_QUIET` (`coord_quiet`, "1-5"),
  `AP_COORD_SCAN_SECS` (`coord_scan_secs`, 25 s, 5..120; also how long the first re-check waits for a starting radio). They are live: saving them restarts no radio, `ap-coord run`
  re-reads `ap.env` at each check.
- Not covered: three or more units on a band with only two free blocks (the list is then left to ACS), coordination with
  units of another vendor (they are found by SSID, which works when they carry the same SSIDs), DFS radar events (ACS and
  hostapd handle those).

Proof: host tests (`tests/run.sh`: scan parsing, block coverage, peer filter by SSID/MAC/signal, rendered chanlist with
and without free blocks, 2.4 GHz, `AP_COORD5=0`, `plan`, `check` tie-break and quiet hours), unit tests (`apwifi`:
defaults, round trip, validation, live), the QEMU gate (`wifi_chanplan`), `ci/wifi-page-e2e.py` (form = API) and the
mac80211_hwsim scenario `tests/coord-scenario.sh` (two units, same SSID, private mount namespaces: started one after the
other they end on different blocks on both bands; started blind at the same moment, the re-check moves exactly the
higher-key unit).
