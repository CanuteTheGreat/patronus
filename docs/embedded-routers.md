# Patronus on embedded routers (GL-AR750S "Slate" first)

Status: plan + feasibility spike, 2026-11-05; local web UI proven in QEMU 2026-11-06. Nothing here has touched the real Slate.
Spike scripts: `ci/embedded-mips/` (numbered in run order). Measured numbers are marked **[measured]**,
numbers taken from other repos' docs **[documented]**, guesses **[estimate]**.

Owner order: do the Slate first, then a test VM on the lab hypervisor, then replace kingscross.
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

### 6d. Two Wi-Fi uplinks in one upstream subnet (2026-11-17)

The repeater runs a client on each radio (`wl5-sta` preferred, `wl24-sta` fallback, board.sh `WAN5_IF`/`WAN_IF`), and both usually
join the same upstream network, so the box holds two addresses in one subnet with two MACs. A first install from OpenWrt came up
with both leases, synced its clock and resolved names, but was unreachable on its reserved address for the whole guard window and
was rolled back. Cause, reproduced in network namespaces (`tests/netns-multihome.sh`, needs root; the slower 2.4 GHz air is
modelled with `netem`): every uplink answered ARP for **both** addresses (`arp_ignore=0`), the faster 5 GHz client won the race,
so the upstream LAN mapped the 2.4 GHz client's reserved address to the 5 GHz MAC; new connections then arrived on `wl5-sta`,
and the boot management rule (SSH/web from `MGMT_NET`) only accepted `wl24-sta`. Result before the fix: 0/20 connections to either
address; after: 20/20 to both.

Fix (all board scripts, both init systems):
- `board-network`: each uplink answers ARP only for its own address and asks with it (`arp_ignore=1`, `arp_announce=2`), loose
  reverse-path filter (`rp_filter=2`). The list is `UPLINKS` in board.sh.
- `wifi-follow`: per-uplink source routing. For each `UPLINK_TABLES` entry `<sta>:<table>:<pref>` (defaults 4241/4242 and prefs
  30241/30242, clear of the routes applier's table 4250 and prefs 31000-31999; a unit can override them in unit.conf) it keeps a
  table with the client's subnet and gateway plus `ip rule from <addr>`, follows lease changes and removes both when the client
  loses its address.
- `apply`: the boot management rule covers every uplink client.
- `check-rootfs.sh` refuses an AP template without WPA (`wpa=` plus a passphrase/PSK); `ALLOW_OPEN_AP=1` is the explicit
  exception for a deliberate open network.
- The unconfirmed-boot count (`/data/.init-boot-attempts`, read by `patronus-init`) now records the root it belongs to
  (`<n> <BUILD>`), and every `patronus-flash root|rollback|openwrt` clears it. Before, a count of 2 left by a root the guard
  reverted survived the OpenWrt round trip, so the next Patronus install from OpenWrt was rolled back to the OLD root on its very
  first boot (seen on the unit: `openrc-attempt-3` -> rollback before any network).
- The early boot takes the hostname from `/etc/hostname` (unit value `UNIT_HOSTNAME`, else the hardware profile); nothing is
  hard-coded.

### 6e. Changing the NOR kernel: a bootloader trial with a way back (2026-11-21)

The kernel of the GL-AR750S lives in NOR (`kernel` partition, uImage at 0x9f060000); the Patronus root is a squashfs on the NAND
UBI. A root flash never touches the kernel and the guard (6b) only rolls the ROOT back, so a kernel change alone is not atomic:
new kernel + a root without its modules = no network, and the guard could not put the kernel back. Since 2026-11-21 a kernel
change is mechanical and has a proven way back (`patronus-flash kernel ...`, implemented in `/usr/libexec/patronus/nor-kernel`).

**What GL's U-Boot does on every power-on** (U-Boot 1.1.4 from github.com/gl-inet/uboot-for-qca95xx, `common/main.c` for
CONFIG_AR750S; read from the source, matched against the unit's own `u-boot` partition):
- environment: 64 KiB `u-boot-env` (CFG_ENV_SIZE 0x10000), CRC32 stored big-endian. On a stock unit it was never saved (all
  0xff), so U-Boot runs its compiled-in defaults (kept as `overlay/usr/share/patronus/uboot/gl-ar750s-1.1.4-gcf378d80.env`).
- `bootcount` is kept in RAM only (bootcount_store is AR300M-only); `bootlimit` is unset. No boot counter survives a power-on.
- the boot is hard-coded: `run lf` (the TFTP auto-recovery: `ping $serverip` fails on a normal network), then
  `bootm 0x9f060000`; only if that bootm fails does it run `bootcmd` (stock: a NAND boot that fails, then the web failsafe).
- hush parser, `test`, `setenv`, `saveenv`, `run` are built in.

**Slots** (board.sh `KSLOT_*`, all configurable): P = the `kernel` partition (what U-Boot boots), T = trial slot at
`nor_reserved`+0 (0x9f460000), K = previous kernel at `nor_reserved`+4 MiB (0x9f860000), each 4 MiB. `nor_reserved` holds only
stale data from GL's stock NOR firmware (nothing reads it; it is in the unit's NOR backup). `u-boot` and `art` are refused by
the code (`KSLOT_NEVER`) and are `read-only` in the kernel's device tree as well (both kernels); only `u-boot-env`, `kernel` and
`nor_reserved` are ever written, every write is erase + write + read
back (sha256).

**Trial script** (written into the environment by `patronus-flash kernel`): `lf` becomes `run pat_boot; <GL's lf>` and
`bootcmd` becomes `run pat_rescue; <GL's bootcmd>`. While `pat_try` is set, every power-on adds one `x` to it, saves the
environment and boots slot T; when it reaches `pat_max` (KSLOT_TRIES, default 3) U-Boot clears it and falls through to P by
itself. `pat_rescue` boots T, then K, when P is unreadable (a commit cut by a power loss). GL's own recovery variables (`lu`,
`rlf`, `lc`, `firmware_addr` ...) are kept verbatim.

**Sequence**
0. Once per unit: `patronus-flash kernel-rehearse` copies the RUNNING kernel to slot T and arms it as a trial (same kernel in T and
   P, so nothing can go wrong); after one reboot the early boot checks that U-Boot ran the script and saved its counter (`ox`) on this
   flash and records `pat_rehearsed` (bootloader sha). The automatic fallback after KSLOT_TRIES depends on that save, so `install`
   refuses until a rehearsal passed (`KSLOT_REQUIRE_REHEARSAL=1`). A failed rehearsal disarms itself and keeps installs refused.
1. `patronus-flash kernel <kver|uImage>` checks before anything is written: valid uImage (magic, header and data CRC), the
   image is one THIS root ships (`/usr/share/patronus/kernel/SHA256SUMS`, so only kernels built together with the running root
   can be installed), the root has `lib/modules/<kver>/modules.dep`, the kernel's device tree names this board (`BOARD=` of
   `/etc/patronus-release`), it fits a slot and the partition, the unit's bootloader is a build the script was proven
   against (`KSLOT_UBOOT_PROVEN`: sha256 of the whole `u-boot` partition) and has passed a rehearsal, and /tmp (16 MiB tmpfs)
   has room for the staged images. Then it writes T and arms the trial.
2. Power-on: U-Boot boots T. The early boot (`nor-kernel boot-check`) notes the trial (`/tmp/kernel-trial`); patronus-init does
   not count the boot against the root; a trial kernel the root has no modules for is aborted at once.
3. The guard decides: a confirmed boot (`patronus-guard ok`, or the unattended gateway check) runs `kernel-commit` (P -> K,
   T -> P, ~1 min of NOR writes); an unconfirmed one runs `kernel-abort` and restarts on P. A kernel that never reaches
   userspace is dropped by U-Boot after KSLOT_TRIES power-ons.
4. `patronus-flash kernel-rollback` puts K back into P; `kernel-status` shows slots, bootloader state and events
   (`/data/kernel/events`).
- Every root carries modules for the stock kernel AND the kernels it ships (`EXTRA_KMOD_ROOTS`, `KERNEL_IMAGES` in assemble.sh;
  `KERNELS=` in /etc/patronus-release; check-rootfs refuses a root missing any of them), so either kernel boots either root.
- `patronus-flash rollback` records which kernels each root has (`/data/.root-prev-kernels`) and moves the kernel back too
  when the previous root lacks modules for the NOR kernel (refuses if slot K doesn't help); `patronus-flash openwrt` first
  puts the recovery root's own kernel (`/usr/share/patronus-recovery/openwrt-kernel.bin`) back into P.

**Size** (OpenWrt 25.12.6 ath79/nand, xz 256 KiB squashfs): a second module set (6.12.118 next to 6.12.112, 4.0 MiB raw) costs
+1208 KiB; the shipped new uImage ~2.95 MiB and the recovery kernel ~2.9 MiB (the stock uImage shipped for `kernel 6.12.112` is
the same file and is deduplicated). NAND root 16.1 -> ~23 MiB; the UBI holds rootfs_new + rootfs + rootfs_prev of that size.
The NOR-only tier does not use it: there kernel and root are always written together (a second module set would take 1208 of
its 2304 KiB free).

**Proof without the unit** (`tests/nor-kernel-test.sh`, CI job `slate-nor-kernel`): fake MTD partitions with the board's layout;
nor-kernel runs under busybox sh with only busybox applets on PATH (the unit's tool set); every power-on is `tests/uboot-sim`:
GL's own hush parser and `test`/`echo`/`run` compiled from the pinned source (`gl-src.pin`, sha256-checked) inside the AR750S
main_loop, the default environment on a bad CRC, CRC checks in `bootm`. Covered: refusals (bad CRC, other board, too big, no
modules, not shipped by the root, unproven bootloader, a slot on `u-boot`/`art`) with flash unchanged; trial -> commit ->
rollback; a hanging trial kernel dropped by U-Boot after 3 power-ons; an unconfirmed trial aborted by the guard; a corrupted
trial slot; a trial kernel without modules; a power cut at EVERY flash erase of install and commit (each one boots a kernel and
ends consistent, the blanked `kernel` partition boots slot T via `pat_rescue` and the early boot resumes the commit); a blank
environment; the rehearsal (passed, and a counter U-Boot did not save). It also runs with the real images (`REAL=<dir>`: the unit's `u-boot` partition dump and the real 6.12.112 / 6.12.118
uImages). QEMU malta-BE then ran the built image's own nor-kernel on the target busybox (MIPS BE) against fake MTD files built from
the image's own files, inside the unit's real 16 MiB /tmp headroom: the flash bytes after install and after commit are identical to
the host runs, and GL's hush boots them as trial T (6.12.118) and then P (6.12.118, K = 6.12.112). Found by these before any flash: busybox `grep` stops a line at a NUL, so the device-tree check needs `tr '\000' '\n'`; the FDT property header puts a non-NUL byte right before the root compatible
string (match it at the end of a line); a `tail | head` pipe under `pipefail` ended assemble.sh silently; the unit's /tmp is 16 MiB.

**Only the unit can show**: that U-Boot's `saveenv` works on its SPI flash (the rehearsal proves it at zero risk before any real
trial), that this U-Boot build reads slot T through the 16 MiB memory-mapped flash window (0x9f460000; a failed bootm there falls
through to P and the early boot records "did not start", so the risk is a wasted trial, not a dead unit), and the real NOR write
time of a commit. A trial kernel that hangs WITHOUT panicking (no reboot) needs power cycles: U-Boot boots P by itself on the
fourth power-on; a panicking one reboots on its own. First flash: watch the serial-less boot through
`kernel-status` and the boot banner (`patronus: trial kernel ... boot ox`), with the U-Boot web failsafe (section 9) as the last
resort, which no part of this sequence touches.

### 6f. QEMU gate for the Slate root, both init systems (2026-11-22, `ci/embedded-mips/slate/qemu-gate.py`)

The board's radios, switch and NAND cannot be emulated; everything else of the router role can. `qemu-bundle.sh` (in the embedded
builder image, nor-ci.sh style) builds the NOR-profile root of each init variant with a THROWAWAY unit (fresh ssh key and dropbear host
key, no Wi-Fi uplink, never a real unit's files) and prepares the test root: the shipped root with OpenWrt's malta/be netfilter modules
(`kmods-malta.pin`, `tools/make-malta-kmods.sh`; the ath79 modules do not fit that kernel) and `wan_interfaces = ["eth1"]`. The bundle is
that root, OpenWrt 25.12.6's `malta/be` kernel (same 6.12.112 release as the Slate's NOR kernel, sha256-pinned), the gate and the key;
a small test host runs it without building anything: `qemu-system-mips -M malta -m 128`, TCG, root on IDE, an ext4 settings disk
(`patronus.data=/dev/sdb`), eth0 = LAN (user network, ssh/443/80 forwarded), eth1 = WAN, eth2 = a second LAN port with a LAN client behind
it (raw frames over a QEMU socket netdev: DHCP and DNS by hand, no extra guest OS).

Off-board mode: with no SoC Wi-Fi radio (`PHY24` empty, `NO_BOARD=1` in `board.sh`, `NO_BOARD=0|1` in `unit.conf` overrides) `board-network` bridges
eth0 flat into `br-lan` (no switch VLANs, no Wi-Fi), `wifi-follow` idles instead of exiting (the supervisor would respawn it), and the early
boot mounts the ext4 device named by `patronus.data=` when there is no UBI (RAM `/data`, marked `NO-DATA`, otherwise).

22 checks per variant, boot, restart from the web UI, boot again on the same disk: PID 1 and every service up (0 crashed/failed), ETPhoneHome
running, first-run claim (setup code, weak/mismatch/second claim refused) and login, web on 443 and the 80 redirect, boot guard armed and
confirmed, a firewall rule added through the API appears in the kernel's nft chain, an invalid rule is refused with the kernel's rules
unchanged, a config change becomes a revision and restoring it removes the rule from nft, a LAN client gets a DHCP lease (pool, router and
DNS options) and the router answers a local DNS record to it, a DNS change is rolled back through the history and undone, host name /
domain / time zone saved and applied, then after the restart everything persisted (rule, login, settings, the same client gets the same
address) and the gate prints the guest's memory and per-process RSS (`GATEMETRIC` lines).

What it found: the root had no zoneinfo database, so System > General refused every time zone ("not found in /usr/share/zoneinfo") on the
router tier (`assemble.sh` now ships the regions of `ZONEINFO_DIRS` from the build host, about 100 KiB squashfs, `check-rootfs.sh` requires it,
`ZONEINFO=0` builds without), and busybox mdev / OpenRC printed "unknown user/group" for every device node because the image had none of
the standard system groups (`assemble.sh` adds them).

### 6g. Proving the way back on the unit before a root swap (2026-11-25, `ci/embedded-mips/slate/tests/unit-rollback-proof/`)

The QEMU gate cannot exercise UBI, so before a new root becomes the boot root it is staged as volume `rootfs_new` and the unit runs the
NEW image's own `patronus-flash` / `patronus-guard` / busybox / mtd-utils from that volume (read-only through ubiblock) against a
throwaway UBI on `mtdram`: forward install, rollback twice, rollback twice more with `ubinfo` disabled (sysfs fallback), the guard's
revert to the embedded OpenWrt root with the config backup on a recreated `rootfs_data`, and a confirmed boot that stays. ubi0 is only
read. First real use: mg-2c677d42, 20/20 checks on the unit's kernel; it also found that `patronus-flash openwrt` mounted
`ubi0:rootfs_data` by name instead of the device it was given (now `$(basename $UBI)`). Procedure: the directory's README.

A unit's SSH/web from the upstream LAN must not depend on the boot-time `patronus-boot-mgmt` rule alone: any firewall apply (a
patronus-web start applies the stored ruleset; on a 128 MB unit an OOM kill of patronus-web restarts it) rebuilds the table without it.
`wifi-follow` re-inserts it within one MGMT_EVERY cycle (measured: back 8 s after `patronus-cli apply`, 13 s after a web restart), and a
stored WAN rule from the management subnet makes it survive applies outright.

### 6h. The 5 GHz radio as uplink client: driver choice, radio watchdog, off by default (2026-11-25)

The GL-AR750S has one 5 GHz radio (QCA9887, ath10k on PCIe). As a repeater it would be the uplink client AND the 5 GHz access point,
on one channel (`#channels <= 1`). Measured on a unit (image mg-2c677d42, OpenWrt's default driver ath10k-ct 2025.12.01 + firmware
10.1-ct-87):

| | ath10k-ct + 10.1-ct-87 (OpenWrt default) | kmod-ath10k + 10.2.4-1.0-00047 (upstream) |
|---|---|---|
| client + AP, idle, burst seen | 11 firmware restarts in 15 min (`Cannot communicate with firmware`, each after ~3 s of `SWBA overrun`), then quiet; after 3.6 days once **wedged** (every firmware call `-143`, supplicant hw scan every second, load 8-17, SSH timeouts) | none in 25 min |
| client + AP, reassociation every 90 s, 15 min | 0 restarts, 3.7% ping loss, avg 19 ms, max 3.9 s | 0 restarts, 1.9% loss, avg 4.6 ms, max 0.8 s |
| client scan | never found an AP 5 GHz BSS at -42 dBm on 5180 MHz (also with the client alone): joined a far AP at -76 dBm, VHT-MCS 0-4 | found it at once: -42 dBm, VHT-MCS 5 80 MHz (260 Mbit/s) |

The stall is the known 10.x "TX credit starvation" in AP mode (no beacons go out: `SWBA overrun`; WMI commands time out, the last
ones `MGMT_TX`), which the driver's hardware restart usually clears; the wedge is the case it does not. The LED trigger
(`ath10k-phy0`, WMI `GPIO_OUTPUT` per blink) is not the cause: with the trigger off the restarts went on. Three changes:

- **Driver (`wifi5.pin`, `WIFI5_DRIVER=upstream|ct`):** the image replaces the stock root's ath10k-ct modules and ct firmware with
  OpenWrt 25.12.6's own kmod-ath10k (same kernel, same backports as mac80211) and linux-firmware's QCA9887 `firmware-5.bin`, from a
  pinned tar (`tools/make-wifi5-kmods.sh`, Forgejo generic package `patronus-owrt-ath10k-ar750s`). `/etc/patronus-release` records
  `WIFI5_DRIVER`; `check-rootfs.sh` refuses an ath10k root without firmware for its driver. A kernel bump (`ci/embedded-openwrt`)
  must rebuild kmod-ath10k for the new kernel too (`EXTRA_KMOD_ROOTS` kernels keep their own driver and the ct firmware stays then).
- **Radio watchdog + blacklist backoff (`wifi-follow`, all `RADIO_*` / `HEALTH_*` keys documented there, settable in `unit.conf`):**
  `RADIO_CRASHES` firmware restarts in `RADIO_WINDOW` s drop the 5 GHz client (supplicant stopped, interface down: the 2.4 GHz
  client carries the traffic, the 5 GHz AP keeps serving); a wedged firmware (`RADIO_WEDGE_LINES` new `-143` errors with no recovery)
  also re-probes the device (PCI unbind/bind, interfaces re-created by `board-network radio5`), at most once per `RADIO_REBIND_MIN` s.
  A dropped client returns after `RADIO_HOLD` s, doubling per drop up to `RADIO_HOLD_MAX` (drop count on `/data/wifi-follow`). The
  gateway-probe blacklist no longer repeats every few seconds: the gap doubles from `HEALTH_BACKOFF` to `HEALTH_BACKOFF_MAX`, and
  `HEALTH_DROP_AFTER` blacklists in `HEALTH_DROP_WINDOW` s drop the client the same way.
- **`UPLINK5=on|off` (board.sh default `off`, per unit in `unit.conf`):** with `off` the 5 GHz radio is an access point only (on its
  template channel, free of any uplink) and the 2.4 GHz client is the uplink. The setting, its default, the reason and its live
  state (connected / stopped by the watchdog) are published by `board-settings` as `/run/patronus/board-settings.json`, served in
  `/api/features` (`board_settings`) and shown on System > Hardware settings. The default stays `off` until a unit runs the upstream
  driver as client + AP for a long soak without a restart or wedge.

Host tests: `tests/wifi-follow-test.sh` (backoff, drop/return/hold doubling, restart count, wedge -> re-probe, no loop, ring rollover,
`UPLINK5=off`), `tests/board-settings-test.sh` (JSON, typed key, fallback on a bad value, escaping), `tests/run.sh` (check-rootfs,
pin). On a unit: the A/B phases above and a 12 h soak.

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

Rules: unknown sections are listed in an `unmapped` report (never dropped silently); secrets are copied into the store's secret table, not into logs; `--dry-run` prints the `patronus apply` diff. Proof order: (1) run it on `router-slate.tar.gz` offline, (2) apply in the malta QEMU twin, (3) only then on the device. Status: **written** for `network` interfaces (static/dhcp/dhcpv6), `dhcp` pools + static hosts, `firewall` zones/ACCEPT rules/redirects (stock OpenWrt rules are reported as covered by default) and `wireless` (AP -> Wi-Fi network with `wifi-ap`; STA entries parked in order with their `disabled` flag). Usage: `patronus import-uci <tarball|dir> [--dry-run] --map lan=br-lan --map wwan=wl24-sta` (UCI device names differ from Patronus ones, hence `--map`). Since the x86 router migration work it also imports (`crates/patronus-cli/src/commands/import_uci_ext.rs`): the `network.globals` ULA prefix (static `::1/64` per interface in OpenWrt's `ip6assign` slot order), the DHCPv6 client DUID, the DHCPv6 IAID (`interfaces.dhcp6_iaid`, see below) and prefix delegation to the `ip6assign` interfaces, packet steering, WireGuard interfaces and peers with their keys, port, addresses, MTU, PSKs, endpoints and keepalive (old client configs keep working), static routes, the dnsmasq section (local domain, rebind protection + exceptions, cache size, query log, `localservice 0` -> DNS on every lan-zone interface, per-domain and reverse-zone forwarding), `domain` host records, DHCP option 6 and IPv6 `dns`, RA/DHCPv6 modes with a prefix-relative DHCPv6 pool, static lease `leasetime`/`dns`, firewall defaults (REJECT, SYN flood), zone `mtu_fix` (MSS clamp), `masq` on non-WAN zones, zone policies for tunnel members, ACCEPT/DROP/REJECT rules, IPv4/IPv6 port forwards (`family`), a redirect to the router itself (input allow), the IPv4-options drop include, mwan3 (gateways, monitor IPs, failover group as the default gateway), DDNS (IPv4+IPv6 pair -> one client), Wi-Fi STA uplinks (first enabled network per radio), host name, time zone, NTP server, and `etc/ssh/sshd_config` (port, listen, root/password policy, user CA, principals). `--ssh root@router[:port]` reads the configuration straight from the running router into a 0700 scratch file. Still listed in `unmapped`: bridges/switch/VLANs, pppoe, dnsmasq ipsets, a second (dropbear) SSH daemon, per-user authorized keys, the old host certificate, LuCI/uhttpd/rpcd/acme/vnstat/socat/wgserver files. Netlab proof: `ci/netlab/lane-d-uci-import.sh`.

**DHCPv6 IAID.** The ISP binds the address and the delegated prefix to DUID + IAID (RFC 8415), so a replacement router that keeps only the old DUID is answered with `NoPrefixAvail` until the old binding expires. The importer carries the old router's IAID into `interfaces.dhcp6_iaid` (one value serves IA_NA and IA_PD). OpenWrt's odhcp6c derives it as follows (odhcp6c `src/dhcpv6.c` and `src/odhcp6c.c`, netifd `dhcpv6.sh` and `network_generate_iface_iaid`):
- OpenWrt 24.10 and older: IA_NA IAID is the constant 1 and the IA_PD IAID is the first prefix index, 1: both 1.
- OpenWrt 25.12 and newer: the first four bytes of `md5(<kernel device odhcp6c runs on>)` (for example `printf eth1 | md5sum` = `6f1799c8...`) for IA_NA, and `dhcpv6.sh` passes the same value as `-P<len>:<hex>` for IA_PD.
- `option reqprefix '56:<hex>'` in UCI pins the IA_PD IAID by hand.
Source of the value, in this order: the running `odhcp6c` command line (`--ssh` reads it from the live router: `-P0:<hex>` = the 25.12 scheme, `-P0` alone = the 24.10 scheme), then the release in `usr/lib/os-release` (`etc/openwrt_release` as a fallback; `--ssh` fetches both), then the device name of the `dhcpv6` interface (`@wan` aliases and PPPoE links resolve to `pppoe-wan`). When the release is unknown and no live client was read, the importer pins nothing and lists a manual step with both candidates (`1` and the md5 value): pin the old router's IAID or the ISP may refuse the delegated prefix until the old binding expires. When IA_NA and IA_PD differ (a hand-set `reqprefix` IAID), the report names both and Patronus pins the IA_PD value. Unit tests: `import_uci_ext.rs` (`iaid_*`, `l3_device_*`, `release_major_*`).

## 8. Spike results and blockers (real runs on CI host)

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

Principle: the Slate stays on OpenWrt for ETPhoneHome QA until step D passes. Patronus development uses the malta QEMU twin and (phase 2) a lab-hypervisor VM. Nothing below is run without the owner.

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
2. **lab-hypervisor test VM:** `standard` tier (glibc, x86_64, OpenRC, full web UI) imported from kingscross' OpenWrt config (`kingscross` is OpenWrt VM 100; its config tarball is about 10 MB and is covered by the nightly vzdump, not the router pull). Same importer, run in a VM that mirrors kingscross' interfaces on a spare bridge with test clients. Exit: LAN/WAN/VPN parity checklist passes for 7 days.
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
- **A remote install through OpenWrt needs the uplink on a LAN port.** Fresh OpenWrt answers SSH only on its LAN ports
  (192.168.1.1). If the unit's only cable sits in the port OpenWrt names `wan`, the unit takes a DHCP lease there and
  answers ping, but the `wan` firewall zone rejects SSH and HTTP, Wi-Fi is off, and there is no remote way in: someone has
  to move the cable to a LAN port (or use U-Boot recovery). This happened on a unit whose stock firmware worked as a plain
  LAN bridge, so the stock setup does not tell you which port OpenWrt will call `wan`. Before writing OpenWrt's
  factory.ubi without hands on site, check which port has link on the stock firmware (each `ethN`'s `carrier` and its
  MAC, compared with OpenWrt's `wan` MAC from the ART partition), and if it is the WAN port, write a factory.ubi whose
  first boot bridges all ports (a Patronus factory.ubi does: br-lan holds `lan1`-`lan4` and `wan` and takes a DHCP lease;
  writing it straight from stock is not yet tested on a unit).
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

### 12.13 Languages and the API description on the router tier (2026-11-26)

`patronus-web` carries the Fluent catalogs (English, German) and the OpenAPI document (`/api/docs`,
`/api/openapi.json`, docs/API.md, docs/I18N.md) on every tier. Cost **[measured]**: the router-tier multi-call
`patronus-cli` (CLI + web UI, `aarch64-unknown-linux-musl`, the exact flags and features of
`stage-patronus.sh`: opt-level z, fat LTO, stripped), built from `origin/main` and from the branch head with the same
toolchain on an arm64 host:

| | stripped binary | as xz -9e (the squashfs codec) | as zstd -19 |
|---|---|---|---|
| before | 16,048,944 B | 5,828,480 B | 6,642,612 B |
| after | 16,573,288 B | 5,911,244 B | 6,739,904 B |
| delta | +524,344 B (+3.3 %) | **+82,764 B (+1.4 %, 80.8 KiB)** | +97,292 B |

About 255 KB of the raw delta is the compact OpenAPI document (it compresses about tenfold); the Fluent runtime and
the two catalogs are the rest. The NAND budget (`nand-budget.sh`) and the NOR budget (`nor-ci.sh`) are checked by CI on
every change as before; the QEMU gates of both images fetch the document and the reference page from the booted router
and switch the account to German (`i18n_docs` in `ci/embedded-aarch64/ax1800/qemu-gate.sh` and
`ci/embedded-mips/slate/qemu-gate.py`).

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

Sizes **[measured]**, CI-unit images built from the same tree with and without these changes (2026-11-17, CI host):

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
  (12.17); disjoint channel lists on the Wi-Fi page remain the manual alternative.
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

**What the units really have** (read on a unit, read-only, 2026-11-17): the U-Boot environment is ONE copy at offset
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


### 12.17 Channel coordination between the access points of one network (2026-11-18)

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
  The kernel can cut a scan short (another radio's hostapd starting, a regulatory update): iw then exits 0 with the
  cached list, so the channels not visited yet are missing and an older scan's leftovers pass for the answer. The
  pre-start scan therefore repeats until two consecutive scans hear the same BSSes (`AP_COORD_SCAN_TRIES`, at most 5;
  it says so when they never agree); an empty first scan is repeated `AP_COORD_RESCANS` times (2). The on-air re-check
  scans once (each `ap-force` scan takes the radio off its channel).
- **Later** (`ap-coord run`, started by `ap start`): `AP_COORD_DELAY` seconds after start and then every
  `AP_COORD_INTERVAL` seconds (0 = once) the unit compares its own block (`hostapd_cli status`) with the peers it can hear.
  When one overlaps, the unit with the HIGHER key restarts that radio (`ap restart-band 5|24`, which plans again, so
  ACS lands elsewhere); the other stays. The key is the last five octets of the radio's own MAC (the first octet differs
  between a radio's BSSes, and both units compute the same ordering). This repairs the case the start-time scan cannot
  see: both units starting at the same second hear nobody. Overlap is judged on what each unit transmits: the peer's
  footprint (2.4 GHz: +-4 channels around its primary, the same rule the start-time plan uses to drop candidates)
  against this unit's own channel(s) only, so 20 MHz units on channels 6 and 11 do not overlap (comparing two widened
  sets reported them as sharing 7-10 and restarted the 2.4 GHz radio every `AP_COORD_INTERVAL`). A move or restart waits for the
  quiet hours `AP_COORD_QUIET` ("1-5", empty = any time) whether or not stations are connected; this includes the first
  check after a start. Loop guard: after a move or restart attempt, no further attempt happens while the radio still sits on
  the same primary channel. A failed move is covered too; the guard clears when the overlap disappears or the channel
  changes. State is kept in `/run/patronus-ap-coord-restart-BAND` and clears at boot; the log says "not moving again".
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

Hardware (two GL-AX1800 access points of one network with the same SSIDs, 2026-11-17/18):
- `ap start` scan: the first unit booted while the second was on 149 (2.4 GHz channel 1): its lists became `36 40 44 48`
  and `6 11` and ACS took 44 / 6. The second unit, flashed afterwards, heard the first on 36-48 and took 153 (block
  149-161) and 2.4 GHz 11. Before this, on the same radios and ACS alone, both units had ended on 36-48 and one unit's
  5 GHz went from 7-9 % to 38 % busy.
- A scan on a radio that is already running an AP only sees its own channel (ath11k does not scan off-channel while it
  serves clients); that is enough for the re-check (an overlap is by definition on or beside the unit's own channel),
  and the start-time scan runs from a temporary interface before the AP exists, where the whole band is visible.
- Both units restarted at the same instant without the start scan (`AP_COORD_NOPLAN=1`, the test hook): 5 GHz happened
  to separate (36-48 / 149-161), 2.4 GHz did not (both on 6). Two minutes later the first re-check on the unit with the
  higher key logged "shares channels with ...; restarting this radio so ACS picks another block", its 2.4 GHz radio
  restarted (about 4 s) and came back on 11; the other unit logged "the other unit has the lower key and moves" and stayed.
- Restarted at the same instant WITH the start scan, both avoided each other at once: the kernel keeps a BSS in its scan
  list for 30 s after its last beacon, so a unit that restarts still shows up for the other one.
- Client tests through a lab Wi-Fi client (private container, MAC cleared between tests): lease < 0.3 s, gateway,
  internet, DNS, 0 % loss of 40 pings on every BSS of both units (SSID x band x unit = 8), roams between the units on 5
  and 2.4 GHz and between the bands of one unit online again within 1.3 s, repeated after the restarts above.

### 12.18 Weak stations stay on the wrong access point; a deaf station floods authentication (2026-11-18)

Found on a two-unit network the morning after both units were upgraded one after the other. Each restart sends every
station to the other unit, and most clients never leave an access point while the link still works (no 802.11k/v on
these images; 802.11r stays off, section 12.6d). The unit restarted last ended up with the far-away devices of the whole
house: 39 stations instead of ~5, smart plugs, washer/dryer and cameras at -65..-79 dBm, while the unit next to them
heard them at -20..-50 dBm. Measured by disconnecting 17 such stations one at a time (hostapd `deauthenticate`): 7
re-joined the other unit 20-45 dB stronger, 10 came straight back (no better unit in range). Weak links mean low rates and
retries (one smart speaker at -79 dBm: 7,943 failed transmissions), which costs airtime for every station on the channel.
A second source of lost airtime: a smart-home device with a deaf radio (never acknowledges the authentication response)
retried every ~4 s on both 2.4 GHz SSIDs, about 1,000 attempts an hour per unit, each a response plus retransmissions,
and its log lines rotated `/var/log/messages` within ~30 min, so every other event was gone before anyone could read it.

Changes:
- `libexec/patronus/ap-steer` (started by `ap start`, stopped by `ap stop`): every `AP_STEER_INTERVAL` s it reads the
  station lists. A station whose average signal stayed at or below `AP_STEER_SIGNAL` dBm for `AP_STEER_AFTER` s and that
  is idle (below `AP_STEER_IDLE` kbit/s, so a call or a stream is never cut) is refused on every BSS of this unit for
  `AP_STEER_BLOCK` s through hostapd's deny list, at most `AP_STEER_MAX` per round; `AP_STEER_EXEMPT` lists MACs it never
  moves. A station it moved that comes back is left alone for `AP_STEER_RETRY` s (see "No ping-pong" below). The unit's
  own block list (`deny-<bss>`) is never lifted by it. `AP_STEER=auto` (default) acts only when another access point of
  this network is known (heard by `ap-coord plan`, listed in `AP_COORD_PEERS`, or a station that left turned up behind a
  wired bridge port); `1` always, `0` off. `ap-steer status` shows what it is doing. (Superseded by 12.18a: the
  refusal is now the last resort; steering asks first with 802.11v and measures with 802.11k.)
- The image's hostapd (`hostapd/patronus-xbss.diff`, pkgrel 105): a station with more than `AP_AUTHFAIL_MAX`
  unacknowledged authentication responses in `AP_AUTHFAIL_WINDOW` s is ignored on that radio for `AP_AUTHFAIL_HOLD` s,
  doubling per further hold up to `AP_AUTHFAIL_HOLD_MAX`, until it completes a connection (one log line per hold instead
  of one per attempt). The SSID-hop limit of 12.6d is now settable too (`AP_XBSS_MAX/WINDOW/HOLD`). Both are written per
  radio as `patronus_*` lines by `ap render`; a `*_MAX` of 0 turns a limit off.

Defaults (board.sh, override in ap.env): `AP_STEER=auto AP_STEER_SIGNAL=-65 AP_STEER_AFTER=600 AP_STEER_IDLE=64
AP_STEER_BLOCK=30 AP_STEER_RETRY=21600 AP_STEER_MAX=2 AP_STEER_INTERVAL=30`, `AP_AUTHFAIL_MAX=10 AP_AUTHFAIL_WINDOW=60
AP_AUTHFAIL_HOLD=60 AP_AUTHFAIL_HOLD_MAX=3600`, `AP_XBSS_MAX=6 AP_XBSS_WINDOW=60 AP_XBSS_HOLD=30`. Host tests:
`tests/run.sh` (renderer values and validation, ap-steer decisions with a fake station dump and hostapd_cli, two units
swapping one station).

No ping-pong: a unit keeps the record of every station it moved for `AP_STEER_RETRY` s. If the station joins this unit
again in that time (it found no better unit, or the other unit sent it back because it was even weaker there), it is
left alone here until the move is `AP_STEER_RETRY` s old. So each unit moves a given station at most once per
`AP_STEER_RETRY`, and two units can swap a station at most once (one round trip) in that time; `tests/run.sh` drives two
units for 11,000 s and checks it. The units do not exchange signal readings over the LAN: that needs an authenticated
channel between units, and the per-unit record already bounds the cost to one round trip of an idle station.

Settings (typed, like the channel coordination of 12.17): every key above is in `/api/wifi`, the Wi-Fi page (groups
"Steering" and "Misbehaving devices") and the declarative document (`patronus ap-wifi export|plan|apply`), with these
ranges: `steer` auto|on|off, `steer_signal` -90..-40 dBm, `steer_after` 30..86400 s, `steer_idle` 0..1000000 kbit/s,
`steer_block` 0..3600 s, `steer_retry` 0..604800 s, `steer_max` 0..64, `steer_interval` 10..3600 s, `steer_exempt` up to
256 MACs; `authfail_*` and `xbss_*` 0..86400 (and `authfail_hold_max` >= `authfail_hold`). Steering settings are live (no
radio restart: ap-steer re-reads ap.env every round); the hostapd limits restart the radios. `check-rootfs.sh` requires
an executable ap-steer and a hostapd that knows `patronus_authfail_*`; the QEMU gate checks the defaults, a live
steering change, bad values (400) and `ap-steer status`.

Found by that gate: the Wi-Fi API compared only some live settings when deciding whether anything changed, so a
change of only the channel-coordination (12.17) or steering settings answered 200 "nothing changed" and was never
written. `same_settings` now compares every typed setting; unit tests cover a live-only change of each kind.

### 12.18a Steering asks first; a disconnect is the last resort, at night only (2026-11-18)

Found in use: the refusal of 12.18 is a disconnect, and "idle" by byte rate still covers devices people look at. A smart
display at -80 dBm was refused at 17:42 local time and was gone for 8 s before it joined the other unit, and the
drop was visible on it. Several speakers, plugs and a phone were refused the same evening. A disconnect is visible on displays,
speakers and TVs, and a phone in a pocket is "idle" until it is picked up.

Changes (`libexec/patronus/ap-steer`, rewritten; header comment = the exact rules):
- Every BSS now advertises 802.11v BSS transition management and 802.11k radio measurement (`bss_transition=1`,
  `rrm_neighbor_report=1`, `rrm_beacon_report=1`, settings `AP_BSS_TRANSITION` / `AP_RRM`, default on; `AP_WNM_SLEEP`
  default off). 802.11r stays off (12.6d). The other units' BSSes of the same SSID are loaded as neighbor reports.
- A weak station that supports beacon reports is first asked what it hears (`req_beacon`, `AP_STEER_REPORT`
  active|passive|table|off). Only if it hears another unit `AP_STEER_MARGIN` dB (default 8) better than this one is it
  asked to move; otherwise it is left alone for `AP_STEER_RETRY`. A station that never answers is treated as one without
  802.11k. A station with 802.11v but no 802.11k gets the request with the other units as candidates and measures them
  itself. The request (`bss_tm_req`, preferred candidate, no "disassociation imminent") is advisory: the station roams
  without a disconnect or declines. At most every `AP_STEER_BTM_EVERY` s per station, only while it is idle.
- A disconnect (the old refusal) happens only inside `AP_STEER_QUIET` (default 01:00-05:00, local time from `AP_TZ`) with
  `AP_STEER_KICK=quiet`, only for a station with no traffic for `AP_STEER_QUIET_IDLE` s (byte counters), that ignored a
  request for `AP_STEER_BTM_WAIT` s (or has no 802.11v, with `AP_STEER_LEGACY=quiet`), never when its own measurement
  says no unit is better or it declined with "no suitable candidate", at most once per `AP_STEER_KICK_EVERY` (a day).
- A weak station that just arrived from another unit (its MAC was behind a wired port last round) is measured at once;
  if it hears another unit clearly better it is asked straight over, so a bad move is undone within a few rounds. A
  station that roamed away on its own is dropped from the live list as soon as the bridge learns it behind a wired port.
- Per-device "don't steer": the Steer checkbox in Connected clients edits `AP_STEER_EXEMPT` (live).
- Every step (measure, request, answer, roam, stay, disconnect, return) is a JSON line in
  `/var/lib/patronus/ap-steer/history` (newest `AP_STEER_HISTORY`, default 500) and in syslog; `/api/wifi` returns
  `steer_status` (mode, why idle/on, peers, stations being worked on) and `steer_history`, shown in the Wi-Fi page's
  Steering card. `ap-steer status` says "off: switched off in the settings" when `AP_STEER=off` (it used to say "no other
  access point known").
- `AP_TZ` (typed `timezone`, POSIX TZ string, default UTC0): board.sh exports it as `TZ`, so the quiet hours, the
  nightly channel re-check (12.19) and the coordination hours (12.17) are local time. The image has no zoneinfo; before
  this every hour setting on these units was UTC (a "03:30" re-check ran at 19:30 in UTC-8).

Proof: `tests/run.sh` (decisions with a fake station dump and hostapd_cli: no disconnect outside the quiet hours for any
station kind, beacon-report-driven requests, roam recording, "stay" when nothing is better, silent 802.11k stations,
night disconnect rules, once per day, midnight-wrapping window, bad-move revert, two units without ping-pong);
`tests/steer-hwsim.sh` (mac80211_hwsim, real hostapd + wpa_supplicant, two APs, the product's `ap render` configs):
10 of 10 soft moves without a disconnect event (BSS-TM-RESP status 0, 0-1 lost pings at 10/s), against the old
refusal, which disconnected the station every time (5 of 5). hwsim has no scan or authentication latency, so it proves
disconnect vs no disconnect, not the length of a real outage. Settings: typed in `/api/wifi`, the Wi-Fi page and
export/plan (`steer_kick`, `steer_quiet`, `steer_legacy`, `steer_report`, `timezone` live; `steer_margin`,
`steer_btm_every`, `steer_btm_wait`, `steer_quiet_idle`, `steer_kick_every`, `steer_history` live numbers;
`bss_transition`, `rrm`, `wnm_sleep` restart the radios). QEMU gate: defaults, a live soft-steering change, bad values,
no 802.11r in the rendered configs.

Limits: the units still exchange nothing over the LAN; "the other unit hears it better" comes from the station's own
beacon report (802.11k) or its own choice (802.11v). Devices with neither (many smart-home devices and some displays)
are never asked; with `AP_STEER_LEGACY=quiet` they can only be moved by the night disconnect.

Hardware results (two GL-AX1800 units, ~50 stations, 2026-11-19):
- 802.11v/k on the IPQ6018 firmware (WLAN.HK.2.5.0.1): `bss_transition=1`, `rrm_neighbor_report=1`,
  `rrm_beacon_report=1` on every BSS ran for 100+ min (first unit, up to 42 stations) and 85 min (second unit) with no
  firmware assert, no remoteproc recovery and no `wifi-guard` crash. 802.11r stays off.
- What stations do (survey with both units advertising 11k/v): 13 of 51 advertise BSS transition (phones, laptops, a
  streaming stick, TVs, a doorbell, one smart plug); most phones advertise it ONLY once the access point does. 30 set the
  Radio Measurement capability bit, but only 2 answered a beacon request (most smart-home devices ignore it and are
  treated as stations without 802.11k after one try). The smart display that was disconnected the evening before has
  no 802.11v; its beacon report claims an implausible -9 dBm for the other unit.
- Daytime mode, 43 min on one unit (`AP_STEER=on`, quiet hours set to a window that excluded the test,
  `AP_STEER_SIGNAL=-60`, `AP_STEER_AFTER=120`): 23 beacon requests, 1 "stay", 4 move requests (one smart plug, which
  declined each time with status 1) and 0 disconnect events on either unit. 1/s pings to the display, streaming stick,
  TVs, speaker and phones: the display lost 1 of 2597, the streaming devices 0. The evening before, the old refusal
  disconnected 7 stations on one unit in 4 min (the display was gone for 8 s).
- Night path with a test client only (house devices exempt): a station without 802.11v, idle 309 s with
  `AP_STEER_QUIET_IDLE=300`, was disconnected once, refused 30 s, came back to the same unit ("back": left alone 6 h)
  and was not disconnected again. A wpa_supplicant 2.10 client with 802.11v answered the request with status 0 and
  THIS unit's BSSID as the target (it measured the candidates and stayed, no disconnect): that answer is now treated
  like status 7 (never a reason for a night disconnect); before, it counted as "ignored".
- `AP_TZ`: with a local POSIX TZ string in `AP_TZ` the units' `date`, the quiet hours and the nightly channel re-check run
  in local time.

### 12.18b Band steering: dual-band stations on 2.4 GHz are asked to move to the same unit's 5 GHz (2026-11-21)

Why: after the 2.4 GHz queue limit (12.20) a legacy station on a busy 2.4 GHz channel still waited ~85 ms under load
with every limit tried (100 ms with none): airtime contention and retries on the channel, not the access point's queue.
The remaining lever is fewer stations on 2.4 GHz. Phones, laptops and TVs pick a band when they join and many stay on
2.4 GHz although the same unit's 5 GHz BSS of the same SSID is right there. Steering between units (12.18, 12.18a)
never moved them: it acts only on weak stations and names other units.

Changes (`libexec/patronus/ap-steer`, function `band_step`; the header comment has the exact rules):
- A station on this unit's 2.4 GHz is ASKED (802.11v BSS transition request naming this unit's 5 GHz BSS of the same
  SSID, preferred candidate, no "disassociation imminent") to move there. It is never disconnected for it, day or
  night: a station that does not take the request stays on 2.4 GHz. Each radio has its own hostapd, so the 5 GHz BSS is
  also loaded as an 802.11k neighbor of the 2.4 GHz BSS.
- Only stations that have shown 5 GHz are asked: seen on this unit's 5 GHz before (`/var/lib/patronus/ap-steer/seen5`,
  kept across restarts), or whose Supported Operating Classes (association request, hostapd `sta` `supp_op_classes`)
  list a 5 GHz class (115-129). The firmware answers probe requests itself (no `RX-PROBE-REQUEST` events, 12.19), so a
  "probed on 5 GHz" test like OpenWrt's usteer/dawn is not possible here.
- An 802.11k station is first asked what it hears on the 5 GHz channel (`req_beacon`, `AP_STEER_REPORT` mode); it is
  asked to move only when it hears the 5 GHz BSS at `AP_BANDSTEER_MIN5` (default -70 dBm) or better, otherwise it stays
  (history `band-stay`, asked again after `AP_STEER_RETRY`). A station without 802.11k (or one that never answers) is
  asked only when its 2.4 GHz signal is `AP_BANDSTEER_SIGNAL` (default -60 dBm) or better: 5 GHz reaches less far, and
  the station measures 5 GHz itself and may decline.
- Only while idle (`AP_STEER_IDLE`), connected at least `AP_BANDSTEER_AFTER` s (default 120), not weak
  (`AP_STEER_SIGNAL`: weak stations are for 12.18a), and when the 2.4 GHz channel was at least `AP_BANDSTEER_BUSY` %
  busy since the last round (survey counters, smoothed; default 0 = always). Stations without 802.11v and
  `AP_STEER_EXEMPT` devices are never asked. A request counts against `AP_STEER_MAX` per round.
- At most once per `AP_STEER_RETRY` per station. A station that moved to 5 GHz and later comes back to 2.4 GHz found 5 GHz
  no good there: it is left alone `AP_STEER_RETRY`, doubling per return in a row up to `AP_STEER_RETRY_MAX`.
- An accepted request names this unit's other band as the target; it counts as accepted (the 12.18a rule "status 0 with
  this unit as the target = it stays" now applies only to the BSS the station is on).
- Independent of `AP_STEER` (steering between units): `AP_BANDSTEER=on|off` (default on) works on a single unit too.
- Status: `ap-steer status` (band steering on/off, 2.4 GHz busy %, the 2.4 -> 5 GHz pairs, stations moved / staying),
  `/api/wifi` `steer_status.band` + per-station `has_5ghz`, history events `band-measure`, `band-btm`, `band-moved`,
  `band-stay`, `band-back`, all shown in the Wi-Fi page's Steering card.
- Settings: typed in `/api/wifi`, the Wi-Fi page and export/plan: `bandsteer` (live switch), `band_signal`, `band_min5`,
  `band_busy`, `band_after` (live numbers). No radio restart.

Proof: `tests/run.sh` 3c2 (fake station dump, hostapd_cli and survey: 802.11v station with 5 GHz operating classes asked
once to the 5 GHz BSS of its own SSID (guest to guest); 2.4-only, no-802.11v, weak-2.4, exempt, busy and 5 GHz stations
not asked; 802.11k station measured first, moved only when it hears 5 GHz well enough; accept naming the other band;
move and return recorded, hold after a return; "seen on 5 GHz" counts; busy gate; off switch; never a disconnect even in
the quiet hours); `tests/bandsteer-hwsim.sh` (mac80211_hwsim, one unit with a 2.4 GHz and a 5 GHz radio from the
product's `ap render`, real hostapd + wpa_supplicant 2.10, `AP_STEER=off` so only band steering acts): 5 of 5 moves
2.4 -> 5 GHz without a disconnect event (BSS-TM-RESP status 0 naming the 5 GHz BSS, 0-2 lost pings at 10/s, longest
gap 0.2-1.2 s), the first after an 802.11k measurement (it heard the 5 GHz BSS at -27 dBm), each return to 2.4 GHz
recorded and not asked again within the hold; a station limited to 2.4 GHz (`freq_list`) was asked once, answered that
it stays, and stayed connected (0 disconnects, 1 lost ping). hwsim has no survey busy times (busy shows -1 %, the gate
then only works with `AP_BANDSTEER_BUSY=0`), no path loss and no scan latency: it proves the decisions and "no
disconnect", not real-world timing.

Limits: a dual-band station without 802.11v (many TVs, some IoT) cannot be asked and stays on 2.4 GHz; OpenWrt-style
probe suppression is impossible because the firmware answers probes. hostapd 2.10 prints `supp_op_classes` only when
the station sent the element (the phone tested below did; most smart-home devices send none); a station that did not is
asked only after it was seen on this unit's 5 GHz once.

Hardware (GL-AX1800, one unit, 2026-11-22, image with kernel 6.12.118, `AP_STEER=off` so only band steering acted,
`AP_BANDSTEER_AFTER=30` for the client tests only):
- A Wi-Fi 6 Android phone (screen off, dozing) on the 2.4 GHz BSS at -15 dBm: measured (it heard the 5 GHz BSS at
  -23 dBm), asked once, accepted, on 5 GHz within a second, no disconnect, still answering pings afterwards.
- A wpa_supplicant client that may change band (no frequency pin), three runs with fresh MACs: each time measured,
  asked once (it heard 5 GHz at -27 dBm), accepted, moved without a disconnect; longest gap in 1/s pings from a wired
  host 1-2 s, no lost pings beyond that. Sent back to 2.4 GHz by hand, it was recorded as `band-back` and held for
  `AP_STEER_RETRY`. wpa_supplicant ignores `bssid_hint` when the 5 GHz BSS is better, so such a client joins 5 GHz
  directly: the test roams it to 2.4 GHz first.
- A client pinned to 2.4 GHz (`freq_list`) advertises only 2.4/6 GHz operating classes, so it never shows 5 GHz and is
  never asked (two runs, 0 requests, 0 disconnects). Pinned after it had been seen on this unit's 5 GHz: measured, no
  beacon report (it cannot scan 5 GHz), asked once, answered that it stays, not asked again, 0 disconnects.
- A house media player (802.11v + 802.11k + 5 GHz classes, -30 dBm on 2.4 GHz) did not answer the beacon request nor
  the move request: asked once, stayed on 2.4 GHz, no disconnect, next request only after `AP_STEER_RETRY`.
- Loaded 2.4 GHz delay on the same unit (channel 11, ~70 % busy, 4 TCP streams down): legacy client median 18 ms at
  14 Mbit/s, HE client 17 ms at 122 Mbit/s: no regression against 12.20.
- The `band-moved` history line is written at the next round (`AP_STEER_INTERVAL`, 30 s), so "N s after the request"
  is the detection time; the move itself takes about a second.
- In this house almost every 2.4 GHz station is a 2.4-only smart-home device: of 25 stations on one unit before the
  flash none advertised 802.11v and one sent operating classes (2.4 GHz only). Band steering therefore moves the few
  dual-band phones, laptops and media players that sit on 2.4 GHz; it cannot empty a crowded 2.4 GHz channel.
- Over the following hour (house devices only, band steering on, steering between units off): no new request (the few
  dual-band stations on 2.4 GHz had been asked already), 0 disconnects by steering, no firmware assert, `wifi-guard`
  0 crashes.

Second unit (GL-AX1800, 2026-11-23, same image, the night after the first unit had run it for 24 h with 0 firmware crashes
and 0 disconnects by steering):
- After the flash every BSS (each SSID x band) gave a real client a lease, gateway, internet and DNS, again after
  `ap stop; ap start`; roams between the two units on both bands and a band switch on the same unit were online again
  within 0.4-1.4 s. The test client heard this unit's 2.4 GHz at about -70 dBm, which is "weak" under the default
  `AP_STEER_SIGNAL` (-65): band steering correctly left it alone (weak stations belong to 12.18a). With the thresholds
  lowered for the test only (`AP_STEER_SIGNAL=-85`, `AP_BANDSTEER_MIN5=-85`, `AP_STEER=off`):
- A client that may change band (limited to this unit's BSSes with `bssid_accept`, two runs): measured, asked once (it
  heard 5 GHz at -66 dBm), accepted, moved without a disconnect; longest gap in 1/s pings 1.1 s. Sent back to 2.4 GHz,
  recorded as `band-back` and held. Without `bssid_accept` the client left for the other unit's much stronger 5 GHz on
  its own right after the measurement (its own roaming decision; no disconnect).
- A 2.4-only client: never asked; seen on 5 GHz first, then pinned: asked once, answered that it stays, not asked again;
  0 disconnects.
- Over the following hour (house devices only): no request (none of this unit's 2.4 GHz stations advertises 802.11v),
  0 disconnects by steering, no firmware assert, `wifi-guard` 0 crashes.

### 12.19 Channel choice by measurement, nightly re-check by channel switch, steering back-off (2026-11-18)

Until now the channel came from hostapd's ACS at radio start, minus the blocks of this network's other units (12.17).
ACS measures once, only busy time, and only while the radio is not yet serving. A running radio's own-channel survey
counter keeps adding up for hours and includes the unit's own traffic, while every other channel is only seen in short
scans, so comparing survey numbers by hand (or re-running ACS) favoured moving off a channel that was only busy with our
own clients. Measured on the house units 2026-11-18: 5 GHz 0-40 % busy, 2.4 GHz 45-50 % busy from neighbours on every
channel (own traffic under 15 %), 32 neighbouring access points heard on 2.4 GHz channel 6 alone.

`libexec/patronus/ap-chan` (started by `ap-coord plan` at radio start and by `ap-coord run` once a minute when due):
- Measurement: every candidate channel (exactly the list ACS may use: `ap candidates BAND`, i.e. AP_CHANLIST*, DFS and
  U-NII-4 switches, whole 40/80 MHz blocks, minus the peers' blocks) gets `AP_CHAN_ROUNDS` scans of `AP_CHAN_DWELL` ms
  each (`iw scan ... duration`; on a radio that already serves clients `scan ap-force`, which the ath11k driver does
  off-channel between beacons). The busy share of each channel is the sum of those dwells, so every candidate is measured
  the same way. The channel in use is measured over the same window from its own survey counters with this unit's own
  airtime (tx/rx bytes of its stations over their bitrates) taken out. Nightly samples spread the rounds over
  `AP_CHAN_SAMPLE_SECS`.
- Score (lower is better): the block's busy % (primary channel counted twice, the other 20 MHz channels of the block once)
  plus `AP_CHAN_BSS_COST` points per other access point heard on the block (at most 10 counted, weaker than
  `AP_CHAN_MIN_SIGNAL` ignored; this unit's own BSSes never count). On 2.4 GHz a neighbour 1-4 channels away adds up to 10
  points scaled by overlap and signal (a strong neighbour on 3 hurts 1 and 6, not 11). Equal best scores keep the channel
  in use.
- At start (`AP_CHAN_SMART5/24=1`): ACS may only use the best candidate's 40/80 MHz block, the measured primary listed
  first (`chanlist=157 149 153 161`, `channel=0`, so hostapd still does its own DFS/HT checks and picks the primary inside
  the block); a pinned channel that is no longer allowed falls back to plain ACS. A lone primary is not enough: hostapd's
  ACS refuses an 80 MHz primary whose block is not in `chanlist`, and on the first hardware flash the 5 GHz radio stayed
  off with `chanlist=48`. The boot guard (12.16) confirmed that boot because its hostapd check only asked the control
  sockets that existed; it now requires a socket for every `interface=`/`bss=` the renderer wrote (host test with one
  radio down), so such an image is rolled back. The hwsim ACS scenario has a `pin` case (157 at 80 MHz, 11 on 2.4 GHz).
- The running primary is not the measured one (2026-11-18, on hardware): the card said "channel 48 chosen" while
  `hostapd_cli status` showed `channel=36`, because ACS picks its own primary inside the pinned block (36-48) and
  both are the same 80 MHz block with the same airtime and neighbours. Pinning the exact primary would mean a fixed
  `channel=` (no ACS, so no re-check and no DFS handling by hostapd); instead the status records both. `chan-status-BAND`
  holds `chosen` (the measured primary), `current` (what hostapd runs), `block` (the 20 MHz channels that block occupies,
  from the board's width) and `width`. `ap-chan sync BAND` fills `current` and `block` from `hostapd_cli status` once the
  radio is ENABLED (waits `AP_CHAN_SYNC_WAIT` s, default 90, typed `chan_sync_wait`); `ap start` runs it in the background
  for each band it started and `ap-chan move` after every channel switch announcement (a restart goes through `ap start`).
  When the two primaries differ inside one block the history gets a `primary` entry saying so. `/api/wifi` `channels.BAND`
  adds `primary` (current, else chosen) and `primary_differs`; the Wi-Fi page reads "5 GHz: block 36-48 (80 MHz), primary 36
  in use" with a note on the measured primary, and marks the table rows "(in use)" for the running primary and "(same block)"
  for the other candidates of that block. Tests: `tests/run.sh` (sync inside the block, a radio not serving, status after a
  channel switch, the start hook) and `channel_status_reports_the_running_primary_inside_the_pinned_block` in `apwifi.rs`.
- The measurement also hears this network's other units (same SSIDs or `AP_COORD_PEERS`, ap-coord's filter): their
  channels join ap-coord's list even when ap-coord's own pre-start scan missed them, which happened on hardware for
  2.4 GHz (the unit took the other unit's channel 11; ap-coord's collision check then moved it to 1 by channel switch
  announcement 3 minutes later, which proved the CSA path with house clients: 13 of 13 2.4 GHz stations stayed
  associated). A hand test on the 5 GHz radio (44 -> 40, both BSSes) kept 3 of 3 stations; on 2.4 GHz a few IoT
  devices reconnect after a switch instead of following (2 of 12 on the second move).
- Nightly (`AP_CHAN_RECHECK5/24=1`, at `AP_CHAN_TIME`, default 03:30 local; empty = never): `AP_CHAN_CONFIRM` samples
  `AP_CHAN_CONFIRM_GAP` s apart must all name the same better channel, at least `AP_CHAN_HYST` % and `AP_CHAN_MIN_GAIN`
  points below the current one. Then the radio moves by channel switch announcement (`hostapd_cli chan_switch
  AP_CHAN_CSA_COUNT <freq> ... ht vht he`, width kept): clients follow without disconnecting. A driver without
  channel-switch support (`iw phy` lacks `channel_switch`) or `AP_CHAN_CSA=off` restarts the radio pinned to the new
  channel instead; the Wi-Fi page says so per radio. A fixed channel is never measured or moved.
- One after the other: units of the same network never select at once. At start each unit waits for the known units with
  a lower key (last five octets of the radio MAC, as in 12.17) to be on air, at most `AP_CHAN_WAIT` s plus a random
  0..`AP_CHAN_JITTER` s, then picks with their blocks excluded; a unit that never appears does not stop the others. Known
  units are kept in `/var/lib/patronus/ap-chan/peers-BAND` and forgotten after `AP_CHAN_FORGET` s unheard. The nightly
  re-check runs `AP_CHAN_STAGGER` s later per unit ahead in that order, and ap-coord's collision check (12.17) still
  separates units that land on one block.
- History: every start pick, sample, stay and move goes to `/var/lib/patronus/ap-chan/history` (JSON lines, last
  `AP_CHAN_HISTORY` kept) with channel, busy %, neighbours, score and the reason in words; the last decision per band with
  every candidate's numbers is `/run/hostapd/chan-status-BAND`. `GET /api/wifi` returns both (`channels`,
  `channel_history`) and the Wi-Fi page shows them as "Why this channel" and "History".

Steering (12.18) changes:
- Back-off: a station that comes back to a unit after being moved (no better access point for it) is left alone for
  `AP_STEER_RETRY` s, doubled for every further return in a row, up to `AP_STEER_RETRY_MAX` (default 7 days). An IoT
  device at -66..-71 dBm with no better unit used to lose 30 s of connection every 6 h; now that falls to one per week.
  `ap-steer status` and the log say how many times in a row. Two-unit host test: moves 3600, then 7200 s apart, capped
  at the maximum.
- "Only refuse a station another unit hears stronger" is not built, because the units cannot hear other units' stations:
  the ath11k firmware answers probe requests itself (probe response offload), so hostapd gets no `RX-PROBE-REQUEST`
  events. Measured on a house unit 2026-11-18: 0 events in 80 s on both radios with 32 stations associated and dozens of
  devices around (hostapd_cli action mode on each BSS). Without probes, the only signal a unit has is for its own
  associated stations, so there is nothing to exchange; a monitor interface beside the AP is unproven on this firmware
  (12.6d). The per-unit record plus the back-off bounds a bad move to one round trip per hold.

Settings: all typed, live (ap-chan and ap-steer re-read ap.env, no radio restart), in `/api/wifi`, the Wi-Fi page (group
"Channel choice" and the steering hold maximum) and the declarative document (`patronus ap-wifi export|plan|apply`):
`chan_smart5/24`, `chan_recheck5/24` (bool), `chan_time` (HH:MM or empty), `chan_csa` (auto|off), `chan_hyst` 0..90 %,
`chan_min_gain` 0..100, `chan_confirm` 1..10, `chan_confirm_gap` 0..3600 s, `chan_rounds` 1..20, `chan_dwell` 20..500 ms,
`chan_sample_secs` 0..600 s, `chan_bss_cost` 0..20, `chan_min_signal` -100..-30 dBm, `chan_csa_count` 1..50 beacons,
`chan_wait` 0..600 s, `chan_jitter` 0..300 s, `chan_sync_wait` 0..600 s, `chan_stagger` 0..21600 s, `chan_history` 10..5000, `chan_forget`
3600..31536000 s, `steer_retry_max` 0..2592000 s (at least `steer_retry`). Defaults are in board.sh; a unit test checks
the API defaults against it.

Tests: `tests/run.sh` (scoring on both bands, the start pick through `ap-coord plan` with the renderer pin, the wait for
an earlier unit and the timeout, nightly move by CSA, hysteresis, the restart fallback, the once-a-day and per-unit
stagger timing, the steering back-off with two units), unit tests in `apwifi.rs`, the QEMU gate check `wifi_chan`
(defaults, a live change, bad values, `ap-chan score` on the image, `channels`/`channel_history` in GET).
`check-rootfs.sh` requires an executable ap-chan.

Other tiers: the Slate's radios run its AP on the channel of its Wi-Fi uplink (one channel per radio, section 6d), so it
has no channel of its own to choose; the standard tier's Wi-Fi (`wireless.rs`) has the same
feature since 2026-11-18 (done): channel `auto` is the default of a new network, measured at radio start with the same
scoring in Rust (`wifichan.rs`: equal dwell samples, own airtime subtracted, neighbour cost, 2.4 GHz overlap),
re-checked nightly and on request by the per-network `patronus wifi-chan run` service, moved by CSA only when clearly and
repeatedly better (restart where the driver or the setting rules CSA out), with the reason and history in the API and
the Segmentation > Wi-Fi tab, typed settings and export. Existing fixed channels are unchanged. Not coordinated between
separate boxes (this tier's units are neighbours of each other). See docs/WIFI-AUTO-CHANNEL.md.

### 12.20 Airtime queue limit and airtime fairness: 2.4 GHz delay under load (2026-11-19)

Symptom: on 2.4 GHz, a laptop at a strong signal (-45 dBm) saw ping times of over a second to the gateway while the
wired side was fast. Cause, measured on the unit and read from the driver source: OpenWrt's ath11k (the module this
image takes from the stock root) advertises neither `NL80211_EXT_FEATURE_AQL` nor `..._AIRTIME_FAIRNESS`
(`iw phy` lists TXQS but no AQL, every station's debugfs `airtime` reads 0 us, `aql_pending` stays 0), and its
`.wake_tx_queue` drains a station's whole mac80211 queue into the hardware rings. So nothing bounds how much of a busy
station's traffic waits in the radio, where there is no AQM and no per-flow separation: a download's own delay is the
depth of that queue in airtime. At 2.4 GHz rates that depth is large (measured on a GL-AX1800 with a test client:
a legacy 54 Mbit/s station, 4 TCP streams downstream: median 82 ms, max 221 ms; by estimate about 8x that, i.e.
near a second, for a station served at 6.5 Mbit/s, which the unit had for several devices at -55..-65 dBm), and without airtime fairness
a slow station also takes most of the radio's airtime. The GL stock firmware avoided it with QSDK's NSS Wi-Fi offload
(own queueing) and firmware WLAN.HK.2.7.0.1, neither of which is usable with the upstream driver.

Fix: the image rebuilds the Wi-Fi modules (cfg80211, mac80211, ath, ath11k, ath11k_ahb) from OpenWrt's own mac80211
package of the same release, with the upstream ath11k series "airtime queue limits, fairness and a driver TXQ scheduler"
(v4, 9 patches) and the mac80211 fix "don't reset the TXQ scheduling round number" applied
(`ci/embedded-aarch64/ax1800/wifi-kmods/`: `patches/`, `sdk.pin` = the release SDK by sha256 and the base-feed commit,
`build-kmods.sh` = the reproducible x86_64 build, `wifi-kmods.pin` = the built tar by sha256, `fetch.sh` = puts the
modules over the stock ones and refuses a different kernel release or vermagic). `/etc/patronus-release` records
`WIFI_KMODS=<tag>`; `check-rootfs.sh` refuses a root whose ath11k lacks the series (`WIFI_KMODS=stock` builds the old
modules on purpose). On the unit, `iw phy` then lists `[ AQL ]` and `[ AIRTIME_FAIRNESS ]`.

Settings (typed, live, Wi-Fi page "Airtime", `/api/wifi`, export/plan; `ap airtime` applies them through mac80211's
debugfs, also at every radio start): `AP_AQL` (on), `AP_ATF` (on), `AP_AQL_LOW24`/`AP_AQL_HIGH24` and
`AP_AQL_LOW5`/`AP_AQL_HIGH5` (microseconds of airtime one station may have queued in the hardware, LOW while the radio
is busy; defaults 2500/5000 on 2.4 GHz and mac80211's 5000/12000 on 5 GHz, chosen by the sweep below). With the stock modules `ap airtime` says the driver has no airtime queue
limit and changes nothing; the Wi-Fi page says the same.

The early boot does not mount debugfs; `ap airtime` mounts it on first use (mac80211's defaults apply without it, but a
changed limit or AP_AQL/AP_ATF=off would otherwise be skipped with "debugfs not mounted").

Proof: `tests/run.sh` (`ap airtime` against a fake debugfs, with and without AQL in the driver), apwifi.rs unit tests
(defaults, board.sh parity, validation, live, export/plan), and an A/B on a GL-AX1800 (2026-11-20, test client 2 m from
the unit at about -27 dBm, 2.4 GHz HT20, 15 s TCP loads from a wired host, 0.2 s pings wired -> client, median / max):

| Client, load | stock modules (ch 6) | rebuilt, AQL+ATF off (ch 11) | rebuilt, AQL+ATF on (ch 11) |
|---|---|---|---|
| 54 Mbit/s legacy, 4 streams down | 77 / 222 ms and 129 / 431 ms, 6.7-7.9 Mbit/s | 173 / 617 ms, 15.8 Mbit/s | 35.5 / 90 ms and 35.5 / 74 ms, 13.5-14.9 Mbit/s |
| 54 Mbit/s legacy, upstream | 67 / 245 ms and 72 / 324 ms, 4.2-5.0 Mbit/s | 41 / 92 ms, 15.2 Mbit/s | 44-45 / 98 ms, 18.2-18.6 Mbit/s |
| HE, 4 streams down | 31.5 / 178 ms and 41.8 / 161 ms, 91-94 Mbit/s | 20.6 / 109 ms, 123 Mbit/s | 22.4 / 80 ms and 24.0 / 84 ms, 113-117 Mbit/s |
| HE, upstream | 17.6 / 127 ms and 20.7 / 82 ms, 47-59 Mbit/s | 21.7 / 66 ms, 73 Mbit/s | 25-27 / 86 ms, 75-76 Mbit/s |

The middle column is the clean comparison (same build, same channel, same minutes; mac80211's `aql_enable` and
`airtime_flags` set to 0): the airtime queue limit cuts a loaded legacy station's delay about 5x at equal throughput; a
fast HE station pays at most about 8% of throughput. The stock column ran on another channel the same night (channel
coordination moved the radio after the flash), so its throughput is not comparable. Every BSS gave a client a lease (3.3 s for
the first one after the boot, 0.2 s otherwise) with gateway, internet and DNS, again after `ap stop; ap start`; no firmware crash, wifi-guard normal.

Second unit (2026-11-21), a harder case: 2.4 GHz channel 1 with about 20 associated stations, test client at about
-62 dBm (the channel stayed the same across the flash, so all columns ran on it within one hour):

| Client, load | stock modules | rebuilt, AQL+ATF off | rebuilt, AQL+ATF on (defaults) | on, 2.4 GHz limits 2500 / 5000 us |
|---|---|---|---|---|
| 54 Mbit/s legacy, 4 streams down | 65.6 / 224 ms and 89.6 / 264 ms, 5.5-7.4 Mbit/s | 109 / 213 ms, 6.1 Mbit/s | 81.4 / 153, 82.9 / 249 and 91.1 / 266 ms, 6.3-6.6 Mbit/s | 49.4 / 221 and 61.8 / 185 ms, 6.8 Mbit/s |
| 54 Mbit/s legacy, upstream | 40.5 / 100 and 46.3 / 100 ms, 6.9-8.9 Mbit/s | 43.5 / 126 ms, 4.6 Mbit/s | 54.4 / 137 and 47.4 / 96 ms, 5.2-5.6 Mbit/s | 42.5 / 119 ms, 9.2 Mbit/s |
| HE, 4 streams down | 44.6 / 118 ms and 73.2 / 205 ms, 58-61 Mbit/s | 137 / 465 ms, 53.9 Mbit/s | 32.0 / 88 and 30.4 / 87 ms, 48.5-51.8 Mbit/s | 20.5 / 94 ms, 46.4 Mbit/s |
| HE, upstream | 28.4 / 107 and 27.6 / 102 ms, 26-44 Mbit/s | 29.8 / 89 ms, 29.8 Mbit/s | 28.2 / 78 and 27.7 / 63 ms, 31-32 Mbit/s | 31.0 / 153 ms, 27.7 Mbit/s |

At equal throughput the queue limit still cuts the loaded delay against the same build without it (HE 137 -> 31 ms,
legacy 109 -> 82 ms), but on a crowded channel a slow legacy station stays near the stock figure with mac80211's
default limits (likely because the limit is counted in estimated airtime at the station's rate, while contention
on a busy channel stretches the real time; not yet proven). Halving the 2.4 GHz limits (`AP_AQL_LOW24=2500`, `AP_AQL_HIGH24=5000`) brought the legacy station to
49-62 ms and HE to 20 ms at about 14% less HE throughput than the unlimited control. Every BSS passed the client suite after the flash and after
`ap stop; ap start`; no firmware crash, wifi-guard normal.

Choosing the 2.4 GHz default (2026-11-21): a sweep on both units, the limits set live on the 2.4 GHz radio only (5 GHz
unchanged), the same test client and loads as above, three runs per setting in interleaved order plus one run with the
queue limit off (fairness stayed on). Median of the per-run medians for 4 TCP streams downstream (0.2 s pings wired ->
client) and median throughput:

| 2.4 GHz LOW / HIGH (us) | unit A legacy | unit A HE | unit B legacy | unit B HE |
|---|---|---|---|---|
| queue limit off | 127 ms, 16.6 Mbit/s | 15.8 ms, 173 Mbit/s | 100 ms, 6.3 Mbit/s | 72.6 ms, 60.9 Mbit/s |
| 5000 / 12000 (mac80211) | 50.0 ms, 16.1 Mbit/s | 13.8 ms, 171 Mbit/s | 103 ms, 6.4 Mbit/s | 30.1 ms, 56.9 Mbit/s |
| 3000 / 7000 | 38.2 ms, 16.1 Mbit/s | 12.4 ms, 169 Mbit/s | 107 ms, 6.2 Mbit/s | 27.9 ms, 56.5 Mbit/s |
| **2500 / 5000 (default)** | **30.0 ms, 16.1 Mbit/s** | **13.7 ms, 170 Mbit/s** | **85.4 ms, 6.6 Mbit/s** | **20.4 ms, 56.7 Mbit/s** |
| 1500 / 4000 | 27.1 ms, 15.1 Mbit/s | 13.7 ms, 165 Mbit/s | 81.2 ms, 6.2 Mbit/s | 19.0 ms, 57.1 Mbit/s |

Unit A: channel 11, about 20 stations, client at about -40 dBm. Unit B: channel 1 (busier), about 11-20 stations,
client at about -62 dBm. Run-to-run spread is about +-20 ms, so differences under that are noise.

2500 / 5000 is the 2.4 GHz default: it cuts the loaded legacy delay 40% on unit A (50 -> 30 ms) and the loaded HE delay
about a third on unit B (30 -> 20 ms), keeps HE throughput at 93-98% of the unlimited control and HE delay no worse
than mac80211's default anywhere. 1500 / 4000 gains little more and was the only setting with throughput dips (a legacy
run at 10.7 Mbit/s, an HE run at 154 Mbit/s). On the busy channel with a weak client no setting brings the legacy
station under 50 ms, and the unlimited control is no better (100 ms): that delay does not come from the AP's queue
depth, which is what this limit controls, but from contention and retries on the channel (and the client's own
upstream queue of TCP acknowledgements). Band steering (12.18b) moves the dual-band clients with 802.11v off that
channel; the 2.4-only smart-home devices that make up most of a house's 2.4 GHz stations stay, so it lowers the load
there but does not remove it.
5 GHz keeps mac80211's limits (its rates make the same budget a short queue).

### 12.21 The embedded kernel tracks its LTS line (2026-11-21, `ci/embedded-openwrt/`)

Before: both AP images and the QEMU gate booted OpenWrt 25.12.6's kernel (6.12.112) byte for byte, and the Slate keeps the same kernel in NOR.
OpenWrt's release branch lags kernel.org's LTS point releases (branch head 6.12.116 while 6.12.118 was out), so the house routers ran
kernels with known security fixes missing. Now the kernel is rebuilt from the pinned OpenWrt tag (`kernel.pin`: `OWRT_TAG`, `KERNEL_LINE`,
`KERNEL_PATCH`, `KERNEL_SHA256`) with only the kernel version and tarball hash changed (OpenWrt's patch set and kernel config stay); the
GL-AX1800 image takes that build's sysupgrade kernel, its kmod apks, and the Wi-Fi modules rebuilt in the same tree (`build-kmods.sh TREE=...`,
same AQL/ATF patches). The line is configuration (`KERNEL_LINE` in `kernel.pin`), never code.

- `kernel-track.sh --check` (CI `kernel-track.yml`, daily) is red when the pin lags kernel.org by more than `MAX_LAG_DAYS` (3); `--bump` moves the two pin lines.
- the project agent host's cron `kernel-track` runs `--bump` daily and, on a newer patch, queues ONE job: build per board (`build-owrt.sh ax1800|virt|slate`), upload the
  artefacts as Forgejo generic packages (`publish-pins.py` also moves `stock.pin`, `kmods.pin`, `sdk.pin`, `wifi-kmods.pin`), run the gates, ff-merge, build the per-unit AP
  images and queue the house-AP window flash (`flash-queue/`, started by cron `ap-window-flash-gate` at 00:55 America/Los_Angeles, flashes only 01:00-05:00, .10 first).
- 6.12.118 needed (stable moved contexts OpenWrt's tag did not know; `patches/6.12.118/`): `623-v6.18-pppoe-remove-rwlock-usage` refreshed (stable's
  `__delete_item()`/`delete_item()` take the socket); dropped because stable already has the change: `732-...mt76-wed...`, `788-...qmi_wwan-Quectel-EG120K-EA`,
  `210-wireless_netns_local_backport` (stable renamed `netns_local` to `netns_immutable`, the package patch mapped it back and broke mac80211); dropped because the
  driver is not built by any of our kernels: `750-net-pcs-mtk-lynxi...` (CONFIG_PCS_MTK_LYNXI unset), `0305-pinctrl-qcom-IPQ5018...` (CONFIG_PINCTRL_IPQ5018 only on ipq50xx).
  `patch-survey.sh` lists every non-applying patch of a series at once (and tells "already in the kernel" from "context moved").
- `fetch-stock.sh` reused an unpacked stock root from a cache volume whenever `.done` existed: a kernel bump built an image with the OLD modules
  ("stock kernel modules: 6.12.112" next to a 6.12.118 Wi-Fi tar). The marker now holds the sysupgrade's sha256.
- Slate (GL-AR750S): the kernel lives in NOR, the Patronus root in UBI on NAND, and `patronus-guard` rolls back only the root, so a kernel change is not atomic and an
  old/new mismatch strands the unit (no network, guard cannot revert the kernel). Since 6e the root carries the modules of both kernels and the kernel goes through
  `patronus-flash kernel-rehearse` / `kernel <kver>`: a U-Boot trial with automatic fallback, commit after a confirmed boot, the previous kernel kept (proof and limits in 6e).
