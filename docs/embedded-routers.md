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
| libc / init | musl, busybox init (OpenRC once its cross-emerge works) | glibc, OpenRC | glibc, systemd or OpenRC |
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
3. **No shipped password.** With `PATRONUS_FIRST_RUN_SETUP=1` and no `admin` account, every page redirects to `/first-run` and every API answers 403 until the owner chooses a password (12+ characters, known defaults refused, entered twice). Then `/first-run` redirects to the login. `admin/admin` is refused before and after (tested). Until it is set the UI is reachable only from the LAN side (input policy drop on the WAN); the password is chosen over TLS and never leaves the box. Recovery of a lost password: set `PATRONUS_ADMIN_PASSWORD` in the init script (re-applied at every web start while set), as on every other tier; removing the store from the console starts over with the first-run page (not tested).
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

1. **Toolchain/rootfs:** crossdev `mips-unknown-linux-musl` with `--with-float=soft --with-arch=mips32r2`, then `ROOT=/rootfs mips-unknown-linux-musl-emerge` of busybox, nftables, dnsmasq, iproute2, wireguard-tools, hostapd (all OK). **Blocker (open): `sys-apps/openrc` does not cross-emerge** (needs `virtual/tmpfiles` + python for the build ROOT); `wpa_supplicant` was not part of the emerge set. The spike used busybox init. Fix: keyword/USE the python deps in the cross profile, or ship OpenRC prebuilt from a Gentoo musl binhost.
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
6. ~~`patronus-web` mips build + memory cap, or a deliberate CLI-only decision~~ **Done 2026-11-06: the web UI ships on the router tier** (section 6a, measured: +4.05 MiB squashfs, 16.4 MB idle / 25.0 MB peak RSS, e2e green in QEMU). Remaining web items:
7. Firmware update + rollback page: upload the sysupgrade-tar, verify (fwtool metadata + signature), write the inactive slot, flip `bootcount`, arm the on-device 5-minute rollback; honest 501 until then.
8. Wi-Fi in the router UI: cross-build `wifi-ap` (+ `segmentation`) and `wpa_supplicant` (repeater mode), add the radios to the QEMU twin or test on the real board in step B.
9. Connected-clients page (DHCP leases + ARP/neighbour table + Wi-Fi stations) and a syslog ring (`logread` equivalent: busybox `syslogd -C` feeding `$PATRONUS_SYSLOG`).
10. Central management: `gitops` feature on MIPS, a per-router API-key client + fleet page in the main Patronus UI, the "pause gitops" switch; then prove push and pull against the malta twin.
11. CI: run `ci/embedded-mips/t_e2e.py` on every push (QEMU TCG, about 8 min) with RSS ceilings (web idle <= 20 MB, peak <= 30 MB, rootfs <= 16 MiB without agents); real-board timing of the first login and TLS handshake in step B.
12. Merge the web changes back into the default build's gates (`cargo test -p patronus-web` with default features and with `--no-default-features --features dhcp,dns,tls-openssl`): the spike compiled and exercised the router build, it did not re-run the full x86 unit-test suites.
