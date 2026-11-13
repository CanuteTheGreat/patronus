# Init parity: OpenRC and systemd, both fully supported

Owner rule (2026-11-13): "horcrux and patronus should fully, 100% support openrc and systemd. Gentoo is about choice."
Status: phase 1 (audit, foundation, CI) landed with this document. Phases 2-5 below.

## Where Patronus stood (audit, 2026-11-13, main @ `git log -1`)

The starting assumption "effectively OpenRC-only" turned out to be wrong in the places that matter most, and right in a few
that are easy to miss. Measured by reading every call site and by running the shipped image under systemd.

Already at parity before phase 1:

* Every service Patronus ships has both halves in `gentoo/net-firewall/patronus/files/`: `*.initd` and `*.service`
  (web, firewall, applyd, gitops, ztp, dhcpc@, daemon@, pppoe@, hostapd@, wifi-events@, dashboard); ipdb is a timer + cron pair.
  Ebuilds (`9999`, `0.1.0`, `0.2.0`) install both under `USE=systemd` / `USE=openrc`, `REQUIRED_USE="|| ( systemd openrc )"`.
* The `ServiceManager` in `patronus-core` detected the init system and had systemd, OpenRC and SysV paths; the LAN-service
  code (`patronus-network/src/lan.rs`, `dhcp.rs`, `supervise.rs`, `services.rs`) used it and had both-init unit tests.
* netlab already runs lanes D (LAN services), F/H (IPsec + service control), G (HA) and segmentation-DNS **once per init system**
  (`ci/netlab/lan-services.sh openrc|systemd`, systemd as PID 1 in a Gentoo stage3). The CI image
  (`Dockerfile`) is built from the systemd stage3 with `USE=systemd -openrc`.
* `sysops.rs` reboot/shutdown picks `systemctl reboot` vs `reboot` at run time.
* `image-name.sh` already knows `INIT=openrc|systemd` image names.

## Gap table

| # | Area | Gap found | Severity | Status |
|---|------|-----------|----------|--------|
| 1 | Rust service control | Five crates bypassed `ServiceManager`: `patronus-proxy/haproxy.rs` (hard-coded `systemctl start/stop/reload haproxy`), `patronus-network/snmp.rs` (`systemctl`), `patronus-vpn/l2tp.rs` (`systemctl start strongswan xl2tpd`; strongSwan is `ipsec` on OpenRC), `patronus-monitoring/status.rs` + `alerts.rs` (`systemctl is-active/is-enabled/show`; on OpenRC every service showed "stopped" and alert rules for stopped services fired or never fired), `seg_dns.rs` (`systemctl daemon-reload`). All were silently broken on OpenRC. | high | **fixed (phase 1)** |
| 2 | Abstraction shape | `ServiceManager` was a struct with three `match` arms, no seam to test the command sets, and `lan.rs`/`supervise.rs`/`system.rs` each re-implemented "queue a non-blocking restart", "main PID", "is the system booting", "log hint" with their own `systemctl`/`rc-service` calls. | medium | **fixed**: `InitBackend` trait (`SystemdBackend`, `OpenRcBackend`, `SysVBackend`), injectable `Runner`, 15 unit tests that assert the exact command lines of both backends without either init installed |
| 3 | Service-name mapping | `ipsec` (OpenRC) vs `strongswan` (systemd), `chrony` vs `chronyd` were scattered literals. | low | **fixed**: one table, `service::native_name` |
| 4 | applyd self-restart | `POST /api/system/services/patronus-applyd/restart` returned **500** ("apply broker answered \"\": EOF") although the restart happened: the broker killed itself before answering. Found by the new systemd container check; same on OpenRC. | medium | **fixed**: queued restart |
| 5 | Regression guard | Nothing stopped a new `Command::new("systemctl")`. | medium | **fixed**: `ci/check-init-parity.sh` (initd/unit pairs, ebuild USE symmetry, no direct init calls outside `service.rs`) in the lint job |
| 6 | Image CI | `container-as-shipped.sh` runs the image with no init at all; the systemd units of the emerge-built image were only `grep`-checked for existence. Nothing booted them. | high | **fixed**: `ci/container-as-shipped-systemd.sh` (systemd as PID 1, `systemd-analyze verify`, UI service control) in rust-ci |
| 7 | OpenRC image test | The emerge-built image is `USE=systemd -openrc`; the OpenRC scripts are only exercised in netlab (stage3-openrc, lanes D/F/G). No `openrc-init` PID 1 check of the shipped scripts (`rc-service patronus-web start`, `rc-update`, `depend()` ordering). | medium | phase 2 |
| 8 | Network setup | Interfaces are applied by `patronus apply` (netlink/`ip`) on both inits, not by netifrc or systemd-networkd. **Not audited under load:** the two systems' own network managers (`net.*` init scripts / `systemd-networkd`, which the stage3-systemd enables) can fight `patronus apply` over addresses and routes (the as-shipped run shows `systemd-networkd-wait-online` failing in a container). Needs a policy: Patronus owns configured interfaces; ship a networkd drop-in `Unmanaged=yes` per Patronus-managed iface and an equivalent netifrc guard (`config_<iface>="null"`). | high | phase 3 |
| 9 | Installer | `patronus-installer` (`bootloader.rs`) runs `rc-update add live-serial default` only; no systemd serial getty (`serial-getty@ttyS0` enable) for installed systems; installer also assumes the live image is OpenRC (stage3 `amd64-openrc` in `x86_64.env`). | medium | phase 4 |
| 10 | Live ISO | Only `server-openrc` Patronus ISO workflows exist (`live-iso-server-openrc-{x86_64,aarch64}.yml`). `image-name.sh` supports `systemd` but no systemd rootfs build (stage3 tag, `Dockerfile.rootfs`, dracut/boot units for `live-serial`) is wired, and no QEMU boot test of one. Shared with Horcrux (`build/live-iso/common`), so coordinate. | high | phase 4 |
| 11 | User-visible strings | `openvpn_export.rs` client help text prints `sudo systemctl start openvpn-client@..` for every client OS; docs mention "OpenRC/systemd" in places (not a functional gap). | low | phase 2 |
| 12 | Embedded MIPS tier | busybox init + two 10-line sysv scripts; no OpenRC, no systemd. See verdict below. | decision | phase 5 |
| 13 | Profiles | Portage profiles / USE defaults: `+systemd +openrc` both default-on in the ebuild; image profiles under `gentoo/profiles` and catalyst specs pick openrc. Need explicit `systemd` profile variants (musl/desktop variants not touched). | medium | phase 4 |
| 14 | netlab on systemd | See plan below. Most lanes already run on both; the gaps are the lanes still openrc-only or init-less. | medium | phase 2 |

## What phase 1 built

`crates/patronus-core/src/service.rs`:

* `trait InitBackend` (`act`, `restart_queued`, `enable`, `disable`, `status`, `is_enabled`, `main_pid`, `is_booting`,
  `reload_definitions`, `log_hint`) with `SystemdBackend`, `OpenRcBackend`, `SysVBackend`.
* `ServiceManager::detect_init_system()`: systemd iff `/run/systemd/system` exists (the `sd_booted(3)` test, so a box with
  both packages installed is judged by what booted it), else OpenRC (`/run/openrc` or `/etc/init.d/functions.sh`), else SysV,
  else Unknown. `detect_under(root)` makes it testable.
* `Runner` seam: backends only talk to the system through it; tests record the command lines.
* `native_name()`: logical name -> distro name (`ipsec` -> `strongswan` on systemd).
* `act_blocking()` for async callers.
* Rule enforced by CI: nothing outside this file spawns `rc-service`, `rc-update` or `systemctl`.

Callers moved to it: haproxy, snmp, l2tp, monitoring status + alerts, seg_dns, lan.rs, supervise.rs, web `system.rs`.

## Embedded MIPS tier: does systemd fit?

Target (docs/embedded-routers.md, branch `feat/embedded-routers`): GL-AR750S, QCA9563 MIPS 24Kc big-endian soft-float,
128 MB RAM (118 MB `MemTotal`), 16 MiB rootfs slot (24 MiB with the ETPhoneHome and Rustinion agents), musl, busybox init.
Patronus today: rootfs 9.99 MiB, whole router 17.4 MB RAM idle, 24-26 MB after login, agents about 20 MB more.

Measured here on x86-64 glibc (Gentoo `gentoo/stage3:amd64-systemd`, systemd 261), **an upper-bound proxy, not a MIPS build**:

| | systemd | OpenRC |
|---|---|---|
| Disk, minimal set (PID 1, journald, systemctl, `libsystemd-core` + `libsystemd-shared`, udevadm, their libs), unstripped-as-shipped | 9.29 MB raw, **2.72 MB xz** | whole OpenRC tree 2.2 MB raw (`openrc`, `openrc-run`, `openrc-init`, `librc`, `libeinfo`, scripts) |
| PID 1 resident | **12.2 MB RSS / 6.6 MB PSS** | `openrc-init` 22 KB binary; no persistent supervisor besides optional `supervise-daemon` |
| journald | 11.1 MB RSS / 6.6 MB PSS | none (syslog daemon of choice) |
| udevd | 10.7 MB RSS / 5.3 MB PSS | none needed (mdev/eudev as today) |
| Minimum useful set (PID 1 + journald + udevd) | **about 18.5 MB PSS** (34 MB RSS) | about 2.2 MB on disk |

Arithmetic against the budget: flash 9.99 MiB rootfs + about 2.7-3.5 MiB (xz, MIPS code is not smaller than x86-64) = 12.7-13.5 MiB:
**fits the 16 MiB slot with about 2.5-3 MiB to spare, and the 24 MiB slot comfortably.** RAM 24-26 MB (logged in) + about 18.5 MB
= about 43-45 MB of the 118 MB usable; with the 20 MB agents about 63-65 MB: **fits, but it takes the headroom** (about 53 MB left vs about 72 MB
now, and the per-daemon `memory.max` caps would then also need cgroup v2 + systemd's own overhead). journald can be dropped
(`Storage=none` plus logs in the existing 512 KB RAM ring) and udevd replaced, cutting the extra cost to about 7-9 MB PSS.

**Verdict: by size and RAM, systemd fits on the 128 MB / 16-24 MiB Slate. What is NOT established is whether it builds and runs there:**
systemd on `mips-unknown-linux-musl` soft-float needs musl support (upstream only since v255, build-time `-Dlibc=musl`, no Gentoo
musl systemd ebuild we could cross-emerge today), and the QCA9563 has **no 64-bit atomics** (the same reason `patronus-web` needs
`libatomic`); systemd's PID 1 and `sd-event` use them. Nothing was cross-built, so every systemd number above is x86-64 data
standing in for MIPS, and the boot is unproven. OpenRC on the tier is also unproven (the embedded doc lists it as blocked on cross-emerge).
Not "skipped": the tier is a **phase-5 spike**, with the decision rule: ship OpenRC + systemd images for the router tier only if the
cross-emerge of both succeeds and boots in QEMU malta BE within the budget above; otherwise the tier stays busybox/OpenRC and the
exception is written into the profile (`profiles/hw/*.toml` `init =` key) and the owner is told that "100%" excludes systemd on
128 MB MIPS because systemd cannot be built there, not because it is too big.

## netlab on systemd: plan

Already both-init (`lan-services.sh openrc|systemd`): lane D LAN services, F/H IPsec + service control, G HA, segmentation DNS.
To do (phase 2), in this order, each as "same script, `INIT=systemd` leg added next to the OpenRC leg":

1. Lanes that run with no init at all (`lane-a-foundation.sh`, `lane-b-*`, `lane-c-*`, `lane-e-routing.sh`, `lane-j-*`): stay init-less
   (they test the apply engine, which has no init dependency); document that in `ci/netlab/README`-style header so nobody adds a leg.
2. `journey-first-boot.sh`, `failure-power-cut.sh`, `failure-atomic-apply.sh`: boot order is exactly where the two inits differ
   (`patronus-firewall.service` oneshot + `After=network-pre.target` vs the OpenRC `depend()` `need`/`before net`). Run both.
3. `wifi-hwsim.sh` hostapd@/wifi-events@ instance units vs `hostapd.<iface>` symlinked OpenRC instances.
4. Add the network-manager collision test from gap 8: stage3-systemd with `systemd-networkd` enabled and stage3-openrc with `netifrc`
   `net.eth0`, then `patronus apply` and a reboot-equivalent; addresses/routes must survive.
Cost control: reuse `patronus-ci-base` and the existing stage3 images; each added leg is about the cost of the existing lane D leg.

## Ordered plan

1. **Phase 1 (this change):** audit, `InitBackend`, name table, call-site migration, unit tests, `check-init-parity.sh`,
   `container-as-shipped-systemd.sh`, this document.
2. **Phase 2:** OpenRC leg of the as-shipped check (stage3-openrc image build with `USE=openrc -systemd`, `openrc-init` as PID 1),
   netlab legs from the plan above, user-visible strings (gap 11).
3. **Phase 3:** network-manager coexistence policy and tests (gap 8): networkd `Unmanaged`/netifrc `null` generated by `patronus apply`.
4. **Phase 4:** installer + live ISO + profiles (gaps 9, 10, 13), done with Horcrux because `build/live-iso/common` is shared:
   a systemd rootfs build, dracut/serial units, QEMU boot test (`gentoo-live-iso-build-and-qemu-test`).
5. **Phase 5:** embedded tier spike (cross-emerge OpenRC and systemd for mips-musl, QEMU malta BE boot, measure for real), then decide.

## Rules for new code

* Never spawn `rc-service`, `rc-update`, `systemctl` or `service`; use `patronus_core::ServiceManager` (CI fails otherwise).
* Every new daemon ships `files/<name>.initd` **and** `files/<name>.service` and is installed in the ebuild under both USE flags.
* A new Gentoo service whose name differs between the inits gets a row in `service::NAME_TABLE`.
