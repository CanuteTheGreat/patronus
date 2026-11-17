# GL-AR750S "Slate" image (real hardware)

Patronus on the GL-AR750S keeps OpenWrt's NOR kernel (6.12.112, never rewritten) and puts a musl/busybox
Patronus root on the NAND UBI `rootfs` volume. Settings live on their own UBI volume `patronus_data`
(overlays for `/etc`, `/var/lib`, `/root`). Proven on a real unit 2026-11-13 (docs/embedded-routers.md, section 6b).

| Step | Where | File |
|---|---|---|
| crossdev mips-unknown-linux-musl, router rootfs (busybox, nftables, dnsmasq, iproute2, hostapd, mtd-utils...), static OpenSSL, rust nightly | build container (Gentoo stage3) | `stage-all.sh` (+ `busybox.portage-env`: busybox with FEATURE_PREFER_APPLETS off) |
| wpa_supplicant 2.11 + dropbear from release tarballs | same | `cbuild.sh` |
| patronus-cli + patronus-web for the router feature set | same | `stage-patronus.sh` (`rebuild.sh` = busybox + bins + pack) |
| rootfs.tar + bins + libatomic | same | `pack.sh` |
| root squashfs + OpenWrt sysupgrade tar (stock kernel, fwtool metadata) | any Linux host, no compiling | `assemble.sh` (inputs in its header; per-unit files stay outside the repo), `check-rootfs.sh`, `fwmeta.py` |
| systemd v262 for the same target | build container | `stage-systemd.sh`, `ucx*.sh`, `sdsize.sh` |
| web UI / firewall / backup test against the real unit | operator host | `t_slate.py` |

On the router: `patronus-guard` (reverts to the embedded stock OpenWrt root + config backup unless the boot is
confirmed within 600 s), `patronus-flash root|openwrt|rollback|factory-reset` (A/B root, way back, settings wipe).

Host tests (CI job "Slate image tooling" in `.forgejo/workflows/embedded-tier.yml`): `sh tests/run.sh`.

First install from stock OpenWrt: `sysupgrade -n patronus-<tag>-glinet_gl-ar750s-nor-nand-sysupgrade.tar`.
Later updates from Patronus: extract `root` from the tar and `patronus-flash root <root>` (keeps settings; the
previous root stays as `rootfs_prev` for `patronus-flash rollback`).

## ETPhoneHome (always in the image)

Every Slate image, OpenRC and systemd, NAND and NOR, carries the ETPhoneHome router client (`/usr/sbin/etphonehome`, static
MIPS binary, ~4.3 MB installed / ~1.8 MB as the release package). The version is pinned in `etph.pin` (release package +
sha256); `fetch-etph.sh` downloads and verifies it, `assemble.sh` installs only the client and refuses any other file.
The service is `patronus-etph` (OpenRC, default runlevel) / `patronus-etph.service` (systemd, multi-user.target); both run
`/usr/libexec/patronus/etph-run`, which keeps all state in `/etc/etph` (the `/etc` overlay on the `patronus_data` volume,
so the adb key and `etph.conf` survive reboots and reflashes). `etph.conf` (optional, sourced): `ETPH_TRANSPORT=usb|auto|wifi`,
`ETPH_HOST`, `ETPH_TOKEN`, `ETPH_PORT`, `ETPH_EXTRA`. Status JSON: `/run/etph/status.json`, log `/var/log/etph.log`.
`check-rootfs.sh` (run by every `assemble.sh`, so by the NOR CI job and every flash build) fails an image that lacks the
binary, `etph-run`, the service, or its enablement under the image's init system; `tests/run.sh` covers those failures.

**NOR tier:** ETPhoneHome fits the OpenRC NOR root (kernel 3008 + root 10880 + settings 1024 of 16000 KiB, 1088 KiB free) but NOT the
systemd NOR root (root 12736 KiB, 768 KiB OVER the 16000 KiB firmware partition, 1024 KiB short of the 256 KiB margin). `nor-ci.sh` prints
that explicitly and tolerates exactly that known overage (it fails if it grows); the Slate itself is NAND, where both variants fit.

## Before a real flash (what went wrong once)

An image assembled in a builder that lacked wpa_supplicant, dropbear and mtd-utils (the reproducible CI image had dropped them
silently: `stage-all.sh` emerges them with `--keep-going`, and wpa_supplicant's own build had a `CFLAGS` bug) booted on the unit
with no ssh and no Wi-Fi uplink, and the guard's way back (`patronus-flash openwrt`) needed mtd-utils' `ubinfo`, so nothing
reverted it. Since then:
- `check-rootfs.sh` (run by every `assemble.sh`) refuses a root without wpa_supplicant, dropbear, hostapd, dnsmasq, nft and busybox;
- `nor-image-inner.sh` builds wpa_supplicant/dropbear (`cbuild.sh`, `CFLAGS` through the environment) and mtd-utils (`-ssl`: the
  Gentoo openssl ebuild does not build for this target) explicitly and fails the builder image if any is missing;
- `patronus-flash` and the early boot find UBI volumes through sysfs when `ubinfo` is absent, so the revert and the boot-loop
  rollback work with busybox's ubi applets alone (host tests run them with `ubinfo` removed).
Also compare the new root's file list with the running one before flashing (`unsquashfs -ll`, then `comm -23 old new`): anything
that disappeared must be explained.
