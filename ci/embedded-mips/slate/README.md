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
