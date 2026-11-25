# On-unit rollback proof (GL-AR750S, NAND tier)

Run this BEFORE a new root becomes the boot root of a unit. It proves, with the NEW image's own busybox, mtd-utils,
`patronus-flash` and `patronus-guard`, on the unit's real kernel and UBI driver, that every way back works:

- `patronus-flash root` (forward), `rollback` twice (what patronus-init's boot-loop rollback runs), and `rollback` twice
  again with mtd-utils' `ubinfo` disabled (busybox applets + sysfs only: an image without ubinfo once could not revert);
- `patronus-guard arm` on an unconfirmed boot: `patronus-flash openwrt` puts the embedded stock root in, recreates
  `rootfs_data` with the config backup and requests the restart; a confirmed boot (`patronus-guard ok`) stays.

The test runs against a THROWAWAY UBI device (ubi1 on `mtdram`, 8 MiB of RAM) with tiny stand-in roots; the unit's own
ubi0 is only read (the staged volume `rootfs_new` is mounted read-only through ubiblock). Nothing on ubi0 changes.

## Steps (from the build host / operator machine)

1. Stage the new root on the unit without swapping it in: drop `rootfs_data` (OpenWrt's overlay, unused by Patronus),
   `ubimkvol /dev/ubi0 -N rootfs_new -s <bytes>`, stream the squashfs with mtd-utils
   `ubiupdatevol /dev/ubi0_<id> -s <bytes> -` and compare the read-back sha256 with the build's.
2. Copy to the unit's `/tmp/pt`: `outer.sh`, `proof.sh`, three small test squashfs images `A.sq`, `B.sq`, `OWRT.sq`
   (any distinct `mksquashfs` outputs), `cfg.tgz` (any small tarball), `mtdram.ko` (OpenWrt's `kmod-mtdram` for the unit's
   exact kernel: the release's `targets/<target>/kmods/<kver>-*/kmod-mtdram-*.apk`, `apk extract`; check its vermagic) and
   `ubiblock.mips` (mtd-utils' `ubiblock` from the builder's target root, `/rootfs/usr/sbin/ubiblock`).
3. `setsid sh /tmp/pt/outer.sh &` on the unit, read `/tmp/pt/proof.out`: it must end with `FAILED: none` and
   `cleanup: 0 mtdram module(s), ubi1 gone, ubiblock 0`. On a loaded unit this takes about a minute.
4. Only then swap it in exactly like `patronus-flash root` does (remove `rootfs_prev`, `ubirename rootfs rootfs_prev
   rootfs_new rootfs`, write `/data/.root-prev-kernels`, clear `/data/.init-boot-attempts`, sync), restart, and confirm
   the boot with `patronus-guard ok` after the network checks.

If any check fails, remove `rootfs_new` again (`ubirmvol /dev/ubi0 -N rootfs_new`): the unit is unchanged.
