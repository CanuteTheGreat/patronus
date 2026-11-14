# embedded-mips spike (see docs/embedded-routers.md)

Throwaway scripts, run in order inside capped containers (paths `/w` = this dir, `/out` = artifacts).
They are the record of the 2026-11-05 feasibility run, not a CI job yet.

01 crossdev mips-unknown-linux-musl (BE, soft-float) | 02 kernel: OpenWrt patches on 6.12.113, malta + ath79 |
03 ath79 config/modules/uImage | 04 malta nft inet fix | 05 cross-emerge rootfs | 06 cross cargo (patronus-cli) |
07 squashfs assemble + sizes | 08 QEMU malta boot + measurement (`08-qemu-cmds.txt`).
Needs the two source fixes on this branch (unused patronus-dashboard dep in patronus-cli, AtomicI64 -> AtomicI32).
The host-specific paths inside are from rw-man-03 and will need editing.

## Web UI spike (2026-11-06, section 6a of the doc)

| Step | File |
|---|---|
| static OpenSSL 3.6.5 for the target (Gentoo's ebuild picks `-m64` here) | `09a-openssl-static.sh` |
| cross-build `patronus-cli` + `patronus-web` with the router feature set | `09-build-both.sh` (needs `OPENSSL_DIR`/`OPENSSL_STATIC=1`, `-C link-arg=-lgcc` in `rust-g.sh`) |
| rootfs = CLI rootfs + web + `overlay/` (patronus.toml, init scripts) -> squashfs | `10-assemble-web.sh` (`CLI=<cli binary> 10-assemble-web.sh <web> <out.squashfs> overlay`) |
| QEMU malta harness (LAN NIC 192.168.1.1 via slirp hostfwd, WAN NIC, ext4 data disk on IDE) | `qemu_harness.py`, `guestd.py`/`gx` (long-lived guest for debugging), `killq.sh` |
| end-to-end: first-run, login, pages, firewall -> nft, backup/restore, reboot from the UI, persistence, RSS | `t_e2e.py <rootfs.squashfs>` (about 8 min; `/out` = artifacts dir, `vmlinux-malta-be2` + `data.img` there) |
| load + peak RSS | `t_load.py <rootfs.squashfs>` |

Run `t_*.py` inside a Debian 12 container with `qemu-system-mips ipxe-qemu seabios curl python3 e2fsprogs`.
