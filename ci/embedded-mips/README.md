# embedded-mips spike (see docs/embedded-routers.md)

Throwaway scripts, run in order inside capped containers (paths `/w` = this dir, `/out` = artifacts).
They are the record of the 2026-11-05 feasibility run, not a CI job yet.

01 crossdev mips-unknown-linux-musl (BE, soft-float) | 02 kernel: OpenWrt patches on 6.12.113, malta + ath79 |
03 ath79 config/modules/uImage | 04 malta nft inet fix | 05 cross-emerge rootfs | 06 cross cargo (patronus-cli) |
07 squashfs assemble + sizes | 08 QEMU malta boot + measurement (`08-qemu-cmds.txt`).
Needs the two source fixes on this branch (unused patronus-dashboard dep in patronus-cli, AtomicI64 -> AtomicI32).
The host-specific paths inside are from rw-man-03 and will need editing.
