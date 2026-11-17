#!/bin/bash
# INSIDE the builder, after stage-patronus.sh + stage-rootfs.sh: collect what assemble.sh takes into /out/pack:
#   rootfs.tar, openrc.tar, patronus-cli; and the missing-library report for every ELF in the root.
set -euo pipefail
T=aarch64-unknown-linux-musl; O=/out/pack; rm -rf $O; mkdir -p $O
cp ${CARGO_TARGET_DIR:-/out/target}/$T/release/patronus-cli $O/
# the cargo features of that binary: assemble.sh records them in /etc/patronus-release, check-rootfs.sh requires the
# runtime pieces of each (vpn-wireguard: wg + the kernel module; ntp-server: chronyd)
cp /out/patronus-features $O/features
tar cf $O/rootfs.tar -C /out/rootfs --exclude=./usr/include --exclude=./usr/share/man --exclude=./usr/share/doc .
tar cf $O/openrc.tar -C /out/rootfs-openrc --exclude=./usr/include --exclude=./usr/share/man --exclude=./usr/share/doc --exclude=./var/db/pkg --exclude=./usr/lib/pkgconfig .
ls -l $O
