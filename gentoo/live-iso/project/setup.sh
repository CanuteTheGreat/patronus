#!/bin/sh
set -e
chmod +x /etc/init.d/patronus-*
getent group patronus >/dev/null || groupadd -r patronus
getent passwd patronus >/dev/null || useradd -r -g patronus -d /var/lib/patronus -s /sbin/nologin patronus
mkdir -p /var/lib/patronus /var/log/patronus /etc/patronus/tls /run/patronus
chown -R patronus:patronus /var/lib/patronus /var/log/patronus /etc/patronus/tls
# patronus-web runs as user patronus and must read /etc/patronus/patronus.toml
chgrp patronus /etc/patronus && chmod 0750 /etc/patronus
chgrp patronus /etc/patronus/patronus.toml && chmod 0640 /etc/patronus/patronus.toml
# patronus-firewall = boot-time `patronus apply` (seeds + applies the ruleset); the stock
# nftables service is NOT enabled (patronus owns the ruleset)
# NOT in the live runlevel: the installer enables them on the installed system (profile services); "Try it live" starts
# patronus-applyd + patronus-web through live-product with a random admin password (firewall rules are not applied to the live host).
# every shipped binary must resolve its libraries on the live system
bad=0; for b in /usr/bin/patronus-cli /usr/bin/patronus-web /usr/bin/patronus-install; do
  if ldd $b | grep -q 'not found'; then echo "MISSING LIBS for $b:"; ldd $b | grep 'not found'; bad=1; fi; done
[ $bad = 0 ]
if [ "$(uname -m)" = riscv64 ]; then echo 'riscv64: no ZFS in the image (XFS fallback)'; exit 0; fi
# ZFS (default root file system + mirror installs): module + tools + dracut hook + a kernel build tree must be in the image
find /lib/modules -name 'zfs.ko*' | grep -q . || { echo "zfs.ko missing for the installed kernel"; exit 1; }
command -v zpool >/dev/null && command -v zgenhostid >/dev/null || { echo "zfs userland missing"; exit 1; }
[ -d /usr/lib/dracut/modules.d/90zfs ] || { echo "dracut zfs module missing"; exit 1; }
for k in /lib/modules/*; do [ -e "$k/build/Makefile" ] || { echo "no kernel build tree for $k: zfs-kmod could not be rebuilt on a kernel update"; exit 1; }; done
grep -qw dist-kernel /var/db/pkg/sys-fs/zfs-kmod-*/USE || { echo "zfs-kmod without USE=dist-kernel"; exit 1; }
# TPM unlock: tools the installer seals with and the initramfs module unseals with
for t in tpm2_createprimary tpm2_create tpm2_load tpm2_unseal tpm2_createpolicy tpm2_pcrread; do command -v $t >/dev/null || { echo "tpm2-tools: $t missing"; exit 1; }; done
[ -d /usr/lib/dracut/modules.d/92tpm-unlock ] || { echo "dracut tpm-unlock module missing"; exit 1; }
[ -e /usr/lib64/libtss2-tcti-device.so.0 ] || [ -e /usr/lib/libtss2-tcti-device.so.0 ] || { echo "libtss2-tcti-device missing; tss libs: $(find / -xdev -name 'libtss2*' 2>/dev/null | grep -E 'device|tctildr' | head -20 | tr '\n' ' ')"; exit 1; }
