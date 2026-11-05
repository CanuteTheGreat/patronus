cd /tmp/linux-6.12.113 && export ARCH=mips CROSS_COMPILE=mips-linux-gnu-
cat >> /tmp/b-malta/.config <<'X'
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_NAT=y

CONFIG_NFT_FIB_INET=y
CONFIG_NFT_COUNTER=y
CONFIG_NF_CONNTRACK_FTP=n
X
make O=/tmp/b-malta olddefconfig >/dev/null
grep -E "^CONFIG_(NF_TABLES_INET|NFT_NAT|NFT_CHAIN_NAT)=" /tmp/b-malta/.config
nice make O=/tmp/b-malta -j3 vmlinux > /out/malta-build2.log 2>&1; echo rc=$?
mips-linux-gnu-objcopy -O elf32-tradbigmips -S /tmp/b-malta/vmlinux /out/vmlinux-malta-be2 2>/dev/null || cp /tmp/b-malta/vmlinux /out/vmlinux-malta-be2
ls -l /out/vmlinux-malta-be2; mips-linux-gnu-size /tmp/b-malta/vmlinux
