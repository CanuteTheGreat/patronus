cd /tmp/linux-6.12.113 && export ARCH=mips CROSS_COMPILE=mips-linux-gnu-
cat >> /tmp/b-ath79/.config <<'X'
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NF_CONNTRACK=m
CONFIG_NF_NAT=m
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_NFT_CT=m
CONFIG_NFT_NAT=m
CONFIG_NFT_MASQ=m
CONFIG_NFT_CHAIN_NAT=m
CONFIG_NFT_LIMIT=m
CONFIG_NFT_LOG=m
CONFIG_NFT_REJECT=m
CONFIG_NF_CONNTRACK_FTP=n
CONFIG_WLAN_VENDOR_ATH=y
CONFIG_ATH9K=m
CONFIG_ATH9K_AHB=y
CONFIG_ATH10K=m
CONFIG_ATH10K_PCI=m
CONFIG_ATH10K_DEBUG=n
CONFIG_PCI=y
CONFIG_INET=y
CONFIG_IP_NF_IPTABLES=n
X
make O=/tmp/b-ath79 olddefconfig >/dev/null
grep -E "CONFIG_(NF_TABLES|NFT_NAT|ATH9K|ATH10K|MAC80211|WIREGUARD)=" /tmp/b-ath79/.config
nice make O=/tmp/b-ath79 -j3 vmlinux modules > /out/ath79-build3.log 2>&1; echo rc=$?; grep -n "Error\|error:" /out/ath79-build3.log | head
cd /tmp/b-ath79
mips-linux-gnu-objcopy -O binary -R .reginfo -R .notes -R .note -R .comment -R .mdebug -S vmlinux vmlinux.bin
cat vmlinux.bin arch/mips/boot/dts/qca/qca9563_glinet_gl-ar750s-nor-nand.dtb > vmlinux-dtb.bin
lzma -9 -k -c vmlinux-dtb.bin > vmlinux-dtb.lzma
mkimage -A mips -O linux -T kernel -C lzma -a 0x80060000 -e 0x80060000 -n 'Patronus embedded ath79' -d vmlinux-dtb.lzma uImage-gl-ar750s
ls -l vmlinux.bin vmlinux-dtb.lzma uImage-gl-ar750s; cp uImage-gl-ar750s .config /out/ath79/
rm -rf /tmp/mods-ath79; make -C /tmp/linux-6.12.113 O=/tmp/b-ath79 INSTALL_MOD_PATH=/tmp/mods-ath79 modules_install >/dev/null 2>&1
find /tmp/mods-ath79 -name '*.ko' | xargs -n1 mips-linux-gnu-strip --strip-unneeded
find /tmp/mods-ath79 -name '*.ko' | sed 's#.*/##' | tr '\n' ' '; echo
du -sh /tmp/mods-ath79; (cd /tmp/mods-ath79 && tar cf - lib | xz -9 | wc -c)
mkdir -p /out/mods && tar -C /tmp/mods-ath79 -cf /out/mods/ath79-modules.tar lib
