#!/bin/bash
# inside debian:12: OpenWrt 25.12 ath79 patch set on vanilla linux 6.12.113 -> (a) GL-AR750S uImage, (b) malta BE QEMU kernel
set -uo pipefail
exec > >(tee -a /out/kernel.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
echo "== $(date) apt"
apt-get update -qq && apt-get install -y -qq gcc-mips-linux-gnu binutils-mips-linux-gnu bc flex bison libssl-dev libelf-dev xz-utils lzma patch perl python3 curl ca-certificates u-boot-tools make gcc file cpio device-tree-compiler >/dev/null || { echo FAIL apt; exit 1; }
OW=/w/owrt/target/linux
V=6.12.113
cd /tmp
curl -fsSL -o linux.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$V.tar.xz || { echo FAIL download; exit 1; }
tar xf linux.tar.xz && cd linux-$V
cp -a $OW/generic/files/. . ; cp -a $OW/ath79/files/. .
echo "== $(date) patches"
n=0; fail=0
for d in $OW/generic/backport-6.12 $OW/generic/pending-6.12 $OW/generic/hack-6.12 $OW/ath79/patches-6.12; do
  for p in $(ls $d/*.patch | sort); do
    if patch -p1 -s --no-backup-if-mismatch < $p >/tmp/patch.out 2>&1; then n=$((n+1)); else echo "PATCH FAIL: $p"; head -5 /tmp/patch.out; fail=$((fail+1)); fi
  done
done
echo "patches applied=$n failed=$fail"
cp $OW/ath79/dts/*.dts $OW/ath79/dts/*.dtsi arch/mips/boot/dts/qca/
export ARCH=mips CROSS_COMPILE=mips-linux-gnu-
# ---- (a) ath79 / GL-AR750S
echo "== $(date) ath79 config"
perl /w/owrt/scripts/kconfig.pl + + $OW/generic/config-6.12 $OW/ath79/config-6.12 $OW/ath79/nand/config-default > /tmp/ath79.config
mkdir -p /tmp/b-ath79 && cp /tmp/ath79.config /tmp/b-ath79/.config
cat >> /tmp/b-ath79/.config <<'EOF'
CONFIG_SQUASHFS=y
CONFIG_SQUASHFS_XZ=y
CONFIG_UBIFS_FS=y
CONFIG_OVERLAY_FS=y
CONFIG_MTD_UBI=y
CONFIG_MTD_SPI_NOR=y
CONFIG_MTD_SPI_NAND=y
CONFIG_MTD_SPLIT_UIMAGE_FW=n
CONFIG_NF_TABLES=m
CONFIG_NF_CONNTRACK=m
CONFIG_NF_NAT=m
CONFIG_NFT_CT=m
CONFIG_NFT_NAT=m
CONFIG_NFT_MASQ=m
CONFIG_NFT_CHAIN_NAT=m
CONFIG_NFT_LIMIT=m
CONFIG_NFT_LOG=m
CONFIG_NFT_REJECT=m
CONFIG_NFT_FIB_IPV4=m
CONFIG_BRIDGE=y
CONFIG_VLAN_8021Q=y
CONFIG_WIREGUARD=m
CONFIG_MAC80211=m
CONFIG_CFG80211=m
CONFIG_ATH9K=m
CONFIG_ATH10K=m
CONFIG_BPF_SYSCALL=n
EOF
make O=/tmp/b-ath79 olddefconfig 2>&1 | tail -3
echo "== $(date) ath79 build"
nice make O=/tmp/b-ath79 -j3 vmlinux qca/qca9563_glinet_gl-ar750s-nor-nand.dtb modules 2>&1 | tail -15
ls -l /tmp/b-ath79/vmlinux /tmp/b-ath79/arch/mips/boot/dts/qca/qca9563_glinet_gl-ar750s-nor-nand.dtb
(cd /tmp/b-ath79 && mips-linux-gnu-objcopy -O binary -R .reginfo -R .notes -R .note -R .comment -R .mdebug -S vmlinux vmlinux.bin && \
 cat vmlinux.bin arch/mips/boot/dts/qca/qca9563_glinet_gl-ar750s-nor-nand.dtb > vmlinux-dtb.bin && lzma -9 -k -c vmlinux-dtb.bin > vmlinux-dtb.lzma && \
 mkimage -A mips -O linux -T kernel -C lzma -a 0x80060000 -e 0x80060000 -n 'Patronus embedded ath79' -d vmlinux-dtb.lzma uImage-gl-ar750s && \
 ls -l vmlinux vmlinux.bin uImage-gl-ar750s && mkimage -l uImage-gl-ar750s)
mkdir -p /out/ath79 && cp /tmp/b-ath79/uImage-gl-ar750s /tmp/b-ath79/.config /out/ath79/
du -sh /tmp/b-ath79/lib 2>/dev/null; (cd /tmp/b-ath79 && make -C /tmp/linux-$V O=/tmp/b-ath79 INSTALL_MOD_PATH=/tmp/mods-ath79 modules_install >/dev/null 2>&1; du -sh /tmp/mods-ath79; echo "module count: $(find /tmp/mods-ath79 -name '*.ko' | wc -l)")
# ---- (b) malta BE (QEMU)
echo "== $(date) malta config"
mkdir -p /tmp/b-malta
make O=/tmp/b-malta malta_defconfig 2>&1 | tail -1
cat >> /tmp/b-malta/.config <<'EOF'
CONFIG_CPU_BIG_ENDIAN=y
CONFIG_CPU_LITTLE_ENDIAN=n
CONFIG_CPU_MIPS32_R2=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_SQUASHFS=y
CONFIG_SQUASHFS_XZ=y
CONFIG_SQUASHFS_ZLIB=y
CONFIG_OVERLAY_FS=y
CONFIG_TMPFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_NETFILTER=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_NAT=y
CONFIG_NF_TABLES=y
CONFIG_NFT_CT=y
CONFIG_NFT_NAT=y
CONFIG_NFT_MASQ=y
CONFIG_NFT_CHAIN_NAT=y
CONFIG_NFT_LIMIT=y
CONFIG_NFT_LOG=y
CONFIG_NFT_REJECT=y
CONFIG_BRIDGE=y
CONFIG_VLAN_8021Q=y
CONFIG_WIREGUARD=y
CONFIG_CRYPTO_ZSTD=y
CONFIG_EXT4_FS=y
EOF
make O=/tmp/b-malta olddefconfig 2>&1 | tail -2
grep -E "CONFIG_(CPU_BIG_ENDIAN|CPU_MIPS32_R2|NF_TABLES|SQUASHFS_XZ|MIPS_MALTA)=" /tmp/b-malta/.config
echo "== $(date) malta build"
nice make O=/tmp/b-malta -j3 vmlinux 2>&1 | tail -5
mips-linux-gnu-strip -o /out/vmlinux-malta-be /tmp/b-malta/vmlinux; cp /tmp/b-malta/vmlinux /out/vmlinux-malta-be.full; cp /tmp/b-malta/.config /out/malta.config
ls -l /out/vmlinux-malta-be*
echo "== $(date) done"
