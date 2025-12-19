# Catalyst spec for Patronus Live CD (stage 2)

subarch: amd64
target: livecd-stage2
version_stamp: patronus-latest
rel_type: default
profile: default/linux/amd64/23.0
source_subpath: default/livecd-stage1-amd64-patronus-latest

# Portage snapshot (HEAD of gentoo.git)
snapshot_treeish: HEAD
portage_confdir: /home/canutethegreat/files/repos/mine/patronus/gentoo/catalyst/portage

# Boot configuration
livecd/bootargs: dokeymap
livecd/cdtar: /usr/share/catalyst/livecd/cdtar/isolinux-elilo-memtest86+-cdtar.tar.bz2
livecd/fstype: squashfs
livecd/iso: /var/tmp/catalyst/builds/patronus-amd64-latest.iso

# Kernel
boot/kernel: gentoo
boot/kernel/gentoo/sources: gentoo-kernel-bin
boot/kernel/gentoo/use: symlink livecd
# Note: gentoo-kernel-bin doesn't need a kernel config - it uses its built-in config

# LiveCD customization
livecd/type: gentoo-release-livecd
livecd/volid: Patronus
livecd/overlay: /home/canutethegreat/files/repos/mine/patronus/gentoo/catalyst/livecd_overlay
livecd/fsscript: /home/canutethegreat/files/repos/mine/patronus/gentoo/catalyst/fsscript-livecd.sh
livecd/root_overlay: /home/canutethegreat/files/repos/mine/patronus/gentoo/catalyst/root_overlay

# Users
livecd/users: patronus
livecd/motd: /home/canutethegreat/files/repos/mine/patronus/gentoo/catalyst/motd.txt

# OpenRC services to enable
livecd/rcadd:
    sshd|default
    dhcpcd|default
