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
# NOTE (fixed 2026-10-13, see patronus_gentoo_kernel_prepare_fail_20261009):
# gentoo-kernel-bin ships ONLY prebuilt binaries/modules, no /usr/src/linux
# kernel source tree. Catalyst's livecd-stage2 kmerge step always drives
# genkernel to build the LiveCD's own custom initramfs (cdroot/aufs/netboot
# support), and genkernel's initramfs build runs `make prepare` against the
# installed kernel source tree to set up Kbuild so it can compile the
# initramfs's bundled modules/busybox -- with gentoo-kernel-bin there is no
# source tree to prepare, so that step hard-fails
# ("ERROR: compile_generic() failed to compile the prepare target").
# The earlier 2026-10-09 installkernel[dracut] USE-flag fix addressed a
# separate dependency-resolution failure during normal `emerge` kernel
# installs; it does not apply to catalyst's genkernel-driven LiveCD
# initramfs build, which is why the kernel step failed again afterward with
# a different root cause. Fix: build gentoo-kernel from source instead (the
# officially-supported catalyst/genkernel LiveCD path) so a real kernel
# source tree exists for genkernel's prepare/module-compile steps.
boot/kernel: gentoo
boot/kernel/gentoo/sources: gentoo-kernel
boot/kernel/gentoo/use: symlink livecd

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
