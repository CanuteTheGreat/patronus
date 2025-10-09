# Catalyst spec for Patronus Live CD (stage 2)

subarch: amd64
target: livecd-stage2
version_stamp: patronus-@TIMESTAMP@
rel_type: default
profile: default/linux/amd64/23.0/systemd
source_subpath: default/livecd-stage1-amd64-patronus-latest

# Portage snapshot
snapshot: latest
portage_confdir: /home/canutethegreat/patronus/gentoo/catalyst/portage

# Boot configuration
livecd/bootargs: dokeymap
livecd/cdtar: /usr/share/catalyst/livecd/cdtar/isolinux-elilo-memtest86+-cdtar.tar.bz2
livecd/fstype: squashfs
livecd/iso: /var/tmp/catalyst/builds/patronus-amd64-@TIMESTAMP@.iso

# Kernel
boot/kernel: gentoo
boot/kernel/gentoo/sources: gentoo-kernel-bin
boot/kernel/gentoo/use: symlink livecd
boot/kernel/gentoo/config: /home/canutethegreat/patronus/gentoo/catalyst/kernel-config-livecd

# LiveCD customization
livecd/type: gentoo-release-livecd
livecd/volid: Patronus @VERSION@
livecd/overlay: /home/canutethegreat/patronus/gentoo/catalyst/livecd_overlay
livecd/fsscript: /home/canutethegreat/patronus/gentoo/catalyst/fsscript-livecd.sh
livecd/root_overlay: /home/canutethegreat/patronus/gentoo/catalyst/root_overlay

# Users
livecd/users: patronus
livecd/motd: /home/canutethegreat/patronus/gentoo/catalyst/motd.txt

# OpenRC/systemd services to enable
livecd/rcadd:
    patronus-firewall|default
    patronus-web|default
    sshd|default
    NetworkManager|default
