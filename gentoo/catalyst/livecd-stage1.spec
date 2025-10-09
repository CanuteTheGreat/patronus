# Catalyst spec for Patronus Live CD (stage 1)

subarch: amd64
target: livecd-stage1
version_stamp: patronus-@TIMESTAMP@
rel_type: default
profile: default/linux/amd64/23.0/systemd
source_subpath: default/stage3-amd64-systemd-latest

# Portage snapshot
snapshot: latest
portage_confdir: /home/canutethegreat/patronus/gentoo/catalyst/portage

# LiveCD stage1 packages
livecd/use:
    systemd
    nftables
    livecd
    fbcon
    ncurses
    readline
    ssl

livecd/packages:
    # Base LiveCD
    app-admin/sudo
    app-admin/syslog-ng
    app-arch/unzip
    app-editors/vim
    app-editors/nano
    app-misc/livecd-tools
    app-misc/screen
    app-misc/tmux

    # Networking
    net-dialup/ppp
    net-dialup/rp-pppoe
    net-misc/dhcpcd
    net-misc/openssh
    net-wireless/iw
    net-wireless/wireless-tools
    net-wireless/wpa_supplicant
    sys-apps/iproute2
    sys-apps/ethtool

    # Firewall
    net-firewall/nftables
    net-firewall/patronus

    # Filesystem tools
    sys-fs/btrfs-progs
    sys-fs/dosfstools
    sys-fs/e2fsprogs
    sys-fs/xfsprogs
    sys-fs/ntfs3g

    # Disk tools
    sys-block/parted
    sys-apps/gptfdisk
    sys-apps/hdparm
    sys-apps/smartmontools

    # System tools
    sys-apps/pciutils
    sys-apps/usbutils
    sys-process/htop
    sys-process/lsof
    app-arch/zip
    app-arch/unzip
    app-arch/tar

    # Network diagnosis
    net-analyzer/tcpdump
    net-analyzer/traceroute
    net-analyzer/nmap
    net-misc/curl
    net-misc/wget
    net-dns/bind-tools
