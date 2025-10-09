# Catalyst spec for Patronus Firewall custom stage3

# Subarch (change based on target architecture)
subarch: amd64
# For ARM64: subarch: arm64
# For RISC-V: subarch: riscv64

# Target profile
target: stage3
version_stamp: patronus-@TIMESTAMP@
rel_type: default
profile: default/linux/amd64/23.0/systemd
# For ARM64: profile: default/linux/arm64/23.0/systemd
# For RISC-V: profile: default/linux/riscv/rv64gc/23.0/systemd

# Source stage3
source_subpath: default/stage3-amd64-systemd-@TIMESTAMP@

# Portage snapshot
snapshot: @TIMESTAMP@
portage_confdir: /home/canutethegreat/patronus/gentoo/catalyst/portage

# Compression
compression_mode: pixz

# Stage3 packages - minimal firewall system
stage3/packages:
    # Base system
    sys-apps/baselayout
    sys-apps/openrc
    sys-apps/systemd
    sys-kernel/gentoo-kernel-bin
    sys-boot/grub
    sys-fs/e2fsprogs
    sys-fs/dosfstools

    # Networking essentials
    net-misc/dhcpcd
    net-misc/openssh
    sys-apps/iproute2
    net-firewall/nftables
    net-firewall/iptables

    # Patronus and dependencies
    dev-lang/rust
    net-firewall/patronus

    # VPN (optional based on USE flags)
    net-vpn/wireguard-tools
    net-vpn/openvpn
    net-vpn/strongswan

    # DNS/DHCP
    net-dns/unbound
    net-misc/dhcp

    # Monitoring
    app-metrics/prometheus
    net-analyzer/ntopng

    # Utilities
    app-admin/sudo
    app-editors/vim
    app-editors/nano
    sys-process/htop
    sys-apps/pciutils
    sys-apps/usbutils
    net-misc/curl
    net-misc/wget

# USE flags for stage3
stage3/use:
    systemd
    nftables
    -iptables
    ipv6
    zstd
    -gtk
    -X
    -qt5
    minimal
    hardened

# Kernel config
boot/kernel: gentoo
boot/kernel/gentoo/sources: gentoo-kernel-bin
boot/kernel/gentoo/config: /home/canutethegreat/patronus/gentoo/catalyst/kernel-config
boot/kernel/gentoo/use: symlink

# Additional options
stage3/fsscript: /home/canutethegreat/patronus/gentoo/catalyst/fsscript-stage3.sh
stage3/root_overlay: /home/canutethegreat/patronus/gentoo/catalyst/root_overlay/

# Portage configuration
portage_overlay: /home/canutethegreat/patronus/gentoo/overlay
