#!/bin/bash
# Filesystem script for Patronus stage3

set -e

echo "Patronus: Configuring stage3..."

# Set hostname
echo "patronus" > /etc/hostname

# Configure network
cat > /etc/systemd/network/20-wired.network <<EOF
[Match]
Name=en*

[Network]
DHCP=yes
EOF

# Enable systemd-networkd
systemctl enable systemd-networkd
systemctl enable systemd-resolved

# Configure Patronus
mkdir -p /etc/patronus
cat > /etc/patronus/patronus.toml <<EOF
[system]
hostname = "patronus"
domain = "local"

[network]
wan_interface = "eth0"
lan_interface = "eth1"

[firewall]
default_input = "drop"
default_forward = "drop"
default_output = "accept"

[web]
listen_addr = "0.0.0.0"
listen_port = 8080
use_tls = false
EOF

# Enable Patronus services
systemctl enable patronus-firewall
systemctl enable patronus-web

# No default root password: lock root; the installer sets credentials
passwd -l root

# Configure SSH
mkdir -p /etc/ssh
cat > /etc/ssh/sshd_config <<EOF
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
EOF

systemctl enable sshd

# Set timezone
ln -sf /usr/share/zoneinfo/UTC /etc/localtime

echo "Patronus: Stage3 configuration complete"
