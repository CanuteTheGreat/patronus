#!/bin/bash
# Filesystem script for Patronus LiveCD

set -e

echo "Patronus LiveCD: Configuring..."

# Create patronus user
useradd -m -G wheel -s /bin/bash patronus
echo "patronus:patronus" | chpasswd

# Allow wheel group sudo without password
echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Configure auto-login for patronus user (OpenRC)
# Modify /etc/inittab for autologin on tty1
if [ -f /etc/inittab ]; then
    sed -i 's|^c1:.*|c1:12345:respawn:/sbin/agetty --autologin patronus 38400 tty1 linux|' /etc/inittab
fi

# Create welcome script
cat > /home/patronus/.bash_profile <<'EOF'
#!/bin/bash

cat <<"WELCOME"
  ____       _
 |  _ \ __ _| |_ _ __ ___  _ __  _   _ ___
 | |_) / _` | __| '__/ _ \| '_ \| | | / __|
 |  __/ (_| | |_| | | (_) | | | | |_| \__ \
 |_|   \__,_|\__|_|  \___/|_| |_|\__,_|___/

Welcome to Patronus Firewall Live CD

Quick Start:
  - View network interfaces: ip addr
  - Configure DHCP: dhcpcd ethX
  - Install to disk: sudo patronus-install

Default credentials:
  Username: patronus
  Password: patronus

WELCOME
EOF

chown patronus:patronus /home/patronus/.bash_profile
chmod +x /home/patronus/.bash_profile

# Install the actual installer binary (installed by ebuild)
# The patronus-install binary is provided by net-firewall/patronus-installer

# Create convenience wrapper for TUI mode
cat > /usr/local/bin/install-patronus <<'EOF'
#!/bin/bash
# Launch Patronus installer in TUI mode
exec /usr/bin/patronus-install --tui "$@"
EOF
chmod +x /usr/local/bin/install-patronus

# Create symlink if patronus-install not in expected location
if [ -f /usr/bin/patronus-install ]; then
    ln -sf /usr/bin/patronus-install /usr/local/bin/patronus-install
fi

echo "Patronus LiveCD: Configuration complete"
