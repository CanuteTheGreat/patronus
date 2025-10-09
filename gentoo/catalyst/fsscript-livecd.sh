#!/bin/bash
# Filesystem script for Patronus LiveCD

set -e

echo "Patronus LiveCD: Configuring..."

# Create patronus user
useradd -m -G wheel -s /bin/bash patronus
echo "patronus:patronus" | chpasswd

# Allow wheel group sudo without password
echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Configure auto-login for patronus user
mkdir -p /etc/systemd/system/getty@tty1.service.d/
cat > /etc/systemd/system/getty@tty1.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin patronus --noclear %I \$TERM
EOF

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
  - Configure network: sudo patronus network list
  - Start firewall: sudo patronus firewall init
  - Web interface: sudo patronus web (then visit http://this-ip:8080)
  - Install to disk: sudo patronus-install

Default credentials:
  Username: patronus
  Password: patronus

WELCOME

# Start web interface automatically
echo "Starting Patronus web interface..."
sudo systemctl start patronus-web
echo "Web interface available at http://$(hostname -I | awk '{print $1}'):8080"
EOF

chown patronus:patronus /home/patronus/.bash_profile
chmod +x /home/patronus/.bash_profile

# Create installation script
cat > /usr/local/bin/patronus-install <<'EOF'
#!/bin/bash
# Patronus installation script

echo "Patronus Firewall Installation"
echo "=============================="
echo ""
echo "This will install Patronus to your hard drive."
echo "WARNING: This will erase the selected disk!"
echo ""

# TODO: Implement installation wizard
echo "Installation wizard not yet implemented."
echo "For manual installation, see: https://docs.patronus.dev/install"
EOF

chmod +x /usr/local/bin/patronus-install

echo "Patronus LiveCD: Configuration complete"
