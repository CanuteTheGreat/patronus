# Patronus Firewall Quick Start Guide

Get Patronus up and running in 15 minutes!

**Version:** 0.1.0
**Last Updated:** 2025-10-08

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation (Gentoo)](#installation-gentoo)
3. [First Boot Configuration](#first-boot-configuration)
4. [Common Scenarios](#common-scenarios)
5. [Next Steps](#next-steps)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum:**
- CPU: 2 cores (x86_64)
- RAM: 512 MB
- Disk: 2 GB
- Network: 2× Ethernet interfaces (WAN + LAN)

**Recommended:**
- CPU: 4+ cores (for AI/eBPF features)
- RAM: 4 GB
- Disk: 10 GB (SSD preferred)
- Network: Intel NIC with XDP support (X710, E810 for best performance)

### Software Requirements

- **Operating System:** Gentoo Linux (required)
- **Kernel:** Linux 5.15+ (6.x recommended for best eBPF support)
- **Kernel Config:**
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_XDP_SOCKETS=y`
  - `CONFIG_NETFILTER=y`
  - `CONFIG_NF_TABLES=y`

### Network Setup

```
Internet ─── [WAN: eth0] Patronus [LAN: eth1] ─── Internal Network
                                                    (192.168.1.0/24)
```

---

## Installation (Gentoo)

### Step 1: Add Patronus Overlay

```bash
# Add the overlay repository
eselect repository add patronus git https://github.com/yourusername/patronus-overlay

# Sync overlay
emaint sync -r patronus

# Verify overlay added
eselect repository list
```

### Step 2: Configure USE Flags

Choose a profile based on your needs:

#### Profile 1: Home Router (Minimal)

```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus cli nftables vpn-wireguard dhcp dns monitoring
EOF
```

**Features:** CLI management, WireGuard VPN, DHCP, DNS

**Resources:** ~300 MB RAM, ~500 MB disk

#### Profile 2: Small Business Gateway

```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus web cli nftables vpn-wireguard vpn-openvpn
  dhcp dns vlan qos monitoring captive-portal
EOF
```

**Features:** Web UI, multiple VPNs, VLANs, QoS, captive portal

**Resources:** ~400 MB RAM, ~600 MB disk

#### Profile 3: Enterprise Edge Firewall

```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus web cli api nftables
  vpn-wireguard vpn-openvpn vpn-ipsec
  dhcp dns dns-unbound
  monitoring monitoring-prometheus
  ids-suricata vlan qos backup
  gitops ai arch-native
EOF
```

**Features:** All VPNs, IDS/IPS, AI threat detection, GitOps, Prometheus

**Resources:** ~600 MB RAM, ~1 GB disk

#### Profile 4: Cloud-Native / Kubernetes

```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus cli nftables kubernetes gitops ai
  monitoring-prometheus arch-native
EOF
```

**Features:** Kubernetes CNI plugin, GitOps, AI, minimal footprint

**Resources:** ~500 MB RAM, ~800 MB disk

### Step 3: Install Patronus

```bash
# Install (this will take 15-30 minutes to compile)
emerge -av net-firewall/patronus

# Verify installation
patronus --version
```

---

## First Boot Configuration

### Step 1: Initialize Secrets

```bash
# Initialize secrets encryption (you'll be prompted for a password)
patronus secrets init

# This creates /etc/patronus/secrets.d/ with encrypted master key
```

**Important:** Remember this password! It's needed to decrypt secrets on boot.

### Step 2: Configure Basic Settings

```bash
# Copy example configuration
cp /etc/patronus/patronus.toml.example /etc/patronus/patronus.toml

# Edit configuration
nano /etc/patronus/patronus.toml
```

**Minimal configuration:**

```toml
[system]
hostname = "gateway"
domain = "localdomain"

[interfaces.wan]
name = "eth0"
role = "wan"
ipv4 = "dhcp"  # or static: "203.0.113.5/24"

[interfaces.lan]
name = "eth1"
role = "lan"
ipv4 = "192.168.1.1/24"

[firewall]
backend = "nftables"
default_policy_wan = "drop"
default_policy_lan = "allow"

[dhcp.lan]
enabled = true
range_start = "192.168.1.100"
range_end = "192.168.1.200"
gateway = "192.168.1.1"
dns_servers = ["192.168.1.1"]
lease_time = 86400

[dns]
enabled = true
upstream = ["1.1.1.1", "8.8.8.8"]
```

### Step 3: Configure Firewall Rules

Create `/etc/patronus/firewall/rules.yaml`:

```yaml
# Basic firewall rules
rules:
  # Allow established/related connections
  - name: allow-established
    action: allow
    state: [established, related]
    enabled: true

  # Allow ICMP (ping)
  - name: allow-icmp
    protocol: icmp
    action: allow
    enabled: true

  # Allow SSH from LAN only
  - name: allow-ssh-lan
    interface: lan
    protocol: tcp
    destination_port: 22
    action: allow
    enabled: true

  # Allow DNS from LAN
  - name: allow-dns-lan
    interface: lan
    protocol: udp
    destination_port: 53
    action: allow
    enabled: true

  # Allow DHCP from LAN
  - name: allow-dhcp-lan
    interface: lan
    protocol: udp
    source_port: 68
    destination_port: 67
    action: allow
    enabled: true

  # Allow web traffic outbound
  - name: allow-http-out
    interface: wan
    protocol: tcp
    destination_port: [80, 443]
    direction: outbound
    action: allow
    enabled: true

  # Drop all other WAN inbound
  - name: drop-wan-default
    interface: wan
    action: drop
    enabled: true
```

### Step 4: Configure NAT (Masquerading)

Create `/etc/patronus/firewall/nat.yaml`:

```yaml
nat_rules:
  # Masquerade LAN traffic to WAN
  - name: masquerade-lan
    type: masquerade
    out_interface: wan
    source: 192.168.1.0/24
    enabled: true
```

### Step 5: Start Services

```bash
# Enable and start firewall service
systemctl enable --now patronus-firewall

# Check status
systemctl status patronus-firewall

# View logs
journalctl -u patronus-firewall -f

# If you installed with USE=web, start web interface
systemctl enable --now patronus-web

# Access web interface at https://192.168.1.1:443
# Default credentials: admin / patronus (CHANGE IMMEDIATELY!)
```

### Step 6: Verify Connectivity

```bash
# From a LAN client:

# Test DNS resolution
nslookup google.com 192.168.1.1

# Test internet connectivity
ping -c 3 8.8.8.8

# Test web browsing
curl -I https://google.com
```

---

## Common Scenarios

### Scenario 1: Add Port Forwarding

**Goal:** Forward port 8080 (WAN) → 192.168.1.10:80 (LAN web server)

Edit `/etc/patronus/firewall/nat.yaml`:

```yaml
nat_rules:
  # ... existing rules ...

  # Port forward for web server
  - name: forward-web-server
    type: dnat
    in_interface: wan
    protocol: tcp
    destination_port: 8080
    to_address: 192.168.1.10
    to_port: 80
    enabled: true
```

Add firewall rule in `/etc/patronus/firewall/rules.yaml`:

```yaml
rules:
  # ... existing rules ...

  - name: allow-forwarded-web
    interface: wan
    protocol: tcp
    destination: 192.168.1.10
    destination_port: 80
    action: allow
    enabled: true
```

Apply changes:

```bash
patronus firewall reload
```

### Scenario 2: Set Up WireGuard VPN

#### Generate Keys

```bash
# Generate server keys
wg genkey | tee /tmp/server-private.key | wg pubkey > /tmp/server-public.key

# Generate client keys
wg genkey | tee /tmp/client-private.key | wg pubkey > /tmp/client-public.key
```

#### Configure Server

Edit `/etc/patronus/patronus.toml`:

```toml
[vpn.wireguard.wg0]
enabled = true
private_key_file = "/etc/patronus/secrets.d/wg-server.key"
listen_port = 51820
address = "10.99.0.1/24"

[[vpn.wireguard.wg0.peers]]
public_key = "CLIENT_PUBLIC_KEY_HERE"
allowed_ips = ["10.99.0.2/32"]
```

#### Save Private Key Securely

```bash
# Store server private key in secrets
cat /tmp/server-private.key | patronus secrets set wireguard-server-key
rm /tmp/server-private.key

# Create symbolic link for config
ln -s /etc/patronus/secrets.d/wireguard-server-key /etc/patronus/secrets.d/wg-server.key
```

#### Start VPN

```bash
systemctl restart patronus-firewall

# Verify interface created
ip addr show wg0

# Check WireGuard status
wg show
```

#### Client Configuration

Create `client-wg0.conf`:

```ini
[Interface]
PrivateKey = <content of client-private.key>
Address = 10.99.0.2/32
DNS = 192.168.1.1

[Peer]
PublicKey = <content of server-public.key>
Endpoint = YOUR_WAN_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Connect:

```bash
# On client machine
wg-quick up ./client-wg0.conf
```

### Scenario 3: Enable AI Threat Detection

Edit `/etc/patronus/patronus.toml`:

```toml
[ai]
enabled = true
model_type = "isolation_forest"
anomaly_threshold = 0.7
confidence_threshold = 0.8
auto_block = false  # Set to true for automatic blocking

# Optional: AbuseIPDB integration
[ai.threat_intel.abuseipdb]
enabled = true
api_key = "YOUR_API_KEY"  # Get free key from abuseipdb.com
confidence_minimum = 75
update_interval = 3600  # 1 hour
```

Restart and train:

```bash
systemctl restart patronus-firewall

# Train on baseline traffic (run during normal operation)
patronus ai train --duration 300  # 5 minutes

# View detected threats
patronus ai threats list

# View pending auto-generated rules
patronus ai rules pending

# Approve a rule
patronus ai rules approve <rule-id>
```

### Scenario 4: Set Up VLANs

Edit `/etc/patronus/patronus.toml`:

```toml
# VLAN 10: Office
[interfaces.lan_office]
name = "eth1.10"
role = "lan"
ipv4 = "192.168.10.1/24"
vlan_id = 10

# VLAN 20: Guest WiFi
[interfaces.lan_guest]
name = "eth1.20"
role = "lan"
ipv4 = "192.168.20.1/24"
vlan_id = 20

# DHCP for Office VLAN
[dhcp.lan_office]
enabled = true
range_start = "192.168.10.100"
range_end = "192.168.10.200"
gateway = "192.168.10.1"

# DHCP for Guest VLAN
[dhcp.lan_guest]
enabled = true
range_start = "192.168.20.100"
range_end = "192.168.20.200"
gateway = "192.168.20.1"
```

Firewall rules in `/etc/patronus/firewall/rules.yaml`:

```yaml
rules:
  # Block guest VLAN from office VLAN
  - name: block-guest-to-office
    source_interface: lan_guest
    destination: 192.168.10.0/24
    action: drop
    enabled: true

  # Allow guest to internet only
  - name: allow-guest-internet
    source_interface: lan_guest
    out_interface: wan
    action: allow
    enabled: true
```

Apply:

```bash
systemctl restart patronus-firewall
```

### Scenario 5: Enable GitOps

**Goal:** Manage firewall configuration from Git repository

#### Set Up Git Repository

```bash
# Create config repository
mkdir -p ~/patronus-config
cd ~/patronus-config
git init

# Create firewall rules
cat > firewall/rules.yaml <<EOF
rules:
  - name: allow-ssh
    protocol: tcp
    destination_port: 22
    action: allow
    enabled: true
EOF

git add .
git commit -m "Initial firewall config"

# Push to GitHub/GitLab
git remote add origin https://github.com/yourorg/patronus-config
git push -u origin main
```

#### Configure Patronus GitOps

Edit `/etc/patronus/patronus.toml`:

```toml
[gitops]
enabled = true
repository = "https://github.com/yourorg/patronus-config"
branch = "main"
sync_interval = 60  # Check every 60 seconds
auto_apply = true   # Automatically apply changes
ssh_key_file = "/etc/patronus/secrets.d/gitops-deploy-key"

# Or use HTTPS with token
# token_file = "/etc/patronus/secrets.d/github-token"
```

#### Deploy Key Setup

```bash
# Generate deploy key
ssh-keygen -t ed25519 -f /tmp/gitops-deploy-key -N ""

# Save to secrets
cat /tmp/gitops-deploy-key | patronus secrets set gitops-deploy-key
rm /tmp/gitops-deploy-key

# Add public key to GitHub/GitLab (Settings → Deploy Keys)
cat /tmp/gitops-deploy-key.pub
```

#### Test GitOps

```bash
# Restart to enable GitOps
systemctl restart patronus-firewall

# View sync status
patronus gitops status

# Manual sync
patronus gitops sync

# Now any changes to Git will auto-apply!
```

---

## Next Steps

### Secure Your Installation

1. **Change default password** (if using Web UI)
   ```bash
   patronus users passwd admin
   ```

2. **Generate TLS certificate**
   ```bash
   patronus tls generate --domain gateway.local
   ```

3. **Enable audit logging**
   ```toml
   [logging]
   audit_enabled = true
   audit_log = "/var/log/patronus/audit.log"
   ```

4. **Review firewall rules**
   ```bash
   patronus firewall list-rules
   patronus firewall test --dry-run
   ```

### Enable Monitoring

```bash
# Install Prometheus (if not using USE=monitoring-prometheus)
emerge -av net-analyzer/prometheus

# Configure Prometheus to scrape Patronus
cat >> /etc/prometheus/prometheus.yml <<EOF
scrape_configs:
  - job_name: 'patronus'
    static_configs:
      - targets: ['localhost:9090']
EOF

# View metrics
curl http://localhost:9090/metrics
```

### Performance Tuning

```bash
# Enable XDP for maximum performance (requires supported NIC)
patronus ebpf enable --mode xdp-native --interface eth0

# Verify XDP loaded
ip link show eth0 | grep xdp

# View performance statistics
patronus stats show
```

### Explore Documentation

- [Architecture](ARCHITECTURE.md) - System design and internals
- [Security Hardening](SECURITY-HARDENING.md) - Advanced security configuration
- [eBPF Optimization](EBPF-OPTIMIZATION.md) - Performance tuning guide
- [Comparisons](COMPARISONS.md) - How Patronus compares to pfSense/OPNsense/etc.
- [Testing](TESTING.md) - Testing procedures

---

## Troubleshooting

### Issue: Services won't start

```bash
# Check system logs
journalctl -u patronus-firewall -n 50

# Verify configuration syntax
patronus validate /etc/patronus/patronus.toml

# Check secrets decryption
patronus secrets list
```

### Issue: No internet connectivity on LAN

```bash
# Verify NAT is configured
patronus nat list

# Check firewall rules
patronus firewall list-rules

# Enable packet forwarding
sysctl net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Verify interface status
ip addr show
ip route show
```

### Issue: DHCP not working

```bash
# Check DHCP server status
patronus dhcp status

# View active leases
patronus dhcp leases

# Check DHCP logs
journalctl -u patronus-firewall | grep -i dhcp

# Test DHCP manually (from client)
sudo dhclient -v eth0
```

### Issue: DNS resolution fails

```bash
# Check DNS server status
patronus dns status

# Test DNS resolution locally
dig @127.0.0.1 google.com

# Check upstream DNS
dig @1.1.1.1 google.com

# View DNS cache
patronus dns cache-stats
```

### Issue: VPN not connecting

```bash
# WireGuard: Check interface status
wg show

# View WireGuard logs
journalctl | grep -i wireguard

# Verify firewall allows VPN port
patronus firewall list-rules | grep 51820

# Check NAT for VPN subnet
patronus nat list | grep 10.99.0
```

### Issue: Web UI not accessible

```bash
# Check web service status
systemctl status patronus-web

# Verify listening port
ss -tlnp | grep 443

# Check firewall rules
patronus firewall list-rules | grep 443

# View web logs
journalctl -u patronus-web -f
```

### Getting Help

- **Documentation:** https://github.com/yourusername/patronus/tree/main/docs
- **GitHub Issues:** https://github.com/yourusername/patronus/issues
- **GitHub Discussions:** https://github.com/yourusername/patronus/discussions
- **Matrix Chat:** #patronus:matrix.org (coming soon)

---

## Quick Reference Commands

### Configuration Management

```bash
patronus validate /etc/patronus/patronus.toml  # Validate config
patronus reload                                 # Reload configuration
patronus backup create                          # Create backup
patronus backup restore backup-2025-10-08.tar   # Restore backup
```

### Firewall Management

```bash
patronus firewall list-rules                    # List all rules
patronus firewall add-rule --help               # Add rule help
patronus firewall delete-rule <name>            # Delete rule
patronus firewall reload                        # Reload rules
patronus firewall stats                         # View statistics
```

### NAT Management

```bash
patronus nat list                               # List NAT rules
patronus nat sessions                           # View active NAT sessions
```

### Network Management

```bash
patronus interface list                         # List interfaces
patronus dhcp leases                            # View DHCP leases
patronus dns cache-stats                        # DNS cache statistics
```

### VPN Management

```bash
patronus vpn wireguard status                   # WireGuard status
patronus vpn wireguard add-peer --help          # Add peer help
patronus vpn wireguard list-peers               # List peers
```

### AI/Threat Detection

```bash
patronus ai enable                              # Enable AI detection
patronus ai train --duration 300                # Train model (5 min)
patronus ai threats list                        # List detected threats
patronus ai rules pending                       # Pending auto-rules
patronus ai rules approve <id>                  # Approve rule
```

### GitOps Management

```bash
patronus gitops status                          # Sync status
patronus gitops sync                            # Manual sync
patronus gitops diff                            # Show pending changes
```

### System Management

```bash
patronus status                                 # Overall system status
patronus stats                                  # Performance statistics
patronus logs --tail 100                        # View recent logs
patronus version                                # Show version
```

---

## Success Checklist

After completing this guide, you should have:

- ✅ Patronus installed on Gentoo
- ✅ WAN and LAN interfaces configured
- ✅ Basic firewall rules applied
- ✅ NAT/masquerading working
- ✅ DHCP server running on LAN
- ✅ DNS resolution working
- ✅ Internet connectivity from LAN clients
- ✅ Services set to start on boot

**Congratulations!** You now have a fully functional Patronus firewall. 🎉

**Next:** Explore advanced features like VPNs, VLANs, AI threat detection, and GitOps!

---

**Last Updated:** 2025-10-08
**Version:** 0.1.0

Welcome to the future of open-source firewalls. Enjoy Patronus!
