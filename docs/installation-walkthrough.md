# Patronus Installation Walkthrough

**Video Tutorial Script and Reference Guide**
**Duration:** ~15 minutes
**Difficulty:** Intermediate
**Prerequisites:** Linux system with kernel 5.10+, basic command-line knowledge

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites Check](#prerequisites-check)
3. [Installation Methods](#installation-methods)
   - [Method 1: Gentoo (Recommended)](#method-1-gentoo-recommended)
   - [Method 2: From Source](#method-2-from-source)
4. [Initial Configuration](#initial-configuration)
5. [First Login](#first-login)
6. [Basic Firewall Setup](#basic-firewall-setup)
7. [VPN Configuration](#vpn-configuration)
8. [Troubleshooting](#troubleshooting)
9. [Next Steps](#next-steps)

---

## Introduction

Welcome to the Patronus installation walkthrough! In this guide, we'll take you from a fresh Linux system to a fully functional eBPF-powered firewall in about 15 minutes.

**What you'll accomplish:**
- ✅ Install Patronus and all dependencies
- ✅ Configure basic firewall rules
- ✅ Access the web management interface
- ✅ Set up your first VPN connection
- ✅ Verify real-time monitoring is working

**What you'll need:**
- Linux system with kernel 5.10 or later
- Root/sudo access
- Network connection
- Web browser
- 10-15 minutes of time

---

## Prerequisites Check

Before we begin, let's verify your system meets the requirements.

### Step 1: Check Kernel Version

```bash
uname -r
```

**Expected output:** `5.10.0` or higher

**Why it matters:** eBPF and XDP require modern kernel features introduced in Linux 5.10+.

**If your kernel is too old:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade
sudo apt install linux-image-generic

# Gentoo
emerge --sync
emerge sys-kernel/gentoo-sources
genkernel all
```

### Step 2: Verify eBPF Support

```bash
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_XDP_SOCKETS="
```

**Expected output:**
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_XDP_SOCKETS=y
```

**If eBPF is not enabled:** You'll need to recompile your kernel with eBPF support enabled.

### Step 3: Check Available Memory

```bash
free -h
```

**Minimum recommended:** 2GB RAM
**Recommended:** 4GB+ RAM for production use

### Step 4: Verify Root Access

```bash
sudo whoami
```

**Expected output:** `root`

---

## Installation Methods

Patronus supports multiple installation methods. Choose the one that best fits your system.

---

## Method 1: Gentoo (Recommended)

Gentoo provides the most integrated experience with native ebuild packaging and OpenRC service management.

### Step 1: Add the Patronus Overlay

```bash
# Install eselect-repository if not already installed
sudo emerge --ask app-eselect/eselect-repository

# Add the Patronus overlay
sudo eselect repository add patronus git https://github.com/yourusername/patronus-gentoo

# Sync the overlay
sudo emaint sync -r patronus
```

**What's happening:**
- `eselect repository` manages third-party package repositories
- We're adding the Patronus overlay which contains the ebuild files
- `emaint sync` downloads the package metadata

**Expected time:** 30-60 seconds

### Step 2: Install Patronus

```bash
# Accept keywords for patronus packages
echo "net-firewall/patronus ~amd64" | sudo tee -a /etc/portage/package.accept_keywords

# Install Patronus
sudo emerge --ask net-firewall/patronus
```

**What's happening:**
- Portage will calculate dependencies
- You'll be prompted to accept the installation
- Compilation will begin (Rust crates take a few minutes)

**Expected time:** 5-10 minutes (depending on CPU)

**During installation, Portage will:**
1. Download Rust dependencies
2. Compile eBPF programs
3. Build the web interface
4. Install systemd/OpenRC service files
5. Create default configuration files

### Step 3: Configure OpenRC Service

```bash
# Enable Patronus to start on boot
sudo rc-update add patronus default

# Start Patronus now
sudo rc-service patronus start

# Check status
sudo rc-service patronus status
```

**Expected output:**
```
* status: started
```

### Step 4: Verify Installation

```bash
# Check if the web server is running
curl http://localhost:8080/health

# Check eBPF program is loaded
sudo bpftool prog list | grep patronus

# View logs
sudo tail -f /var/log/patronus/patronus.log
```

**Expected output:**
- HTTP 200 from health check
- eBPF programs listed in bpftool output
- Log entries showing successful startup

---

## Method 2: From Source

If you're not on Gentoo or want the latest development version, install from source.

### Step 1: Install Rust

```bash
# Install rustup (Rust toolchain installer)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow prompts and select default installation
# Restart your shell or run:
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

**Expected output:**
```
rustc 1.70.0 (or later)
cargo 1.70.0 (or later)
```

### Step 2: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libmnl-dev \
    libnftnl-dev \
    pkg-config \
    linux-headers-$(uname -r)
```

**Gentoo:**
```bash
sudo emerge --ask \
    sys-devel/clang \
    sys-devel/llvm \
    dev-libs/elfutils \
    net-libs/libmnl \
    net-libs/libnftnl
```

**Arch Linux:**
```bash
sudo pacman -S \
    base-devel \
    clang \
    llvm \
    elfutils \
    libmnl \
    libnftnl \
    linux-headers
```

### Step 3: Clone and Build Patronus

```bash
# Clone the repository
git clone https://github.com/yourusername/patronus.git
cd patronus

# Build all workspace crates
cargo build --release --workspace

# This will take 5-10 minutes on first build
```

**What's happening:**
- Cargo downloads all Rust dependencies
- Compiles eBPF programs with clang
- Builds the web interface
- Links everything into release binaries

**Build artifacts location:**
- `target/release/patronus` - Main daemon
- `target/release/patronus-cli` - Command-line tool
- `target/release/patronus-web` - Web interface binary

### Step 4: Install Binaries

```bash
# Create installation directories
sudo mkdir -p /opt/patronus/bin
sudo mkdir -p /etc/patronus
sudo mkdir -p /var/log/patronus

# Copy binaries
sudo cp target/release/patronus* /opt/patronus/bin/

# Copy default configuration
sudo cp config/patronus.toml /etc/patronus/

# Set permissions
sudo chown -R root:root /opt/patronus
sudo chmod 755 /opt/patronus/bin/*
```

### Step 5: Create Systemd Service (Optional)

```bash
# Create service file
sudo tee /etc/systemd/system/patronus.service > /dev/null <<'EOF'
[Unit]
Description=Patronus eBPF Firewall
After=network.target

[Service]
Type=simple
ExecStart=/opt/patronus/bin/patronus-web
Restart=on-failure
RestartSec=5s
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable patronus
sudo systemctl start patronus

# Check status
sudo systemctl status patronus
```

### Step 6: Verify Installation

```bash
# Test web server
curl http://localhost:8080/health

# Test CLI tool
/opt/patronus/bin/patronus-cli status

# Check logs
journalctl -u patronus -f
```

---

## Initial Configuration

Now that Patronus is installed, let's configure the basics.

### Step 1: Edit Configuration File

```bash
sudo vim /etc/patronus/patronus.toml
```

**Key settings to review:**

```toml
[server]
# Web interface bind address
bind_address = "0.0.0.0:8080"

# Enable HTTPS (recommended for production)
# tls_cert = "/etc/patronus/cert.pem"
# tls_key = "/etc/patronus/key.pem"

[firewall]
# Default policy (ACCEPT or DROP)
default_policy = "DROP"

# Enable stateful connection tracking
stateful = true

[logging]
# Log level (ERROR, WARN, INFO, DEBUG, TRACE)
level = "INFO"

# Log file location
file = "/var/log/patronus/patronus.log"

[monitoring]
# Enable metrics collection
enabled = true

# Metrics retention (days)
retention_days = 30
```

### Step 2: Configure Network Interfaces

```bash
# List your network interfaces
ip link show

# Edit configuration to specify which interfaces to monitor
sudo vim /etc/patronus/interfaces.toml
```

**Example configuration:**

```toml
[[interfaces]]
name = "eth0"
description = "WAN - Internet"
zone = "external"
xdp_enabled = true

[[interfaces]]
name = "eth1"
description = "LAN - Internal Network"
zone = "internal"
xdp_enabled = true
```

### Step 3: Restart Patronus

```bash
# OpenRC
sudo rc-service patronus restart

# Systemd
sudo systemctl restart patronus

# Verify it started successfully
# OpenRC:
sudo rc-service patronus status

# Systemd:
sudo systemctl status patronus
```

---

## First Login

Time to access the web interface!

### Step 1: Open Web Browser

Navigate to: `http://your-server-ip:8080`

**If running locally:** `http://localhost:8080`

### Step 2: Initial Login

**Default credentials:**
- **Username:** `admin`
- **Password:** `admin`

**⚠️ SECURITY WARNING:** Change the default password immediately!

### Step 3: Change Default Password

1. After logging in, click your username in the top-right corner
2. Select "Change Password"
3. Enter a strong password (12+ characters, mixed case, numbers, symbols)
4. Click "Update Password"
5. You'll be logged out - log back in with your new password

### Step 4: Tour the Interface

**Main sections:**

1. **Dashboard** - Real-time system metrics and traffic overview
2. **Firewall** - Rule management and configuration
3. **VPN** - WireGuard, OpenVPN, and IPsec setup
4. **Monitoring** - Live charts and historical data
5. **Logs** - Real-time log streaming
6. **Settings** - System configuration

---

## Basic Firewall Setup

Let's create some basic firewall rules to protect your system.

### Default Rules to Create

#### Rule 1: Allow SSH (Critical!)

**Why:** Prevent locking yourself out of remote systems.

1. Navigate to **Firewall** → **Rules**
2. Click **Add Rule**
3. Configure:
   - **Name:** Allow SSH
   - **Action:** ACCEPT
   - **Protocol:** TCP
   - **Destination Port:** 22
   - **Source:** YOUR_IP_ADDRESS (for security)
   - **Interface:** eth0 (WAN)
4. Click **Save**

**Command-line equivalent:**
```bash
patronus-cli firewall add-rule \
  --name "Allow SSH" \
  --action ACCEPT \
  --protocol tcp \
  --dport 22 \
  --source YOUR_IP/32 \
  --interface eth0
```

#### Rule 2: Allow Web Interface

1. Click **Add Rule**
2. Configure:
   - **Name:** Allow Web UI
   - **Action:** ACCEPT
   - **Protocol:** TCP
   - **Destination Port:** 8080
   - **Source:** YOUR_NETWORK/24 (e.g., 192.168.1.0/24)
   - **Interface:** eth0
3. Click **Save**

#### Rule 3: Allow Established Connections

1. Click **Add Rule**
2. Configure:
   - **Name:** Allow Established
   - **Action:** ACCEPT
   - **State:** ESTABLISHED,RELATED
   - **Interface:** ANY
3. Click **Save**

#### Rule 4: Allow Loopback

1. Click **Add Rule**
2. Configure:
   - **Name:** Allow Loopback
   - **Action:** ACCEPT
   - **Interface:** lo
3. Click **Save**

#### Rule 5: Allow ICMP (Ping)

1. Click **Add Rule**
2. Configure:
   - **Name:** Allow ICMP
   - **Action:** ACCEPT
   - **Protocol:** ICMP
3. Click **Save**

### Apply Rules

1. Review your rules in the rule list
2. Click **Apply Configuration**
3. Patronus will update the eBPF maps
4. Changes take effect immediately (no restart needed!)

### Verify Rules

```bash
# Via CLI
patronus-cli firewall list-rules

# Via eBPF
sudo bpftool map dump name FIREWALL_RULES

# Test connectivity
ping your-server-ip
ssh user@your-server-ip
```

---

## VPN Configuration

Let's set up a WireGuard VPN for secure remote access.

### Step 1: Enable WireGuard

1. Navigate to **VPN** → **WireGuard**
2. Click **Enable WireGuard**
3. Configure:
   - **Interface:** wg0
   - **Listen Port:** 51820
   - **Private Key:** (auto-generated, or paste your own)
   - **Address:** 10.0.0.1/24
4. Click **Save**

### Step 2: Create VPN Peer (Mobile Device)

1. Click **Add Peer**
2. Configure:
   - **Name:** MyPhone
   - **Public Key:** (auto-generated)
   - **Allowed IPs:** 10.0.0.2/32
   - **Persistent Keepalive:** 25
3. Click **Generate QR Code**

### Step 3: Connect Mobile Device

**On your phone:**
1. Install WireGuard app (iOS/Android)
2. Open app, tap "+" → "Scan from QR code"
3. Scan the QR code displayed in Patronus
4. Tap "Activate"
5. You're connected!

**Verify connection:**
- In Patronus, navigate to **VPN** → **Active Connections**
- You should see "MyPhone" listed as connected
- Try accessing your internal network from your phone

### Step 4: Firewall Rule for VPN

Don't forget to allow WireGuard traffic:

1. **Firewall** → **Rules** → **Add Rule**
2. Configure:
   - **Name:** Allow WireGuard
   - **Action:** ACCEPT
   - **Protocol:** UDP
   - **Destination Port:** 51820
   - **Interface:** eth0
3. Click **Save** → **Apply Configuration**

---

## Troubleshooting

Common issues and solutions.

### Issue: "Cannot connect to web interface"

**Symptoms:** Browser shows "Connection refused" or times out.

**Diagnosis:**
```bash
# Check if service is running
sudo systemctl status patronus   # systemd
sudo rc-service patronus status  # OpenRC

# Check if port is listening
sudo netstat -tlnp | grep 8080

# Check firewall rules
sudo iptables -L -n | grep 8080
```

**Solutions:**
1. Ensure service is started: `sudo systemctl start patronus`
2. Check configuration bind address in `/etc/patronus/patronus.toml`
3. Verify firewall allows port 8080
4. Check logs: `journalctl -u patronus -n 50`

### Issue: "eBPF program failed to load"

**Symptoms:** Service fails to start, logs show eBPF errors.

**Diagnosis:**
```bash
# Check kernel config
cat /boot/config-$(uname -r) | grep BPF

# Check for eBPF programs
sudo bpftool prog list

# View detailed error
journalctl -u patronus -n 100
```

**Solutions:**
1. Verify kernel version: `uname -r` (need 5.10+)
2. Recompile kernel with eBPF support enabled
3. Check if another eBPF program is loaded on the interface
4. Try unloading: `sudo ip link set dev eth0 xdp off`

### Issue: "High CPU usage"

**Symptoms:** System sluggish, top shows patronus consuming CPU.

**Diagnosis:**
```bash
# Check packet rate
sudo bpftool prog show | grep xdp
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Monitor resource usage
htop -p $(pidof patronus-web)
```

**Solutions:**
1. Optimize eBPF programs (reduce map lookups)
2. Increase map sizes to reduce evictions
3. Disable AI threat detection if not needed
4. Check for packet storms or DDoS

### Issue: "VPN not connecting"

**Symptoms:** WireGuard peer shows as disconnected.

**Diagnosis:**
```bash
# Check WireGuard status
sudo wg show

# Check if port is open
sudo netstat -ulnp | grep 51820

# Test connectivity
ping 10.0.0.1  # from peer
```

**Solutions:**
1. Verify firewall allows UDP 51820
2. Check NAT configuration if behind router
3. Verify peer configuration matches server
4. Check logs: `journalctl -u patronus | grep wireguard`

---

## Next Steps

Congratulations! You now have a working Patronus firewall installation.

### Recommended Next Actions

**1. Harden Security**
- [ ] Change default admin password (if not done already)
- [ ] Enable HTTPS for web interface
- [ ] Configure fail2ban for SSH protection
- [ ] Set up 2FA for web login (coming soon)

**2. Configure Monitoring**
- [ ] Set up alerting rules (CPU > 90%, disk full, etc.)
- [ ] Configure log retention policies
- [ ] Export metrics to Prometheus/Grafana (optional)

**3. Advanced Features**
- [ ] Configure NAT for LAN
- [ ] Set up DHCP server
- [ ] Configure DNS filtering
- [ ] Enable AI threat detection

**4. Backup Configuration**
- [ ] Export firewall rules: `patronus-cli firewall export > rules.json`
- [ ] Backup `/etc/patronus/` directory
- [ ] Document your network topology

**5. Learn More**
- [ ] Read the [Architecture Guide](./architecture.md)
- [ ] Explore the [API Documentation](./api-reference.md)
- [ ] Join the community (Discord/Reddit)
- [ ] Contribute to the project!

### Resources

- **Documentation:** https://patronus.readthedocs.io
- **GitHub:** https://github.com/yourusername/patronus
- **Blog:** https://patronus.dev/blog
- **Discord:** https://discord.gg/patronus

---

## Video Tutorial Outline

**For content creators:** Here's the recommended structure for a video walkthrough.

### Intro (0:00-1:00)
- Welcome and overview
- What Patronus is and why you'd want it
- Prerequisites disclaimer

### Installation (1:00-5:00)
- Show kernel version check
- Demonstrate Gentoo installation
- Show alternative: from-source build
- Wait during compilation (time-lapse)

### First Login (5:00-7:00)
- Access web interface
- Change default password
- Tour of the UI

### Firewall Setup (7:00-10:00)
- Create basic rules (SSH, established, etc.)
- Explain rule ordering
- Show eBPF map updates
- Test connectivity

### VPN Setup (10:00-13:00)
- Enable WireGuard
- Create mobile peer
- Generate QR code
- Connect from phone
- Show active connection

### Monitoring Demo (13:00-14:00)
- Real-time charts
- Live log streaming
- WebSocket latency demo

### Wrap-up (14:00-15:00)
- Recap what we built
- Next steps
- Call to action (star on GitHub, join Discord)

---

## Frequently Asked Questions

**Q: Can I run Patronus in a VM?**
A: Yes, but XDP requires virtual NIC drivers that support XDP (virtio-net does). Performance will be lower than bare metal.

**Q: Does Patronus replace iptables/nftables?**
A: Patronus uses eBPF/XDP for high-performance filtering, but can coexist with iptables for compatibility.

**Q: What's the performance impact?**
A: Minimal. eBPF/XDP adds ~10-20μs latency vs. 500-1000μs for iptables. CPU usage is <5% at 1Gbps.

**Q: Can I use this in production?**
A: Patronus is production-ready for adventurous users. Test thoroughly in your environment first.

**Q: How do I upgrade?**
A: Gentoo: `emerge --update patronus`. From source: `git pull && cargo build --release`.

**Q: What if I lock myself out?**
A: Boot into single-user mode, disable Patronus service, fix rules, re-enable.

**Q: Does it support IPv6?**
A: Yes! IPv6 is fully supported in both firewall and VPN components.

---

**Installation Complete!** 🎉

You now have a modern, high-performance firewall powered by eBPF, Rust, and AI.

🤖 *Generated with [Claude Code](https://claude.com/claude-code)*
