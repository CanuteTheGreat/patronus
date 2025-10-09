# Gentoo Integration Guide

Patronus is designed from the ground up to integrate seamlessly with Gentoo Linux, embracing the Gentoo philosophy of choice and customization.

## USE Flags

Patronus provides extensive USE flag support to customize your installation. This is the Gentoo way - compile only what you need.

### Core Features

| USE Flag | Description | Default |
|----------|-------------|---------|
| `web` | Enable web-based management interface | Yes |
| `cli` | Enable command-line interface | Yes |
| `api` | Enable REST API for automation | No |

### Firewall Backends

| USE Flag | Description | Default |
|----------|-------------|---------|
| `nftables` | Use nftables for packet filtering (recommended) | Yes |
| `iptables` | Use legacy iptables for packet filtering | No |

Note: At least one firewall backend must be enabled.

### Network Services

| USE Flag | Description | Default |
|----------|-------------|---------|
| `dhcp` | Enable DHCP server functionality | No |
| `dns` | Enable DNS server functionality | No |
| `unbound` | Use Unbound as DNS resolver (requires `dns`) | No |

### VPN Support

| USE Flag | Description | Default |
|----------|-------------|---------|
| `vpn` | Enable VPN functionality | No |
| `wireguard` | Enable WireGuard VPN (modern, fast) | No |
| `openvpn` | Enable OpenVPN support | No |
| `ipsec` | Enable IPsec/strongSwan support | No |

### Monitoring

| USE Flag | Description | Default |
|----------|-------------|---------|
| `monitoring` | Enable system monitoring | No |
| `prometheus` | Enable Prometheus metrics export | No |
| `ntopng` | Enable ntopng traffic analysis | No |

### Advanced Features

| USE Flag | Description | Default |
|----------|-------------|---------|
| `captive-portal` | Enable captive portal for guest networks | No |
| `intrusion-detection` | Enable IDS/IPS | No |
| `suricata` | Use Suricata for IDS (requires `intrusion-detection`) | No |
| `vlan` | Enable VLAN support | No |
| `qos` | Enable Quality of Service (traffic shaping) | No |
| `backup` | Enable configuration backup/restore | No |

## Installation

### Using the Gentoo Overlay

1. Add the Patronus overlay:

```bash
# Using eselect repository (recommended)
eselect repository add patronus git https://github.com/yourusername/patronus-overlay

# Or manually in /etc/portage/repos.conf/patronus.conf
[patronus]
location = /var/db/repos/patronus
sync-type = git
sync-uri = https://github.com/yourusername/patronus-overlay.git
auto-sync = yes
```

2. Sync the overlay:

```bash
emerge --sync patronus
```

3. Install Patronus with your desired USE flags:

```bash
# Minimal firewall-only installation
echo "net-firewall/patronus -web -cli nftables" >> /etc/portage/package.use/patronus
emerge net-firewall/patronus

# Full-featured installation with VPN and monitoring
echo "net-firewall/patronus web cli wireguard monitoring prometheus" >> /etc/portage/package.use/patronus
emerge net-firewall/patronus

# Enterprise setup with everything
echo "net-firewall/patronus web cli api wireguard openvpn ipsec dhcp dns monitoring prometheus suricata vlan qos backup" >> /etc/portage/package.use/patronus
emerge net-firewall/patronus
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/patronus.git
cd patronus

# Build with specific features
./build-arch.sh x86_64 "web,cli,nftables,wireguard"

# Or use cargo directly
cargo build --release --no-default-features --features "web,cli,nftables"
```

## Architecture Support

Patronus supports all architectures that Gentoo supports, with optimizations for:

- **x86_64 (amd64)**: Full support with CPU-specific optimizations
- **aarch64 (arm64)**: Full support, optimized for ARM servers
- **riscv64**: Full support for RISC-V systems

The build system automatically detects your architecture and applies appropriate optimizations:

```bash
# Build for current architecture (auto-detected)
./build-arch.sh

# Build for specific architecture
./build-arch.sh aarch64 "web,cli,nftables"
```

## Kernel Configuration

Patronus requires certain kernel features. Add these to your kernel config:

### Required

```
# Networking
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_BRIDGE_NETFILTER=y
CONFIG_NET_SCHED=y
CONFIG_NET_SCH_HTB=y
CONFIG_NET_SCH_FQ_CODEL=y

# nftables (if using nftables USE flag)
CONFIG_NF_TABLES=y
CONFIG_NFT_NAT=y
CONFIG_NFT_MASQ=y
CONFIG_NFT_REJECT=y
CONFIG_NFT_COUNTER=y
CONFIG_NFT_LOG=y

# iptables (if using iptables USE flag)
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=y
CONFIG_NETFILTER_XT_MATCH_STATE=y
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
```

### Optional (based on USE flags)

```
# VLAN support
CONFIG_VLAN_8021Q=y

# WireGuard VPN
CONFIG_WIREGUARD=m

# IPsec
CONFIG_XFRM_USER=y
CONFIG_INET_ESP=y
CONFIG_INET_AH=y
```

A sample kernel config is provided in `gentoo/kernel-config`.

## make.conf Optimizations

For optimal performance, add these to your `/etc/portage/make.conf`:

```bash
# CPU-specific optimizations (x86_64 example)
COMMON_FLAGS="-march=native -O3 -pipe"
CFLAGS="${COMMON_FLAGS}"
CXXFLAGS="${COMMON_FLAGS}"
RUSTFLAGS="-C target-cpu=native -C opt-level=3"

# LTO (Link Time Optimization)
CFLAGS="${CFLAGS} -flto"
CXXFLAGS="${CXXFLAGS} -flto"
LDFLAGS="${LDFLAGS} -flto"

# Rust-specific
CARGO_PROFILE_RELEASE_LTO=true
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
```

## Package.env for Patronus

Create `/etc/portage/env/patronus-optimize.conf`:

```bash
RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat"
CARGO_PROFILE_RELEASE_LTO="fat"
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
CARGO_PROFILE_RELEASE_OPT_LEVEL=3
```

Then in `/etc/portage/package.env`:

```
net-firewall/patronus patronus-optimize.conf
```

## Creating a Custom Stage3

For dedicated firewall appliances, you can create a custom Gentoo stage3:

1. Create a catalyst spec file (see `gentoo/catalyst/patronus-firewall.spec`)
2. Build the stage:

```bash
catalyst -f gentoo/catalyst/patronus-firewall.spec
```

3. The resulting stage3 will have Patronus and all dependencies pre-installed

## Live ISO

A bootable Patronus live ISO can be built using:

```bash
cd gentoo/catalyst
./build-liveiso.sh
```

This creates a bootable ISO for:
- Live testing
- Installation to hardware
- Emergency firewall deployment

## Service Management

### OpenRC (default)

```bash
# Enable at boot
rc-update add patronus-firewall boot
rc-update add patronus-web default

# Start services
rc-service patronus-firewall start
rc-service patronus-web start
```

### systemd

```bash
# Enable at boot
systemctl enable patronus-firewall
systemctl enable patronus-web

# Start services
systemctl start patronus-firewall
systemctl start patronus-web
```

## Configuration

Main configuration file: `/etc/patronus/patronus.toml`

```toml
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

# Enable only if USE=wireguard is set
[vpn.wireguard]
enabled = true
listen_port = 51820
```

## Comparison: Patronus vs Traditional Gentoo Packages

| Aspect | Traditional Package | Patronus Approach |
|--------|-------------------|-------------------|
| Customization | USE flags | USE flags + Cargo features |
| Dependencies | Package manager | Statically linked where beneficial |
| Updates | emerge --update | emerge --update |
| Configuration | /etc files | /etc files + Web UI |
| Performance | System compiler flags | Rust optimizations + compiler flags |

## Why Gentoo?

Patronus chose Gentoo as its base OS for several reasons:

1. **Source-based**: Compile with optimizations specific to your hardware
2. **USE flags**: Enable only the features you need
3. **Flexibility**: Full control over every aspect of the system
4. **Security**: Hardened kernel and toolchain options available
5. **Minimal**: No bloat, only what you choose to install
6. **Rolling release**: Always up-to-date packages

## Hardware Recommendations

### Minimum Requirements
- CPU: Any x86_64, ARM64, or RISC-V processor
- RAM: 512MB (1GB recommended with web UI)
- Storage: 2GB for minimal install, 4GB with all features
- NICs: 2x network interfaces (WAN + LAN)

### Recommended
- CPU: Multi-core x86_64 or ARM64
- RAM: 2GB or more
- Storage: 8GB SSD
- NICs: 4x gigabit (WAN, LAN, DMZ, spare)

### Enterprise
- CPU: 8+ core x86_64 with AES-NI
- RAM: 8GB or more
- Storage: 32GB+ NVMe SSD
- NICs: 10GbE or multiple gigabit with bonding

## Troubleshooting

### USE flag conflicts

```bash
# Check USE flag dependencies
emerge --pretend --verbose net-firewall/patronus

# Resolve conflicts
emerge --autounmask-write net-firewall/patronus
dispatch-conf
```

### Build failures

```bash
# Check Rust version
rustc --version  # Should be 1.75+

# Update Rust
emerge dev-lang/rust

# Clean and rebuild
cargo clean
emerge -1 net-firewall/patronus
```

## Contributing

See `CONTRIBUTING.md` for Gentoo-specific contribution guidelines.
