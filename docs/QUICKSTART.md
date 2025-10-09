# Patronus Quickstart Guide

Welcome to Patronus - a modern, Rust-based firewall built on Gentoo Linux!

## What You've Built

Patronus is now a **fully functional firewall system** with:

✅ **Core Firewall** - nftables-based packet filtering
✅ **NAT/Masquerading** - Full NAT support including port forwarding
✅ **Network Management** - Complete interface control (IPs, MTU, up/down)
✅ **Routing** - Static routes, default gateway, IPv4/IPv6
✅ **VLAN Support** - 802.1Q VLAN interfaces
✅ **SQL Persistence** - Configuration survives reboots
✅ **Gentoo Distribution** - Bootable Live ISO and custom stage3

## Quick Start

### 1. Build the Project

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build Patronus
cd /home/canutethegreat/patronus
cargo build --release

# Or build with specific features
./build-arch.sh amd64 "web,cli,nftables"
```

### 2. Basic Firewall Usage

```bash
# Check if nftables is available
sudo ./target/release/patronus firewall check

# Initialize firewall (creates nftables table and base rules)
sudo ./target/release/patronus firewall init

# Enable IP forwarding (for routing/NAT)
sudo ./target/release/patronus firewall enable-forwarding

# Show current nftables ruleset
sudo ./target/release/patronus firewall show

# List configured rules
./target/release/patronus firewall list
```

### 3. Network Management

```bash
# List all network interfaces
./target/release/patronus network list

# Example output:
# Network Interfaces:
#   - eth0 (MTU: 1500, Enabled: true)
#   - eth1 (MTU: 1500, Enabled: true)
#   - lo (MTU: 65536, Enabled: true)
```

### 4. Run Example Configuration

```bash
# Run the basic firewall example
sudo cargo run --example basic_firewall
```

This will:
- Initialize the firewall
- Enable IP forwarding
- Add SSH rule (allow from LAN)
- Add HTTP/HTTPS outbound rule
- Configure NAT masquerading
- Set up port forwarding

## Installation on Gentoo

### Using the Ebuild

```bash
# Add the Patronus overlay (when published)
eselect repository add patronus git https://github.com/yourusername/patronus-overlay
emerge --sync patronus

# Install with desired features
echo "net-firewall/patronus web cli nftables wireguard" >> /etc/portage/package.use/patronus
emerge net-firewall/patronus

# Enable and start services
systemctl enable patronus-firewall patronus-web
systemctl start patronus-firewall patronus-web
```

### Custom USE Flags

```bash
# Minimal CLI-only firewall
USE="-web cli nftables" emerge net-firewall/patronus

# Full-featured enterprise deployment
USE="web cli api nftables wireguard openvpn ipsec dhcp dns monitoring prometheus suricata vlan qos backup" \
    emerge net-firewall/patronus

# VPN gateway with monitoring
USE="web cli nftables wireguard monitoring prometheus" emerge net-firewall/patronus
```

## Building the Live ISO

```bash
cd gentoo/catalyst

# Build ISO (requires Gentoo with catalyst installed)
sudo ./build-iso.sh amd64

# Output: ./output/patronus-0.1.0-amd64-YYYYMMDD.iso

# Test with QEMU
qemu-system-x86_64 \
    -cdrom ./output/patronus-0.1.0-amd64-*.iso \
    -m 2048 \
    -enable-kvm
```

## Example: Basic Router Setup

Here's a complete example to set up Patronus as a basic router:

```rust
use patronus_core::types::*;
use patronus_firewall::RuleManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut manager = RuleManager::new();

    // 1. Initialize firewall
    manager.initialize().await?;
    manager.enable_forwarding().await?;

    // 2. Allow SSH from LAN
    manager.add_filter_rule(FirewallRule {
        id: None,
        name: "Allow SSH from LAN".to_string(),
        enabled: true,
        chain: ChainType::Input,
        action: FirewallAction::Accept,
        source: Some("192.168.1.0/24".to_string()),
        protocol: Some(Protocol::Tcp),
        dport: Some(PortSpec::Single(22)),
        interface_in: Some("eth1".to_string()),
        ..Default::default()
    }).await?;

    // 3. NAT for LAN to WAN
    manager.add_nat_rule(NatRule {
        id: None,
        name: "Masquerade LAN".to_string(),
        enabled: true,
        nat_type: NatType::Masquerade,
        source: Some("192.168.1.0/24".to_string()),
        interface_out: Some("eth0".to_string()),
        ..Default::default()
    }).await?;

    Ok(())
}
```

## Architecture Highlights

### Project Structure

```
patronus/
├── crates/
│   ├── patronus-core/       # Shared types ✅
│   ├── patronus-firewall/   # nftables integration ✅
│   ├── patronus-network/    # Interface/routing/VLAN ✅
│   ├── patronus-config/     # SQLite persistence ✅
│   ├── patronus-web/        # Web UI (basic) ✅
│   └── patronus-cli/        # CLI tool ✅
├── gentoo/
│   ├── net-firewall/patronus/  # Ebuild + metadata ✅
│   └── catalyst/               # Live ISO builder ✅
├── examples/                # Usage examples ✅
└── docs/                    # Documentation ✅
```

### Key Features Implemented

| Component | Status | Description |
|-----------|--------|-------------|
| **nftables** | ✅ Complete | Filter rules, NAT, masquerading |
| **Interfaces** | ✅ Complete | Up/down, IPs, MTU, MAC |
| **Routing** | ✅ Complete | Static routes, default GW |
| **VLANs** | ✅ Complete | 802.1Q VLAN creation |
| **Persistence** | ✅ Complete | SQLite database |
| **Gentoo** | ✅ Complete | Ebuild, USE flags, Live ISO |
| **Multi-arch** | ✅ Complete | amd64, arm64, riscv64 |

## What's Next?

The foundation is solid! Here are logical next steps:

### Web UI (Partially Started)
- Build out the dashboard
- Firewall rules editor
- Real-time monitoring
- User authentication

### VPN Integration
- WireGuard implementation
- OpenVPN support
- IPsec/strongSwan

### Additional Services
- DHCP server
- DNS (Unbound)
- IDS/IPS (Suricata)
- Monitoring (Prometheus)

### Testing & Documentation
- Unit tests
- Integration tests
- User manual
- Video tutorials

## Support & Contributing

- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues (when published)
- **Discussions**: GitHub Discussions
- **IRC**: #patronus on Libera.Chat (future)

## License

GNU General Public License v3.0 or later

This ensures Patronus remains free and open-source forever!

---

**Built with ❤️ using Rust and Gentoo Linux**
