# Feature Comparison: Patronus vs pfSense vs OPNsense

This document provides a detailed comparison of Patronus against pfSense and OPNsense.

## Core System

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **Base OS** | FreeBSD 14.x | FreeBSD 14.x | Gentoo Linux |
| **Primary Language** | PHP | PHP | Rust |
| **Web Framework** | Custom PHP | Phalcon (PHP) | Axum (Rust) |
| **CLI** | PHP scripts | Custom | Native Rust binary |
| **License** | Apache 2.0 (CE) | BSD 2-Clause | GPL-3.0+ |
| **Commercial Version** | pfSense Plus | OPNsense Business | None (100% FOSS) |
| **Memory Safety** | No | No | Yes (Rust) |
| **Package System** | pkg | pkg | Portage |
| **Customization** | Plugin system | Plugin system | USE flags + Cargo features |

## Architecture Support

| Architecture | pfSense | OPNsense | Patronus |
|--------------|---------|----------|----------|
| x86_64 (amd64) | ✓ | ✓ | ✓ (optimized) |
| ARM64 | ✗ | Limited | ✓ (optimized) |
| RISC-V | ✗ | ✗ | ✓ (optimized) |
| 32-bit | Dropped | Dropped | Not planned |

## Firewall Features

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **Packet Filter** | pf | pf | nftables |
| **Stateful Filtering** | ✓ | ✓ | ✓ (planned) |
| **NAT/PAT** | ✓ | ✓ | ✓ (planned) |
| **Port Forwarding** | ✓ | ✓ | ✓ (planned) |
| **1:1 NAT** | ✓ | ✓ | ✓ (planned) |
| **Outbound NAT** | ✓ | ✓ | ✓ (planned) |
| **Firewall Aliases** | ✓ | ✓ | ✓ (planned) |
| **Schedules** | ✓ | ✓ | ✓ (planned) |
| **Traffic Shaping** | ALTQ | ALTQ | tc/cake/fq_codel |
| **IPv6 Support** | ✓ | ✓ | ✓ (planned) |

## VPN Support

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **WireGuard** | Package | Built-in | USE flag |
| **OpenVPN** | Built-in | Built-in | USE flag |
| **IPsec** | Built-in | Built-in | USE flag (strongSwan) |
| **L2TP** | ✓ | ✓ | Planned |
| **PPTP** | Deprecated | Deprecated | Not planned |
| **SSL VPN** | Via OpenVPN | Via OpenVPN | Planned |

## Network Services

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **DHCP Server** | ISC DHCPD | ISC DHCPD/Kea | USE flag |
| **DHCPv6** | ✓ | ✓ | Planned |
| **DNS Resolver** | Unbound | Unbound | USE flag (Unbound) |
| **DNS Forwarder** | Dnsmasq | Dnsmasq | Planned |
| **Dynamic DNS** | ✓ | ✓ | Planned |
| **VLAN** | ✓ | ✓ | USE flag |
| **Bridge** | ✓ | ✓ | Planned |
| **LAGG/LACP** | ✓ | ✓ | Planned |
| **PPPoE** | ✓ | ✓ | Planned |

## Monitoring & Logging

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **Traffic Graphs** | ✓ | ✓ | Planned |
| **Real-time Monitor** | ✓ | ✓ | Planned |
| **Syslog** | ✓ | ✓ | ✓ |
| **Remote Logging** | ✓ | ✓ | Planned |
| **NetFlow** | Via package | Via package | Planned |
| **Prometheus** | Via package | Via package | USE flag |
| **ntopng** | Package | Plugin | USE flag |
| **Packet Capture** | ✓ | ✓ | Planned |

## High Availability

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **CARP (HA)** | ✓ | ✓ | Planned (VRRP) |
| **Config Sync** | ✓ | ✓ | Planned |
| **pfsync** | ✓ | ✓ | N/A (Linux alternative) |
| **Multi-WAN** | ✓ | ✓ | Planned |
| **Load Balancing** | ✓ | ✓ | Planned |
| **Failover** | ✓ | ✓ | Planned |

## Security Features

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **IDS/IPS** | Snort/Suricata | Suricata | USE flag (Suricata) |
| **Captive Portal** | ✓ | ✓ | USE flag |
| **2FA** | Via package | Built-in | Planned |
| **RADIUS** | ✓ | ✓ | Planned |
| **LDAP** | ✓ | ✓ | Planned |
| **GeoIP Blocking** | Via package | Via package | Planned |
| **Country Blocking** | ✓ | ✓ | Planned |

## Web Interface

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **GUI Framework** | Bootstrap 3 (old) | Bootstrap 5 | Modern Rust/Axum |
| **Responsive** | Limited | ✓ | ✓ (planned) |
| **Dark Mode** | ✗ | ✓ | Planned |
| **Dashboard** | ✓ | ✓ | Planned |
| **Widgets** | ✓ | ✓ | Planned |
| **REST API** | Limited | ✓ | USE flag |
| **CLI Access** | Via PHP | Via custom | Native binary |

## Customization

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **Package Manager** | pkg (binary) | pkg (binary) | Portage (source) |
| **Custom Compilation** | ✗ | ✗ | ✓ (Gentoo) |
| **USE Flags** | ✗ | ✗ | ✓ |
| **Kernel Customization** | Limited | Limited | Full (Gentoo) |
| **Compiler Optimizations** | ✗ | ✗ | ✓ (native CPU) |
| **Plugin System** | ✓ | ✓ | Planned (Cargo crates) |

## Performance

| Metric | pfSense | OPNsense | Patronus |
|--------|---------|----------|----------|
| **Boot Time** | ~30-60s | ~30-60s | Optimizable (Gentoo) |
| **Memory Usage** | ~512MB | ~512MB | <512MB (minimal) |
| **Packet Processing** | pf (kernel) | pf (kernel) | nftables (kernel) |
| **Web UI Response** | PHP (slow) | PHP (moderate) | Rust (fast) |
| **Config Changes** | PHP processing | PHP processing | Native Rust |

## Installation & Updates

| Feature | pfSense | OPNsense | Patronus |
|---------|---------|----------|----------|
| **Live CD** | ✓ | ✓ | Planned |
| **USB Install** | ✓ | ✓ | Planned |
| **ZFS Support** | ✓ | ✓ | ✓ (planned) |
| **Auto Updates** | ✓ | ✓ | Portage sync |
| **Config Backup** | ✓ | ✓ | USE flag |
| **Cloud Deploy** | ✓ | ✓ | Planned |

## Unique Patronus Advantages

### 1. **Memory Safety**
- Rust eliminates entire classes of vulnerabilities (buffer overflows, use-after-free, etc.)
- No security bugs from memory management

### 2. **Source-Based Compilation**
- Compile with optimizations for your exact CPU
- Remove unused features entirely (smaller attack surface)
- Native performance on all architectures

### 3. **USE Flags**
- Granular control over every feature
- No bloat - only compile what you need
- Example: `USE="-web cli nftables wireguard"` for minimal CLI-only VPN gateway

### 4. **Multi-Architecture**
- First-class ARM64 support (perfect for edge devices)
- RISC-V support (future-proof)
- Same features across all architectures

### 5. **No Commercial Pressure**
- GPL-3.0+ ensures it stays free forever
- No "Plus" or "Business" versions holding features hostage
- Community-driven development

### 6. **Modern Stack**
- nftables (successor to pf/iptables)
- Axum web framework (faster than PHP)
- WireGuard native support (not a package)
- Rust async/await for efficient concurrency

## Migration Path from pfSense/OPNsense

Patronus will provide migration tools:

1. **Config Import**: Parse and convert pfSense/OPNsense XML configs
2. **Rule Translation**: Convert pf rules to nftables
3. **Feature Mapping**: Map packages to USE flags
4. **Documentation**: Step-by-step migration guide

## Feature Development Priority

### Phase 1 (MVP - Current)
- [ ] Core firewall (nftables)
- [ ] Web UI basics
- [ ] Network interface management
- [ ] Basic NAT/routing

### Phase 2 (Essential)
- [ ] VPN (WireGuard, OpenVPN)
- [ ] DHCP/DNS servers
- [ ] Traffic monitoring
- [ ] Backup/restore

### Phase 3 (Advanced)
- [ ] IDS/IPS (Suricata)
- [ ] High availability
- [ ] Multi-WAN
- [ ] Captive portal

### Phase 4 (Enterprise)
- [ ] RADIUS/LDAP
- [ ] Advanced monitoring
- [ ] Plugin ecosystem
- [ ] Migration tools

## Why Choose Patronus?

Choose Patronus if you want:

- **Security**: Memory-safe Rust implementation
- **Performance**: Native CPU optimizations, efficient Rust code
- **Customization**: Full control via USE flags and Gentoo
- **Freedom**: GPL-3.0+, no commercial restrictions
- **Modern**: Latest technologies (nftables, WireGuard, Rust)
- **Multi-arch**: ARM64 or RISC-V support

Stick with pfSense/OPNsense if you need:

- Production-ready system today (Patronus is in development)
- Commercial support contracts
- Extensive plugin ecosystem (for now)
- Proven track record in enterprise

## Contributing

Want to help achieve feature parity? See `CONTRIBUTING.md` for how to get involved.

---

**Last Updated**: 2025-10-08
**Patronus Version**: 0.1.0-dev
**pfSense Version Compared**: CE 2.7.x
**OPNsense Version Compared**: 24.x
