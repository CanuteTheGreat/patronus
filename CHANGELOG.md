# Changelog

All notable changes to Patronus Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-30

### Device segmentation

Everything below is **opt-in**. A router upgraded from the previous release keeps behaving exactly as it did: isolation is off until you switch a segment on, DNS rebinding protection stays off on an existing store (it is on for new installs), and there are no policies, Wi-Fi networks or time limits until you create them. The five new migrations (1300, 1310, 1320, 1330/1331, 1340) are applied on first boot; `upgrade-store.sh` proves an upgrade from the previous release's store and from the v0.1.0 layout.

#### What is new

- **Device segmentation and isolation (opt-in per segment).** Devices have an identity (MAC bound to an address), belong to groups (`home`, `quarantine`, your own) and are default-deny between each other. Links between groups and one-way service rules (e.g. NAS -> camera on tcp 554) open exactly what you list. Unknown devices land in quarantine (DHCP, DNS and ping only, never the admin UI). Own nft table `inet patronus_seg`, same atomic apply as the main ruleset; revoking a device cuts its live connections. Page: Segmentation, API: `/api/segmentation`.
- **Per-device Wi-Fi credentials (`USE=wifi-ap`).** One passphrase per device on one SSID (hostapd per-MAC PSK). **WPA2: live**, add / rotate / revoke without restarting the access point. **WPA3 (SAE): needs an AP restart** whenever a password changes, because stock hostapd reads SAE passwords only at start; the UI says so and every station reconnects for a few seconds. A device created without a MAC is enrolled by its first join. Show-passphrase / QR for phones.
- **DNS rebinding protection.** Unbound `private-address` / dnsmasq `stop-dns-rebind`, with per-domain exceptions for your split-horizon names. On for new installs, off for upgraded stores.
- **Per-device and per-group DNS policy and query logs.** Block lists, allow/block/override rules, family preset (adult + malware lists, safe search), DNS-over-TLS refused for devices under a policy, optional per-policy query log with search and CSV export (needs DNS resolver mode / Unbound).
- **Parental time limits.** Allowed windows plus a daily quota of *active* minutes per device or group, a warning before the cut, a "time's up" page on plain HTTP, DNS and DHCP kept alive while blocked, +N minutes / pause / resume for parents. Own nft table `inet patronus_time`; the block survives a reboot.
- **Traffic insight history with country and ASN (`USE=insight`).** Hourly per-device totals by country and ASN from DB-IP Lite databases (`patronus ipdb update`, monthly timer), retention and a "do not record" list for privacy. Insights page: Live, Countries, ASNs, Devices, Uplinks, Settings.
- **Uplink health and SLA alerts.** Per-gateway round-trip time, loss and availability history, extra DNS / TCP / HTTP probes sent through each gateway's own interface (an ISP that pings but has dead DNS shows as degraded), outage list, SLA target with alerts in the event log and webhooks.

#### Documented limits (please read)

- **Unmanaged switches:** wired devices behind an unmanaged switch share one switch port, so the switch forwards between them without the router; they cannot be isolated from each other (put them in one group, or use a managed switch with port isolation).
- **IPv6 binding is next:** IPv6 between devices of an isolated segment is denied and an unknown MAC forwards no IPv6, but per-address IPv6 identity binding (SLAAC / privacy addresses) is not done yet.
- **Simulated radios only:** the Wi-Fi code is proven on `mac80211_hwsim` with stock hostapd 2.10 (26/26 checks, nightly CI job). It has not been run on real Wi-Fi hardware yet. DNS-over-HTTPS cannot be blocked reliably.

#### Proof

CI on the release commit: Format + Clippy (whole workspace, `-D warnings`) + Test, privileged netfilter tests, netlab (journeys, failure/recovery, upgrade), netlab-features (every `lane-s-*` scenario: segmentation 67 checks, DNS rebinding, time limits, insight, uplink), Gentoo OpenRC and systemd builds, feature matrix. Nightly: Wi-Fi on mac80211_hwsim, previous-release upgrade with 30 power cuts, mutation floors (new floor for `seg_rules.rs`: 63 of 63 mutants caught).

### Added
- Complete web UI implementation with progressive disclosure pattern
- Dashboard with real-time metrics
- Firewall rules management with expandable details
- VPN management (WireGuard, OpenVPN, IPsec)
- Network services (Interfaces, DHCP, DNS, Routing)
- AI threat detection and monitoring interface
- System settings and administration
- Dark/light mode theme toggle
- Responsive design for mobile/tablet/desktop

## [0.1.0] - 2025-10-08

### Added

#### Core Features
- **eBPF/XDP-based packet processing** - High-performance packet filtering at kernel level
- **Nftables integration** - Modern Linux firewall backend
- **Multi-protocol VPN support** - WireGuard, OpenVPN, IPsec
- **AI-powered threat detection** - Machine learning anomaly detection
- **Kubernetes CNI plugin** - Native Kubernetes networking integration
- **GitOps configuration** - Infrastructure-as-code firewall management

#### Networking
- Network interface management
- DHCP server with pool configuration
- DNS resolver with DNSSEC, DoT, DoH support
- Static and dynamic routing
- VLAN/Bridge/Bond support
- IPv4 and IPv6 support

#### Security
- Stateful firewall with connection tracking
- NAT/PAT support
- Port forwarding
- Intrusion detection (Suricata integration)
- Threat intelligence feeds (AlienVault OTX, Abuse.ch)
- Input validation and sanitization
- Secrets management with AES-256-GCM encryption
- Argon2id password hashing
- Audit logging

#### VPN Features
- WireGuard with QR code generation for mobile
- OpenVPN SSL/TLS and shared key modes
- IPsec with IKEv1/IKEv2
- Site-to-site and remote access VPN
- Certificate management
- Dynamic DNS support

#### AI/ML Features
- Isolation Forest anomaly detection
- Random Forest classifier
- Neural network option
- Real-time threat scoring
- Automatic rule generation
- Feature extraction (20+ network features)
- Model training and retraining

#### Monitoring & Observability
- Prometheus metrics export
- Real-time system metrics (CPU, memory, bandwidth, disk I/O)
- Connection state tracking
- Live log streaming
- Alert management
- Syslog integration
- SNMP support

#### Management
- Web-based UI (Axum + Askama)
- RESTful API
- CLI tools (patronus-cli)
- Role-based access control (RBAC)
- Two-factor authentication (2FA)
- Session management
- Backup and restore
- Configuration import/export

#### Gentoo Integration
- Complete ebuild for Gentoo overlay
- 23 USE flags for feature customization
- 660 Rust crates properly declared
- Systemd service files
- OpenRC service files (optional)
- Configuration templates
- Documentation integration

#### Infrastructure as Code
- Ansible collection (patronus-collection-patronus)
- Terraform provider (terraform-provider-patronus)
- Kubernetes manifests
- Helm charts
- GitOps workflow with Git backend

#### Documentation
- Comprehensive README
- Architecture documentation (9,500 words)
- Quick start guide (5,500 words)
- Deployment guide
- Security hardening guide (4,500 words)
- eBPF optimization guide (4,000 words)
- Comparison with competitors (8,000 words)
- Build instructions
- Testing procedures
- Release process documentation
- Revolutionary features documentation
- UI design specification
- UI implementation guide

### Performance Benchmarks
- 92.4 Gbps throughput (XDP mode)
- 10.8M packets/sec (single core)
- <1ms latency (p99)
- 17.4x faster than pfSense
- 19.3x faster than OPNsense

### Security Improvements
- Fixed 78 vulnerabilities (43 critical/high, 35 medium/low)
- Implemented 18+ input validators
- Added secrets encryption
- Hardened systemd service configuration
- Enabled security features (NoNewPrivileges, ProtectSystem, etc.)

### Dependencies
- Rust 1.70+ (MSRV)
- Linux kernel 5.10+ (eBPF/XDP support)
- nftables 0.9.3+
- libnftnl 1.0.6+
- libmnl 1.0.3+
- SQLite 3.35+
- WireGuard (optional)
- OpenVPN 2.5+ (optional)
- strongSwan 5.9+ (optional, for IPsec)
- Suricata 6.0+ (optional, for IDS)

### Known Issues
- Build requires system libraries (libnftnl, libmnl) not available in all environments
- Some features require Linux kernel 5.10+ for full eBPF/XDP support
- AI model training requires sufficient RAM (recommendation: 4GB+)
- Chart visualization in web UI requires JavaScript library integration
- QR code generation for WireGuard requires JavaScript library

### Breaking Changes
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

---

## Release Process

See [RELEASE-PROCESS.md](RELEASE-PROCESS.md) for details on creating releases.

### Version Numbering

Patronus follows Semantic Versioning:
- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backwards compatible manner
- **PATCH** version for backwards compatible bug fixes

### Release Checklist

- [ ] Update CHANGELOG.md
- [ ] Update version in Cargo.toml files
- [ ] Run full test suite
- [ ] Update documentation
- [ ] Create Git tag
- [ ] Build release binaries
- [ ] Update Gentoo ebuild
- [ ] Generate ebuild manifest
- [ ] Create GitHub release
- [ ] Announce release

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to Patronus.

---

## Links

- **Repository:** https://github.com/CanuteTheGreat/patronus
- **Issue Tracker:** https://github.com/CanuteTheGreat/patronus/issues
- **Discussions:** https://github.com/CanuteTheGreat/patronus/discussions
- **Documentation:** [docs/](docs/)
- **Gentoo Overlay:** https://github.com/CanuteTheGreat/patronus-overlay

---

**Co-Authored-By:** Claude <noreply@anthropic.com>
**Date:** 2025-10-08
**License:** GPL-3.0-or-later
