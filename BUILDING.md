# Building Patronus Firewall

Complete build instructions for Patronus on Gentoo Linux.

---

## Prerequisites

### Gentoo System Requirements

```bash
# Install Rust toolchain
emerge -av dev-lang/rust dev-util/cargo

# Install build dependencies
emerge -av dev-db/sqlite dev-util/pkgconf sys-devel/clang

# Install eBPF development tools (optional, for ebpf feature)
emerge -av sys-devel/llvm sys-kernel/linux-headers
```

---

## Building from Source

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/patronus.git
cd patronus
```

### 2. Build with Default Features

Default features: `web`, `cli`, `nftables`, `dhcp`, `dns`, `monitoring`

```bash
cargo build --release
```

**Binaries created:**
- `target/release/patronus-cli` - Command-line interface
- `target/release/patronus-web` - Web interface server

### 3. Build with Specific Features

#### Minimal CLI-only Build

```bash
cargo build --release \
  --no-default-features \
  --features "cli,nftables"
```

**Binary:** `target/release/patronus-cli`

#### Full-Featured Build (All Features)

```bash
cargo build --release \
  --features "web,cli,api,nftables,iptables,\
dhcp-server,dns-server,dns-unbound,\
vpn-wireguard,vpn-openvpn,vpn-ipsec,\
monitoring,monitoring-prometheus,monitoring-ntopng,\
captive-portal,ids-suricata,vlan,qos,backup,\
gitops,ai,kubernetes"
```

**Binaries created:**
- `target/release/patronus-cli`
- `target/release/patronus-web`
- `target/release/patronus-cni` (when `kubernetes` feature enabled)

#### GitOps-Enabled Build

```bash
cargo build --release \
  --features "cli,nftables,gitops"
```

Enables Infrastructure as Code workflows with Git repository synchronization.

#### Kubernetes CNI Build

```bash
cargo build --release \
  --features "cli,nftables,kubernetes"
```

Creates `/opt/cni/bin/patronus-cni` binary for Kubernetes integration.

#### AI Threat Detection Build

```bash
cargo build --release \
  --features "cli,nftables,monitoring,ai"
```

Enables machine learning-based anomaly detection.

### 4. Architecture-Specific Optimization

For maximum performance on your CPU:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --all-features
```

**Performance gain:** 5-15% throughput improvement
**Warning:** Binary only works on CPUs with similar instruction sets

---

## Building via Gentoo Ebuild

### 1. Add Patronus Overlay

```bash
# Using eselect repository
eselect repository add patronus git https://github.com/yourusername/patronus-overlay
emaint sync -r patronus

# Or manually
mkdir -p /var/db/repos/patronus
git clone https://github.com/yourusername/patronus-overlay /var/db/repos/patronus
```

### 2. Configure USE Flags

Edit `/etc/portage/package.use/patronus`:

#### Minimal Installation
```bash
echo "net-firewall/patronus cli nftables" >> /etc/portage/package.use/patronus
```

#### Standard Home Router
```bash
echo "net-firewall/patronus web cli nftables vpn-wireguard dhcp dns monitoring" >> /etc/portage/package.use/patronus
```

#### Enterprise Gateway
```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus web cli api nftables
  vpn-wireguard vpn-openvpn vpn-ipsec
  dhcp dns dns-unbound
  monitoring monitoring-prometheus
  captive-portal vlan qos backup
  arch-native
EOF
```

#### Cloud-Native Kubernetes Gateway
```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus web cli api nftables
  vpn-wireguard monitoring monitoring-prometheus
  kubernetes gitops ai arch-native
EOF
```

#### Maximum Features (All)
```bash
cat >> /etc/portage/package.use/patronus <<EOF
net-firewall/patronus web cli api nftables iptables
  dhcp dns dns-unbound
  vpn-wireguard vpn-openvpn vpn-ipsec
  monitoring monitoring-prometheus monitoring-ntopng
  captive-portal ids-suricata vlan qos backup
  gitops ai kubernetes arch-native
EOF
```

### 3. Install Package

```bash
# Preview installation
emerge -pv net-firewall/patronus

# Install
emerge -av net-firewall/patronus
```

### 4. Post-Installation

```bash
# Copy example configuration
cp /etc/patronus/patronus.toml.example /etc/patronus/patronus.toml

# Edit configuration
nano /etc/patronus/patronus.toml

# Initialize secrets encryption
patronus secrets init

# Enable and start services
systemctl enable --now patronus-firewall

# If web interface enabled
systemctl enable --now patronus-web
```

---

## Feature Flag to Cargo Feature Mapping

| USE Flag | Cargo Feature | Description |
|----------|---------------|-------------|
| `web` | `web` | Web management interface |
| `cli` | `cli` | Command-line interface |
| `api` | `api` | REST API endpoints |
| `nftables` | `nftables` | nftables backend |
| `iptables` | `iptables` | iptables backend |
| `dhcp` | `dhcp-server` | DHCP server |
| `dns` | `dns-server` | DNS resolver |
| `dns-unbound` | `dns-unbound` | Unbound DNS integration |
| `vpn-wireguard` | `vpn-wireguard` | WireGuard VPN |
| `vpn-openvpn` | `vpn-openvpn` | OpenVPN |
| `vpn-ipsec` | `vpn-ipsec` | IPsec VPN |
| `monitoring` | `monitoring` | Metrics collection |
| `monitoring-prometheus` | `monitoring-prometheus` | Prometheus exporter |
| `monitoring-ntopng` | `monitoring-ntopng` | ntopng DPI integration |
| `captive-portal` | `captive-portal` | Guest network portal |
| `ids-suricata` | `ids-suricata` | Suricata IDS/IPS |
| `vlan` | `vlan` | VLAN support |
| `qos` | `qos` | Traffic shaping |
| `backup` | `backup` | Config backup/restore |
| `gitops` | `gitops` | GitOps workflows |
| `ai` | `ai` | AI threat detection |
| `kubernetes` | `kubernetes` | Kubernetes CNI plugin |
| `arch-native` | *(RUSTFLAGS)* | CPU-specific optimization |

---

## Building Individual Crates

### Core Library
```bash
cd crates/patronus-core
cargo build --release
```

### CLI Binary
```bash
cd crates/patronus-cli
cargo build --release --features "cli,nftables"
```

### Web Interface
```bash
cd crates/patronus-web
cargo build --release
```

### Kubernetes CNI Plugin
```bash
cd crates/patronus-cni
cargo build --release
```

### Benchmarking Suite
```bash
cd crates/patronus-bench
cargo build --release
```

---

## Testing

### Run All Tests
```bash
cargo test --workspace
```

### Run Tests with All Features
```bash
cargo test --workspace --all-features
```

### Run Tests for Specific Crate
```bash
cargo test -p patronus-firewall
cargo test -p patronus-gitops
cargo test -p patronus-ai
```

### Run Benchmarks
```bash
cd crates/patronus-bench
cargo run --release -- throughput --duration 60
cargo run --release -- latency --count 10000
cargo run --release -- all --output report.html
```

---

## Binary Locations After Installation

| Binary | Location | Created When |
|--------|----------|--------------|
| `patronus-cli` | `/usr/bin/patronus-cli` | `cli` USE flag |
| `patronus` (symlink) | `/usr/bin/patronus` | `cli` USE flag |
| `patronus-web` | `/usr/bin/patronus-web` | `web` USE flag |
| `patronus-cni` | `/opt/cni/bin/patronus-cni` | `kubernetes` USE flag |

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/patronus/patronus.toml` | Main configuration |
| `/etc/patronus/firewall.d/*.yaml` | Firewall rules (GitOps) |
| `/etc/patronus/secrets.d/*.enc` | Encrypted secrets |
| `/etc/patronus/dhcp.conf` | DHCP server config |
| `/etc/patronus/dns.conf` | DNS resolver config |

---

## Systemd Services

| Service | Description | Enabled When |
|---------|-------------|--------------|
| `patronus-firewall.service` | Core firewall daemon | Always |
| `patronus-web.service` | Web interface | `web` USE flag |

---

## Troubleshooting

### Build Errors

**Error:** `failed to compile patronus-ebpf`
```bash
# Install LLVM/Clang for eBPF compilation
emerge -av sys-devel/llvm sys-devel/clang
```

**Error:** `cannot find -lsqlite3`
```bash
# Install SQLite development files
emerge -av dev-db/sqlite
```

**Error:** `pkg-config not found`
```bash
# Install pkg-config
emerge -av dev-util/pkgconf
```

### Feature Dependency Issues

**Error:** `feature 'dns-unbound' requires 'dns'`

This is enforced by `REQUIRED_USE` in the ebuild. Enable both:
```bash
echo "net-firewall/patronus dns dns-unbound" >> /etc/portage/package.use/patronus
```

**Error:** `must enable at least one of: web, cli`

Enable at least one interface:
```bash
echo "net-firewall/patronus cli" >> /etc/portage/package.use/patronus
```

---

## Performance Tuning

### eBPF/XDP Optimization

For maximum performance (40-100 Gbps):

1. Enable architecture-native optimization:
   ```bash
   echo "net-firewall/patronus arch-native" >> /etc/portage/package.use/patronus
   ```

2. Configure XDP mode:
   ```bash
   # In /etc/patronus/patronus.toml
   [ebpf]
   xdp_mode = "native"  # or "generic" for compatibility
   ```

3. See `/usr/share/doc/patronus-*/EBPF-OPTIMIZATION.md` for detailed tuning.

### Build Parallelism

Speed up compilation:
```bash
# In /etc/portage/make.conf
MAKEOPTS="-j$(nproc)"
CARGO_BUILD_JOBS=$(nproc)
```

---

## Cross-Compilation

### For ARM64 (aarch64)
```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

### For RISC-V (riscv64gc)
```bash
rustup target add riscv64gc-unknown-linux-gnu
cargo build --release --target riscv64gc-unknown-linux-gnu
```

---

## Clean Build

```bash
# Clean build artifacts
cargo clean

# Clean and rebuild
cargo clean && cargo build --release
```

---

## Development Build

For faster iteration during development:

```bash
# Debug build (faster compilation, slower runtime)
cargo build

# Check without building
cargo check

# Run with logging
RUST_LOG=debug cargo run --bin patronus-cli -- --help
```

---

**Last Updated:** 2025-10-08
**Patronus Version:** 0.1.0
