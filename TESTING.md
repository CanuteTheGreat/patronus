# Patronus Firewall Testing Guide

Comprehensive testing documentation for Patronus Firewall.

---

## Table of Contents

1. [Testing Strategy](#testing-strategy)
2. [Unit Testing](#unit-testing)
3. [Integration Testing](#integration-testing)
4. [Gentoo Ebuild Testing](#gentoo-ebuild-testing)
5. [Performance Testing](#performance-testing)
6. [Security Testing](#security-testing)
7. [Manual Testing](#manual-testing)
8. [CI/CD Testing](#cicd-testing)

---

## Testing Strategy

Patronus employs a multi-layered testing approach:

- **Unit Tests**: Test individual functions and modules
- **Integration Tests**: Test component interactions
- **System Tests**: Test complete functionality
- **Performance Tests**: Verify throughput and latency targets
- **Security Tests**: Vulnerability scanning and penetration testing
- **Ebuild Tests**: Verify Gentoo package builds correctly

---

## Unit Testing

### Running Unit Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p patronus-firewall
cargo test -p patronus-network
cargo test -p patronus-ai

# Run with specific features
cargo test --features "nftables,vpn-wireguard"

# Run all tests with all features
cargo test --workspace --all-features

# Show test output
cargo test -- --nocapture

# Run specific test
cargo test test_firewall_rule_parsing
```

### Writing Unit Tests

Place tests in the same file as the code being tested:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_validation() {
        let rule = FirewallRule {
            action: Action::Allow,
            interface: "lan".to_string(),
            protocol: Protocol::TCP,
            destination_port: Some(80),
        };

        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_invalid_rule() {
        let rule = FirewallRule {
            action: Action::Allow,
            interface: "".to_string(),  // Invalid
            protocol: Protocol::TCP,
            destination_port: None,
        };

        assert!(rule.validate().is_err());
    }
}
```

### Test Coverage

Generate coverage report:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --workspace --all-features --out Html

# Open report
firefox tarpaulin-report.html
```

**Coverage Goals:**
- Core modules: >80%
- Critical paths (firewall, VPN): >90%
- Overall project: >70%

---

## Integration Testing

### Integration Test Structure

Place integration tests in `tests/` directory:

```
tests/
├── firewall_integration.rs
├── vpn_integration.rs
├── gitops_integration.rs
└── common/
    └── mod.rs
```

### Example Integration Test

```rust
// tests/firewall_integration.rs
use patronus_firewall::{FirewallManager, Rule};
use patronus_network::InterfaceManager;

#[tokio::test]
async fn test_firewall_rule_application() {
    let manager = FirewallManager::new().await.unwrap();

    let rule = Rule::new()
        .interface("lan")
        .action("allow")
        .protocol("tcp")
        .port(80)
        .build();

    // Apply rule
    manager.add_rule(rule).await.unwrap();

    // Verify rule is active
    let rules = manager.list_rules().await.unwrap();
    assert_eq!(rules.len(), 1);

    // Cleanup
    manager.clear_rules().await.unwrap();
}
```

### Running Integration Tests

```bash
# Run all integration tests
cargo test --test '*'

# Run specific integration test
cargo test --test firewall_integration

# Run with logging
RUST_LOG=debug cargo test --test firewall_integration -- --nocapture
```

---

## Gentoo Ebuild Testing

### Prerequisites

- Gentoo Linux system (VM or physical)
- Overlay added to system
- Network access for downloading dependencies

### Ebuild Verification

```bash
# Step 1: Verify ebuild syntax
cd /var/db/repos/patronus
./verify-ebuild.sh

# Expected output: "✓ All USE flags properly configured!"
```

### Manifest Generation

```bash
# Generate Manifest file
ebuild net-firewall/patronus/patronus-0.1.0.ebuild manifest

# Expected: No errors, Manifest file created
```

### Test Builds

#### Minimal Build

```bash
USE="cli nftables" emerge -av net-firewall/patronus
```

**Expected:**
- ✅ Build completes successfully
- ✅ Binary installed: `/usr/bin/patronus-cli`
- ✅ Symlink created: `/usr/bin/patronus`
- ✅ Service file: `/usr/lib/systemd/system/patronus-firewall.service`

#### Standard Build

```bash
USE="web cli nftables vpn-wireguard dhcp dns monitoring" emerge -av net-firewall/patronus
```

**Expected:**
- ✅ All minimal build items
- ✅ Binary installed: `/usr/bin/patronus-web`
- ✅ Web service: `/usr/lib/systemd/system/patronus-web.service`
- ✅ Config example: `/etc/patronus/patronus.toml.example`

#### Maximum Features Build

```bash
USE="web cli api nftables iptables dhcp dns dns-unbound \
     vpn-wireguard vpn-openvpn vpn-ipsec \
     monitoring monitoring-prometheus monitoring-ntopng \
     captive-portal ids-suricata vlan qos backup \
     gitops ai kubernetes arch-native" \
  emerge -av net-firewall/patronus
```

**Expected:**
- ✅ All standard build items
- ✅ Binary installed: `/opt/cni/bin/patronus-cni` (kubernetes feature)
- ✅ All dependencies satisfied
- ✅ Build completes in <30 minutes (on modern hardware)

### USE Flag Constraint Testing

Test REQUIRED_USE constraints:

```bash
# Should FAIL: No interface
USE="-web -cli nftables" emerge -pv net-firewall/patronus
# Expected error: "At least one of web or cli required"

# Should FAIL: No firewall backend
USE="web cli -nftables -iptables" emerge -pv net-firewall/patronus
# Expected error: "At least one of nftables or iptables required"

# Should FAIL: dns-unbound without dns
USE="web cli nftables dns-unbound -dns" emerge -pv net-firewall/patronus
# Expected error: "dns-unbound requires dns"
```

### Post-Installation Testing

```bash
# Verify binaries
which patronus
which patronus-cli
which patronus-web  # if USE=web

# Test binary execution
patronus --version
patronus-cli --help

# Verify services
systemctl status patronus-firewall
systemctl status patronus-web  # if USE=web

# Verify configuration
ls -l /etc/patronus/
cat /etc/patronus/patronus.toml.example

# Verify directories
ls -ld /var/lib/patronus
ls -ld /var/log/patronus
ls -ld /etc/patronus/secrets.d
```

---

## Performance Testing

### Using patronus-bench

```bash
# Build benchmark suite
cargo build --release -p patronus-bench

# Run all benchmarks
./target/release/patronus-bench all --output report.html

# Run specific benchmarks
./target/release/patronus-bench throughput --duration 60
./target/release/patronus-bench latency --count 100000
./target/release/patronus-bench connection-rate --duration 30
```

### Throughput Testing

```bash
# Test packet forwarding throughput
./target/release/patronus-bench throughput \
  --packet-size 1500 \
  --duration 60 \
  --interfaces eth0,eth1
```

**Expected Results:**
- Software (nftables): 10-15 Gbps
- XDP Generic: 20-30 Gbps
- XDP Native: 40-100 Gbps (hardware dependent)

### Latency Testing

```bash
# Test firewall rule processing latency
./target/release/patronus-bench latency \
  --count 100000 \
  --rules 1000
```

**Expected Results:**
- Mean latency: <100 μs
- P95 latency: <150 μs
- P99 latency: <200 μs

### Connection Rate Testing

```bash
# Test new connection handling rate
./target/release/patronus-bench connection-rate \
  --duration 60 \
  --target 100000
```

**Expected Results:**
- Connection rate: >100,000 connections/sec
- No dropped connections
- Memory usage remains stable

### VPN Performance Testing

```bash
# WireGuard throughput
./target/release/patronus-bench vpn-throughput \
  --vpn wireguard \
  --duration 60
```

**Expected Results:**
- WireGuard: 9.2 Gbps
- OpenVPN: 650 Mbps
- IPsec: 4.5 Gbps

---

## Security Testing

### Dependency Vulnerability Scanning

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit

# Expected: No known vulnerabilities
```

### Static Analysis

```bash
# Run clippy
cargo clippy --all-features -- -D warnings

# Expected: No warnings
```

### Secrets Security Testing

```bash
# Test secrets encryption
patronus secrets init
patronus secrets set test_secret

# Verify encrypted storage
ls -l /etc/patronus/secrets.d/
file /etc/patronus/secrets.d/*

# Verify no plaintext secrets
grep -r "password" /etc/patronus/secrets.d/
# Expected: Binary file (no plaintext)
```

### Input Validation Testing

Test against injection attacks:

```bash
# SQL Injection attempt (should fail)
patronus firewall add-rule --description "'; DROP TABLE rules; --"

# Command Injection attempt (should fail)
patronus interface add --name "eth0 && rm -rf /"

# Path Traversal attempt (should fail)
patronus backup restore --file "../../etc/passwd"
```

**Expected:** All attempts rejected with validation errors.

### Network Security Testing

```bash
# Port scanning (should only show configured ports)
nmap -sS localhost

# TLS testing
testssl localhost:443
# Expected: A+ rating

# Authentication testing
curl -k https://localhost/api/status
# Expected: 401 Unauthorized (without auth)
```

---

## Manual Testing

### Basic Functionality Testing

#### 1. Initial Setup

```bash
# Install
emerge -av net-firewall/patronus

# Configure
cp /etc/patronus/patronus.toml.example /etc/patronus/patronus.toml
nano /etc/patronus/patronus.toml

# Initialize
patronus secrets init

# Start services
systemctl start patronus-firewall
systemctl start patronus-web
```

#### 2. Web Interface Testing

1. Open browser: `https://localhost:443`
2. Login (default: admin/patronus)
3. **Immediately change password!**
4. Navigate all menu items
5. Verify dashboard displays correctly

#### 3. Firewall Rule Testing

```bash
# Add allow rule
patronus firewall add-rule \
  --interface lan \
  --protocol tcp \
  --port 22 \
  --action allow \
  --description "SSH access"

# List rules
patronus firewall list-rules

# Test rule (from LAN)
ssh user@firewall-ip
# Expected: Connection succeeds

# Add block rule
patronus firewall add-rule \
  --interface wan \
  --protocol tcp \
  --port 23 \
  --action block \
  --description "Block telnet"

# Test rule (from WAN)
telnet firewall-wan-ip 23
# Expected: Connection blocked
```

#### 4. DHCP Server Testing

```bash
# Configure DHCP
patronus dhcp add-pool \
  --interface lan \
  --range-start 192.168.1.100 \
  --range-end 192.168.1.200 \
  --gateway 192.168.1.1

# Release DHCP on client
sudo dhclient -r eth0

# Request new lease
sudo dhclient eth0

# Verify lease on firewall
patronus dhcp list-leases
```

#### 5. DNS Server Testing

```bash
# Test DNS resolution
dig @192.168.1.1 google.com

# Expected: ANSWER section with IP

# Test DNS caching
dig @192.168.1.1 google.com
# Should be faster on second query
```

#### 6. VPN Testing (WireGuard)

```bash
# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# Add peer
patronus vpn wireguard add-peer \
  --interface wg0 \
  --public-key "$(cat publickey)" \
  --allowed-ips 10.99.0.2/32

# Start VPN on client
wg-quick up wg0

# Test connectivity
ping 10.99.0.1
# Expected: Replies from firewall
```

### GitOps Testing (if enabled)

```bash
# Configure Git repository
patronus gitops init \
  --repo https://github.com/yourorg/patronus-config \
  --branch main

# Create firewall rule in Git
cat > firewall/allow-http.yaml <<EOF
apiVersion: patronus.dev/v1
kind: FirewallRule
metadata:
  name: allow-http
spec:
  interface: wan
  protocol: tcp
  destinationPort: 80
  action: allow
EOF

# Commit and push
git add firewall/allow-http.yaml
git commit -m "Allow HTTP"
git push

# Wait for sync (or trigger webhook)
# Verify rule applied
patronus firewall list-rules | grep allow-http
```

### AI Threat Detection Testing (if enabled)

```bash
# Enable AI
patronus ai enable

# Generate sample traffic
for i in {1..1000}; do
  curl http://firewall-ip
done

# View threats
patronus ai threats list

# Test blocking
patronus ai set-action block

# Verify threats are blocked
patronus firewall list-rules | grep "AI-"
```

---

## CI/CD Testing

### GitHub Actions Workflow

Create `.github/workflows/test.yml`:

```yaml
name: Test Patronus

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true

    - name: Run tests
      run: cargo test --workspace --all-features

    - name: Run clippy
      run: cargo clippy --all-features -- -D warnings

    - name: Security audit
      run: |
        cargo install cargo-audit
        cargo audit

    - name: Build
      run: cargo build --release --all-features
```

### Local CI Testing

```bash
# Install act (GitHub Actions locally)
# https://github.com/nektos/act

# Run CI locally
act push
```

---

## Regression Testing

When fixing bugs, add regression tests:

```rust
#[test]
fn test_issue_123_firewall_rule_ordering() {
    // This test ensures issue #123 doesn't regress
    // Bug: Rules were applied in wrong order

    let manager = FirewallManager::new();

    // Add rules in specific order
    manager.add_rule(rule1);
    manager.add_rule(rule2);

    // Verify order is preserved
    let rules = manager.list_rules();
    assert_eq!(rules[0].priority, 1);
    assert_eq!(rules[1].priority, 2);
}
```

---

## Test Environments

### Development Environment

- **Platform**: Any Linux
- **Purpose**: Quick iteration, unit tests
- **Setup**: `cargo test`

### Staging Environment

- **Platform**: Gentoo VM
- **Purpose**: Integration tests, ebuild testing
- **Setup**: Full Gentoo install with overlay

### Production-Like Environment

- **Platform**: Dedicated hardware
- **Purpose**: Performance testing, security testing
- **Setup**: Bare metal Gentoo, production configuration

---

## Troubleshooting Tests

### Tests Fail to Compile

```bash
# Clean and rebuild
cargo clean
cargo test

# Check for missing dependencies
cargo tree
```

### Tests Timeout

```bash
# Increase timeout
cargo test -- --test-threads=1 --nocapture

# Or set environment variable
RUST_TEST_THREADS=1 cargo test
```

### Integration Tests Fail

```bash
# Check if services are running
systemctl status patronus-firewall

# Check logs
journalctl -u patronus-firewall -f

# Check permissions
ls -l /var/lib/patronus
```

---

## Test Reporting

### Generate Test Report

```bash
# Install cargo-nextest
cargo install cargo-nextest

# Run tests with report
cargo nextest run --workspace --all-features

# Generate JUnit XML
cargo nextest run --workspace --junit report.xml
```

### Continuous Monitoring

Set up automated testing:
- Run tests on every commit (GitHub Actions)
- Run performance benchmarks nightly
- Run security scans weekly
- Monitor test coverage trends

---

## Test Checklist

Before releasing a new version:

- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Ebuild builds with all USE flag combinations
- [ ] Performance benchmarks meet targets
- [ ] Security audit passes (no critical/high vulnerabilities)
- [ ] Manual smoke tests complete
- [ ] Documentation updated
- [ ] CHANGELOG updated

---

**Last Updated:** 2025-10-08
**Version:** 0.1.0
