# Sprint 32: Real Network Probing - Planning Document

**Sprint**: 32
**Focus**: Real Network Probing
**Duration**: 3-5 days
**Status**: Planning
**Dependencies**: Sprint 31 (Complete)

---

## Executive Summary

Sprint 32 will replace the simulated network probing in Sprint 31 with real ICMP and UDP probing capabilities. This completes the production readiness of the health monitoring and failover systems by enabling actual network path quality measurements.

**Current State**: Sprint 31 delivered a complete health monitoring system with simulated probes for testing purposes.

**Goal**: Implement real ICMP Echo (ping) and UDP probing to measure actual network path latency, packet loss, and jitter.

**Success Criteria**:
- Real ICMP probing functional with proper permissions
- Real UDP probing as fallback mechanism
- Automatic probe type selection and fallback
- All existing Sprint 31 tests continue to pass
- New integration tests with real network probing
- Production deployment ready

---

## Background

### Current Implementation (Sprint 31)

The health monitoring system in `crates/patronus-sdwan/src/health/probe.rs` currently uses simulated probing:

```rust
pub enum ProbeType {
    Icmp,
    Udp,
    Simulated, // Currently used for testing
}

impl ProbeExecutor {
    async fn execute_probe(&self, target: IpAddr, probe_type: ProbeType) -> ProbeResult {
        match probe_type {
            ProbeType::Simulated => {
                // Returns fixed/random values for testing
                tokio::time::sleep(Duration::from_millis(20)).await;
                ProbeResult {
                    success: true,
                    latency_ms: 25.0 + (rand() % 10) as f64,
                    timestamp: SystemTime::now(),
                }
            }
            ProbeType::Icmp => todo!("Real ICMP implementation"),
            ProbeType::Udp => todo!("Real UDP implementation"),
        }
    }
}
```

### Requirements for Real Probing

**ICMP Echo (Ping)**:
- Requires raw sockets (`CAP_NET_RAW` capability on Linux)
- Most accurate for network reachability
- Standard ICMP Echo Request/Reply (Type 8/Type 0)
- Sequence numbers for packet matching
- RTT calculation from send/receive timestamps

**UDP Probing**:
- No special privileges required
- Works in restricted environments
- Can use ephemeral ports
- Detects reachability via ICMP Port Unreachable or application response
- Measures RTT if target responds

---

## Technical Design

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Health Monitor                            │
│  (existing, no changes to public API)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Probe Executor                              │
│  - Probe type selection (ICMP → UDP → Simulated)           │
│  - Capability detection                                      │
│  - Automatic fallback                                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌──────────┐  ┌──────────┐  ┌──────────────┐
│   ICMP   │  │   UDP    │  │  Simulated   │
│  Prober  │  │  Prober  │  │   (testing)  │
└──────────┘  └──────────┘  └──────────────┘
```

### Component Design

#### 1. ICMP Prober (`health/icmp_probe.rs`)

```rust
pub struct IcmpProber {
    socket: Arc<Socket>,
    identifier: u16, // Process ID
    sequence: AtomicU16,
}

impl IcmpProber {
    /// Create ICMP prober (requires CAP_NET_RAW)
    pub fn new() -> Result<Self, ProbeError> {
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::ICMPV4),
        )?;

        socket.set_read_timeout(Some(Duration::from_secs(2)))?;

        Ok(Self {
            socket: Arc::new(socket),
            identifier: process::id() as u16,
            sequence: AtomicU16::new(0),
        })
    }

    /// Send ICMP Echo Request and wait for reply
    pub async fn probe(&self, target: IpAddr) -> Result<ProbeResult, ProbeError> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        // Build ICMP Echo Request
        let packet = self.build_echo_request(seq);

        // Send packet
        let send_time = Instant::now();
        self.socket.send_to(&packet, &target.into())?;

        // Wait for reply
        let reply = self.recv_echo_reply(seq, timeout).await?;
        let recv_time = Instant::now();

        let latency = recv_time.duration_since(send_time);

        Ok(ProbeResult {
            success: true,
            latency_ms: latency.as_secs_f64() * 1000.0,
            timestamp: SystemTime::now(),
        })
    }

    fn build_echo_request(&self, seq: u16) -> Vec<u8> {
        // ICMP Echo Request packet structure
        let mut packet = vec![0u8; 64];
        packet[0] = 8;  // Type: Echo Request
        packet[1] = 0;  // Code: 0
        // [2-3] Checksum (calculated later)
        packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());

        // Payload (timestamp for RTT verification)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        packet[8..16].copy_from_slice(&timestamp.to_be_bytes());

        // Calculate checksum
        let checksum = self.calculate_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }

    async fn recv_echo_reply(&self, expected_seq: u16, timeout: Duration) -> Result<Vec<u8>, ProbeError> {
        let mut buf = vec![0u8; 1024];

        let deadline = Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProbeError::Timeout);
            }

            // Receive packet
            let len = self.socket.recv(&mut buf)?;

            // Parse IP header (skip to ICMP)
            let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
            let icmp_packet = &buf[ip_header_len..len];

            // Verify ICMP Echo Reply
            if icmp_packet[0] != 0 {  // Type: Echo Reply
                continue;
            }

            // Verify identifier and sequence
            let id = u16::from_be_bytes([icmp_packet[4], icmp_packet[5]]);
            let seq = u16::from_be_bytes([icmp_packet[6], icmp_packet[7]]);

            if id == self.identifier && seq == expected_seq {
                return Ok(icmp_packet.to_vec());
            }
        }
    }

    fn calculate_checksum(&self, data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for chunk in data.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}
```

#### 2. UDP Prober (`health/udp_probe.rs`)

```rust
pub struct UdpProber {
    socket: UdpSocket,
    port: u16,
}

impl UdpProber {
    /// Create UDP prober (no special privileges required)
    pub async fn new() -> Result<Self, ProbeError> {
        // Bind to ephemeral port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let port = socket.local_addr()?.port();

        socket.set_read_timeout(Some(Duration::from_secs(2)))?;

        Ok(Self { socket, port })
    }

    /// Send UDP probe and measure RTT
    pub async fn probe(&self, target: IpAddr, port: u16) -> Result<ProbeResult, ProbeError> {
        // Probe packet (simple payload)
        let probe_data = b"PATRONUS_PROBE";

        let send_time = Instant::now();

        // Send probe
        self.socket.send_to(probe_data, (target, port)).await?;

        // Wait for response or ICMP error
        match tokio::time::timeout(Duration::from_secs(2), self.recv_response()).await {
            Ok(Ok(_)) => {
                let recv_time = Instant::now();
                let latency = recv_time.duration_since(send_time);

                Ok(ProbeResult {
                    success: true,
                    latency_ms: latency.as_secs_f64() * 1000.0,
                    timestamp: SystemTime::now(),
                })
            }
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                // ICMP Port Unreachable = host is reachable
                let recv_time = Instant::now();
                let latency = recv_time.duration_since(send_time);

                Ok(ProbeResult {
                    success: true,
                    latency_ms: latency.as_secs_f64() * 1000.0,
                    timestamp: SystemTime::now(),
                })
            }
            Ok(Err(e)) => Err(ProbeError::NetworkError(e)),
            Err(_) => Err(ProbeError::Timeout),
        }
    }

    async fn recv_response(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![0u8; 1024];
        let len = self.socket.recv(&mut buf).await?;
        buf.truncate(len);
        Ok(buf)
    }
}
```

#### 3. Enhanced Probe Executor (`health/probe.rs` modifications)

```rust
pub struct ProbeExecutor {
    icmp_prober: Option<Arc<IcmpProber>>,
    udp_prober: Arc<UdpProber>,
    fallback_mode: Arc<RwLock<ProbeType>>,
}

impl ProbeExecutor {
    pub async fn new(config: ProbeConfig) -> Self {
        // Try to create ICMP prober
        let icmp_prober = match IcmpProber::new() {
            Ok(prober) => {
                tracing::info!("ICMP probing enabled");
                Some(Arc::new(prober))
            }
            Err(e) => {
                tracing::warn!(error = %e, "ICMP probing unavailable, will use UDP");
                None
            }
        };

        // Always create UDP prober as fallback
        let udp_prober = Arc::new(UdpProber::new().await.expect("UDP prober creation failed"));

        let fallback_mode = if icmp_prober.is_some() {
            ProbeType::Icmp
        } else {
            ProbeType::Udp
        };

        Self {
            icmp_prober,
            udp_prober,
            fallback_mode: Arc::new(RwLock::new(fallback_mode)),
        }
    }

    pub async fn probe(&self, target: IpAddr, count: usize, timeout_ms: u64) -> ProbeStats {
        let mut results = Vec::with_capacity(count);

        for _ in 0..count {
            let result = self.execute_single_probe(target, timeout_ms).await;
            results.push(result);

            // Small delay between probes
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        self.calculate_stats(&results)
    }

    async fn execute_single_probe(&self, target: IpAddr, timeout_ms: u64) -> ProbeResult {
        let mode = *self.fallback_mode.read().await;

        match mode {
            ProbeType::Icmp => {
                if let Some(ref prober) = self.icmp_prober {
                    match prober.probe(target).await {
                        Ok(result) => return result,
                        Err(e) => {
                            tracing::warn!(error = %e, "ICMP probe failed, falling back to UDP");
                            *self.fallback_mode.write().await = ProbeType::Udp;
                        }
                    }
                }
                // Fall through to UDP
                self.udp_prober.probe(target, 33434).await
                    .unwrap_or_else(|_| ProbeResult::failure())
            }
            ProbeType::Udp => {
                self.udp_prober.probe(target, 33434).await
                    .unwrap_or_else(|e| {
                        tracing::warn!(error = %e, "UDP probe failed, using simulated");
                        ProbeResult::simulated()
                    })
            }
            ProbeType::Simulated => ProbeResult::simulated(),
        }
    }
}
```

---

## Implementation Plan

### Phase 1: ICMP Prober Implementation (Day 1-2)

**Tasks:**
1. Create `health/icmp_probe.rs`
2. Implement ICMP packet building (Echo Request)
3. Implement ICMP packet parsing (Echo Reply)
4. Implement checksum calculation
5. Handle raw socket creation and permissions
6. Add capability detection
7. Write unit tests

**Deliverables:**
- `IcmpProber` struct with `probe()` method
- Proper error handling for permission issues
- 10+ unit tests
- Documentation

**Testing Strategy:**
```rust
#[tokio::test]
#[ignore] // Requires CAP_NET_RAW
async fn test_icmp_probe_localhost() {
    let prober = IcmpProber::new().unwrap();
    let result = prober.probe("127.0.0.1".parse().unwrap()).await.unwrap();
    assert!(result.success);
    assert!(result.latency_ms < 10.0);
}

#[tokio::test]
async fn test_icmp_checksum() {
    let prober = IcmpProber::new().unwrap();
    let packet = prober.build_echo_request(1);
    assert!(prober.verify_checksum(&packet));
}
```

### Phase 2: UDP Prober Implementation (Day 2-3)

**Tasks:**
1. Create `health/udp_probe.rs`
2. Implement UDP socket creation
3. Implement probe sending
4. Handle ICMP Port Unreachable detection
5. Implement RTT measurement
6. Add timeout handling
7. Write unit tests

**Deliverables:**
- `UdpProber` struct with `probe()` method
- No privilege requirements
- 8+ unit tests
- Documentation

**Testing Strategy:**
```rust
#[tokio::test]
async fn test_udp_probe_localhost() {
    let prober = UdpProber::new().await.unwrap();
    let result = prober.probe("127.0.0.1".parse().unwrap(), 33434).await.unwrap();
    assert!(result.success);
}

#[tokio::test]
async fn test_udp_probe_timeout() {
    let prober = UdpProber::new().await.unwrap();
    // Non-routable address
    let result = prober.probe("192.0.2.1".parse().unwrap(), 33434).await;
    assert!(result.is_err());
}
```

### Phase 3: Integration with Health Monitor (Day 3-4)

**Tasks:**
1. Modify `ProbeExecutor` to support real probing
2. Implement automatic fallback logic
3. Add configuration options for probe type
4. Update `HealthMonitor` configuration
5. Ensure backward compatibility
6. Update all existing tests

**Deliverables:**
- Enhanced `ProbeExecutor` with real probing
- Configuration options
- Fallback logic
- 15+ integration tests
- All Sprint 31 tests still passing

**Configuration:**
```rust
pub struct ProbeConfig {
    pub preferred_type: ProbeType,
    pub allow_fallback: bool,
    pub timeout_ms: u64,
    pub udp_port: u16, // Default: 33434 (traceroute port)
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            preferred_type: ProbeType::Icmp,
            allow_fallback: true,
            timeout_ms: 2000,
            udp_port: 33434,
        }
    }
}
```

### Phase 4: Testing & Validation (Day 4-5)

**Tasks:**
1. Integration testing with real network
2. Performance benchmarking
3. Privilege handling tests
4. Error condition testing
5. Regression testing (all Sprint 31 tests)
6. Documentation updates

**Test Categories:**
- Unit tests (per prober)
- Integration tests (with health monitor)
- Permission tests (capability detection)
- Network tests (real network conditions)
- Performance tests (throughput, latency)
- Regression tests (Sprint 31 compatibility)

**Acceptance Tests:**
```rust
#[tokio::test]
async fn test_real_network_health_monitoring() {
    let db = Arc::new(Database::new_in_memory().await.unwrap());
    let config = HealthConfig::default();
    let monitor = HealthMonitor::new(db, config).await.unwrap();

    // Test with real network target
    let path_id = PathId::new(1);
    let target = "8.8.8.8".parse().unwrap(); // Google DNS

    let health = monitor.check_path_health(&path_id, target).await.unwrap();
    assert!(health.health_score > 0.0);
    assert!(health.latency_ms > 0.0);
}
```

### Phase 5: Documentation & Deployment (Day 5)

**Tasks:**
1. Update Sprint 32 summary
2. Update API reference
3. Create deployment guide for permissions
4. Update PROJECT_STATUS.md
5. Create completion certificate
6. Git commits and tagging

**Documentation:**
- `SPRINT-32-SUMMARY.md` - Implementation details
- `docs/sprint-32-api-reference.md` - API documentation
- `docs/DEPLOYMENT-NETWORK-PROBING.md` - Deployment guide
- `docs/sprints/SPRINT-32-COMPLETE.md` - Completion certificate

---

## Dependencies & Requirements

### System Requirements

**For ICMP Probing:**
- Linux: `CAP_NET_RAW` capability or root privileges
- Docker: Run container with `--cap-add=NET_RAW`
- Kubernetes: Add `NET_RAW` to pod security context

**For UDP Probing:**
- No special privileges required
- Works in all environments

### Rust Crates

```toml
[dependencies]
# Existing dependencies...

# New for Sprint 32
socket2 = "0.5"     # Cross-platform raw socket support
pnet = "0.35"       # Optional: Packet parsing utilities
```

### Capability Configuration

**systemd service:**
```ini
[Service]
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
```

**Docker:**
```yaml
services:
  patronus-sdwan:
    image: patronus:latest
    cap_add:
      - NET_RAW
```

**Kubernetes:**
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: patronus-sdwan
    securityContext:
      capabilities:
        add:
        - NET_RAW
```

---

## Error Handling

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("Insufficient permissions for ICMP probing (requires CAP_NET_RAW)")]
    InsufficientPermissions,

    #[error("Probe timeout after {0:?}")]
    Timeout(Duration),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Invalid ICMP packet: {0}")]
    InvalidPacket(String),

    #[error("Checksum mismatch")]
    ChecksumError,

    #[error("No probe method available")]
    NoProbeMethod,
}
```

### Fallback Strategy

```
ICMP Probe
    ↓ (permission denied)
UDP Probe
    ↓ (network unreachable)
Simulated Probe (testing only)
    ↓
Error (in production)
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| ICMP probe latency | <50ms | Local network |
| UDP probe latency | <100ms | Includes setup |
| Probe success rate | >95% | Under normal conditions |
| Concurrent probes | 100+ | Parallel execution |
| Memory per probe | <1KB | Minimal overhead |
| CPU usage | <5% | During active probing |

---

## Testing Strategy

### Test Matrix

| Test Type | Count | Coverage |
|-----------|-------|----------|
| Unit tests | 25+ | Per-component functionality |
| Integration tests | 15+ | Health monitor integration |
| Permission tests | 5 | Capability detection |
| Network tests | 10 | Real network conditions |
| Performance tests | 5 | Throughput and latency |
| Regression tests | 102 | Sprint 31 compatibility |

**Total: 162+ tests**

### Test Environments

1. **Local Development** - Simulated probes (no privileges)
2. **CI/CD** - Docker with NET_RAW capability
3. **Staging** - Real network environment
4. **Production** - Full deployment

---

## Security Considerations

### Raw Socket Risks

**Mitigations:**
1. Minimal privilege principle - only `CAP_NET_RAW`
2. Packet validation - verify all received packets
3. Rate limiting - prevent probe flooding
4. Target validation - whitelist probe targets
5. Logging - audit all probe activity

### Attack Vectors

1. **ICMP Flood** - Rate limit outbound probes
2. **Spoofed Replies** - Validate sequence numbers and identifiers
3. **Privilege Escalation** - Drop capabilities after socket creation
4. **Resource Exhaustion** - Limit concurrent probes

---

## Deployment Considerations

### Configuration Options

```rust
// In production config
let health_config = HealthConfig {
    probe_type: ProbeType::Icmp,     // Preferred method
    allow_fallback: true,             // Enable UDP fallback
    check_interval_secs: 10,
    probes_per_check: 5,
    probe_timeout_ms: 2000,
    // ... existing config
};
```

### Permission Setup

**Option 1: Set capabilities on binary**
```bash
sudo setcap cap_net_raw+ep /usr/local/bin/patronus-sdwan
```

**Option 2: Run as privileged service**
```bash
sudo systemctl start patronus-sdwan
```

**Option 3: Use UDP probing (no privileges)**
```rust
let config = HealthConfig {
    probe_type: ProbeType::Udp,
    allow_fallback: false,
    // ...
};
```

---

## Success Metrics

### Functional Requirements ✅

- [ ] ICMP Echo Request/Reply implementation
- [ ] UDP probing with port unreachable detection
- [ ] Automatic probe type selection
- [ ] Fallback logic (ICMP → UDP → Simulated)
- [ ] Capability detection
- [ ] Error handling for all failure modes
- [ ] Configuration options for probe type

### Quality Requirements ✅

- [ ] 25+ unit tests for probers
- [ ] 15+ integration tests
- [ ] 100% of Sprint 31 tests passing
- [ ] Performance targets met
- [ ] Documentation complete
- [ ] Security review passed

### Integration Requirements ✅

- [ ] Health monitor integration complete
- [ ] Backward compatibility maintained
- [ ] Configuration backward compatible
- [ ] No breaking API changes
- [ ] Database schema unchanged

---

## Risks & Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Permission issues in deployment | High | Medium | UDP fallback, clear docs |
| ICMP blocked by firewall | Medium | Low | UDP fallback automatic |
| Platform compatibility issues | Low | Medium | Comprehensive testing |
| Performance degradation | Low | Medium | Benchmarking |
| Security vulnerabilities | Low | High | Security review, validation |

---

## Future Enhancements (Post-Sprint 32)

### Sprint 33 Candidates

1. **Advanced Probe Types**
   - TCP SYN probing
   - HTTP/HTTPS health checks
   - DNS resolution probing
   - Custom application-layer probes

2. **Probe Scheduling**
   - Adaptive probe intervals based on path stability
   - Burst probing during failover
   - Bandwidth-aware probing

3. **Enhanced Metrics**
   - Path MTU discovery
   - Hop count measurement (TTL)
   - Route tracing
   - QoS marker detection

4. **Multi-Protocol Support**
   - IPv6 probing (ICMPv6)
   - Dual-stack support
   - Protocol preference

---

## Timeline

### Week 1 (Days 1-5)

**Day 1:**
- ✅ Planning complete (this document)
- [ ] ICMP prober implementation start

**Day 2:**
- [ ] ICMP prober complete
- [ ] UDP prober implementation start

**Day 3:**
- [ ] UDP prober complete
- [ ] ProbeExecutor integration start

**Day 4:**
- [ ] Integration complete
- [ ] Testing start

**Day 5:**
- [ ] Testing complete
- [ ] Documentation
- [ ] Sprint 32 complete

---

## Acceptance Criteria

### Phase 1: ICMP Probing ✅
- [ ] IcmpProber struct implemented
- [ ] Echo Request/Reply working
- [ ] Checksum calculation correct
- [ ] Capability detection working
- [ ] 10+ unit tests passing
- [ ] Documentation complete

### Phase 2: UDP Probing ✅
- [ ] UdpProber struct implemented
- [ ] UDP probe sending working
- [ ] Port unreachable detection working
- [ ] RTT measurement accurate
- [ ] 8+ unit tests passing
- [ ] Documentation complete

### Phase 3: Integration ✅
- [ ] ProbeExecutor enhanced
- [ ] Fallback logic working
- [ ] Configuration options added
- [ ] All Sprint 31 tests passing
- [ ] 15+ integration tests passing
- [ ] Documentation updated

### Phase 4: Testing ✅
- [ ] 162+ total tests passing
- [ ] Performance targets met
- [ ] Security review complete
- [ ] Regression tests passing
- [ ] Real network validation

### Phase 5: Deployment ✅
- [ ] Deployment guide written
- [ ] Permission setup documented
- [ ] Docker/K8s configs provided
- [ ] PROJECT_STATUS.md updated
- [ ] Sprint complete certificate

---

## References

### RFC Documents
- RFC 792 - Internet Control Message Protocol (ICMP)
- RFC 768 - User Datagram Protocol (UDP)
- RFC 1071 - Computing the Internet Checksum

### External Resources
- Linux capabilities: `man 7 capabilities`
- Raw sockets: `man 7 raw`
- ICMP specification: https://datatracker.ietf.org/doc/html/rfc792

### Internal Documentation
- Sprint 31 Summary: SPRINT-31-SUMMARY.md
- Sprint 31 API Reference: docs/sprint-31-api-reference.md
- Health Monitoring: crates/patronus-sdwan/src/health/

---

## Appendix A: ICMP Packet Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Data ...
+-+-+-+-+-

Echo Request: Type=8, Code=0
Echo Reply:   Type=0, Code=0
```

---

## Appendix B: Checksum Algorithm

```rust
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            // Odd byte - pad with zero
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}
```

---

**Sprint 32 Status**: 📋 **PLANNING COMPLETE**

**Ready to Begin**: Phase 1 - ICMP Prober Implementation

**Contact**: See project documentation for details

---

🤖 *Generated with [Claude Code](https://claude.com/claude-code)*

Co-Authored-By: Claude <noreply@anthropic.com>
