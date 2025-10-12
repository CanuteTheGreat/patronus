//! ICMP Echo (ping) probing implementation
//!
//! This module provides real ICMP Echo Request/Reply probing for network
//! path health monitoring. Requires CAP_NET_RAW capability or root privileges.

use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use socket2::{Domain, Protocol, Socket, Type};

/// Errors that can occur during ICMP probing
#[derive(Debug, thiserror::Error)]
pub enum IcmpError {
    #[error("Insufficient permissions for ICMP probing (requires CAP_NET_RAW)")]
    InsufficientPermissions,

    #[error("Probe timeout after {0:?}")]
    Timeout(Duration),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Invalid ICMP packet: {0}")]
    InvalidPacket(String),

    #[error("Checksum mismatch in ICMP packet")]
    ChecksumError,

    #[error("Unsupported IP version: {0}")]
    UnsupportedIpVersion(String),
}

/// Result of a single ICMP probe
#[derive(Debug, Clone)]
pub struct IcmpProbeResult {
    /// Whether the probe was successful
    pub success: bool,

    /// Round-trip time in milliseconds
    pub latency_ms: f64,

    /// Timestamp when probe completed
    pub timestamp: SystemTime,

    /// Error message if probe failed
    pub error: Option<String>,
}

impl IcmpProbeResult {
    /// Create a successful probe result
    pub fn success(latency_ms: f64) -> Self {
        Self {
            success: true,
            latency_ms,
            timestamp: SystemTime::now(),
            error: None,
        }
    }

    /// Create a failed probe result
    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            latency_ms: 0.0,
            timestamp: SystemTime::now(),
            error: Some(error),
        }
    }
}

/// ICMP Echo prober
///
/// Sends ICMP Echo Request packets and waits for Echo Reply packets.
/// Uses raw sockets which require special privileges.
pub struct IcmpProber {
    /// Raw socket for ICMP
    socket: Arc<Socket>,

    /// Identifier for this process (typically PID)
    identifier: u16,

    /// Sequence counter for ICMP packets
    sequence: AtomicU16,

    /// Timeout for probe responses
    timeout: Duration,
}

impl IcmpProber {
    /// Create a new ICMP prober
    ///
    /// # Errors
    ///
    /// Returns `IcmpError::InsufficientPermissions` if the process lacks
    /// CAP_NET_RAW capability or root privileges.
    pub fn new() -> Result<Self, IcmpError> {
        Self::with_timeout(Duration::from_secs(2))
    }

    /// Create a new ICMP prober with custom timeout
    pub fn with_timeout(timeout: Duration) -> Result<Self, IcmpError> {
        // Try to create raw socket for ICMP
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    IcmpError::InsufficientPermissions
                } else {
                    IcmpError::NetworkError(e)
                }
            })?;

        // Set socket timeout
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        // Use process ID as identifier (lower 16 bits)
        let identifier = std::process::id() as u16;

        Ok(Self {
            socket: Arc::new(socket),
            identifier,
            sequence: AtomicU16::new(0),
            timeout,
        })
    }

    /// Send an ICMP Echo Request and wait for Echo Reply
    ///
    /// # Arguments
    ///
    /// * `target` - IP address to probe
    ///
    /// # Returns
    ///
    /// Returns the probe result with RTT measurement
    pub async fn probe(&self, target: IpAddr) -> Result<IcmpProbeResult, IcmpError> {
        // Only IPv4 supported currently
        if !target.is_ipv4() {
            return Err(IcmpError::UnsupportedIpVersion(
                "IPv6 not yet supported".to_string(),
            ));
        }

        // Get next sequence number
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        // Build ICMP Echo Request packet
        let packet = self.build_echo_request(seq);

        // Send packet and measure time
        let send_time = Instant::now();

        let socket = self.socket.clone();
        let target_addr: std::net::SocketAddr = format!("{}:0", target).parse().unwrap();

        // Send in blocking task to avoid blocking async runtime
        tokio::task::spawn_blocking(move || {
            socket.send_to(&packet, &target_addr.into())
        })
        .await
        .map_err(|e| IcmpError::NetworkError(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        )))?
        .map_err(IcmpError::NetworkError)?;

        // Wait for reply
        let reply = self.recv_echo_reply(seq).await?;
        let recv_time = Instant::now();

        // Verify checksum
        if !self.verify_checksum(&reply) {
            return Err(IcmpError::ChecksumError);
        }

        // Calculate RTT
        let latency = recv_time.duration_since(send_time);
        let latency_ms = latency.as_secs_f64() * 1000.0;

        Ok(IcmpProbeResult::success(latency_ms))
    }

    /// Build an ICMP Echo Request packet
    fn build_echo_request(&self, seq: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 64];

        // ICMP Header
        packet[0] = 8; // Type: Echo Request
        packet[1] = 0; // Code: 0
        // [2-3] Checksum (calculated later)
        packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());

        // Payload: timestamp for verification
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        packet[8..16].copy_from_slice(&timestamp.to_be_bytes());

        // Fill rest with pattern
        for i in 16..64 {
            packet[i] = (i & 0xFF) as u8;
        }

        // Calculate and set checksum (with checksum field zeroed)
        let checksum = self.calculate_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }

    /// Receive ICMP Echo Reply packet
    async fn recv_echo_reply(&self, expected_seq: u16) -> Result<Vec<u8>, IcmpError> {
        let deadline = Instant::now() + self.timeout;

        loop {
            // Check if timeout reached
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(IcmpError::Timeout(self.timeout));
            }

            // Receive packet
            let socket = self.socket.clone();
            let packet_result = tokio::task::spawn_blocking(move || {
                let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
                match socket.recv(&mut buf) {
                    Ok(len) => {
                        let initialized: Vec<u8> = buf[..len]
                            .iter()
                            .map(|b| unsafe { b.assume_init() })
                            .collect();
                        Ok(initialized)
                    }
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(|e| {
                IcmpError::NetworkError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

            let buf = match packet_result {
                Ok(data) => data,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout on receive, check deadline and retry
                    continue;
                }
                Err(e) => return Err(IcmpError::NetworkError(e)),
            };

            // Parse IP header to find ICMP data
            let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
            if buf.len() < ip_header_len + 8 {
                continue; // Packet too short
            }

            let icmp_packet = &buf[ip_header_len..];

            // Check if this is an Echo Reply (Type 0)
            if icmp_packet[0] != 0 {
                continue;
            }

            // Verify code
            if icmp_packet[1] != 0 {
                continue;
            }

            // Extract identifier and sequence
            let id = u16::from_be_bytes([icmp_packet[4], icmp_packet[5]]);
            let seq = u16::from_be_bytes([icmp_packet[6], icmp_packet[7]]);

            // Check if this reply is for our request
            if id == self.identifier && seq == expected_seq {
                return Ok(icmp_packet.to_vec());
            }

            // Not our packet, continue waiting
        }
    }

    /// Calculate Internet checksum for ICMP packet
    ///
    /// The checksum is the 16-bit one's complement of the one's complement
    /// sum of the ICMP message starting with the ICMP Type field.
    fn calculate_checksum(&self, data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Sum all 16-bit words
        for chunk in data.chunks(2) {
            if chunk.len() == 2 {
                let word = u16::from_be_bytes([chunk[0], chunk[1]]);
                sum += word as u32;
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

    /// Verify checksum of received ICMP packet
    fn verify_checksum(&self, packet: &[u8]) -> bool {
        // Calculate checksum with checksum field zeroed
        let mut packet_copy = packet.to_vec();
        packet_copy[2] = 0;
        packet_copy[3] = 0;

        let calculated = self.calculate_checksum(&packet_copy);
        let received = u16::from_be_bytes([packet[2], packet[3]]);

        calculated == received
    }

    /// Check if ICMP probing is available on this system
    pub fn is_available() -> bool {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_calculation() {
        let prober = match IcmpProber::new() {
            Ok(p) => p,
            Err(_) => {
                println!("Skipping test: ICMP not available");
                return;
            }
        };

        let packet = prober.build_echo_request(1);

        // Verify checksum is correct
        assert!(prober.verify_checksum(&packet));
    }

    #[test]
    fn test_checksum_algorithm() {
        let prober = match IcmpProber::new() {
            Ok(p) => p,
            Err(_) => {
                println!("Skipping test: ICMP not available");
                return;
            }
        };

        // Test with known data
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let checksum = prober.calculate_checksum(&data);

        // Verify checksum is non-zero
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_packet_structure() {
        let prober = match IcmpProber::new() {
            Ok(p) => p,
            Err(_) => {
                println!("Skipping test: ICMP not available");
                return;
            }
        };

        let packet = prober.build_echo_request(42);

        // Verify packet structure
        assert_eq!(packet.len(), 64);
        assert_eq!(packet[0], 8); // Type: Echo Request
        assert_eq!(packet[1], 0); // Code: 0

        // Verify identifier
        let id = u16::from_be_bytes([packet[4], packet[5]]);
        assert_eq!(id, prober.identifier);

        // Verify sequence
        let seq = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(seq, 42);
    }

    #[test]
    fn test_sequence_increment() {
        let prober = match IcmpProber::new() {
            Ok(p) => p,
            Err(_) => {
                println!("Skipping test: ICMP not available");
                return;
            }
        };

        let seq1 = prober.sequence.fetch_add(1, Ordering::SeqCst);
        let seq2 = prober.sequence.fetch_add(1, Ordering::SeqCst);
        let seq3 = prober.sequence.fetch_add(1, Ordering::SeqCst);

        assert_eq!(seq2, seq1 + 1);
        assert_eq!(seq3, seq2 + 1);
    }

    #[tokio::test]
    #[ignore] // Requires CAP_NET_RAW
    async fn test_probe_localhost() {
        let prober = IcmpProber::new().expect("ICMP prober creation failed");
        let target = "127.0.0.1".parse().unwrap();

        let result = prober.probe(target).await.expect("Probe failed");

        assert!(result.success);
        assert!(result.latency_ms < 10.0); // Should be very fast for localhost
        assert!(result.error.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires CAP_NET_RAW and network access
    async fn test_probe_google_dns() {
        let prober = IcmpProber::new().expect("ICMP prober creation failed");
        let target = "8.8.8.8".parse().unwrap();

        let result = prober.probe(target).await.expect("Probe failed");

        assert!(result.success);
        assert!(result.latency_ms > 0.0);
        assert!(result.latency_ms < 1000.0); // Should be under 1 second
        assert!(result.error.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires CAP_NET_RAW
    async fn test_probe_timeout() {
        let prober = IcmpProber::with_timeout(Duration::from_millis(100))
            .expect("ICMP prober creation failed");

        // Non-routable address
        let target = "192.0.2.1".parse().unwrap();

        let result = prober.probe(target).await;

        assert!(result.is_err());
        match result {
            Err(IcmpError::Timeout(_)) => {}
            _ => panic!("Expected timeout error"),
        }
    }

    #[test]
    fn test_is_available() {
        // Just test that the function runs without panicking
        let _available = IcmpProber::is_available();
        // Don't assert on the result since it depends on privileges
    }

    #[test]
    fn test_probe_result_success() {
        let result = IcmpProbeResult::success(25.5);
        assert!(result.success);
        assert_eq!(result.latency_ms, 25.5);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_probe_result_failure() {
        let result = IcmpProbeResult::failure("Network unreachable".to_string());
        assert!(!result.success);
        assert_eq!(result.latency_ms, 0.0);
        assert!(result.error.is_some());
        assert_eq!(result.error.unwrap(), "Network unreachable");
    }

    #[test]
    fn test_ipv6_not_supported() {
        let prober = match IcmpProber::new() {
            Ok(p) => p,
            Err(_) => {
                println!("Skipping test: ICMP not available");
                return;
            }
        };

        let target = "::1".parse().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let result = runtime.block_on(prober.probe(target));

        assert!(result.is_err());
        match result {
            Err(IcmpError::UnsupportedIpVersion(_)) => {}
            _ => panic!("Expected UnsupportedIpVersion error"),
        }
    }
}
