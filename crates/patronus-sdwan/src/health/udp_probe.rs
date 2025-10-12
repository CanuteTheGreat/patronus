//! UDP probing implementation
//!
//! This module provides UDP-based network probing as a fallback when ICMP
//! probing is unavailable. Works without special privileges.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;

/// Errors that can occur during UDP probing
#[derive(Debug, thiserror::Error)]
pub enum UdpError {
    #[error("Probe timeout after {0:?}")]
    Timeout(Duration),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Failed to bind UDP socket")]
    BindFailed,

    #[error("Unsupported IP version: {0}")]
    UnsupportedIpVersion(String),
}

/// Result of a single UDP probe
#[derive(Debug, Clone)]
pub struct UdpProbeResult {
    /// Whether the probe was successful
    pub success: bool,

    /// Round-trip time in milliseconds
    pub latency_ms: f64,

    /// Timestamp when probe completed
    pub timestamp: SystemTime,

    /// Error message if probe failed
    pub error: Option<String>,
}

impl UdpProbeResult {
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

/// UDP prober
///
/// Sends UDP probe packets to measure network reachability and latency.
/// This method works without special privileges and is useful as a fallback
/// when ICMP probing is unavailable.
///
/// # How it works
///
/// 1. Sends a UDP packet to the target (typically on a high port)
/// 2. Measures RTT in one of three ways:
///    - Application response (if target service responds)
///    - ICMP Port Unreachable (indicates host is reachable but port closed)
///    - Timeout (indicates host/network unreachable)
pub struct UdpProber {
    /// UDP socket for sending/receiving probes
    socket: UdpSocket,

    /// Timeout for probe responses
    timeout: Duration,

    /// Default target port (typically 33434 - traceroute port)
    default_port: u16,
}

impl UdpProber {
    /// Create a new UDP prober
    ///
    /// # Errors
    ///
    /// Returns error if unable to bind UDP socket
    pub async fn new() -> Result<Self, UdpError> {
        Self::with_timeout(Duration::from_secs(2)).await
    }

    /// Create a new UDP prober with custom timeout
    pub async fn with_timeout(timeout: Duration) -> Result<Self, UdpError> {
        // Bind to ephemeral port on all interfaces
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| UdpError::BindFailed)?;

        // Set socket options
        socket.set_broadcast(false)?;

        Ok(Self {
            socket,
            timeout,
            default_port: 33434, // Standard traceroute port
        })
    }

    /// Create a new UDP prober with custom timeout and port
    pub async fn with_config(timeout: Duration, default_port: u16) -> Result<Self, UdpError> {
        let mut prober = Self::with_timeout(timeout).await?;
        prober.default_port = default_port;
        Ok(prober)
    }

    /// Send a UDP probe and measure RTT
    ///
    /// # Arguments
    ///
    /// * `target` - IP address to probe
    ///
    /// # Returns
    ///
    /// Returns the probe result with RTT measurement
    pub async fn probe(&self, target: IpAddr) -> Result<UdpProbeResult, UdpError> {
        self.probe_port(target, self.default_port).await
    }

    /// Send a UDP probe to a specific port
    ///
    /// # Arguments
    ///
    /// * `target` - IP address to probe
    /// * `port` - UDP port to probe
    pub async fn probe_port(&self, target: IpAddr, port: u16) -> Result<UdpProbeResult, UdpError> {
        // Only IPv4 supported currently
        if !target.is_ipv4() {
            return Err(UdpError::UnsupportedIpVersion(
                "IPv6 not yet supported".to_string(),
            ));
        }

        let target_addr = SocketAddr::new(target, port);

        // Create probe payload with timestamp
        let probe_data = self.build_probe_payload();

        // Send probe and measure time
        let send_time = Instant::now();
        self.socket.send_to(&probe_data, target_addr).await?;

        // Wait for response or ICMP error
        match self.recv_response().await {
            Ok(_) => {
                // Got a response (application replied)
                let recv_time = Instant::now();
                let latency = recv_time.duration_since(send_time);
                Ok(UdpProbeResult::success(latency.as_secs_f64() * 1000.0))
            }
            Err(e) if self.is_port_unreachable(&e) => {
                // ICMP Port Unreachable means host is reachable
                let recv_time = Instant::now();
                let latency = recv_time.duration_since(send_time);
                Ok(UdpProbeResult::success(latency.as_secs_f64() * 1000.0))
            }
            Err(e) if self.is_timeout(&e) => {
                // Timeout - host/network unreachable
                Err(UdpError::Timeout(self.timeout))
            }
            Err(e) => {
                // Other network error
                Err(UdpError::NetworkError(e))
            }
        }
    }

    /// Build probe payload with timestamp
    fn build_probe_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);

        // Magic marker
        payload.extend_from_slice(b"PATRONUS_UDP_PROBE");

        // Timestamp (for verification if we get a response)
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        payload.extend_from_slice(&timestamp.to_be_bytes());

        // Padding to make packet reasonable size
        while payload.len() < 64 {
            payload.push(0);
        }

        payload
    }

    /// Receive response from probe
    async fn recv_response(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 1024];

        // Wait for response with timeout
        match tokio::time::timeout(self.timeout, self.socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                buf.truncate(len);
                Ok(buf)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Probe timeout",
            )),
        }
    }

    /// Check if error indicates ICMP Port Unreachable
    fn is_port_unreachable(&self, error: &std::io::Error) -> bool {
        // On Linux, ICMP Port Unreachable is reported as ConnectionRefused
        error.kind() == std::io::ErrorKind::ConnectionRefused
    }

    /// Check if error is a timeout
    fn is_timeout(&self, error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::TimedOut
            || error.kind() == std::io::ErrorKind::WouldBlock
    }

    /// Get the local port this prober is bound to
    pub fn local_port(&self) -> std::io::Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }

    /// Check if UDP probing is available on this system
    pub async fn is_available() -> bool {
        UdpSocket::bind("0.0.0.0:0").await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_prober_creation() {
        let prober = UdpProber::new().await;
        assert!(prober.is_ok());

        let prober = prober.unwrap();
        assert_eq!(prober.timeout, Duration::from_secs(2));
        assert_eq!(prober.default_port, 33434);
    }

    #[tokio::test]
    async fn test_udp_prober_with_timeout() {
        let timeout = Duration::from_millis(500);
        let prober = UdpProber::with_timeout(timeout).await.unwrap();
        assert_eq!(prober.timeout, timeout);
    }

    #[tokio::test]
    async fn test_udp_prober_with_config() {
        let timeout = Duration::from_secs(1);
        let port = 12345;
        let prober = UdpProber::with_config(timeout, port).await.unwrap();
        assert_eq!(prober.timeout, timeout);
        assert_eq!(prober.default_port, port);
    }

    #[tokio::test]
    async fn test_probe_payload() {
        let prober = UdpProber::new().await.unwrap();
        let payload = prober.build_probe_payload();

        // Verify payload structure
        assert_eq!(payload.len(), 64);
        assert_eq!(&payload[0..18], b"PATRONUS_UDP_PROBE");

        // Verify timestamp is present
        let timestamp_bytes = &payload[18..26];
        let timestamp = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
        assert!(timestamp > 0);
    }

    #[tokio::test]
    async fn test_local_port() {
        let prober = UdpProber::new().await.unwrap();
        let port = prober.local_port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_probe_localhost() {
        let prober = UdpProber::new().await.unwrap();
        let target = "127.0.0.1".parse().unwrap();

        // This should timeout or get port unreachable (both indicate reachability)
        let result = prober.probe(target).await;

        // Either success (port unreachable = reachable) or timeout
        match result {
            Ok(probe_result) => {
                assert!(probe_result.success);
                assert!(probe_result.latency_ms < 100.0);
            }
            Err(UdpError::Timeout(_)) => {
                // Also acceptable - means we didn't get ICMP error
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_probe_unreachable() {
        let prober = UdpProber::with_timeout(Duration::from_millis(200))
            .await
            .unwrap();

        // Non-routable address (TEST-NET-1)
        let target = "192.0.2.1".parse().unwrap();

        let result = prober.probe(target).await;

        // Should timeout
        assert!(result.is_err());
        match result {
            Err(UdpError::Timeout(_)) => {}
            _ => panic!("Expected timeout error"),
        }
    }

    #[tokio::test]
    async fn test_ipv6_not_supported() {
        let prober = UdpProber::new().await.unwrap();
        let target = "::1".parse().unwrap();

        let result = prober.probe(target).await;

        assert!(result.is_err());
        match result {
            Err(UdpError::UnsupportedIpVersion(_)) => {}
            _ => panic!("Expected UnsupportedIpVersion error"),
        }
    }

    #[test]
    fn test_probe_result_success() {
        let result = UdpProbeResult::success(42.5);
        assert!(result.success);
        assert_eq!(result.latency_ms, 42.5);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_probe_result_failure() {
        let result = UdpProbeResult::failure("Network down".to_string());
        assert!(!result.success);
        assert_eq!(result.latency_ms, 0.0);
        assert!(result.error.is_some());
        assert_eq!(result.error.unwrap(), "Network down");
    }

    #[tokio::test]
    async fn test_is_available() {
        let available = UdpProber::is_available().await;
        assert!(available); // UDP should always be available
    }

    #[test]
    fn test_error_detection() {
        let prober_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(UdpProber::new());
        let prober = prober_result.unwrap();

        // Test timeout detection
        let timeout_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        assert!(prober.is_timeout(&timeout_err));

        let wouldblock_err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
        assert!(prober.is_timeout(&wouldblock_err));

        // Test port unreachable detection
        let refused_err =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        assert!(prober.is_port_unreachable(&refused_err));

        // Test non-timeout/non-unreachable
        let other_err = std::io::Error::new(std::io::ErrorKind::Other, "other");
        assert!(!prober.is_timeout(&other_err));
        assert!(!prober.is_port_unreachable(&other_err));
    }
}
