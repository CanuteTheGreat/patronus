//! Core type definitions for SD-WAN

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Unique identifier for a site
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SiteId(Uuid);

impl SiteId {
    /// Generate a new random site ID
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl std::fmt::Display for SiteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for SiteId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Unique identifier for a path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathId(u64);

impl PathId {
    /// Create new path ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get inner value
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Site information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// Unique site identifier
    pub id: SiteId,

    /// Human-readable name
    pub name: String,

    /// Public key for authentication
    pub public_key: Vec<u8>,

    /// Available endpoints (multi-homing)
    pub endpoints: Vec<Endpoint>,

    /// When site was created
    pub created_at: SystemTime,

    /// Last time we heard from this site
    pub last_seen: SystemTime,

    /// Current site status
    pub status: SiteStatus,
}

/// Endpoint (network path to a site)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Socket address
    pub address: SocketAddr,

    /// Interface type (fiber, lte, starlink, etc.)
    pub interface_type: String,

    /// Cost per gigabyte (for cost-aware routing)
    pub cost_per_gb: f64,

    /// Whether this endpoint is currently reachable
    pub reachable: bool,
}

/// Site status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiteStatus {
    /// Site is active and healthy
    Active,

    /// Site is unreachable
    Inactive,

    /// Site is degraded (poor connectivity)
    Degraded,
}

impl std::fmt::Display for SiteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteStatus::Active => write!(f, "active"),
            SiteStatus::Inactive => write!(f, "inactive"),
            SiteStatus::Degraded => write!(f, "degraded"),
        }
    }
}

/// Network path between two sites
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    /// Unique path identifier
    pub id: PathId,

    /// Source site
    pub src_site: SiteId,

    /// Destination site
    pub dst_site: SiteId,

    /// Source endpoint
    pub src_endpoint: SocketAddr,

    /// Destination endpoint
    pub dst_endpoint: SocketAddr,

    /// WireGuard interface name
    pub wg_interface: Option<String>,

    /// Current path metrics
    pub metrics: PathMetrics,

    /// Current path status
    pub status: PathStatus,
}

/// Path quality metrics
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PathMetrics {
    /// Round-trip latency in milliseconds
    pub latency_ms: f64,

    /// Jitter (variance in latency) in milliseconds
    pub jitter_ms: f64,

    /// Packet loss percentage (0-100)
    pub packet_loss_pct: f64,

    /// Available bandwidth in Mbps
    pub bandwidth_mbps: f64,

    /// Path MTU
    pub mtu: u16,

    /// When metrics were measured
    pub measured_at: SystemTime,

    /// Computed path score (0-100)
    pub score: u8,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            latency_ms: 0.0,
            jitter_ms: 0.0,
            packet_loss_pct: 0.0,
            bandwidth_mbps: 0.0,
            mtu: 1500,
            measured_at: SystemTime::now(),
            score: 0,
        }
    }
}

/// Path status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathStatus {
    /// Path is up and healthy
    Up,

    /// Path is down
    Down,

    /// Path is degraded (poor quality)
    Degraded,
}

impl std::fmt::Display for PathStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathStatus::Up => write!(f, "up"),
            PathStatus::Down => write!(f, "down"),
            PathStatus::Degraded => write!(f, "degraded"),
        }
    }
}

/// Flow identifier (5-tuple)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    /// Source IP address
    pub src_ip: IpAddr,

    /// Destination IP address
    pub dst_ip: IpAddr,

    /// Source port
    pub src_port: u16,

    /// Destination port
    pub dst_port: u16,

    /// IP protocol (TCP=6, UDP=17, etc.)
    pub protocol: u8,
}

/// Active flow tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    /// Flow identifier
    pub key: FlowKey,

    /// Path currently used for this flow
    pub selected_path: PathId,

    /// When flow started
    pub started_at: SystemTime,

    /// Last packet timestamp
    pub last_packet_at: SystemTime,

    /// Bytes transmitted
    pub bytes_tx: u64,

    /// Bytes received
    pub bytes_rx: u64,

    /// Flow statistics
    pub stats: FlowStats,
}

/// Flow statistics
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FlowStats {
    /// Packets transmitted
    pub packets_tx: u64,

    /// Packets received
    pub packets_rx: u64,

    /// Retransmissions (TCP only)
    pub retransmits: u64,

    /// Average RTT
    pub avg_rtt_ms: f64,
}

/// Site announcement (for mesh discovery)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteAnnouncement {
    /// Announcing site ID
    pub site_id: SiteId,

    /// Site name
    pub site_name: String,

    /// Public key for authentication
    pub public_key: Vec<u8>,

    /// Available endpoints
    pub endpoints: Vec<Endpoint>,

    /// Site capabilities
    pub capabilities: SiteCapabilities,

    /// Announcement timestamp
    pub timestamp: SystemTime,

    /// Signature (for authentication)
    pub signature: Vec<u8>,
}

/// Site capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCapabilities {
    /// Maximum bandwidth (Mbps)
    pub max_bandwidth_mbps: u64,

    /// Supported features
    pub features: Vec<String>,

    /// Protocol version
    pub protocol_version: u32,
}

impl Default for SiteCapabilities {
    fn default() -> Self {
        Self {
            max_bandwidth_mbps: 1000,
            features: vec!["wireguard".to_string(), "path-monitoring".to_string()],
            protocol_version: 1,
        }
    }
}

/// Path probe packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathProbe {
    /// Probe sequence number
    pub sequence: u64,

    /// Probe timestamp
    pub timestamp: SystemTime,

    /// Probe type
    pub probe_type: ProbeType,

    /// HMAC signature (for authenticity)
    pub signature: Vec<u8>,
}

/// Probe type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProbeType {
    /// ICMP echo request
    Icmp,

    /// UDP probe
    Udp,

    /// TCP SYN probe
    Tcp,
}

/// Path probe response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathProbeResponse {
    /// Original probe sequence
    pub sequence: u64,

    /// Response timestamp
    pub timestamp: SystemTime,

    /// Computed metrics
    pub metrics: PathMetrics,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_site_id_generation() {
        let id1 = SiteId::generate();
        let id2 = SiteId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_site_id_string_conversion() {
        let id = SiteId::generate();
        let s = id.to_string();
        let parsed: SiteId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_flow_key_hash() {
        use std::collections::HashMap;

        let key = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 1234,
            dst_port: 80,
            protocol: 6, // TCP
        };

        let mut map = HashMap::new();
        map.insert(key, "value");

        assert_eq!(map.get(&key), Some(&"value"));
    }
}
