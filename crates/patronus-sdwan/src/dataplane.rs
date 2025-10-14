//! Data plane for SD-WAN packet forwarding
//!
//! This module implements the data plane that handles actual packet forwarding
//! through SD-WAN tunnels with compression support.

use crate::compression::{CompressionEngine, CompressionConfig, CompressedPacket};
use crate::types::{PathId, SiteId};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Data plane configuration
#[derive(Debug, Clone)]
pub struct DataPlaneConfig {
    /// Local bind address for data plane
    pub bind_addr: SocketAddr,

    /// Compression configuration
    pub compression: CompressionConfig,

    /// Maximum packet size (MTU)
    pub max_packet_size: usize,

    /// Enable packet statistics
    pub enable_stats: bool,
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:51822".parse().unwrap(), // Data plane port
            compression: CompressionConfig::default(),
            max_packet_size: 1500,
            enable_stats: true,
        }
    }
}

/// Tunnel endpoint information
#[derive(Debug, Clone)]
pub struct TunnelEndpoint {
    /// Remote site ID
    pub site_id: SiteId,

    /// Path ID for this tunnel
    pub path_id: PathId,

    /// Remote endpoint address
    pub remote_addr: SocketAddr,

    /// Whether compression is negotiated for this tunnel
    pub compression_enabled: bool,
}

/// Data plane statistics
#[derive(Debug, Clone, Default)]
pub struct DataPlaneStats {
    /// Total packets forwarded
    pub packets_forwarded: u64,

    /// Total bytes forwarded (before compression)
    pub bytes_forwarded: u64,

    /// Packets dropped (errors, MTU exceeded, etc.)
    pub packets_dropped: u64,

    /// Packets received
    pub packets_received: u64,

    /// Bytes received (after decompression)
    pub bytes_received: u64,
}

/// SD-WAN data plane
pub struct DataPlane {
    /// Configuration
    config: DataPlaneConfig,

    /// UDP socket for data plane traffic
    socket: Arc<UdpSocket>,

    /// Compression engine
    compression: Arc<RwLock<CompressionEngine>>,

    /// Active tunnel endpoints
    tunnels: Arc<RwLock<HashMap<PathId, TunnelEndpoint>>>,

    /// Routing table: destination IP -> path ID
    routes: Arc<RwLock<HashMap<IpAddr, PathId>>>,

    /// Statistics
    stats: Arc<RwLock<DataPlaneStats>>,
}

impl DataPlane {
    /// Create a new data plane
    pub async fn new(config: DataPlaneConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = Arc::new(UdpSocket::bind(config.bind_addr).await?);
        let compression = Arc::new(RwLock::new(CompressionEngine::new(config.compression.clone())));

        info!("Data plane bound to {}", config.bind_addr);

        Ok(Self {
            config,
            socket,
            compression,
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DataPlaneStats::default())),
        })
    }

    /// Add a tunnel endpoint
    pub async fn add_tunnel(&self, tunnel: TunnelEndpoint) {
        let path_id = tunnel.path_id.clone();
        let mut tunnels = self.tunnels.write().await;
        tunnels.insert(path_id.clone(), tunnel);
        info!("Added tunnel endpoint for path {}", path_id);
    }

    /// Remove a tunnel endpoint
    pub async fn remove_tunnel(&self, path_id: &PathId) {
        let mut tunnels = self.tunnels.write().await;
        if tunnels.remove(path_id).is_some() {
            info!("Removed tunnel endpoint for path {}", path_id);
        }
    }

    /// Add a route
    pub async fn add_route(&self, destination: IpAddr, path_id: PathId) {
        let mut routes = self.routes.write().await;
        routes.insert(destination, path_id);
        debug!("Added route: {} -> path {}", destination, path_id);
    }

    /// Remove a route
    pub async fn remove_route(&self, destination: &IpAddr) {
        let mut routes = self.routes.write().await;
        routes.remove(destination);
    }

    /// Forward a packet through the data plane
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet data
    /// * `destination` - Destination IP address
    ///
    /// # Returns
    ///
    /// Result indicating success or error
    #[tracing::instrument(skip(self, packet), fields(packet_size = packet.len(), dest = %destination))]
    pub async fn forward_packet(
        &self,
        packet: &[u8],
        destination: IpAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Look up route
        let path_id = {
            let routes = self.routes.read().await;
            routes.get(&destination).cloned()
        };

        let path_id = match path_id {
            Some(p) => p,
            None => {
                warn!("No route found for {}", destination);
                let mut stats = self.stats.write().await;
                stats.packets_dropped += 1;
                return Err("No route found".into());
            }
        };

        // Get tunnel endpoint
        let tunnel = {
            let tunnels = self.tunnels.read().await;
            tunnels.get(&path_id).cloned()
        };

        let tunnel = match tunnel {
            Some(t) => t,
            None => {
                error!("No tunnel found for path {}", path_id);
                let mut stats = self.stats.write().await;
                stats.packets_dropped += 1;
                return Err("No tunnel found".into());
            }
        };

        // Check MTU
        if packet.len() > self.config.max_packet_size {
            warn!("Packet exceeds MTU: {} > {}", packet.len(), self.config.max_packet_size);
            let mut stats = self.stats.write().await;
            stats.packets_dropped += 1;
            return Err("Packet exceeds MTU".into());
        }

        // Compress packet if enabled
        let payload = if tunnel.compression_enabled {
            let mut compression = self.compression.write().await;
            match compression.compress(packet) {
                Ok(compressed) => {
                    let packet_wrapper = if compressed.len() < packet.len() {
                        CompressedPacket::compressed(compressed, packet.len())
                    } else {
                        CompressedPacket::uncompressed(packet.to_vec())
                    };
                    packet_wrapper.to_bytes()
                }
                Err(e) => {
                    error!("Compression failed: {}", e);
                    // Fall back to uncompressed
                    CompressedPacket::uncompressed(packet.to_vec()).to_bytes()
                }
            }
        } else {
            CompressedPacket::uncompressed(packet.to_vec()).to_bytes()
        };

        // Send through tunnel
        match self.socket.send_to(&payload, tunnel.remote_addr).await {
            Ok(sent) => {
                debug!(
                    "Forwarded packet to {} via path {}: {} bytes",
                    destination, path_id, sent
                );

                if self.config.enable_stats {
                    let mut stats = self.stats.write().await;
                    stats.packets_forwarded += 1;
                    stats.bytes_forwarded += packet.len() as u64;
                }

                Ok(())
            }
            Err(e) => {
                error!("Failed to send packet: {}", e);
                let mut stats = self.stats.write().await;
                stats.packets_dropped += 1;
                Err(e.into())
            }
        }
    }

    /// Start receiving packets
    ///
    /// This spawns a background task that receives packets from tunnels
    /// and processes them (decompression, decapsulation, etc.)
    pub fn start_rx(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536]; // 64KB buffer

            loop {
                match self.socket.recv_from(&mut buf).await {
                    Ok((len, from_addr)) => {
                        debug!("Received {} bytes from {}", len, from_addr);

                        if let Err(e) = self.process_received_packet(&buf[..len], from_addr).await {
                            error!("Failed to process received packet: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Socket receive error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }

    /// Process a received packet
    async fn process_received_packet(
        &self,
        data: &[u8],
        from_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Parse compressed packet wrapper
        let packet_wrapper = CompressedPacket::from_bytes(data)?;

        // Decompress if needed
        let payload = if packet_wrapper.compressed {
            let mut compression = self.compression.write().await;
            compression.decompress(&packet_wrapper.data, packet_wrapper.original_size.map(|s| s as i32))?
        } else {
            packet_wrapper.data
        };

        // Update statistics
        if self.config.enable_stats {
            let mut stats = self.stats.write().await;
            stats.packets_received += 1;
            stats.bytes_received += payload.len() as u64;
        }

        // TODO: Forward to local network interface or process locally
        debug!("Processed packet: {} bytes from {}", payload.len(), from_addr);

        Ok(())
    }

    /// Get data plane statistics
    pub async fn get_stats(&self) -> DataPlaneStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Get compression statistics
    pub async fn get_compression_stats(&self) -> crate::compression::CompressionStats {
        let compression = self.compression.read().await;
        compression.stats().clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = DataPlaneStats::default();

        let mut compression = self.compression.write().await;
        compression.reset_stats();
    }

    /// Get all active tunnels
    pub async fn get_tunnels(&self) -> Vec<TunnelEndpoint> {
        let tunnels = self.tunnels.read().await;
        tunnels.values().cloned().collect()
    }

    /// Get all routes
    pub async fn get_routes(&self) -> HashMap<IpAddr, PathId> {
        let routes = self.routes.read().await;
        routes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_dataplane() -> DataPlane {
        let config = DataPlaneConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // Random port
            ..Default::default()
        };

        DataPlane::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_dataplane_creation() {
        let dataplane = create_test_dataplane().await;
        let stats = dataplane.get_stats().await;
        assert_eq!(stats.packets_forwarded, 0);
    }

    #[tokio::test]
    async fn test_add_remove_tunnel() {
        let dataplane = create_test_dataplane().await;

        let tunnel = TunnelEndpoint {
            site_id: SiteId::generate(),
            path_id: PathId::new(1),
            remote_addr: "192.168.1.100:51822".parse().unwrap(),
            compression_enabled: true,
        };

        dataplane.add_tunnel(tunnel.clone()).await;

        let tunnels = dataplane.get_tunnels().await;
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].path_id, tunnel.path_id);

        dataplane.remove_tunnel(&tunnel.path_id).await;

        let tunnels = dataplane.get_tunnels().await;
        assert_eq!(tunnels.len(), 0);
    }

    #[tokio::test]
    async fn test_add_remove_route() {
        let dataplane = create_test_dataplane().await;

        let destination: IpAddr = "10.0.0.1".parse().unwrap();
        let path_id = PathId::new(1);

        dataplane.add_route(destination, path_id.clone()).await;

        let routes = dataplane.get_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes.get(&destination), Some(&path_id));

        dataplane.remove_route(&destination).await;

        let routes = dataplane.get_routes().await;
        assert_eq!(routes.len(), 0);
    }

    #[tokio::test]
    async fn test_forward_packet_no_route() {
        let dataplane = create_test_dataplane().await;

        let packet = b"Test packet";
        let destination: IpAddr = "10.0.0.1".parse().unwrap();

        let result = dataplane.forward_packet(packet, destination).await;
        assert!(result.is_err());

        let stats = dataplane.get_stats().await;
        assert_eq!(stats.packets_dropped, 1);
    }

    #[tokio::test]
    async fn test_compression_stats() {
        let dataplane = create_test_dataplane().await;

        let comp_stats = dataplane.get_compression_stats().await;
        assert_eq!(comp_stats.packets_compressed, 0);
    }
}
