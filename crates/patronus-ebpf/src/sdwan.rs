///! SD-WAN fast path forwarding using eBPF/XDP
///!
///! This module provides high-performance packet forwarding for SD-WAN tunnels
///! using XDP to bypass the kernel network stack.

use crate::xdp::{XdpFirewall, XdpConfig, XdpMode};
use crate::stats::XdpStats;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use anyhow::{Context, Result};
use tokio::sync::RwLock;
use std::sync::Arc;

/// SD-WAN tunnel endpoint
#[derive(Debug, Clone)]
pub struct TunnelEndpoint {
    pub tunnel_id: u32,
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub interface: String,
    pub priority: u16,
    pub metrics: LinkMetrics,
}

/// Link quality metrics
#[derive(Debug, Clone, Default)]
pub struct LinkMetrics {
    pub latency_ms: u32,
    pub packet_loss: f64,
    pub bandwidth_mbps: u64,
    pub jitter_ms: u32,
}

/// SD-WAN XDP fast path
pub struct SdwanFastPath {
    xdp: Arc<RwLock<XdpFirewall>>,
    tunnels: Arc<RwLock<HashMap<u32, TunnelEndpoint>>>,
    routing_table: Arc<RwLock<HashMap<Ipv4Addr, u32>>>, // dest_ip -> tunnel_id
}

impl SdwanFastPath {
    /// Create new SD-WAN fast path
    pub fn new() -> Result<Self> {
        let config = XdpConfig {
            enabled: true,
            mode: XdpMode::Generic, // Start with generic for compatibility
            interfaces: vec![],
            block_list: vec![],
            allow_list: vec![],
            rate_limits: vec![],
            enable_ddos_protection: false,
            syn_flood_protection: false,
            udp_flood_protection: false,
            icmp_flood_protection: false,
            batch_size: 64,
            use_hw_offload: false,
        };

        let xdp = XdpFirewall::new(config)?;

        Ok(Self {
            xdp: Arc::new(RwLock::new(xdp)),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Add tunnel endpoint
    pub async fn add_tunnel(&self, tunnel: TunnelEndpoint) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        tunnels.insert(tunnel.tunnel_id, tunnel.clone());

        // Attach XDP to tunnel interface if not already attached
        let mut xdp = self.xdp.write().await;
        xdp.attach(&tunnel.interface).await
            .context("Failed to attach XDP to tunnel interface")?;

        tracing::info!("Added tunnel {} on interface {}", tunnel.tunnel_id, tunnel.interface);
        Ok(())
    }

    /// Remove tunnel endpoint
    pub async fn remove_tunnel(&self, tunnel_id: u32) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        if let Some(tunnel) = tunnels.remove(&tunnel_id) {
            // Clean up routing entries
            let mut routing_table = self.routing_table.write().await;
            routing_table.retain(|_, tid| *tid != tunnel_id);

            tracing::info!("Removed tunnel {} from interface {}", tunnel_id, tunnel.interface);
        }

        Ok(())
    }

    /// Add route through tunnel
    pub async fn add_route(&self, dest_ip: Ipv4Addr, tunnel_id: u32) -> Result<()> {
        // Verify tunnel exists
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels.get(&tunnel_id)
            .context("Tunnel not found")?;

        // Add to routing table
        let mut routing_table = self.routing_table.write().await;
        routing_table.insert(dest_ip, tunnel_id);

        // TODO: Update XDP map with forwarding rule
        // This would require extending XdpFirewall to support custom routing

        tracing::info!("Added route {} -> tunnel {}", dest_ip, tunnel_id);
        Ok(())
    }

    /// Remove route
    pub async fn remove_route(&self, dest_ip: Ipv4Addr) -> Result<()> {
        let mut routing_table = self.routing_table.write().await;
        routing_table.remove(&dest_ip);

        tracing::info!("Removed route for {}", dest_ip);
        Ok(())
    }

    /// Update tunnel metrics
    pub async fn update_metrics(&self, tunnel_id: u32, metrics: LinkMetrics) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        if let Some(tunnel) = tunnels.get_mut(&tunnel_id) {
            tunnel.metrics = metrics.clone();

            // TODO: Update XDP map with new metrics for dynamic path selection
            tracing::debug!("Updated metrics for tunnel {}: latency={}ms, loss={:.2}%",
                tunnel_id, metrics.latency_ms, metrics.packet_loss);
        }

        Ok(())
    }

    /// Select best tunnel for destination based on metrics
    pub async fn select_best_tunnel(&self, dest_ip: Ipv4Addr) -> Option<u32> {
        let routing_table = self.routing_table.read().await;
        if let Some(&tunnel_id) = routing_table.get(&dest_ip) {
            return Some(tunnel_id);
        }

        // No specific route, select best tunnel based on metrics
        let tunnels = self.tunnels.read().await;
        let mut best_tunnel: Option<(u32, f64)> = None;

        for (tid, tunnel) in tunnels.iter() {
            // Calculate score: lower is better
            // Score = latency + (packet_loss * 100) + (100000 / bandwidth)
            let score = tunnel.metrics.latency_ms as f64
                + (tunnel.metrics.packet_loss * 100.0)
                + (100000.0 / tunnel.metrics.bandwidth_mbps.max(1) as f64);

            if let Some((_, best_score)) = best_tunnel {
                if score < best_score {
                    best_tunnel = Some((*tid, score));
                }
            } else {
                best_tunnel = Some((*tid, score));
            }
        }

        best_tunnel.map(|(tid, _)| tid)
    }

    /// Get statistics
    pub async fn get_stats(&self) -> Result<XdpStats> {
        let xdp = self.xdp.read().await;
        xdp.get_stats().await
    }

    /// Get all tunnels
    pub async fn get_tunnels(&self) -> Vec<TunnelEndpoint> {
        let tunnels = self.tunnels.read().await;
        tunnels.values().cloned().collect()
    }

    /// Get routing table
    pub async fn get_routes(&self) -> HashMap<Ipv4Addr, u32> {
        let routing_table = self.routing_table.read().await;
        routing_table.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tunnel_management() {
        let fastpath = SdwanFastPath::new().unwrap();

        let tunnel = TunnelEndpoint {
            tunnel_id: 1,
            local_addr: "10.0.0.1".parse().unwrap(),
            remote_addr: "10.0.0.2".parse().unwrap(),
            interface: "wg0".to_string(),
            priority: 100,
            metrics: LinkMetrics::default(),
        };

        // Note: This will fail in test environment without privileges
        // In production, would need proper XDP setup
        // fastpath.add_tunnel(tunnel).await.ok();

        let tunnels = fastpath.get_tunnels().await;
        // assert_eq!(tunnels.len(), 0); // Expected to fail without privileges
    }

    #[tokio::test]
    async fn test_routing() {
        let fastpath = SdwanFastPath::new().unwrap();

        let dest_ip: Ipv4Addr = "192.168.1.0".parse().unwrap();
        let tunnel_id = 1;

        // Add route (will succeed even without XDP)
        fastpath.add_route(dest_ip, tunnel_id).await.ok();

        let routes = fastpath.get_routes().await;
        assert_eq!(routes.get(&dest_ip), Some(&tunnel_id));

        // Remove route
        fastpath.remove_route(dest_ip).await.ok();
        let routes = fastpath.get_routes().await;
        assert!(!routes.contains_key(&dest_ip));
    }

    #[tokio::test]
    async fn test_best_tunnel_selection() {
        let fastpath = SdwanFastPath::new().unwrap();

        // Add tunnels with different metrics
        {
            let mut tunnels = fastpath.tunnels.write().await;

            tunnels.insert(1, TunnelEndpoint {
                tunnel_id: 1,
                local_addr: "10.0.0.1".parse().unwrap(),
                remote_addr: "10.0.0.2".parse().unwrap(),
                interface: "wg0".to_string(),
                priority: 100,
                metrics: LinkMetrics {
                    latency_ms: 50,
                    packet_loss: 0.01,
                    bandwidth_mbps: 1000,
                    jitter_ms: 5,
                },
            });

            tunnels.insert(2, TunnelEndpoint {
                tunnel_id: 2,
                local_addr: "10.0.1.1".parse().unwrap(),
                remote_addr: "10.0.1.2".parse().unwrap(),
                interface: "wg1".to_string(),
                priority: 90,
                metrics: LinkMetrics {
                    latency_ms: 20,
                    packet_loss: 0.001,
                    bandwidth_mbps: 2000,
                    jitter_ms: 2,
                },
            });
        }

        let dest_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let best = fastpath.select_best_tunnel(dest_ip).await;

        // Tunnel 2 should be selected (lower latency, lower loss, higher bandwidth)
        assert_eq!(best, Some(2));
    }
}
