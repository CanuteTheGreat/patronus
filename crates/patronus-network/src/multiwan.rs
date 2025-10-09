//! Multi-WAN support with load balancing and failover
//!
//! Provides WAN gateway management, health monitoring, load balancing,
//! and automatic failover.

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Gateway monitoring method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MonitorMethod {
    Ping,      // ICMP ping
    TcpPort,   // TCP connection test
    HttpGet,   // HTTP GET request
}

/// Gateway status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GatewayStatus {
    Online,
    Offline,
    Degraded,
    Unknown,
}

/// Load balancing algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoadBalanceAlgorithm {
    RoundRobin,      // Simple round-robin
    WeightedRandom,  // Weighted random selection
    LeastConnections, // Least connections (stateful)
    Failover,        // Primary/backup only
}

/// WAN gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanGateway {
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    pub gateway_ip: IpAddr,
    pub weight: u32,  // For load balancing (1-100)
    pub priority: u32, // Lower = higher priority (for failover)

    // Monitoring
    pub monitor_enabled: bool,
    pub monitor_method: MonitorMethod,
    pub monitor_target: Option<String>,  // IP or hostname to monitor
    pub monitor_interval: u32,  // seconds
    pub monitor_timeout: u32,   // seconds
    pub failure_threshold: u32, // Consecutive failures before marking down
    pub recovery_threshold: u32, // Consecutive successes before marking up

    // Metrics
    pub latency_ms: Option<f64>,
    pub packet_loss: Option<f64>,
    pub last_check: Option<SystemTime>,
    pub status: GatewayStatus,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

impl Default for WanGateway {
    fn default() -> Self {
        Self {
            name: "wan1".to_string(),
            enabled: true,
            interface: "eth0".to_string(),
            gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            weight: 50,
            priority: 1,
            monitor_enabled: true,
            monitor_method: MonitorMethod::Ping,
            monitor_target: Some("8.8.8.8".to_string()),
            monitor_interval: 10,
            monitor_timeout: 5,
            failure_threshold: 3,
            recovery_threshold: 3,
            latency_ms: None,
            packet_loss: None,
            last_check: None,
            status: GatewayStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }
}

/// Gateway group (for load balancing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayGroup {
    pub name: String,
    pub enabled: bool,
    pub algorithm: LoadBalanceAlgorithm,
    pub gateways: Vec<String>,  // Gateway names
    pub sticky: bool,  // Use source-based hashing for session persistence
}

/// Policy-based routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRoute {
    pub name: String,
    pub enabled: bool,
    pub priority: u32,

    // Match criteria
    pub source_network: Option<String>,  // CIDR
    pub destination_network: Option<String>,
    pub protocol: Option<String>,  // tcp, udp, icmp
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,

    // Action
    pub gateway_group: String,  // Which gateway group to use
}

/// Multi-WAN manager
pub struct MultiWanManager {
    gateways: Arc<RwLock<HashMap<String, WanGateway>>>,
    groups: Arc<RwLock<HashMap<String, GatewayGroup>>>,
    policies: Arc<RwLock<Vec<PolicyRoute>>>,
    monitoring_enabled: Arc<RwLock<bool>>,
}

impl MultiWanManager {
    /// Create a new Multi-WAN manager
    pub fn new() -> Self {
        Self {
            gateways: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(Vec::new())),
            monitoring_enabled: Arc::new(RwLock::new(false)),
        }
    }

    /// Add a WAN gateway
    pub async fn add_gateway(&self, gateway: WanGateway) -> Result<()> {
        let mut gateways = self.gateways.write().await;
        gateways.insert(gateway.name.clone(), gateway);
        Ok(())
    }

    /// Remove a WAN gateway
    pub async fn remove_gateway(&self, name: &str) -> Result<()> {
        let mut gateways = self.gateways.write().await;
        gateways.remove(name);
        Ok(())
    }

    /// Get gateway status
    pub async fn get_gateway(&self, name: &str) -> Result<WanGateway> {
        let gateways = self.gateways.read().await;
        gateways.get(name)
            .cloned()
            .ok_or_else(|| Error::Network(format!("Gateway not found: {}", name)))
    }

    /// List all gateways
    pub async fn list_gateways(&self) -> Result<Vec<WanGateway>> {
        let gateways = self.gateways.read().await;
        Ok(gateways.values().cloned().collect())
    }

    /// Add a gateway group
    pub async fn add_group(&self, group: GatewayGroup) -> Result<()> {
        let mut groups = self.groups.write().await;
        groups.insert(group.name.clone(), group);
        Ok(())
    }

    /// Remove a gateway group
    pub async fn remove_group(&self, name: &str) -> Result<()> {
        let mut groups = self.groups.write().await;
        groups.remove(name);
        Ok(())
    }

    /// List all groups
    pub async fn list_groups(&self) -> Result<Vec<GatewayGroup>> {
        let groups = self.groups.read().await;
        Ok(groups.values().cloned().collect())
    }

    /// Add a policy route
    pub async fn add_policy(&self, policy: PolicyRoute) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.push(policy);
        policies.sort_by_key(|p| p.priority);
        Ok(())
    }

    /// Remove a policy route
    pub async fn remove_policy(&self, name: &str) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.retain(|p| p.name != name);
        Ok(())
    }

    /// List all policies
    pub async fn list_policies(&self) -> Result<Vec<PolicyRoute>> {
        let policies = self.policies.read().await;
        Ok(policies.clone())
    }

    /// Monitor a single gateway (internal)
    async fn monitor_gateway(&self, gateway_name: &str) -> Result<()> {
        let mut gateway = {
            let gateways = self.gateways.read().await;
            gateways.get(gateway_name)
                .ok_or_else(|| Error::Network(format!("Gateway not found: {}", gateway_name)))?
                .clone()
        };

        if !gateway.enabled || !gateway.monitor_enabled {
            return Ok(());
        }

        let target = gateway.monitor_target.as_ref()
            .ok_or_else(|| Error::Network("No monitor target configured".to_string()))?;

        // Perform health check
        let (is_up, latency) = match gateway.monitor_method {
            MonitorMethod::Ping => self.ping_check(target, gateway.monitor_timeout).await?,
            MonitorMethod::TcpPort => {
                // Parse target as host:port
                self.tcp_check(target, gateway.monitor_timeout).await?
            }
            MonitorMethod::HttpGet => {
                self.http_check(target, gateway.monitor_timeout).await?
            }
        };

        gateway.last_check = Some(SystemTime::now());
        gateway.latency_ms = latency;

        // Update status based on threshold
        if is_up {
            gateway.consecutive_failures = 0;
            gateway.consecutive_successes += 1;

            if gateway.consecutive_successes >= gateway.recovery_threshold {
                if gateway.status != GatewayStatus::Online {
                    tracing::info!("Gateway {} is now ONLINE", gateway_name);
                    gateway.status = GatewayStatus::Online;
                }
            }
        } else {
            gateway.consecutive_successes = 0;
            gateway.consecutive_failures += 1;

            if gateway.consecutive_failures >= gateway.failure_threshold {
                if gateway.status != GatewayStatus::Offline {
                    tracing::warn!("Gateway {} is now OFFLINE", gateway_name);
                    gateway.status = GatewayStatus::Offline;
                }
            }
        }

        // Update gateway in map
        let mut gateways = self.gateways.write().await;
        gateways.insert(gateway_name.to_string(), gateway);

        Ok(())
    }

    /// Ping check
    async fn ping_check(&self, target: &str, timeout: u32) -> Result<(bool, Option<f64>)> {
        let output = Command::new("ping")
            .args(&["-c", "1", "-W", &timeout.to_string(), target])
            .output()
            .map_err(|e| Error::Network(format!("Ping failed: {}", e)))?;

        let is_up = output.status.success();
        let latency = if is_up {
            // Parse latency from output (simplified)
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.lines()
                .find(|line| line.contains("time="))
                .and_then(|line| {
                    line.split("time=")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .and_then(|s| s.parse::<f64>().ok())
                })
        } else {
            None
        };

        Ok((is_up, latency))
    }

    /// TCP port check
    async fn tcp_check(&self, target: &str, timeout: u32) -> Result<(bool, Option<f64>)> {
        // Use tokio::net::TcpStream with timeout
        let parts: Vec<&str> = target.split(':').collect();
        if parts.len() != 2 {
            return Err(Error::Network("Invalid TCP target format (use host:port)".to_string()));
        }

        let start = SystemTime::now();
        let result = tokio::time::timeout(
            Duration::from_secs(timeout as u64),
            tokio::net::TcpStream::connect(target)
        ).await;

        let is_up = result.is_ok() && result.unwrap().is_ok();
        let latency = if is_up {
            start.elapsed().ok().map(|d| d.as_secs_f64() * 1000.0)
        } else {
            None
        };

        Ok((is_up, latency))
    }

    /// HTTP GET check
    async fn http_check(&self, url: &str, timeout: u32) -> Result<(bool, Option<f64>)> {
        // Simple HTTP check (would use reqwest in production)
        let start = SystemTime::now();

        // For now, just use TCP check on port 80/443
        let host = url.trim_start_matches("http://").trim_start_matches("https://");
        let port = if url.starts_with("https://") { 443 } else { 80 };
        let target = format!("{}:{}", host.split('/').next().unwrap_or(host), port);

        let (is_up, _) = self.tcp_check(&target, timeout).await?;
        let latency = if is_up {
            start.elapsed().ok().map(|d| d.as_secs_f64() * 1000.0)
        } else {
            None
        };

        Ok((is_up, latency))
    }

    /// Start monitoring all gateways
    pub async fn start_monitoring(&self) -> Result<()> {
        *self.monitoring_enabled.write().await = true;

        // Spawn monitoring task
        let gateways = self.gateways.clone();
        let monitoring_enabled = self.monitoring_enabled.clone();
        let manager = self.clone_for_monitoring();

        tokio::spawn(async move {
            while *monitoring_enabled.read().await {
                let gateway_names: Vec<String> = {
                    let gateways_lock = gateways.read().await;
                    gateways_lock.keys().cloned().collect()
                };

                for name in gateway_names {
                    if let Err(e) = manager.monitor_gateway(&name).await {
                        tracing::error!("Failed to monitor gateway {}: {}", name, e);
                    }
                }

                // Sleep between monitoring cycles
                sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    /// Stop monitoring
    pub async fn stop_monitoring(&self) -> Result<()> {
        *self.monitoring_enabled.write().await = false;
        Ok(())
    }

    /// Clone for monitoring task
    fn clone_for_monitoring(&self) -> Self {
        Self {
            gateways: self.gateways.clone(),
            groups: self.groups.clone(),
            policies: self.policies.clone(),
            monitoring_enabled: self.monitoring_enabled.clone(),
        }
    }

    /// Apply load balancing configuration
    pub async fn apply_load_balancing(&self) -> Result<()> {
        let groups = self.groups.read().await;
        let gateways = self.gateways.read().await;

        for (group_name, group) in groups.iter() {
            if !group.enabled {
                continue;
            }

            // Get online gateways in this group
            let online_gateways: Vec<&WanGateway> = group.gateways.iter()
                .filter_map(|gw_name| gateways.get(gw_name))
                .filter(|gw| gw.enabled && gw.status == GatewayStatus::Online)
                .collect();

            if online_gateways.is_empty() {
                tracing::warn!("No online gateways in group {}", group_name);
                continue;
            }

            // Configure routing based on algorithm
            match group.algorithm {
                LoadBalanceAlgorithm::RoundRobin => {
                    self.configure_round_robin(&online_gateways).await?;
                }
                LoadBalanceAlgorithm::WeightedRandom => {
                    self.configure_weighted(&online_gateways).await?;
                }
                LoadBalanceAlgorithm::LeastConnections => {
                    self.configure_least_connections(&online_gateways).await?;
                }
                LoadBalanceAlgorithm::Failover => {
                    self.configure_failover(&online_gateways).await?;
                }
            }
        }

        Ok(())
    }

    /// Configure round-robin load balancing
    async fn configure_round_robin(&self, gateways: &[&WanGateway]) -> Result<()> {
        // Use iproute2 multipath routing
        let mut nexthops = String::new();
        for gw in gateways {
            nexthops.push_str(&format!("nexthop via {} dev {} weight 1 ",
                gw.gateway_ip, gw.interface));
        }

        // Add multipath default route
        Command::new("ip")
            .args(&["route", "replace", "default"])
            .arg(&nexthops.trim())
            .output()
            .map_err(|e| Error::Network(format!("Failed to configure routing: {}", e)))?;

        Ok(())
    }

    /// Configure weighted load balancing
    async fn configure_weighted(&self, gateways: &[&WanGateway]) -> Result<()> {
        let mut nexthops = String::new();
        for gw in gateways {
            nexthops.push_str(&format!("nexthop via {} dev {} weight {} ",
                gw.gateway_ip, gw.interface, gw.weight));
        }

        Command::new("ip")
            .args(&["route", "replace", "default"])
            .arg(&nexthops.trim())
            .output()
            .map_err(|e| Error::Network(format!("Failed to configure routing: {}", e)))?;

        Ok(())
    }

    /// Configure least connections (simplified)
    async fn configure_least_connections(&self, gateways: &[&WanGateway]) -> Result<()> {
        // For now, same as round-robin
        // Full implementation would track connection counts
        self.configure_round_robin(gateways).await
    }

    /// Configure failover routing
    async fn configure_failover(&self, gateways: &[&WanGateway]) -> Result<()> {
        // Use highest priority (lowest number) gateway
        if let Some(primary) = gateways.iter()
            .min_by_key(|gw| gw.priority) {

            Command::new("ip")
                .args(&["route", "replace", "default", "via"])
                .arg(primary.gateway_ip.to_string())
                .args(&["dev", &primary.interface])
                .output()
                .map_err(|e| Error::Network(format!("Failed to configure routing: {}", e)))?;
        }

        Ok(())
    }

    /// Apply policy-based routing
    pub async fn apply_policies(&self) -> Result<()> {
        let policies = self.policies.read().await;
        let groups = self.groups.read().await;
        let gateways = self.gateways.read().await;

        // Create routing tables for each gateway group
        for (table_id, policy) in policies.iter().enumerate() {
            if !policy.enabled {
                continue;
            }

            let table_id = table_id + 100; // Start at table 100

            // Get group
            let group = groups.get(&policy.gateway_group)
                .ok_or_else(|| Error::Network(format!("Group not found: {}", policy.gateway_group)))?;

            // Get online gateways
            let online_gateways: Vec<&WanGateway> = group.gateways.iter()
                .filter_map(|gw_name| gateways.get(gw_name))
                .filter(|gw| gw.enabled && gw.status == GatewayStatus::Online)
                .collect();

            if online_gateways.is_empty() {
                continue;
            }

            // Create routing rule
            let mut rule_args = vec!["rule", "add"];

            if let Some(src) = &policy.source_network {
                rule_args.extend(&["from", src]);
            }
            if let Some(dst) = &policy.destination_network {
                rule_args.extend(&["to", dst]);
            }

            rule_args.extend(&["table", &table_id.to_string(), "priority", &policy.priority.to_string()]);

            Command::new("ip")
                .args(&rule_args)
                .output()
                .map_err(|e| Error::Network(format!("Failed to add routing rule: {}", e)))?;

            // Configure route in table
            // (simplified - would configure based on group algorithm)
            if let Some(gw) = online_gateways.first() {
                Command::new("ip")
                    .args(&["route", "replace", "default", "via"])
                    .arg(gw.gateway_ip.to_string())
                    .args(&["dev", &gw.interface, "table", &table_id.to_string()])
                    .output()
                    .map_err(|e| Error::Network(format!("Failed to add route: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Get statistics for all gateways
    pub async fn get_statistics(&self) -> Result<HashMap<String, GatewayStats>> {
        let gateways = self.gateways.read().await;
        let mut stats = HashMap::new();

        for (name, gw) in gateways.iter() {
            stats.insert(name.clone(), GatewayStats {
                status: gw.status.clone(),
                latency_ms: gw.latency_ms,
                packet_loss: gw.packet_loss,
                uptime_seconds: gw.last_check.and_then(|check| {
                    check.elapsed().ok().map(|d| d.as_secs())
                }),
            });
        }

        Ok(stats)
    }
}

impl Default for MultiWanManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Gateway statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStats {
    pub status: GatewayStatus,
    pub latency_ms: Option<f64>,
    pub packet_loss: Option<f64>,
    pub uptime_seconds: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_gateway() {
        let manager = MultiWanManager::new();
        let gateway = WanGateway::default();

        manager.add_gateway(gateway.clone()).await.unwrap();

        let retrieved = manager.get_gateway(&gateway.name).await.unwrap();
        assert_eq!(retrieved.name, gateway.name);
    }

    #[tokio::test]
    async fn test_gateway_group() {
        let manager = MultiWanManager::new();

        let group = GatewayGroup {
            name: "group1".to_string(),
            enabled: true,
            algorithm: LoadBalanceAlgorithm::RoundRobin,
            gateways: vec!["wan1".to_string(), "wan2".to_string()],
            sticky: false,
        };

        manager.add_group(group).await.unwrap();

        let groups = manager.list_groups().await.unwrap();
        assert_eq!(groups.len(), 1);
    }
}
