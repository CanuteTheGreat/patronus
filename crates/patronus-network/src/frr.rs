//! Dynamic Routing with FRR (Free Range Routing)
//!
//! Provides integration with FRRouting for advanced routing protocols:
//! - BGP (Border Gateway Protocol) - Internet routing
//! - OSPF (Open Shortest Path First) - Internal routing
//! - RIP (Routing Information Protocol) - Simple distance-vector
//! - IS-IS, EIGRP, PIM, and more
//!
//! FRR is a Linux routing stack fork of Quagga, providing enterprise-grade
//! routing capabilities that rival Cisco and Juniper.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::net::IpAddr;
use std::collections::HashMap;
use tokio::fs;
use tokio::process::Command;

/// Routing protocol daemon
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingDaemon {
    /// Border Gateway Protocol (Internet routing)
    BGP,
    /// Open Shortest Path First (Link-state IGP)
    OSPF,
    /// OSPFv3 (OSPF for IPv6)
    OSPF6,
    /// Routing Information Protocol (Simple distance-vector)
    RIP,
    /// RIPng (RIP for IPv6)
    RIPNG,
    /// IS-IS (Intermediate System to Intermediate System)
    ISIS,
    /// EIGRP (Enhanced Interior Gateway Routing Protocol)
    EIGRP,
    /// PIM (Protocol Independent Multicast)
    PIM,
    /// BFD (Bidirectional Forwarding Detection)
    BFD,
}

impl std::fmt::Display for RoutingDaemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingDaemon::BGP => write!(f, "bgpd"),
            RoutingDaemon::OSPF => write!(f, "ospfd"),
            RoutingDaemon::OSPF6 => write!(f, "ospf6d"),
            RoutingDaemon::RIP => write!(f, "ripd"),
            RoutingDaemon::RIPNG => write!(f, "ripngd"),
            RoutingDaemon::ISIS => write!(f, "isisd"),
            RoutingDaemon::EIGRP => write!(f, "eigrpd"),
            RoutingDaemon::PIM => write!(f, "pimd"),
            RoutingDaemon::BFD => write!(f, "bfdd"),
        }
    }
}

/// BGP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    pub enabled: bool,
    pub asn: u32,  // Autonomous System Number
    pub router_id: IpAddr,
    pub networks: Vec<BgpNetwork>,
    pub neighbors: Vec<BgpNeighbor>,
    pub route_maps: Vec<RouteMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNetwork {
    pub prefix: String,  // "10.0.0.0/8"
    pub route_map: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighbor {
    pub address: IpAddr,
    pub remote_asn: u32,
    pub description: Option<String>,
    pub password: Option<String>,
    pub ebgp_multihop: Option<u8>,
    pub update_source: Option<String>,
    pub route_map_in: Option<String>,
    pub route_map_out: Option<String>,
    pub prefix_list_in: Option<String>,
    pub prefix_list_out: Option<String>,
}

/// OSPF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfConfig {
    pub enabled: bool,
    pub router_id: IpAddr,
    pub areas: Vec<OspfArea>,
    pub redistribute: Vec<RedistributeProtocol>,
    pub passive_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfArea {
    pub area_id: String,  // "0.0.0.0" for backbone
    pub networks: Vec<String>,  // ["10.0.1.0/24"]
    pub area_type: OspfAreaType,
    pub authentication: Option<OspfAuth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfAreaType {
    Normal,
    Stub,
    TotallyStubby,
    NSSA,
    TotallyNSSA,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OspfAuth {
    Simple { password: String },
    MD5 { key_id: u8, password: String },
}

/// RIP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RipConfig {
    pub enabled: bool,
    pub version: RipVersion,
    pub networks: Vec<String>,
    pub passive_interfaces: Vec<String>,
    pub redistribute: Vec<RedistributeProtocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RipVersion {
    V1,
    V2,
}

/// Protocol redistribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedistributeProtocol {
    pub protocol: String,  // "connected", "static", "ospf", "bgp"
    pub route_map: Option<String>,
    pub metric: Option<u32>,
}

/// Route map for policy-based routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteMap {
    pub name: String,
    pub action: RouteMapAction,
    pub sequence: u32,
    pub match_rules: Vec<RouteMapMatch>,
    pub set_actions: Vec<RouteMapSet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteMapAction {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteMapMatch {
    IpAddress { prefix_list: String },
    IpNextHop { prefix_list: String },
    AsPath { access_list: String },
    Community { list: String },
    Interface { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteMapSet {
    LocalPreference { value: u32 },
    Metric { value: u32 },
    NextHop { ip: IpAddr },
    AsPathPrepend { asn: u32, count: u8 },
    Community { community: String },
    Weight { value: u32 },
}

/// Prefix list for filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixList {
    pub name: String,
    pub entries: Vec<PrefixListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixListEntry {
    pub sequence: u32,
    pub action: PrefixListAction,
    pub prefix: String,
    pub ge: Option<u8>,  // Greater than or equal
    pub le: Option<u8>,  // Less than or equal
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrefixListAction {
    Permit,
    Deny,
}

pub struct FrrManager {
    config_dir: PathBuf,
    daemons: Vec<RoutingDaemon>,
}

impl FrrManager {
    pub fn new() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/frr"),
            daemons: Vec::new(),
        }
    }

    /// Check if FRR is installed
    pub fn is_available() -> bool {
        std::process::Command::new("which")
            .arg("vtysh")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Enable a routing daemon
    pub fn enable_daemon(&mut self, daemon: RoutingDaemon) {
        if !self.daemons.contains(&daemon) {
            self.daemons.push(daemon);
        }
    }

    /// Configure FRR daemons file
    pub async fn configure_daemons(&self) -> Result<()> {
        let mut config = String::from("# FRR Daemons - Managed by Patronus\n\n");

        config.push_str("# Always enabled\n");
        config.push_str("zebra=yes\n");
        config.push_str("staticd=yes\n\n");

        for daemon in &self.daemons {
            let daemon_name = daemon.to_string();
            config.push_str(&format!("{}=yes\n", daemon_name));
        }

        config.push_str("\n# Global options\n");
        config.push_str("vtysh_enable=yes\n");
        config.push_str("zebra_options=\"--retain -A 127.0.0.1 -s 90000000\"\n");

        let daemons_file = self.config_dir.join("daemons");
        fs::write(&daemons_file, config).await?;

        Ok(())
    }

    /// Configure BGP
    pub async fn configure_bgp(&mut self, config: &BgpConfig) -> Result<()> {
        if !config.enabled {
            return Ok(());
        }

        self.enable_daemon(RoutingDaemon::BGP);

        let bgp_config = self.generate_bgp_config(config)?;
        let config_file = self.config_dir.join("bgpd.conf");
        fs::write(&config_file, bgp_config).await?;

        Ok(())
    }

    fn generate_bgp_config(&self, config: &BgpConfig) -> Result<String> {
        let mut conf = String::from("! BGP Configuration - Managed by Patronus\n!\n");

        conf.push_str(&format!("hostname patronus-bgp\n"));
        conf.push_str(&format!("log syslog informational\n"));
        conf.push_str("!\n");

        // Router BGP
        conf.push_str(&format!("router bgp {}\n", config.asn));
        conf.push_str(&format!("  bgp router-id {}\n", config.router_id));
        conf.push_str("  bgp log-neighbor-changes\n");
        conf.push_str("  no bgp default ipv4-unicast\n");
        conf.push_str("!\n");

        // Neighbors
        for neighbor in &config.neighbors {
            conf.push_str(&format!("  neighbor {} remote-as {}\n",
                neighbor.address, neighbor.remote_asn));

            if let Some(ref desc) = neighbor.description {
                conf.push_str(&format!("  neighbor {} description {}\n",
                    neighbor.address, desc));
            }

            if let Some(ref password) = neighbor.password {
                conf.push_str(&format!("  neighbor {} password {}\n",
                    neighbor.address, password));
            }

            if let Some(multihop) = neighbor.ebgp_multihop {
                conf.push_str(&format!("  neighbor {} ebgp-multihop {}\n",
                    neighbor.address, multihop));
            }

            if let Some(ref source) = neighbor.update_source {
                conf.push_str(&format!("  neighbor {} update-source {}\n",
                    neighbor.address, source));
            }
        }

        conf.push_str("!\n");

        // Address families
        conf.push_str("  address-family ipv4 unicast\n");

        for network in &config.networks {
            conf.push_str(&format!("    network {}\n", network.prefix));
            if let Some(ref route_map) = network.route_map {
                conf.push_str(&format!("      route-map {} out\n", route_map));
            }
        }

        for neighbor in &config.neighbors {
            conf.push_str(&format!("    neighbor {} activate\n", neighbor.address));

            if let Some(ref rm) = neighbor.route_map_in {
                conf.push_str(&format!("    neighbor {} route-map {} in\n",
                    neighbor.address, rm));
            }

            if let Some(ref rm) = neighbor.route_map_out {
                conf.push_str(&format!("    neighbor {} route-map {} out\n",
                    neighbor.address, rm));
            }

            if let Some(ref pl) = neighbor.prefix_list_in {
                conf.push_str(&format!("    neighbor {} prefix-list {} in\n",
                    neighbor.address, pl));
            }

            if let Some(ref pl) = neighbor.prefix_list_out {
                conf.push_str(&format!("    neighbor {} prefix-list {} out\n",
                    neighbor.address, pl));
            }
        }

        conf.push_str("  exit-address-family\n");
        conf.push_str("!\n");

        // Route maps
        for route_map in &config.route_maps {
            let action = match route_map.action {
                RouteMapAction::Permit => "permit",
                RouteMapAction::Deny => "deny",
            };

            conf.push_str(&format!("route-map {} {} {}\n",
                route_map.name, action, route_map.sequence));

            for match_rule in &route_map.match_rules {
                match match_rule {
                    RouteMapMatch::IpAddress { prefix_list } => {
                        conf.push_str(&format!("  match ip address prefix-list {}\n", prefix_list));
                    }
                    RouteMapMatch::AsPath { access_list } => {
                        conf.push_str(&format!("  match as-path {}\n", access_list));
                    }
                    RouteMapMatch::Community { list } => {
                        conf.push_str(&format!("  match community {}\n", list));
                    }
                    _ => {}
                }
            }

            for set_action in &route_map.set_actions {
                match set_action {
                    RouteMapSet::LocalPreference { value } => {
                        conf.push_str(&format!("  set local-preference {}\n", value));
                    }
                    RouteMapSet::Metric { value } => {
                        conf.push_str(&format!("  set metric {}\n", value));
                    }
                    RouteMapSet::NextHop { ip } => {
                        conf.push_str(&format!("  set ip next-hop {}\n", ip));
                    }
                    RouteMapSet::AsPathPrepend { asn, count } => {
                        let prepend = (0..*count).map(|_| asn.to_string()).collect::<Vec<_>>().join(" ");
                        conf.push_str(&format!("  set as-path prepend {}\n", prepend));
                    }
                    RouteMapSet::Community { community } => {
                        conf.push_str(&format!("  set community {}\n", community));
                    }
                    RouteMapSet::Weight { value } => {
                        conf.push_str(&format!("  set weight {}\n", value));
                    }
                }
            }

            conf.push_str("!\n");
        }

        conf.push_str("line vty\n!\n");

        Ok(conf)
    }

    /// Configure OSPF
    pub async fn configure_ospf(&mut self, config: &OspfConfig) -> Result<()> {
        if !config.enabled {
            return Ok(());
        }

        self.enable_daemon(RoutingDaemon::OSPF);

        let ospf_config = self.generate_ospf_config(config)?;
        let config_file = self.config_dir.join("ospfd.conf");
        fs::write(&config_file, ospf_config).await?;

        Ok(())
    }

    fn generate_ospf_config(&self, config: &OspfConfig) -> Result<String> {
        let mut conf = String::from("! OSPF Configuration - Managed by Patronus\n!\n");

        conf.push_str("hostname patronus-ospf\n");
        conf.push_str("log syslog informational\n");
        conf.push_str("!\n");

        // Router OSPF
        conf.push_str("router ospf\n");
        conf.push_str(&format!("  ospf router-id {}\n", config.router_id));
        conf.push_str("  log-adjacency-changes\n");
        conf.push_str("!\n");

        // Areas and networks
        for area in &config.areas {
            for network in &area.networks {
                conf.push_str(&format!("  network {} area {}\n",
                    network, area.area_id));
            }

            // Area type
            match area.area_type {
                OspfAreaType::Stub => {
                    conf.push_str(&format!("  area {} stub\n", area.area_id));
                }
                OspfAreaType::TotallyStubby => {
                    conf.push_str(&format!("  area {} stub no-summary\n", area.area_id));
                }
                OspfAreaType::NSSA => {
                    conf.push_str(&format!("  area {} nssa\n", area.area_id));
                }
                OspfAreaType::TotallyNSSA => {
                    conf.push_str(&format!("  area {} nssa no-summary\n", area.area_id));
                }
                OspfAreaType::Normal => {}
            }

            // Authentication
            if let Some(ref auth) = area.authentication {
                match auth {
                    OspfAuth::Simple { password } => {
                        conf.push_str(&format!("  area {} authentication\n", area.area_id));
                    }
                    OspfAuth::MD5 { key_id, password } => {
                        conf.push_str(&format!("  area {} authentication message-digest\n",
                            area.area_id));
                    }
                }
            }
        }

        // Passive interfaces
        for iface in &config.passive_interfaces {
            conf.push_str(&format!("  passive-interface {}\n", iface));
        }

        // Redistribution
        for redist in &config.redistribute {
            let mut redist_line = format!("  redistribute {}", redist.protocol);
            if let Some(metric) = redist.metric {
                redist_line.push_str(&format!(" metric {}", metric));
            }
            if let Some(ref route_map) = redist.route_map {
                redist_line.push_str(&format!(" route-map {}", route_map));
            }
            conf.push_str(&format!("{}\n", redist_line));
        }

        conf.push_str("!\n");
        conf.push_str("line vty\n!\n");

        Ok(conf)
    }

    /// Configure RIP
    pub async fn configure_rip(&mut self, config: &RipConfig) -> Result<()> {
        if !config.enabled {
            return Ok(());
        }

        self.enable_daemon(RoutingDaemon::RIP);

        let rip_config = self.generate_rip_config(config)?;
        let config_file = self.config_dir.join("ripd.conf");
        fs::write(&config_file, rip_config).await?;

        Ok(())
    }

    fn generate_rip_config(&self, config: &RipConfig) -> Result<String> {
        let mut conf = String::from("! RIP Configuration - Managed by Patronus\n!\n");

        conf.push_str("hostname patronus-rip\n");
        conf.push_str("log syslog informational\n");
        conf.push_str("!\n");

        conf.push_str("router rip\n");

        let version = match config.version {
            RipVersion::V1 => "1",
            RipVersion::V2 => "2",
        };
        conf.push_str(&format!("  version {}\n", version));

        for network in &config.networks {
            conf.push_str(&format!("  network {}\n", network));
        }

        for iface in &config.passive_interfaces {
            conf.push_str(&format!("  passive-interface {}\n", iface));
        }

        for redist in &config.redistribute {
            conf.push_str(&format!("  redistribute {}\n", redist.protocol));
        }

        conf.push_str("!\n");
        conf.push_str("line vty\n!\n");

        Ok(conf)
    }

    /// Apply configuration and restart FRR
    pub async fn apply(&self) -> Result<()> {
        // Reload FRR
        Command::new("systemctl")
            .arg("reload")
            .arg("frr")
            .spawn()
            .map_err(|e| Error::Firewall(format!("Failed to reload FRR: {}", e)))?
            .wait()
            .await
            .map_err(|e| Error::Firewall(format!("FRR reload failed: {}", e)))?;

        Ok(())
    }

    /// Execute vtysh command
    pub async fn vtysh(&self, command: &str) -> Result<String> {
        let output = Command::new("vtysh")
            .arg("-c")
            .arg(command)
            .output()
            .await
            .map_err(|e| Error::Firewall(format!("vtysh command failed: {}", e)))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Show BGP summary
    pub async fn show_bgp_summary(&self) -> Result<String> {
        self.vtysh("show ip bgp summary").await
    }

    /// Show OSPF neighbors
    pub async fn show_ospf_neighbors(&self) -> Result<String> {
        self.vtysh("show ip ospf neighbor").await
    }

    /// Show routing table
    pub async fn show_routes(&self) -> Result<String> {
        self.vtysh("show ip route").await
    }
}

impl Default for BgpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            asn: 65000,  // Private ASN
            router_id: "192.168.1.1".parse().unwrap(),
            networks: Vec::new(),
            neighbors: Vec::new(),
            route_maps: Vec::new(),
        }
    }
}

impl Default for OspfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            router_id: "192.168.1.1".parse().unwrap(),
            areas: vec![
                OspfArea {
                    area_id: "0.0.0.0".to_string(),  // Backbone
                    networks: vec!["192.168.1.0/24".to_string()],
                    area_type: OspfAreaType::Normal,
                    authentication: None,
                },
            ],
            redistribute: Vec::new(),
            passive_interfaces: Vec::new(),
        }
    }
}

impl Default for RipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            version: RipVersion::V2,
            networks: Vec::new(),
            passive_interfaces: Vec::new(),
            redistribute: Vec::new(),
        }
    }
}
