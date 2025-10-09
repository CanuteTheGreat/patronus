//! Dynamic routing with FRR (Free Range Routing)
//!
//! This example demonstrates how to configure enterprise routing protocols
//! with Patronus using FRRouting.

use patronus_network::frr::{
    FrrManager, BgpConfig, BgpNetwork, BgpNeighbor, OspfConfig, OspfArea,
    OspfAreaType, RipConfig, RipVersion, RedistributeProtocol, RouteMap,
    RouteMapAction, RouteMapMatch, RouteMapSet,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Patronus Dynamic Routing Setup ===\n");

    // Check if FRR is installed
    if !FrrManager::is_available() {
        eprintln!("ERROR: FRRouting is not installed!");
        eprintln!("Install it with:");
        eprintln!("  emerge net-misc/frr");
        eprintln!("Or visit: https://frrouting.org/");
        return Ok(());
    }

    println!("✓ FRRouting detected\n");

    let mut frr_mgr = FrrManager::new();

    // Example 1: BGP Configuration (ISP peering)
    println!("=== Example 1: BGP Configuration ===\n");
    println!("Use case: Multi-homed site with two ISPs\n");

    let bgp_config = BgpConfig {
        enabled: true,
        asn: 65001,  // Your AS number
        router_id: "192.168.1.1".parse().unwrap(),

        // Advertise your networks
        networks: vec![
            BgpNetwork {
                prefix: "203.0.113.0/24".to_string(),  // Your public IP range
                route_map: None,
            },
        ],

        // BGP neighbors (ISP peering)
        neighbors: vec![
            // ISP 1
            BgpNeighbor {
                address: "198.51.100.1".parse().unwrap(),
                remote_asn: 64500,  // ISP 1's AS number
                description: Some("ISP1 - Primary".to_string()),
                password: Some("secretpass123".to_string()),
                ebgp_multihop: None,
                update_source: Some("eth1".to_string()),
                route_map_in: Some("ISP1-IN".to_string()),
                route_map_out: Some("ISP1-OUT".to_string()),
                prefix_list_in: None,
                prefix_list_out: None,
            },
            // ISP 2
            BgpNeighbor {
                address: "198.51.100.2".parse().unwrap(),
                remote_asn: 64501,  // ISP 2's AS number
                description: Some("ISP2 - Secondary".to_string()),
                password: Some("secretpass456".to_string()),
                ebgp_multihop: None,
                update_source: Some("eth2".to_string()),
                route_map_in: Some("ISP2-IN".to_string()),
                route_map_out: Some("ISP2-OUT".to_string()),
                prefix_list_in: None,
                prefix_list_out: None,
            },
        ],

        // Route maps for traffic engineering
        route_maps: vec![
            // Prefer ISP1 for outbound (higher local pref)
            RouteMap {
                name: "ISP1-IN".to_string(),
                action: RouteMapAction::Permit,
                sequence: 10,
                match_rules: vec![],
                set_actions: vec![
                    RouteMapSet::LocalPreference { value: 200 },
                ],
            },
            // ISP2 as backup (lower local pref)
            RouteMap {
                name: "ISP2-IN".to_string(),
                action: RouteMapAction::Permit,
                sequence: 10,
                match_rules: vec![],
                set_actions: vec![
                    RouteMapSet::LocalPreference { value: 100 },
                ],
            },
        ],
    };

    println!("BGP Configuration:");
    println!("  AS Number: {}", bgp_config.asn);
    println!("  Router ID: {}", bgp_config.router_id);
    println!("  Networks: {}", bgp_config.networks.len());
    println!("  Neighbors: {}", bgp_config.neighbors.len());
    for neighbor in &bgp_config.neighbors {
        println!("    - {} (AS {}): {:?}",
            neighbor.address,
            neighbor.remote_asn,
            neighbor.description
        );
    }
    println!();

    frr_mgr.configure_bgp(&bgp_config).await?;
    println!("✓ BGP configuration generated\n");

    // Example 2: OSPF Configuration (Internal network)
    println!("=== Example 2: OSPF Configuration ===\n");
    println!("Use case: Campus network with multiple buildings\n");

    let ospf_config = OspfConfig {
        enabled: true,
        router_id: "192.168.1.1".parse().unwrap(),

        areas: vec![
            // Backbone area
            OspfArea {
                area_id: "0.0.0.0".to_string(),
                networks: vec![
                    "192.168.1.0/24".to_string(),  // Core network
                    "10.0.0.0/16".to_string(),      // Distribution
                ],
                area_type: OspfAreaType::Normal,
                authentication: None,
            },
            // Branch office (stub area - no external routes)
            OspfArea {
                area_id: "0.0.0.10".to_string(),
                networks: vec![
                    "192.168.10.0/24".to_string(),
                ],
                area_type: OspfAreaType::Stub,
                authentication: None,
            },
        ],

        // Don't send OSPF hello on these interfaces
        passive_interfaces: vec![
            "eth0".to_string(),  // LAN-facing
        ],

        // Redistribute connected networks into OSPF
        redistribute: vec![
            RedistributeProtocol {
                protocol: "connected".to_string(),
                route_map: None,
                metric: Some(20),
            },
        ],
    };

    println!("OSPF Configuration:");
    println!("  Router ID: {}", ospf_config.router_id);
    println!("  Areas: {}", ospf_config.areas.len());
    for area in &ospf_config.areas {
        println!("    - Area {} ({:?}): {} networks",
            area.area_id,
            area.area_type,
            area.networks.len()
        );
    }
    println!();

    frr_mgr.configure_ospf(&ospf_config).await?;
    println!("✓ OSPF configuration generated\n");

    // Example 3: RIP Configuration (Simple small office)
    println!("=== Example 3: RIP Configuration ===\n");
    println!("Use case: Small office with legacy equipment\n");

    let rip_config = RipConfig {
        enabled: true,
        version: RipVersion::V2,  // RIPv2 supports CIDR
        networks: vec![
            "192.168.1.0/24".to_string(),
            "192.168.2.0/24".to_string(),
        ],
        passive_interfaces: vec![
            "eth0".to_string(),
        ],
        redistribute: vec![
            RedistributeProtocol {
                protocol: "connected".to_string(),
                route_map: None,
                metric: None,
            },
        ],
    };

    println!("RIP Configuration:");
    println!("  Version: {:?}", rip_config.version);
    println!("  Networks: {}", rip_config.networks.len());
    println!();

    frr_mgr.configure_rip(&rip_config).await?;
    println!("✓ RIP configuration generated\n");

    // Generate daemons file
    frr_mgr.configure_daemons().await?;
    println!("✓ FRR daemons configuration generated\n");

    println!("=== Setup Complete! ===\n");

    println!("Next steps:\n");
    println!("1. Start FRR:");
    println!("   systemctl start frr");
    println!("   systemctl enable frr");
    println!();
    println!("2. Check daemon status:");
    println!("   systemctl status frr");
    println!();
    println!("3. Enter FRR shell (Cisco-like CLI):");
    println!("   vtysh");
    println!();
    println!("4. Useful commands in vtysh:");
    println!("   show ip bgp summary            # BGP neighbor status");
    println!("   show ip bgp                    # BGP routing table");
    println!("   show ip ospf neighbor          # OSPF neighbors");
    println!("   show ip ospf database          # OSPF link-state DB");
    println!("   show ip rip                    # RIP routes");
    println!("   show ip route                  # Full routing table");
    println!("   show running-config            # Current config");
    println!();
    println!("5. Monitor logs:");
    println!("   tail -f /var/log/frr/frr.log");
    println!();
    println!("Configuration files:");
    println!("  /etc/frr/daemons               # Enabled daemons");
    println!("  /etc/frr/bgpd.conf             # BGP config");
    println!("  /etc/frr/ospfd.conf            # OSPF config");
    println!("  /etc/frr/ripd.conf             # RIP config");
    println!();
    println!("Pro Tips:");
    println!("  - Always test in a lab first!");
    println!("  - Use route-maps for traffic engineering");
    println!("  - Enable MD5 authentication for production");
    println!("  - Monitor BGP with Prometheus exporter");
    println!("  - Use BFD for fast failure detection");

    Ok(())
}
