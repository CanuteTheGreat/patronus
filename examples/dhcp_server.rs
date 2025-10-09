//! DHCP server configuration example
//!
//! This example demonstrates how to:
//! 1. Configure a DHCP server
//! 2. Set up IP ranges and options
//! 3. Add static reservations
//! 4. Manage leases

use patronus_network::dhcp::{DhcpConfig, DhcpManager, StaticLease};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== Patronus DHCP Server Setup ===\n");

    let dhcp_mgr = DhcpManager::new();

    // 1. Create DHCP configuration
    println!("1. Configuring DHCP server...");
    let config = DhcpConfig {
        enabled: true,
        interface: "eth1".to_string(), // LAN interface
        subnet: "192.168.1.0".to_string(),
        netmask: "255.255.255.0".to_string(),
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 200),
        gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ],
        lease_time: 86400, // 24 hours
        domain_name: Some("local".to_string()),
    };

    println!("  Interface: {}", config.interface);
    println!("  Subnet: {}/{}", config.subnet, config.netmask);
    println!("  Range: {} - {}", config.range_start, config.range_end);
    println!("  Gateway: {:?}", config.gateway);
    println!("  DNS Servers: {:?}", config.dns_servers);
    println!("  Lease Time: {} seconds ({} hours)", config.lease_time, config.lease_time / 3600);
    println!();

    // 2. Generate and save configuration
    println!("2. Generating DHCP configuration...");
    let conf_content = dhcp_mgr.generate_config(&config)?;
    println!("{}", conf_content);

    dhcp_mgr.save_config(&config).await?;
    println!("  ✓ Configuration saved\n");

    // 3. Add static reservations
    println!("3. Adding static DHCP reservations...");

    let static_leases = vec![
        StaticLease {
            mac_address: "00:11:22:33:44:55".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 10),
            hostname: Some("server1".to_string()),
        },
        StaticLease {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: Ipv4Addr::new(192, 168, 1, 11),
            hostname: Some("printer1".to_string()),
        },
    ];

    for lease in &static_leases {
        dhcp_mgr.add_static_lease(lease).await?;
        println!("  ✓ Reserved {} for {} ({})",
            lease.ip_address,
            lease.hostname.as_ref().unwrap(),
            lease.mac_address
        );
    }
    println!();

    // 4. Show current leases
    println!("4. Current DHCP Leases:");
    match dhcp_mgr.get_leases().await {
        Ok(leases) => {
            if leases.is_empty() {
                println!("  No active leases");
            } else {
                for lease in leases {
                    println!("  {} ({}) - {} - {:?}",
                        lease.ip_address,
                        lease.mac_address,
                        lease.hostname.unwrap_or_else(|| "unknown".to_string()),
                        lease.state
                    );
                }
            }
        }
        Err(e) => println!("  Could not read leases: {}", e),
    }
    println!();

    // 5. Check server status
    println!("5. DHCP Server Status:");
    match dhcp_mgr.status().await {
        Ok(running) => {
            if running {
                println!("  ✓ Server is running");
            } else {
                println!("  ✗ Server is stopped");
            }
        }
        Err(e) => println!("  Could not check status: {}", e),
    }
    println!();

    println!("=== Setup Complete! ===");
    println!();
    println!("To start the DHCP server:");
    println!("  sudo systemctl start dhcpd");
    println!();
    println!("To enable at boot:");
    println!("  sudo systemctl enable dhcpd");
    println!();
    println!("To view leases:");
    println!("  cat /var/lib/patronus/dhcp.leases");

    Ok(())
}
