//! High Availability cluster configuration example
//!
//! This example demonstrates how to configure a Patronus HA cluster
//! with virtual IPs and automatic failover.

use patronus_network::ha::{HaManager, HaBackend, HaCluster, HaRole, VirtualIp};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Patronus High Availability Setup ===\n");

    // Check available backends
    println!("1. Detecting available HA backends...");
    let backends = HaManager::list_available_backends();

    if backends.is_empty() {
        eprintln!("ERROR: No HA backends available!");
        eprintln!("Install one of: keepalived, ucarp, vrrpd");
        return Ok(());
    }

    println!("  Available backends:");
    for backend in &backends {
        println!("    - {}", backend);
    }

    // Choose backend (Gentoo way - give options!)
    let backend = if backends.contains(&HaBackend::Keepalived) {
        println!("  Using: keepalived (most feature-rich)");
        HaBackend::Keepalived
    } else if backends.contains(&HaBackend::Ucarp) {
        println!("  Using: ucarp (CARP-compatible)");
        HaBackend::Ucarp
    } else {
        println!("  Using: vrrpd (simple VRRP)");
        HaBackend::Vrrpd
    };
    println!();

    let ha_mgr = HaManager::new(backend.clone());

    // Configure primary node
    println!("2. Configuring HA cluster (PRIMARY node)...");

    let mut cluster = HaCluster {
        name: "patronus-cluster".to_string(),
        enabled: true,
        backend: backend.clone(),
        role: HaRole::Master,  // This is the primary node
        peer_ip: "192.168.1.2".parse().unwrap(),  // Secondary node IP
        sync_interface: "eth1".to_string(),
        sync_enabled: true,
        virtual_ips: vec![
            // VIP for LAN
            VirtualIp {
                name: "lan-vip".to_string(),
                enabled: true,
                vip: "192.168.1.100".parse().unwrap(),
                interface: "eth0".to_string(),
                vhid: 1,
                priority: 200,  // Higher = preferred master
                password: Some("supersecret123".to_string()),
                preempt: true,
                advskew: 0,
            },
            // VIP for WAN
            VirtualIp {
                name: "wan-vip".to_string(),
                enabled: true,
                vip: "203.0.113.100".parse().unwrap(),
                interface: "eth2".to_string(),
                vhid: 2,
                priority: 200,
                password: Some("supersecret123".to_string()),
                preempt: true,
                advskew: 0,
            },
        ],
        config_sync_enabled: true,
        config_sync_user: "patronus".to_string(),
        config_sync_path: "/etc/patronus".into(),
    };

    println!("  Cluster Configuration:");
    println!("    Name: {}", cluster.name);
    println!("    Role: {:?}", cluster.role);
    println!("    Backend: {}", cluster.backend);
    println!("    Peer IP: {}", cluster.peer_ip);
    println!("    Config Sync: {}", cluster.config_sync_enabled);
    println!();

    println!("  Virtual IPs:");
    for vip in &cluster.virtual_ips {
        println!("    {} (VHID {})", vip.name, vip.vhid);
        println!("      IP: {} on {}", vip.vip, vip.interface);
        println!("      Priority: {} (higher = preferred)", vip.priority);
        println!("      Preempt: {}", vip.preempt);
    }
    println!();

    // Configure the cluster
    println!("3. Generating HA configuration files...");
    ha_mgr.configure(&cluster).await?;
    println!("  ✓ Configuration generated\n");

    // Show secondary node configuration
    println!("4. Secondary node configuration:");
    println!("  On the secondary node (192.168.1.2), configure with:");
    println!();

    cluster.role = HaRole::Backup;
    cluster.peer_ip = "192.168.1.1".parse().unwrap();  // Primary node IP
    for vip in &mut cluster.virtual_ips {
        vip.priority = 100;  // Lower priority for backup
    }

    println!("  Role: BACKUP");
    println!("  Peer IP: 192.168.1.1 (this node)");
    println!("  VIP Priorities: 100 (lower than master)");
    println!();

    println!("=== Setup Complete! ===\n");

    println!("Next steps:");
    println!();

    match backend {
        HaBackend::Keepalived => {
            println!("1. Start keepalived on PRIMARY:");
            println!("   systemctl start keepalived");
            println!("   systemctl enable keepalived");
            println!();
            println!("2. Configure SECONDARY node (repeat setup with role=BACKUP)");
            println!();
            println!("3. Start keepalived on SECONDARY:");
            println!("   systemctl start keepalived");
            println!();
            println!("4. Verify VIPs are assigned:");
            println!("   ip addr show");
            println!("   # You should see 192.168.1.100 on eth0 (PRIMARY only)");
            println!();
            println!("5. Test failover:");
            println!("   # On PRIMARY:");
            println!("   systemctl stop keepalived");
            println!("   # VIP should move to SECONDARY");
        }
        HaBackend::Ucarp => {
            println!("1. Install systemd services:");
            println!("   cp /etc/patronus/ha/ucarp-*.service /etc/systemd/system/");
            println!("   systemctl daemon-reload");
            println!();
            println!("2. Start ucarp on PRIMARY:");
            println!("   systemctl start ucarp-lan-vip");
            println!("   systemctl start ucarp-wan-vip");
            println!();
            println!("3. Configure and start on SECONDARY");
            println!();
            println!("4. Test failover:");
            println!("   pkill ucarp  # On PRIMARY");
        }
        HaBackend::Vrrpd => {
            println!("1. Start vrrpd on PRIMARY:");
            println!("   vrrpd -i eth0 -v 1 -p 200 192.168.1.100");
            println!();
            println!("2. Start on SECONDARY with lower priority:");
            println!("   vrrpd -i eth0 -v 1 -p 100 192.168.1.100");
        }
    }

    println!();
    println!("Monitoring:");
    println!("  tail -f /var/log/syslog | grep -i \"(ucarp|keepalived|vrrp)\"");
    println!();
    println!("Configuration sync:");
    println!("  # Automatically syncs /etc/patronus to peer after changes");
    println!("  patronus ha sync");

    Ok(())
}
