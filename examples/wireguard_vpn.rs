//! WireGuard VPN configuration example
//!
//! This example demonstrates how to:
//! 1. Generate WireGuard keys
//! 2. Create a WireGuard interface
//! 3. Add peers
//! 4. Configure firewall rules for VPN

use patronus_network::wireguard::{WireGuardInterface, WireGuardManager, WireGuardPeer};
use patronus_core::types::{ChainType, FirewallAction, FirewallRule, Protocol, PortSpec};
use patronus_firewall::RuleManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== Patronus WireGuard VPN Setup ===\n");

    // 1. Generate keys
    println!("1. Generating WireGuard keys...");
    let private_key = WireGuardManager::generate_private_key()?;
    let public_key = WireGuardManager::derive_public_key(&private_key)?;

    println!("  Server Private Key: {}", private_key);
    println!("  Server Public Key: {}", public_key);
    println!();

    // 2. Create WireGuard interface
    println!("2. Creating WireGuard interface...");
    let wg_manager = WireGuardManager::new();

    let wg_config = WireGuardInterface {
        name: "wg0".to_string(),
        private_key: private_key.clone(),
        public_key: public_key.clone(),
        listen_port: 51820,
        address: vec!["10.0.0.1/24".to_string()],
    };

    wg_manager.create_interface(&wg_config).await?;
    println!("  ✓ Created interface wg0 at 10.0.0.1/24");
    println!();

    // 3. Add a peer (client)
    println!("3. Generating client keys and adding peer...");
    let client_private_key = WireGuardManager::generate_private_key()?;
    let client_public_key = WireGuardManager::derive_public_key(&client_private_key)?;

    println!("  Client Private Key: {}", client_private_key);
    println!("  Client Public Key: {}", client_public_key);

    let peer = WireGuardPeer {
        public_key: client_public_key.clone(),
        preshared_key: None,
        endpoint: None, // Client will connect to us
        allowed_ips: vec!["10.0.0.2/32".to_string()],
        persistent_keepalive: Some(25),
    };

    wg_manager.add_peer("wg0", &peer).await?;
    println!("  ✓ Added peer with IP 10.0.0.2/32");
    println!();

    // 4. Configure firewall for VPN
    println!("4. Configuring firewall rules...");
    let mut fw_manager = RuleManager::new();
    fw_manager.initialize().await?;

    // Allow WireGuard port
    let wg_port_rule = FirewallRule {
        id: None,
        name: "Allow WireGuard".to_string(),
        enabled: true,
        chain: ChainType::Input,
        action: FirewallAction::Accept,
        source: None,
        destination: None,
        protocol: Some(Protocol::Udp),
        sport: None,
        dport: Some(PortSpec::Single(51820)),
        interface_in: None,
        interface_out: None,
        comment: Some("WireGuard VPN port".to_string()),
    };

    fw_manager.add_filter_rule(wg_port_rule).await?;
    println!("  ✓ Added firewall rule for UDP port 51820");

    // Allow traffic from VPN network
    let vpn_traffic_rule = FirewallRule {
        id: None,
        name: "Allow VPN traffic".to_string(),
        enabled: true,
        chain: ChainType::Input,
        action: FirewallAction::Accept,
        source: Some("10.0.0.0/24".to_string()),
        destination: None,
        protocol: None,
        sport: None,
        dport: None,
        interface_in: Some("wg0".to_string()),
        interface_out: None,
        comment: Some("Allow traffic from VPN clients".to_string()),
    };

    fw_manager.add_filter_rule(vpn_traffic_rule).await?;
    println!("  ✓ Added firewall rule for VPN traffic");
    println!();

    // 5. Get and display status
    println!("5. WireGuard Status:");
    let status = wg_manager.get_status("wg0").await?;
    println!("  Interface: {}", status.interface);
    println!("  Public Key: {}", status.public_key);
    println!("  Listen Port: {}", status.listen_port);
    println!("  Peers: {}", status.peers.len());
    println!();

    // 6. Generate client configuration
    println!("6. Client Configuration:");
    println!("  Save this to /etc/wireguard/wg0.conf on the client:\n");
    println!("[Interface]");
    println!("PrivateKey = {}", client_private_key);
    println!("Address = 10.0.0.2/32");
    println!("DNS = 1.1.1.1");
    println!();
    println!("[Peer]");
    println!("PublicKey = {}", public_key);
    println!("Endpoint = YOUR_SERVER_IP:51820");
    println!("AllowedIPs = 0.0.0.0/0  # Route all traffic through VPN");
    println!("PersistentKeepalive = 25");
    println!();

    println!("=== Setup Complete! ===");
    println!();
    println!("To connect the client:");
    println!("  sudo wg-quick up wg0");
    println!();
    println!("To check server status:");
    println!("  sudo wg show wg0");

    Ok(())
}
