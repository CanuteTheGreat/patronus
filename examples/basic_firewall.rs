//! Basic firewall configuration example
//!
//! This example demonstrates how to:
//! 1. Initialize the firewall
//! 2. Add filter rules
//! 3. Add NAT/masquerading rules
//! 4. Enable IP forwarding

use patronus_core::types::{ChainType, FirewallAction, FirewallRule, NatRule, NatType, PortSpec, Protocol};
use patronus_firewall::RuleManager;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let mut manager = RuleManager::new();

    // Initialize the firewall (creates nftables table and base chains)
    println!("Initializing firewall...");
    manager.initialize().await?;

    // Enable IP forwarding (required for routing/NAT)
    println!("Enabling IP forwarding...");
    manager.enable_forwarding().await?;

    // Example 1: Allow SSH from LAN
    let ssh_rule = FirewallRule {
        id: None,
        name: "Allow SSH from LAN".to_string(),
        enabled: true,
        chain: ChainType::Input,
        action: FirewallAction::Accept,
        source: Some("192.168.1.0/24".to_string()),
        destination: None,
        protocol: Some(Protocol::Tcp),
        sport: None,
        dport: Some(PortSpec::Single(22)),
        interface_in: Some("eth1".to_string()),
        interface_out: None,
        comment: Some("Allow SSH access from LAN".to_string()),
    };
    manager.add_filter_rule(ssh_rule).await?;
    println!("✓ Added SSH rule");

    // Example 2: Allow HTTP/HTTPS outbound
    let http_rule = FirewallRule {
        id: None,
        name: "Allow HTTP/HTTPS outbound".to_string(),
        enabled: true,
        chain: ChainType::Output,
        action: FirewallAction::Accept,
        source: None,
        destination: None,
        protocol: Some(Protocol::Tcp),
        sport: None,
        dport: Some(PortSpec::Multiple(vec![80, 443])),
        interface_in: None,
        interface_out: Some("eth0".to_string()),
        comment: Some("Allow web traffic".to_string()),
    };
    manager.add_filter_rule(http_rule).await?;
    println!("✓ Added HTTP/HTTPS rule");

    // Example 3: NAT masquerading for LAN to WAN
    let masquerade_rule = NatRule {
        id: None,
        name: "Masquerade LAN to WAN".to_string(),
        enabled: true,
        nat_type: NatType::Masquerade,
        source: Some("192.168.1.0/24".to_string()),
        destination: None,
        protocol: None,
        dport: None,
        interface_out: Some("eth0".to_string()),
        comment: Some("NAT for LAN".to_string()),
    };
    manager.add_nat_rule(masquerade_rule).await?;
    println!("✓ Added masquerading rule");

    // Example 4: Port forwarding (DNAT) - forward port 8080 to internal server
    let port_forward_rule = NatRule {
        id: None,
        name: "Forward port 8080 to 192.168.1.10:80".to_string(),
        enabled: true,
        nat_type: NatType::Dnat {
            to_address: "192.168.1.10".parse::<IpAddr>()?,
            to_port: Some(80),
        },
        source: None,
        destination: None,
        protocol: Some(Protocol::Tcp),
        dport: Some(PortSpec::Single(8080)),
        interface_out: None,
        comment: Some("Port forward to web server".to_string()),
    };
    manager.add_nat_rule(port_forward_rule).await?;
    println!("✓ Added port forwarding rule");

    // Show current configuration
    println!("\nCurrent firewall configuration:");
    let filter_rules = manager.list_filter_rules().await?;
    let nat_rules = manager.list_nat_rules().await?;
    println!("  Filter rules: {}", filter_rules.len());
    println!("  NAT rules: {}", nat_rules.len());

    // Get and print nftables ruleset
    println!("\nNftables ruleset:");
    let ruleset = manager.get_nftables_ruleset().await?;
    println!("{}", ruleset);

    Ok(())
}
