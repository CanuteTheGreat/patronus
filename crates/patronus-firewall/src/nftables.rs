//! nftables interaction layer

use patronus_core::{
    types::{ChainType, FirewallAction, FirewallRule, NatRule, NatType, PortSpec, Protocol},
    Error, Result,
};
use std::process::Command;

const TABLE_NAME: &str = "patronus";
const TABLE_FAMILY: &str = "inet";

/// Execute an nftables command
pub fn execute_nft_command(args: &[&str]) -> Result<String> {
    tracing::debug!("Executing nft command: {:?}", args);

    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| Error::Firewall(format!("Failed to execute nft command: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Firewall(format!("nft command failed: {}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Execute an nftables command from a script
pub fn execute_nft_script(script: &str) -> Result<String> {
    tracing::debug!("Executing nft script:\n{}", script);

    let output = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(script.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| Error::Firewall(format!("Failed to execute nft script: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Firewall(format!("nft script failed: {}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Initialize the patronus nftables table and chains
pub fn initialize_table() -> Result<()> {
    let script = format!(
        r#"
# Create table
add table {} {}

# Create filter chains
add chain {} {} input {{ type filter hook input priority 0; policy drop; }}
add chain {} {} output {{ type filter hook output priority 0; policy accept; }}
add chain {} {} forward {{ type filter hook forward priority 0; policy drop; }}

# Create NAT chains
add chain {} {} prerouting {{ type nat hook prerouting priority -100; }}
add chain {} {} postrouting {{ type nat hook postrouting priority 100; }}

# Allow loopback
add rule {} {} input iifname "lo" accept

# Allow established/related connections
add rule {} {} input ct state established,related accept
add rule {} {} forward ct state established,related accept

# Allow ICMP
add rule {} {} input ip protocol icmp accept
add rule {} {} input ip6 nexthdr icmpv6 accept
        "#,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
        TABLE_FAMILY, TABLE_NAME,
    );

    execute_nft_script(&script)?;
    tracing::info!("Initialized nftables table: {}", TABLE_NAME);
    Ok(())
}

/// Flush the patronus table
pub fn flush_table() -> Result<()> {
    execute_nft_command(&["flush", "table", TABLE_FAMILY, TABLE_NAME])?;
    tracing::info!("Flushed nftables table: {}", TABLE_NAME);
    Ok(())
}

/// Delete the patronus table
pub fn delete_table() -> Result<()> {
    execute_nft_command(&["delete", "table", TABLE_FAMILY, TABLE_NAME])?;
    tracing::info!("Deleted nftables table: {}", TABLE_NAME);
    Ok(())
}

/// List all nftables rulesets
pub fn list_ruleset() -> Result<String> {
    execute_nft_command(&["list", "ruleset"])
}

/// List the patronus table
pub fn list_table() -> Result<String> {
    execute_nft_command(&["list", "table", TABLE_FAMILY, TABLE_NAME])
}

/// Convert a FirewallRule to nftables command
pub fn rule_to_nft_command(rule: &FirewallRule) -> String {
    if !rule.enabled {
        return String::new();
    }

    let mut parts = Vec::new();

    // Interface filters
    if let Some(ref iface) = rule.interface_in {
        parts.push(format!("iifname \"{}\"", iface));
    }
    if let Some(ref iface) = rule.interface_out {
        parts.push(format!("oifname \"{}\"", iface));
    }

    // Protocol
    if let Some(ref protocol) = rule.protocol {
        match protocol {
            Protocol::Tcp => parts.push("tcp".to_string()),
            Protocol::Udp => parts.push("udp".to_string()),
            Protocol::Icmp => parts.push("icmp".to_string()),
            Protocol::All => {}
        }
    }

    // Source
    if let Some(ref src) = rule.source {
        parts.push(format!("ip saddr {}", src));
    }

    // Destination
    if let Some(ref dst) = rule.destination {
        parts.push(format!("ip daddr {}", dst));
    }

    // Source port
    if let Some(ref sport) = rule.sport {
        parts.push(format!("sport {}", sport));
    }

    // Destination port
    if let Some(ref dport) = rule.dport {
        parts.push(format!("dport {}", dport));
    }

    // Action
    parts.push(rule.action.to_string());

    // Comment
    if let Some(ref comment) = rule.comment {
        parts.push(format!("comment \"{}\"", comment.replace('"', "\\\"")));
    }

    format!(
        "add rule {} {} {} {}",
        TABLE_FAMILY,
        TABLE_NAME,
        rule.chain,
        parts.join(" ")
    )
}

/// Add a firewall rule to nftables
pub fn add_rule(rule: &FirewallRule) -> Result<()> {
    let command = rule_to_nft_command(rule);
    if command.is_empty() {
        return Ok(()); // Rule is disabled
    }

    execute_nft_script(&command)?;
    tracing::info!("Added firewall rule: {}", rule.name);
    Ok(())
}

/// Convert NAT rule to nftables command
pub fn nat_rule_to_nft_command(rule: &NatRule) -> String {
    if !rule.enabled {
        return String::new();
    }

    let mut parts = Vec::new();
    let chain = match rule.nat_type {
        NatType::Masquerade | NatType::Snat { .. } => "postrouting",
        NatType::Dnat { .. } => "prerouting",
    };

    // Interface
    if let Some(ref iface) = rule.interface_out {
        parts.push(format!("oifname \"{}\"", iface));
    }

    // Protocol
    if let Some(ref protocol) = rule.protocol {
        parts.push(protocol.to_string());
    }

    // Source
    if let Some(ref src) = rule.source {
        parts.push(format!("ip saddr {}", src));
    }

    // Destination
    if let Some(ref dst) = rule.destination {
        parts.push(format!("ip daddr {}", dst));
    }

    // Destination port
    if let Some(ref dport) = rule.dport {
        parts.push(format!("dport {}", dport));
    }

    // NAT action
    let nat_action = match &rule.nat_type {
        NatType::Masquerade => "masquerade".to_string(),
        NatType::Snat { to_address } => format!("snat to {}", to_address),
        NatType::Dnat { to_address, to_port } => {
            if let Some(port) = to_port {
                format!("dnat to {}:{}", to_address, port)
            } else {
                format!("dnat to {}", to_address)
            }
        }
    };
    parts.push(nat_action);

    // Comment
    if let Some(ref comment) = rule.comment {
        parts.push(format!("comment \"{}\"", comment.replace('"', "\\\"")));
    }

    format!(
        "add rule {} {} {} {}",
        TABLE_FAMILY, TABLE_NAME, chain,
        parts.join(" ")
    )
}

/// Add a NAT rule to nftables
pub fn add_nat_rule(rule: &NatRule) -> Result<()> {
    let command = nat_rule_to_nft_command(rule);
    if command.is_empty() {
        return Ok(()); // Rule is disabled
    }

    execute_nft_script(&command)?;
    tracing::info!("Added NAT rule: {}", rule.name);
    Ok(())
}

/// Enable IP forwarding
pub fn enable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| Error::Firewall(format!("Failed to enable IPv4 forwarding: {}", e)))?;

    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .map_err(|e| Error::Firewall(format!("Failed to enable IPv6 forwarding: {}", e)))?;

    tracing::info!("Enabled IP forwarding");
    Ok(())
}

/// Disable IP forwarding
pub fn disable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "0")
        .map_err(|e| Error::Firewall(format!("Failed to disable IPv4 forwarding: {}", e)))?;

    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0")
        .map_err(|e| Error::Firewall(format!("Failed to disable IPv6 forwarding: {}", e)))?;

    tracing::info!("Disabled IP forwarding");
    Ok(())
}
