//! nftables interaction layer

use patronus_core::{
    types::{FirewallRule, NatRule, NatType, Protocol},
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

# Drop invalid packets
add rule {} {} input ct state invalid drop
add rule {} {} forward ct state invalid drop

# Allow ICMP
add rule {} {} input ip protocol icmp accept
add rule {} {} input ip6 nexthdr icmpv6 accept
        "#,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
        TABLE_FAMILY,
        TABLE_NAME,
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

/// Validate a source/destination address specifier (`ip saddr`/`ip daddr`
/// operand) before it is spliced into an nftables script. This accepts a bare
/// IPv4/IPv6 address, a CIDR network, or the literal `any`/`all` -- nothing
/// else, and in particular no whitespace, `;`, `{`/`}`, or other characters
/// that would let a value break out of its single `ip saddr <value>` operand
/// position.
///
/// `execute_nft_script` feeds its whole argument to `nft -f -`, which parses
/// its own statement grammar directly (no shell involved) -- an unvalidated
/// `source`/`destination` string containing e.g. `0.0.0.0/0; add rule ...`
/// is therefore a real nftables ruleset-injection vector, not just a
/// cosmetic parsing concern (same bug class as the captive-portal
/// `mac_address` injection fixed in 37c832c).
fn is_valid_address_spec(s: &str) -> bool {
    if s.eq_ignore_ascii_case("any") || s.eq_ignore_ascii_case("all") {
        return true;
    }
    match s.split_once('/') {
        Some((addr, prefix)) => {
            addr.parse::<std::net::IpAddr>().is_ok()
                && prefix.len() <= 3
                && !prefix.is_empty()
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && prefix.parse::<u8>().is_ok()
        }
        None => s.parse::<std::net::IpAddr>().is_ok(),
    }
}

/// Validate an interface name before it is spliced into an nftables script
/// (`iifname "<value>"`/`oifname "<value>"`). Linux interface names are at
/// most `IFNAMSIZ - 1` (15) bytes and never contain a `"`, so anything
/// outside that is either not a real interface or an attempt to break out of
/// the quoted operand (same injection class as `is_valid_address_spec`).
fn is_valid_interface_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Convert a FirewallRule to nftables command. Returns an error instead of
/// building a script from a `source`/`destination`/`interface_in`/`interface_out`
/// value that doesn't pass validation, rather than silently splicing an
/// unsafe value into the generated nft script.
pub fn rule_to_nft_command(rule: &FirewallRule) -> Result<String> {
    if !rule.enabled {
        return Ok(String::new());
    }

    let mut parts = Vec::new();

    // Interface filters. "any"/"all" means "match every interface" -- same
    // rule as the source/destination "any"/"all" handling below: the
    // correct way to express that in nft is to omit the iifname/oifname
    // match entirely, not to splice the literal word "any" in as if it were
    // a real interface name. nft does not resolve "any" as a wildcard here
    // either -- it fails at apply time ("Could not process rule: No such
    // file or directory"), and "any" is the UI's own default interface
    // value, so this broke ordinary legitimate rules, not just injection
    // attempts.
    if let Some(ref iface) = rule.interface_in {
        if !is_valid_interface_name(iface)
            && !iface.eq_ignore_ascii_case("any")
            && !iface.eq_ignore_ascii_case("all")
        {
            return Err(Error::Firewall(format!(
                "Invalid interface_in name for firewall rule: {:?}",
                iface
            )));
        }
        if !iface.eq_ignore_ascii_case("any") && !iface.eq_ignore_ascii_case("all") {
            parts.push(format!("iifname \"{}\"", iface));
        }
    }
    if let Some(ref iface) = rule.interface_out {
        if !is_valid_interface_name(iface)
            && !iface.eq_ignore_ascii_case("any")
            && !iface.eq_ignore_ascii_case("all")
        {
            return Err(Error::Firewall(format!(
                "Invalid interface_out name for firewall rule: {:?}",
                iface
            )));
        }
        if !iface.eq_ignore_ascii_case("any") && !iface.eq_ignore_ascii_case("all") {
            parts.push(format!("oifname \"{}\"", iface));
        }
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

    // Source. "any"/"all" means "match every source" -- the correct way to
    // express that in nft is to omit the `ip saddr` match entirely, not to
    // splice the literal word "any" in as if it were an address (nft parses
    // that as a hostname to resolve, which fails outright: "Could not
    // resolve hostname: any"). This previously meant every rule with the
    // UI's default "Any" source/destination was rejected by real nftables
    // on apply -- invisible before the apply-result propagation fix because
    // the error used to be discarded.
    if let Some(ref src) = rule.source {
        if !is_valid_address_spec(src) {
            return Err(Error::Firewall(format!(
                "Invalid source address spec for firewall rule: {:?}",
                src
            )));
        }
        if !src.eq_ignore_ascii_case("any") && !src.eq_ignore_ascii_case("all") {
            parts.push(format!("ip saddr {}", src));
        }
    }

    // Destination (same "any"/"all" = omit-the-match rule as source, above)
    if let Some(ref dst) = rule.destination {
        if !is_valid_address_spec(dst) {
            return Err(Error::Firewall(format!(
                "Invalid destination address spec for firewall rule: {:?}",
                dst
            )));
        }
        if !dst.eq_ignore_ascii_case("any") && !dst.eq_ignore_ascii_case("all") {
            parts.push(format!("ip daddr {}", dst));
        }
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

    Ok(format!(
        "add rule {} {} {} {}",
        TABLE_FAMILY,
        TABLE_NAME,
        rule.chain,
        parts.join(" ")
    ))
}

/// Add a firewall rule to nftables
pub fn add_rule(rule: &FirewallRule) -> Result<()> {
    let command = rule_to_nft_command(rule)?;
    if command.is_empty() {
        return Ok(()); // Rule is disabled
    }

    execute_nft_script(&command)?;
    tracing::info!("Added firewall rule: {}", rule.name);
    Ok(())
}

/// Convert NAT rule to nftables command. Returns an error instead of
/// splicing an unvalidated `source`/`destination`/`interface_out` value into
/// the generated nft script (see `is_valid_address_spec`/
/// `is_valid_interface_name` on `rule_to_nft_command`, above, for why).
pub fn nat_rule_to_nft_command(rule: &NatRule) -> Result<String> {
    if !rule.enabled {
        return Ok(String::new());
    }

    let mut parts = Vec::new();
    let chain = match rule.nat_type {
        NatType::Masquerade | NatType::Snat { .. } => "postrouting",
        NatType::Dnat { .. } => "prerouting",
    };

    // Interface. See rule_to_nft_command's "any"/"all" interface note,
    // above -- omit the match entirely rather than splice the literal
    // placeholder in as an interface name.
    if let Some(ref iface) = rule.interface_out {
        if !is_valid_interface_name(iface)
            && !iface.eq_ignore_ascii_case("any")
            && !iface.eq_ignore_ascii_case("all")
        {
            return Err(Error::Firewall(format!(
                "Invalid interface_out name for NAT rule: {:?}",
                iface
            )));
        }
        if !iface.eq_ignore_ascii_case("any") && !iface.eq_ignore_ascii_case("all") {
            parts.push(format!("oifname \"{}\"", iface));
        }
    }

    // Protocol
    if let Some(ref protocol) = rule.protocol {
        parts.push(protocol.to_string());
    }

    // Source (see rule_to_nft_command's "any"/"all" note, above)
    if let Some(ref src) = rule.source {
        if !is_valid_address_spec(src) {
            return Err(Error::Firewall(format!(
                "Invalid source address spec for NAT rule: {:?}",
                src
            )));
        }
        if !src.eq_ignore_ascii_case("any") && !src.eq_ignore_ascii_case("all") {
            parts.push(format!("ip saddr {}", src));
        }
    }

    // Destination
    if let Some(ref dst) = rule.destination {
        if !is_valid_address_spec(dst) {
            return Err(Error::Firewall(format!(
                "Invalid destination address spec for NAT rule: {:?}",
                dst
            )));
        }
        if !dst.eq_ignore_ascii_case("any") && !dst.eq_ignore_ascii_case("all") {
            parts.push(format!("ip daddr {}", dst));
        }
    }

    // Destination port
    if let Some(ref dport) = rule.dport {
        parts.push(format!("dport {}", dport));
    }

    // NAT action (to_address is a typed std::net::IpAddr, not a raw string,
    // so it can't carry an injection payload)
    let nat_action = match &rule.nat_type {
        NatType::Masquerade => "masquerade".to_string(),
        NatType::Snat { to_address } => format!("snat to {}", to_address),
        NatType::Dnat {
            to_address,
            to_port,
        } => {
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

    Ok(format!(
        "add rule {} {} {} {}",
        TABLE_FAMILY,
        TABLE_NAME,
        chain,
        parts.join(" ")
    ))
}

/// Add a NAT rule to nftables
pub fn add_nat_rule(rule: &NatRule) -> Result<()> {
    let command = nat_rule_to_nft_command(rule)?;
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

#[cfg(test)]
mod qa_regression_tests {
    use super::*;
    use patronus_core::types::{ChainType, FirewallAction, NatRule, NatType};
    use std::net::IpAddr;

    fn base_rule() -> FirewallRule {
        let mut r = FirewallRule::new(
            "test-rule".to_string(),
            ChainType::Input,
            FirewallAction::Accept,
        );
        r.enabled = true;
        r
    }

    #[test]
    fn is_valid_address_spec_accepts_ip_cidr_and_any() {
        assert!(is_valid_address_spec("10.0.0.0/8"));
        assert!(is_valid_address_spec("192.168.1.1"));
        assert!(is_valid_address_spec("::1"));
        assert!(is_valid_address_spec("2001:db8::/32"));
        assert!(is_valid_address_spec("any"));
        assert!(is_valid_address_spec("ANY"));
        assert!(is_valid_address_spec("all"));
    }

    #[test]
    fn is_valid_address_spec_rejects_injection_payloads() {
        // A real payload that would otherwise be spliced straight into
        // `ip saddr <value>` inside a multi-statement nft script fed to
        // `nft -f -`, letting the caller inject an arbitrary extra rule.
        assert!(!is_valid_address_spec(
            "0.0.0.0/0; add rule inet patronus forward accept"
        ));
        assert!(!is_valid_address_spec(""));
        assert!(!is_valid_address_spec("not-an-address"));
        assert!(!is_valid_address_spec("10.0.0.0/999"));
        assert!(!is_valid_address_spec("10.0.0.0/"));
    }

    #[test]
    fn is_valid_interface_name_accepts_real_names_rejects_injection() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("wg0"));
        assert!(is_valid_interface_name("br-lan.100"));
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name(
            "eth0\" }; add rule inet patronus forward accept #"
        ));
        assert!(!is_valid_interface_name(
            "this-name-is-way-too-long-for-ifnamsiz"
        ));
    }

    #[test]
    fn rule_to_nft_command_rejects_injection_in_source() {
        let mut rule = base_rule();
        rule.source = Some("0.0.0.0/0; add rule inet patronus forward accept #".to_string());
        let result = rule_to_nft_command(&rule);
        assert!(
            result.is_err(),
            "a source value containing nft statement syntax must be rejected, not spliced into the script"
        );
    }

    #[test]
    fn rule_to_nft_command_rejects_injection_in_destination() {
        let mut rule = base_rule();
        rule.destination = Some("10.0.0.1 }; flush ruleset #".to_string());
        assert!(rule_to_nft_command(&rule).is_err());
    }

    #[test]
    fn rule_to_nft_command_rejects_injection_in_interface_name() {
        let mut rule = base_rule();
        rule.interface_in = Some("eth0\" }; add rule inet patronus forward accept #".to_string());
        assert!(rule_to_nft_command(&rule).is_err());
    }

    #[test]
    fn rule_to_nft_command_omits_match_for_any_interface_instead_of_splicing_literal_any() {
        // Same bug class as the source/destination "any"/"all" fix above:
        // "any" is the UI's own default interface value, but it is not a
        // real interface name -- nft fails outright trying to apply
        // `iifname "any"`/`oifname "any"` ("Could not process rule: No
        // such file or directory"). A rule with the default "Any"
        // interface_in/interface_out must still produce a command nft can
        // actually run, by omitting the match entirely.
        let mut rule = base_rule();
        rule.interface_in = Some("any".to_string());
        rule.interface_out = Some("ALL".to_string());
        let command =
            rule_to_nft_command(&rule).expect("'any'/'all' interface must not be rejected");
        assert!(!command.contains("iifname \"any\""));
        assert!(!command.contains("oifname \"ALL\""));
    }

    #[test]
    fn rule_to_nft_command_accepts_well_formed_rule() {
        let mut rule = base_rule();
        rule.source = Some("10.0.0.0/8".to_string());
        rule.destination = Some("any".to_string());
        rule.interface_in = Some("eth0".to_string());
        let command = rule_to_nft_command(&rule).expect("well-formed rule should be accepted");
        assert!(command.contains("ip saddr 10.0.0.0/8"));
        assert!(command.contains("iifname \"eth0\""));
    }

    #[test]
    fn rule_to_nft_command_omits_match_for_any_destination_instead_of_splicing_literal_any() {
        // "any" is a valid value from `is_valid_address_spec`'s point of
        // view, but it is not a real nftables address -- nft would try to
        // resolve it as a hostname and fail ("Could not resolve hostname:
        // any"). A rule with the UI's default "Any" destination/source must
        // still produce a command nft can actually run.
        let mut rule = base_rule();
        rule.destination = Some("any".to_string());
        rule.source = Some("ALL".to_string());
        let command = rule_to_nft_command(&rule).expect("'any'/'all' must not be rejected");
        assert!(!command.contains("ip daddr any"));
        assert!(!command.contains("ip saddr ALL"));
    }

    #[test]
    fn nat_rule_to_nft_command_rejects_injection_in_source() {
        let mut rule = NatRule::new(
            "test-nat".to_string(),
            NatType::Dnat {
                to_address: "192.168.1.100".parse::<IpAddr>().unwrap(),
                to_port: Some(8080),
            },
        );
        rule.enabled = true;
        rule.source = Some("0.0.0.0/0; add rule inet patronus forward accept #".to_string());
        assert!(nat_rule_to_nft_command(&rule).is_err());
    }

    #[test]
    fn nat_rule_to_nft_command_accepts_well_formed_rule() {
        let mut rule = NatRule::new("test-nat".to_string(), NatType::Masquerade);
        rule.enabled = true;
        rule.source = Some("10.0.0.0/8".to_string());
        rule.interface_out = Some("eth0".to_string());
        let command =
            nat_rule_to_nft_command(&rule).expect("well-formed NAT rule should be accepted");
        assert!(command.contains("masquerade"));
        assert!(command.contains("ip saddr 10.0.0.0/8"));
    }

    #[test]
    fn disabled_rule_still_short_circuits_to_empty_command() {
        let mut rule = base_rule();
        rule.enabled = false;
        // Deliberately set an "invalid" value here too -- a disabled rule
        // must never even reach validation/the nft script, matching the
        // pre-existing early-return-on-disabled behavior.
        rule.source = Some("0.0.0.0/0; add rule inet patronus forward accept #".to_string());
        assert_eq!(rule_to_nft_command(&rule).unwrap(), "");
    }
}
