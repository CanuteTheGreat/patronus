//! Input validation framework for security
//!
//! Provides comprehensive input validation to prevent injection attacks:
//! - Command injection prevention
//! - Path traversal prevention
//! - SQL injection prevention (complementary to parameterized queries)
//! - XSS prevention
//! - Network input validation (IPs, ports, interfaces)

use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Validate an interface name (e.g., eth0, wg0)
pub fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Interface name cannot be empty");
    }

    if name.len() > 15 {
        bail!("Interface name too long (max 15 characters)");
    }

    // Interface names should only contain alphanumeric, dash, underscore, dot
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("Interface name contains invalid characters");
    }

    // Should not start with dot or dash
    if name.starts_with('.') || name.starts_with('-') {
        bail!("Interface name cannot start with '.' or '-'");
    }

    // Reject obvious injection attempts
    if name.contains("&&") || name.contains("||") || name.contains(";") || name.contains("`") {
        bail!("Interface name contains shell metacharacters");
    }

    Ok(())
}

/// Validate an IP address
pub fn validate_ip_address(ip: &str) -> Result<IpAddr> {
    ip.parse::<IpAddr>()
        .map_err(|e| anyhow::anyhow!("Invalid IP address '{}': {}", ip, e))
}

/// Validate an IPv4 address
pub fn validate_ipv4_address(ip: &str) -> Result<Ipv4Addr> {
    ip.parse::<Ipv4Addr>()
        .map_err(|e| anyhow::anyhow!("Invalid IPv4 address '{}': {}", ip, e))
}

/// Validate an IPv6 address
pub fn validate_ipv6_address(ip: &str) -> Result<Ipv6Addr> {
    ip.parse::<Ipv6Addr>()
        .map_err(|e| anyhow::anyhow!("Invalid IPv6 address '{}': {}", ip, e))
}

/// Validate a CIDR notation (IP/prefix)
pub fn validate_cidr(cidr: &str) -> Result<()> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        bail!("Invalid CIDR format (expected IP/prefix)");
    }

    // Validate IP part
    validate_ip_address(parts[0])?;

    // Validate prefix length
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid prefix length"))?;

    // Check prefix range based on IP type
    if parts[0].contains(':') {
        // IPv6
        if prefix > 128 {
            bail!("IPv6 prefix must be <= 128");
        }
    } else {
        // IPv4
        if prefix > 32 {
            bail!("IPv4 prefix must be <= 32");
        }
    }

    Ok(())
}

/// Validate a port number
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        bail!("Port cannot be 0");
    }
    Ok(())
}

/// Validate a port range
pub fn validate_port_range(start: u16, end: u16) -> Result<()> {
    validate_port(start)?;
    validate_port(end)?;

    if start > end {
        bail!("Port range start ({}) must be <= end ({})", start, end);
    }

    Ok(())
}

/// Validate a hostname/domain name
pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() {
        bail!("Hostname cannot be empty");
    }

    if hostname.len() > 253 {
        bail!("Hostname too long (max 253 characters)");
    }

    // Split into labels
    let labels: Vec<&str> = hostname.split('.').collect();

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            bail!("Invalid hostname label length");
        }

        // Labels should start and end with alphanumeric
        let first_char = label.chars().next();
        let last_char = label.chars().last();

        match (first_char, last_char) {
            (Some(first), Some(last)) => {
                if !first.is_alphanumeric() || !last.is_alphanumeric() {
                    bail!("Hostname labels must start and end with alphanumeric characters");
                }
            }
            _ => bail!("Invalid hostname label"),
        }

        // Labels should only contain alphanumeric and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            bail!("Hostname contains invalid characters");
        }
    }

    Ok(())
}

/// Validate a protocol name
pub fn validate_protocol(protocol: &str) -> Result<()> {
    const VALID_PROTOCOLS: &[&str] = &[
        "tcp", "udp", "icmp", "icmpv6", "esp", "ah", "gre", "ipip",
        "tcp", "udp", "icmp", "sctp", "all", "any",
    ];

    let proto_lower = protocol.to_lowercase();

    if !VALID_PROTOCOLS.contains(&proto_lower.as_str()) {
        bail!("Invalid protocol '{}'. Must be one of: {:?}", protocol, VALID_PROTOCOLS);
    }

    Ok(())
}

/// Validate a firewall action
pub fn validate_firewall_action(action: &str) -> Result<()> {
    const VALID_ACTIONS: &[&str] = &["allow", "deny", "reject", "drop"];

    let action_lower = action.to_lowercase();

    if !VALID_ACTIONS.contains(&action_lower.as_str()) {
        bail!("Invalid action '{}'. Must be one of: {:?}", action, VALID_ACTIONS);
    }

    Ok(())
}

/// Validate and sanitize a comment/description field
pub fn sanitize_comment(comment: &str, max_length: usize) -> Result<String> {
    if comment.len() > max_length {
        bail!("Comment too long (max {} characters)", max_length);
    }

    // Remove control characters and potentially dangerous characters
    let sanitized: String = comment
        .chars()
        .filter(|c| {
            !c.is_control()
                && *c != '\n'
                && *c != '\r'
                && *c != '\t'
                && *c != '\\'
                && *c != '"'
                && *c != '\''
                && *c != '`'
                && *c != '$'
                && *c != '&'
                && *c != '|'
                && *c != ';'
        })
        .collect();

    Ok(sanitized)
}

/// Validate a file path (prevent path traversal)
pub fn validate_safe_path(path: &Path, allowed_base: &Path) -> Result<PathBuf> {
    // Canonicalize both paths
    let canonical_base = allowed_base
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("Invalid base path: {}", e))?;

    let canonical_path = if path.is_relative() {
        canonical_base.join(path)
    } else {
        path.canonicalize()
            .map_err(|e| anyhow::anyhow!("Invalid path: {}", e))?
    };

    // Ensure the path is within the allowed base
    if !canonical_path.starts_with(&canonical_base) {
        bail!(
            "Path traversal detected: {:?} is outside {:?}",
            canonical_path,
            canonical_base
        );
    }

    // Check for suspicious path components
    for component in path.components() {
        let component_str = component.as_os_str().to_string_lossy();
        if component_str.contains("..") {
            bail!("Path contains '..' component");
        }
    }

    Ok(canonical_path)
}

/// Validate a URL (basic validation to prevent injection)
pub fn validate_url(url: &str) -> Result<()> {
    if url.is_empty() {
        bail!("URL cannot be empty");
    }

    // Must start with http:// or https://
    if !url.starts_with("http://") && !url.starts_with("https://") {
        bail!("URL must start with http:// or https://");
    }

    // Check for obvious injection attempts
    if url.contains('\n')
        || url.contains('\r')
        || url.contains('\0')
        || url.contains(' ')
        || url.contains('<')
        || url.contains('>')
    {
        bail!("URL contains invalid characters");
    }

    // Length check
    if url.len() > 2048 {
        bail!("URL too long (max 2048 characters)");
    }

    Ok(())
}

/// Validate a MAC address
pub fn validate_mac_address(mac: &str) -> Result<()> {
    // MAC address should be in format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else {
        bail!("MAC address must use ':' or '-' as separator");
    };

    if parts.len() != 6 {
        bail!("MAC address must have 6 octets");
    }

    for part in parts {
        if part.len() != 2 {
            bail!("Each MAC address octet must be 2 hex digits");
        }

        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("MAC address contains non-hexadecimal characters");
        }
    }

    Ok(())
}

/// Validate a VLAN ID
pub fn validate_vlan_id(vlan: u16) -> Result<()> {
    if vlan == 0 || vlan > 4094 {
        bail!("VLAN ID must be between 1 and 4094");
    }
    Ok(())
}

/// Validate alphanumeric identifier (for names, keys, etc.)
pub fn validate_identifier(id: &str, max_length: usize) -> Result<()> {
    if id.is_empty() {
        bail!("Identifier cannot be empty");
    }

    if id.len() > max_length {
        bail!("Identifier too long (max {} characters)", max_length);
    }

    // Must start with letter (safe to use match since we already checked non-empty)
    match id.chars().next() {
        Some(first) if first.is_alphabetic() => {}
        _ => bail!("Identifier must start with a letter"),
    }

    // Only alphanumeric, underscore, hyphen
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        bail!("Identifier can only contain alphanumeric, underscore, and hyphen");
    }

    Ok(())
}

/// Escape a string for safe use in shell commands
pub fn escape_shell_arg(arg: &str) -> String {
    // Use single quotes and escape any single quotes in the string
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Validate email address (basic validation)
pub fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() {
        bail!("Email cannot be empty");
    }

    if !email.contains('@') {
        bail!("Email must contain '@'");
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        bail!("Email must have exactly one '@'");
    }

    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() || domain.is_empty() {
        bail!("Email local and domain parts cannot be empty");
    }

    // Validate domain part
    validate_hostname(domain)?;

    // Basic length check
    if email.len() > 254 {
        bail!("Email too long (max 254 characters)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_interface_name() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("br-lan").is_ok());

        // Invalid cases
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("interface_with_very_long_name").is_err());
        assert!(validate_interface_name("eth0;rm -rf").is_err());
        assert!(validate_interface_name("eth0&&whoami").is_err());
    }

    #[test]
    fn test_validate_ip_address() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("::1").is_ok());
        assert!(validate_ip_address("2001:db8::1").is_ok());

        assert!(validate_ip_address("invalid").is_err());
        assert!(validate_ip_address("256.1.1.1").is_err());
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());

        assert!(validate_cidr("192.168.1.0").is_err());
        assert!(validate_cidr("192.168.1.0/33").is_err());
        assert!(validate_cidr("::1/129").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("my-host").is_ok());

        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid").is_err());
        assert!(validate_hostname("invalid..com").is_err());
    }

    #[test]
    fn test_sanitize_comment() {
        assert_eq!(
            sanitize_comment("Normal comment", 100).unwrap(),
            "Normal comment"
        );

        let result = sanitize_comment("Comment with $injection; attempt", 100).unwrap();
        assert!(!result.contains('$'));
        assert!(!result.contains(';'));

        assert!(sanitize_comment("Very long comment".repeat(100).as_str(), 50).is_err());
    }

    #[test]
    fn test_validate_mac_address() {
        assert!(validate_mac_address("00:11:22:33:44:55").is_ok());
        assert!(validate_mac_address("00-11-22-33-44-55").is_ok());
        assert!(validate_mac_address("AA:BB:CC:DD:EE:FF").is_ok());

        assert!(validate_mac_address("00:11:22:33:44").is_err());
        assert!(validate_mac_address("00:11:22:33:44:ZZ").is_err());
        assert!(validate_mac_address("invalid").is_err());
    }

    #[test]
    fn test_validate_vlan_id() {
        assert!(validate_vlan_id(1).is_ok());
        assert!(validate_vlan_id(100).is_ok());
        assert!(validate_vlan_id(4094).is_ok());

        assert!(validate_vlan_id(0).is_err());
        assert!(validate_vlan_id(4095).is_err());
    }

    #[test]
    fn test_escape_shell_arg() {
        assert_eq!(escape_shell_arg("normal"), "'normal'");
        assert_eq!(escape_shell_arg("with space"), "'with space'");
        assert_eq!(escape_shell_arg("with'quote"), "'with'\\''quote'");
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@sub.example.com").is_ok());

        assert!(validate_email("").is_err());
        assert!(validate_email("no-at-sign").is_err());
        assert!(validate_email("@no-local.com").is_err());
        assert!(validate_email("no-domain@").is_err());
    }
}
