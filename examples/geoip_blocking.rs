//! GeoIP Blocking Example
//!
//! This example demonstrates country-based firewall filtering using
//! GeoIP databases.

use patronus_firewall::geoip::{
    GeoIpManager, GeoIpBackend, GeoIpConfig, GeoIpRule, GeoIpAction,
    TrafficDirection, CountryCodes,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Patronus GeoIP Blocking ===\n");

    // Check available backends
    println!("1. Detecting GeoIP backends...");
    let backends = GeoIpManager::list_available_backends();

    if backends.is_empty() {
        eprintln!("ERROR: No GeoIP databases found!");
        eprintln!("Install one of:");
        eprintln!("  - GeoIP2: emerge dev-libs/libmaxminddb");
        eprintln!("           Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data");
        eprintln!("  - GeoIP Legacy: emerge dev-libs/geoip");
        return Ok(());
    }

    println!("  Available backends:");
    for backend in &backends {
        println!("    - {}", backend);
    }

    // Choose backend
    let backend = if backends.contains(&GeoIpBackend::GeoIp2) {
        println!("  Using: GeoIP2 (modern, accurate)");
        GeoIpBackend::GeoIp2
    } else {
        println!("  Using: Legacy GeoIP (deprecated)");
        GeoIpBackend::GeoIpLegacy
    };
    println!();

    let geoip_mgr = GeoIpManager::new(backend.clone());

    // Example 1: Block specific countries
    println!("=== Example 1: Block High-Risk Countries ===\n");
    println!("Use case: Block traffic from countries with high attack rates\n");

    let block_rule = GeoIpRule {
        name: "Block Abusive Countries".to_string(),
        enabled: true,
        action: GeoIpAction::Block,
        countries: vec![
            CountryCodes::CN.to_string(),  // China
            CountryCodes::RU.to_string(),  // Russia
            CountryCodes::KP.to_string(),  // North Korea
            CountryCodes::IR.to_string(),  // Iran
        ],
        interfaces: vec!["wan".to_string(), "eth1".to_string()],
        direction: TrafficDirection::Inbound,
        log: true,
        comment: Some("Security: Block high-risk countries".to_string()),
    };

    println!("Block Rule:");
    println!("  Countries: {}", block_rule.countries.join(", "));
    println!("  Action: {:?}", block_rule.action);
    println!("  Direction: {:?}", block_rule.direction);
    println!("  Logging: {}", block_rule.log);
    println!();

    // Example 2: Allow only specific countries
    println!("=== Example 2: Allow Only Local Country ===\n");
    println!("Use case: Service only for local users\n");

    let allow_rule = GeoIpRule {
        name: "Allow Local Only".to_string(),
        enabled: true,
        action: GeoIpAction::Allow,
        countries: vec![
            CountryCodes::US.to_string(),  // United States
            CountryCodes::CA.to_string(),  // Canada
            CountryCodes::MX.to_string(),  // Mexico
        ],
        interfaces: vec!["wan".to_string()],
        direction: TrafficDirection::Inbound,
        log: false,
        comment: Some("Allow North America only".to_string()),
    };

    println!("Allow Rule:");
    println!("  Countries: {}", allow_rule.countries.join(", "));
    println!("  Comment: {}", allow_rule.comment.as_ref().unwrap());
    println!();

    // Example 3: Block outbound to specific countries
    println!("=== Example 3: Prevent Data Exfiltration ===\n");
    println!("Use case: Block outbound connections to untrusted countries\n");

    let outbound_block = GeoIpRule {
        name: "Block Outbound to High-Risk".to_string(),
        enabled: true,
        action: GeoIpAction::Block,
        countries: vec![
            CountryCodes::CN.to_string(),
            CountryCodes::RU.to_string(),
        ],
        interfaces: vec!["wan".to_string()],
        direction: TrafficDirection::Outbound,
        log: true,
        comment: Some("Prevent data exfiltration".to_string()),
    };

    println!("Outbound Block:");
    println!("  Countries: {}", outbound_block.countries.join(", "));
    println!("  Direction: {:?}", outbound_block.direction);
    println!();

    // Create full configuration
    let mut config = GeoIpConfig {
        enabled: true,
        backend: backend.clone(),
        database_path: PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
        auto_update: true,
        update_interval_days: 7,
        rules: vec![
            block_rule,
            allow_rule,
            outbound_block,
        ],
    };

    println!("=== Full Configuration ===\n");
    println!("Backend: {}", config.backend);
    println!("Auto-Update: {} (every {} days)", config.auto_update, config.update_interval_days);
    println!("Active Rules: {}", config.rules.len());
    println!();

    // Generate IP sets
    println!("2. Downloading IP address blocks...");
    println!("   (This downloads current IP ranges for each country)");
    geoip_mgr.generate_ipsets(&config).await?;
    println!("   ✓ IP sets generated\n");

    // Generate nftables rules
    println!("3. Generating nftables rules...");
    let nft_rules = geoip_mgr.apply_rules(&config).await?;
    println!("   ✓ Rules generated ({} lines)\n", nft_rules.lines().count());

    // Show sample rules
    println!("=== Sample nftables Rules ===\n");
    println!("{}", nft_rules.lines().take(40).collect::<Vec<_>>().join("\n"));
    println!("...\n");

    // IP Lookup example
    println!("=== IP Address Lookup ===\n");

    let test_ips = vec![
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("192.168.1.1", "Private IP"),
    ];

    for (ip, description) in test_ips {
        if let Ok(ip_addr) = ip.parse() {
            match geoip_mgr.lookup_country(ip_addr).await {
                Ok(country) => {
                    println!("  {} ({}): {}", ip, description, country);
                }
                Err(_) => {
                    println!("  {} ({}): Lookup failed", ip, description);
                }
            }
        }
    }
    println!();

    println!("=== Setup Complete! ===\n");

    println!("Next steps:\n");
    println!("1. Review generated rules:");
    println!("   cat /etc/patronus/geoip/rules.nft");
    println!();
    println!("2. Test without applying:");
    println!("   nft -c -f /etc/patronus/geoip/rules.nft");
    println!();
    println!("3. Apply rules:");
    println!("   patronus firewall apply");
    println!();
    println!("4. Monitor blocked traffic:");
    println!("   tail -f /var/log/syslog | grep GeoIP");
    println!();
    println!("5. Update GeoIP database:");
    println!("   patronus geoip update");
    println!();

    println!("=== Common Use Cases ===\n");

    println!("1. E-commerce (US-only store):");
    println!("   - Allow: US, CA");
    println!("   - Block: All others");
    println!("   - Reduces fraud from international cards");
    println!();

    println!("2. Enterprise security:");
    println!("   - Block: CN, RU, KP, IR (high-risk)");
    println!("   - Log all blocks for analysis");
    println!("   - Review logs weekly");
    println!();

    println!("3. Compliance (GDPR/Data residency):");
    println!("   - Block outbound to non-EU countries");
    println!("   - Allow: DE, FR, GB, IT, etc.");
    println!("   - Ensures data stays in EU");
    println!();

    println!("4. Gaming servers:");
    println!("   - Allow specific regions only");
    println!("   - Reduces latency");
    println!("   - Prevents region-hopping");
    println!();

    println!("=== Important Notes ===\n");

    println!("⚠ GeoIP is not perfect:");
    println!("  - IPs can be misclassified");
    println!("  - VPNs/proxies bypass GeoIP");
    println!("  - Mobile users may appear in wrong country");
    println!("  - Update databases regularly!");
    println!();

    println!("✓ Best practices:");
    println!("  - Start with logging only (action: log)");
    println!("  - Monitor for false positives");
    println!("  - Whitelist known good IPs");
    println!("  - Combine with other security layers");
    println!("  - Keep databases updated weekly");
    println!();

    println!("📊 Database sources:");
    println!("  - MaxMind GeoLite2 (free, requires account)");
    println!("  - IPdeny.com (free IP blocks)");
    println!("  - DB-IP (free tier available)");
    println!();

    println!("🔧 Troubleshooting:");
    println!("  - \"Database not found\": Download GeoIP database");
    println!("  - \"Permission denied\": Run as root or with CAP_NET_ADMIN");
    println!("  - \"Too many IPs\": Increase nftables limits");
    println!("  - \"Slow updates\": Use cron for off-peak updates");

    Ok(())
}
