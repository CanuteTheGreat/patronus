//! IDS/IPS configuration example
//!
//! This example demonstrates how to configure Patronus with an
//! intrusion detection/prevention system.

use patronus_network::ids::{
    IdsManager, IdsBackend, IdsConfig, IdsMode, IdsRule, RuleAction,
    RuleSource, IdsPerformance,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Patronus IDS/IPS Setup ===\n");

    // Check available IDS backends
    println!("1. Detecting available IDS/IPS backends...");
    let backends = IdsManager::list_available_backends();

    if backends.is_empty() {
        eprintln!("ERROR: No IDS/IPS backends available!");
        eprintln!("Install one of:");
        eprintln!("  - Suricata: emerge net-analyzer/suricata");
        eprintln!("  - Snort: emerge net-analyzer/snort");
        return Ok(());
    }

    println!("  Available backends:");
    for backend in &backends {
        println!("    - {}", backend);
    }

    // Choose backend (Gentoo way - give options!)
    let backend = if backends.contains(&IdsBackend::Suricata) {
        println!("  Using: Suricata (modern, multi-threaded)");
        IdsBackend::Suricata
    } else if backends.contains(&IdsBackend::Snort3) {
        println!("  Using: Snort 3 (latest Snort)");
        IdsBackend::Snort3
    } else {
        println!("  Using: Snort 2 (classic, proven)");
        IdsBackend::Snort2
    };
    println!();

    let ids_mgr = IdsManager::new(backend.clone());

    // Configure IDS/IPS
    println!("2. Configuring IDS/IPS...");

    let config = IdsConfig {
        enabled: true,
        backend: backend.clone(),
        mode: IdsMode::IDS,  // Start with detection only

        // Monitor WAN interface
        interfaces: vec!["eth1".to_string()],

        // Define networks
        home_net: vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
        ],
        external_net: vec!["!$HOME_NET".to_string()],

        // Rule sources
        rule_sources: vec![
            RuleSource {
                name: "Emerging Threats Open".to_string(),
                enabled: true,
                url: "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz".to_string(),
                update_interval_hours: 24,
            },
            RuleSource {
                name: "Abuse.ch SSL Blacklist".to_string(),
                enabled: true,
                url: "https://sslbl.abuse.ch/blacklist/sslblacklist.rules".to_string(),
                update_interval_hours: 12,
            },
        ],

        // Custom rules for specific threats
        custom_rules: vec![
            IdsRule {
                name: "Detect Crypto Mining".to_string(),
                enabled: true,
                action: RuleAction::Alert,
                protocol: "tcp".to_string(),
                src_ip: "$HOME_NET".to_string(),
                src_port: "any".to_string(),
                dst_ip: "$EXTERNAL_NET".to_string(),
                dst_port: "3333".to_string(),  // Common mining pool port
                msg: "Cryptocurrency mining detected".to_string(),
                sid: 1000010,
                rev: 1,
                content: Some("stratum+tcp".to_string()),
                pcre: None,
                classtype: Some("policy-violation".to_string()),
                priority: 2,
            },
            IdsRule {
                name: "Ransomware Communication".to_string(),
                enabled: true,
                action: RuleAction::Drop,  // Block this!
                protocol: "tcp".to_string(),
                src_ip: "$HOME_NET".to_string(),
                src_port: "any".to_string(),
                dst_ip: "$EXTERNAL_NET".to_string(),
                dst_port: "any".to_string(),
                msg: "Possible ransomware C2 communication".to_string(),
                sid: 1000011,
                rev: 1,
                content: None,
                pcre: Some(r"/\.(onion|i2p)/i".to_string()),
                classtype: Some("trojan-activity".to_string()),
                priority: 1,
            },
        ],

        enabled_categories: vec![
            "malware".to_string(),
            "exploit".to_string(),
            "trojan".to_string(),
            "botnet".to_string(),
            "dos".to_string(),
            "scan".to_string(),
            "web-attack".to_string(),
        ],

        performance: IdsPerformance {
            workers: Some(4),  // 4 worker threads
            ring_size: 8192,   // Larger buffer for high traffic
            af_packet: true,   // Use AF_PACKET for performance
            hardware_offload: false,
        },

        // Comprehensive logging
        log_alerts: true,
        log_pcap: false,    // Don't log packets (huge storage)
        log_flow: true,
        log_http: true,
        log_tls: true,
        log_dns: true,
        log_files: true,
    };

    println!("  Configuration:");
    println!("    Backend: {}", config.backend);
    println!("    Mode: {:?}", config.mode);
    println!("    Interfaces: {}", config.interfaces.join(", "));
    println!("    Home Networks: {}", config.home_net.join(", "));
    println!("    Rule Sources: {}", config.rule_sources.len());
    println!("    Custom Rules: {}", config.custom_rules.len());
    println!("    Categories: {}", config.enabled_categories.len());
    println!();

    // Generate configuration files
    println!("3. Generating IDS/IPS configuration...");
    ids_mgr.configure(&config).await?;
    println!("  ✓ Configuration generated");
    println!();

    // Update rules
    println!("4. Updating rule databases...");
    println!("  (This downloads the latest threat signatures)");
    match backend {
        IdsBackend::Suricata => {
            println!("  Run: suricata-update");
        }
        IdsBackend::Snort3 | IdsBackend::Snort2 => {
            println!("  Run: pulledpork3.pl -c /etc/patronus/ids/pulledpork.conf");
        }
    }
    println!();

    println!("=== Setup Complete! ===\n");

    println!("Next steps:\n");

    match backend {
        IdsBackend::Suricata => {
            println!("1. Test configuration:");
            println!("   suricata -T -c /etc/patronus/ids/suricata.yaml");
            println!();
            println!("2. Start Suricata (IDS mode):");
            println!("   systemctl start patronus-ids");
            println!("   systemctl enable patronus-ids");
            println!();
            println!("3. Monitor alerts:");
            println!("   tail -f /var/log/patronus/ids/fast.log");
            println!("   tail -f /var/log/patronus/ids/eve.json | jq");
            println!();
            println!("4. For IPS mode (inline blocking):");
            println!("   - Change mode to IPS in config");
            println!("   - Configure nftables NFQUEUE:");
            println!("     nft add rule filter forward ct state new queue num 0");
            println!("   - Restart Suricata");
        }
        IdsBackend::Snort3 => {
            println!("1. Test configuration:");
            println!("   snort -c /etc/patronus/ids/snort.lua -T");
            println!();
            println!("2. Start Snort (IDS mode):");
            println!("   systemctl start patronus-ids");
            println!("   systemctl enable patronus-ids");
            println!();
            println!("3. Monitor alerts:");
            println!("   tail -f /var/log/patronus/ids/alerts.txt");
            println!("   tail -f /var/log/patronus/ids/alerts.json | jq");
        }
        IdsBackend::Snort2 => {
            println!("1. Test configuration:");
            println!("   snort -c /etc/patronus/ids/snort.conf -T");
            println!();
            println!("2. Start Snort (IDS mode):");
            println!("   systemctl start patronus-ids");
            println!();
            println!("3. Monitor alerts:");
            println!("   tail -f /var/log/patronus/ids/alerts.txt");
        }
    }

    println!();
    println!("Performance Tuning:");
    println!("  - Adjust worker threads based on CPU cores");
    println!("  - Increase ring_size for high-traffic networks");
    println!("  - Enable hardware offload if NIC supports it");
    println!("  - Use AF_PACKET for best performance on Linux");
    println!();
    println!("Security Tips:");
    println!("  - Start in IDS mode to tune rules");
    println!("  - Monitor false positives for 1-2 weeks");
    println!("  - Then switch to IPS mode for active blocking");
    println!("  - Update rules daily for latest threat intel");

    Ok(())
}
