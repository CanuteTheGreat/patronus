//! Certificate Management Example
//!
//! This example demonstrates automated SSL/TLS certificate management
//! with Let's Encrypt using either acme.sh or certbot.

use patronus_core::certs::{
    CertManager, CertBackend, CertConfig, AcmeChallenge, KeyType, DnsProviders,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Patronus Certificate Management ===\n");

    // Check available backends
    println!("1. Detecting certificate backends...");
    let backends = CertManager::list_available_backends();

    if backends.is_empty() {
        eprintln!("ERROR: No certificate backends available!");
        eprintln!("Install one of:");
        eprintln!("  - acme.sh: emerge app-crypt/acme-sh");
        eprintln!("  - certbot: emerge app-crypt/certbot");
        return Ok(());
    }

    println!("  Available backends:");
    for backend in &backends {
        println!("    - {}", backend);
    }

    // Choose backend (Gentoo way!)
    let backend = if backends.contains(&CertBackend::AcmeSh) {
        println!("  Using: acme.sh (lightweight, shell-based)");
        CertBackend::AcmeSh
    } else {
        println!("  Using: certbot (official Let's Encrypt client)");
        CertBackend::Certbot
    };
    println!();

    let cert_mgr = CertManager::new(backend.clone());

    // Example 1: Simple HTTP-01 challenge (most common)
    println!("=== Example 1: HTTP-01 Challenge ===\n");
    println!("Use case: Simple website with port 80 accessible\n");

    let http_config = CertConfig {
        name: "web-server".to_string(),
        enabled: true,
        domains: vec![
            "patronus.example.com".to_string(),
            "www.patronus.example.com".to_string(),  // SAN
        ],
        email: "admin@example.com".to_string(),
        challenge: AcmeChallenge::Http01,
        key_type: KeyType::ECDSA,  // Modern, smaller, faster
        key_length: 256,
        auto_renew: true,
        renew_days_before: 30,
        post_renew_hook: Some("systemctl reload nginx".to_string()),
    };

    println!("HTTP-01 Configuration:");
    println!("  Domains: {}", http_config.domains.join(", "));
    println!("  Challenge: HTTP-01 (serves file on port 80)");
    println!("  Key Type: {:?} {}-bit", http_config.key_type, http_config.key_length);
    println!("  Auto-Renew: {}", http_config.auto_renew);
    println!();

    println!("To issue this certificate:");
    println!("  1. Ensure port 80 is accessible from internet");
    println!("  2. Stop web server temporarily (or use webroot mode)");
    println!("  3. Run: patronus cert issue web-server");
    println!();

    // Example 2: DNS-01 challenge (for wildcard certs)
    println!("=== Example 2: DNS-01 Challenge (Wildcard) ===\n");
    println!("Use case: Wildcard certificate for *.example.com\n");

    let dns_config = CertConfig {
        name: "wildcard".to_string(),
        enabled: true,
        domains: vec![
            "*.patronus.example.com".to_string(),  // Wildcard!
            "patronus.example.com".to_string(),     // Also include apex
        ],
        email: "admin@example.com".to_string(),
        challenge: AcmeChallenge::Dns01 {
            provider: DnsProviders::CLOUDFLARE.to_string(),
        },
        key_type: KeyType::ECDSA,
        key_length: 384,  // Stronger for wildcard
        auto_renew: true,
        renew_days_before: 30,
        post_renew_hook: Some("patronus reload-services".to_string()),
    };

    println!("DNS-01 Configuration:");
    println!("  Domains: {}", dns_config.domains.join(", "));
    println!("  Challenge: DNS-01 via Cloudflare");
    println!("  Key Type: {:?} {}-bit", dns_config.key_type, dns_config.key_length);
    println!();

    println!("Supported DNS providers:");
    println!("  - Cloudflare (dns_cf)");
    println!("  - AWS Route53 (dns_aws)");
    println!("  - DigitalOcean (dns_dgon)");
    println!("  - Namecheap (dns_namecheap)");
    println!("  - And 100+ more!");
    println!();

    println!("Setup for Cloudflare:");
    println!("  export CF_Token=\"your-api-token\"");
    println!("  export CF_Account_ID=\"your-account-id\"");
    println!();

    // Example 3: Multiple certificates
    println!("=== Example 3: VPN Server Certificate ===\n");

    let vpn_config = CertConfig {
        name: "vpn-server".to_string(),
        enabled: true,
        domains: vec!["vpn.patronus.example.com".to_string()],
        email: "admin@example.com".to_string(),
        challenge: AcmeChallenge::Http01,
        key_type: KeyType::RSA,  // Some VPN clients prefer RSA
        key_length: 2048,
        auto_renew: true,
        renew_days_before: 30,
        post_renew_hook: Some("systemctl restart openvpn".to_string()),
    };

    println!("VPN Certificate:");
    println!("  Domain: {}", vpn_config.domains[0]);
    println!("  Key Type: RSA 2048 (broader compatibility)");
    println!("  Post-Renewal: Restart OpenVPN");
    println!();

    // Get certificate paths
    println!("=== Certificate Paths ===\n");

    let paths = cert_mgr.get_cert_paths("patronus.example.com");
    println!("After issuing, find certificates at:");
    println!("  Certificate: {}", paths.cert.display());
    println!("  Private Key: {}", paths.key.display());
    println!("  Chain: {}", paths.chain.display());
    println!("  Full Chain: {}", paths.fullchain.display());
    println!();

    // Setup auto-renewal
    println!("=== Auto-Renewal Setup ===\n");

    println!("Setting up automatic renewal...");
    cert_mgr.setup_auto_renewal().await?;
    println!("✓ Cron job installed");
    println!();

    match backend {
        CertBackend::AcmeSh => {
            println!("Renewal runs daily at midnight");
            println!("Checks all certificates and renews if needed");
            println!("Manual renewal: acme.sh --cron --force");
        }
        CertBackend::Certbot => {
            println!("Renewal runs twice daily (recommended by Let's Encrypt)");
            println!("Manual renewal: certbot renew");
        }
    }
    println!();

    println!("=== Usage Commands ===\n");

    println!("Issue a certificate:");
    println!("  patronus cert issue <name>");
    println!();

    println!("Renew a certificate:");
    println!("  patronus cert renew <domain>");
    println!();

    println!("Renew all certificates:");
    println!("  patronus cert renew-all");
    println!();

    println!("List all certificates:");
    println!("  patronus cert list");
    println!();

    println!("Revoke a certificate:");
    println!("  patronus cert revoke <domain>");
    println!();

    println!("=== Integration Examples ===\n");

    println!("Nginx configuration:");
    println!(r#"  server {{
      listen 443 ssl http2;
      server_name patronus.example.com;

      ssl_certificate     /etc/patronus/certs/patronus.example.com/fullchain.pem;
      ssl_certificate_key /etc/patronus/certs/patronus.example.com/privkey.pem;

      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
      ssl_prefer_server_ciphers off;
  }}"#);
    println!();

    println!("OpenVPN configuration:");
    println!("  ca /etc/patronus/certs/vpn.example.com/chain.pem");
    println!("  cert /etc/patronus/certs/vpn.example.com/cert.pem");
    println!("  key /etc/patronus/certs/vpn.example.com/privkey.pem");
    println!();

    println!("Patronus Web UI:");
    println!("  Automatically uses certificates from /etc/patronus/certs/");
    println!("  Configure in /etc/patronus/patronus.toml:");
    println!("  [web]");
    println!("  https = true");
    println!(r#"  cert = "/etc/patronus/certs/patronus.example.com/fullchain.pem""#);
    println!(r#"  key = "/etc/patronus/certs/patronus.example.com/privkey.pem""#);
    println!();

    println!("=== Best Practices ===\n");

    println!("✓ Use ECDSA for modern systems (smaller, faster)");
    println!("✓ Use RSA 2048 for legacy compatibility");
    println!("✓ Always use DNS-01 for wildcard certificates");
    println!("✓ Set up post-renewal hooks to reload services");
    println!("✓ Monitor certificate expiration (Patronus alerts you)");
    println!("✓ Test renewals before they're critical");
    println!("✓ Keep email address current for expiration warnings");

    println!();
    println!("=== Rate Limits (Let's Encrypt) ===\n");

    println!("Important limits to know:");
    println!("  - 50 certificates per domain per week");
    println!("  - 5 duplicate certificates per week");
    println!("  - 300 new orders per account per 3 hours");
    println!("  - 10 accounts per IP per 3 hours");
    println!();
    println!("Use staging environment for testing!");
    println!("  acme.sh --staging");
    println!("  certbot --staging");

    Ok(())
}
