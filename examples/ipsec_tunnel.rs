//! IPsec site-to-site tunnel example
//!
//! This example demonstrates how to configure an IPsec VPN tunnel between two sites.

use patronus_network::ipsec::{
    IpsecManager, IpsecTunnelConfig, IpsecAuthMethod,
    IpsecCipher, IpsecIntegrity, DhGroup,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    println!("=== Patronus IPsec Site-to-Site Tunnel ===\n");

    let ipsec_mgr = IpsecManager::new();

    // Configure tunnel (Site A -> Site B)
    println!("1. Configuring IPsec tunnel...");

    let mut tunnel = IpsecTunnelConfig::default();
    tunnel.name = "site-a-to-site-b".to_string();
    tunnel.ikev2 = true;

    // Local (Site A) configuration
    tunnel.local_id = Some("siteA.example.com".to_string());
    tunnel.local_subnets = vec!["10.0.1.0/24".to_string()];

    // Remote (Site B) configuration
    tunnel.remote_address = "203.0.113.100".to_string();
    tunnel.remote_id = Some("siteB.example.com".to_string());
    tunnel.remote_subnets = vec!["10.0.2.0/24".to_string()];

    // Use PSK authentication for this example
    tunnel.auth_method = IpsecAuthMethod::Psk;
    tunnel.psk = Some("SuperSecretPreSharedKey123!".to_string());

    // Strong cryptography
    tunnel.ike_cipher = vec![IpsecCipher::Aes256, IpsecCipher::Aes256Gcm128];
    tunnel.ike_integrity = vec![IpsecIntegrity::Sha512, IpsecIntegrity::Sha256];
    tunnel.ike_dh_group = vec![DhGroup::Ecp256, DhGroup::Modp2048];
    tunnel.ike_lifetime = 28800;  // 8 hours

    tunnel.esp_cipher = vec![IpsecCipher::Aes256Gcm128, IpsecCipher::Aes256];
    tunnel.esp_integrity = vec![IpsecIntegrity::Sha512];
    tunnel.esp_dh_group = vec![DhGroup::Ecp256];  // PFS
    tunnel.esp_lifetime = 3600;  // 1 hour

    // High availability settings
    tunnel.auto_start = true;
    tunnel.dpdaction = "restart".to_string();
    tunnel.dpddelay = 30;
    tunnel.close_action = "restart".to_string();

    println!("  Tunnel Configuration:");
    println!("    Name: {}", tunnel.name);
    println!("    Local: {} ({})", tunnel.local_id.as_ref().unwrap(), tunnel.local_subnets.join(", "));
    println!("    Remote: {} @ {} ({})",
        tunnel.remote_id.as_ref().unwrap(),
        tunnel.remote_address,
        tunnel.remote_subnets.join(", ")
    );
    println!("    Authentication: {}", tunnel.auth_method);
    println!("    IKE Ciphers: {:?}", tunnel.ike_cipher);
    println!("    ESP Ciphers: {:?}", tunnel.esp_cipher);
    println!();

    // Save configuration
    println!("2. Saving configuration...");
    ipsec_mgr.save_tunnel_config(&tunnel).await?;
    println!("  ✓ Configuration saved\n");

    // Start strongSwan
    println!("3. Starting strongSwan...");
    ipsec_mgr.start().await?;
    println!("  ✓ strongSwan started\n");

    // Bring up the tunnel
    println!("4. Bringing up tunnel...");
    ipsec_mgr.start_tunnel(&tunnel.name).await?;
    println!("  ✓ Tunnel initiated\n");

    println!("=== Setup Complete! ===\n");
    println!("Next steps:");
    println!();
    println!("1. Configure Site B with matching settings:");
    println!("   - Local: siteB.example.com (10.0.2.0/24)");
    println!("   - Remote: siteA.example.com (10.0.1.0/24)");
    println!("   - Same PSK");
    println!();
    println!("2. Check tunnel status:");
    println!("   sudo ipsec status");
    println!();
    println!("3. View security associations:");
    println!("   sudo ipsec statusall");
    println!();
    println!("4. Monitor logs:");
    println!("   sudo tail -f /var/log/syslog | grep charon");
    println!();
    println!("5. Test connectivity:");
    println!("   ping -c 4 10.0.2.1  # From Site A to Site B");

    Ok(())
}
