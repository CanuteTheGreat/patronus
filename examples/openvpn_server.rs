//! OpenVPN server configuration example
//!
//! This example demonstrates how to:
//! 1. Initialize PKI (CA, server cert, DH params)
//! 2. Configure an OpenVPN server
//! 3. Generate client certificates
//! 4. Export client configurations

use patronus_network::openvpn::{
    OpenVpnManager, OpenVpnServerConfig, OpenVpnClientConfig,
    OpenVpnProtocol, OpenVpnCipher, OpenVpnAuth,
};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== Patronus OpenVPN Server Setup ===\n");

    let openvpn_mgr = OpenVpnManager::new();

    // 1. Generate PKI (one-time setup)
    println!("1. Generating PKI infrastructure...");
    println!("  Generating CA certificate...");
    openvpn_mgr.generate_ca("Patronus VPN CA").await?;
    println!("  ✓ CA certificate generated");

    println!("  Generating server certificate...");
    openvpn_mgr.generate_server_cert("vpn.patronus.local").await?;
    println!("  ✓ Server certificate generated");

    println!("  Generating Diffie-Hellman parameters (this may take a while)...");
    openvpn_mgr.generate_dh_params(2048).await?;
    println!("  ✓ DH parameters generated");

    println!("  Generating TLS authentication key...");
    openvpn_mgr.generate_tls_key().await?;
    println!("  ✓ TLS key generated\n");

    // 2. Configure OpenVPN server
    println!("2. Configuring OpenVPN server...");
    let mut server_config = OpenVpnServerConfig::default();
    server_config.name = "main-server".to_string();
    server_config.port = 1194;
    server_config.protocol = OpenVpnProtocol::Udp;
    server_config.tunnel_network = "10.8.0.0".to_string();
    server_config.tunnel_netmask = "255.255.255.0".to_string();
    server_config.cipher = OpenVpnCipher::Aes256Gcm;
    server_config.auth = OpenVpnAuth::Sha256;
    server_config.tls_crypt = true;
    server_config.client_to_client = false;
    server_config.max_clients = 100;

    // Push routes to clients
    server_config.push_routes = vec![
        "192.168.1.0 255.255.255.0".to_string(), // LAN access
    ];

    // Push DNS servers
    server_config.push_dns = vec![
        Ipv4Addr::new(1, 1, 1, 1).into(),
        Ipv4Addr::new(8, 8, 8, 8).into(),
    ];

    println!("  Server configuration:");
    println!("    Protocol: {}", server_config.protocol);
    println!("    Port: {}", server_config.port);
    println!("    Tunnel: {}/{}", server_config.tunnel_network, server_config.tunnel_netmask);
    println!("    Cipher: {}", server_config.cipher);
    println!("    Auth: {}", server_config.auth);
    println!("    Max Clients: {}", server_config.max_clients);
    println!("    TLS-Crypt: {}", server_config.tls_crypt);

    // Save server configuration
    openvpn_mgr.save_server_config(&server_config).await?;
    println!("  ✓ Server configuration saved\n");

    // 3. Generate client certificates
    println!("3. Generating client certificates...");
    let clients = vec!["laptop", "phone", "tablet"];

    for client_name in &clients {
        println!("  Generating certificate for {}...", client_name);
        openvpn_mgr.generate_client_cert(client_name).await?;
        println!("  ✓ {} certificate generated", client_name);
    }
    println!();

    // 4. Create and export client configurations
    println!("4. Creating client configurations...");
    for client_name in &clients {
        let client_config = OpenVpnClientConfig {
            name: client_name.to_string(),
            enabled: true,
            remote_host: "vpn.patronus.local".to_string(), // Change to your server's public IP/hostname
            remote_port: 1194,
            protocol: OpenVpnProtocol::Udp,
            device: "tun".to_string(),
            cipher: OpenVpnCipher::Aes256Gcm,
            auth: OpenVpnAuth::Sha256,
            compression: false,
            verify_x509_name: Some("vpn.patronus.local".to_string()),
            ca_cert_path: format!("/etc/patronus/openvpn/ca.crt").into(),
            client_cert_path: format!("/etc/patronus/openvpn/clients/{}/client.crt", client_name).into(),
            client_key_path: format!("/etc/patronus/openvpn/clients/{}/client.key", client_name).into(),
            tls_crypt: true,
            tls_auth: false,
            tls_key_path: Some("/etc/patronus/openvpn/ta.key".into()),
        };

        // Save client config
        openvpn_mgr.save_client_config(&client_config).await?;

        // Export as single .ovpn file
        let ovpn_content = openvpn_mgr.export_client_config(&client_config).await?;
        tokio::fs::write(
            format!("/tmp/{}.ovpn", client_name),
            ovpn_content
        ).await?;

        println!("  ✓ {} configuration exported to /tmp/{}.ovpn", client_name, client_name);
    }
    println!();

    println!("=== Setup Complete! ===\n");
    println!("Next steps:");
    println!("1. Start the OpenVPN server:");
    println!("   sudo patronus vpn openvpn start-server main-server");
    println!();
    println!("2. Distribute client .ovpn files to users:");
    for client_name in &clients {
        println!("   /tmp/{}.ovpn", client_name);
    }
    println!();
    println!("3. Clients can connect using:");
    println!("   openvpn --config <client-name>.ovpn");
    println!();
    println!("4. Monitor server status:");
    println!("   sudo patronus vpn openvpn status main-server");
    println!();
    println!("5. View connected clients:");
    println!("   tail -f /var/log/patronus/openvpn-main-server-status.log");

    Ok(())
}
