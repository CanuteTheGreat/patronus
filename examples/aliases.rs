//! Firewall Aliases Example
//!
//! This example demonstrates how to use aliases to simplify firewall
//! rule management.

use patronus_firewall::aliases::{
    AliasManager, NetworkAlias, NetworkEntry, PortAlias, PortEntry,
    MacAlias, NetworkAliasBuilder, PortAliasBuilder, AliasType,
};

fn main() -> anyhow::Result<()> {
    println!("=== Patronus Firewall Aliases ===\n");

    let mut alias_mgr = AliasManager::new();

    // Load common presets
    println!("1. Loading common alias presets...");
    alias_mgr.load_common_aliases()?;
    println!("   ✓ Loaded standard aliases\n");

    // Show preloaded aliases
    println!("Preloaded aliases:");
    for (name, alias_type, count) in alias_mgr.list_all() {
        println!("  - {} ({:?}): {} entries", name, alias_type, count);
    }
    println!();

    // Example 1: Network aliases for infrastructure
    println!("=== Example 1: Infrastructure Network Aliases ===\n");

    let web_servers = NetworkAliasBuilder::new("WebServers")
        .description("Production web servers")
        .add_host("192.168.1.10".parse().unwrap())
        .add_host("192.168.1.11".parse().unwrap())
        .add_host("192.168.1.12".parse().unwrap())
        .build();

    alias_mgr.add_network_alias(web_servers)?;

    let db_servers = NetworkAliasBuilder::new("DatabaseServers")
        .description("Production database servers")
        .add_network("192.168.2.0".parse().unwrap(), 24)
        .build();

    alias_mgr.add_network_alias(db_servers)?;

    let dmz = NetworkAliasBuilder::new("DMZ")
        .description("DMZ network")
        .add_network("203.0.113.0".parse().unwrap(), 24)
        .build();

    alias_mgr.add_network_alias(dmz)?;

    let trusted_clients = NetworkAliasBuilder::new("TrustedClients")
        .description("Trusted client IP addresses")
        .add_host("203.0.113.50".parse().unwrap())  // Office
        .add_host("203.0.113.51".parse().unwrap())  // VPN gateway
        .add_range(
            "203.0.113.100".parse().unwrap(),
            "203.0.113.110".parse().unwrap(),
        )  // Partner network
        .build();

    alias_mgr.add_network_alias(trusted_clients)?;

    println!("Created network aliases:");
    println!("  - WebServers: 3 IPs");
    println!("  - DatabaseServers: 192.168.2.0/24");
    println!("  - DMZ: 203.0.113.0/24");
    println!("  - TrustedClients: IPs + ranges");
    println!();

    // Example 2: Port aliases for services
    println!("=== Example 2: Service Port Aliases ===\n");

    let custom_web = PortAliasBuilder::new("CustomWebPorts")
        .description("Custom web application ports")
        .add_port(8080)
        .add_port(8443)
        .add_port(9000)
        .build();

    alias_mgr.add_port_alias(custom_web)?;

    let monitoring = PortAliasBuilder::new("MonitoringPorts")
        .description("Monitoring and metrics ports")
        .add_port(9090)  // Prometheus
        .add_port(3000)  // Grafana
        .add_port(9100)  // Node Exporter
        .add_port(9093)  // Alertmanager
        .build();

    alias_mgr.add_port_alias(monitoring)?;

    let file_sharing = PortAliasBuilder::new("FileSharingPorts")
        .description("SMB and NFS ports")
        .add_port(445)   // SMB
        .add_port(139)   // NetBIOS
        .add_port(2049)  // NFS
        .add_range(111, 111)  // Portmap
        .build();

    alias_mgr.add_port_alias(file_sharing)?;

    println!("Created port aliases:");
    println!("  - CustomWebPorts: 8080, 8443, 9000");
    println!("  - MonitoringPorts: Prometheus, Grafana, etc.");
    println!("  - FileSharingPorts: SMB, NFS");
    println!();

    // Example 3: MAC address aliases
    println!("=== Example 3: MAC Address Aliases ===\n");

    let iot_devices = MacAlias {
        name: "IoTDevices".to_string(),
        description: Some("IoT devices on network".to_string()),
        mac_addresses: vec![
            "aa:bb:cc:dd:ee:01".to_string(),  // Smart TV
            "aa:bb:cc:dd:ee:02".to_string(),  // Security camera
            "aa:bb:cc:dd:ee:03".to_string(),  // Smart thermostat
        ],
    };

    alias_mgr.add_mac_alias(iot_devices)?;

    let admin_workstations = MacAlias {
        name: "AdminWorkstations".to_string(),
        description: Some("Administrator workstations".to_string()),
        mac_addresses: vec![
            "11:22:33:44:55:66".to_string(),
            "11:22:33:44:55:67".to_string(),
        ],
    };

    alias_mgr.add_mac_alias(admin_workstations)?;

    println!("Created MAC aliases:");
    println!("  - IoTDevices: 3 devices");
    println!("  - AdminWorkstations: 2 workstations");
    println!();

    // Generate nftables configuration
    println!("=== Generated nftables Configuration ===\n");

    let nft_config = alias_mgr.generate_nftables()?;
    println!("{}", nft_config);

    println!();
    println!("=== Usage in Firewall Rules ===\n");

    println!("Example rules using these aliases:\n");

    println!("1. Allow web traffic to web servers:");
    println!("   nft add rule inet filter forward ip daddr @WebServers tcp dport @WebPorts accept");
    println!();

    println!("2. Block database access except from web servers:");
    println!("   nft add rule inet filter forward ip daddr @DatabaseServers ip saddr != @WebServers tcp dport @DatabasePorts drop");
    println!();

    println!("3. Allow monitoring from trusted clients:");
    println!("   nft add rule inet filter input ip saddr @TrustedClients tcp dport @MonitoringPorts accept");
    println!();

    println!("4. Isolate IoT devices:");
    println!("   nft add rule inet filter forward ether saddr @IoTDevices ip daddr != @RFC1918 drop");
    println!();

    println!("5. Admin access only from workstations:");
    println!("   nft add rule inet filter input ether saddr @AdminWorkstations tcp dport 22 accept");
    println!();

    println!("=== Benefits of Using Aliases ===\n");

    println!("✓ Maintainability:");
    println!("  - Update one alias instead of many rules");
    println!("  - Example: Add new web server to WebServers alias");
    println!("  - All rules using @WebServers updated automatically");
    println!();

    println!("✓ Readability:");
    println!("  - Rules are self-documenting");
    println!("  - '@WebServers' is clearer than '192.168.1.10,192.168.1.11'");
    println!("  - Easier to audit and review");
    println!();

    println!("✓ Performance:");
    println!("  - nftables sets use hash tables");
    println!("  - O(1) lookup time regardless of size");
    println!("  - Can handle thousands of entries efficiently");
    println!();

    println!("✓ Flexibility:");
    println!("  - Aliases can reference other aliases");
    println!("  - Create hierarchies of rules");
    println!("  - Example: AllServers = WebServers + DatabaseServers");
    println!();

    println!("=== Real-World Examples ===\n");

    println!("Example 1: E-commerce Infrastructure");
    println!("  Aliases:");
    println!("    - FrontendServers (web tier)");
    println!("    - BackendServers (API tier)");
    println!("    - DatabaseServers (data tier)");
    println!("    - AdminIPs (trusted admins)");
    println!("  Rules:");
    println!("    - Internet → FrontendServers:443 (ALLOW)");
    println!("    - FrontendServers → BackendServers:8080 (ALLOW)");
    println!("    - BackendServers → DatabaseServers:5432 (ALLOW)");
    println!("    - AdminIPs → * (ALLOW)");
    println!("    - * → DatabaseServers (DENY)");
    println!();

    println!("Example 2: Office Network");
    println!("  Aliases:");
    println!("    - EmployeeNetwork");
    println!("    - GuestNetwork");
    println!("    - Servers");
    println!("    - Printers");
    println!("  Rules:");
    println!("    - EmployeeNetwork → Servers (ALLOW)");
    println!("    - EmployeeNetwork → Printers (ALLOW)");
    println!("    - GuestNetwork → Internet only (ALLOW)");
    println!("    - GuestNetwork → Internal (DENY)");
    println!();

    println!("Example 3: Multi-Tenant Environment");
    println!("  Aliases:");
    println!("    - TenantA_Network");
    println!("    - TenantB_Network");
    println!("    - TenantC_Network");
    println!("    - SharedServices");
    println!("  Rules:");
    println!("    - TenantA → SharedServices (ALLOW)");
    println!("    - TenantA → TenantB/C (DENY)");
    println!("    - Each tenant isolated from others");
    println!();

    println!("=== Best Practices ===\n");

    println!("1. Naming conventions:");
    println!("   - Use PascalCase: WebServers, DatabasePorts");
    println!("   - Be descriptive: TrustedClients not Trusted1");
    println!("   - Include type hint: ServersIPv4, PortsHTTPS");
    println!();

    println!("2. Organization:");
    println!("   - Group related aliases");
    println!("   - Document purpose in description");
    println!("   - Keep aliases small and focused");
    println!();

    println!("3. Maintenance:");
    println!("   - Review aliases quarterly");
    println!("   - Remove unused aliases");
    println!("   - Document changes in version control");
    println!();

    println!("4. Security:");
    println!("   - Use most restrictive aliases possible");
    println!("   - Avoid catch-all aliases");
    println!("   - Regularly audit alias contents");
    println!();

    println!("=== CLI Commands ===\n");

    println!("Create alias:");
    println!("  patronus alias add network MyServers --ip 192.168.1.10 --ip 192.168.1.11");
    println!();

    println!("List aliases:");
    println!("  patronus alias list");
    println!();

    println!("Show alias details:");
    println!("  patronus alias show WebServers");
    println!();

    println!("Update alias:");
    println!("  patronus alias update WebServers --add-ip 192.168.1.13");
    println!();

    println!("Delete alias:");
    println!("  patronus alias delete OldAlias");
    println!();

    println!("Apply aliases to firewall:");
    println!("  patronus firewall apply");

    Ok(())
}
