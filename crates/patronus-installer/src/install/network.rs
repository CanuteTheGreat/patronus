//! Network configuration module

use crate::config::{InterfaceConfig, NetworkConfig, NetworkMethod};
use crate::error::Result;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

/// Configure network for the installed system
pub async fn configure_network(target: &Path, config: &NetworkConfig) -> Result<()> {
    info!("Configuring network settings");

    // Detect init system
    let has_systemd = target.join("usr/lib/systemd").exists();
    let has_networkmanager = target.join("usr/bin/NetworkManager").exists()
        || target.join("usr/sbin/NetworkManager").exists();

    if has_networkmanager {
        configure_networkmanager(target, config).await?;
    } else if has_systemd {
        configure_systemd_networkd(target, config).await?;
    } else {
        configure_openrc_network(target, config).await?;
    }

    // Configure DNS
    configure_dns(target, config).await?;

    Ok(())
}

/// Configure NetworkManager
async fn configure_networkmanager(target: &Path, config: &NetworkConfig) -> Result<()> {
    info!("Configuring NetworkManager");

    let nm_dir = target.join("etc/NetworkManager/system-connections");
    fs::create_dir_all(&nm_dir).await?;

    for iface in &config.interfaces {
        let filename = format!("{}.nmconnection", iface.name);
        let filepath = nm_dir.join(&filename);

        let content = generate_nm_connection(iface)?;
        fs::write(&filepath, content).await?;

        // Set permissions (mode 600)
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&filepath, std::fs::Permissions::from_mode(0o600)).await?;
    }

    // Enable NetworkManager service
    enable_systemd_service(target, "NetworkManager").await?;

    Ok(())
}

/// Generate NetworkManager connection file
fn generate_nm_connection(iface: &InterfaceConfig) -> Result<String> {
    let uuid = uuid::Uuid::new_v4();

    let mut content = format!(
        r#"[connection]
id={}
uuid={}
type=ethernet
interface-name={}
autoconnect=true

[ethernet]

"#,
        iface.name, uuid, iface.name
    );

    match &iface.method {
        NetworkMethod::Dhcp => {
            content.push_str("[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n");
        }
        NetworkMethod::Static {
            address,
            prefix_len,
            gateway,
        } => {
            content.push_str(&format!(
                r#"[ipv4]
method=manual
addresses={}/{}
"#,
                address, prefix_len
            ));

            if let Some(gw) = gateway {
                content.push_str(&format!("gateway={}\n", gw));
            }

            content.push_str("\n[ipv6]\nmethod=ignore\n");
        }
        NetworkMethod::Disabled => {
            content.push_str("[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=ignore\n");
        }
    }

    Ok(content)
}

/// Configure systemd-networkd
async fn configure_systemd_networkd(target: &Path, config: &NetworkConfig) -> Result<()> {
    info!("Configuring systemd-networkd");

    let networkd_dir = target.join("etc/systemd/network");
    fs::create_dir_all(&networkd_dir).await?;

    for (i, iface) in config.interfaces.iter().enumerate() {
        let filename = format!("{:02}-{}.network", 10 + i, iface.name);
        let filepath = networkd_dir.join(&filename);

        let content = generate_networkd_config(iface)?;
        fs::write(&filepath, content).await?;
    }

    // Enable systemd-networkd
    enable_systemd_service(target, "systemd-networkd").await?;
    enable_systemd_service(target, "systemd-resolved").await?;

    Ok(())
}

/// Generate systemd-networkd configuration
fn generate_networkd_config(iface: &InterfaceConfig) -> Result<String> {
    let mut content = format!(
        r#"[Match]
Name={}

[Network]
"#,
        iface.name
    );

    match &iface.method {
        NetworkMethod::Dhcp => {
            content.push_str("DHCP=yes\n");
        }
        NetworkMethod::Static {
            address,
            prefix_len,
            gateway,
        } => {
            content.push_str(&format!("Address={}/{}\n", address, prefix_len));
            if let Some(gw) = gateway {
                content.push_str(&format!("Gateway={}\n", gw));
            }
        }
        NetworkMethod::Disabled => {
            // Don't configure
        }
    }

    Ok(content)
}

/// Configure OpenRC network (Gentoo style)
async fn configure_openrc_network(target: &Path, config: &NetworkConfig) -> Result<()> {
    info!("Configuring OpenRC network");

    let conf_d = target.join("etc/conf.d");
    fs::create_dir_all(&conf_d).await?;

    let mut net_content = String::from("# Network configuration\n\n");

    for iface in &config.interfaces {
        match &iface.method {
            NetworkMethod::Dhcp => {
                net_content.push_str(&format!("config_{}=\"dhcp\"\n", iface.name));
            }
            NetworkMethod::Static {
                address,
                prefix_len,
                gateway,
            } => {
                net_content.push_str(&format!(
                    "config_{}=\"{}/{}\"\n",
                    iface.name, address, prefix_len
                ));
                if let Some(gw) = gateway {
                    net_content.push_str(&format!("routes_{}=\"default via {}\"\n", iface.name, gw));
                }
            }
            NetworkMethod::Disabled => {
                net_content.push_str(&format!("config_{}=\"null\"\n", iface.name));
            }
        }
        net_content.push('\n');
    }

    let net_path = conf_d.join("net");
    fs::write(&net_path, net_content).await?;

    // Create init symlinks for each interface
    let init_d = target.join("etc/init.d");
    for iface in &config.interfaces {
        if matches!(iface.method, NetworkMethod::Disabled) {
            continue;
        }

        let link_name = format!("net.{}", iface.name);
        let link_path = init_d.join(&link_name);
        let target_path = init_d.join("net.lo");

        if target_path.exists() && !link_path.exists() {
            tokio::fs::symlink("net.lo", &link_path).await.ok();
        }
    }

    Ok(())
}

/// Configure DNS resolvers
async fn configure_dns(target: &Path, config: &NetworkConfig) -> Result<()> {
    if config.dns_servers.is_empty() {
        return Ok(());
    }

    info!("Configuring DNS resolvers");

    let mut resolv_conf = String::new();

    // Add search domains
    if !config.search_domains.is_empty() {
        resolv_conf.push_str(&format!("search {}\n", config.search_domains.join(" ")));
    }

    // Add nameservers
    for dns in &config.dns_servers {
        resolv_conf.push_str(&format!("nameserver {}\n", dns));
    }

    let resolv_path = target.join("etc/resolv.conf");
    fs::write(&resolv_path, resolv_conf).await?;

    Ok(())
}

/// Enable a systemd service
async fn enable_systemd_service(target: &Path, service: &str) -> Result<()> {
    let service_unit = format!("{}.service", service);
    let service_path = target.join(format!("usr/lib/systemd/system/{}", service_unit));

    if !service_path.exists() {
        debug!("Service {} not found, skipping", service);
        return Ok(());
    }

    // Create symlink in multi-user.target.wants
    let wants_dir = target.join("etc/systemd/system/multi-user.target.wants");
    fs::create_dir_all(&wants_dir).await?;

    let link_path = wants_dir.join(&service_unit);
    let link_target = format!("/usr/lib/systemd/system/{}", service_unit);

    if !link_path.exists() {
        tokio::fs::symlink(&link_target, &link_path).await.ok();
    }

    debug!("Enabled service: {}", service);
    Ok(())
}

/// Detect available network interfaces
pub async fn detect_interfaces() -> Result<Vec<String>> {
    let mut interfaces = Vec::new();

    let sys_net = Path::new("/sys/class/net");
    if let Ok(mut entries) = fs::read_dir(sys_net).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip loopback and virtual interfaces
            if name == "lo" || name.starts_with("veth") || name.starts_with("docker") {
                continue;
            }

            interfaces.push(name);
        }
    }

    interfaces.sort();
    Ok(interfaces)
}

/// Check if interface is physical (not virtual)
pub async fn is_physical_interface(name: &str) -> bool {
    let device_path = format!("/sys/class/net/{}/device", name);
    tokio::fs::metadata(&device_path).await.is_ok()
}

/// Get interface MAC address
pub async fn get_mac_address(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/address", name);
    tokio::fs::read_to_string(&path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
}

/// Get interface link state
pub async fn get_link_state(name: &str) -> Option<bool> {
    let path = format!("/sys/class/net/{}/carrier", name);
    tokio::fs::read_to_string(&path)
        .await
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|v| v == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InterfaceRole;

    #[test]
    fn test_generate_nm_connection_dhcp() {
        let iface = InterfaceConfig {
            name: "eth0".to_string(),
            method: NetworkMethod::Dhcp,
            role: InterfaceRole::Lan,
        };

        let content = generate_nm_connection(&iface).unwrap();
        assert!(content.contains("interface-name=eth0"));
        assert!(content.contains("method=auto"));
    }

    #[test]
    fn test_generate_networkd_config_static() {
        let iface = InterfaceConfig {
            name: "eth0".to_string(),
            method: NetworkMethod::Static {
                address: "192.168.1.1".parse().unwrap(),
                prefix_len: 24,
                gateway: Some("192.168.1.254".parse().unwrap()),
            },
            role: InterfaceRole::Lan,
        };

        let content = generate_networkd_config(&iface).unwrap();
        assert!(content.contains("Name=eth0"));
        assert!(content.contains("Address=192.168.1.1/24"));
        assert!(content.contains("Gateway=192.168.1.254"));
    }
}
