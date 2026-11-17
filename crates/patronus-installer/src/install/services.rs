//! Service configuration module

use crate::config::{PatronusConfig, ServiceConfig};
use crate::error::Result;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

/// Configure services for the installed system
pub async fn configure_services(
    target: &Path,
    config: &ServiceConfig,
    patronus_config: &PatronusConfig,
) -> Result<()> {
    info!("Configuring services");

    // Detect init system
    let has_systemd = target.join("usr/lib/systemd").exists();

    if has_systemd {
        configure_systemd_services(target, config).await?;
    } else {
        configure_openrc_services(target, config).await?;
    }
    configure_guest_agent(target, Path::new("/sys")).await?;

    // Configure Patronus
    configure_patronus(target, config, patronus_config).await?;

    Ok(())
}

/// virtio port the QEMU/KVM guest agent talks over.
pub const QGA_PORT: &str = "org.qemu.guest_agent.0";

/// Is a QEMU guest-agent virtio port present under `sysfs` (`/sys`)? That
/// is the one sign that a hypervisor is listening for the agent (bare metal
/// and other hypervisors have no such port, so nothing is enabled there).
pub fn qemu_guest_agent_port_present(sysfs: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(sysfs.join("class/virtio-ports")) else {
        return false;
    };
    rd.flatten().any(|e| {
        std::fs::read_to_string(e.path().join("name"))
            .map(|n| n.trim() == QGA_PORT)
            .unwrap_or(false)
    })
}

/// Enable app-emulation/qemu-guest-agent on the installed system when the
/// installer itself runs in a QEMU/KVM guest with the agent channel, on
/// systemd and OpenRC. The installed image also enables it at boot under the
/// same condition (`patronus-qga-enable`), so a disk moved to another VM
/// still gets it. Returns whether it was enabled.
pub async fn configure_guest_agent(target: &Path, sysfs: &Path) -> Result<bool> {
    if !qemu_guest_agent_port_present(sysfs) {
        return Ok(false);
    }
    if target.join("usr/lib/systemd").exists() {
        enable_systemd_unit(target, "qemu-guest-agent.service").await?;
    } else {
        add_to_openrc_runlevel(target, "qemu-guest-agent", "default").await?;
    }
    Ok(true)
}

/// Configure systemd services
async fn configure_systemd_services(target: &Path, config: &ServiceConfig) -> Result<()> {
    info!("Configuring systemd services");

    let wants_dir = target.join("etc/systemd/system/multi-user.target.wants");
    fs::create_dir_all(&wants_dir).await?;

    // Patronus firewall
    if config.firewall {
        enable_systemd_unit(target, "patronus-firewall.service").await?;
    }

    // Patronus web UI
    if config.web_ui {
        enable_systemd_unit(target, "patronus-web.service").await?;
    }

    // SSH
    if config.ssh {
        enable_systemd_unit(target, "sshd.service").await?;
    }

    // DHCP server
    if config.dhcp_server {
        enable_systemd_unit(target, "dhcpd.service").await?;
    }

    // DNS server
    if config.dns_server {
        enable_systemd_unit(target, "unbound.service").await?;
    }

    Ok(())
}

/// Enable a systemd unit
async fn enable_systemd_unit(target: &Path, unit: &str) -> Result<()> {
    // Check if unit exists
    let unit_paths = [
        target.join(format!("usr/lib/systemd/system/{}", unit)),
        target.join(format!("lib/systemd/system/{}", unit)),
        target.join(format!("etc/systemd/system/{}", unit)),
    ];

    let unit_exists = unit_paths.iter().any(|p| {
        // Check synchronously since we're in async context
        std::path::Path::new(p).exists()
    });

    if !unit_exists {
        debug!("Unit {} not found, skipping", unit);
        return Ok(());
    }

    // Create symlink in multi-user.target.wants
    let wants_dir = target.join("etc/systemd/system/multi-user.target.wants");
    let link_path = wants_dir.join(unit);

    if !link_path.exists() {
        // Find the actual unit path
        for unit_path in &unit_paths {
            if std::path::Path::new(unit_path).exists() {
                let relative = format!("/usr/lib/systemd/system/{}", unit);
                tokio::fs::symlink(&relative, &link_path).await.ok();
                break;
            }
        }
    }

    info!("Enabled systemd service: {}", unit);
    Ok(())
}

/// Configure OpenRC services
async fn configure_openrc_services(target: &Path, config: &ServiceConfig) -> Result<()> {
    info!("Configuring OpenRC services");

    // Patronus firewall
    if config.firewall {
        add_to_openrc_runlevel(target, "patronus-firewall", "default").await?;
    }

    // Patronus web UI
    if config.web_ui {
        add_to_openrc_runlevel(target, "patronus-web", "default").await?;
    }

    // SSH
    if config.ssh {
        add_to_openrc_runlevel(target, "sshd", "default").await?;
    }

    // DHCP server
    if config.dhcp_server {
        add_to_openrc_runlevel(target, "dhcpd", "default").await?;
    }

    // DNS server
    if config.dns_server {
        add_to_openrc_runlevel(target, "unbound", "default").await?;
    }

    Ok(())
}

/// Add service to OpenRC runlevel
async fn add_to_openrc_runlevel(target: &Path, service: &str, runlevel: &str) -> Result<()> {
    let init_script = target.join(format!("etc/init.d/{}", service));
    if !init_script.exists() {
        debug!("Init script {} not found, skipping", service);
        return Ok(());
    }

    let runlevel_dir = target.join(format!("etc/runlevels/{}", runlevel));
    fs::create_dir_all(&runlevel_dir).await?;

    let link_path = runlevel_dir.join(service);
    let link_target = format!("/etc/init.d/{}", service);

    if !link_path.exists() {
        tokio::fs::symlink(&link_target, &link_path).await.ok();
    }

    info!("Added {} to OpenRC runlevel {}", service, runlevel);
    Ok(())
}

/// Configure Patronus-specific settings
async fn configure_patronus(
    target: &Path,
    config: &ServiceConfig,
    patronus_config: &PatronusConfig,
) -> Result<()> {
    info!("Configuring Patronus");

    // Create Patronus config directory
    let patronus_dir = target.join("etc/patronus");
    fs::create_dir_all(&patronus_dir).await?;

    // Generate main configuration
    let config_content = generate_patronus_config(config, patronus_config)?;
    let config_path = patronus_dir.join("config.yaml");
    fs::write(&config_path, config_content).await?;

    // Create rules directory
    let rules_dir = patronus_dir.join("rules.d");
    fs::create_dir_all(&rules_dir).await?;

    // Create initial firewall rules
    if config.firewall {
        let rules_content = generate_default_firewall_rules(patronus_config)?;
        let rules_path = rules_dir.join("00-default.yaml");
        fs::write(&rules_path, rules_content).await?;
    }

    // Set permissions
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&patronus_dir, std::fs::Permissions::from_mode(0o750)).await?;

    Ok(())
}

/// Generate Patronus configuration file
fn generate_patronus_config(
    config: &ServiceConfig,
    patronus_config: &PatronusConfig,
) -> Result<String> {
    let content = format!(
        r#"# Patronus Configuration
# Generated by patronus-install

# General settings
general:
  log_level: info
  data_dir: /var/lib/patronus

# Web interface
web:
  enabled: {}
  bind: "0.0.0.0"
  port: {}
  tls: false

# Firewall settings
firewall:
  enabled: {}
  default_policy: {}
  log_dropped: true

# SD-WAN settings
sdwan:
  enabled: {}

# Intrusion detection
ids:
  enabled: {}

# VPN server
vpn:
  enabled: {}
  type: wireguard
  port: 51820
"#,
        config.web_ui,
        config.web_port,
        config.firewall,
        patronus_config.default_policy,
        patronus_config.sdwan_enabled,
        patronus_config.ids_enabled,
        patronus_config.vpn_server,
    );

    Ok(content)
}

/// Generate default firewall rules
fn generate_default_firewall_rules(patronus_config: &PatronusConfig) -> Result<String> {
    let policy = &patronus_config.default_policy;

    let content = format!(
        r#"# Default firewall rules
# Generated by patronus-install

rules:
  # Allow established/related connections
  - name: allow-established
    action: accept
    state: [established, related]
    priority: 1

  # Allow loopback
  - name: allow-loopback
    action: accept
    interface_in: lo
    priority: 2

  # Allow ICMP (ping)
  - name: allow-icmp
    action: accept
    protocol: icmp
    priority: 10

  # Allow SSH (rate limited)
  - name: allow-ssh
    action: accept
    protocol: tcp
    dst_port: 22
    limit: 10/minute
    priority: 20

  # Allow web UI
  - name: allow-web-ui
    action: accept
    protocol: tcp
    dst_port: 8080
    priority: 21

  # Default policy
  - name: default-policy
    action: {}
    priority: 9999
"#,
        policy
    );

    Ok(content)
}

/// Configure SSH settings
pub async fn configure_ssh(target: &Path, config: &ServiceConfig) -> Result<()> {
    if !config.ssh {
        return Ok(());
    }

    info!("Configuring SSH");

    let sshd_config_path = target.join("etc/ssh/sshd_config");
    if !sshd_config_path.exists() {
        return Ok(());
    }

    // Read existing config
    let mut content = fs::read_to_string(&sshd_config_path)
        .await
        .unwrap_or_default();

    // Update port if non-default
    if config.ssh_port != 22 {
        content = update_ssh_config(&content, "Port", &config.ssh_port.to_string());
    }

    // Security hardening
    content = update_ssh_config(&content, "PermitRootLogin", "prohibit-password");
    content = update_ssh_config(&content, "PasswordAuthentication", "no");
    content = update_ssh_config(&content, "X11Forwarding", "no");
    content = update_ssh_config(&content, "MaxAuthTries", "3");

    fs::write(&sshd_config_path, content).await?;

    Ok(())
}

/// Update SSH config option
fn update_ssh_config(content: &str, option: &str, value: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let option_lower = option.to_lowercase();
    let mut found = false;

    for line in &mut lines {
        let trimmed = line.trim().to_lowercase();
        if trimmed.starts_with(&option_lower) || trimmed.starts_with(&format!("#{}", option_lower))
        {
            *line = format!("{} {}", option, value);
            found = true;
            break;
        }
    }

    if !found {
        lines.push(format!("{} {}", option, value));
    }

    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_ssh_config() {
        let content = "Port 22\nPermitRootLogin yes\n";

        let updated = update_ssh_config(content, "Port", "2222");
        assert!(updated.contains("Port 2222"));

        let updated = update_ssh_config(content, "PermitRootLogin", "no");
        assert!(updated.contains("PermitRootLogin no"));

        let updated = update_ssh_config(content, "NewOption", "value");
        assert!(updated.contains("NewOption value"));
    }

    #[test]
    fn test_generate_patronus_config() {
        let config = ServiceConfig::default();
        let patronus_config = PatronusConfig::default();

        let content = generate_patronus_config(&config, &patronus_config).unwrap();
        assert!(content.contains("enabled: true"));
        assert!(content.contains("port: 8080"));
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("patronus-qga-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sysfs_with_port(root: &Path, name: &str) {
        let p = root.join("class/virtio-ports/vport1p1");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("name"), format!("{name}\n")).unwrap();
    }

    #[test]
    fn guest_agent_port_detection() {
        let none = tmp("none");
        assert!(!qemu_guest_agent_port_present(&none));
        let other = tmp("other");
        sysfs_with_port(&other, "com.example.channel");
        assert!(!qemu_guest_agent_port_present(&other));
        let qga = tmp("qga");
        sysfs_with_port(&qga, QGA_PORT);
        assert!(qemu_guest_agent_port_present(&qga));
    }

    #[tokio::test]
    async fn guest_agent_enabled_only_under_qemu_on_both_inits() {
        let sys = tmp("sys-yes");
        sysfs_with_port(&sys, QGA_PORT);
        let bare = tmp("sys-no");

        // OpenRC target
        let o = tmp("openrc");
        std::fs::create_dir_all(o.join("etc/init.d")).unwrap();
        std::fs::write(o.join("etc/init.d/qemu-guest-agent"), "").unwrap();
        assert!(!configure_guest_agent(&o, &bare).await.unwrap());
        assert!(!o.join("etc/runlevels/default/qemu-guest-agent").exists());
        assert!(configure_guest_agent(&o, &sys).await.unwrap());
        assert!(o
            .join("etc/runlevels/default/qemu-guest-agent")
            .symlink_metadata()
            .is_ok());

        // systemd target
        let d = tmp("systemd");
        std::fs::create_dir_all(d.join("usr/lib/systemd/system")).unwrap();
        std::fs::write(
            d.join("usr/lib/systemd/system/qemu-guest-agent.service"),
            "",
        )
        .unwrap();
        std::fs::create_dir_all(d.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        assert!(!configure_guest_agent(&d, &bare).await.unwrap());
        assert!(configure_guest_agent(&d, &sys).await.unwrap());
        assert!(d
            .join("etc/systemd/system/multi-user.target.wants/qemu-guest-agent.service")
            .symlink_metadata()
            .is_ok());
    }
}
