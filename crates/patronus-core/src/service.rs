//! Service management abstraction
//!
//! Provides a unified interface for managing system services across
//! different init systems (systemd, OpenRC).

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Init system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitSystem {
    Systemd,
    OpenRC,
    SysVInit,
    Unknown,
}

/// Service state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Running,
    Stopped,
    Failed,
    Unknown,
}

/// Service manager
pub struct ServiceManager {
    init_system: InitSystem,
}

impl ServiceManager {
    /// Create a new service manager (auto-detects init system)
    pub fn new() -> Self {
        Self {
            init_system: Self::detect_init_system(),
        }
    }

    /// Create a service manager for a specific init system
    pub fn with_init_system(init_system: InitSystem) -> Self {
        Self { init_system }
    }

    /// Detect the running init system
    pub fn detect_init_system() -> InitSystem {
        // Check for systemd
        if std::path::Path::new("/run/systemd/system").exists() {
            return InitSystem::Systemd;
        }

        // Check for OpenRC
        if std::path::Path::new("/run/openrc").exists()
            || std::path::Path::new("/etc/init.d/functions.sh").exists()
        {
            return InitSystem::OpenRC;
        }

        // Check for SysV init
        if std::path::Path::new("/etc/init.d").exists() {
            return InitSystem::SysVInit;
        }

        InitSystem::Unknown
    }

    /// Get the current init system
    pub fn init_system(&self) -> InitSystem {
        self.init_system
    }

    /// Start a service
    pub fn start(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => self.systemd_command("start", service_name),
            InitSystem::OpenRC => self.openrc_command("start", service_name),
            InitSystem::SysVInit => self.sysv_command("start", service_name),
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Stop a service
    pub fn stop(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => self.systemd_command("stop", service_name),
            InitSystem::OpenRC => self.openrc_command("stop", service_name),
            InitSystem::SysVInit => self.sysv_command("stop", service_name),
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Restart a service
    pub fn restart(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => self.systemd_command("restart", service_name),
            InitSystem::OpenRC => self.openrc_command("restart", service_name),
            InitSystem::SysVInit => self.sysv_command("restart", service_name),
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Reload a service configuration
    pub fn reload(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => self.systemd_command("reload", service_name),
            InitSystem::OpenRC => self.openrc_command("reload", service_name),
            InitSystem::SysVInit => self.sysv_command("reload", service_name),
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Enable a service to start on boot
    pub fn enable(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => self.systemd_command("enable", service_name),
            InitSystem::OpenRC => {
                // OpenRC uses rc-update
                let output = Command::new("rc-update")
                    .args(["add", service_name, "default"])
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to enable service: {}", e)))?;

                if !output.status.success() {
                    return Err(Error::Service(format!(
                        "Failed to enable service: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }

                Ok(())
            }
            InitSystem::SysVInit => {
                // SysV uses update-rc.d or chkconfig
                if std::path::Path::new("/usr/sbin/update-rc.d").exists() {
                    let output = Command::new("update-rc.d")
                        .args([service_name, "defaults"])
                        .output()
                        .map_err(|e| Error::Service(format!("Failed to enable service: {}", e)))?;

                    if !output.status.success() {
                        return Err(Error::Service(format!(
                            "Failed to enable service: {}",
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                } else if std::path::Path::new("/sbin/chkconfig").exists() {
                    let output = Command::new("chkconfig")
                        .args([service_name, "on"])
                        .output()
                        .map_err(|e| Error::Service(format!("Failed to enable service: {}", e)))?;

                    if !output.status.success() {
                        return Err(Error::Service(format!(
                            "Failed to enable service: {}",
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                }

                Ok(())
            }
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Disable a service from starting on boot
    pub fn disable(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => self.systemd_command("disable", service_name),
            InitSystem::OpenRC => {
                let output = Command::new("rc-update")
                    .args(["del", service_name])
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to disable service: {}", e)))?;

                if !output.status.success() {
                    return Err(Error::Service(format!(
                        "Failed to disable service: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }

                Ok(())
            }
            InitSystem::SysVInit => {
                if std::path::Path::new("/usr/sbin/update-rc.d").exists() {
                    let output = Command::new("update-rc.d")
                        .args([service_name, "remove"])
                        .output()
                        .map_err(|e| Error::Service(format!("Failed to disable service: {}", e)))?;

                    if !output.status.success() {
                        return Err(Error::Service(format!(
                            "Failed to disable service: {}",
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                } else if std::path::Path::new("/sbin/chkconfig").exists() {
                    let output = Command::new("chkconfig")
                        .args([service_name, "off"])
                        .output()
                        .map_err(|e| Error::Service(format!("Failed to disable service: {}", e)))?;

                    if !output.status.success() {
                        return Err(Error::Service(format!(
                            "Failed to disable service: {}",
                            String::from_utf8_lossy(&output.stderr)
                        )));
                    }
                }

                Ok(())
            }
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Get service status
    pub fn status(&self, service_name: &str) -> Result<ServiceState> {
        match self.init_system {
            InitSystem::Systemd => {
                let output = Command::new("systemctl")
                    .args(["is-active", service_name])
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to get service status: {}", e)))?;

                let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

                match status.as_str() {
                    "active" => Ok(ServiceState::Running),
                    "inactive" => Ok(ServiceState::Stopped),
                    "failed" => Ok(ServiceState::Failed),
                    _ => Ok(ServiceState::Unknown),
                }
            }
            InitSystem::OpenRC => {
                // OpenRC's own records first: readable by any user and
                // what `rc-service status` reports for ordinary scripts.
                // Scripts with their own status() never say started /
                // stopped and may need root: Gentoo's strongSwan `ipsec`
                // runs `ipsec statusall`, so an unprivileged patronus-web
                // saw a running ipsec as Unknown or Stopped.
                let recorded = openrc_recorded_state(
                    OPENRC_STATE_DIRS.iter().map(std::path::Path::new),
                    service_name,
                );
                if matches!(recorded, ServiceState::Stopped | ServiceState::Failed) {
                    return Ok(recorded);
                }
                let output = Command::new("rc-service")
                    .args([service_name, "status"])
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to get service status: {}", e)))?;
                let status = String::from_utf8_lossy(&output.stdout);
                if status.contains("crashed") {
                    // marked started, daemon gone
                    Ok(ServiceState::Failed)
                } else if recorded == ServiceState::Running {
                    Ok(ServiceState::Running)
                } else if !output.status.success() {
                    Ok(ServiceState::Stopped)
                } else if status.contains("started") {
                    Ok(ServiceState::Running)
                } else if status.contains("stopped") {
                    Ok(ServiceState::Stopped)
                } else {
                    Ok(ServiceState::Unknown)
                }
            }
            InitSystem::SysVInit => {
                let output = Command::new("/etc/init.d/".to_string() + service_name)
                    .arg("status")
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to get service status: {}", e)))?;

                if output.status.success() {
                    Ok(ServiceState::Running)
                } else {
                    Ok(ServiceState::Stopped)
                }
            }
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    /// Check if a service is running
    pub fn is_running(&self, service_name: &str) -> Result<bool> {
        Ok(self.status(service_name)? == ServiceState::Running)
    }

    /// Check if a service is enabled
    pub fn is_enabled(&self, service_name: &str) -> Result<bool> {
        match self.init_system {
            InitSystem::Systemd => {
                let output = Command::new("systemctl")
                    .args(["is-enabled", service_name])
                    .output()
                    .map_err(|e| {
                        Error::Service(format!("Failed to check if service is enabled: {}", e))
                    })?;

                Ok(output.status.success())
            }
            InitSystem::OpenRC => {
                let output = Command::new("rc-update")
                    .arg("show")
                    .output()
                    .map_err(|e| {
                        Error::Service(format!("Failed to check if service is enabled: {}", e))
                    })?;

                let list = String::from_utf8_lossy(&output.stdout);
                Ok(list.contains(service_name))
            }
            InitSystem::SysVInit => {
                // This is more complex and depends on the distribution
                Ok(false)
            }
            InitSystem::Unknown => Err(Error::Service("Unknown init system".to_string())),
        }
    }

    // Private helper methods

    fn systemd_command(&self, action: &str, service_name: &str) -> Result<()> {
        let output = Command::new("systemctl")
            .args([action, service_name])
            .output()
            .map_err(|e| Error::Service(format!("Failed to {} service: {}", action, e)))?;

        if !output.status.success() {
            return Err(Error::Service(format!(
                "Failed to {} service: {}",
                action,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn openrc_command(&self, action: &str, service_name: &str) -> Result<()> {
        let output = Command::new("rc-service")
            .args([service_name, action])
            .output()
            .map_err(|e| Error::Service(format!("Failed to {} service: {}", action, e)))?;

        if !output.status.success() {
            return Err(Error::Service(format!(
                "Failed to {} service: {}",
                action,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn sysv_command(&self, action: &str, service_name: &str) -> Result<()> {
        let script_path = format!("/etc/init.d/{}", service_name);

        let output = Command::new(&script_path)
            .arg(action)
            .output()
            .map_err(|e| Error::Service(format!("Failed to {} service: {}", action, e)))?;

        if !output.status.success() {
            return Err(Error::Service(format!(
                "Failed to {} service: {}",
                action,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }
}

/// Where OpenRC records service states (`$RC_SVCDIR`: /run/openrc on Linux,
/// /lib/rc/init.d on old installs).
const OPENRC_STATE_DIRS: &[&str] = &["/run/openrc", "/lib/rc/init.d"];

/// The state OpenRC itself recorded for `name`: a `started/<name>` (or
/// `starting`/`failed`/...) entry in the first state directory that exists.
/// No entry = stopped (OpenRC removes it on stop).
fn openrc_recorded_state<'a>(
    dirs: impl IntoIterator<Item = &'a std::path::Path>,
    name: &str,
) -> ServiceState {
    let Some(dir) = dirs.into_iter().find(|d| d.join("started").is_dir()) else {
        return ServiceState::Unknown;
    };
    let has = |state: &str| dir.join(state).join(name).symlink_metadata().is_ok();
    if has("started") || has("starting") {
        ServiceState::Running
    } else if has("failed") {
        ServiceState::Failed
    } else {
        ServiceState::Stopped
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_init_system() {
        let init = ServiceManager::detect_init_system();
        // Should detect something on most systems
        assert_ne!(init, InitSystem::Unknown);
    }

    #[test]
    fn test_service_manager_creation() {
        let manager = ServiceManager::new();
        assert_ne!(manager.init_system(), InitSystem::Unknown);
    }

    /// Gentoo's strongSwan `ipsec` script answers `status` with `ipsec
    /// statusall` (no started/stopped word): the state comes from OpenRC's
    /// own records, so the System page shows Running/Stopped, not Unknown.
    #[test]
    fn openrc_state_comes_from_its_state_directory() {
        let root = std::env::temp_dir().join(format!("patronus-openrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rc = root.join("run-openrc");
        for d in ["started", "failed", "starting"] {
            std::fs::create_dir_all(rc.join(d)).unwrap();
        }
        std::os::unix::fs::symlink("/etc/init.d/ipsec", rc.join("started/ipsec")).unwrap();
        std::os::unix::fs::symlink("/etc/init.d/unbound", rc.join("failed/unbound")).unwrap();
        let missing = root.join("nope");
        let dirs = [missing.as_path(), rc.as_path()];
        assert_eq!(openrc_recorded_state(dirs, "ipsec"), ServiceState::Running);
        assert_eq!(openrc_recorded_state(dirs, "unbound"), ServiceState::Failed);
        assert_eq!(
            openrc_recorded_state(dirs, "kea-dhcp4"),
            ServiceState::Stopped
        );
        // no OpenRC state directory at all: cannot tell
        assert_eq!(
            openrc_recorded_state([missing.as_path()], "ipsec"),
            ServiceState::Unknown
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
