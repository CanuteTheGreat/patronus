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
            || std::path::Path::new("/etc/init.d/functions.sh").exists() {
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
            InitSystem::Systemd => {
                self.systemd_command("start", service_name)
            }
            InitSystem::OpenRC => {
                self.openrc_command("start", service_name)
            }
            InitSystem::SysVInit => {
                self.sysv_command("start", service_name)
            }
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    /// Stop a service
    pub fn stop(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => {
                self.systemd_command("stop", service_name)
            }
            InitSystem::OpenRC => {
                self.openrc_command("stop", service_name)
            }
            InitSystem::SysVInit => {
                self.sysv_command("stop", service_name)
            }
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    /// Restart a service
    pub fn restart(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => {
                self.systemd_command("restart", service_name)
            }
            InitSystem::OpenRC => {
                self.openrc_command("restart", service_name)
            }
            InitSystem::SysVInit => {
                self.sysv_command("restart", service_name)
            }
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    /// Reload a service configuration
    pub fn reload(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => {
                self.systemd_command("reload", service_name)
            }
            InitSystem::OpenRC => {
                self.openrc_command("reload", service_name)
            }
            InitSystem::SysVInit => {
                self.sysv_command("reload", service_name)
            }
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    /// Enable a service to start on boot
    pub fn enable(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => {
                self.systemd_command("enable", service_name)
            }
            InitSystem::OpenRC => {
                // OpenRC uses rc-update
                let output = Command::new("rc-update")
                    .args(&["add", service_name, "default"])
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
                        .args(&[service_name, "defaults"])
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
                        .args(&[service_name, "on"])
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
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    /// Disable a service from starting on boot
    pub fn disable(&self, service_name: &str) -> Result<()> {
        match self.init_system {
            InitSystem::Systemd => {
                self.systemd_command("disable", service_name)
            }
            InitSystem::OpenRC => {
                let output = Command::new("rc-update")
                    .args(&["del", service_name])
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
                        .args(&[service_name, "remove"])
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
                        .args(&[service_name, "off"])
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
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    /// Get service status
    pub fn status(&self, service_name: &str) -> Result<ServiceState> {
        match self.init_system {
            InitSystem::Systemd => {
                let output = Command::new("systemctl")
                    .args(&["is-active", service_name])
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
                let output = Command::new("rc-service")
                    .args(&[service_name, "status"])
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to get service status: {}", e)))?;

                if output.status.success() {
                    let status = String::from_utf8_lossy(&output.stdout);
                    if status.contains("started") {
                        Ok(ServiceState::Running)
                    } else if status.contains("stopped") {
                        Ok(ServiceState::Stopped)
                    } else if status.contains("crashed") {
                        Ok(ServiceState::Failed)
                    } else {
                        Ok(ServiceState::Unknown)
                    }
                } else {
                    Ok(ServiceState::Stopped)
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
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
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
                    .args(&["is-enabled", service_name])
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to check if service is enabled: {}", e)))?;

                Ok(output.status.success())
            }
            InitSystem::OpenRC => {
                let output = Command::new("rc-update")
                    .arg("show")
                    .output()
                    .map_err(|e| Error::Service(format!("Failed to check if service is enabled: {}", e)))?;

                let list = String::from_utf8_lossy(&output.stdout);
                Ok(list.contains(service_name))
            }
            InitSystem::SysVInit => {
                // This is more complex and depends on the distribution
                Ok(false)
            }
            InitSystem::Unknown => {
                Err(Error::Service("Unknown init system".to_string()))
            }
        }
    }

    // Private helper methods

    fn systemd_command(&self, action: &str, service_name: &str) -> Result<()> {
        let output = Command::new("systemctl")
            .args(&[action, service_name])
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
            .args(&[service_name, action])
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
}
