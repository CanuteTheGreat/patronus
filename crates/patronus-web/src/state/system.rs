//! System state (users, backups, updates, services). Lane H replaces the
//! in-memory fixtures below with store-backed adapters.

use std::sync::Arc;
use tokio::sync::RwLock;

/// System management operations
pub struct SystemManager {
    users: Arc<RwLock<Vec<crate::templates::User>>>,
    backups: Arc<RwLock<Vec<crate::templates::Backup>>>,
    services: Arc<RwLock<Vec<crate::templates::Service>>>,
}

impl Default for SystemManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemManager {
    pub fn new() -> Self {
        let default_users = vec![
            crate::templates::User {
                id: 1,
                username: "admin".to_string(),
                full_name: "System Administrator".to_string(),
                role: "Administrator".to_string(),
                two_factor_enabled: true,
                last_login: Some("2024-01-15 14:30:00".to_string()),
                is_active: true,
                is_system_user: false,
                last_login_display: "2024-01-15 14:30:00".to_string(),
            },
            crate::templates::User {
                id: 2,
                username: "operator".to_string(),
                full_name: "Network Operator".to_string(),
                role: "Operator".to_string(),
                two_factor_enabled: false,
                last_login: Some("2024-01-14 09:15:00".to_string()),
                is_active: true,
                is_system_user: false,
                last_login_display: "2024-01-14 09:15:00".to_string(),
            },
        ];

        let default_backups = vec![
            crate::templates::Backup {
                id: 1,
                name: "patronus-backup-20240115.tar.gz".to_string(),
                created_at: "2024-01-15 00:00:00".to_string(),
                size: "15.2 MB".to_string(),
                backup_type: "Full".to_string(),
                is_valid: true,
            },
            crate::templates::Backup {
                id: 2,
                name: "patronus-backup-20240114.tar.gz".to_string(),
                created_at: "2024-01-14 00:00:00".to_string(),
                size: "14.8 MB".to_string(),
                backup_type: "Full".to_string(),
                is_valid: true,
            },
        ];

        let default_services = vec![
            crate::templates::Service {
                name: "patronus-web".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "128 MB".to_string(),
            },
            crate::templates::Service {
                name: "patronus-firewall".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "64 MB".to_string(),
            },
            crate::templates::Service {
                name: "wireguard".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 40m".to_string(),
                memory_display: "32 MB".to_string(),
            },
            crate::templates::Service {
                name: "dhcpd".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "16 MB".to_string(),
            },
            crate::templates::Service {
                name: "unbound".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "48 MB".to_string(),
            },
        ];

        Self {
            users: Arc::new(RwLock::new(default_users)),
            backups: Arc::new(RwLock::new(default_backups)),
            services: Arc::new(RwLock::new(default_services)),
        }
    }

    pub async fn get_info(&self) -> anyhow::Result<crate::templates::SystemInfo> {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "patronus".to_string())
            .trim()
            .to_string();

        let uptime = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
            .and_then(|s| s.parse::<f64>().ok())
            .map(|s| s as u64)
            .unwrap_or(0);

        let (memory_usage, _total_mem) = Self::get_memory_info();
        let cpu_usage = Self::get_cpu_usage();
        let disk_usage = Self::get_disk_usage();
        let load_avg = Self::get_load_average();

        Ok(crate::templates::SystemInfo {
            hostname,
            uptime,
            cpu_usage,
            memory_usage,
            disk_usage,
            load_avg,
        })
    }

    pub(super) fn get_memory_info() -> (f64, u64) {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;

            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    available = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }

            if total > 0 {
                let used = total - available;
                return ((used as f64 / total as f64) * 100.0, total * 1024);
            }
        }
        (0.0, 0)
    }

    pub(super) fn get_cpu_usage() -> f64 {
        if let Ok(content) = std::fs::read_to_string("/proc/stat") {
            if let Some(line) = content.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let user: u64 = parts[1].parse().unwrap_or(0);
                    let nice: u64 = parts[2].parse().unwrap_or(0);
                    let system: u64 = parts[3].parse().unwrap_or(0);
                    let idle: u64 = parts[4].parse().unwrap_or(0);

                    let total = user + nice + system + idle;
                    let used = user + nice + system;

                    if total > 0 {
                        return (used as f64 / total as f64) * 100.0;
                    }
                }
            }
        }
        0.0
    }

    pub(super) fn get_disk_usage() -> f64 {
        25.0 // Default fallback
    }

    fn get_load_average() -> (f64, f64, f64) {
        if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                let load1 = parts[0].parse().unwrap_or(0.0);
                let load5 = parts[1].parse().unwrap_or(0.0);
                let load15 = parts[2].parse().unwrap_or(0.0);
                return (load1, load5, load15);
            }
        }
        (0.0, 0.0, 0.0)
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<crate::templates::User>> {
        let users = self.users.read().await;
        Ok(users.clone())
    }

    pub async fn list_backups(&self) -> anyhow::Result<Vec<crate::templates::Backup>> {
        let backups = self.backups.read().await;
        Ok(backups.clone())
    }

    pub async fn create_backup(&self) -> anyhow::Result<u32> {
        let mut backups = self.backups.write().await;
        let id = backups.len() as u32 + 1;
        let now = chrono::Utc::now();

        backups.insert(
            0,
            crate::templates::Backup {
                id,
                name: format!("patronus-backup-{}.tar.gz", now.format("%Y%m%d%H%M%S")),
                created_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
                size: "0 MB".to_string(),
                backup_type: "Full".to_string(),
                is_valid: true,
            },
        );

        Ok(id)
    }

    pub async fn check_updates(&self) -> anyhow::Result<Vec<crate::templates::Update>> {
        Ok(vec![crate::templates::Update {
            package_name: "patronus-core".to_string(),
            current_version: "0.1.0".to_string(),
            new_version: "0.1.1".to_string(),
            security: false,
            size: "2.5 MB".to_string(),
        }])
    }

    pub async fn list_services(&self) -> anyhow::Result<Vec<crate::templates::Service>> {
        let services = self.services.read().await;
        Ok(services.clone())
    }

    pub async fn start_service(&self, name: &str) -> anyhow::Result<()> {
        let mut services = self.services.write().await;
        if let Some(service) = services.iter_mut().find(|s| s.name == name) {
            service.status = "Running".to_string();
            service.is_running = true;
        }
        Ok(())
    }

    pub async fn stop_service(&self, name: &str) -> anyhow::Result<()> {
        let mut services = self.services.write().await;
        if let Some(service) = services.iter_mut().find(|s| s.name == name) {
            service.status = "Stopped".to_string();
            service.is_running = false;
        }
        Ok(())
    }

    pub async fn restart_service(&self, name: &str) -> anyhow::Result<()> {
        self.stop_service(name).await?;
        self.start_service(name).await?;
        Ok(())
    }

    pub async fn get_config(&self) -> anyhow::Result<crate::templates::SystemConfig> {
        Ok(crate::templates::SystemConfig {
            hostname: std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "patronus".to_string())
                .trim()
                .to_string(),
            domain: "local".to_string(),
            timezone: "UTC".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        })
    }
}
