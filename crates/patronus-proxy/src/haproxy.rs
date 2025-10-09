//! HAProxy Load Balancer and Reverse Proxy
//!
//! Provides enterprise-grade load balancing, reverse proxy, SSL offloading,
//! and high availability for web services.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tokio::process::Command;

/// HAProxy mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    HTTP,     // HTTP/HTTPS load balancing
    TCP,      // TCP load balancing (layer 4)
    Health,   // Health check only (no forwarding)
}

/// Load balancing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BalanceAlgorithm {
    RoundRobin,      // Each server in turn
    LeastConn,       // Server with least connections
    Source,          // Based on source IP hash
    URI,             // Based on URI hash
    URLParam,        // Based on URL parameter
    Header,          // Based on HTTP header
    Random,          // Random selection
    Static,          // Based on server weight
}

/// Backend server health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub enabled: bool,
    pub method: HealthCheckMethod,
    pub interval: u32,           // Seconds between checks
    pub timeout: u32,            // Seconds before timeout
    pub rise: u32,               // Successful checks before marking up
    pub fall: u32,               // Failed checks before marking down
    pub check_port: Option<u16>, // Port for health checks (if different)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthCheckMethod {
    TCP,              // Simple TCP connect
    HTTP { uri: String, expect: Option<String> },  // HTTP GET request
    HTTPS { uri: String, expect: Option<String> }, // HTTPS GET request
    SSL,              // SSL handshake check
    MySQL,            // MySQL protocol check
    PostgreSQL,       // PostgreSQL protocol check
    Redis,            // Redis PING
    SMTP,             // SMTP banner check
}

/// Backend server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    pub id: String,
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    pub weight: u32,             // Load balancing weight (default 100)
    pub max_conn: Option<u32>,   // Max concurrent connections
    pub backup: bool,            // Backup server (only used if all primaries down)
    pub check: HealthCheck,
    pub ssl: bool,               // Use SSL to backend
    pub send_proxy: bool,        // Send PROXY protocol header
    pub enabled: bool,
}

/// Frontend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frontend {
    pub id: String,
    pub name: String,
    pub bind_address: IpAddr,
    pub bind_port: u16,
    pub mode: ProxyMode,
    pub default_backend: String,  // Default backend name

    // SSL/TLS
    pub ssl: bool,
    pub ssl_cert: Option<PathBuf>,
    pub ssl_key: Option<PathBuf>,
    pub ssl_ca: Option<PathBuf>,
    pub force_https: bool,        // Redirect HTTP to HTTPS

    // Limits
    pub max_conn: Option<u32>,
    pub rate_limit: Option<u32>,  // Connections per second

    // Timeouts
    pub client_timeout: u32,      // Seconds
    pub connect_timeout: u32,

    // ACLs and routing
    pub acls: Vec<AccessControlList>,
    pub use_backend_rules: Vec<BackendRule>,

    // Advanced
    pub xff_enabled: bool,        // Add X-Forwarded-For header
    pub compression: bool,
    pub http2_enabled: bool,

    pub enabled: bool,
}

/// Access Control List for request matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlList {
    pub name: String,
    pub condition: AclCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AclCondition {
    PathBegins(String),          // Path starts with
    PathEquals(String),           // Path exactly matches
    PathRegex(String),            // Path matches regex
    HostEquals(String),           // Host header equals
    HostRegex(String),            // Host matches regex
    MethodEquals(String),         // HTTP method (GET, POST, etc.)
    HeaderExists(String),         // HTTP header exists
    HeaderEquals(String, String), // Header equals value
    SourceIP(String),             // Source IP/CIDR
    SSL,                          // Is SSL connection
    URLParam(String, String),     // URL parameter equals value
}

/// Backend routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRule {
    pub acl_name: String,         // Which ACL to match
    pub backend_name: String,     // Which backend to use
    pub negate: bool,             // If true, use when ACL doesn't match
}

/// Backend pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: String,
    pub name: String,
    pub mode: ProxyMode,
    pub balance: BalanceAlgorithm,
    pub servers: Vec<BackendServer>,

    // Session persistence
    pub sticky_session: bool,
    pub cookie_name: Option<String>,  // Cookie for session persistence

    // Timeouts
    pub server_timeout: u32,      // Seconds
    pub connect_timeout: u32,

    // Advanced
    pub forwardfor: bool,         // Add X-Forwarded-For
    pub httpclose: bool,          // Force connection close

    pub enabled: bool,
}

/// Statistics page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsConfig {
    pub enabled: bool,
    pub bind_address: IpAddr,
    pub bind_port: u16,
    pub uri: String,              // "/haproxy-stats"
    pub username: Option<String>,
    pub password: Option<String>,
    pub refresh: u32,             // Auto-refresh interval (seconds)
}

/// HAProxy global configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HAProxyConfig {
    pub enabled: bool,

    // Global settings
    pub max_conn: u32,
    pub log_level: LogLevel,
    pub log_facility: String,     // Local syslog facility
    pub nbproc: u32,              // Number of processes (deprecated, use nbthread)
    pub nbthread: u32,            // Number of threads

    // SSL
    pub ssl_default_bind_ciphers: String,
    pub ssl_default_bind_options: String,

    // Stats
    pub stats: StatsConfig,

    // Components
    pub frontends: Vec<Frontend>,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

/// HAProxy runtime statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HAProxyStats {
    pub uptime_seconds: u64,
    pub current_connections: u32,
    pub total_connections: u64,
    pub requests_per_second: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub backend_stats: Vec<BackendStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStats {
    pub backend_name: String,
    pub status: BackendStatus,
    pub active_servers: u32,
    pub backup_servers: u32,
    pub current_sessions: u32,
    pub total_sessions: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub server_stats: Vec<ServerStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub server_name: String,
    pub status: ServerStatus,
    pub weight: u32,
    pub current_sessions: u32,
    pub total_sessions: u64,
    pub last_check: Option<String>,
    pub downtime_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendStatus {
    Up,
    Down,
    Maint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerStatus {
    Up,
    Down,
    Maint,
    NoCheck,
}

pub struct HAProxyManager {
    config: HAProxyConfig,
    config_path: PathBuf,
}

impl HAProxyManager {
    pub fn new(config: HAProxyConfig) -> Self {
        Self {
            config,
            config_path: PathBuf::from("/etc/haproxy/haproxy.cfg"),
        }
    }

    /// Generate HAProxy configuration file
    pub async fn configure(&self) -> Result<()> {
        tracing::info!("Generating HAProxy configuration");

        let config_content = self.generate_config();

        // Create directory
        tokio::fs::create_dir_all("/etc/haproxy").await?;

        // Write config
        tokio::fs::write(&self.config_path, config_content).await?;

        // Validate configuration
        self.validate_config().await?;

        // Create systemd service
        self.create_systemd_service().await?;

        Ok(())
    }

    fn generate_config(&self) -> String {
        let mut config = String::new();

        // Global section
        config.push_str("# HAProxy Configuration\n");
        config.push_str("# Generated by Patronus\n\n");

        config.push_str("global\n");
        config.push_str(&format!("    maxconn {}\n", self.config.max_conn));
        config.push_str(&format!("    log {} local0 {:?}\n",
            self.config.log_facility,
            self.config.log_level));
        config.push_str(&format!("    nbthread {}\n", self.config.nbthread));
        config.push_str("    daemon\n");
        config.push_str("    user haproxy\n");
        config.push_str("    group haproxy\n");
        config.push_str("    pidfile /var/run/haproxy.pid\n");

        // SSL defaults
        config.push_str(&format!("    ssl-default-bind-ciphers {}\n",
            self.config.ssl_default_bind_ciphers));
        config.push_str(&format!("    ssl-default-bind-options {}\n\n",
            self.config.ssl_default_bind_options));

        // Defaults section
        config.push_str("defaults\n");
        config.push_str("    log     global\n");
        config.push_str("    mode    http\n");
        config.push_str("    option  httplog\n");
        config.push_str("    option  dontlognull\n");
        config.push_str("    timeout connect 5000\n");
        config.push_str("    timeout client  50000\n");
        config.push_str("    timeout server  50000\n");
        config.push_str("    errorfile 400 /etc/haproxy/errors/400.http\n");
        config.push_str("    errorfile 403 /etc/haproxy/errors/403.http\n");
        config.push_str("    errorfile 408 /etc/haproxy/errors/408.http\n");
        config.push_str("    errorfile 500 /etc/haproxy/errors/500.http\n");
        config.push_str("    errorfile 502 /etc/haproxy/errors/502.http\n");
        config.push_str("    errorfile 503 /etc/haproxy/errors/503.http\n");
        config.push_str("    errorfile 504 /etc/haproxy/errors/504.http\n\n");

        // Statistics page
        if self.config.stats.enabled {
            config.push_str("listen stats\n");
            config.push_str(&format!("    bind {}:{}\n",
                self.config.stats.bind_address,
                self.config.stats.bind_port));
            config.push_str("    mode http\n");
            config.push_str("    stats enable\n");
            config.push_str(&format!("    stats uri {}\n", self.config.stats.uri));
            config.push_str(&format!("    stats refresh {}s\n", self.config.stats.refresh));

            if let (Some(user), Some(pass)) = (&self.config.stats.username, &self.config.stats.password) {
                config.push_str(&format!("    stats auth {}:{}\n", user, pass));
            }
            config.push_str("    stats admin if TRUE\n\n");
        }

        // Frontends
        for frontend in &self.config.frontends {
            if !frontend.enabled {
                continue;
            }

            config.push_str(&format!("frontend {}\n", frontend.name));

            // Bind
            let bind_str = if frontend.ssl {
                format!("    bind {}:{} ssl crt {}\n",
                    frontend.bind_address,
                    frontend.bind_port,
                    frontend.ssl_cert.as_ref().unwrap().display())
            } else {
                format!("    bind {}:{}\n", frontend.bind_address, frontend.bind_port)
            };
            config.push_str(&bind_str);

            // Mode
            config.push_str(&format!("    mode {:?}\n", frontend.mode).to_lowercase());

            // Timeouts
            config.push_str(&format!("    timeout client {}s\n", frontend.client_timeout));

            // Max connections
            if let Some(max_conn) = frontend.max_conn {
                config.push_str(&format!("    maxconn {}\n", max_conn));
            }

            // Force HTTPS redirect
            if frontend.force_https && !frontend.ssl {
                config.push_str("    redirect scheme https code 301 if !{ ssl_fc }\n");
            }

            // HTTP/2
            if frontend.http2_enabled {
                config.push_str("    option http-use-htx\n");
            }

            // Compression
            if frontend.compression {
                config.push_str("    compression algo gzip\n");
                config.push_str("    compression type text/html text/plain text/css text/javascript application/javascript\n");
            }

            // X-Forwarded-For
            if frontend.xff_enabled {
                config.push_str("    option forwardfor\n");
            }

            // ACLs
            for acl in &frontend.acls {
                config.push_str(&self.generate_acl(acl));
            }

            // Backend routing rules
            for rule in &frontend.use_backend_rules {
                let negation = if rule.negate { "!" } else { "" };
                config.push_str(&format!("    use_backend {} if {}{}\n",
                    rule.backend_name, negation, rule.acl_name));
            }

            // Default backend
            config.push_str(&format!("    default_backend {}\n\n", frontend.default_backend));
        }

        // Backends
        for backend in &self.config.backends {
            if !backend.enabled {
                continue;
            }

            config.push_str(&format!("backend {}\n", backend.name));
            config.push_str(&format!("    mode {:?}\n", backend.mode).to_lowercase());
            config.push_str(&format!("    balance {:?}\n", backend.balance).to_lowercase());

            // Timeouts
            config.push_str(&format!("    timeout server {}s\n", backend.server_timeout));
            config.push_str(&format!("    timeout connect {}s\n", backend.connect_timeout));

            // X-Forwarded-For
            if backend.forwardfor {
                config.push_str("    option forwardfor\n");
            }

            // HTTP close
            if backend.httpclose {
                config.push_str("    option httpclose\n");
            }

            // Sticky sessions
            if backend.sticky_session {
                if let Some(cookie) = &backend.cookie_name {
                    config.push_str(&format!("    cookie {} insert indirect nocache\n", cookie));
                }
            }

            // Servers
            for server in &backend.servers {
                if !server.enabled {
                    continue;
                }

                let mut server_line = format!("    server {} {}:{}",
                    server.name, server.address, server.port);

                // Weight
                if server.weight != 100 {
                    server_line.push_str(&format!(" weight {}", server.weight));
                }

                // Max connections
                if let Some(max_conn) = server.max_conn {
                    server_line.push_str(&format!(" maxconn {}", max_conn));
                }

                // Backup
                if server.backup {
                    server_line.push_str(" backup");
                }

                // SSL
                if server.ssl {
                    server_line.push_str(" ssl verify none");
                }

                // Send PROXY protocol
                if server.send_proxy {
                    server_line.push_str(" send-proxy");
                }

                // Health check
                if server.check.enabled {
                    server_line.push_str(" check");
                    server_line.push_str(&format!(" inter {}s", server.check.interval));
                    server_line.push_str(&format!(" rise {}", server.check.rise));
                    server_line.push_str(&format!(" fall {}", server.check.fall));

                    if let Some(port) = server.check.check_port {
                        server_line.push_str(&format!(" port {}", port));
                    }
                }

                server_line.push('\n');
                config.push_str(&server_line);
            }

            config.push_str("\n");
        }

        config
    }

    fn generate_acl(&self, acl: &AccessControlList) -> String {
        let condition = match &acl.condition {
            AclCondition::PathBegins(path) => format!("path_beg {}", path),
            AclCondition::PathEquals(path) => format!("path {}", path),
            AclCondition::PathRegex(regex) => format!("path_reg {}", regex),
            AclCondition::HostEquals(host) => format!("hdr(host) -i {}", host),
            AclCondition::HostRegex(regex) => format!("hdr_reg(host) -i {}", regex),
            AclCondition::MethodEquals(method) => format!("method {}", method),
            AclCondition::HeaderExists(header) => format!("hdr_cnt({}) gt 0", header),
            AclCondition::HeaderEquals(header, value) => format!("hdr({}) {}", header, value),
            AclCondition::SourceIP(cidr) => format!("src {}", cidr),
            AclCondition::SSL => "ssl_fc".to_string(),
            AclCondition::URLParam(param, value) => format!("urlp({}) {}", param, value),
        };

        format!("    acl {} {}\n", acl.name, condition)
    }

    async fn validate_config(&self) -> Result<()> {
        let output = Command::new("haproxy")
            .args(&["-c", "-f", self.config_path.to_str().unwrap()])
            .output()
            .await?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Config(format!("HAProxy config validation failed: {}", error)));
        }

        Ok(())
    }

    async fn create_systemd_service(&self) -> Result<()> {
        let service = r#"[Unit]
Description=HAProxy Load Balancer
After=network.target

[Service]
Type=forking
PIDFile=/var/run/haproxy.pid
ExecStartPre=/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg
ExecStart=/usr/sbin/haproxy -D -f /etc/haproxy/haproxy.cfg -p /var/run/haproxy.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#;

        tokio::fs::write("/etc/systemd/system/haproxy.service", service).await?;

        Ok(())
    }

    /// Start HAProxy
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting HAProxy");

        let status = Command::new("systemctl")
            .args(&["start", "haproxy"])
            .status()
            .await?;

        if !status.success() {
            return Err(Error::Network("Failed to start HAProxy".to_string()));
        }

        Ok(())
    }

    /// Stop HAProxy
    pub async fn stop(&self) -> Result<()> {
        Command::new("systemctl")
            .args(&["stop", "haproxy"])
            .status()
            .await?;

        Ok(())
    }

    /// Reload HAProxy configuration
    pub async fn reload(&self) -> Result<()> {
        // Validate first
        self.validate_config().await?;

        // Reload
        let status = Command::new("systemctl")
            .args(&["reload", "haproxy"])
            .status()
            .await?;

        if !status.success() {
            return Err(Error::Network("Failed to reload HAProxy".to_string()));
        }

        Ok(())
    }

    /// Get HAProxy statistics
    pub async fn get_stats(&self) -> Result<HAProxyStats> {
        // Query HAProxy stats socket or HTTP stats page
        // Simplified implementation
        Ok(HAProxyStats {
            uptime_seconds: 0,
            current_connections: 0,
            total_connections: 0,
            requests_per_second: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            backend_stats: vec![],
        })
    }

    /// Set server maintenance mode
    pub async fn set_server_maint(&self, backend: &str, server: &str, enabled: bool) -> Result<()> {
        let state = if enabled { "maint" } else { "ready" };

        // Use HAProxy runtime API
        let cmd = format!("set server {}/{} state {}", backend, server, state);

        // Send to stats socket
        // echo "set server backend/server1 state maint" | socat stdio /var/run/haproxy.sock

        Ok(())
    }
}

impl Default for HAProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_conn: 10000,
            log_level: LogLevel::Info,
            log_facility: "/dev/log".to_string(),
            nbproc: 1,
            nbthread: 4,
            ssl_default_bind_ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            ssl_default_bind_options: "no-sslv3 no-tlsv10 no-tlsv11".to_string(),
            stats: StatsConfig {
                enabled: true,
                bind_address: "127.0.0.1".parse().unwrap(),
                bind_port: 8404,
                uri: "/stats".to_string(),
                username: Some("admin".to_string()),
                password: Some("changeme".to_string()),
                refresh: 5,
            },
            frontends: vec![],
            backends: vec![],
        }
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            enabled: true,
            method: HealthCheckMethod::TCP,
            interval: 2,
            timeout: 1,
            rise: 2,
            fall: 3,
            check_port: None,
        }
    }
}
