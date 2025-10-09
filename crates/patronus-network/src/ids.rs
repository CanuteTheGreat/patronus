//! Intrusion Detection and Prevention System (IDS/IPS)
//!
//! Provides integration with Suricata and Snort for network security monitoring
//! and inline intrusion prevention.
//!
//! # The Gentoo Way: Choice of Backends
//!
//! - **Suricata**: Modern multi-threaded IDS/IPS with advanced features
//! - **Snort**: Classic proven IDS/IPS with extensive rule community
//!
//! Both are excellent. Choose based on your needs!

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tokio::process::Command;

/// IDS/IPS backend
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdsBackend {
    /// Suricata - Modern multi-threaded IDS/IPS
    Suricata,
    /// Snort 3 - Latest version of classic Snort
    Snort3,
    /// Snort 2 - Legacy Snort (widely deployed)
    Snort2,
}

impl std::fmt::Display for IdsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdsBackend::Suricata => write!(f, "suricata"),
            IdsBackend::Snort3 => write!(f, "snort3"),
            IdsBackend::Snort2 => write!(f, "snort2"),
        }
    }
}

/// IDS/IPS operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdsMode {
    /// Detection only (monitor/alert)
    IDS,
    /// Inline prevention (block threats)
    IPS,
}

/// Rule action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Alert,
    Drop,
    Reject,
    Pass,
}

/// Custom IDS rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub name: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub protocol: String,  // tcp, udp, icmp, ip
    pub src_ip: String,
    pub src_port: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub msg: String,
    pub sid: u32,  // Rule ID
    pub rev: u32,  // Revision
    pub content: Option<String>,
    pub pcre: Option<String>,  // Perl-compatible regex
    pub classtype: Option<String>,
    pub priority: u32,
}

/// Rule source/subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub enabled: bool,
    pub url: String,
    pub update_interval_hours: u32,
}

/// IDS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsConfig {
    pub enabled: bool,
    pub backend: IdsBackend,
    pub mode: IdsMode,

    /// Interfaces to monitor
    pub interfaces: Vec<String>,

    /// Home network (what to protect)
    pub home_net: Vec<String>,

    /// External networks
    pub external_net: Vec<String>,

    /// Rule sources
    pub rule_sources: Vec<RuleSource>,

    /// Custom rules
    pub custom_rules: Vec<IdsRule>,

    /// Categories to enable
    pub enabled_categories: Vec<String>,

    /// Performance tuning
    pub performance: IdsPerformance,

    /// Logging
    pub log_alerts: bool,
    pub log_pcap: bool,
    pub log_flow: bool,
    pub log_http: bool,
    pub log_tls: bool,
    pub log_dns: bool,
    pub log_files: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsPerformance {
    /// Number of worker threads (Suricata)
    pub workers: Option<u32>,

    /// Ring buffer size for packet capture
    pub ring_size: u32,

    /// Enable AF_PACKET for high performance (Linux)
    pub af_packet: bool,

    /// Enable hardware offload
    pub hardware_offload: bool,
}

/// IDS statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub alerts: u64,
    pub blocked: u64,
    pub uptime_seconds: u64,
}

pub struct IdsManager {
    backend: IdsBackend,
    config_dir: PathBuf,
    rules_dir: PathBuf,
    log_dir: PathBuf,
}

impl IdsManager {
    pub fn new(backend: IdsBackend) -> Self {
        Self {
            backend,
            config_dir: PathBuf::from("/etc/patronus/ids"),
            rules_dir: PathBuf::from("/etc/patronus/ids/rules"),
            log_dir: PathBuf::from("/var/log/patronus/ids"),
        }
    }

    /// Auto-detect available IDS backend
    pub fn new_auto() -> Self {
        let backend = Self::detect_backend();
        Self::new(backend)
    }

    /// Detect which IDS backend is available
    pub fn detect_backend() -> IdsBackend {
        if Self::is_command_available("suricata") {
            IdsBackend::Suricata
        } else if Self::is_command_available("snort") {
            // Check version
            if let Ok(output) = std::process::Command::new("snort")
                .arg("--version")
                .output()
            {
                let version = String::from_utf8_lossy(&output.stdout);
                if version.contains("Version 3") {
                    IdsBackend::Snort3
                } else {
                    IdsBackend::Snort2
                }
            } else {
                IdsBackend::Snort2  // Default assumption
            }
        } else {
            IdsBackend::Suricata  // Default preference
        }
    }

    /// List all available backends on this system
    pub fn list_available_backends() -> Vec<IdsBackend> {
        let mut backends = Vec::new();

        if Self::is_command_available("suricata") {
            backends.push(IdsBackend::Suricata);
        }

        if Self::is_command_available("snort") {
            // Try to detect version
            if let Ok(output) = std::process::Command::new("snort")
                .arg("--version")
                .output()
            {
                let version = String::from_utf8_lossy(&output.stdout);
                if version.contains("Version 3") {
                    backends.push(IdsBackend::Snort3);
                } else {
                    backends.push(IdsBackend::Snort2);
                }
            }
        }

        backends
    }

    fn is_command_available(cmd: &str) -> bool {
        std::process::Command::new("which")
            .arg(cmd)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Generate configuration for the selected backend
    pub async fn configure(&self, config: &IdsConfig) -> Result<()> {
        // Create directories
        fs::create_dir_all(&self.config_dir).await?;
        fs::create_dir_all(&self.rules_dir).await?;
        fs::create_dir_all(&self.log_dir).await?;

        match self.backend {
            IdsBackend::Suricata => self.configure_suricata(config).await,
            IdsBackend::Snort3 => self.configure_snort3(config).await,
            IdsBackend::Snort2 => self.configure_snort2(config).await,
        }
    }

    /// Generate Suricata configuration
    async fn configure_suricata(&self, config: &IdsConfig) -> Result<()> {
        let yaml_config = self.generate_suricata_yaml(config)?;

        let config_path = self.config_dir.join("suricata.yaml");
        fs::write(&config_path, yaml_config).await?;

        // Write custom rules
        self.write_custom_rules(config).await?;

        Ok(())
    }

    fn generate_suricata_yaml(&self, config: &IdsConfig) -> Result<String> {
        let mode_comment = match config.mode {
            IdsMode::IDS => "# IDS mode - alert only",
            IdsMode::IPS => "# IPS mode - inline blocking",
        };

        let workers = config.performance.workers
            .map(|w| w.to_string())
            .unwrap_or_else(|| "auto".to_string());

        let af_packet_config = if config.performance.af_packet {
            format!(r#"
af-packet:
  - interface: {}
    threads: {}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: {}
"#,
                config.interfaces.join("\n  - interface: "),
                workers,
                config.performance.ring_size
            )
        } else {
            String::new()
        };

        let home_net = config.home_net.join(",");
        let external_net = config.external_net.join(",");

        Ok(format!(r#"%YAML 1.1
---
# Patronus IDS/IPS - Suricata Configuration
{}

vars:
  address-groups:
    HOME_NET: "[{}]"
    EXTERNAL_NET: "[{}]"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21

# Threading
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
  detect-thread-ratio: 1.0

{}

# Outputs
outputs:
  - fast:
      enabled: {}
      filename: fast.log

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            packet: yes
            metadata: yes
        - http:
            enabled: {}
        - dns:
            enabled: {}
        - tls:
            enabled: {}
        - files:
            enabled: {}
        - flow:
            enabled: {}

# Rule files
default-rule-path: {}
rule-files:
  - suricata.rules
  - custom.rules

# Performance
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

stream:
    memcap: 64mb
    checksum-validation: yes
    inline: {}
    reassembly:
      memcap: 256mb
      depth: 1mb
      toserver-chunk-size: 2560
      toclient-chunk-size: 2560

# Logging
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: /var/log/patronus/ids/suricata.log
    - syslog:
        enabled: yes
        facility: local5
"#,
            mode_comment,
            home_net,
            external_net,
            af_packet_config,
            config.log_alerts,
            config.log_http,
            config.log_dns,
            config.log_tls,
            config.log_files,
            config.log_flow,
            self.rules_dir.display(),
            if config.mode == IdsMode::IPS { "auto" } else { "no" },
        ))
    }

    /// Generate Snort 3 configuration
    async fn configure_snort3(&self, config: &IdsConfig) -> Result<()> {
        let lua_config = self.generate_snort3_lua(config)?;

        let config_path = self.config_dir.join("snort.lua");
        fs::write(&config_path, lua_config).await?;

        self.write_custom_rules(config).await?;

        Ok(())
    }

    fn generate_snort3_lua(&self, config: &IdsConfig) -> Result<String> {
        let home_net = config.home_net.join(",");
        let external_net = config.external_net.join(",");

        let mode = match config.mode {
            IdsMode::IDS => "tap",
            IdsMode::IPS => "inline",
        };

        Ok(format!(r#"-- Patronus IDS/IPS - Snort 3 Configuration

---------------------------------------------------------------------------
-- Variables
---------------------------------------------------------------------------
HOME_NET = '{}'
EXTERNAL_NET = '{}'

---------------------------------------------------------------------------
-- Network
---------------------------------------------------------------------------
network = {{
    home_net = HOME_NET,
    external_net = EXTERNAL_NET,
}}

---------------------------------------------------------------------------
-- Detection
---------------------------------------------------------------------------
ips = {{
    mode = '{}',
    variables = network,
    rules = [[
        include {}/custom.rules
    ]],
}}

---------------------------------------------------------------------------
-- Outputs
---------------------------------------------------------------------------
alert_fast = {{
    file = true,
    packet = false,
}}

alert_json = {{
    file = true,
    fields = 'seconds action class b64_data dir dst_addr dst_port eth_dst eth_src ' ..
             'gid iface msg mpls pkt_gen pkt_len pkt_num priority proto rev rule ' ..
             'service sid src_addr src_port target tcp_ack tcp_flags tcp_seq tcp_win ' ..
             'tos ttl udp_len vlan timestamp',
}}

---------------------------------------------------------------------------
-- Performance
---------------------------------------------------------------------------
search_engine = {{
    search_method = 'ac_bnfa',
}}

detection = {{
    pcre_match_limit = 1500,
    pcre_match_limit_recursion = 1500,
}}

---------------------------------------------------------------------------
-- Logging
---------------------------------------------------------------------------
output = {{
    logdir = '/var/log/patronus/ids',
}}
"#,
            home_net,
            external_net,
            mode,
            self.rules_dir.display(),
        ))
    }

    /// Generate Snort 2 configuration
    async fn configure_snort2(&self, config: &IdsConfig) -> Result<()> {
        let conf_text = self.generate_snort2_conf(config)?;

        let config_path = self.config_dir.join("snort.conf");
        fs::write(&config_path, conf_text).await?;

        self.write_custom_rules(config).await?;

        Ok(())
    }

    fn generate_snort2_conf(&self, config: &IdsConfig) -> Result<String> {
        let home_net = config.home_net.join(",");
        let external_net = config.external_net.join(",");

        Ok(format!(r#"# Patronus IDS/IPS - Snort 2 Configuration

#--------------------------------------------------
# Variables
#--------------------------------------------------
var HOME_NET {}
var EXTERNAL_NET {}

var HTTP_SERVERS $HOME_NET
var SMTP_SERVERS $HOME_NET
var SQL_SERVERS $HOME_NET
var DNS_SERVERS $HOME_NET

var HTTP_PORTS 80
var SHELLCODE_PORTS !80
var ORACLE_PORTS 1521

#--------------------------------------------------
# Decoder and Preprocessor Configuration
#--------------------------------------------------
config checksum_mode: all
config disable_decode_alerts
config disable_tcpopt_experimental_alerts
config disable_tcpopt_obsolete_alerts
config disable_ttcp_alerts
config disable_tcpopt_alerts
config disable_ipopt_alerts

# Performance
config detection: search-method ac-bnfa
config event_queue: max_queue 8 log 5 order_events content_length

# Stream5 preprocessor
preprocessor stream5_global: track_tcp yes, \
   track_udp yes, \
   track_icmp no, \
   max_tcp 262144, \
   max_udp 131072, \
   max_active_responses 2, \
   min_response_seconds 5

preprocessor stream5_tcp: policy linux, detect_anomalies, require_3whs 180, \
   overlap_limit 10, small_segments 3 bytes 150, timeout 180, \
   ports client 21 22 23 25 42 53 79 109 110 111 113 119 135 136 137 139 143 \
         161 445 513 514 587 593 691 1433 1521 1741 2100 3306 6070 6665 6666 6667 6668 6669 \
         7000 8181 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779, \
   ports both 80 81 311 383 443 465 563 591 593 636 901 989 992 993 994 995 1220 1414 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7907 7001 7802 7777 7779 \
         7801 7900 7901 7902 7903 7904 7905 7906 7908 7909 7910 7911 7912 7913 7914 7915 7916 \
         7917 7918 7919 7920 8000 8008 8028 8080 8088 8118 8123 8180 8243 8280 8888 9090 9091 9443 9999 11371 34443 34444 41080 50002 55555

preprocessor stream5_udp: timeout 180

# HTTP Inspect
preprocessor http_inspect: global iis_unicode_map unicode.map 1252 compress_depth 65535 decompress_depth 65535

preprocessor http_inspect_server: server default \
    http_methods {{ GET POST PUT SEARCH MKCOL COPY MOVE LOCK UNLOCK NOTIFY POLL BCOPY BDELETE BMOVE LINK UNLINK OPTIONS HEAD DELETE TRACE TRACK CONNECT SOURCE SUBSCRIBE UNSUBSCRIBE PROPFIND PROPPATCH BPROPFIND BPROPPATCH RPC_CONNECT PROXY_SUCCESS BITS_POST CCM_POST SMS_POST RPC_IN_DATA RPC_OUT_DATA RPC_ECHO_DATA }} \
    chunk_length 500000 \
    server_flow_depth 0 \
    client_flow_depth 0 \
    post_depth 65495 \
    oversize_dir_length 500 \
    max_header_length 750 \
    max_headers 100 \
    max_spaces 200 \
    small_chunk_length {{ 10 5 }} \
    ports {{ 80 81 311 383 591 593 901 1220 1414 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7000 7001 7777 7779 7801 7900 7901 7902 7903 7904 7905 7906 7908 7909 7910 }} \
    non_rfc_char {{ 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 }} \
    enable_cookie \
    extended_response_inspection \
    inspect_gzip \
    normalize_utf \
    unlimited_decompress \
    normalize_javascript \
    apache_whitespace no \
    ascii no \
    bare_byte no \
    directory no \
    double_decode no \
    iis_backslash no \
    iis_delimiter no \
    iis_unicode no \
    multi_slash no \
    utf_8 no \
    u_encode yes \
    webroot no

#--------------------------------------------------
# Output Plugins
#--------------------------------------------------
output alert_fast: alerts.txt
output alert_json: alerts.json

#--------------------------------------------------
# Rules
#--------------------------------------------------
var RULE_PATH {}
include $RULE_PATH/custom.rules
"#,
            home_net,
            external_net,
            self.rules_dir.display(),
        ))
    }

    /// Write custom rules file
    async fn write_custom_rules(&self, config: &IdsConfig) -> Result<()> {
        let mut rules_text = String::from("# Patronus Custom IDS Rules\n\n");

        for rule in &config.custom_rules {
            if !rule.enabled {
                continue;
            }

            let action = match rule.action {
                RuleAction::Alert => "alert",
                RuleAction::Drop => "drop",
                RuleAction::Reject => "reject",
                RuleAction::Pass => "pass",
            };

            let mut rule_parts = vec![
                format!("{} {} {} {} -> {} {}",
                    action,
                    rule.protocol,
                    rule.src_ip,
                    rule.src_port,
                    rule.dst_ip,
                    rule.dst_port
                ),
                format!("(msg:\"{}\"; sid:{}; rev:{};",
                    rule.msg,
                    rule.sid,
                    rule.rev
                ),
            ];

            if let Some(ref content) = rule.content {
                rule_parts.push(format!("content:\"{}\";", content));
            }

            if let Some(ref pcre) = rule.pcre {
                rule_parts.push(format!("pcre:\"{}\";", pcre));
            }

            if let Some(ref classtype) = rule.classtype {
                rule_parts.push(format!("classtype:{};", classtype));
            }

            rule_parts.push(format!("priority:{};", rule.priority));
            rule_parts.push(")".to_string());

            rules_text.push_str(&format!("{}\n", rule_parts.join(" ")));
        }

        let rules_path = self.rules_dir.join("custom.rules");
        fs::write(&rules_path, rules_text).await?;

        Ok(())
    }

    /// Update rule sources
    pub async fn update_rules(&self) -> Result<()> {
        match self.backend {
            IdsBackend::Suricata => {
                Command::new("suricata-update")
                    .spawn()
                    .map_err(|e| Error::Firewall(format!("Failed to update Suricata rules: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Firewall(format!("suricata-update failed: {}", e)))?;
            }
            IdsBackend::Snort3 | IdsBackend::Snort2 => {
                // For Snort, users typically use pulledpork
                Command::new("pulledpork3.pl")
                    .arg("-c")
                    .arg("/etc/patronus/ids/pulledpork.conf")
                    .spawn()
                    .map_err(|e| Error::Firewall(format!("Failed to update Snort rules: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Firewall(format!("pulledpork failed: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Start IDS/IPS
    pub async fn start(&self, config: &IdsConfig) -> Result<()> {
        match self.backend {
            IdsBackend::Suricata => self.start_suricata(config).await,
            IdsBackend::Snort3 => self.start_snort3(config).await,
            IdsBackend::Snort2 => self.start_snort2(config).await,
        }
    }

    async fn start_suricata(&self, config: &IdsConfig) -> Result<()> {
        let config_file = self.config_dir.join("suricata.yaml");

        let mut cmd = Command::new("suricata");
        cmd.arg("-c").arg(&config_file);

        if config.mode == IdsMode::IPS {
            // IPS mode - use NFQUEUE
            cmd.arg("-q").arg("0");
        } else {
            // IDS mode - listen on interfaces
            for iface in &config.interfaces {
                cmd.arg("-i").arg(iface);
            }
        }

        cmd.spawn()
            .map_err(|e| Error::Firewall(format!("Failed to start Suricata: {}", e)))?;

        Ok(())
    }

    async fn start_snort3(&self, config: &IdsConfig) -> Result<()> {
        let config_file = self.config_dir.join("snort.lua");

        let mut cmd = Command::new("snort");
        cmd.arg("-c").arg(&config_file);

        if config.mode == IdsMode::IPS {
            cmd.arg("-Q");
        } else {
            for iface in &config.interfaces {
                cmd.arg("-i").arg(iface);
            }
        }

        cmd.spawn()
            .map_err(|e| Error::Firewall(format!("Failed to start Snort 3: {}", e)))?;

        Ok(())
    }

    async fn start_snort2(&self, config: &IdsConfig) -> Result<()> {
        let config_file = self.config_dir.join("snort.conf");

        let mut cmd = Command::new("snort");
        cmd.arg("-c").arg(&config_file);

        if config.mode == IdsMode::IPS {
            cmd.arg("-Q");
        } else {
            for iface in &config.interfaces {
                cmd.arg("-i").arg(iface);
            }
        }

        cmd.spawn()
            .map_err(|e| Error::Firewall(format!("Failed to start Snort 2: {}", e)))?;

        Ok(())
    }

    /// Get IDS statistics
    pub async fn get_stats(&self) -> Result<IdsStats> {
        match self.backend {
            IdsBackend::Suricata => {
                // Suricata provides stats via unix socket
                // For simplicity, we'll parse the stats.log file
                Ok(IdsStats {
                    packets_received: 0,
                    packets_dropped: 0,
                    alerts: 0,
                    blocked: 0,
                    uptime_seconds: 0,
                })
            }
            IdsBackend::Snort3 | IdsBackend::Snort2 => {
                // Snort stats from console output or file
                Ok(IdsStats {
                    packets_received: 0,
                    packets_dropped: 0,
                    alerts: 0,
                    blocked: 0,
                    uptime_seconds: 0,
                })
            }
        }
    }

    /// Create a preset for common attack detection
    pub fn create_basic_ruleset() -> Vec<IdsRule> {
        vec![
            IdsRule {
                name: "SSH Brute Force".to_string(),
                enabled: true,
                action: RuleAction::Alert,
                protocol: "tcp".to_string(),
                src_ip: "$EXTERNAL_NET".to_string(),
                src_port: "any".to_string(),
                dst_ip: "$HOME_NET".to_string(),
                dst_port: "22".to_string(),
                msg: "Possible SSH brute force attack".to_string(),
                sid: 1000001,
                rev: 1,
                content: Some("SSH".to_string()),
                pcre: None,
                classtype: Some("attempted-admin".to_string()),
                priority: 1,
            },
            IdsRule {
                name: "SQL Injection Attempt".to_string(),
                enabled: true,
                action: RuleAction::Alert,
                protocol: "tcp".to_string(),
                src_ip: "$EXTERNAL_NET".to_string(),
                src_port: "any".to_string(),
                dst_ip: "$HTTP_SERVERS".to_string(),
                dst_port: "$HTTP_PORTS".to_string(),
                msg: "SQL injection attempt detected".to_string(),
                sid: 1000002,
                rev: 1,
                content: None,
                pcre: Some(r"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i".to_string()),
                classtype: Some("web-application-attack".to_string()),
                priority: 1,
            },
            IdsRule {
                name: "Port Scan Detection".to_string(),
                enabled: true,
                action: RuleAction::Alert,
                protocol: "tcp".to_string(),
                src_ip: "$EXTERNAL_NET".to_string(),
                src_port: "any".to_string(),
                dst_ip: "$HOME_NET".to_string(),
                dst_port: "any".to_string(),
                msg: "Possible port scan detected".to_string(),
                sid: 1000003,
                rev: 1,
                content: None,
                pcre: None,
                classtype: Some("attempted-recon".to_string()),
                priority: 2,
            },
        ]
    }
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: IdsBackend::Suricata,
            mode: IdsMode::IDS,
            interfaces: vec!["eth0".to_string()],
            home_net: vec!["192.168.1.0/24".to_string()],
            external_net: vec!["!$HOME_NET".to_string()],
            rule_sources: vec![
                RuleSource {
                    name: "Emerging Threats Open".to_string(),
                    enabled: true,
                    url: "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz".to_string(),
                    update_interval_hours: 24,
                },
            ],
            custom_rules: IdsManager::create_basic_ruleset(),
            enabled_categories: vec![
                "malware".to_string(),
                "exploit".to_string(),
                "trojan".to_string(),
                "dos".to_string(),
                "scan".to_string(),
            ],
            performance: IdsPerformance {
                workers: None,  // Auto-detect
                ring_size: 4096,
                af_packet: true,
                hardware_offload: false,
            },
            log_alerts: true,
            log_pcap: false,
            log_flow: true,
            log_http: true,
            log_tls: true,
            log_dns: true,
            log_files: false,
        }
    }
}
