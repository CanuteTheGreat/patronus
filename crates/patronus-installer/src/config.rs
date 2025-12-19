//! Installation configuration types

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// Main installation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallConfig {
    /// Target root mount point (where system is installed)
    #[serde(default = "default_target_root")]
    pub target_root: PathBuf,

    /// Disk configuration
    pub disk: DiskConfig,

    /// System configuration
    pub system: SystemConfig,

    /// User configuration
    #[serde(default)]
    pub users: Vec<UserConfig>,

    /// Network configuration
    pub network: NetworkConfig,

    /// Service configuration
    pub services: ServiceConfig,

    /// Patronus-specific configuration
    #[serde(default)]
    pub patronus: PatronusConfig,
}

fn default_target_root() -> PathBuf {
    PathBuf::from("/mnt/install")
}

/// Disk configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskConfig {
    /// Target device (e.g., /dev/sda, /dev/nvme0n1)
    pub device: PathBuf,

    /// Partition scheme to use
    #[serde(default)]
    pub scheme: PartitionScheme,

    /// Root filesystem type
    #[serde(default)]
    pub filesystem: Filesystem,

    /// Swap size in MB (0 = no swap)
    #[serde(default)]
    pub swap_size_mb: u64,

    /// Separate /home partition size in MB (None = no separate home)
    pub home_size_mb: Option<u64>,
}

/// Partition scheme options
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionScheme {
    /// UEFI with GPT: ESP (512MB) + Root
    #[default]
    UefiSimple,

    /// UEFI with GPT: ESP (512MB) + Root + Swap
    UefiWithSwap,

    /// UEFI with GPT: ESP (512MB) + Root + Swap + Home
    UefiSeparateHome,

    /// BIOS with GPT: BIOS boot (2MB) + Root
    BiosSimple,

    /// BIOS with GPT: BIOS boot (2MB) + Root + Swap
    BiosWithSwap,

    /// Use existing partitions (manual)
    UseExisting,
}

impl PartitionScheme {
    pub fn is_uefi(&self) -> bool {
        matches!(
            self,
            Self::UefiSimple | Self::UefiWithSwap | Self::UefiSeparateHome
        )
    }

    pub fn has_swap(&self) -> bool {
        matches!(
            self,
            Self::UefiWithSwap | Self::UefiSeparateHome | Self::BiosWithSwap
        )
    }

    pub fn has_separate_home(&self) -> bool {
        matches!(self, Self::UefiSeparateHome)
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::UefiSimple => "UEFI (GPT): EFI System + Root",
            Self::UefiWithSwap => "UEFI (GPT): EFI System + Root + Swap",
            Self::UefiSeparateHome => "UEFI (GPT): EFI System + Root + Swap + Home",
            Self::BiosSimple => "BIOS (GPT): BIOS Boot + Root",
            Self::BiosWithSwap => "BIOS (GPT): BIOS Boot + Root + Swap",
            Self::UseExisting => "Use existing partitions",
        }
    }
}

/// Filesystem types
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Filesystem {
    /// ext4 filesystem (default, widely compatible)
    #[default]
    Ext4,

    /// Btrfs filesystem (snapshots, compression)
    Btrfs,

    /// XFS filesystem (performance)
    Xfs,
}

impl Filesystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
            Self::Xfs => "xfs",
        }
    }

    pub fn mkfs_command(&self) -> &'static str {
        match self {
            Self::Ext4 => "mkfs.ext4",
            Self::Btrfs => "mkfs.btrfs",
            Self::Xfs => "mkfs.xfs",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Ext4 => "ext4 - Stable, widely compatible",
            Self::Btrfs => "Btrfs - Snapshots, compression, modern",
            Self::Xfs => "XFS - High performance, large files",
        }
    }
}

/// System configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    /// System hostname
    pub hostname: String,

    /// Timezone (e.g., "America/New_York", "UTC")
    #[serde(default = "default_timezone")]
    pub timezone: String,

    /// Locale (e.g., "en_US.UTF-8")
    #[serde(default = "default_locale")]
    pub locale: String,

    /// Keyboard layout (e.g., "us")
    #[serde(default = "default_keyboard")]
    pub keyboard: String,

    /// Bootloader choice
    #[serde(default)]
    pub bootloader: Bootloader,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

fn default_locale() -> String {
    "en_US.UTF-8".to_string()
}

fn default_keyboard() -> String {
    "us".to_string()
}

/// Bootloader options
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Bootloader {
    /// GRUB2 bootloader (default)
    #[default]
    Grub,

    /// systemd-boot (UEFI only)
    SystemdBoot,
}

impl Bootloader {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Grub => "GRUB2 - Full featured, BIOS/UEFI compatible",
            Self::SystemdBoot => "systemd-boot - Simple, UEFI only",
        }
    }
}

/// User account configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// Username
    pub username: String,

    /// Full name (GECOS)
    #[serde(default)]
    pub full_name: String,

    /// Password (plaintext, will be hashed)
    #[serde(skip_serializing)]
    pub password: Option<String>,

    /// Pre-hashed password (for unattended installs)
    pub password_hash: Option<String>,

    /// Groups to add user to
    #[serde(default = "default_user_groups")]
    pub groups: Vec<String>,

    /// Whether user can use sudo
    #[serde(default = "default_true")]
    pub sudo: bool,

    /// Shell path
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_user_groups() -> Vec<String> {
    vec!["wheel".to_string(), "patronus".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_shell() -> String {
    "/bin/bash".to_string()
}

/// Network configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network interfaces
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,

    /// DNS servers
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,

    /// DNS search domains
    #[serde(default)]
    pub search_domains: Vec<String>,
}

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Interface name (e.g., "eth0", "enp0s3")
    pub name: String,

    /// Configuration method
    #[serde(default)]
    pub method: NetworkMethod,

    /// Interface role (WAN, LAN, etc.)
    #[serde(default)]
    pub role: InterfaceRole,
}

/// Network configuration method
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMethod {
    /// DHCP client
    #[default]
    Dhcp,

    /// Static IP configuration
    Static {
        address: IpAddr,
        prefix_len: u8,
        gateway: Option<IpAddr>,
    },

    /// Interface disabled
    Disabled,
}

/// Interface role in firewall
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceRole {
    /// WAN interface (untrusted)
    Wan,

    /// LAN interface (trusted)
    #[default]
    Lan,

    /// DMZ interface
    Dmz,

    /// Management interface
    Management,

    /// No specific role
    None,
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Enable patronus-firewall service
    #[serde(default = "default_true")]
    pub firewall: bool,

    /// Enable patronus-web service
    #[serde(default = "default_true")]
    pub web_ui: bool,

    /// Enable SSH server
    #[serde(default = "default_true")]
    pub ssh: bool,

    /// Enable DHCP server
    #[serde(default)]
    pub dhcp_server: bool,

    /// Enable DNS server
    #[serde(default)]
    pub dns_server: bool,

    /// Web UI port
    #[serde(default = "default_web_port")]
    pub web_port: u16,

    /// SSH port
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
}

fn default_web_port() -> u16 {
    8080
}

fn default_ssh_port() -> u16 {
    22
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            firewall: true,
            web_ui: true,
            ssh: true,
            dhcp_server: false,
            dns_server: false,
            web_port: 8080,
            ssh_port: 22,
        }
    }
}

/// Patronus-specific configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatronusConfig {
    /// Initial firewall policy (allow/deny)
    #[serde(default = "default_policy")]
    pub default_policy: String,

    /// Enable SD-WAN features
    #[serde(default)]
    pub sdwan_enabled: bool,

    /// Enable intrusion detection
    #[serde(default)]
    pub ids_enabled: bool,

    /// Enable VPN server
    #[serde(default)]
    pub vpn_server: bool,
}

fn default_policy() -> String {
    "deny".to_string()
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            target_root: default_target_root(),
            disk: DiskConfig {
                device: PathBuf::from("/dev/sda"),
                scheme: PartitionScheme::default(),
                filesystem: Filesystem::default(),
                swap_size_mb: 2048,
                home_size_mb: None,
            },
            system: SystemConfig {
                hostname: "patronus".to_string(),
                timezone: default_timezone(),
                locale: default_locale(),
                keyboard: default_keyboard(),
                bootloader: Bootloader::default(),
            },
            users: vec![UserConfig {
                username: "admin".to_string(),
                full_name: "Patronus Administrator".to_string(),
                password: None,
                password_hash: None,
                groups: default_user_groups(),
                sudo: true,
                shell: default_shell(),
            }],
            network: NetworkConfig::default(),
            services: ServiceConfig::default(),
            patronus: PatronusConfig::default(),
        }
    }
}
