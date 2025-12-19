//! Disk detection module

use crate::error::{InstallerError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{debug, info};

/// Disk transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// SATA/IDE disk
    Sata,
    /// NVMe SSD
    Nvme,
    /// USB storage
    Usb,
    /// SCSI disk
    Scsi,
    /// Virtual disk (VM)
    Virtio,
    /// MMC/SD card
    Mmc,
    /// Unknown transport
    Unknown,
}

impl Transport {
    /// Detect transport from device name
    pub fn from_device_name(name: &str) -> Self {
        if name.starts_with("nvme") {
            Self::Nvme
        } else if name.starts_with("sd") {
            // Could be SATA, USB, or SCSI - need to check sysfs
            Self::Sata // Default, will be refined
        } else if name.starts_with("vd") {
            Self::Virtio
        } else if name.starts_with("mmcblk") {
            Self::Mmc
        } else {
            Self::Unknown
        }
    }
}

/// Information about a partition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    /// Partition device path (e.g., /dev/sda1)
    pub path: PathBuf,

    /// Partition number
    pub number: u32,

    /// Start sector
    pub start_sector: u64,

    /// End sector
    pub end_sector: u64,

    /// Size in bytes
    pub size_bytes: u64,

    /// Filesystem type (if detected)
    pub filesystem: Option<String>,

    /// Partition label
    pub label: Option<String>,

    /// Mount point (if mounted)
    pub mount_point: Option<PathBuf>,

    /// Partition type GUID/ID
    pub partition_type: Option<String>,

    /// Partition flags
    pub flags: Vec<String>,
}

/// Information about a disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    /// Device path (e.g., /dev/sda, /dev/nvme0n1)
    pub path: PathBuf,

    /// Device name without /dev/ prefix
    pub name: String,

    /// Disk model/product name
    pub model: String,

    /// Disk serial number
    pub serial: Option<String>,

    /// Total size in bytes
    pub size_bytes: u64,

    /// Logical sector size
    pub sector_size: u32,

    /// Physical sector size
    pub physical_sector_size: u32,

    /// Transport type
    pub transport: Transport,

    /// Partition table type (gpt, msdos, none)
    pub partition_table: Option<String>,

    /// Partitions on this disk
    pub partitions: Vec<PartitionInfo>,

    /// Whether disk is removable (USB, etc.)
    pub is_removable: bool,

    /// Whether disk is read-only
    pub is_readonly: bool,

    /// Whether this is the boot disk (contains running system)
    pub is_boot_disk: bool,

    /// Whether disk is an SSD
    pub is_ssd: bool,
}

impl DiskInfo {
    /// Get human-readable size string
    pub fn size_string(&self) -> String {
        format_size(self.size_bytes)
    }

    /// Get summary string for display
    pub fn summary(&self) -> String {
        let mut flags = Vec::new();
        if self.is_removable {
            flags.push("removable");
        }
        if self.is_ssd {
            flags.push("SSD");
        }
        if self.is_boot_disk {
            flags.push("boot");
        }

        let flags_str = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(", "))
        };

        format!(
            "{} - {} ({}){}",
            self.path.display(),
            self.model,
            self.size_string(),
            flags_str
        )
    }

    /// Check if disk is suitable for installation
    pub fn is_suitable_target(&self) -> bool {
        !self.is_readonly && !self.is_boot_disk && self.size_bytes >= 8 * 1024 * 1024 * 1024
        // Minimum 8GB
    }
}

/// Format bytes into human-readable size
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Detect all available disks on the system
pub async fn detect_disks() -> Result<Vec<DiskInfo>> {
    info!("Detecting available disks...");

    let mut disks = Vec::new();

    // Use lsblk to get disk information
    let output = Command::new("lsblk")
        .args([
            "-J",       // JSON output
            "-b",       // Size in bytes
            "-o",       // Output columns
            "NAME,TYPE,SIZE,MODEL,SERIAL,TRAN,RO,RM,MOUNTPOINT,FSTYPE,PTTYPE,PHY-SEC,LOG-SEC",
        ])
        .output()
        .await
        .map_err(|e| InstallerError::Disk(format!("Failed to run lsblk: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Disk(format!(
            "lsblk failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| InstallerError::Disk(format!("Failed to parse lsblk output: {}", e)))?;

    // Find the boot device (device containing /)
    let boot_device = find_boot_device().await;

    // Parse blockdevices
    if let Some(devices) = json.get("blockdevices").and_then(|v| v.as_array()) {
        for device in devices {
            if let Some(disk) = parse_disk_entry(device, &boot_device).await {
                disks.push(disk);
            }
        }
    }

    info!("Found {} disk(s)", disks.len());
    for disk in &disks {
        debug!(
            "  {} - {} ({})",
            disk.path.display(),
            disk.model,
            disk.size_string()
        );
    }

    Ok(disks)
}

/// Get information about a specific disk
pub async fn get_disk_info(path: &Path) -> Result<DiskInfo> {
    let disks = detect_disks().await?;

    disks
        .into_iter()
        .find(|d| d.path == path)
        .ok_or_else(|| InstallerError::Disk(format!("Disk not found: {}", path.display())))
}

/// Find the device containing the root filesystem
async fn find_boot_device() -> Option<String> {
    // Read /proc/mounts to find root device
    if let Ok(content) = tokio::fs::read_to_string("/proc/mounts").await {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "/" {
                let device = parts[0];
                // Extract base device name (e.g., /dev/sda1 -> sda)
                if let Some(name) = device.strip_prefix("/dev/") {
                    // Remove partition number
                    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
                    // Handle NVMe partition naming (nvme0n1p1 -> nvme0n1)
                    let base = base.trim_end_matches('p');
                    return Some(base.to_string());
                }
            }
        }
    }
    None
}

/// Parse a disk entry from lsblk JSON
async fn parse_disk_entry(
    device: &serde_json::Value,
    boot_device: &Option<String>,
) -> Option<DiskInfo> {
    let device_type = device.get("type")?.as_str()?;

    // Only process whole disks
    if device_type != "disk" {
        return None;
    }

    let name = device.get("name")?.as_str()?.to_string();
    let path = PathBuf::from(format!("/dev/{}", name));

    let size_bytes = device
        .get("size")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);

    let model = device
        .get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let serial = device
        .get("serial")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let transport = device
        .get("tran")
        .and_then(|v| v.as_str())
        .map(|t| match t {
            "sata" | "ata" => Transport::Sata,
            "nvme" => Transport::Nvme,
            "usb" => Transport::Usb,
            "scsi" => Transport::Scsi,
            "virtio" => Transport::Virtio,
            "mmc" => Transport::Mmc,
            _ => Transport::from_device_name(&name),
        })
        .unwrap_or_else(|| Transport::from_device_name(&name));

    let is_readonly = device
        .get("ro")
        .and_then(|v| {
            v.as_bool()
                .or_else(|| v.as_u64().map(|n| n != 0))
                .or_else(|| v.as_str().map(|s| s == "1" || s == "true"))
        })
        .unwrap_or(false);

    let is_removable = device
        .get("rm")
        .and_then(|v| {
            v.as_bool()
                .or_else(|| v.as_u64().map(|n| n != 0))
                .or_else(|| v.as_str().map(|s| s == "1" || s == "true"))
        })
        .unwrap_or(transport == Transport::Usb);

    let partition_table = device
        .get("pttype")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let sector_size = device
        .get("log-sec")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n as u32)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(512);

    let physical_sector_size = device
        .get("phy-sec")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n as u32)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(512);

    // Check if this is the boot disk
    let is_boot_disk = boot_device
        .as_ref()
        .map(|bd| name == *bd || name.starts_with(bd))
        .unwrap_or(false);

    // Check if SSD (rotational = 0)
    let is_ssd = check_is_ssd(&name).await;

    // Parse partitions
    let partitions = if let Some(children) = device.get("children").and_then(|v| v.as_array()) {
        children
            .iter()
            .filter_map(|p| parse_partition_entry(p))
            .collect()
    } else {
        Vec::new()
    };

    Some(DiskInfo {
        path,
        name,
        model,
        serial,
        size_bytes,
        sector_size,
        physical_sector_size,
        transport,
        partition_table,
        partitions,
        is_removable,
        is_readonly,
        is_boot_disk,
        is_ssd,
    })
}

/// Parse a partition entry from lsblk JSON
fn parse_partition_entry(partition: &serde_json::Value) -> Option<PartitionInfo> {
    let part_type = partition.get("type")?.as_str()?;
    if part_type != "part" {
        return None;
    }

    let name = partition.get("name")?.as_str()?;
    let path = PathBuf::from(format!("/dev/{}", name));

    // Extract partition number from name
    let number = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0);

    let size_bytes = partition
        .get("size")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);

    let filesystem = partition
        .get("fstype")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let mount_point = partition
        .get("mountpoint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    Some(PartitionInfo {
        path,
        number,
        start_sector: 0, // Would need additional parsing
        end_sector: 0,
        size_bytes,
        filesystem,
        label: None,
        mount_point,
        partition_type: None,
        flags: Vec::new(),
    })
}

/// Check if a disk is an SSD by reading /sys/block/{name}/queue/rotational
async fn check_is_ssd(name: &str) -> bool {
    let path = format!("/sys/block/{}/queue/rotational", name);
    if let Ok(content) = tokio::fs::read_to_string(&path).await {
        return content.trim() == "0";
    }
    // For NVMe, assume SSD
    name.starts_with("nvme")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_size(1024 * 1024 * 1024 * 1024), "1.0 TB");
        assert_eq!(format_size(500 * 1024 * 1024 * 1024), "500.0 GB");
    }

    #[test]
    fn test_transport_detection() {
        assert_eq!(Transport::from_device_name("nvme0n1"), Transport::Nvme);
        assert_eq!(Transport::from_device_name("sda"), Transport::Sata);
        assert_eq!(Transport::from_device_name("vda"), Transport::Virtio);
        assert_eq!(Transport::from_device_name("mmcblk0"), Transport::Mmc);
    }
}
