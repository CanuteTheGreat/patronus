//! Disk partitioning module

use crate::config::{Filesystem, PartitionScheme};
use crate::error::{InstallerError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Partition flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionFlag {
    /// Boot flag (legacy BIOS)
    Boot,
    /// ESP flag (UEFI)
    Esp,
    /// BIOS boot partition
    BiosGrub,
    /// Swap partition
    Swap,
    /// Root partition
    Root,
    /// Home partition
    Home,
}

/// Information about a created partition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedPartition {
    /// Partition device path
    pub path: PathBuf,

    /// Partition number
    pub number: u32,

    /// Mount point
    pub mount_point: String,

    /// Filesystem to use
    pub filesystem: PartitionFilesystem,

    /// Size in bytes
    pub size_bytes: u64,

    /// Partition flags
    pub flags: Vec<PartitionFlag>,
}

/// Filesystem type for partition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PartitionFilesystem {
    /// FAT32 (for ESP)
    Fat32,
    /// Linux filesystem (ext4, btrfs, xfs)
    Linux(Filesystem),
    /// Swap
    Swap,
    /// None (BIOS boot)
    None,
}

/// Create partitions on a disk according to the specified scheme
pub async fn create_partitions(
    disk: &Path,
    scheme: &PartitionScheme,
    root_fs: Filesystem,
    swap_size_mb: u64,
    home_size_mb: Option<u64>,
) -> Result<Vec<CreatedPartition>> {
    info!(
        "Creating partitions on {} with scheme {:?}",
        disk.display(),
        scheme
    );

    // First, wipe the disk and create new partition table
    wipe_disk(disk).await?;

    // Create GPT partition table
    create_gpt_table(disk).await?;

    let mut partitions = Vec::new();
    let mut part_num = 1u32;

    match scheme {
        PartitionScheme::UefiSimple => {
            // ESP: 512MB
            partitions.push(create_esp_partition(disk, part_num, 512).await?);
            part_num += 1;

            // Root: remaining space
            partitions.push(create_root_partition(disk, part_num, root_fs, None).await?);
        }

        PartitionScheme::UefiWithSwap => {
            // ESP: 512MB
            partitions.push(create_esp_partition(disk, part_num, 512).await?);
            part_num += 1;

            // Swap
            if swap_size_mb > 0 {
                partitions.push(create_swap_partition(disk, part_num, swap_size_mb).await?);
                part_num += 1;
            }

            // Root: remaining space
            partitions.push(create_root_partition(disk, part_num, root_fs, None).await?);
        }

        PartitionScheme::UefiSeparateHome => {
            // ESP: 512MB
            partitions.push(create_esp_partition(disk, part_num, 512).await?);
            part_num += 1;

            // Swap
            if swap_size_mb > 0 {
                partitions.push(create_swap_partition(disk, part_num, swap_size_mb).await?);
                part_num += 1;
            }

            // Root: fixed size or calculated
            let root_size_mb = calculate_root_size(home_size_mb);
            partitions.push(
                create_root_partition(disk, part_num, root_fs, Some(root_size_mb)).await?,
            );
            part_num += 1;

            // Home: remaining space
            partitions.push(create_home_partition(disk, part_num, root_fs, None).await?);
        }

        PartitionScheme::BiosSimple => {
            // BIOS boot: 2MB
            partitions.push(create_bios_boot_partition(disk, part_num).await?);
            part_num += 1;

            // Root: remaining space
            partitions.push(create_root_partition(disk, part_num, root_fs, None).await?);
        }

        PartitionScheme::BiosWithSwap => {
            // BIOS boot: 2MB
            partitions.push(create_bios_boot_partition(disk, part_num).await?);
            part_num += 1;

            // Swap
            if swap_size_mb > 0 {
                partitions.push(create_swap_partition(disk, part_num, swap_size_mb).await?);
                part_num += 1;
            }

            // Root: remaining space
            partitions.push(create_root_partition(disk, part_num, root_fs, None).await?);
        }

        PartitionScheme::UseExisting => {
            return Err(InstallerError::Partition(
                "UseExisting scheme requires manual partition specification".to_string(),
            ));
        }
    }

    // Wait for partition devices to appear
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify partitions were created
    run_partprobe(disk).await?;

    info!("Created {} partition(s)", partitions.len());
    Ok(partitions)
}

/// Wipe disk signatures and partition table
async fn wipe_disk(disk: &Path) -> Result<()> {
    debug!("Wiping disk {}", disk.display());

    let output = Command::new("wipefs")
        .args(["--all", "--force"])
        .arg(disk)
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to run wipefs: {}", e)))?;

    if !output.status.success() {
        warn!(
            "wipefs warning: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Create GPT partition table
async fn create_gpt_table(disk: &Path) -> Result<()> {
    debug!("Creating GPT partition table on {}", disk.display());

    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["mklabel", "gpt"])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to run parted: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to create GPT: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Create EFI System Partition
async fn create_esp_partition(
    disk: &Path,
    number: u32,
    size_mb: u64,
) -> Result<CreatedPartition> {
    debug!("Creating ESP partition {} ({}MB)", number, size_mb);

    let start = "1MiB";
    let end = format!("{}MiB", size_mb + 1);

    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["mkpart", "ESP", "fat32", start, &end])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to create ESP: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to create ESP: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Set ESP flag
    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["set", &number.to_string(), "esp", "on"])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to set ESP flag: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to set ESP flag: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(CreatedPartition {
        path: partition_path(disk, number),
        number,
        mount_point: "/boot/efi".to_string(),
        filesystem: PartitionFilesystem::Fat32,
        size_bytes: size_mb * 1024 * 1024,
        flags: vec![PartitionFlag::Esp, PartitionFlag::Boot],
    })
}

/// Create BIOS boot partition (for GRUB on GPT)
async fn create_bios_boot_partition(disk: &Path, number: u32) -> Result<CreatedPartition> {
    debug!("Creating BIOS boot partition {}", number);

    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["mkpart", "BIOS", "1MiB", "3MiB"])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to create BIOS boot: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to create BIOS boot: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Set bios_grub flag
    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["set", &number.to_string(), "bios_grub", "on"])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to set bios_grub flag: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to set bios_grub flag: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(CreatedPartition {
        path: partition_path(disk, number),
        number,
        mount_point: String::new(), // Not mounted
        filesystem: PartitionFilesystem::None,
        size_bytes: 2 * 1024 * 1024,
        flags: vec![PartitionFlag::BiosGrub],
    })
}

/// Create swap partition
async fn create_swap_partition(
    disk: &Path,
    number: u32,
    size_mb: u64,
) -> Result<CreatedPartition> {
    debug!("Creating swap partition {} ({}MB)", number, size_mb);

    // Calculate start from previous partition
    let start = get_next_start(disk).await?;
    let end = format!("{}MiB", parse_mib(&start)? + size_mb);

    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["mkpart", "swap", "linux-swap", &start, &end])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to create swap: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to create swap: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(CreatedPartition {
        path: partition_path(disk, number),
        number,
        mount_point: "swap".to_string(),
        filesystem: PartitionFilesystem::Swap,
        size_bytes: size_mb * 1024 * 1024,
        flags: vec![PartitionFlag::Swap],
    })
}

/// Create root partition
async fn create_root_partition(
    disk: &Path,
    number: u32,
    filesystem: Filesystem,
    size_mb: Option<u64>,
) -> Result<CreatedPartition> {
    debug!("Creating root partition {}", number);

    let start = get_next_start(disk).await?;
    let end = match size_mb {
        Some(size) => format!("{}MiB", parse_mib(&start)? + size),
        None => "100%".to_string(),
    };

    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["mkpart", "root", filesystem.as_str(), &start, &end])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to create root: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to create root: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(CreatedPartition {
        path: partition_path(disk, number),
        number,
        mount_point: "/".to_string(),
        filesystem: PartitionFilesystem::Linux(filesystem),
        size_bytes: size_mb.unwrap_or(0) * 1024 * 1024, // 0 means use remaining
        flags: vec![PartitionFlag::Root],
    })
}

/// Create home partition
async fn create_home_partition(
    disk: &Path,
    number: u32,
    filesystem: Filesystem,
    size_mb: Option<u64>,
) -> Result<CreatedPartition> {
    debug!("Creating home partition {}", number);

    let start = get_next_start(disk).await?;
    let end = match size_mb {
        Some(size) => format!("{}MiB", parse_mib(&start)? + size),
        None => "100%".to_string(),
    };

    let output = Command::new("parted")
        .args(["-s", "--"])
        .arg(disk)
        .args(["mkpart", "home", filesystem.as_str(), &start, &end])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to create home: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Partition(format!(
            "Failed to create home: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(CreatedPartition {
        path: partition_path(disk, number),
        number,
        mount_point: "/home".to_string(),
        filesystem: PartitionFilesystem::Linux(filesystem),
        size_bytes: size_mb.unwrap_or(0) * 1024 * 1024,
        flags: vec![PartitionFlag::Home],
    })
}

/// Get the start position for the next partition
async fn get_next_start(disk: &Path) -> Result<String> {
    let output = Command::new("parted")
        .args(["-s", "-m"])
        .arg(disk)
        .args(["unit", "MiB", "print", "free"])
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to query partitions: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the last partition end or first free space
    let mut last_end = 1u64; // Start at 1MiB by default

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            // Try to parse as partition info
            if let Ok(end) = parts[2].trim_end_matches("MiB").parse::<f64>() {
                let end_mib = end.ceil() as u64;
                if end_mib > last_end {
                    last_end = end_mib;
                }
            }
        }
    }

    Ok(format!("{}MiB", last_end))
}

/// Parse MiB value from string like "512MiB"
fn parse_mib(s: &str) -> Result<u64> {
    s.trim_end_matches("MiB")
        .parse()
        .map_err(|_| InstallerError::Partition(format!("Invalid size: {}", s)))
}

/// Get partition device path (handles NVMe naming)
fn partition_path(disk: &Path, number: u32) -> PathBuf {
    let disk_str = disk.to_string_lossy();

    // NVMe uses p prefix for partitions (nvme0n1p1)
    if disk_str.contains("nvme") || disk_str.contains("mmcblk") {
        PathBuf::from(format!("{}p{}", disk_str, number))
    } else {
        PathBuf::from(format!("{}{}", disk_str, number))
    }
}

/// Run partprobe to re-read partition table
async fn run_partprobe(disk: &Path) -> Result<()> {
    let output = Command::new("partprobe")
        .arg(disk)
        .output()
        .await
        .map_err(|e| InstallerError::Partition(format!("Failed to run partprobe: {}", e)))?;

    if !output.status.success() {
        warn!(
            "partprobe warning: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Calculate root partition size when using separate home
fn calculate_root_size(home_size_mb: Option<u64>) -> u64 {
    // If home size is specified, use 30GB for root
    // Otherwise use 50GB as default root size
    if home_size_mb.is_some() {
        30 * 1024 // 30GB
    } else {
        50 * 1024 // 50GB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_path() {
        assert_eq!(
            partition_path(Path::new("/dev/sda"), 1),
            PathBuf::from("/dev/sda1")
        );
        assert_eq!(
            partition_path(Path::new("/dev/nvme0n1"), 1),
            PathBuf::from("/dev/nvme0n1p1")
        );
        assert_eq!(
            partition_path(Path::new("/dev/mmcblk0"), 1),
            PathBuf::from("/dev/mmcblk0p1")
        );
    }

    #[test]
    fn test_parse_mib() {
        assert_eq!(parse_mib("512MiB").unwrap(), 512);
        assert_eq!(parse_mib("1024MiB").unwrap(), 1024);
    }
}
