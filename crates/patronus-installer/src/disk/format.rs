//! Filesystem formatting module

use crate::config::Filesystem;
use crate::disk::partition::{CreatedPartition, PartitionFilesystem};
use crate::error::{InstallerError, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::{debug, info};

/// Format a partition with the specified filesystem
pub async fn format_partition(partition: &Path, fs: Filesystem, label: Option<&str>) -> Result<()> {
    info!("Formatting {} as {}", partition.display(), fs.as_str());

    let mut cmd = Command::new(fs.mkfs_command());

    // Add filesystem-specific options
    match fs {
        Filesystem::Zfs => {
            // ZFS pools are created with `zpool create`, not `mkfs.*`
            // against a single partition — see `disk::zfs::create_root_pool`,
            // which the caller (`create_partitions`/`install_base_system`)
            // must route to instead of `format_partition` whenever
            // `Filesystem::Zfs` is selected. Reaching this arm at all is a
            // caller bug, not a runtime condition to recover from.
            return Err(InstallerError::Filesystem(
                "ZFS pools are created via disk::zfs::create_root_pool, not format_partition"
                    .to_string(),
            ));
        }
        Filesystem::Ext4 => {
            cmd.arg("-F"); // Force
            if let Some(l) = label {
                cmd.args(["-L", l]);
            }
        }
        Filesystem::Btrfs => {
            cmd.arg("-f"); // Force
            if let Some(l) = label {
                cmd.args(["-L", l]);
            }
        }
        Filesystem::Xfs => {
            cmd.arg("-f"); // Force
            if let Some(l) = label {
                cmd.args(["-L", l]);
            }
        }
    }

    cmd.arg(partition);

    let output = cmd.output().await.map_err(|e| {
        InstallerError::Filesystem(format!("Failed to run {}: {}", fs.mkfs_command(), e))
    })?;

    if !output.status.success() {
        return Err(InstallerError::Filesystem(format!(
            "Failed to format {}: {}",
            partition.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    debug!("Successfully formatted {}", partition.display());
    Ok(())
}

/// Format a partition as FAT32 (for ESP)
pub async fn format_fat32(partition: &Path, label: Option<&str>) -> Result<()> {
    info!("Formatting {} as FAT32", partition.display());

    let mut cmd = Command::new("mkfs.fat");
    cmd.args(["-F", "32"]); // FAT32

    if let Some(l) = label {
        cmd.args(["-n", l]);
    }

    cmd.arg(partition);

    let output = cmd
        .output()
        .await
        .map_err(|e| InstallerError::Filesystem(format!("Failed to run mkfs.fat: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Filesystem(format!(
            "Failed to format FAT32: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    debug!("Successfully formatted {} as FAT32", partition.display());
    Ok(())
}

/// Format a partition as swap
pub async fn format_swap(partition: &Path, label: Option<&str>) -> Result<()> {
    info!("Formatting {} as swap", partition.display());

    let mut cmd = Command::new("mkswap");

    if let Some(l) = label {
        cmd.args(["-L", l]);
    }

    cmd.arg(partition);

    let output = cmd
        .output()
        .await
        .map_err(|e| InstallerError::Filesystem(format!("Failed to run mkswap: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Filesystem(format!(
            "Failed to format swap: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    debug!("Successfully formatted {} as swap", partition.display());
    Ok(())
}

/// Format all created partitions. `target_root` is where a ZFS root pool
/// gets its `mountpoint` property set to (see `disk::zfs::create_root_pool`)
/// — `zpool create -O mountpoint=...` mounts the pool immediately, so
/// `mount_partitions` must skip the ZFS root partition afterward instead
/// of trying to `mount` an already-mounted pool. Non-root ZFS is not
/// supported (the `PartitionScheme::UefiSeparateHome` home partition still
/// uses `root_fs` as its own filesystem — see `create_home_partition` —
/// so a `/home` on ZFS would need its own pool or a dataset under the
/// root pool; neither is wired up yet, so a separate-home ZFS install is
/// rejected below rather than silently formatting `/home` as ext4).
pub async fn format_all_partitions(
    partitions: &[CreatedPartition],
    target_root: &Path,
) -> Result<()> {
    info!("Formatting {} partition(s)", partitions.len());

    for partition in partitions {
        match &partition.filesystem {
            PartitionFilesystem::Fat32 => {
                format_fat32(&partition.path, Some("ESP")).await?;
            }
            PartitionFilesystem::Linux(Filesystem::Zfs) => {
                if partition.mount_point != "/" {
                    return Err(InstallerError::Filesystem(format!(
                        "ZFS is only supported for the root partition, not {}",
                        partition.mount_point
                    )));
                }
                crate::disk::zfs::create_root_pool(&partition.path, target_root).await?;
            }
            PartitionFilesystem::Linux(fs) => {
                let label = match partition.mount_point.as_str() {
                    "/" => Some("ROOT"),
                    "/home" => Some("HOME"),
                    _ => None,
                };
                format_partition(&partition.path, *fs, label).await?;
            }
            PartitionFilesystem::Swap => {
                format_swap(&partition.path, Some("SWAP")).await?;
            }
            PartitionFilesystem::None => {
                debug!("Skipping format for {}", partition.path.display());
            }
        }
    }

    Ok(())
}

/// Get filesystem UUID after formatting
pub async fn get_uuid(partition: &Path) -> Result<String> {
    let output = Command::new("blkid")
        .args(["-s", "UUID", "-o", "value"])
        .arg(partition)
        .output()
        .await
        .map_err(|e| InstallerError::Filesystem(format!("Failed to get UUID: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Filesystem(format!(
            "Failed to get UUID for {}: {}",
            partition.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uuid.is_empty() {
        return Err(InstallerError::Filesystem(format!(
            "Empty UUID for {}",
            partition.display()
        )));
    }

    Ok(uuid)
}

/// Get filesystem PARTUUID
pub async fn get_partuuid(partition: &Path) -> Result<String> {
    let output = Command::new("blkid")
        .args(["-s", "PARTUUID", "-o", "value"])
        .arg(partition)
        .output()
        .await
        .map_err(|e| InstallerError::Filesystem(format!("Failed to get PARTUUID: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Filesystem(format!(
            "Failed to get PARTUUID for {}: {}",
            partition.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let partuuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if partuuid.is_empty() {
        return Err(InstallerError::Filesystem(format!(
            "Empty PARTUUID for {}",
            partition.display()
        )));
    }

    Ok(partuuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mkfs_commands() {
        assert_eq!(Filesystem::Ext4.mkfs_command(), "mkfs.ext4");
        assert_eq!(Filesystem::Btrfs.mkfs_command(), "mkfs.btrfs");
        assert_eq!(Filesystem::Xfs.mkfs_command(), "mkfs.xfs");
    }
}
