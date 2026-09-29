//! Root-on-ZFS support.
//!
//! ZFS doesn't fit the partition -> mkfs -> fstab model every other
//! `Filesystem` variant uses (`disk::format::format_partition`,
//! `install::system::generate_fstab`): there's no per-partition mkfs
//! step (a pool spans one or more whole block devices), and mounting
//! is `zpool import` + dataset `canmount`/`mountpoint` properties, not
//! a UUID line in fstab. This module is the ZFS-specific parallel path
//! those two call into instead of `mkfs`/fstab-generation when
//! `Filesystem::Zfs` is selected — same reasoning and `zpool`/`zfs`
//! CLI-driving approach as horcrux's `nas::storage::pools::create_zfs_pool`.

use crate::error::{InstallerError, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

/// Fixed pool name for the root pool — patronus is a single-appliance
/// installer (one target disk), not a multi-pool NAS like horcrux, so a
/// hardcoded name matching the OS convention (Proxmox, Ubuntu's own ZFS
/// installer) avoids needing to prompt for one.
pub const ROOT_POOL_NAME: &str = "rpool";

/// Create the root pool on `disk` (a whole block device, e.g. `/dev/sda`
/// — no partition, ZFS uses the disk directly) and a `ROOT` dataset
/// mounted at `mount_point` (normally the installer's `target_root`).
/// Same `ashift=12`/`compression=lz4`/`atime=off` defaults as horcrux's
/// `create_zfs_pool`, since both exist for the same "sane, modern
/// defaults for a fresh pool" reason.
pub async fn create_root_pool(disk: &Path, mount_point: &Path) -> Result<()> {
    info!(
        "Creating ZFS root pool {} on {}",
        ROOT_POOL_NAME,
        disk.display()
    );

    let output = Command::new("zpool")
        .args(["create", "-f"])
        .args(["-o", "ashift=12"])
        .args(["-O", "compression=lz4"])
        .args(["-O", "atime=off"])
        .args(["-O", "xattr=sa"])
        .args(["-O", &format!("mountpoint={}", mount_point.display())])
        .arg(ROOT_POOL_NAME)
        .arg(disk)
        .output()
        .await
        .map_err(|e| InstallerError::Filesystem(format!("zpool create failed: {e}")))?;

    if !output.status.success() {
        return Err(InstallerError::Filesystem(format!(
            "zpool create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Whether this install environment can actually create a ZFS pool —
/// same check `Filesystem::preferred()` uses, exposed separately so
/// call sites that already have a concrete `Filesystem::Zfs` selection
/// (e.g. re-entering a saved/scripted config) can still fail with a
/// clear error instead of a confusing `zpool: command not found`.
pub async fn zfs_tooling_available() -> bool {
    let has = |cmd: &'static str| async move {
        Command::new("which")
            .arg(cmd)
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    has("zpool").await && has("zfs").await
}

/// Import the root pool inside the target chroot before running any
/// `run_in_chroot` step, and export it again afterward — mirrors what
/// `mount_partitions`/`unmount_partitions` do for regular filesystems,
/// since ZFS pools aren't just bind-mounted the way a formatted
/// partition is.
pub async fn import_root_pool(_target: &Path) -> Result<()> {
    let output = Command::new("zpool")
        .args(["import", "-f", "-R"])
        .arg("/")
        .arg(ROOT_POOL_NAME)
        .output()
        .await
        .map_err(|e| InstallerError::Mount(format!("zpool import failed: {e}")))?;

    if !output.status.success() {
        return Err(InstallerError::Mount(format!(
            "zpool import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Export the root pool — must run before the installer's own process
/// exits/reboots the target, or the new system will refuse to import
/// it (a pool can't be imported twice at once).
pub async fn export_root_pool() -> Result<()> {
    let output = Command::new("zpool")
        .args(["export", ROOT_POOL_NAME])
        .output()
        .await
        .map_err(|e| InstallerError::Mount(format!("zpool export failed: {e}")))?;

    if !output.status.success() {
        return Err(InstallerError::Mount(format!(
            "zpool export failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}
