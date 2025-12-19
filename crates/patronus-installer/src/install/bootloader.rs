//! Bootloader installation module

use crate::config::{Bootloader, PartitionScheme};
use crate::disk::partition::CreatedPartition;
use crate::error::{InstallerError, Result};
use crate::install::system::run_in_chroot;
use std::path::Path;
use tokio::fs;
use tokio::process::Command;
use tracing::{info, warn};

/// Install bootloader to the target system
pub async fn install_bootloader(
    target: &Path,
    bootloader: Bootloader,
    scheme: &PartitionScheme,
    disk: &Path,
    partitions: &[CreatedPartition],
) -> Result<()> {
    info!("Installing bootloader: {:?}", bootloader);

    match bootloader {
        Bootloader::Grub => {
            install_grub(target, scheme, disk, partitions).await?;
        }
        Bootloader::SystemdBoot => {
            if !scheme.is_uefi() {
                return Err(InstallerError::Bootloader(
                    "systemd-boot requires UEFI".to_string(),
                ));
            }
            install_systemd_boot(target, partitions).await?;
        }
    }

    Ok(())
}

/// Install GRUB bootloader
async fn install_grub(
    target: &Path,
    scheme: &PartitionScheme,
    disk: &Path,
    partitions: &[CreatedPartition],
) -> Result<()> {
    info!("Installing GRUB to {}", disk.display());

    if scheme.is_uefi() {
        // UEFI installation
        install_grub_uefi(target, partitions).await?;
    } else {
        // BIOS installation
        install_grub_bios(target, disk).await?;
    }

    // Generate GRUB configuration
    generate_grub_config(target).await?;

    Ok(())
}

/// Install GRUB for UEFI systems
async fn install_grub_uefi(target: &Path, partitions: &[CreatedPartition]) -> Result<()> {
    info!("Installing GRUB for UEFI");

    // Find ESP partition
    let esp = partitions
        .iter()
        .find(|p| p.mount_point == "/boot/efi")
        .ok_or_else(|| InstallerError::Bootloader("ESP partition not found".to_string()))?;

    // Mount ESP if not already mounted
    let esp_mount = target.join("boot/efi");
    if !esp_mount.exists() {
        fs::create_dir_all(&esp_mount).await?;
    }

    // Check if ESP is mounted
    let mounts = fs::read_to_string("/proc/mounts").await.unwrap_or_default();
    if !mounts.contains(&esp_mount.to_string_lossy().to_string()) {
        let output = Command::new("mount")
            .arg(&esp.path)
            .arg(&esp_mount)
            .output()
            .await
            .map_err(|e| InstallerError::Bootloader(format!("Failed to mount ESP: {}", e)))?;

        if !output.status.success() {
            return Err(InstallerError::Bootloader(format!(
                "Failed to mount ESP: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    // Install GRUB EFI
    run_in_chroot(
        target,
        &[
            "grub-install",
            "--target=x86_64-efi",
            "--efi-directory=/boot/efi",
            "--bootloader-id=PATRONUS",
            "--recheck",
        ],
    )
    .await?;

    Ok(())
}

/// Install GRUB for BIOS systems
async fn install_grub_bios(target: &Path, disk: &Path) -> Result<()> {
    info!("Installing GRUB for BIOS to {}", disk.display());

    let disk_str = disk.to_string_lossy();

    run_in_chroot(
        target,
        &[
            "grub-install",
            "--target=i386-pc",
            "--recheck",
            &disk_str,
        ],
    )
    .await?;

    Ok(())
}

/// Generate GRUB configuration
async fn generate_grub_config(target: &Path) -> Result<()> {
    info!("Generating GRUB configuration");

    // Create /etc/default/grub if it doesn't exist
    let grub_default = target.join("etc/default/grub");
    if !grub_default.exists() {
        let content = r#"# GRUB configuration
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="Patronus"
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX=""
GRUB_PRELOAD_MODULES="part_gpt part_msdos"
GRUB_TERMINAL_OUTPUT="console"
GRUB_GFXMODE="auto"
GRUB_GFXPAYLOAD_LINUX="keep"
"#;
        fs::write(&grub_default, content).await?;
    }

    // Generate grub.cfg
    run_in_chroot(target, &["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]).await?;

    Ok(())
}

/// Install systemd-boot
async fn install_systemd_boot(target: &Path, partitions: &[CreatedPartition]) -> Result<()> {
    info!("Installing systemd-boot");

    // Find ESP partition
    let esp = partitions
        .iter()
        .find(|p| p.mount_point == "/boot/efi")
        .ok_or_else(|| InstallerError::Bootloader("ESP partition not found".to_string()))?;

    // Mount ESP if needed
    let esp_mount = target.join("boot/efi");
    if !esp_mount.exists() {
        fs::create_dir_all(&esp_mount).await?;
    }

    // Check if ESP is mounted
    let mounts = fs::read_to_string("/proc/mounts").await.unwrap_or_default();
    if !mounts.contains(&esp_mount.to_string_lossy().to_string()) {
        let output = Command::new("mount")
            .arg(&esp.path)
            .arg(&esp_mount)
            .output()
            .await
            .map_err(|e| InstallerError::Bootloader(format!("Failed to mount ESP: {}", e)))?;

        if !output.status.success() {
            return Err(InstallerError::Bootloader(format!(
                "Failed to mount ESP: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    // Install systemd-boot
    run_in_chroot(target, &["bootctl", "--esp-path=/boot/efi", "install"]).await?;

    // Find root partition
    let root = partitions
        .iter()
        .find(|p| p.mount_point == "/")
        .ok_or_else(|| InstallerError::Bootloader("Root partition not found".to_string()))?;

    // Get root UUID
    let root_uuid = crate::disk::format::get_partuuid(&root.path).await?;

    // Create loader configuration
    let loader_conf = target.join("boot/efi/loader/loader.conf");
    fs::create_dir_all(loader_conf.parent().unwrap()).await?;
    let loader_content = r#"default patronus.conf
timeout 5
console-mode keep
editor no
"#;
    fs::write(&loader_conf, loader_content).await?;

    // Create boot entry
    let entries_dir = target.join("boot/efi/loader/entries");
    fs::create_dir_all(&entries_dir).await?;

    // Find kernel version (look for vmlinuz)
    let kernel_version = find_kernel_version(target).await?;

    let entry_content = format!(
        r#"title   Patronus
linux   /vmlinuz-{}
initrd  /initramfs-{}.img
options root=PARTUUID={} rw quiet
"#,
        kernel_version, kernel_version, root_uuid
    );

    let entry_path = entries_dir.join("patronus.conf");
    fs::write(&entry_path, entry_content).await?;

    // Copy kernel and initramfs to ESP
    copy_kernel_to_esp(target, &kernel_version).await?;

    Ok(())
}

/// Find kernel version from installed kernel
async fn find_kernel_version(target: &Path) -> Result<String> {
    let boot_dir = target.join("boot");

    // Look for vmlinuz-* files
    let mut entries = fs::read_dir(&boot_dir)
        .await
        .map_err(|e| InstallerError::Bootloader(format!("Failed to read /boot: {}", e)))?;

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.starts_with("vmlinuz-") || name_str.starts_with("kernel-") {
            let version = name_str
                .strip_prefix("vmlinuz-")
                .or_else(|| name_str.strip_prefix("kernel-"))
                .unwrap_or("gentoo");
            return Ok(version.to_string());
        }
    }

    // Default fallback
    Ok("gentoo".to_string())
}

/// Copy kernel and initramfs to ESP for systemd-boot
async fn copy_kernel_to_esp(target: &Path, version: &str) -> Result<()> {
    let boot_dir = target.join("boot");
    let esp_dir = target.join("boot/efi");

    // Copy vmlinuz
    let kernel_src = boot_dir.join(format!("vmlinuz-{}", version));
    let kernel_alt = boot_dir.join(format!("kernel-{}", version));
    let kernel_dst = esp_dir.join(format!("vmlinuz-{}", version));

    if kernel_src.exists() {
        fs::copy(&kernel_src, &kernel_dst).await?;
    } else if kernel_alt.exists() {
        fs::copy(&kernel_alt, &kernel_dst).await?;
    } else {
        warn!("Kernel not found, boot may fail");
    }

    // Copy initramfs
    let initrd_src = boot_dir.join(format!("initramfs-{}.img", version));
    let initrd_alt = boot_dir.join(format!("initrd-{}", version));
    let initrd_dst = esp_dir.join(format!("initramfs-{}.img", version));

    if initrd_src.exists() {
        fs::copy(&initrd_src, &initrd_dst).await?;
    } else if initrd_alt.exists() {
        fs::copy(&initrd_alt, &initrd_dst).await?;
    } else {
        warn!("Initramfs not found, boot may fail");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootloader_description() {
        assert!(Bootloader::Grub.description().contains("GRUB"));
        assert!(Bootloader::SystemdBoot.description().contains("systemd"));
    }
}
