//! Bootloader installation module

use crate::config::{Bootloader, Filesystem, PartitionScheme};
use crate::disk::partition::{CreatedPartition, PartitionFilesystem};
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
    let root_is_zfs = partitions
        .iter()
        .any(|p| matches!(p.filesystem, PartitionFilesystem::Linux(Filesystem::Zfs)));
    generate_grub_config(target, root_is_zfs).await?;

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

    // grub-install's --target and the UEFI-spec removable-media fallback
    // filename are both architecture-specific (x86_64-efi/BOOTX64.EFI vs.
    // arm64-efi/BOOTAA64.EFI) - this used to be hardcoded to the x86_64
    // names, which silently produced an unbootable (wrong-arch) ESP on
    // any non-x86_64 target, including the aarch64 guest this installer
    // now also runs on in the nightly CI VM test.
    #[cfg(target_arch = "aarch64")]
    let (grub_target, grub_binary, fallback_name) = ("arm64-efi", "grubaa64.efi", "BOOTAA64.EFI");
    #[cfg(target_arch = "x86_64")]
    let (grub_target, grub_binary, fallback_name) = ("x86_64-efi", "grubx64.efi", "BOOTX64.EFI");
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("install_grub_uefi: unsupported target_arch, add its grub-install target/fallback filename here");

    // Install GRUB EFI
    run_in_chroot(
        target,
        &[
            "grub-install",
            &format!("--target={grub_target}"),
            "--efi-directory=/boot/efi",
            "--bootloader-id=PATRONUS",
            "--recheck",
        ],
    )
    .await?;

    // Some firmware (notably QEMU/OVMF in CI/test VMs, and some real
    // hardware with a flaky/reset NVRAM) never gets the efibootmgr NVRAM
    // entry grub-install just tried to register, and only ever looks at
    // the UEFI-spec-mandated removable-media fallback path. Without this
    // a perfectly good install can still fail to boot on first power-on.
    // Harmless no-op copy when the NVRAM entry worked fine too.
    let fallback_dir = target.join("boot/efi/EFI/BOOT");
    fs::create_dir_all(&fallback_dir).await.ok();
    let _ = run_in_chroot(
        target,
        &[
            "sh",
            "-c",
            &format!(
                "cp -f /boot/efi/EFI/PATRONUS/{grub_binary} /boot/efi/EFI/BOOT/{fallback_name}"
            ),
        ],
    )
    .await;

    Ok(())
}

/// Install GRUB for BIOS systems
async fn install_grub_bios(target: &Path, disk: &Path) -> Result<()> {
    info!("Installing GRUB for BIOS to {}", disk.display());

    let disk_str = disk.to_string_lossy();

    run_in_chroot(
        target,
        &["grub-install", "--target=i386-pc", "--recheck", &disk_str],
    )
    .await?;

    Ok(())
}

/// `/etc/default/grub` content with the kernel and GRUB itself on the serial
/// console (ttyS0, 115200 8N1) in addition to the VGA console. Idempotent.
fn with_serial_console(content: &str) -> String {
    let mut out: String = content
        .lines()
        .filter(|l| {
            let l = l.trim_start();
            !(l.starts_with("GRUB_CMDLINE_LINUX=")
                || l.starts_with("GRUB_TERMINAL=")
                || l.starts_with("GRUB_TERMINAL_OUTPUT=")
                || l.starts_with("GRUB_SERIAL_COMMAND="))
        })
        .collect::<Vec<_>>()
        .join("\n");
    out.push_str(
        "\nGRUB_CMDLINE_LINUX=\"console=tty0 console=ttyS0,115200n8\"\n\
         GRUB_TERMINAL=\"console serial\"\n\
         GRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200\"\n",
    );
    out
}

/// Generate GRUB configuration
async fn generate_grub_config(target: &Path, root_is_zfs: bool) -> Result<()> {
    info!("Generating GRUB configuration");

    // Create /etc/default/grub if it doesn't exist
    let grub_default = target.join("etc/default/grub");
    if !grub_default.exists() {
        let preload_modules = if root_is_zfs {
            // GRUB needs its own `zfs` module to read a root pool's
            // /boot before the real kernel/zfs.ko take over — without
            // this in GRUB_PRELOAD_MODULES, `grub-mkconfig`'s bundled
            // `10_linux_zfs` script (part of zfsutils-linux's grub
            // integration, ships alongside `zfs-mount.service`) still
            // finds the pool, but the resulting grub.cfg can fail to
            // actually boot if grub-install didn't embed zfs support.
            "part_gpt part_msdos zfs"
        } else {
            "part_gpt part_msdos"
        };
        let content = format!(
            r#"# GRUB configuration
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="Patronus"
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX=""
GRUB_PRELOAD_MODULES="{preload_modules}"
GRUB_TERMINAL_OUTPUT="console"
GRUB_GFXMODE="auto"
GRUB_GFXPAYLOAD_LINUX="keep"
"#
        );
        fs::write(&grub_default, content).await?;
    }

    // Keep the serial console the installer itself was booted with (QEMU/KVM
    // test VMs, headless boxes): without it the installed system boots with
    // no output on ttyS0 and cannot be driven. The file may already exist
    // (shipped in the live image), so patch it either way.
    let serial = std::fs::read_to_string("/proc/cmdline")
        .map(|c| c.contains("console=ttyS0"))
        .unwrap_or(false);
    if serial {
        let current = fs::read_to_string(&grub_default).await.unwrap_or_default();
        fs::write(&grub_default, with_serial_console(&current)).await?;
        // login prompt on the serial console (init script ships in the live image)
        let _ = run_in_chroot(
            target,
            &[
                "sh",
                "-c",
                "[ -x /etc/init.d/live-serial ] && rc-update add live-serial default",
            ],
        )
        .await;
    }

    // Let udev publish the new partitions' UUID links so grub-mkconfig can
    // write root=UUID=... (a /dev/vdaN or /dev/sdXN name can change between
    // boots when USB media or another disk is present).
    let _ = tokio::process::Command::new("udevadm")
        .args(["settle", "--timeout=10"])
        .output()
        .await;

    // Generate grub.cfg
    run_in_chroot(target, &["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]).await?;

    // Belt and braces: turn any remaining root=/dev/... into root=UUID=...
    let _ = run_in_chroot(
        target,
        &[
            "sh",
            "-c",
            "for d in $(grep -o 'root=/dev/[A-Za-z0-9/_-]*' /boot/grub/grub.cfg | sort -u | cut -d= -f2); do \
             u=$(blkid -s UUID -o value $d); [ -n \"$u\" ] && sed -i \"s#root=$d#root=UUID=$u#g\" /boot/grub/grub.cfg; done; true",
        ],
    )
    .await;

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
    fn serial_console_replaces_existing_keys_and_is_idempotent() {
        let orig = "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=\"quiet\"\n#GRUB_TERMINAL=console\nGRUB_TERMINAL=console\n";
        let once = with_serial_console(orig);
        assert!(once.contains("GRUB_TIMEOUT=5"));
        assert!(once.contains("console=ttyS0,115200n8"));
        assert!(!once.contains("GRUB_CMDLINE_LINUX=\"quiet\""));
        assert!(once.contains("#GRUB_TERMINAL=console"), "comments are kept");
        assert_eq!(once.matches("GRUB_TERMINAL=").count(), 1 + 1); // comment + ours
        assert_eq!(with_serial_console(&once), once);
    }

    #[test]
    fn test_bootloader_description() {
        assert!(Bootloader::Grub.description().contains("GRUB"));
        assert!(Bootloader::SystemdBoot.description().contains("systemd"));
    }
}
