//! Base system installation module

use crate::config::{InstallConfig, UserConfig};
use crate::disk::partition::CreatedPartition;
use crate::error::{InstallerError, Result};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(f32, &str) + Send + Sync>;

/// Mount all partitions for installation
pub async fn mount_partitions(
    partitions: &[CreatedPartition],
    target_root: &Path,
) -> Result<()> {
    info!("Mounting partitions to {}", target_root.display());

    // Create target root directory
    fs::create_dir_all(target_root)
        .await
        .map_err(|e| InstallerError::Mount(format!("Failed to create mount point: {}", e)))?;

    // Sort partitions by mount point depth (root first, then others)
    let mut sorted: Vec<_> = partitions
        .iter()
        .filter(|p| !p.mount_point.is_empty() && p.mount_point != "swap")
        .collect();

    sorted.sort_by(|a, b| {
        let depth_a = a.mount_point.matches('/').count();
        let depth_b = b.mount_point.matches('/').count();
        depth_a.cmp(&depth_b)
    });

    // Mount each partition
    for partition in sorted {
        let mount_point = if partition.mount_point == "/" {
            target_root.to_path_buf()
        } else {
            target_root.join(partition.mount_point.trim_start_matches('/'))
        };

        // Create mount point
        fs::create_dir_all(&mount_point)
            .await
            .map_err(|e| InstallerError::Mount(format!("Failed to create {}: {}", mount_point.display(), e)))?;

        // Mount
        let output = Command::new("mount")
            .arg(&partition.path)
            .arg(&mount_point)
            .output()
            .await
            .map_err(|e| InstallerError::Mount(format!("Failed to run mount: {}", e)))?;

        if !output.status.success() {
            return Err(InstallerError::Mount(format!(
                "Failed to mount {} to {}: {}",
                partition.path.display(),
                mount_point.display(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        info!("Mounted {} to {}", partition.path.display(), mount_point.display());
    }

    // Enable swap
    for partition in partitions.iter().filter(|p| p.mount_point == "swap") {
        let output = Command::new("swapon")
            .arg(&partition.path)
            .output()
            .await
            .map_err(|e| InstallerError::Mount(format!("Failed to enable swap: {}", e)))?;

        if !output.status.success() {
            warn!(
                "Failed to enable swap {}: {}",
                partition.path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            info!("Enabled swap {}", partition.path.display());
        }
    }

    Ok(())
}

/// Unmount all partitions after installation
pub async fn unmount_partitions(
    partitions: &[CreatedPartition],
    target_root: &Path,
) -> Result<()> {
    info!("Unmounting partitions from {}", target_root.display());

    // Disable swap first
    for partition in partitions.iter().filter(|p| p.mount_point == "swap") {
        let _ = Command::new("swapoff")
            .arg(&partition.path)
            .output()
            .await;
    }

    // Sort partitions by mount point depth (deepest first)
    let mut sorted: Vec<_> = partitions
        .iter()
        .filter(|p| !p.mount_point.is_empty() && p.mount_point != "swap")
        .collect();

    sorted.sort_by(|a, b| {
        let depth_a = a.mount_point.matches('/').count();
        let depth_b = b.mount_point.matches('/').count();
        depth_b.cmp(&depth_a) // Reverse order
    });

    // Unmount each partition
    for partition in sorted {
        let mount_point = if partition.mount_point == "/" {
            target_root.to_path_buf()
        } else {
            target_root.join(partition.mount_point.trim_start_matches('/'))
        };

        let output = Command::new("umount")
            .arg(&mount_point)
            .output()
            .await
            .map_err(|e| InstallerError::Mount(format!("Failed to run umount: {}", e)))?;

        if !output.status.success() {
            warn!(
                "Failed to unmount {}: {}",
                mount_point.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            debug!("Unmounted {}", mount_point.display());
        }
    }

    Ok(())
}

/// Install base system from LiveCD
pub async fn install_base_system(
    config: &InstallConfig,
    progress: Option<&ProgressCallback>,
) -> Result<()> {
    let target = &config.target_root;
    info!("Installing base system to {}", target.display());

    if let Some(cb) = progress {
        cb(0.0, "Starting base system installation...");
    }

    // Check if we're on a LiveCD with squashfs
    let squashfs_path = PathBuf::from("/mnt/cdrom/image.squashfs");
    let alt_squashfs = PathBuf::from("/run/initramfs/live/image.squashfs");

    if squashfs_path.exists() {
        install_from_squashfs(&squashfs_path, target, progress).await?;
    } else if alt_squashfs.exists() {
        install_from_squashfs(&alt_squashfs, target, progress).await?;
    } else {
        // Fallback: rsync from live environment
        install_via_rsync(target, progress).await?;
    }

    if let Some(cb) = progress {
        cb(70.0, "Base system installed");
    }

    // Create essential directories
    create_essential_directories(target).await?;

    if let Some(cb) = progress {
        cb(75.0, "Created essential directories");
    }

    Ok(())
}

/// Install from squashfs image
async fn install_from_squashfs(
    squashfs: &Path,
    target: &Path,
    progress: Option<&ProgressCallback>,
) -> Result<()> {
    info!("Installing from squashfs: {}", squashfs.display());

    if let Some(cb) = progress {
        cb(5.0, "Extracting system image...");
    }

    // Mount squashfs
    let squash_mount = PathBuf::from("/tmp/squash_mount");
    fs::create_dir_all(&squash_mount).await?;

    let output = Command::new("mount")
        .args(["-o", "loop"])
        .arg(squashfs)
        .arg(&squash_mount)
        .output()
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to mount squashfs: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Install(format!(
            "Failed to mount squashfs: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    if let Some(cb) = progress {
        cb(10.0, "Copying system files...");
    }

    // rsync from mounted squashfs
    let output = Command::new("rsync")
        .args([
            "-aAXH",
            "--info=progress2",
            "--exclude=/dev/*",
            "--exclude=/proc/*",
            "--exclude=/sys/*",
            "--exclude=/tmp/*",
            "--exclude=/run/*",
            "--exclude=/mnt/*",
            "--exclude=/media/*",
            "--exclude=/lost+found",
        ])
        .arg(format!("{}/", squash_mount.display()))
        .arg(format!("{}/", target.display()))
        .output()
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to run rsync: {}", e)))?;

    // Unmount squashfs
    let _ = Command::new("umount").arg(&squash_mount).output().await;

    if !output.status.success() {
        return Err(InstallerError::Install(format!(
            "Failed to copy system: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Install via rsync from running system
async fn install_via_rsync(
    target: &Path,
    progress: Option<&ProgressCallback>,
) -> Result<()> {
    info!("Installing via rsync from live system");

    if let Some(cb) = progress {
        cb(5.0, "Copying system files via rsync...");
    }

    let output = Command::new("rsync")
        .args([
            "-aAXH",
            "--info=progress2",
            "--exclude=/dev/*",
            "--exclude=/proc/*",
            "--exclude=/sys/*",
            "--exclude=/tmp/*",
            "--exclude=/run/*",
            "--exclude=/mnt/*",
            "--exclude=/media/*",
            "--exclude=/lost+found",
            "--exclude=/var/tmp/*",
            "--exclude=/var/cache/*",
        ])
        .arg("/")
        .arg(format!("{}/", target.display()))
        .output()
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to run rsync: {}", e)))?;

    if !output.status.success() {
        return Err(InstallerError::Install(format!(
            "Failed to copy system: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Create essential system directories
async fn create_essential_directories(target: &Path) -> Result<()> {
    let dirs = [
        "dev", "proc", "sys", "tmp", "run", "mnt", "media",
        "var/tmp", "var/cache", "var/log", "var/lib",
        "boot/efi",
    ];

    for dir in &dirs {
        let path = target.join(dir);
        fs::create_dir_all(&path)
            .await
            .map_err(|e| InstallerError::Install(format!("Failed to create {}: {}", path.display(), e)))?;
    }

    // Set correct permissions for /tmp
    let tmp = target.join("tmp");
    fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o1777))
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to set /tmp permissions: {}", e)))?;

    Ok(())
}

/// Configure the installed system
pub async fn configure_system(
    config: &InstallConfig,
    partitions: &[CreatedPartition],
    progress: Option<&ProgressCallback>,
) -> Result<()> {
    let target = &config.target_root;
    info!("Configuring installed system");

    if let Some(cb) = progress {
        cb(80.0, "Configuring system...");
    }

    // Generate fstab
    generate_fstab(target, partitions).await?;

    // Set hostname
    set_hostname(target, &config.system.hostname).await?;

    // Set timezone
    set_timezone(target, &config.system.timezone).await?;

    // Set locale
    set_locale(target, &config.system.locale).await?;

    // Set keyboard layout
    set_keyboard(target, &config.system.keyboard).await?;

    if let Some(cb) = progress {
        cb(85.0, "Creating users...");
    }

    // Create users
    for user in &config.users {
        create_user(target, user).await?;
    }

    if let Some(cb) = progress {
        cb(90.0, "System configured");
    }

    Ok(())
}

/// Generate /etc/fstab
async fn generate_fstab(target: &Path, partitions: &[CreatedPartition]) -> Result<()> {
    info!("Generating fstab");

    let mut fstab = String::from("# /etc/fstab - generated by patronus-install\n");
    fstab.push_str("# <file system>  <mount point>  <type>  <options>  <dump>  <pass>\n\n");

    for partition in partitions {
        // Get UUID
        let uuid = crate::disk::format::get_uuid(&partition.path).await?;

        let (fs_type, options, dump, pass) = match &partition.filesystem {
            crate::disk::partition::PartitionFilesystem::Fat32 => {
                ("vfat", "umask=0077", "0", "2")
            }
            crate::disk::partition::PartitionFilesystem::Linux(fs) => {
                let opts = if partition.mount_point == "/" {
                    "defaults"
                } else {
                    "defaults"
                };
                let pass = if partition.mount_point == "/" { "1" } else { "2" };
                (fs.as_str(), opts, "0", pass)
            }
            crate::disk::partition::PartitionFilesystem::Swap => {
                ("swap", "defaults", "0", "0")
            }
            crate::disk::partition::PartitionFilesystem::None => continue,
        };

        let mount = if partition.mount_point == "swap" {
            "none"
        } else {
            &partition.mount_point
        };

        fstab.push_str(&format!(
            "UUID={}  {}  {}  {}  {}  {}\n",
            uuid, mount, fs_type, options, dump, pass
        ));
    }

    // Write fstab
    let fstab_path = target.join("etc/fstab");
    fs::write(&fstab_path, fstab)
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to write fstab: {}", e)))?;

    Ok(())
}

/// Set system hostname
async fn set_hostname(target: &Path, hostname: &str) -> Result<()> {
    let hostname_path = target.join("etc/hostname");
    fs::write(&hostname_path, format!("{}\n", hostname))
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to write hostname: {}", e)))?;

    // Update /etc/hosts
    let hosts_path = target.join("etc/hosts");
    let hosts = format!(
        "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n127.0.1.1\t{} {}.localdomain\n",
        hostname, hostname
    );
    fs::write(&hosts_path, hosts)
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to write hosts: {}", e)))?;

    Ok(())
}

/// Set system timezone
async fn set_timezone(target: &Path, timezone: &str) -> Result<()> {
    let localtime_path = target.join("etc/localtime");
    let zoneinfo_path = format!("/usr/share/zoneinfo/{}", timezone);

    // Remove existing symlink
    let _ = fs::remove_file(&localtime_path).await;

    // Create symlink
    tokio::fs::symlink(&zoneinfo_path, &localtime_path)
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to set timezone: {}", e)))?;

    // Write timezone file
    let timezone_path = target.join("etc/timezone");
    fs::write(&timezone_path, format!("{}\n", timezone))
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to write timezone: {}", e)))?;

    Ok(())
}

/// Set system locale
async fn set_locale(target: &Path, locale: &str) -> Result<()> {
    // Generate locale.gen
    let locale_gen = target.join("etc/locale.gen");
    if locale_gen.exists() {
        let content = fs::read_to_string(&locale_gen).await.unwrap_or_default();
        let new_content = content.replace(&format!("# {}", locale), locale);
        fs::write(&locale_gen, new_content).await?;
    }

    // Write locale.conf
    let locale_conf = target.join("etc/locale.conf");
    fs::write(&locale_conf, format!("LANG={}\n", locale))
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to write locale.conf: {}", e)))?;

    // Run locale-gen in chroot (if available)
    let _ = run_in_chroot(target, &["locale-gen"]).await;

    Ok(())
}

/// Set keyboard layout
async fn set_keyboard(target: &Path, layout: &str) -> Result<()> {
    // For systemd
    let vconsole = target.join("etc/vconsole.conf");
    fs::write(&vconsole, format!("KEYMAP={}\n", layout))
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to write vconsole.conf: {}", e)))?;

    Ok(())
}

/// Create a user account
async fn create_user(target: &Path, user: &UserConfig) -> Result<()> {
    info!("Creating user: {}", user.username);

    // Create user in chroot
    let mut args = vec![
        "-m".to_string(),
        "-s".to_string(),
        user.shell.clone(),
    ];

    if !user.full_name.is_empty() {
        args.push("-c".to_string());
        args.push(user.full_name.clone());
    }

    if !user.groups.is_empty() {
        args.push("-G".to_string());
        args.push(user.groups.join(","));
    }

    args.push(user.username.clone());

    let args_ref: Vec<&str> = std::iter::once("useradd")
        .chain(args.iter().map(|s| s.as_str()))
        .collect();

    run_in_chroot(target, &args_ref).await?;

    // Set password
    if let Some(ref password) = user.password {
        set_user_password(target, &user.username, password).await?;
    } else if let Some(ref hash) = user.password_hash {
        set_user_password_hash(target, &user.username, hash).await?;
    }

    // Add to sudoers if sudo enabled
    if user.sudo {
        let sudoers_dir = target.join("etc/sudoers.d");
        fs::create_dir_all(&sudoers_dir).await?;

        let sudoers_file = sudoers_dir.join(&user.username);
        fs::write(&sudoers_file, format!("{} ALL=(ALL:ALL) ALL\n", user.username))
            .await
            .map_err(|e| InstallerError::User(format!("Failed to write sudoers: {}", e)))?;

        // Set permissions (mode 440)
        fs::set_permissions(&sudoers_file, std::fs::Permissions::from_mode(0o440)).await?;
    }

    Ok(())
}

/// Set user password (plaintext, will be hashed)
async fn set_user_password(target: &Path, username: &str, password: &str) -> Result<()> {
    // Use chpasswd in chroot
    let input = format!("{}:{}", username, password);

    // Create a temporary script to run chpasswd
    let script = format!("echo '{}' | chpasswd", input);
    run_in_chroot(target, &["sh", "-c", &script]).await
}

/// Set user password from hash
async fn set_user_password_hash(target: &Path, username: &str, hash: &str) -> Result<()> {
    // Use usermod in chroot
    run_in_chroot(target, &["usermod", "-p", hash, username]).await
}

/// Run a command in chroot
pub async fn run_in_chroot(target: &Path, args: &[&str]) -> Result<()> {
    // First, bind mount essential filesystems
    mount_for_chroot(target).await?;

    let output = Command::new("chroot")
        .arg(target)
        .args(args)
        .output()
        .await
        .map_err(|e| InstallerError::Install(format!("Failed to run chroot: {}", e)))?;

    if !output.status.success() {
        warn!(
            "chroot command failed: {} - {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Mount filesystems for chroot
async fn mount_for_chroot(target: &Path) -> Result<()> {
    // Bind mount /dev
    let dev = target.join("dev");
    let _ = Command::new("mount")
        .args(["--bind", "/dev"])
        .arg(&dev)
        .output()
        .await;

    // Mount /proc
    let proc = target.join("proc");
    let _ = Command::new("mount")
        .args(["-t", "proc", "proc"])
        .arg(&proc)
        .output()
        .await;

    // Mount /sys
    let sys = target.join("sys");
    let _ = Command::new("mount")
        .args(["--bind", "/sys"])
        .arg(&sys)
        .output()
        .await;

    // Bind mount /run
    let run = target.join("run");
    let _ = Command::new("mount")
        .args(["--bind", "/run"])
        .arg(&run)
        .output()
        .await;

    Ok(())
}

use std::os::unix::fs::PermissionsExt;
