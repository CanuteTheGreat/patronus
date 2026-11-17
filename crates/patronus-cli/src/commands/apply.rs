//! `patronus apply`: bring the whole system in line with the config store.
//!
//! This is what the boot unit runs (`patronus-firewall.service` /
//! `/etc/init.d/patronus-firewall`). It
//! 1. opens (creating if needed) the store at `--db` / `$PATRONUS_DB` /
//!    `/var/lib/patronus/config.db`,
//! 2. on first boot assigns interface roles from `/etc/patronus/patronus.toml`
//!    and seeds the safe default ruleset (`patronus_config::defaults`),
//! 3. runs every registered [`Applier`] in dependency order:
//!    sysctl -> interfaces/VLANs -> routes/gateways -> firewall/NAT -> services.
//!
//! `patronus firewall apply` is the same with only the firewall phase.
//!
//! LANES: register your subsystem's applier in [`registry`] -- one line,
//! in the phase block it belongs to. That is the only shared line you
//! touch to get boot-time apply, `--dry-run` and `--phase` for free.

use colored::Colorize;
use patronus_config::applier::{Applier, ApplierRegistry, Phase};
use patronus_config::defaults::{self, Bootstrap};
use patronus_config::store::{self, ConfigStore};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Every applier this binary knows about.
pub fn registry() -> ApplierRegistry {
    let r = ApplierRegistry::new()
        // --- Phase::Sysctl (lane A) ---
        .with(patronus_network::SysctlApplier::default())
        // --- Phase::Interfaces (lane C: interfaces, VLANs, bonds, bridges) ---
        .with(patronus_network::InterfacesApplier::default())
        // --- Phase::Routes (lane E: static routes, gateways, groups) ---
        .with(patronus_network::RoutesApplier::default())
        // --- Phase::Firewall (lane B rules; lane A applier) ---
        .with(patronus_firewall::FirewallApplier)
        // --- Phase::Services (lanes D, F, G, J: dhcp, dns, vpn, ha, ids) ---
        // web accounts + RBAC groups (GitOps `User` / `Group`; rows only)
        .with(patronus_config::accounts::AccountsApplier)
        .with_all(patronus_network::lan::appliers())
        // --- lane F: WireGuard (interfaces phase), IPsec (services phase) ---
        .with_all(patronus_network::vpn_appliers());
    // device segmentation: parental time-limit sets, computed at boot before
    // the first forwarded packet (Phase::Firewall)
    #[cfg(feature = "segmentation")]
    let r = r.with(patronus_firewall::seg_time::SegTimeApplier);
    r
}

/// Options shared by `apply`, `firewall apply` and `config rollback`.
pub struct ApplyOptions {
    pub db: Option<PathBuf>,
    pub bootstrap: Option<PathBuf>,
    pub phases: Option<Vec<Phase>>,
    pub dry_run: bool,
}

/// Open the store. When run as root and the store's directory belongs to
/// the service user (as /var/lib/patronus does), hand the database file to
/// that user too, so patronus-web (which runs as `patronus`) can write the
/// store the boot unit created.
pub async fn open_store(db: Option<&Path>) -> anyhow::Result<ConfigStore> {
    let path = db.map(PathBuf::from).unwrap_or_else(store::default_db_path);
    let s = ConfigStore::open(&path)
        .await
        .map_err(|e| anyhow::anyhow!("config store {}: {e}", path.display()))?;
    hand_to_dir_owner(&path);
    Ok(s)
}

fn hand_to_dir_owner(path: &Path) {
    let Ok(me) = std::fs::metadata("/proc/self") else {
        return;
    };
    if me.uid() != 0 {
        return;
    }
    let Some(dir) = path.parent() else { return };
    let (Ok(d), Ok(f)) = (std::fs::metadata(dir), std::fs::metadata(path)) else {
        return;
    };
    if d.uid() != 0 && f.uid() == 0 {
        if let Err(e) = std::os::unix::fs::chown(path, Some(d.uid()), Some(d.gid())) {
            tracing::warn!(
                "could not chown {} to the service user: {e}",
                path.display()
            );
        }
    }
}

/// Assign roles / seed defaults (first boot), printing what happened.
pub async fn seed(store: &ConfigStore, bootstrap: Option<&Path>) -> anyhow::Result<()> {
    let path = bootstrap
        .map(PathBuf::from)
        .unwrap_or_else(defaults::default_bootstrap_path);
    let b = Bootstrap::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let rep = defaults::ensure_defaults(store, b.as_ref(), &defaults::existing_interfaces())
        .await
        .map_err(|e| anyhow::anyhow!("seeding defaults: {e}"))?;
    for (iface, role) in &rep.roles_assigned {
        println!(
            "{} interface {iface} -> {}",
            "•".cyan(),
            role.to_uppercase()
        );
    }
    if rep.defaults_seeded {
        println!(
            "{} first boot: seeded the default ruleset (anti-lockout, LAN->any, outbound NAT, ip_forward)",
            "•".cyan()
        );
    }
    for w in &rep.warnings {
        println!("{} {w}", "!".yellow());
    }
    if let Some(line) = super::firstboot::seed_lan(store, &path, b.as_ref()).await? {
        println!("{} first boot: {line}", "•".cyan());
    }
    Ok(())
}

/// The store cannot be opened at boot (unreadable, corrupt, disk gone):
/// nothing would be applied and the box would come up with no firewall.
/// Build the defaults from patronus.toml in memory and load the lockdown
/// ruleset from them (anti-lockout on the LAN only, nothing forwarded).
async fn emergency_lockdown(bootstrap: Option<&Path>) -> String {
    let scratch = match ConfigStore::open_in_memory().await {
        Ok(s) => s,
        Err(e) => return format!("no scratch store for the lockdown ruleset: {e}"),
    };
    if let Err(e) = seed(&scratch, bootstrap).await {
        println!("{} {e}", "!".yellow());
    }
    match patronus_firewall::FirewallApplier
        .load_lockdown(&scratch)
        .await
    {
        Ok(()) => "lockdown ruleset loaded: only anti-lockout access is allowed".into(),
        Err(e) => e.to_string(),
    }
}

pub async fn run(opts: ApplyOptions) -> anyhow::Result<()> {
    let store = match open_store(opts.db.as_deref()).await {
        Ok(s) => s,
        Err(e) => {
            let firewall_phase = opts
                .phases
                .as_ref()
                .is_none_or(|p| p.contains(&Phase::Firewall));
            if opts.dry_run || !firewall_phase {
                return Err(e);
            }
            let what = emergency_lockdown(opts.bootstrap.as_deref()).await;
            anyhow::bail!("{e} ({what})");
        }
    };
    let reg = registry();
    let phases = opts.phases.clone();

    // A commit-confirmed change whose deadline passed while the box was down
    // must not come back: put the previous generation in the store first.
    if !opts.dry_run {
        match patronus_config::generations::resolve_pending_at_boot(&store).await {
            Ok(patronus_config::generations::BootPending::Reverted(p)) => println!(
                "{} the change in generation {} was not confirmed before its deadline: booting generation {} again",
                "!".yellow(),
                p.generation,
                p.previous
            ),
            Ok(patronus_config::generations::BootPending::Resumed(p)) => println!(
                "{} generation {} is still on trial: {}s until it reverts unless confirmed",
                "•".cyan(),
                p.generation,
                p.seconds_left(chrono::Utc::now().timestamp())
            ),
            Ok(patronus_config::generations::BootPending::None) => {}
            Err(e) => println!("{} commit-confirm state: {e}", "!".yellow()),
        }
    }

    if opts.dry_run {
        // Seed a scratch copy, so a dry run never changes the real store.
        let scratch = ConfigStore::open_in_memory()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let doc = store
            .export_json()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        scratch
            .import_json(&doc)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        seed(&scratch, opts.bootstrap.as_deref()).await?;
        for a in reg.ordered() {
            if phases.as_ref().is_some_and(|p| !p.contains(&a.phase())) {
                continue;
            }
            println!("### {} ({})", a.name(), a.phase().as_str());
            print!(
                "{}",
                a.render(&scratch)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            );
        }
        return Ok(());
    }

    // A seeding failure (unwritable store, bad patronus.toml) must not stop
    // the appliers: the box would boot with no firewall at all.
    let seeded = seed(&store, opts.bootstrap.as_deref()).await;
    if let Err(e) = &seeded {
        println!("{} first-boot seeding failed: {e}", "✗".red());
    }
    let run = reg.apply_all(&store, phases.as_deref()).await;
    for o in &run.outcomes {
        match (&o.report, &o.error) {
            (Some(r), None) => {
                println!(
                    "{} {:<10} {}",
                    "✓".green(),
                    o.applier,
                    if r.applied.is_empty() {
                        "nothing to apply".to_string()
                    } else {
                        r.applied.join(", ")
                    }
                );
                for w in &r.warnings {
                    println!("  {} {w}", "!".yellow());
                }
            }
            (_, Some(e)) => println!("{} {:<10} {e}", "✗".red(), o.applier),
            _ => {}
        }
    }
    let _ = store
        .audit(
            "system",
            "apply",
            "config",
            None,
            &serde_json::to_value(&run).unwrap_or_default(),
        )
        .await;
    store.close().await;
    if !run.ok() {
        let names: Vec<&str> = run.failures().iter().map(|o| o.applier).collect();
        anyhow::bail!("apply failed for: {}", names.join(", "));
    }
    seeded
}

/// `patronus firewall flush`
pub async fn flush_firewall() -> anyhow::Result<()> {
    patronus_firewall::FirewallApplier
        .teardown()
        .await
        .map_err(|e| anyhow::anyhow!("failed to remove the Patronus nftables table: {e}"))
}

/// Parse `--phase` values.
pub fn parse_phases(v: &[String]) -> anyhow::Result<Option<Vec<Phase>>> {
    if v.is_empty() {
        return Ok(None);
    }
    v.iter()
        .map(|s| {
            Phase::parse(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown phase {s:?} (one of: {})",
                    Phase::ALL.map(|p| p.as_str()).join(", ")
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(Some)
}

/// `patronus config revisions` (the old name of `config generations`)
pub async fn list_revisions(db: Option<&Path>) -> anyhow::Result<()> {
    super::generations::list(db, false).await
}

/// `patronus config rollback <id> [--confirm-in N]`: restore a generation
/// and apply it. The rollback is a new generation itself.
pub async fn rollback(id: i64, opts: ApplyOptions, confirm_in: Option<i64>) -> anyhow::Result<()> {
    if confirm_in.is_some() {
        super::generations::require_watchdog().await?;
    }
    let store = open_store(opts.db.as_deref()).await?;
    let before = store
        .export_json()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let prev = store
        .snapshot_kind("cli", &format!("rollback to generation {id}"), "rollback")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    store
        .restore_generation(id, "cli")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    store.close().await;
    println!("{} restored generation {id}; applying", "•".cyan());
    let db = opts.db.clone();
    apply_or_revert(opts, before).await?;
    let store = open_store(db.as_deref()).await?;
    super::generations::arm(&store, prev, confirm_in).await?;
    store.close().await;
    Ok(())
}

/// Apply what was just written to the store. If it does not apply, put the
/// previous configuration back into the store and apply that, so the store
/// (what the next boot loads) never disagrees with what is enforced. Used
/// to leave the store holding the change while the kernel kept the old
/// ruleset -- and the next boot then failed into lockdown.
async fn apply_or_revert(opts: ApplyOptions, before: serde_json::Value) -> anyhow::Result<()> {
    let again = ApplyOptions {
        db: opts.db.clone(),
        bootstrap: opts.bootstrap.clone(),
        phases: opts.phases.clone(),
        dry_run: false,
    };
    let Err(e) = run(opts).await else {
        return Ok(());
    };
    let store = open_store(again.db.as_deref()).await?;
    store.import_json(&before).await.map_err(|e2| {
        anyhow::anyhow!("{e}; restoring the previous configuration failed too: {e2}")
    })?;
    store.close().await;
    println!(
        "{} the new configuration did not apply; restored the previous one",
        "!".yellow()
    );
    match run(again).await {
        Ok(()) => anyhow::bail!("{e} (the previous configuration was restored and re-applied)"),
        Err(e2) => anyhow::bail!("{e}; re-applying the previous configuration failed too: {e2}"),
    }
}

/// `patronus config export [-o FILE]`: the whole configuration as JSON
/// (a backup). Written 0600: later lanes keep secrets (VPN keys) here.
pub async fn export(db: Option<&Path>, output: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let doc = store
        .export_json()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    store.close().await;
    let text = serde_json::to_string_pretty(&doc)? + "\n";
    match output {
        None => print!("{text}"),
        Some(path) => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            eprintln!(
                "{} configuration exported to {}",
                "•".cyan(),
                path.display()
            );
        }
    }
    Ok(())
}

/// `patronus config import FILE [--dry-run] [--confirm-in N]`: replace the
/// configuration with a declarative file (or a JSON backup), after showing
/// the diff against the live configuration, and apply it (reverted if it
/// does not apply). It becomes a new generation; the configuration it
/// replaces stays one.
pub async fn import(
    file: &Path,
    apply: bool,
    dry_run: bool,
    confirm_in: Option<i64>,
    opts: ApplyOptions,
) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(file).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
    let store = open_store(opts.db.as_deref()).await?;
    let preview = patronus_config::genfile::prepare_import(&store, &text)
        .await
        .map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
    if dry_run || preview.identical {
        if preview.identical {
            println!("{} {} is identical to the live configuration", "•".cyan(), file.display());
        } else {
            let s = &preview.diff["summary"];
            println!(
                "{} row(s) added, {} removed, {} changed in {} table(s) (dry run, nothing written)",
                s["added"], s["removed"], s["changed"], s["tables"]
            );
            print!("{}", preview.text_diff);
        }
        return Ok(());
    }
    if confirm_in.is_some() {
        super::generations::require_watchdog().await?;
    }
    let before = store
        .export_json()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let prev = store
        .snapshot_kind("cli", &format!("import of {}", file.display()), "import")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    store
        .import_checked(&preview.doc)
        .await
        .map_err(|e| anyhow::anyhow!("{} was not imported: {e}", file.display()))?;
    println!("{} imported {}", "•".cyan(), file.display());
    if !apply {
        store.close().await;
        return Ok(());
    }
    store.close().await;
    let db = opts.db.clone();
    apply_or_revert(opts, before).await?;
    let store = open_store(db.as_deref()).await?;
    super::generations::arm(&store, prev, confirm_in).await?;
    store.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_in_boot_dependency_order() {
        let names: Vec<(&str, Phase)> = registry()
            .ordered()
            .iter()
            .map(|a| (a.name(), a.phase()))
            .collect();
        let phases: Vec<Phase> = names.iter().map(|(_, p)| *p).collect();
        let mut sorted = phases.clone();
        sorted.sort();
        assert_eq!(phases, sorted);
        assert_eq!(names.first().unwrap().0, "sysctl");
        assert!(names.iter().any(|(n, _)| *n == "firewall"));
        assert!(names
            .iter()
            .any(|(n, p)| *n == "interfaces" && *p == Phase::Interfaces));
        assert!(names
            .iter()
            .any(|(n, p)| *n == "routes" && *p == Phase::Routes));
    }

    #[test]
    fn phase_parsing() {
        assert_eq!(
            parse_phases(&["firewall".into()]).unwrap(),
            Some(vec![Phase::Firewall])
        );
        assert!(parse_phases(&["bogus".into()]).is_err());
        assert_eq!(parse_phases(&[]).unwrap(), None);
    }
}
