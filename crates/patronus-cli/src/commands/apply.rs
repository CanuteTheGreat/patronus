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
    ApplierRegistry::new()
        // --- Phase::Sysctl (lane A) ---
        .with(patronus_network::SysctlApplier::default())
        // --- Phase::Interfaces (lane C: interfaces, VLANs, bonds, bridges) ---
        // --- Phase::Routes (lane E: static routes, gateways, groups) ---
        // --- Phase::Firewall (lane B rules; lane A applier) ---
        .with(patronus_firewall::FirewallApplier)
    // --- Phase::Services (lanes D, F, G, J: dhcp, dns, vpn, ha, ids) ---
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
    Ok(())
}

pub async fn run(opts: ApplyOptions) -> anyhow::Result<()> {
    let store = open_store(opts.db.as_deref()).await?;
    let reg = registry();
    let phases = opts.phases.clone();

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

    seed(&store, opts.bootstrap.as_deref()).await?;
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
    Ok(())
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

/// `patronus config revisions`
pub async fn list_revisions(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    for (id, at, user, summary) in store
        .list_revisions()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        let when = chrono::DateTime::from_timestamp(at, 0)
            .map(|t| t.to_rfc3339())
            .unwrap_or_default();
        println!("{id:>5}  {when}  {user:<10} {summary}");
    }
    Ok(())
}

/// `patronus config rollback <id>`: restore a revision and apply it.
pub async fn rollback(id: i64, opts: ApplyOptions) -> anyhow::Result<()> {
    let store = open_store(opts.db.as_deref()).await?;
    store
        .restore_revision(id, "cli")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    store.close().await;
    println!("{} restored revision {id}; applying", "•".cyan());
    run(opts).await
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
