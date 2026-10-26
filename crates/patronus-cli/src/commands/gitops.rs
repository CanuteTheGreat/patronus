//! `patronus gitops sync|watch`: the shipped GitOps watcher.
//!
//! Reads the `[gitops]` section of /etc/patronus/patronus.toml (or
//! `--bootstrap`/$PATRONUS_BOOTSTRAP), clones the repository into
//! `local_path` and applies its declarative resources through the same
//! appliers `patronus apply` runs ([`super::apply::registry`]), so a rule
//! committed to the repository ends up in the config store, in
//! `nft list ruleset`, and survives a reboot (`patronus apply` at boot).
//! `watch` is what the `patronus-gitops` service runs (USE=gitops).

use anyhow::Context;
use colored::Colorize;
use patronus_config::ApplyEngine;
use patronus_gitops::{GitOpsConfig, GitOpsWatcher, GitSyncEvent};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Where the engine keeps the resources it last applied from git (used to
/// tell which ones a commit removed).
pub const STATE_DIR: &str = "/var/lib/patronus/gitops/state";

#[derive(serde::Deserialize, Default)]
struct File {
    #[serde(default)]
    gitops: Option<GitOpsConfig>,
}

/// `[gitops]` from patronus.toml; `None` when the section is missing.
pub fn load_config(path: &Path) -> anyhow::Result<Option<GitOpsConfig>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let f: File = toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(f.gitops)
}

pub struct Options {
    pub db: Option<PathBuf>,
    pub bootstrap: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    /// Override `repo_url` (testing a repository before writing it to the file)
    pub repo: Option<String>,
}

async fn watcher(opts: &Options) -> anyhow::Result<GitOpsWatcher> {
    let path = opts
        .bootstrap
        .clone()
        .unwrap_or_else(patronus_config::defaults::default_bootstrap_path);
    let mut cfg = load_config(&path)?.unwrap_or_default();
    if let Some(r) = &opts.repo {
        cfg.repo_url = r.clone();
    }
    if cfg.repo_url.trim().is_empty() {
        anyhow::bail!(
            "GitOps is not configured: add a [gitops] section with repo_url to {} (or pass --repo)",
            path.display()
        );
    }
    let store = super::apply::open_store(opts.db.as_deref()).await?;
    let state = opts
        .state_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(STATE_DIR));
    let mut engine = ApplyEngine::new(state).with_target(Arc::new(store), super::apply::registry());
    engine
        .init()
        .await
        .map_err(|e| anyhow::anyhow!("gitops state: {e}"))?;
    let mut w = GitOpsWatcher::new(cfg, Arc::new(RwLock::new(engine)));
    w.init().await?;
    Ok(w)
}

fn print_event(ev: &GitSyncEvent, applying: bool) {
    let short = &ev.commit_hash[..ev.commit_hash.len().min(12)];
    println!(
        "{} commit {short} \"{}\" by {}: {} resource(s) in {} file(s)",
        "•".cyan(),
        ev.commit_message,
        ev.author,
        ev.configs_found,
        ev.files_changed.len()
    );
    match (&ev.error, ev.applied) {
        (Some(e), _) => println!("{} {e}", "✗".red()),
        (None, true) => println!("{} applied ({} change(s))", "✓".green(), ev.changes_applied),
        (None, false) if !applying => println!(
            "{} validated, not applied (auto_apply off; `patronus gitops sync --apply` applies)",
            "•".yellow()
        ),
        (None, false) => {}
    }
}

/// One pass. `apply`: Some(true) = --apply, Some(false) = --dry-run,
/// None = the file's auto_apply.
pub async fn sync(opts: Options, apply: Option<bool>) -> anyhow::Result<()> {
    let mut w = watcher(&opts).await?;
    let applying = apply.unwrap_or(w.config().auto_apply);
    let r = w.sync_with(applying).await?;
    match r.event {
        Some(ev) => {
            print_event(&ev, applying);
            if let Some(e) = ev.error {
                anyhow::bail!("gitops sync failed: {e}");
            }
        }
        None => println!("{} nothing new", "•".cyan()),
    }
    if applying {
        refresh_feeds(opts.db.as_deref(), true).await;
    }
    Ok(())
}

/// URL-table / GeoIP / threat-feed aliases that a repository declared start
/// empty: fetch whatever is due (everything new is) and load the result.
/// patronus-web does the same every minute when it runs; this covers boxes
/// that only run the `patronus-gitops` service.
async fn refresh_feeds(db: Option<&std::path::Path>, announce: bool) {
    let store = match super::apply::open_store(db).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("alias refresh: {e}");
            return;
        }
    };
    let now = chrono::Utc::now().timestamp();
    let out = match patronus_firewall::feeds::refresh_due(
        &store,
        &patronus_firewall::feeds::CurlFetcher,
        None,
        now,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("alias refresh: {e}");
            return;
        }
    };
    for o in &out {
        if announce || !o.ok {
            println!(
                "{} alias {}: {}",
                if o.ok { "✓".green() } else { "✗".red() },
                o.alias,
                o.status
            );
        }
    }
    if out.iter().any(|o| o.changed.is_some()) {
        use patronus_config::Applier;
        if let Err(e) = patronus_firewall::FirewallApplier.apply(&store).await {
            tracing::warn!("loading the refreshed aliases: {e}");
        }
    }
}

/// Poll forever (the `patronus-gitops` service).
pub async fn watch(opts: Options) -> anyhow::Result<()> {
    let mut w = watcher(&opts).await?;
    let db = opts.db.clone();
    // (a thread driving the future: the store's futures are not Send)
    let rt = tokio::runtime::Handle::current();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        rt.block_on(refresh_feeds(db.as_deref(), false));
    });
    w.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitops_section_is_read_from_patronus_toml_next_to_the_other_sections() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("patronus.toml");
        std::fs::write(
            &p,
            "[network]\nwan_interface = \"eth0\"\n\n[gitops]\nrepo_url = \"https://git.example.test/fw.git\"\nconfig_path = \"firewall\"\nauto_apply = true\n",
        )
        .unwrap();
        let c = load_config(&p).unwrap().unwrap();
        assert_eq!(c.repo_url, "https://git.example.test/fw.git");
        assert_eq!(c.branch, "main");
        assert!(c.auto_apply);
        assert_eq!(c.poll_interval_secs, 60);
        std::fs::write(&p, "[network]\nwan_interface = \"eth0\"\n").unwrap();
        assert!(load_config(&p).unwrap().is_none());
        assert!(load_config(&d.path().join("missing.toml"))
            .unwrap()
            .is_none());
    }
}
