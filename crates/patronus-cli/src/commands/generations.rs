//! `patronus config generations|show|diff|pin|confirm|revert-now|pending`
//! and the declarative export (`config export --declarative`).
//!
//! Rollback and import (apply.rs) share the commit-confirmed handling here.

use super::apply::{open_store, registry};
use colored::Colorize;
use patronus_config::generations::{Generation, Pending};
use patronus_config::store::ConfigStore;
use patronus_config::{gendiff, genfile};
use std::path::Path;

fn ts(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn e(err: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{err}")
}

fn markers(g: &Generation) -> String {
    let mut m = Vec::new();
    if g.live {
        m.push("live");
    }
    if g.boot {
        m.push("boot");
    }
    if g.pinned {
        m.push("pinned");
    }
    m.join(",")
}

/// `patronus config generations [--json]`
pub async fn list(db: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let gens = store.generations().await.map_err(e)?;
    let pending = store.pending().await.map_err(e)?;
    let drift = store.has_unrecorded_changes().await.map_err(e)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "generations": gens, "pending": pending, "unrecorded_changes": drift,
            }))?
        );
        return Ok(());
    }
    let (id, time, actor, kind, marks, msg) = ("ID", "TIME", "ACTOR", "KIND", "MARKERS", "MESSAGE");
    println!("{id:>5}  {time:<19}  {actor:<12} {kind:<9} {marks:<14} {msg}");
    for g in &gens {
        let line = format!(
            "{:>5}  {:<19}  {:<12} {:<9} {:<14} {}",
            g.id,
            ts(g.created_at),
            g.actor,
            g.kind,
            markers(g),
            g.message
        );
        if g.live {
            println!("{}", line.bold());
        } else {
            println!("{line}");
        }
    }
    if gens.is_empty() {
        println!("(no generations yet: the first change creates one)");
    }
    if drift && !gens.is_empty() {
        println!(
            "{} the live configuration differs from generation {}: something wrote the store outside a change set (the next change records it)",
            "!".yellow(),
            gens[0].id
        );
    }
    if let Some(p) = pending {
        print_pending(&p);
    }
    Ok(())
}

fn print_pending(p: &Pending) {
    let left = p.seconds_left(chrono::Utc::now().timestamp());
    println!(
        "{} generation {} is applied on trial: it reverts to generation {} in {}m{:02}s unless `patronus config confirm` runs",
        "!".yellow(),
        p.generation,
        p.previous,
        left / 60,
        left % 60
    );
}

/// `patronus config show ID [--json]`: metadata and the declarative file.
pub async fn show(
    db: Option<&Path>,
    id: i64,
    json: bool,
    include_secrets: bool,
) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let g = store
        .generation(id)
        .await
        .map_err(e)?
        .ok_or_else(|| anyhow::anyhow!("generation {id} not found"))?;
    let doc = store
        .generation_json(id)
        .await
        .map_err(e)?
        .ok_or_else(|| anyhow::anyhow!("generation {id} not found"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }
    println!(
        "# generation {} ({})  {}  by {}  [{}]\n# {}\n# sha256 {}",
        g.id,
        g.kind,
        ts(g.created_at),
        g.actor,
        markers(&g),
        g.message,
        g.hash
    );
    let keys = store.table_keys().await.map_err(e)?;
    print!(
        "{}",
        genfile::to_yaml(&doc, &keys, include_secrets).map_err(e)?
    );
    Ok(())
}

/// `patronus config diff [FROM] [TO]`: generation ids or `live`. One
/// argument compares it with live; none compares live with the generation
/// before it.
pub async fn diff(
    db: Option<&Path>,
    from: Option<String>,
    to: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let (from, to) = match (from, to) {
        (Some(a), Some(b)) => (a, b),
        (Some(a), None) => (a, "live".to_string()),
        (None, _) => {
            let gens = store.generations().await.map_err(e)?;
            let prev = gens
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("fewer than two generations: nothing to compare"))?;
            (prev.id.to_string(), "live".to_string())
        }
    };
    let a = store.document(&from).await.map_err(e)?;
    let b = store.document(&to).await.map_err(e)?;
    let keys = store.table_keys().await.map_err(e)?;
    let d = gendiff::diff_docs(&a, &b, &keys);
    let text = gendiff::unified_diff(
        &genfile::to_yaml(&a, &keys, false).map_err(e)?,
        &genfile::to_yaml(&b, &keys, false).map_err(e)?,
        &format!("generation {from}"),
        &format!("generation {to}"),
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "from": from, "to": to, "diff": d, "text": text,
            }))?
        );
        return Ok(());
    }
    if d["identical"] == true {
        println!("generation {from} and {to} are identical");
        return Ok(());
    }
    let s = &d["summary"];
    println!(
        "{} row(s) added, {} removed, {} changed in {} table(s)  (secrets show as (changed), never as values)",
        s["added"], s["removed"], s["changed"], s["tables"]
    );
    print!("{text}");
    Ok(())
}

/// `patronus config pin ID [--unpin]`
pub async fn pin(db: Option<&Path>, id: i64, unpin: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    store.pin_generation(id, !unpin).await.map_err(e)?;
    println!(
        "generation {id} {}",
        if unpin {
            "unpinned"
        } else {
            "pinned (retention never removes it)"
        }
    );
    Ok(())
}

/// `patronus config pending`
pub async fn pending(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    match store.pending().await.map_err(e)? {
        Some(p) => print_pending(&p),
        None => {
            println!("no change is waiting for confirmation");
            if let Some(v) = store.last_revert().await.map_err(e)? {
                println!("last automatic revert: {v}");
            }
        }
    }
    Ok(())
}

/// `patronus config confirm`
pub async fn confirm(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    match store.confirm_pending("cli").await.map_err(e)? {
        Some(p) => println!(
            "{} generation {} confirmed: it is the boot default now",
            "✓".green(),
            p.generation
        ),
        None => println!("nothing is waiting for confirmation"),
    }
    Ok(())
}

/// `patronus config revert-now`: go back to the generation before the
/// pending change now, without waiting for the deadline.
pub async fn revert_now(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let Some(p) = store.pending().await.map_err(e)? else {
        println!(
            "nothing is waiting for confirmation: nothing to revert (use `config rollback ID`)"
        );
        return Ok(());
    };
    let reg = registry();
    let store_ref = &store;
    let res =
        patronus_config::generations::revert_now(&store, "cli", "reverted by hand", || async {
            let run = reg.apply_all(store_ref, None).await;
            if run.ok() {
                Ok(())
            } else {
                let names: Vec<&str> = run.failures().iter().map(|o| o.applier).collect();
                Err(format!("apply failed for: {}", names.join(", ")))
            }
        })
        .await
        .map_err(e)?;
    println!(
        "{} reverted to generation {} (recorded as generation {})",
        "✓".green(),
        p.previous,
        res.map(|n| n.to_string()).unwrap_or_default()
    );
    Ok(())
}

/// A commit-confirm needs something independent to enforce the deadline.
pub async fn require_watchdog() -> anyhow::Result<()> {
    let sock = patronus_network::applyd::socket_path();
    if patronus_network::applyd::watchdog_alive(&sock).await {
        return Ok(());
    }
    anyhow::bail!(
        "--confirm-in needs `patronus applyd` running ({}): it enforces the deadline, so nothing was changed",
        sock.display()
    )
}

/// After an applied change: arm the auto-revert when asked.
pub async fn arm(
    store: &ConfigStore,
    previous: i64,
    confirm_in: Option<i64>,
) -> anyhow::Result<()> {
    store.seal().await.map_err(e)?;
    let Some(n) = confirm_in else { return Ok(()) };
    match store.start_pending(previous, n, "cli").await.map_err(e)? {
        Some(p) => {
            println!(
                "{} applied on trial: reverts to generation {} in {n} minute(s) unless you run `patronus config confirm`",
                "!".yellow(),
                p.previous
            );
        }
        None => println!("the change left the configuration as it was: nothing to confirm"),
    }
    Ok(())
}

/// `patronus config export --declarative [--include-secrets] [-o FILE]`
pub async fn export_declarative(
    db: Option<&Path>,
    output: Option<&Path>,
    include_secrets: bool,
) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let doc = store.export_json().await.map_err(e)?;
    let keys = store.table_keys().await.map_err(e)?;
    store.close().await;
    let text = genfile::to_yaml(&doc, &keys, include_secrets).map_err(e)?;
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
                .map_err(|x| anyhow::anyhow!("{}: {x}", path.display()))?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            eprintln!(
                "{} declarative configuration ({}) written to {}",
                "•".cyan(),
                if include_secrets {
                    "with secrets, mode 0600"
                } else {
                    "secrets excluded"
                },
                path.display()
            );
        }
    }
    Ok(())
}
