//! `patronus firewall apply|flush`
//!
//! `apply` is `patronus apply --phase firewall`: it loads every filter and
//! NAT rule from the config store and loads them as one atomic nftables
//! transaction (it used to build an empty in-memory `RuleManager`, so the
//! boot unit always applied a ruleset with no user rules at all).
//! `flush` removes the Patronus table.

use crate::FirewallCommands;
use colored::Colorize;
use patronus_config::applier::Phase;
use std::path::PathBuf;

use super::apply::{self, ApplyOptions};

pub async fn handle_firewall_command(
    action: FirewallCommands,
    db: Option<PathBuf>,
) -> anyhow::Result<()> {
    match action {
        FirewallCommands::Apply { bootstrap, dry_run } => {
            apply::run(ApplyOptions {
                db,
                bootstrap,
                phases: Some(vec![Phase::Firewall]),
                dry_run,
            })
            .await
        }
        FirewallCommands::Flush => {
            apply::flush_firewall().await?;
            println!("{} Firewall rules flushed", "✓".green());
            Ok(())
        }
        FirewallCommands::Log { lines, follow } => log(db, lines, follow).await,
    }
}

/// One stored firewall log line (table `firewall_log`, written by the web UI's NFLOG collector).
fn log_line(r: &sqlx::sqlite::SqliteRow) -> String {
    use sqlx::Row;
    let ts: i64 = r.get("ts");
    let when = chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_string());
    let port = |p: Option<i64>| p.map(|p| format!(":{p}")).unwrap_or_default();
    let (src, dst): (String, String) = (r.get("src"), r.get("dst"));
    let src = if src.contains(':') && r.get::<Option<i64>, _>("sport").is_some() {
        format!("[{src}]")
    } else {
        src
    };
    let dst = if dst.contains(':') && r.get::<Option<i64>, _>("dport").is_some() {
        format!("[{dst}]")
    } else {
        dst
    };
    let iface_in: String = r.get("iface_in");
    let iface_out: String = r.get("iface_out");
    let ifaces = match (iface_in.is_empty(), iface_out.is_empty()) {
        (false, false) => format!("{iface_in}->{iface_out}"),
        (false, true) => iface_in,
        (true, false) => format!("->{iface_out}"),
        _ => "-".into(),
    };
    format!(
        "{when} {:<6} {:<8} {:<10} {:<5} {}{} -> {}{}  ({})",
        r.get::<String, _>("action"),
        r.get::<String, _>("chain"),
        ifaces,
        r.get::<String, _>("proto"),
        src,
        port(r.get("sport")),
        dst,
        port(r.get("dport")),
        r.get::<String, _>("rule"),
    )
}

/// `patronus firewall log [-n N] [--follow]`: the newest lines of the firewall log (the same lines
/// as the web UI's log viewer), oldest first; `--follow` keeps printing new ones (Ctrl+C ends).
pub async fn log(db: Option<PathBuf>, lines: i64, follow: bool) -> anyhow::Result<()> {
    let store = apply::open_store(db.as_deref()).await?;
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = sqlx::query(
        "SELECT * FROM (SELECT * FROM firewall_log ORDER BY id DESC LIMIT ?) ORDER BY id",
    )
    .bind(lines.max(0))
    .fetch_all(pool)
    .await?;
    use sqlx::Row;
    let mut last: i64 = 0;
    if rows.is_empty() {
        println!(
            "(no firewall log lines yet: rules log when their Log option is on; the web UI collects them)"
        );
    }
    for r in &rows {
        println!("{}", log_line(r));
        last = r.get("id");
    }
    if !follow {
        return Ok(());
    }
    if last == 0 {
        last = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM firewall_log")
            .fetch_one(pool)
            .await?;
    }
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
        }
        let rows = sqlx::query("SELECT * FROM firewall_log WHERE id > ? ORDER BY id LIMIT 1000")
            .bind(last)
            .fetch_all(pool)
            .await?;
        for r in &rows {
            println!("{}", log_line(r));
            last = r.get("id");
        }
    }
}
