//! `patronus guard`: brute-force protection on the box (docs/BRUTE-FORCE.md).
//! Works without the web UI: `status` lists the active bans and the settings, `ban` /
//! `unban` change the store and sync the kernel table at once (a running engine sees
//! the change too, the store is the source of truth), `set KEY=VALUE ...` changes
//! settings (`enabled=1`, `max_failures=3`, `allowlist=198.51.100.0/24,2001:db8::/32`).

use super::apply::open_store;
use patronus_firewall::guard;
use std::path::Path;

pub async fn status(db: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let s = guard::load(&store).await?;
    let now = guard::now();
    let bans = guard::active_bans(&store, now).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "settings": s, "active": bans, "kernel": guard::live_state(),
            }))?
        );
        return Ok(());
    }
    println!(
        "brute-force protection: {}  ({} failures in {} -> ban {}, longest {}, sources {})",
        if s.enabled { "on" } else { "off" },
        s.max_failures,
        guard::human_secs(s.find_secs),
        guard::human_secs(s.ban_secs),
        guard::human_secs(s.ban_max_secs),
        s.sources.join(",")
    );
    if bans.is_empty() {
        println!("no active bans");
    }
    for b in bans {
        let left = b
            .expires_at
            .map(|e| guard::human_secs((e - now).max(0) as u64))
            .unwrap_or_else(|| "until lifted".into());
        println!(
            "{:<40} {:<9} {:<14} {}",
            b.address, b.source, left, b.reason
        );
    }
    Ok(())
}

async fn sync(store: &patronus_config::ConfigStore) -> anyhow::Result<()> {
    let s = guard::load(store).await?;
    if let Err(e) = guard::sync(store, &s).await {
        // not root / no nft: the running engine applies it within its next round
        eprintln!("note: kernel table not updated here ({e}); the engine applies it shortly");
    }
    Ok(())
}

pub async fn ban(
    db: Option<&Path>,
    addr: &str,
    secs: Option<u64>,
    reason: &str,
) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let key = guard::manual_ban(&store, addr, secs, reason).await?;
    sync(&store).await?;
    println!("banned {key}");
    Ok(())
}

pub async fn unban(db: Option<&Path>, addr: &str) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let n = guard::unban(&store, addr, "cli").await?;
    sync(&store).await?;
    println!("lifted {n} ban(s) for {addr}");
    Ok(())
}

pub async fn set(db: Option<&Path>, pairs: &[String]) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let mut m = serde_json::Map::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE, got {p:?}"))?;
        let k = k.trim().trim_start_matches("guard.");
        let v = v.trim();
        let val = match k {
            "enabled" | "escalate" | "exempt_lan" => {
                serde_json::Value::Bool(matches!(v, "1" | "true" | "yes" | "on"))
            }
            "sources" | "allowlist" | "log_files" | "log_tags" => serde_json::Value::Array(
                v.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(|x| serde_json::Value::String(x.into()))
                    .collect(),
            ),
            "journal" | "openvpn_log" => serde_json::Value::String(v.into()),
            _ => serde_json::Value::Number(
                v.parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("{k}: a number expected, got {v:?}"))?
                    .into(),
            ),
        };
        m.insert(k.to_string(), val);
    }
    let i: guard::SettingsIn = serde_json::from_value(serde_json::Value::Object(m))
        .map_err(|e| anyhow::anyhow!("unknown setting: {e}"))?;
    guard::save(&store, &i).await?;
    sync(&store).await?;
    status(db, false).await
}
