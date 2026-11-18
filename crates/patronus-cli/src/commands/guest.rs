//! `patronus guest`: the guest network from the command line (USE=guest).
//! Same code path as the web page and API (`patronus_network::guest`): every
//! change is validated as a whole, stored, audited, applied (guest network +
//! firewall) and undone if the apply fails.

use super::apply;
use crate::GuestCommands;
use patronus_config::{Applier, ConfigStore};
use patronus_network::guest::{self, GuestSvc};
use patronus_network::lan;
use patronus_network::svc::Svc;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Apply what a change needs; on failure put the store back as it was.
async fn change(store: &ConfigStore, what: &str, snap: Value) -> anyhow::Result<()> {
    let mut failure = None;
    if let Err(e) = guest::GuestApplier::default().apply(store).await {
        failure = Some(e.to_string());
    } else if let Err(e) = patronus_firewall::FirewallApplier.apply(store).await {
        failure = Some(e.to_string());
    }
    match failure {
        None => {
            let _ = store.audit("cli", "update", "lan", Some(what), &Value::Null).await;
            Ok(())
        }
        Some(msg) => {
            lan::restore_tables(store, &snap).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            anyhow::bail!("{what} failed and was undone: {msg}")
        }
    }
}

fn parse_pairs(pairs: &[String]) -> anyhow::Result<Value> {
    let mut m = serde_json::Map::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{p:?}: use key=value"))?;
        m.insert(k.trim().to_string(), json!(v));
    }
    Ok(Value::Object(m))
}

pub async fn run(action: GuestCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    let store = apply::open_store(db.as_deref()).await?;
    let mapped = |e: patronus_core::Error| anyhow::anyhow!("{e}");
    match action {
        GuestCommands::Show => {
            let v = GuestSvc.get(&store).await.map_err(mapped)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        GuestCommands::Status => {
            let v = guest::GuestApplier::default().status(&store).await.map_err(mapped)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        GuestCommands::Set { pairs } => {
            let body = parse_pairs(&pairs)?;
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            GuestSvc.put(&store, &body).await.map_err(mapped)?;
            change(&store, "guest settings", snap).await?;
            println!("guest network settings saved and applied");
        }
        GuestCommands::Enable | GuestCommands::Disable => {
            let on = matches!(action, GuestCommands::Enable);
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            GuestSvc.put(&store, &json!({"enabled": on})).await.map_err(mapped)?;
            change(&store, "guest network switch", snap).await?;
            println!("guest network {}", if on { "enabled" } else { "disabled" });
        }
        GuestCommands::Open { minutes } => {
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            let r = GuestSvc.action(&store, "open", &json!({"minutes": minutes})).await.map_err(mapped)?;
            change(&store, "guest open", snap).await?;
            println!("guest network open for {minutes} minutes (until {})", r["open_until"]);
        }
        GuestCommands::Close => {
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            GuestSvc.action(&store, "close", &Value::Null).await.map_err(mapped)?;
            change(&store, "guest close", snap).await?;
            println!("guest network closed (timed access)");
        }
        GuestCommands::NewPassword => {
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            let r = GuestSvc.action(&store, "new_password", &Value::Null).await.map_err(mapped)?;
            change(&store, "guest Wi-Fi password", snap).await?;
            println!("{}", r["wifi_password"].as_str().unwrap_or_default());
        }
        GuestCommands::Voucher { name, minutes } => {
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            let mut body = json!({"minutes": minutes});
            if let Some(n) = name {
                body["name"] = json!(n);
            }
            let r = GuestSvc.action(&store, "voucher", &body).await.map_err(mapped)?;
            change(&store, "guest voucher", snap).await?;
            println!("{}", r["wifi_password"].as_str().unwrap_or_default());
        }
        GuestCommands::Vouchers => {
            let now = chrono::Utc::now().timestamp();
            for v in guest::vouchers(&store).await.map_err(mapped)? {
                println!(
                    "{}\t{}\t{}",
                    v.id,
                    v.name,
                    match v.expires_at() {
                        None => "never expires".to_string(),
                        Some(e) if e > now => format!("{} min left", (e - now) / 60),
                        Some(_) => "expired".to_string(),
                    }
                );
            }
        }
        GuestCommands::VoucherDelete { id } => {
            let snap = lan::snapshot_tables(&store).await.map_err(mapped)?;
            GuestSvc.delete_row(&store, "vouchers", id).await.map_err(mapped)?;
            change(&store, "guest voucher delete", snap).await?;
            println!("voucher {id} deleted");
        }
    }
    Ok(())
}
