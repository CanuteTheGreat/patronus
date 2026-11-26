//! `patronus captive-portal ...`: the captive portal's sessions and vouchers
//! on the box (USE=captive-portal). Configuration is the web UI's feature
//! page `captive` (`/svc/captive`, `/api/svc/captive`) and the declarative
//! config; the sign-in pages and the session ticker run in patronus-web.

use std::path::PathBuf;

#[cfg(feature = "captive-portal")]
use sqlx::Row;

pub enum Action {
    Sessions { all: bool },
    Disconnect { id: i64 },
    Vouchers { roll: String },
}

#[cfg(not(feature = "captive-portal"))]
pub async fn run(_action: Action, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this build has no captive portal (USE=captive-portal)")
}

#[cfg(feature = "captive-portal")]
pub async fn run(action: Action, db: Option<PathBuf>) -> anyhow::Result<()> {
    let store = super::apply::open_store(db.as_deref()).await?;
    let pool = store.pool()?;
    match action {
        Action::Sessions { all } => {
            let sql = if all {
                "SELECT id, zone, ip, mac, username, method, started, expires, ended, end_reason \
                 FROM cp_sessions ORDER BY id"
            } else {
                "SELECT id, zone, ip, mac, username, method, started, expires, ended, end_reason \
                 FROM cp_sessions WHERE ended IS NULL ORDER BY id"
            };
            let rows = sqlx::query(sql).fetch_all(pool).await?;
            if rows.is_empty() {
                println!("no {}sessions", if all { "" } else { "active " });
            }
            let now = patronus_network::lan::now();
            for r in rows {
                let expires: i64 = r.get(7);
                let ended: Option<i64> = r.get(8);
                let state = match ended {
                    Some(_) => format!(
                        "ended ({})",
                        r.get::<Option<String>, _>(9).unwrap_or_default()
                    ),
                    None if expires > 0 => format!("active, {}s left", (expires - now).max(0)),
                    None => "active".to_string(),
                };
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    r.get::<i64, _>(0),
                    r.get::<String, _>(1),
                    r.get::<String, _>(2),
                    r.get::<String, _>(3),
                    r.get::<String, _>(5),
                    r.get::<String, _>(4),
                    state
                );
            }
        }
        Action::Disconnect { id } => {
            let n = patronus_network::captive::request_disconnect(&store, id).await?;
            if n == 0 {
                anyhow::bail!("no active session {id}");
            }
            println!("session {id}: disconnect requested (the portal ends it within seconds)");
        }
        Action::Vouchers { roll } => {
            let r = sqlx::query("SELECT id FROM cp_voucher_rolls WHERE name = ?")
                .bind(&roll)
                .fetch_optional(pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no voucher roll {roll:?}"))?;
            let id: i64 = r.get(0);
            for c in patronus_network::captive::roll_codes(&store, id).await? {
                println!("{c}");
            }
        }
    }
    Ok(())
}
