//! `patronus users`: the web UI accounts in the config store (lane H).
//! Mainly the way back in when an admin lost the phone with the second
//! factor: `patronus users reset-2fa admin` on the box (as root). A lost
//! admin password is reset with `PATRONUS_ADMIN_PASSWORD` (re-applied at
//! every patronus-web start while set).

use super::apply::open_store;
use sqlx::Row;
use std::path::Path;

pub async fn list(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let rows = sqlx::query(
        "SELECT username, role, enabled, totp_secret IS NOT NULL FROM web_users ORDER BY id",
    )
    .fetch_all(store.pool().map_err(|e| anyhow::anyhow!("{e}"))?)
    .await?;
    if rows.is_empty() {
        println!("no web accounts yet (patronus-web creates admin at its first start)");
    }
    for r in rows {
        println!(
            "{:<24} {:<9} {:<9} 2fa {}",
            r.get::<String, _>(0),
            r.get::<String, _>(1),
            if r.get::<i64, _>(2) != 0 {
                "enabled"
            } else {
                "disabled"
            },
            if r.get::<bool, _>(3) { "on" } else { "off" }
        );
    }
    Ok(())
}

/// `patronus users hash-password`: the argon2 hash of the password on stdin,
/// for `password_hash:` in a GitOps `User` resource (the password itself
/// never goes into the repository).
pub fn hash_password() -> anyhow::Result<()> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\n', '\r']);
    if pw.len() < 8 {
        anyhow::bail!("the password must have at least 8 characters");
    }
    println!("{}", patronus_secrets::crypto::hash_password(pw)?);
    Ok(())
}

pub async fn reset_2fa(db: Option<&Path>, name: &str) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let r = sqlx::query(
        "UPDATE web_users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL,
            recovery_codes = NULL, updated_at = ? WHERE username = ?",
    )
    .bind(chrono::Utc::now().timestamp())
    .bind(name.trim().to_ascii_lowercase())
    .execute(store.pool().map_err(|e| anyhow::anyhow!("{e}"))?)
    .await?;
    if r.rows_affected() == 0 {
        anyhow::bail!("no web account {name:?} (see `patronus users list`)");
    }
    let _ = store
        .audit(
            "cli",
            "update",
            "user",
            Some(name),
            &serde_json::json!({"two_factor": "reset"}),
        )
        .await;
    println!(
        "two-factor login turned off for {name}; it can log in with its password and enrol again"
    );
    Ok(())
}
