//! Remote and encrypted automatic configuration backups.
//!
//! The export of the config store (`ConfigStore::export_json`) is
//! uploaded to every enabled target on its schedule (and on demand). With a
//! passphrase the file is encrypted first: `PBK1` + 16-byte salt +
//! AES-256-GCM(nonce || ciphertext) under an Argon2id key, so the remote
//! never sees accounts, keys or VPN secrets. The upload itself is `curl -T`
//! (http/https PUT, sftp, ftps); credentials go to curl on stdin, never on
//! the command line.

use patronus_config::ConfigStore;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub fn encrypt(plain: &[u8], passphrase: &str) -> anyhow::Result<Vec<u8>> {
    patronus_secrets::crypto::seal_with_passphrase(plain, passphrase)
}

pub fn is_encrypted(bytes: &[u8]) -> bool {
    patronus_secrets::crypto::is_sealed(bytes)
}

pub fn decrypt(bytes: &[u8], passphrase: &str) -> anyhow::Result<Vec<u8>> {
    patronus_secrets::crypto::open_with_passphrase(bytes, passphrase)
}

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub username: String,
    pub has_password: bool,
    pub encrypted: bool,
    pub interval_hours: i64,
    pub insecure_tls: bool,
    pub enabled: bool,
    pub last_run: Option<i64>,
    pub last_status: Option<String>,
    pub last_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TargetInput {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// non-empty = encrypt the backups with it
    #[serde(default)]
    pub passphrase: String,
    #[serde(default = "day")]
    pub interval_hours: i64,
    #[serde(default)]
    pub insecure_tls: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn day() -> i64 {
    24
}
fn yes() -> bool {
    true
}

fn validate(t: &TargetInput) -> anyhow::Result<()> {
    if t.name.trim().is_empty() || t.name.len() > 64 {
        anyhow::bail!("Invalid target name");
    }
    let ok = ["http://", "https://", "sftp://", "ftps://"]
        .iter()
        .any(|p| t.url.starts_with(p));
    if !ok || t.url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        anyhow::bail!("Invalid URL {:?}: http(s)://, sftp:// or ftps:// without spaces", t.url);
    }
    if !(0..=24 * 366).contains(&t.interval_hours) {
        anyhow::bail!("Invalid interval: 0 (manual) to 8784 hours");
    }
    if t.username.contains(['\n', '"']) || t.password.contains(['\n', '"']) {
        anyhow::bail!("Invalid credentials: no quotes or line breaks");
    }
    if !t.passphrase.is_empty() && t.passphrase.len() < 8 {
        anyhow::bail!("Invalid passphrase: at least 8 characters");
    }
    Ok(())
}

#[derive(Clone)]
pub struct BackupTargets {
    store: Arc<ConfigStore>,
}

impl BackupTargets {
    pub fn new(store: Arc<ConfigStore>) -> Self {
        Self { store }
    }
    fn pool(&self) -> anyhow::Result<&sqlx::SqlitePool> {
        self.store.pool().map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub async fn list(&self) -> anyhow::Result<Vec<Target>> {
        let rows = sqlx::query(
            "SELECT id, name, url, username, password, passphrase, interval_hours, insecure_tls, enabled, \
             last_run, last_status, last_file FROM backup_targets ORDER BY name",
        )
        .fetch_all(self.pool()?)
        .await?;
        Ok(rows
            .iter()
            .map(|r| Target {
                id: r.get(0),
                name: r.get(1),
                url: r.get(2),
                username: r.get(3),
                has_password: !r.get::<String, _>(4).is_empty(),
                encrypted: !r.get::<String, _>(5).is_empty(),
                interval_hours: r.get(6),
                insecure_tls: r.get::<i64, _>(7) != 0,
                enabled: r.get::<i64, _>(8) != 0,
                last_run: r.get(9),
                last_status: r.get(10),
                last_file: r.get(11),
            })
            .collect())
    }

    pub async fn create(&self, t: &TargetInput) -> anyhow::Result<i64> {
        validate(t)?;
        let r = sqlx::query(
            "INSERT INTO backup_targets (name, url, username, password, passphrase, interval_hours, insecure_tls, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(t.name.trim())
        .bind(&t.url)
        .bind(&t.username)
        .bind(&t.password)
        .bind(&t.passphrase)
        .bind(t.interval_hours)
        .bind(t.insecure_tls as i64)
        .bind(t.enabled as i64)
        .execute(self.pool()?)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                anyhow::anyhow!("Invalid target name: {:?} exists already", t.name)
            } else {
                e.into()
            }
        })?;
        Ok(r.last_insert_rowid())
    }

    pub async fn delete(&self, id: i64) -> anyhow::Result<()> {
        let r = sqlx::query("DELETE FROM backup_targets WHERE id = ?")
            .bind(id)
            .execute(self.pool()?)
            .await?;
        if r.rows_affected() == 0 {
            anyhow::bail!("no such backup target");
        }
        Ok(())
    }

    /// Upload one backup to target `id` now. Returns the remote file name.
    pub async fn run(&self, id: i64) -> anyhow::Result<String> {
        let row = sqlx::query("SELECT url, username, password, passphrase, insecure_tls FROM backup_targets WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool()?)
            .await?
            .ok_or_else(|| anyhow::anyhow!("no such backup target"))?;
        let (url, user, pass, phrase, insecure): (String, String, String, String, i64) =
            (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4));
        let res = self.upload(&url, &user, &pass, &phrase, insecure != 0).await;
        let (status, file) = match &res {
            Ok(f) => ("ok".to_string(), Some(f.clone())),
            Err(e) => (format!("failed: {e}"), None),
        };
        sqlx::query("UPDATE backup_targets SET last_run = ?, last_status = ?, last_file = COALESCE(?, last_file) WHERE id = ?")
            .bind(chrono::Utc::now().timestamp())
            .bind(&status)
            .bind(&file)
            .bind(id)
            .execute(self.pool()?)
            .await?;
        res
    }

    async fn upload(&self, url: &str, user: &str, pass: &str, phrase: &str, insecure: bool) -> anyhow::Result<String> {
        let doc = self
            .store
            .export_json()
            .await
            .map_err(|e| anyhow::anyhow!("exporting the configuration: {e}"))?;
        let mut bytes = (serde_json::to_string_pretty(&doc)? + "\n").into_bytes();
        let mut name = format!("patronus-config-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
        if !phrase.is_empty() {
            let p = phrase.to_string();
            bytes = tokio::task::spawn_blocking(move || encrypt(&bytes, &p)).await??;
            name.push_str(".enc");
        }
        let dir = std::env::temp_dir();
        let tmp = dir.join(format!(".patronus-upload-{}", uuid::Uuid::new_v4()));
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            std::io::Write::write_all(&mut f, &bytes)?;
        }
        let target = format!("{}/{}", url.trim_end_matches('/'), name);
        let mut cmd = tokio::process::Command::new("curl");
        cmd.args(["--silent", "--show-error", "--fail", "--max-time", "120", "--config", "-", "-T"])
            .arg(&tmp)
            .arg(&target)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let out = async {
            let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!("running curl: {e}"))?;
            let mut cfg = String::new();
            if !user.is_empty() {
                cfg.push_str(&format!("user = \"{user}:{pass}\"\n"));
            }
            if insecure {
                cfg.push_str("insecure\n");
            }
            if let Some(mut si) = child.stdin.take() {
                si.write_all(cfg.as_bytes()).await?;
            }
            Ok::<_, anyhow::Error>(child.wait_with_output().await?)
        }
        .await;
        let _ = std::fs::remove_file(&tmp);
        let out = out?;
        if !out.status.success() {
            let e = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("upload to {} failed: {}", url, e.trim());
        }
        Ok(name)
    }

    /// Run every enabled target whose interval has elapsed.
    pub async fn run_due(&self) {
        let now = chrono::Utc::now().timestamp();
        let Ok(list) = self.list().await else { return };
        for t in list {
            if !t.enabled || t.interval_hours == 0 {
                continue;
            }
            if t.last_run.is_none_or(|l| now - l >= t.interval_hours * 3600) {
                match self.run(t.id).await {
                    Ok(f) => tracing::info!("remote backup {}: uploaded {f}", t.name),
                    Err(e) => tracing::warn!("remote backup {}: {e}", t.name),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_backups_round_trip_and_need_the_passphrase() {
        let enc = encrypt(b"{\"tables\":{}}", "correct horse battery").unwrap();
        assert!(is_encrypted(&enc));
        assert!(!String::from_utf8_lossy(&enc).contains("tables"));
        assert_eq!(decrypt(&enc, "correct horse battery").unwrap(), b"{\"tables\":{}}");
        assert!(decrypt(&enc, "wrong passphrase").is_err());
        assert!(!is_encrypted(b"{}"));
    }

    #[test]
    fn urls_and_credentials_are_checked() {
        let mk = |url: &str| TargetInput {
            name: "n".into(),
            url: url.into(),
            username: String::new(),
            password: String::new(),
            passphrase: String::new(),
            interval_hours: 24,
            insecure_tls: false,
            enabled: true,
        };
        assert!(validate(&mk("https://x.example/dav")).is_ok());
        assert!(validate(&mk("file:///etc")).is_err());
        assert!(validate(&mk("http://a b")).is_err());
    }
}
