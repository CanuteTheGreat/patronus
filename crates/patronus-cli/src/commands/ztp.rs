//! `patronus ztp`: zero-touch provisioning.
//!
//! A box that boots with only `/etc/patronus/patronus.toml` (written by the
//! installer or baked into an image) can configure itself:
//!
//! ```toml
//! [provisioning]
//! url = "https://provision.example.net/sites/branch-17.json"
//! passphrase_file = "/etc/patronus/provision.pass"   # optional: encrypted bundle
//! wait_secs = 180                                    # optional: how long to wait for the network
//! ```
//!
//! The bundle is a configuration export (`patronus config export`, or a remote
//! backup), optionally sealed with a passphrase. It is fetched with curl
//! (retrying until the WAN is up), imported and applied exactly like
//! `patronus config import`, and a marker in the store (`ztp.done`) keeps it
//! from running again at the next boot (`--force` repeats it).

use super::apply::{self, ApplyOptions};
use colored::Colorize;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, PartialEq)]
pub struct Provisioning {
    pub url: String,
    pub passphrase_file: Option<PathBuf>,
    pub wait_secs: u64,
}

/// The `[provisioning]` section of the bootstrap file, if any.
pub fn parse(text: &str) -> anyhow::Result<Option<Provisioning>> {
    let v: toml::Value = text.parse().map_err(|e| anyhow::anyhow!("patronus.toml: {e}"))?;
    let Some(p) = v.get("provisioning") else {
        return Ok(None);
    };
    let url = p.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string();
    if !["http://", "https://", "sftp://", "ftps://"].iter().any(|s| url.starts_with(s))
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        anyhow::bail!("[provisioning] url {url:?}: http(s)://, sftp:// or ftps:// without spaces");
    }
    Ok(Some(Provisioning {
        url,
        passphrase_file: p.get("passphrase_file").and_then(|u| u.as_str()).map(PathBuf::from),
        wait_secs: p.get("wait_secs").and_then(|u| u.as_integer()).unwrap_or(180).clamp(0, 3600) as u64,
    }))
}

/// Decrypt a fetched bundle when it is sealed, check it is an export.
pub fn open_bundle(bytes: &[u8], passphrase: Option<&str>) -> anyhow::Result<serde_json::Value> {
    let plain = if patronus_secrets::crypto::is_sealed(bytes) {
        let p = passphrase.ok_or_else(|| {
            anyhow::anyhow!("the bundle is encrypted: set passphrase_file in [provisioning]")
        })?;
        patronus_secrets::crypto::open_with_passphrase(bytes, p)?
    } else {
        bytes.to_vec()
    };
    let doc: serde_json::Value =
        serde_json::from_slice(&plain).map_err(|e| anyhow::anyhow!("the bundle is not JSON: {e}"))?;
    if !doc.get("tables").is_some_and(serde_json::Value::is_object) {
        anyhow::bail!("the bundle is not a Patronus configuration export (no \"tables\")");
    }
    Ok(doc)
}

fn fetch(url: &str, wait_secs: u64) -> anyhow::Result<Vec<u8>> {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        let out = std::process::Command::new("curl")
            .args(["--silent", "--show-error", "--fail", "--location", "--max-time", "30", url])
            .output()
            .map_err(|e| anyhow::anyhow!("running curl: {e}"))?;
        if out.status.success() {
            return Ok(out.stdout);
        }
        if std::time::Instant::now() >= end {
            anyhow::bail!("could not fetch {url}: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        println!("{} waiting for {url} ({})", "•".cyan(), String::from_utf8_lossy(&out.stderr).trim());
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

async fn marker(db: Option<&Path>) -> anyhow::Result<Option<String>> {
    let store = apply::open_store(db).await?;
    let v = patronus_network::lan::get_setting(&store, "ztp.done").await.map_err(|e| anyhow::anyhow!("{e}"))?;
    store.close().await;
    Ok(v)
}

pub async fn run(db: Option<PathBuf>, bootstrap: Option<PathBuf>, force: bool) -> anyhow::Result<()> {
    let path = bootstrap.clone().unwrap_or_else(patronus_config::defaults::default_bootstrap_path);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let Some(p) = parse(&text)? else {
        println!("{} no [provisioning] section in {}: nothing to do", "•".cyan(), path.display());
        return Ok(());
    };
    if !force {
        if let Some(when) = marker(db.as_deref()).await? {
            println!("{} already provisioned (at {when}); use --force to repeat", "•".cyan());
            return Ok(());
        }
    }
    let phrase = match &p.passphrase_file {
        Some(f) => Some(
            std::fs::read_to_string(f)
                .map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?
                .trim()
                .to_string(),
        ),
        None => None,
    };
    let url = p.url.clone();
    let wait = p.wait_secs;
    let bytes = tokio::task::spawn_blocking(move || fetch(&url, wait)).await??;
    let doc = open_bundle(&bytes, phrase.as_deref())?;
    let tmp = std::env::temp_dir().join(format!(".patronus-ztp-{}.json", std::process::id()));
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        std::io::Write::write_all(&mut f, serde_json::to_string(&doc)?.as_bytes())?;
    }
    let res = apply::import(
        &tmp,
        true,
        ApplyOptions { db: db.clone(), bootstrap, phases: None, dry_run: false },
    )
    .await;
    let _ = std::fs::remove_file(&tmp);
    res?;
    let store = apply::open_store(db.as_deref()).await?;
    let now = chrono::Utc::now().to_rfc3339();
    patronus_network::lan::set_setting(&store, "ztp.done", &now).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    store.close().await;
    println!("{} provisioned from {}", "•".cyan(), p.url);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_provisioning_section() {
        assert_eq!(parse("[network]\nwan_interfaces=[\"a\"]\n").unwrap(), None);
        let p = parse("[provisioning]\nurl = \"https://p.example/x.json\"\npassphrase_file = \"/etc/p\"\n").unwrap().unwrap();
        assert_eq!((p.url.as_str(), p.wait_secs), ("https://p.example/x.json", 180));
        assert_eq!(p.passphrase_file, Some(PathBuf::from("/etc/p")));
        assert!(parse("[provisioning]\nurl = \"file:///etc/shadow\"\n").is_err());
    }

    #[test]
    fn bundles_open_plain_or_sealed() {
        let doc = br#"{"tables":{}}"#;
        assert!(open_bundle(doc, None).is_ok());
        let sealed = patronus_secrets::crypto::seal_with_passphrase(doc, "correct horse battery").unwrap();
        assert!(open_bundle(&sealed, None).is_err());
        assert!(open_bundle(&sealed, Some("wrong wrong wrong")).is_err());
        assert!(open_bundle(&sealed, Some("correct horse battery")).is_ok());
        assert!(open_bundle(b"{}", None).is_err());
    }
}
