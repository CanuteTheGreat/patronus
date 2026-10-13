//! Self-signed TLS for the dashboard.
//!
//! The Patronus dashboard is documented (README, install guide) as an
//! HTTPS service on 8443, and the project already ships self-signed
//! certificate generation for internal PKI (see patronus-security::pki).
//! This wires that same capability into the actual dashboard listener so
//! the service matches what's documented instead of serving plain HTTP
//! on an HTTPS-looking port.
//!
//! Behavior: on first start, generate a self-signed cert/key pair and
//! cache it under the given directory (defaults to /etc/patronus/tls,
//! which lives on the same persistent volume as the rest of /etc/patronus
//! so it survives container restarts). On later starts, reuse the cached
//! pair. Operators who want a CA-issued cert instead can just drop their
//! own cert.pem/key.pem in that directory before starting the container.

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use std::path::{Path, PathBuf};

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";

/// Default location for the dashboard's TLS material. Overridable via the
/// PATRONUS_TLS_DIR environment variable (used by tests/alternate deployments).
pub fn default_tls_dir() -> PathBuf {
    std::env::var("PATRONUS_TLS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/patronus/tls"))
}

/// Load an existing self-signed cert/key pair from `dir`, generating one
/// if neither file exists yet.
pub async fn ensure_self_signed_cert(dir: &Path) -> Result<RustlsConfig> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if !cert_path.exists() || !key_path.exists() {
        tracing::info!(
            "No TLS material found at {}, generating a self-signed certificate",
            dir.display()
        );
        generate_self_signed(&cert_path, &key_path)?;
    } else {
        tracing::info!("Using existing TLS material at {}", dir.display());
    }

    RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .with_context(|| format!("failed to load TLS material from {}", dir.display()))
}

fn generate_self_signed(cert_path: &Path, key_path: &Path) -> Result<()> {
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create TLS directory {}", parent.display()))?;
    }

    let hostname = std::env::var("PATRONUS_TLS_HOSTNAME").unwrap_or_else(|_| "localhost".into());
    let subject_alt_names = vec![
        hostname,
        "patronus".to_string(),
        "patronus.local".to_string(),
    ];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("failed to generate self-signed certificate")?;
    let cert_pem = cert
        .serialize_pem()
        .context("failed to serialize certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    std::fs::write(cert_path, cert_pem)
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    std::fs::write(key_path, key_pem)
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict permissions on {}", key_path.display()))?;
    }

    tracing::info!(
        "Generated self-signed TLS certificate at {} (valid for ~90 days by default)",
        cert_path.display()
    );
    Ok(())
}
