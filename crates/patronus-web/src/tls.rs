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
#[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
use axum_server::tls_openssl::OpenSSLConfig as RustlsConfig;
#[cfg(feature = "tls-rustls")]
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

    load_config(&cert_path, &key_path)
        .await
        .with_context(|| format!("failed to load TLS material from {}", dir.display()))
}

#[cfg(feature = "tls-rustls")]
async fn load_config(cert: &Path, key: &Path) -> Result<RustlsConfig> {
    Ok(RustlsConfig::from_pem_file(cert, key).await?)
}

#[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
async fn load_config(cert: &Path, key: &Path) -> Result<RustlsConfig> {
    Ok(RustlsConfig::from_pem_file(cert, key)?)
}

/// Self-signed certificate (ECDSA P-256, 10 years, SANs = hostname, patronus,
/// patronus.local plus the LAN IP from `PATRONUS_TLS_IP`) via OpenSSL.
#[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
fn make_cert(sans: &[String]) -> Result<(String, String)> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509NameBuilder, X509};
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, &sans[0])?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Patronus")?;
    let name = name.build();
    let mut b = X509::builder()?;
    b.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    b.set_serial_number(&serial)?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    b.set_pubkey(&key)?;
    // A router often boots with the clock at 1970: back-date the start.
    let nb = Asn1Time::from_unix(1_600_000_000)?;
    let na = Asn1Time::days_from_now(3650)?;
    b.set_not_before(&nb)?;
    b.set_not_after(&na)?;
    let mut san = SubjectAlternativeName::new();
    for s in sans {
        if s.parse::<std::net::IpAddr>().is_ok() {
            san.ip(s);
        } else {
            san.dns(s);
        }
    }
    let ext = san.build(&b.x509v3_context(None, None))?;
    b.append_extension(ext)?;
    b.sign(&key, MessageDigest::sha256())?;
    let cert = b.build();
    Ok((
        String::from_utf8(cert.to_pem()?)?,
        String::from_utf8(key.private_key_to_pem_pkcs8()?)?,
    ))
}

fn generate_self_signed(cert_path: &Path, key_path: &Path) -> Result<()> {
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create TLS directory {}", parent.display()))?;
    }

    let hostname = std::env::var("PATRONUS_TLS_HOSTNAME").unwrap_or_else(|_| "localhost".into());
    let mut subject_alt_names = vec![
        hostname,
        "patronus".to_string(),
        "patronus.local".to_string(),
    ];
    if let Ok(ip) = std::env::var("PATRONUS_TLS_IP") {
        subject_alt_names.extend(ip.split(',').map(|s| s.trim().to_string()));
    }

    #[cfg(feature = "tls-rustls")]
    let (cert_pem, key_pem) = {
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)
            .context("failed to generate self-signed certificate")?;
        (
            cert.serialize_pem()
                .context("failed to serialize certificate")?,
            cert.serialize_private_key_pem(),
        )
    };
    #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
    let (cert_pem, key_pem) =
        make_cert(&subject_alt_names).context("failed to generate self-signed certificate")?;

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
