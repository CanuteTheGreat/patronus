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

    if !material_present(&cert_path, &key_path) {
        tracing::info!(
            "No usable TLS material found at {}, generating a self-signed certificate",
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

/// Both files exist and are non-empty. A zero-length file is never operator
/// material: it is what an ext4 volume holds when power was cut between the
/// first-boot write and the delayed allocation (the UI then never came back).
/// Non-empty but unparsable material is left alone (it may be the operator's
/// own pair; the load error names it).
fn material_present(cert: &Path, key: &Path) -> bool {
    let non_empty = |p: &Path| std::fs::metadata(p).map(|m| m.is_file() && m.len() > 0).unwrap_or(false);
    non_empty(cert) && non_empty(key)
}

/// Write `data` to `path` so a crash leaves either the old file or the whole
/// new one: temp file in the same directory, fsync, rename, fsync the directory.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.with_context(|| format!("failed to write {}", path.display()))
}

/// The certificate the settings name (`web.tls_cert` / `web.tls_key`), or the
/// generated self-signed one when none is named. A named pair that cannot be
/// loaded is logged and replaced by the self-signed certificate: the UI stays
/// reachable (fail open to a working login page, never to no UI).
pub async fn configured_or_self_signed(cert: &str, key: &str, dir: &Path) -> Result<RustlsConfig> {
    if !cert.is_empty() && !key.is_empty() {
        match load_config(Path::new(cert), Path::new(key)).await {
            Ok(c) => {
                tracing::info!("Using TLS certificate {cert}");
                return Ok(c);
            }
            Err(e) => tracing::error!(
                "cannot load the configured TLS certificate {cert} / {key}: {e:#}; \
                 falling back to the self-signed certificate"
            ),
        }
    }
    ensure_self_signed_cert(dir).await
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

    // Key first, certificate last: the pair counts as present only when both
    // are whole files, so a cut between the two regenerates both next start.
    write_atomic(key_path, key_pem.as_bytes(), 0o600)?;
    write_atomic(cert_path, cert_pem.as_bytes(), 0o644)?;

    tracing::info!(
        "Generated self-signed TLS certificate at {} (valid for ~90 days by default)",
        cert_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_files_count_as_missing_and_are_regenerated() {
        // What a power cut right after first boot leaves on ext4: both files exist, length 0.
        let d = tempfile::tempdir().unwrap();
        let (c, k) = (d.path().join(CERT_FILE), d.path().join(KEY_FILE));
        std::fs::write(&c, b"").unwrap();
        std::fs::write(&k, b"").unwrap();
        assert!(!material_present(&c, &k));
        generate_self_signed(&c, &k).unwrap();
        assert!(material_present(&c, &k));
        assert!(std::fs::read_to_string(&c).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(std::fs::read_to_string(&k).unwrap().contains("PRIVATE KEY"));
    }

    #[test]
    fn a_half_pair_is_not_present() {
        let d = tempfile::tempdir().unwrap();
        let (c, k) = (d.path().join(CERT_FILE), d.path().join(KEY_FILE));
        std::fs::write(&c, b"x").unwrap();
        assert!(!material_present(&c, &k));
        std::fs::write(&k, b"").unwrap();
        assert!(!material_present(&c, &k));
    }

    #[test]
    fn operator_material_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let (c, k) = (d.path().join(CERT_FILE), d.path().join(KEY_FILE));
        std::fs::write(&c, b"operator cert").unwrap();
        std::fs::write(&k, b"operator key").unwrap();
        assert!(material_present(&c, &k));
    }

    #[test]
    fn generation_leaves_no_temp_files_and_key_is_private() {
        let d = tempfile::tempdir().unwrap();
        let (c, k) = (d.path().join(CERT_FILE), d.path().join(KEY_FILE));
        generate_self_signed(&c, &k).unwrap();
        let names: Vec<_> = std::fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&k).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn ensure_recovers_from_zero_length_pair_and_loads() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(CERT_FILE), b"").unwrap();
        std::fs::write(d.path().join(KEY_FILE), b"").unwrap();
        ensure_self_signed_cert(d.path()).await.expect("UI must come back after a power cut");
    }
}
