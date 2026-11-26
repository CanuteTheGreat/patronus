//! PKI facade kept for existing callers.
//!
//! Thin, thread-safe wrapper over [`crate::ca::CertificateAuthority`], the
//! real backend (CSR signing, ledger, revocation, CRLs).  New code should use
//! the backend directly; this type exists so `issue_certificate` honours its
//! validity argument and `revoke_certificate` really revokes.

use std::sync::Mutex;

use anyhow::{anyhow, Result};

use crate::ca::{self, CaConfig, CertProfile, CrlSummary, IssueOptions, IssuedCrl, RevokeReason};

pub struct CertificateAuthority {
    inner: Mutex<ca::CertificateAuthority>,
}

pub struct Certificate {
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl CertificateAuthority {
    /// New CA with default [`CaConfig`].
    pub fn new() -> Result<Self> {
        Self::with_config(CaConfig::default())
    }

    pub fn with_config(config: CaConfig) -> Result<Self> {
        Ok(Self {
            inner: Mutex::new(ca::CertificateAuthority::create(config)?),
        })
    }

    pub fn from_backend(backend: ca::CertificateAuthority) -> Self {
        Self {
            inner: Mutex::new(backend),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ca::CertificateAuthority>> {
        self.inner.lock().map_err(|_| anyhow!("CA state poisoned"))
    }

    pub fn ca_certificate_pem(&self) -> Result<String> {
        Ok(self.lock()?.ca_certificate_pem().to_string())
    }

    /// Issue a server certificate for `common_name` (also used as its DNS/IP SAN).
    pub fn issue_certificate(&self, common_name: &str, validity_days: u32) -> Result<Certificate> {
        let g = self.lock()?.issue_with_generated_key(
            common_name,
            &[common_name.to_string()],
            &IssueOptions {
                profile: CertProfile::Server,
                validity_days: Some(validity_days),
            },
        )?;
        Ok(Certificate {
            cert_pem: g.certificate.cert_pem.clone(),
            key_pem: g.private_key_pem().to_string(),
        })
    }

    /// Revoke by serial (hex).  Unknown serials are an error.
    pub fn revoke_certificate(&self, serial: &str) -> Result<()> {
        self.lock()?.revoke(serial, RevokeReason::Unspecified)?;
        Ok(())
    }

    pub fn generate_crl(&self) -> Result<IssuedCrl> {
        Ok(self.lock()?.generate_crl()?)
    }

    pub fn crl_summary(&self) -> Result<CrlSummary> {
        Ok(self.lock()?.crl_summary())
    }
}

impl Default for CertificateAuthority {
    fn default() -> Self {
        Self::new().expect("default CA configuration is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[test]
    fn issue_honours_validity_and_revocation_reaches_crl() {
        let ca = CertificateAuthority::new().unwrap();
        let cert = ca.issue_certificate("test.example.com", 30).unwrap();
        assert!(cert.key_pem.contains("PRIVATE KEY"));
        let der = x509_parser::pem::parse_x509_pem(cert.cert_pem.as_bytes())
            .unwrap()
            .1
            .contents;
        let (_, c) = X509Certificate::from_der(&der).unwrap();
        let span = c.validity().not_after.timestamp() - c.validity().not_before.timestamp();
        assert_eq!(span, 30 * 86_400 + 300);
        let serial = c
            .tbs_certificate
            .raw_serial()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(ca.generate_crl().unwrap().revoked_count, 0);
        ca.revoke_certificate(&serial).unwrap();
        assert_eq!(ca.generate_crl().unwrap().revoked_count, 1);
        assert!(ca.revoke_certificate("1234abcd").is_err());
        assert!(!format!("{cert:?}").contains("PRIVATE"));
    }

    #[test]
    fn rejects_excessive_validity() {
        let ca = CertificateAuthority::new().unwrap();
        assert!(ca.issue_certificate("a.example.com", 100_000).is_err());
        assert!(ca.issue_certificate("a.example.com", 0).is_err());
    }
}
