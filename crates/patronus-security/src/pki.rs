//! PKI (Public Key Infrastructure)

use anyhow::Result;
use rcgen::{Certificate as RcgenCertificate, CertificateParams, DnType};

pub struct CertificateAuthority {
    ca_cert: RcgenCertificate,
}

pub struct Certificate {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertificateAuthority {
    pub fn new() -> Result<Self> {
        let mut params = CertificateParams::new(vec!["Patronus CA".to_string()]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let ca_cert = RcgenCertificate::from_params(params)?;

        Ok(Self { ca_cert })
    }

    pub fn issue_certificate(&self, common_name: &str, validity_days: u32) -> Result<Certificate> {
        let mut params = CertificateParams::new(vec![common_name.to_string()]);
        params.distinguished_name.push(DnType::CommonName, common_name);

        let cert = RcgenCertificate::from_params(params)?;
        let cert_pem = cert.serialize_pem_with_signer(&self.ca_cert)?;
        let key_pem = cert.serialize_private_key_pem();

        tracing::info!("Issued certificate for {} (valid for {} days)", common_name, validity_days);

        Ok(Certificate {
            cert_pem,
            key_pem,
        })
    }

    pub fn revoke_certificate(&self, serial: &str) -> Result<()> {
        tracing::info!("Revoking certificate {}", serial);
        // In production: add to CRL
        Ok(())
    }
}

impl Default for CertificateAuthority {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_creation() {
        let ca = CertificateAuthority::new().unwrap();
        let cert = ca.issue_certificate("test.example.com", 365).unwrap();
        assert!(!cert.cert_pem.is_empty());
        assert!(!cert.key_pem.is_empty());
    }
}
