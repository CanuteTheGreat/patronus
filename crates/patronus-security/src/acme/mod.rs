//! ACME client (RFC 8555) for the certificate manager.
//!
//! Built on `instant-acme` (Apache-2.0, pure Rust, rustls/ring).  Challenge
//! types: HTTP-01 (answered by patronus-web on its port-80 listener through
//! [`Http01Store`]) and DNS-01 through the [`dns::DnsProvider`] trait
//! (Cloudflare, RFC 2136 with TSIG).  Every value is a field of
//! [`AcmeSettings`]; nothing here has a compiled-in endpoint except the two
//! public Let's Encrypt directory *names* that the typed `directory` setting
//! selects.  Private keys are returned to the caller, never logged.

pub mod dns;
pub mod rfc2136;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub use dns::{DnsProvider, DnsProviderConfig};

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("invalid ACME configuration: {0}")]
    Config(String),
    #[error("ACME server: {0}")]
    Server(String),
    #[error("DNS: {0}")]
    Dns(String),
    #[error("challenge failed: {0}")]
    Challenge(String),
    #[error("certificate: {0}")]
    Cert(String),
}

impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        AcmeError::Server(e.to_string())
    }
}

/// Which ACME directory to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DirectoryKind {
    /// Let's Encrypt staging: untrusted certificates, generous rate limits.
    #[default]
    Staging,
    Production,
    /// `directory_url` (Pebble, ZeroSSL, step-ca, an internal CA...).
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Challenge {
    #[default]
    Http01,
    Dns01,
}

/// One ACME-managed certificate (typed settings; the declarative shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeSettings {
    pub directory: DirectoryKind,
    pub directory_url: String,
    /// PEM bundle of extra trust roots for the ACME server's TLS (Pebble).
    pub ca_bundle: Option<PathBuf>,
    pub email: String,
    pub terms_of_service_agreed: bool,
    pub domains: Vec<String>,
    pub challenge: Challenge,
    pub dns: Option<DnsProviderConfig>,
    /// Seconds to wait after publishing a TXT record before asking the CA.
    pub dns_propagation_secs: u64,
    /// Renew when this many days remain.
    pub renew_days_before: u32,
    /// How long to poll the CA for order/certificate readiness.
    pub poll_timeout_secs: u64,
}

impl Default for AcmeSettings {
    fn default() -> Self {
        Self {
            directory: DirectoryKind::Staging,
            directory_url: String::new(),
            ca_bundle: None,
            email: String::new(),
            terms_of_service_agreed: false,
            domains: Vec::new(),
            challenge: Challenge::Http01,
            dns: None,
            dns_propagation_secs: 5,
            renew_days_before: 30,
            poll_timeout_secs: 120,
        }
    }
}

impl AcmeSettings {
    pub fn validate(&self) -> Result<(), AcmeError> {
        if self.domains.is_empty() {
            return Err(AcmeError::Config("at least one domain is required".into()));
        }
        for d in &self.domains {
            validate_domain(d, self.challenge)?;
        }
        if !self.terms_of_service_agreed {
            return Err(AcmeError::Config(
                "terms_of_service_agreed must be set to true to register an account".into(),
            ));
        }
        if self.directory == DirectoryKind::Custom && self.directory_url.is_empty() {
            return Err(AcmeError::Config(
                "directory_url is required for directory=custom".into(),
            ));
        }
        if self.challenge == Challenge::Dns01 && self.dns.is_none() {
            return Err(AcmeError::Config("dns-01 needs a DNS provider".into()));
        }
        if self.email.contains(char::is_whitespace) {
            return Err(AcmeError::Config("email contains whitespace".into()));
        }
        Ok(())
    }

    pub fn directory_url(&self) -> String {
        match self.directory {
            DirectoryKind::Staging => LetsEncrypt::Staging.url().to_string(),
            DirectoryKind::Production => LetsEncrypt::Production.url().to_string(),
            DirectoryKind::Custom => self.directory_url.clone(),
        }
    }
}

fn validate_domain(d: &str, ch: Challenge) -> Result<(), AcmeError> {
    let bare = d.strip_prefix("*.").unwrap_or(d);
    if d.starts_with("*.") && ch != Challenge::Dns01 {
        return Err(AcmeError::Config(format!("wildcard {d} needs dns-01")));
    }
    let ok = !bare.is_empty()
        && bare.len() <= 253
        && bare.contains('.')
        && bare.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if ok {
        Ok(())
    } else {
        Err(AcmeError::Config(format!(
            "{d:?} is not a valid public DNS name"
        )))
    }
}

/// Token -> key authorization map shared with the port-80 listener.
#[derive(Clone, Default)]
pub struct Http01Store(Arc<RwLock<HashMap<String, String>>>);

impl Http01Store {
    pub fn put(&self, token: &str, key_auth: &str) {
        if let Ok(mut m) = self.0.write() {
            m.insert(token.to_string(), key_auth.to_string());
        }
    }
    pub fn remove(&self, token: &str) {
        if let Ok(mut m) = self.0.write() {
            m.remove(token);
        }
    }
    /// Body for `GET /.well-known/acme-challenge/<token>`.
    pub fn lookup(&self, token: &str) -> Option<String> {
        // Tokens are base64url; refuse anything else (no path tricks).
        if token.is_empty()
            || token.len() > 256
            || !token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }
        self.0.read().ok()?.get(token).cloned()
    }
}

/// The process-wide HTTP-01 store: patronus-web's port-80 listener answers
/// from it and the issuing code (same process) fills it.
pub fn global_http01() -> &'static Http01Store {
    static G: std::sync::OnceLock<Http01Store> = std::sync::OnceLock::new();
    G.get_or_init(Http01Store::default)
}

/// Result of a successful order.  The key and account credentials are secret.
pub struct Issued {
    pub chain_pem: String,
    pub key_pem: String,
    /// JSON account credentials to reuse on the next order.
    pub account_json: String,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("chain_pem_len", &self.chain_pem.len())
            .finish_non_exhaustive()
    }
}

/// Run one order to completion.  `account_json` reuses a stored account.
pub async fn issue(
    s: &AcmeSettings,
    account_json: Option<&str>,
    http01: &Http01Store,
) -> Result<Issued, AcmeError> {
    s.validate()?;
    let builder = match &s.ca_bundle {
        Some(p) => Account::builder_with_root(p)?,
        None => Account::builder()?,
    };
    let (account, creds_json) = match account_json {
        Some(j) => {
            let creds = serde_json::from_str(j)
                .map_err(|_| AcmeError::Config("stored ACME account is unreadable".into()))?;
            let a = builder.from_credentials(creds).await?;
            (a, j.to_string())
        }
        None => {
            let contact = if s.email.is_empty() {
                vec![]
            } else {
                vec![format!("mailto:{}", s.email)]
            };
            let refs: Vec<&str> = contact.iter().map(String::as_str).collect();
            let (a, creds) = builder
                .create(
                    &NewAccount {
                        contact: &refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    s.directory_url(),
                    None,
                )
                .await?;
            let j = serde_json::to_string(&creds).map_err(|e| AcmeError::Server(e.to_string()))?;
            (a, j)
        }
    };

    let provider = match (&s.challenge, &s.dns) {
        (Challenge::Dns01, Some(c)) => Some(c.build()?),
        _ => None,
    };
    let idents: Vec<Identifier> = s
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account.new_order(&NewOrder::new(&idents)).await?;

    let mut tokens: Vec<String> = Vec::new();
    let mut txt: Vec<(String, String)> = Vec::new();
    let retry = RetryPolicy::default().timeout(Duration::from_secs(s.poll_timeout_secs));
    // The CA validates while we poll: the challenge answers must stay in
    // place until the order is ready (or has failed), and are removed
    // afterwards in every case.
    let res = async {
        run_challenges(s, &mut order, http01, provider.as_deref(), &mut tokens, &mut txt).await?;
        let status = order.poll_ready(&retry).await?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::Challenge(format!("order ended {status:?}")));
        }
        Ok(())
    }
    .await;
    for t in &tokens {
        http01.remove(t);
    }
    if let Some(p) = provider.as_deref() {
        for (n, v) in &txt {
            if let Err(e) = p.cleanup(n, v).await {
                tracing::warn!("ACME DNS cleanup of {n} failed: {e}");
            }
        }
    }
    res?;

    let key_pem = order.finalize().await?;
    let chain_pem = order.poll_certificate(&retry).await?;
    Ok(Issued {
        chain_pem,
        key_pem,
        account_json: creds_json,
    })
}

async fn run_challenges(
    s: &AcmeSettings,
    order: &mut instant_acme::Order,
    http01: &Http01Store,
    dns: Option<&dyn DnsProvider>,
    tokens: &mut Vec<String>,
    txt: &mut Vec<(String, String)>,
) -> Result<(), AcmeError> {
    let mut pending = Vec::new();
    let mut authzs = order.authorizations();
    while let Some(a) = authzs.next().await {
        let mut authz = a?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => return Err(AcmeError::Challenge(format!("authorization is {other:?}"))),
        }
        let kind = match s.challenge {
            Challenge::Http01 => ChallengeType::Http01,
            Challenge::Dns01 => ChallengeType::Dns01,
        };
        let mut ch = authz
            .challenge(kind.clone())
            .ok_or_else(|| AcmeError::Challenge(format!("CA offers no {kind:?} challenge")))?;
        let key_auth = ch.key_authorization();
        match s.challenge {
            Challenge::Http01 => {
                let token = ch.token.clone();
                http01.put(&token, key_auth.as_str());
                tokens.push(token);
            }
            Challenge::Dns01 => {
                let ident = ch.identifier().to_string();
                let base = ident.strip_prefix("*.").unwrap_or(&ident).to_string();
                let name = format!("_acme-challenge.{base}");
                let value = key_auth.dns_value();
                let p = dns.ok_or_else(|| AcmeError::Config("no DNS provider".into()))?;
                p.present(&name, &value).await?;
                txt.push((name, value));
            }
        }
        pending.push(());
        // Delay readiness until all records are in place when DNS.
        if s.challenge == Challenge::Http01 {
            ch.set_ready().await?;
        }
    }
    if s.challenge == Challenge::Dns01 && !pending.is_empty() {
        tokio::time::sleep(Duration::from_secs(s.dns_propagation_secs)).await;
        let mut authzs = order.authorizations();
        while let Some(a) = authzs.next().await {
            let mut authz = a?;
            if authz.status != AuthorizationStatus::Pending {
                continue;
            }
            if let Some(mut ch) = authz.challenge(ChallengeType::Dns01) {
                ch.set_ready().await?;
            }
        }
    }
    Ok(())
}

/// Revoke an issued certificate at its CA.
pub async fn revoke(s: &AcmeSettings, account_json: &str, cert_pem: &str) -> Result<(), AcmeError> {
    let builder = match &s.ca_bundle {
        Some(p) => Account::builder_with_root(p)?,
        None => Account::builder()?,
    };
    let creds = serde_json::from_str(account_json)
        .map_err(|_| AcmeError::Config("stored ACME account is unreadable".into()))?;
    let account = builder.from_credentials(creds).await?;
    let der = first_cert_der(cert_pem)?;
    let cd = rustls::pki_types::CertificateDer::from(der);
    account
        .revoke(&instant_acme::RevocationRequest {
            certificate: &cd,
            reason: None,
        })
        .await?;
    Ok(())
}

fn first_cert_der(pem: &str) -> Result<Vec<u8>, AcmeError> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| AcmeError::Cert(format!("bad PEM: {e}")))?;
    Ok(p.contents)
}

/// Where a certificate stands, for the UI and the renewal task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RenewalState {
    Valid {
        days_left: i64,
    },
    /// Inside the renewal window (or forced).
    Due {
        days_left: i64,
    },
    Expired {
        days_ago: i64,
    },
    NotYetValid,
}

/// Expiry (unix seconds) of the first certificate in a PEM chain.
pub fn not_after(cert_pem: &str) -> Result<i64, AcmeError> {
    let (_, p) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AcmeError::Cert(format!("bad PEM: {e}")))?;
    let cert = p.parse_x509().map_err(|e| AcmeError::Cert(format!("bad certificate: {e}")))?;
    Ok(cert.validity().not_after.timestamp())
}

pub fn renewal_state(
    cert_pem: &str,
    renew_days_before: u32,
    now_unix: i64,
) -> Result<RenewalState, AcmeError> {
    let (_, p) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AcmeError::Cert(format!("bad PEM: {e}")))?;
    let cert = p
        .parse_x509()
        .map_err(|e| AcmeError::Cert(format!("bad certificate: {e}")))?;
    let nb = cert.validity().not_before.timestamp();
    let na = cert.validity().not_after.timestamp();
    if now_unix < nb {
        return Ok(RenewalState::NotYetValid);
    }
    if now_unix >= na {
        return Ok(RenewalState::Expired {
            days_ago: (now_unix - na) / 86400,
        });
    }
    let days_left = (na - now_unix) / 86400;
    if days_left <= i64::from(renew_days_before) {
        Ok(RenewalState::Due { days_left })
    } else {
        Ok(RenewalState::Valid { days_left })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> AcmeSettings {
        AcmeSettings {
            domains: vec!["router.example.org".into()],
            terms_of_service_agreed: true,
            ..Default::default()
        }
    }

    #[test]
    fn defaults_are_staging_http01() {
        let s = AcmeSettings::default();
        assert_eq!(s.directory, DirectoryKind::Staging);
        assert_eq!(s.challenge, Challenge::Http01);
        assert!(s.directory_url().contains("staging"));
    }

    #[test]
    fn validation() {
        assert!(ok().validate().is_ok());
        let mut s = ok();
        s.terms_of_service_agreed = false;
        assert!(s.validate().is_err());
        let mut s = ok();
        s.domains = vec!["*.example.org".into()];
        assert!(s.validate().is_err(), "wildcard needs dns-01");
        s.challenge = Challenge::Dns01;
        assert!(s.validate().is_err(), "dns-01 needs provider");
        let mut s = ok();
        s.domains = vec!["bad_name".into()];
        assert!(s.validate().is_err());
        let mut s = ok();
        s.directory = DirectoryKind::Custom;
        assert!(s.validate().is_err());
        s.directory_url = "https://ca.test/dir".into();
        assert!(s.validate().is_ok());
        assert_eq!(s.directory_url(), "https://ca.test/dir");
    }

    #[test]
    fn http01_store_refuses_odd_tokens() {
        let st = Http01Store::default();
        st.put("abc-_1", "abc-_1.thumb");
        assert_eq!(st.lookup("abc-_1").as_deref(), Some("abc-_1.thumb"));
        assert_eq!(st.lookup("../etc/passwd"), None);
        assert_eq!(st.lookup(""), None);
        st.remove("abc-_1");
        assert_eq!(st.lookup("abc-_1"), None);
    }

    fn cert(not_before: i64, not_after: i64) -> String {
        let mut p = rcgen::CertificateParams::new(vec!["a.example.org".into()]).unwrap();
        p.not_before = time::OffsetDateTime::from_unix_timestamp(not_before).unwrap();
        p.not_after = time::OffsetDateTime::from_unix_timestamp(not_after).unwrap();
        let k = rcgen::KeyPair::generate().unwrap();
        p.self_signed(&k).unwrap().pem()
    }

    #[test]
    fn renewal_states() {
        let day = 86400;
        let base = 1_700_000_000;
        let c = cert(base, base + 90 * day);
        assert!(matches!(
            renewal_state(&c, 30, base + day).unwrap(),
            RenewalState::Valid { .. }
        ));
        assert!(matches!(
            renewal_state(&c, 30, base + 70 * day).unwrap(),
            RenewalState::Due { .. }
        ));
        assert!(matches!(
            renewal_state(&c, 30, base + 91 * day).unwrap(),
            RenewalState::Expired { .. }
        ));
        assert_eq!(
            renewal_state(&c, 30, base - day).unwrap(),
            RenewalState::NotYetValid
        );
        assert!(renewal_state("junk", 30, base).is_err());
    }

    #[test]
    fn issued_debug_has_no_key() {
        let i = Issued {
            chain_pem: "c".into(),
            key_pem: "SECRETKEY".into(),
            account_json: "SECRETACCT".into(),
        };
        let d = format!("{i:?}");
        assert!(!d.contains("SECRET"));
    }
}
