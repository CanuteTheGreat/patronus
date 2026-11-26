//! Certificate authority backend: CSR signing, issuance ledger, revocation and CRLs.
//!
//! This is the signing/revocation engine behind the certificate manager.  It is
//! deliberately free of I/O policy: callers (API handlers, the ACME responder,
//! the CLI) hand it PEM text and get PEM text back, and persistence goes
//! through [`CaStore`] (private key file mode 0600, written atomically).
//!
//! Security properties enforced here:
//! * CSR contents are *requests*: a CSR can never make a CA, pick its own
//!   validity, serial, key usages or CRL pointers.  Only the subject CN and
//!   SANs survive, and only if they pass [`CaPolicy`].
//! * The CSR proof-of-possession signature is verified (by the parser) before
//!   anything is issued.
//! * Serial numbers are 127-bit random values, never reused, recorded in the
//!   ledger.
//! * The CA private key is never part of [`CaState`], never `Debug`-printed
//!   and never logged.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate as RcgenCert, CertificateParams, CertificateRevocationListParams,
    CertificateSigningRequestParams, CrlDistributionPoint, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SanType, SerialNumber,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Errors from the CA backend.  Messages never contain key material.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid CSR: {0}")]
    Csr(String),
    #[error("request rejected by policy: {0}")]
    Policy(String),
    #[error("unknown certificate serial {0}")]
    UnknownSerial(String),
    #[error("invalid serial number {0:?}")]
    BadSerial(String),
    #[error("CA material invalid: {0}")]
    BadCaMaterial(String),
    #[error("certificate error: {0}")]
    Cert(String),
    #[error("storage error: {0}")]
    Store(String),
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        CaError::Cert(e.to_string())
    }
}

pub type CaResult<T> = Result<T, CaError>;

/// Typed CA settings.  Every operational value lives here (and is meant to be
/// surfaced as config keys by the certificate manager); there are no
/// compiled-in hostnames, URLs or paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaConfig {
    /// CN of the CA certificate.
    pub common_name: String,
    /// Optional O of the CA certificate.
    pub organization: Option<String>,
    /// Lifetime of the CA certificate itself.
    pub ca_validity_days: u32,
    /// Leaf lifetime when the request names none.
    pub default_leaf_validity_days: u32,
    /// Hard cap on any leaf lifetime.
    pub max_leaf_validity_days: u32,
    /// Seconds a freshly issued certificate's notBefore is backdated (clock skew).
    pub backdate_seconds: u32,
    /// nextUpdate - thisUpdate of generated CRLs.
    pub crl_validity_hours: u32,
    /// CRL distribution point URLs embedded in issued certificates (empty = none).
    pub crl_distribution_urls: Vec<String>,
    pub policy: CaPolicy,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            common_name: "Patronus Local CA".to_string(),
            organization: None,
            ca_validity_days: 3650,
            default_leaf_validity_days: 365,
            max_leaf_validity_days: 825,
            backdate_seconds: 300,
            crl_validity_hours: 168,
            crl_distribution_urls: Vec::new(),
            policy: CaPolicy::default(),
        }
    }
}

impl CaConfig {
    pub fn validate(&self) -> CaResult<()> {
        validate_cn(&self.common_name).map_err(|e| CaError::Config(format!("common_name: {e}")))?;
        if self.ca_validity_days == 0 {
            return Err(CaError::Config("ca_validity_days must be > 0".into()));
        }
        if self.default_leaf_validity_days == 0 || self.max_leaf_validity_days == 0 {
            return Err(CaError::Config("leaf validity must be > 0".into()));
        }
        if self.default_leaf_validity_days > self.max_leaf_validity_days {
            return Err(CaError::Config(
                "default_leaf_validity_days exceeds max_leaf_validity_days".into(),
            ));
        }
        if self.max_leaf_validity_days > self.ca_validity_days {
            return Err(CaError::Config(
                "max_leaf_validity_days exceeds ca_validity_days".into(),
            ));
        }
        if self.crl_validity_hours == 0 {
            return Err(CaError::Config("crl_validity_hours must be > 0".into()));
        }
        for u in &self.crl_distribution_urls {
            if !(u.starts_with("http://") || u.starts_with("https://"))
                || u.contains(char::is_whitespace)
            {
                return Err(CaError::Config(format!("bad CRL distribution URL {u:?}")));
            }
        }
        Ok(())
    }
}

/// Which names a CSR may ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaPolicy {
    /// If non-empty every DNS SAN must equal one of these or be a subdomain of
    /// one (`example.lan` allows `example.lan` and `a.example.lan`).
    pub allowed_dns_suffixes: Vec<String>,
    pub allow_ip_sans: bool,
    pub allow_wildcards: bool,
    pub max_sans: usize,
}

impl Default for CaPolicy {
    fn default() -> Self {
        Self {
            allowed_dns_suffixes: Vec::new(),
            allow_ip_sans: true,
            allow_wildcards: false,
            max_sans: 20,
        }
    }
}

/// What a leaf certificate may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertProfile {
    Server,
    Client,
    ServerAndClient,
}

/// Revocation reasons (RFC 5280 5.3.1) the backend accepts.  `removeFromCRL`
/// and `certificateHold` are intentionally absent: revocation is permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    Unspecified,
    KeyCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    PrivilegeWithdrawn,
}

impl RevokeReason {
    fn to_rcgen(self) -> RevocationReason {
        match self {
            RevokeReason::Unspecified => RevocationReason::Unspecified,
            RevokeReason::KeyCompromise => RevocationReason::KeyCompromise,
            RevokeReason::AffiliationChanged => RevocationReason::AffiliationChanged,
            RevokeReason::Superseded => RevocationReason::Superseded,
            RevokeReason::CessationOfOperation => RevocationReason::CessationOfOperation,
            RevokeReason::PrivilegeWithdrawn => RevocationReason::PrivilegeWithdrawn,
        }
    }
}

/// Per-request issuance options.
#[derive(Debug, Clone)]
pub struct IssueOptions {
    pub profile: CertProfile,
    /// `None` = `CaConfig::default_leaf_validity_days`.
    pub validity_days: Option<u32>,
}

impl Default for IssueOptions {
    fn default() -> Self {
        Self {
            profile: CertProfile::Server,
            validity_days: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub revoked_at: i64,
    pub reason: RevokeReason,
}

/// One issued certificate in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedRecord {
    /// Lower-case hex of the serial, no separators.
    pub serial: String,
    pub subject_cn: String,
    pub sans: Vec<String>,
    pub profile: CertProfile,
    pub issued_at: i64,
    pub not_before: i64,
    pub not_after: i64,
    pub revocation: Option<Revocation>,
}

/// Serialisable CA state.  Contains **no** private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaState {
    pub version: u32,
    pub crl_number: u64,
    pub issued: Vec<IssuedRecord>,
}

impl Default for CaState {
    fn default() -> Self {
        Self {
            version: 1,
            crl_number: 0,
            issued: Vec::new(),
        }
    }
}

/// Result of signing.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub cert_pem: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
}

/// A freshly generated leaf key + certificate (server-side keygen path).
/// `Debug` redacts the key.
#[derive(Clone)]
pub struct GeneratedCertificate {
    pub certificate: IssuedCertificate,
    key_pem: String,
}

impl GeneratedCertificate {
    /// The private key PEM.  Hand it to the owner only; never log it.
    pub fn private_key_pem(&self) -> &str {
        &self.key_pem
    }
}

impl fmt::Debug for GeneratedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedCertificate")
            .field("certificate", &self.certificate)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// A signed CRL.
#[derive(Debug, Clone)]
pub struct IssuedCrl {
    pub pem: String,
    pub der: Vec<u8>,
    pub crl_number: u64,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked_count: usize,
}

/// Outcome of [`CertificateAuthority::verify_certificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    Valid,
    Revoked {
        revoked_at: i64,
        reason: RevokeReason,
    },
    Expired,
    NotYetValid,
    /// Not signed by this CA (or the signature does not verify).
    UntrustedIssuer,
    /// Signed by this CA but absent from the ledger (e.g. ledger lost).
    UnknownSerial,
}

pub type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(OffsetDateTime::now_utc)
}

/// The CA.  Holds the signing key in memory.
pub struct CertificateAuthority {
    config: CaConfig,
    key: KeyPair,
    cert_pem: String,
    /// Reconstructed issuer (subject DN + key id) used for signing.
    issuer: RcgenCert,
    state: CaState,
    clock: Clock,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("common_name", &self.config.common_name)
            .field("issued", &self.state.issued.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------- helpers

fn validate_cn(cn: &str) -> Result<(), String> {
    if cn.is_empty() {
        return Err("empty".into());
    }
    if cn.chars().count() > 64 {
        return Err("longer than 64 characters".into());
    }
    if cn.chars().any(|c| c.is_control()) {
        return Err("contains control characters".into());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Normalise a user-supplied serial (hex, optional `:` separators / `0x`).
pub fn normalize_serial(input: &str) -> CaResult<String> {
    let t = input.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    let cleaned: String = t.chars().filter(|c| *c != ':').collect();
    if cleaned.is_empty() || cleaned.len() > 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CaError::BadSerial(input.to_string()));
    }
    let lower = cleaned.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches('0');
    if trimmed.is_empty() {
        return Err(CaError::BadSerial(input.to_string()));
    }
    Ok(trimmed.to_string())
}

fn serial_bytes(norm_hex: &str) -> Vec<u8> {
    let padded = if norm_hex.len() % 2 == 1 {
        format!("0{norm_hex}")
    } else {
        norm_hex.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).expect("validated hex"))
        .collect()
}

fn random_serial() -> CaResult<Vec<u8>> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| CaError::Cert(format!("entropy: {e}")))?;
    // Positive INTEGER with a fixed non-zero leading byte: 127 random bits.
    b[0] = (b[0] & 0x7f) | 0x40;
    Ok(b.to_vec())
}

fn ts(dt: OffsetDateTime) -> i64 {
    dt.unix_timestamp()
}

fn from_ts(t: i64) -> CaResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(t).map_err(|e| CaError::Cert(e.to_string()))
}

fn dn_cn(dn: &DistinguishedName) -> Option<String> {
    match dn.get(&DnType::CommonName)? {
        DnValue::Utf8String(s) => Some(s.clone()),
        DnValue::PrintableString(s) => Some(s.as_str().to_string()),
        DnValue::Ia5String(s) => Some(s.as_str().to_string()),
        _ => None,
    }
}

fn san_label(s: &SanType) -> String {
    match s {
        SanType::DnsName(d) => d.as_str().to_string(),
        SanType::IpAddress(ip) => ip.to_string(),
        _ => String::new(),
    }
}

fn dns_allowed(name: &str, policy: &CaPolicy) -> Result<(), String> {
    let lower = name.to_ascii_lowercase();
    if lower.is_empty() || lower.len() > 253 {
        return Err(format!("bad DNS name length {name:?}"));
    }
    if let Some(rest) = lower.strip_prefix("*.") {
        if !policy.allow_wildcards {
            return Err(format!("wildcard name {name:?} not allowed"));
        }
        if !rest.contains('.') && policy.allowed_dns_suffixes.is_empty() {
            return Err(format!("wildcard {name:?} too broad"));
        }
    }
    let host = lower.strip_prefix("*.").unwrap_or(&lower);
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !ok {
            return Err(format!("invalid DNS name {name:?}"));
        }
    }
    if !policy.allowed_dns_suffixes.is_empty() {
        let ok = policy.allowed_dns_suffixes.iter().any(|suf| {
            let suf = suf.trim_start_matches('.').to_ascii_lowercase();
            host == suf || host.ends_with(&format!(".{suf}"))
        });
        if !ok {
            return Err(format!("DNS name {name:?} outside allowed suffixes"));
        }
    }
    Ok(())
}

fn x509_is_ca(c: &X509Certificate<'_>) -> bool {
    matches!(c.basic_constraints(), Ok(Some(bc)) if bc.value.ca)
}

fn parse_pem_cert(pem: &str) -> CaResult<Vec<u8>> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| CaError::Cert(format!("bad PEM: {e}")))?;
    if p.label != "CERTIFICATE" {
        return Err(CaError::Cert(format!("unexpected PEM label {:?}", p.label)));
    }
    Ok(p.contents)
}

impl CertificateAuthority {
    /// Generate a brand-new CA (fresh ECDSA P-256 key).
    pub fn create(config: CaConfig) -> CaResult<Self> {
        Self::create_with_clock(config, system_clock())
    }

    pub fn create_with_clock(config: CaConfig, clock: Clock) -> CaResult<Self> {
        config.validate()?;
        let key = KeyPair::generate()?;
        let now = clock();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, config.common_name.clone());
        if let Some(o) = &config.organization {
            dn.push(DnType::OrganizationName, o.clone());
        }
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = now - time::Duration::seconds(config.backdate_seconds as i64);
        params.not_after = now + time::Duration::days(config.ca_validity_days as i64);
        params.serial_number = Some(SerialNumber::from(random_serial()?));
        params.key_identifier_method = KeyIdMethod::Sha256;
        let cert = params.self_signed(&key)?;
        let cert_pem = cert.pem();
        Ok(Self {
            config,
            key,
            cert_pem,
            issuer: cert,
            state: CaState::default(),
            clock,
        })
    }

    /// Re-open an existing CA from its certificate, key and ledger.
    pub fn from_parts(
        config: CaConfig,
        ca_cert_pem: &str,
        ca_key_pem: &str,
        state: CaState,
    ) -> CaResult<Self> {
        Self::from_parts_with_clock(config, ca_cert_pem, ca_key_pem, state, system_clock())
    }

    pub fn from_parts_with_clock(
        config: CaConfig,
        ca_cert_pem: &str,
        ca_key_pem: &str,
        state: CaState,
        clock: Clock,
    ) -> CaResult<Self> {
        config.validate()?;
        let der = parse_pem_cert(ca_cert_pem).map_err(|e| CaError::BadCaMaterial(e.to_string()))?;
        let (_, x509) = X509Certificate::from_der(&der)
            .map_err(|e| CaError::BadCaMaterial(format!("unparseable CA certificate: {e}")))?;
        if !x509_is_ca(&x509) {
            return Err(CaError::BadCaMaterial("certificate is not a CA".into()));
        }
        // Self-signed check: the CA cert must verify under its own key.
        x509.verify_signature(None).map_err(|_| {
            CaError::BadCaMaterial("CA certificate is not self-signed/valid".into())
        })?;
        let key = KeyPair::from_pem(ca_key_pem)
            .map_err(|_| CaError::BadCaMaterial("CA private key unreadable".into()))?;
        if key.public_key_raw() != x509.public_key().subject_public_key.data.as_ref() {
            return Err(CaError::BadCaMaterial(
                "CA key does not match CA certificate".into(),
            ));
        }
        let now = ts(clock());
        if now > x509.validity().not_after.timestamp() {
            return Err(CaError::BadCaMaterial("CA certificate has expired".into()));
        }
        // The CA's own key usage must allow signing certs and CRLs.
        match x509.key_usage() {
            Ok(Some(ku)) if ku.value.key_cert_sign() && ku.value.crl_sign() => {}
            _ => {
                return Err(CaError::BadCaMaterial(
                    "CA certificate lacks keyCertSign/cRLSign".into(),
                ))
            }
        }
        let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| CaError::BadCaMaterial(e.to_string()))?;
        let issuer = params.self_signed(&key)?;
        Ok(Self {
            config,
            key,
            cert_pem: ca_cert_pem.to_string(),
            issuer,
            state,
            clock,
        })
    }

    pub fn config(&self) -> &CaConfig {
        &self.config
    }

    /// The CA certificate to distribute to relying parties.
    pub fn ca_certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA private key as PEM, for [`CaStore`] only.
    pub(crate) fn ca_private_key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    pub fn state(&self) -> &CaState {
        &self.state
    }

    pub fn issued(&self) -> &[IssuedRecord] {
        &self.state.issued
    }

    pub fn record(&self, serial: &str) -> CaResult<&IssuedRecord> {
        let n = normalize_serial(serial)?;
        self.state
            .issued
            .iter()
            .find(|r| r.serial == n)
            .ok_or(CaError::UnknownSerial(n))
    }

    fn now(&self) -> OffsetDateTime {
        (self.clock)()
    }

    // ------------------------------------------------------------ issuing

    fn resolve_validity(
        &self,
        requested: Option<u32>,
    ) -> CaResult<(OffsetDateTime, OffsetDateTime)> {
        let days = requested.unwrap_or(self.config.default_leaf_validity_days);
        if days == 0 {
            return Err(CaError::Policy("validity must be at least 1 day".into()));
        }
        if days > self.config.max_leaf_validity_days {
            return Err(CaError::Policy(format!(
                "validity {days}d exceeds maximum {}d",
                self.config.max_leaf_validity_days
            )));
        }
        let now = self.now();
        let nb = now - time::Duration::seconds(self.config.backdate_seconds as i64);
        let na = now + time::Duration::days(days as i64);
        let ca_na = self.issuer.params().not_after;
        if na > ca_na {
            return Err(CaError::Policy(
                "requested lifetime outlives the CA certificate".into(),
            ));
        }
        Ok((nb, na))
    }

    fn check_names(&self, sans: &[SanType]) -> CaResult<()> {
        let p = &self.config.policy;
        if sans.len() > p.max_sans {
            return Err(CaError::Policy(format!("more than {} SANs", p.max_sans)));
        }
        for s in sans {
            match s {
                SanType::DnsName(d) => dns_allowed(d.as_str(), p).map_err(CaError::Policy)?,
                SanType::IpAddress(ip) => {
                    if !p.allow_ip_sans {
                        return Err(CaError::Policy("IP SANs not allowed".into()));
                    }
                    if ip_unspecified(ip) {
                        return Err(CaError::Policy("unspecified IP SAN".into()));
                    }
                }
                _ => {
                    return Err(CaError::Policy(
                        "only DNS and IP subject alternative names are supported".into(),
                    ))
                }
            }
        }
        Ok(())
    }

    fn build_leaf_params(
        &self,
        cn: &str,
        sans: Vec<SanType>,
        opts: &IssueOptions,
    ) -> CaResult<(CertificateParams, IssuedRecord)> {
        validate_cn(cn).map_err(|e| CaError::Policy(format!("subject CN: {e}")))?;
        self.check_names(&sans)?;
        if sans.is_empty() && opts.profile != CertProfile::Client {
            return Err(CaError::Policy(
                "server certificates need at least one SAN".into(),
            ));
        }
        let (nb, na) = self.resolve_validity(opts.validity_days)?;
        let serial = random_serial()?;
        let serial_hex = hex(&serial);

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn.to_string());
        params.distinguished_name = dn;
        params.not_before = nb;
        params.not_after = na;
        params.serial_number = Some(SerialNumber::from(serial));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = match opts.profile {
            CertProfile::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
            CertProfile::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
            CertProfile::ServerAndClient => {
                vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ]
            }
        };
        params.use_authority_key_identifier_extension = true;
        if !self.config.crl_distribution_urls.is_empty() {
            params.crl_distribution_points = vec![CrlDistributionPoint {
                uris: self.config.crl_distribution_urls.clone(),
            }];
        }
        let labels: Vec<String> = sans.iter().map(san_label).collect();
        params.subject_alt_names = sans;

        let rec = IssuedRecord {
            serial: serial_hex,
            subject_cn: cn.to_string(),
            sans: labels,
            profile: opts.profile,
            issued_at: ts(self.now()),
            not_before: ts(nb),
            not_after: ts(na),
            revocation: None,
        };
        Ok((params, rec))
    }

    /// Sign a PKCS#10 CSR.  The CSR's signature (proof of possession) is
    /// verified; only its public key, CN and SANs are used.
    pub fn sign_csr_pem(
        &mut self,
        csr_pem: &str,
        opts: &IssueOptions,
    ) -> CaResult<IssuedCertificate> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| CaError::Csr(e.to_string()))?;
        let sans = csr.params.subject_alt_names.clone();
        let cn = dn_cn(&csr.params.distinguished_name)
            .or_else(|| sans.iter().map(san_label).find(|l| !l.is_empty()))
            .ok_or_else(|| CaError::Csr("no subject CN and no SAN".into()))?;
        let (params, rec) = self.build_leaf_params(&cn, sans, opts)?;
        let cert = params.signed_by(&csr.public_key, &self.issuer, &self.key)?;
        Ok(self.finish_issue(cert, rec))
    }

    /// Generate a key pair server-side and issue for it (for devices that
    /// cannot make a CSR).  The key is returned once and not retained.
    pub fn issue_with_generated_key(
        &mut self,
        common_name: &str,
        san_names: &[String],
        opts: &IssueOptions,
    ) -> CaResult<GeneratedCertificate> {
        let sans = san_names
            .iter()
            .map(|s| match s.parse::<IpAddr>() {
                Ok(ip) => Ok(SanType::IpAddress(ip)),
                Err(_) => rcgen::Ia5String::try_from(s.clone())
                    .map(SanType::DnsName)
                    .map_err(|_| CaError::Policy(format!("invalid SAN {s:?}"))),
            })
            .collect::<CaResult<Vec<_>>>()?;
        let (params, rec) = self.build_leaf_params(common_name, sans, opts)?;
        let leaf_key = KeyPair::generate()?;
        let cert = params.signed_by(&leaf_key, &self.issuer, &self.key)?;
        let issued = self.finish_issue(cert, rec);
        Ok(GeneratedCertificate {
            certificate: issued,
            key_pem: leaf_key.serialize_pem(),
        })
    }

    fn finish_issue(&mut self, cert: RcgenCert, rec: IssuedRecord) -> IssuedCertificate {
        let out = IssuedCertificate {
            cert_pem: cert.pem(),
            serial: rec.serial.clone(),
            not_before: rec.not_before,
            not_after: rec.not_after,
        };
        tracing::info!(
            serial = %rec.serial,
            subject = %rec.subject_cn,
            not_after = rec.not_after,
            "certificate issued"
        );
        self.state.issued.push(rec);
        out
    }

    // --------------------------------------------------------- revocation

    /// Revoke by serial.  Returns `true` if newly revoked, `false` if it was
    /// already revoked (the original time/reason are kept).
    pub fn revoke(&mut self, serial: &str, reason: RevokeReason) -> CaResult<bool> {
        let n = normalize_serial(serial)?;
        let now = ts(self.now());
        let rec = self
            .state
            .issued
            .iter_mut()
            .find(|r| r.serial == n)
            .ok_or_else(|| CaError::UnknownSerial(n.clone()))?;
        if rec.revocation.is_some() {
            return Ok(false);
        }
        rec.revocation = Some(Revocation {
            revoked_at: now,
            reason,
        });
        tracing::info!(serial = %n, ?reason, "certificate revoked");
        Ok(true)
    }

    /// Build and sign a fresh CRL.  Increments the monotonic CRL number.
    /// Revoked certificates that have already expired are omitted (RFC 5280
    /// 3.3 permits it and it keeps the list bounded).
    pub fn generate_crl(&mut self) -> CaResult<IssuedCrl> {
        let now = self.now();
        let now_ts = ts(now);
        let mut revoked = Vec::new();
        for r in &self.state.issued {
            if let Some(rv) = &r.revocation {
                if r.not_after < now_ts {
                    continue;
                }
                revoked.push(RevokedCertParams {
                    serial_number: SerialNumber::from(serial_bytes(&r.serial)),
                    revocation_time: from_ts(rv.revoked_at)?,
                    reason_code: Some(rv.reason.to_rcgen()),
                    invalidity_date: None,
                });
            }
        }
        let number = self.state.crl_number + 1;
        let next = now + time::Duration::hours(self.config.crl_validity_hours as i64);
        let count = revoked.len();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: next,
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: revoked,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&self.issuer, &self.key)?;
        // Only consume the number once the CRL is really signed.
        self.state.crl_number = number;
        Ok(IssuedCrl {
            pem: crl.pem()?,
            der: crl.der().to_vec(),
            crl_number: number,
            this_update: ts(now),
            next_update: ts(next),
            revoked_count: count,
        })
    }

    // ------------------------------------------------------- verification

    /// Check a leaf certificate against this CA: signature, validity window
    /// and the revocation ledger.
    pub fn verify_certificate(&self, cert_pem: &str) -> CaResult<CertStatus> {
        let der = parse_pem_cert(cert_pem)?;
        let (_, leaf) = X509Certificate::from_der(&der)
            .map_err(|e| CaError::Cert(format!("unparseable: {e}")))?;
        let ca_der = parse_pem_cert(&self.cert_pem)?;
        let (_, ca) = X509Certificate::from_der(&ca_der)
            .map_err(|e| CaError::Cert(format!("CA unparseable: {e}")))?;
        if leaf.issuer().as_raw() != ca.subject().as_raw()
            || leaf.verify_signature(Some(ca.public_key())).is_err()
        {
            return Ok(CertStatus::UntrustedIssuer);
        }
        let now = ts(self.now());
        if now < leaf.validity().not_before.timestamp() {
            return Ok(CertStatus::NotYetValid);
        }
        if now > leaf.validity().not_after.timestamp() {
            return Ok(CertStatus::Expired);
        }
        let serial = hex_trim(leaf.tbs_certificate.raw_serial());
        match self.state.issued.iter().find(|r| r.serial == serial) {
            None => Ok(CertStatus::UnknownSerial),
            Some(r) => match &r.revocation {
                Some(rv) => Ok(CertStatus::Revoked {
                    revoked_at: rv.revoked_at,
                    reason: rv.reason,
                }),
                None => Ok(CertStatus::Valid),
            },
        }
    }
}

fn ip_unspecified(ip: &IpAddr) -> bool {
    ip.is_unspecified()
}

fn hex_trim(raw: &[u8]) -> String {
    let h = hex(raw);
    let t = h.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

// ------------------------------------------------------------------ store

/// Filesystem persistence for a CA: `ca.crt`, `ca.key` (mode 0600, atomic),
/// `state.json`, plus an optional published `ca.crl`.  The directory is
/// supplied by the caller (declarative config); nothing is compiled in.
#[derive(Debug, Clone)]
pub struct CaStore {
    dir: PathBuf,
}

impl CaStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn exists(&self) -> bool {
        self.dir.join("ca.key").exists() && self.dir.join("ca.crt").exists()
    }

    fn io<T>(r: std::io::Result<T>, what: &str) -> CaResult<T> {
        r.map_err(|e| CaError::Store(format!("{what}: {}", e.kind())))
    }

    pub fn save(&self, ca: &CertificateAuthority) -> CaResult<()> {
        Self::io(std::fs::create_dir_all(&self.dir), "create dir")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Self::io(
                std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700)),
                "chmod dir",
            )?;
        }
        write_atomic(
            &self.dir.join("ca.key"),
            ca.ca_private_key_pem().as_bytes(),
            0o600,
        )?;
        write_atomic(
            &self.dir.join("ca.crt"),
            ca.ca_certificate_pem().as_bytes(),
            0o644,
        )?;
        let json = serde_json::to_vec_pretty(ca.state())
            .map_err(|e| CaError::Store(format!("serialize state: {e}")))?;
        write_atomic(&self.dir.join("state.json"), &json, 0o600)
    }

    pub fn load(&self, config: CaConfig, clock: Clock) -> CaResult<CertificateAuthority> {
        let key_path = self.dir.join("ca.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = Self::io(std::fs::metadata(&key_path), "stat ca.key")?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(CaError::Store(format!(
                    "ca.key is accessible to group/others (mode {:o}); refusing to load",
                    mode & 0o777
                )));
            }
        }
        let key = Self::io(std::fs::read_to_string(&key_path), "read ca.key")?;
        let crt = Self::io(
            std::fs::read_to_string(self.dir.join("ca.crt")),
            "read ca.crt",
        )?;
        let state = match std::fs::read(self.dir.join("state.json")) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| CaError::Store(format!("state.json corrupt: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CaState::default(),
            Err(e) => return Err(CaError::Store(format!("read state.json: {}", e.kind()))),
        };
        CertificateAuthority::from_parts_with_clock(config, &crt, &key, state, clock)
    }

    /// Load the CA if present, otherwise create and persist one.
    pub fn load_or_create(&self, config: CaConfig, clock: Clock) -> CaResult<CertificateAuthority> {
        if self.exists() {
            self.load(config, clock)
        } else {
            let ca = CertificateAuthority::create_with_clock(config, clock)?;
            self.save(&ca)?;
            Ok(ca)
        }
    }

    /// Publish a CRL (world-readable by design) next to the CA files.
    pub fn publish_crl(&self, crl: &IssuedCrl) -> CaResult<PathBuf> {
        let p = self.dir.join("ca.crl");
        write_atomic(&p, crl.pem.as_bytes(), 0o644)?;
        Ok(p)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> CaResult<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(&tmp)
        .map_err(|e| CaError::Store(format!("create temp file: {}", e.kind())))?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|e| CaError::Store(format!("write temp file: {}", e.kind())))?;
    std::fs::rename(&tmp, path).map_err(|e| CaError::Store(format!("rename: {}", e.kind())))
}

/// Compact CA status for dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlSummary {
    pub crl_number: u64,
    pub issued: usize,
    pub revoked: usize,
}

impl CertificateAuthority {
    pub fn crl_summary(&self) -> CrlSummary {
        CrlSummary {
            crl_number: self.state.crl_number,
            issued: self.state.issued.len(),
            revoked: self
                .state
                .issued
                .iter()
                .filter(|r| r.revocation.is_some())
                .count(),
        }
    }
}

/// Count of ledger entries per state, for status pages.
pub fn summarize(ca: &CertificateAuthority, now: i64) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for r in ca.issued() {
        let k = if r.revocation.is_some() {
            "revoked"
        } else if r.not_after < now {
            "expired"
        } else {
            "active"
        };
        *m.entry(k).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests;
