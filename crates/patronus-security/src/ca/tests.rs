#![allow(clippy::field_reassign_with_default)]
use super::*;
use rcgen::{CertificateParams as RP, KeyPair as RK};
use std::sync::Mutex;
use x509_parser::prelude::*;
use x509_parser::revocation_list::CertificateRevocationList;

const T0: i64 = 1_800_000_000; // fixed "now" (2027-01-15)

struct TestClock(Arc<Mutex<i64>>);

impl TestClock {
    fn new() -> (Self, Clock) {
        let t = Arc::new(Mutex::new(T0));
        let t2 = t.clone();
        let clock: Clock =
            Arc::new(move || OffsetDateTime::from_unix_timestamp(*t2.lock().unwrap()).unwrap());
        (TestClock(t), clock)
    }
    fn advance_days(&self, d: i64) {
        *self.0.lock().unwrap() += d * 86_400;
    }
    fn set(&self, t: i64) {
        *self.0.lock().unwrap() = t;
    }
}

fn new_ca() -> (CertificateAuthority, TestClock) {
    new_ca_with(CaConfig::default())
}

fn new_ca_with(cfg: CaConfig) -> (CertificateAuthority, TestClock) {
    let (tc, clock) = TestClock::new();
    (
        CertificateAuthority::create_with_clock(cfg, clock).unwrap(),
        tc,
    )
}

fn csr_pem(cn: Option<&str>, sans: &[&str]) -> (String, RK) {
    let key = RK::generate().unwrap();
    let mut p = RP::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name = DistinguishedName::new();
    if let Some(cn) = cn {
        p.distinguished_name.push(DnType::CommonName, cn);
    }
    (p.serialize_request(&key).unwrap().pem().unwrap(), key)
}

fn der_of(pem: &str) -> Vec<u8> {
    parse_x509_pem(pem.as_bytes()).unwrap().1.contents
}

fn crl_der(pem: &str) -> Vec<u8> {
    let p = parse_x509_pem(pem.as_bytes()).unwrap().1;
    assert_eq!(p.label, "X509 CRL");
    p.contents
}

fn hex_of(raw: &[u8]) -> String {
    hex_trim(raw)
}

#[test]
fn ca_cert_is_constrained_ca_with_signing_usages() {
    let (ca, _) = new_ca();
    let der = der_of(ca.ca_certificate_pem());
    let (_, c) = X509Certificate::from_der(&der).unwrap();
    let bc = c.basic_constraints().unwrap().unwrap();
    assert!(bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, Some(0));
    let ku = c.key_usage().unwrap().unwrap().value;
    assert!(ku.key_cert_sign() && ku.crl_sign());
    assert!(!ku.digital_signature());
    c.verify_signature(None).expect("self-signed");
    assert_eq!(
        c.validity().not_after.timestamp() - c.validity().not_before.timestamp(),
        3650 * 86_400 + 300
    );
    assert!(c.subject().to_string().contains("Patronus Local CA"));
}

#[test]
fn csr_is_signed_with_server_profile_and_verifies_against_ca() {
    let (mut ca, _) = new_ca();
    let (csr, key) = csr_pem(
        Some("router.example.lan"),
        &["router.example.lan", "10.0.0.1"],
    );
    let out = ca.sign_csr_pem(&csr, &IssueOptions::default()).unwrap();

    let der = der_of(&out.cert_pem);
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    let ca_der = der_of(ca.ca_certificate_pem());
    let (_, cac) = X509Certificate::from_der(&ca_der).unwrap();
    leaf.verify_signature(Some(cac.public_key()))
        .expect("leaf signed by CA");
    assert_eq!(leaf.issuer().as_raw(), cac.subject().as_raw());
    assert!(!x509_is_ca(&leaf));
    // subject key is the CSR key, not a CA-generated one
    assert_eq!(
        leaf.public_key().subject_public_key.data.as_ref(),
        key.public_key_raw()
    );
    // validity: default 365 days (+ backdate)
    let v = leaf.validity();
    assert_eq!(v.not_after.timestamp(), T0 + 365 * 86_400);
    assert_eq!(v.not_before.timestamp(), T0 - 300);
    // EKU / KU
    let eku = leaf.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && !eku.client_auth);
    assert!(leaf.key_usage().unwrap().unwrap().value.digital_signature());
    // SANs
    let san = leaf.subject_alternative_name().unwrap().unwrap().value;
    let names: Vec<String> = san.general_names.iter().map(|g| g.to_string()).collect();
    assert!(
        names.iter().any(|n| n.contains("router.example.lan")),
        "{names:?}"
    );
    assert_eq!(san.general_names.len(), 2);
    // serial in ledger matches the cert
    assert_eq!(hex_of(leaf.tbs_certificate.raw_serial()), out.serial);
    let rec = ca.record(&out.serial).unwrap();
    assert_eq!(rec.subject_cn, "router.example.lan");
    assert_eq!(rec.not_after, T0 + 365 * 86_400);
    assert!(rec.revocation.is_none());
    // authority key identifier present
    assert!(leaf.iter_extensions().any(|e| matches!(
        e.parsed_extension(),
        ParsedExtension::AuthorityKeyIdentifier(_)
    )));
}

#[test]
fn client_profile_needs_no_san_and_gets_client_auth_only() {
    let (mut ca, _) = new_ca();
    let (csr, _) = csr_pem(Some("device-7"), &[]);
    let out = ca
        .sign_csr_pem(
            &csr,
            &IssueOptions {
                profile: CertProfile::Client,
                validity_days: Some(30),
            },
        )
        .unwrap();
    let der = der_of(&out.cert_pem);
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    let eku = leaf.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth);
    assert_eq!(out.not_after, T0 + 30 * 86_400);
    // a server cert with no SAN is refused
    let err = ca.sign_csr_pem(&csr, &IssueOptions::default()).unwrap_err();
    assert!(matches!(err, CaError::Policy(_)), "{err}");
}

#[test]
fn csr_cannot_request_ca_status_or_usages() {
    let (mut ca, _) = new_ca();
    let key = RK::generate().unwrap();
    let mut p = RP::new(vec!["evil.example.lan".to_string()]).unwrap();
    p.distinguished_name
        .push(DnType::CommonName, "evil.example.lan");
    // rcgen refuses to *encode* a CA request, so ask for CA-ish usages instead
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::Any,
        ExtendedKeyUsagePurpose::CodeSigning,
    ];
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let csr = p.serialize_request(&key).unwrap().pem().unwrap();
    let out = ca.sign_csr_pem(&csr, &IssueOptions::default()).unwrap();
    let der = der_of(&out.cert_pem);
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    assert!(!x509_is_ca(&leaf), "CSR escalated to CA");
    let ku = leaf.key_usage().unwrap().unwrap().value;
    assert!(ku.digital_signature() && !ku.key_cert_sign() && !ku.crl_sign());
    let eku = leaf.extended_key_usage().unwrap().unwrap().value;
    assert!(
        eku.server_auth && !eku.any && !eku.code_signing,
        "requested EKU must be ignored"
    );
}

#[test]
fn tampered_or_garbage_csr_is_rejected_and_nothing_is_recorded() {
    let (mut ca, _) = new_ca();
    let (csr, _) = csr_pem(Some("a.example.lan"), &["a.example.lan"]);
    // flip a bit near the end (inside the signature)
    let mut der = der_of(&csr);
    let n = der.len();
    der[n - 5] ^= 0x01;
    let bad = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64_std(&der)
    );
    assert!(matches!(
        ca.sign_csr_pem(&bad, &IssueOptions::default()),
        Err(CaError::Csr(_))
    ));
    assert!(matches!(
        ca.sign_csr_pem("not a csr", &IssueOptions::default()),
        Err(CaError::Csr(_))
    ));
    assert!(matches!(
        ca.sign_csr_pem("", &IssueOptions::default()),
        Err(CaError::Csr(_))
    ));
    assert!(ca.issued().is_empty());
}

fn base64_std(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for ch in data.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= ch.len() {
                s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[test]
fn policy_rejections() {
    let mut cfg = CaConfig::default();
    cfg.policy.allowed_dns_suffixes = vec!["example.lan".into()];
    cfg.policy.max_sans = 3;
    let (mut ca, _) = new_ca_with(cfg);
    let opts = IssueOptions::default();

    let (c, _) = csr_pem(Some("x"), &["host.other.org"]);
    assert!(matches!(ca.sign_csr_pem(&c, &opts), Err(CaError::Policy(m)) if m.contains("suffix")));
    // suffix match is label-aligned: "evilexample.lan" must not pass
    let (c, _) = csr_pem(Some("x"), &["evilexample.lan"]);
    assert!(matches!(
        ca.sign_csr_pem(&c, &opts),
        Err(CaError::Policy(_))
    ));
    let (c, _) = csr_pem(Some("x"), &["*.example.lan"]);
    assert!(
        matches!(ca.sign_csr_pem(&c, &opts), Err(CaError::Policy(m)) if m.contains("wildcard"))
    );
    let (c, _) = csr_pem(
        Some("x"),
        &[
            "a.example.lan",
            "b.example.lan",
            "c.example.lan",
            "d.example.lan",
        ],
    );
    assert!(matches!(ca.sign_csr_pem(&c, &opts), Err(CaError::Policy(m)) if m.contains("SANs")));
    let (c, _) = csr_pem(Some("x"), &["0.0.0.0"]);
    assert!(matches!(
        ca.sign_csr_pem(&c, &opts),
        Err(CaError::Policy(_))
    ));
    // allowed one passes, suffix itself and a subdomain
    let (c, _) = csr_pem(Some("ok"), &["example.lan", "A.Sub.Example.LAN"]);
    ca.sign_csr_pem(&c, &opts).unwrap();
    // CN too long
    let long = "a".repeat(65);
    let (c, _) = csr_pem(Some(&long), &["a.example.lan"]);
    assert!(matches!(
        ca.sign_csr_pem(&c, &opts),
        Err(CaError::Policy(_))
    ));
    assert_eq!(
        ca.issued().len(),
        1,
        "rejected requests must not hit the ledger"
    );
}

#[test]
fn wildcard_and_ip_policy_toggles() {
    let mut cfg = CaConfig::default();
    cfg.policy.allow_wildcards = true;
    cfg.policy.allow_ip_sans = false;
    let (mut ca, _) = new_ca_with(cfg);
    let (c, _) = csr_pem(Some("w"), &["*.lab.example.lan"]);
    ca.sign_csr_pem(&c, &IssueOptions::default()).unwrap();
    let (c, _) = csr_pem(Some("w"), &["*.lan"]);
    assert!(
        ca.sign_csr_pem(&c, &IssueOptions::default()).is_err(),
        "bare-TLD wildcard"
    );
    let (c, _) = csr_pem(Some("w"), &["192.0.2.5"]);
    assert!(matches!(
        ca.sign_csr_pem(&c, &IssueOptions::default()),
        Err(CaError::Policy(m)) if m.contains("IP")
    ));
}

#[test]
fn validity_bounds_enforced() {
    let (mut ca, _) = new_ca();
    let (c, _) = csr_pem(Some("v"), &["v.example.lan"]);
    let mk = |d| IssueOptions {
        profile: CertProfile::Server,
        validity_days: Some(d),
    };
    assert!(matches!(
        ca.sign_csr_pem(&c, &mk(0)),
        Err(CaError::Policy(_))
    ));
    assert!(matches!(
        ca.sign_csr_pem(&c, &mk(826)),
        Err(CaError::Policy(_))
    ));
    assert!(ca.sign_csr_pem(&c, &mk(825)).is_ok());

    // leaf may not outlive the CA
    let mut cfg = CaConfig::default();
    cfg.ca_validity_days = 100;
    cfg.max_leaf_validity_days = 100;
    cfg.default_leaf_validity_days = 50;
    let (mut ca, tc) = new_ca_with(cfg);
    tc.advance_days(10);
    let (c, _) = csr_pem(Some("v"), &["v.example.lan"]);
    assert!(matches!(
        ca.sign_csr_pem(&c, &IssueOptions { profile: CertProfile::Server, validity_days: Some(95) }),
        Err(CaError::Policy(m)) if m.contains("outlives")
    ));
    assert!(ca
        .sign_csr_pem(
            &c,
            &IssueOptions {
                profile: CertProfile::Server,
                validity_days: Some(85)
            }
        )
        .is_ok());
}

#[test]
fn serials_are_unique_positive_and_random_looking() {
    let (mut ca, _) = new_ca();
    let mut seen = std::collections::HashSet::new();
    for i in 0..50 {
        let g = ca
            .issue_with_generated_key(
                &format!("h{i}"),
                &[format!("h{i}.example.lan")],
                &IssueOptions::default(),
            )
            .unwrap();
        assert_eq!(g.certificate.serial.len(), 32);
        assert!(
            g.certificate.serial.starts_with(['4', '5', '6', '7']),
            "top bit clear, bit 6 set"
        );
        assert!(seen.insert(g.certificate.serial.clone()));
    }
}

#[test]
fn generated_key_matches_certificate_and_is_not_retained_or_logged() {
    let (mut ca, _) = new_ca();
    let g = ca
        .issue_with_generated_key(
            "dev",
            &["dev.example.lan".into(), "2001:db8::1".into()],
            &IssueOptions::default(),
        )
        .unwrap();
    let key = RK::from_pem(g.private_key_pem()).unwrap();
    let der = der_of(&g.certificate.cert_pem);
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    assert_eq!(
        leaf.public_key().subject_public_key.data.as_ref(),
        key.public_key_raw()
    );
    assert_eq!(
        ca.verify_certificate(&g.certificate.cert_pem).unwrap(),
        CertStatus::Valid
    );
    for dbg in [
        format!("{g:?}"),
        format!("{ca:?}"),
        format!("{:?}", ca.state()),
    ] {
        assert!(!dbg.contains("PRIVATE KEY"), "{dbg}");
    }
    assert!(!serde_json::to_string(ca.state())
        .unwrap()
        .contains("PRIVATE"));
    let bad = ca.issue_with_generated_key("dev", &["bad name!".into()], &IssueOptions::default());
    assert!(matches!(bad, Err(CaError::Policy(_))));
}

#[test]
fn serial_normalisation() {
    assert_eq!(normalize_serial("0x00AB:cd").unwrap(), "abcd");
    assert_eq!(normalize_serial(" 0F ").unwrap(), "f");
    for bad in ["", "0", "00:00", "xyz", "12g4", &"f".repeat(65)] {
        assert!(
            matches!(normalize_serial(bad), Err(CaError::BadSerial(_))),
            "{bad}"
        );
    }
    assert_eq!(serial_bytes("abc"), vec![0x0a, 0xbc]);
}

#[test]
fn revoke_semantics() {
    let (mut ca, tc) = new_ca();
    let g = ca
        .issue_with_generated_key("a", &["a.example.lan".into()], &IssueOptions::default())
        .unwrap();
    let s = g.certificate.serial.clone();
    assert!(matches!(
        ca.revoke("deadbeef", RevokeReason::Unspecified),
        Err(CaError::UnknownSerial(_))
    ));
    assert!(matches!(
        ca.revoke("zz", RevokeReason::Unspecified),
        Err(CaError::BadSerial(_))
    ));
    assert!(ca
        .revoke(&s.to_uppercase(), RevokeReason::KeyCompromise)
        .unwrap());
    tc.advance_days(1);
    // second revoke is a no-op: original time and reason kept
    assert!(!ca.revoke(&s, RevokeReason::Superseded).unwrap());
    let rv = ca.record(&s).unwrap().revocation.clone().unwrap();
    assert_eq!(rv.reason, RevokeReason::KeyCompromise);
    assert_eq!(rv.revoked_at, T0);
    assert_eq!(
        ca.verify_certificate(&g.certificate.cert_pem).unwrap(),
        CertStatus::Revoked {
            revoked_at: T0,
            reason: RevokeReason::KeyCompromise
        }
    );
}

fn parse_crl(pem: &str, ca: &CertificateAuthority) -> Vec<(String, Option<u8>)> {
    let der = crl_der(pem);
    let (_, crl) = CertificateRevocationList::from_der(&der).unwrap();
    let ca_der = der_of(ca.ca_certificate_pem());
    let (_, cac) = X509Certificate::from_der(&ca_der).unwrap();
    crl.verify_signature(cac.public_key())
        .expect("CRL signed by CA");
    assert_eq!(crl.issuer().as_raw(), cac.subject().as_raw());
    crl.iter_revoked_certificates()
        .map(|r| (hex_of(r.raw_serial()), r.reason_code().map(|(_, c)| c.0)))
        .collect()
}

#[test]
fn crl_lists_exactly_the_revoked_serials_with_reasons_and_verifies() {
    let (mut ca, _) = new_ca();
    let mut serials = vec![];
    for i in 0..4 {
        let g = ca
            .issue_with_generated_key(
                &format!("n{i}"),
                &[format!("n{i}.example.lan")],
                &IssueOptions::default(),
            )
            .unwrap();
        serials.push(g.certificate.serial);
    }
    ca.revoke(&serials[1], RevokeReason::KeyCompromise).unwrap();
    ca.revoke(&serials[3], RevokeReason::CessationOfOperation)
        .unwrap();
    let crl = ca.generate_crl().unwrap();
    assert_eq!(crl.revoked_count, 2);
    assert_eq!(crl.crl_number, 1);
    assert_eq!(crl.next_update - crl.this_update, 168 * 3600);
    let mut listed = parse_crl(&crl.pem, &ca);
    listed.sort();
    let mut want = vec![
        (serials[1].clone(), Some(1u8)),
        (serials[3].clone(), Some(5u8)),
    ];
    want.sort();
    assert_eq!(listed, want);

    let der = crl_der(&crl.pem);
    assert_eq!(der, crl.der);
    let (_, p) = CertificateRevocationList::from_der(&der).unwrap();
    assert_eq!(p.last_update().timestamp(), T0);
    assert_eq!(p.next_update().unwrap().timestamp(), crl.next_update);
    assert_eq!(p.crl_number().map(|n| n.to_string()), Some("1".to_string()));
}

#[test]
fn crl_number_is_monotonic_and_empty_crl_is_valid() {
    let (mut ca, _) = new_ca();
    let a = ca.generate_crl().unwrap();
    assert_eq!(a.revoked_count, 0);
    assert!(parse_crl(&a.pem, &ca).is_empty());
    let b = ca.generate_crl().unwrap();
    assert_eq!((a.crl_number, b.crl_number), (1, 2));
    assert_eq!(ca.state().crl_number, 2);
}

#[test]
fn expired_revoked_certs_drop_off_the_crl_but_stay_in_the_ledger() {
    let (mut ca, tc) = new_ca();
    let g = ca
        .issue_with_generated_key(
            "s",
            &["s.example.lan".into()],
            &IssueOptions {
                profile: CertProfile::Server,
                validity_days: Some(10),
            },
        )
        .unwrap();
    let long = ca
        .issue_with_generated_key("l", &["l.example.lan".into()], &IssueOptions::default())
        .unwrap();
    ca.revoke(&g.certificate.serial, RevokeReason::Superseded)
        .unwrap();
    ca.revoke(&long.certificate.serial, RevokeReason::Superseded)
        .unwrap();
    assert_eq!(ca.generate_crl().unwrap().revoked_count, 2);
    tc.advance_days(11);
    let crl = ca.generate_crl().unwrap();
    assert_eq!(crl.revoked_count, 1);
    assert_eq!(parse_crl(&crl.pem, &ca)[0].0, long.certificate.serial);
    assert!(ca
        .record(&g.certificate.serial)
        .unwrap()
        .revocation
        .is_some());
    // expired takes precedence in verification only for the validity window
    assert_eq!(
        ca.verify_certificate(&g.certificate.cert_pem).unwrap(),
        CertStatus::Expired
    );
}

#[test]
fn crl_distribution_point_embedded_when_configured() {
    let mut cfg = CaConfig::default();
    cfg.crl_distribution_urls = vec!["http://pki.example.lan/ca.crl".into()];
    let (mut ca, _) = new_ca_with(cfg);
    let g = ca
        .issue_with_generated_key("c", &["c.example.lan".into()], &IssueOptions::default())
        .unwrap();
    let der = der_of(&g.certificate.cert_pem);
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    let found = leaf.iter_extensions().any(|e| match e.parsed_extension() {
        ParsedExtension::CRLDistributionPoints(p) => {
            format!("{p:?}").contains("pki.example.lan/ca.crl")
        }
        _ => false,
    });
    assert!(found);
    // and absent by default
    let (mut ca2, _) = new_ca();
    let g2 = ca2
        .issue_with_generated_key("c", &["c.example.lan".into()], &IssueOptions::default())
        .unwrap();
    let d2 = der_of(&g2.certificate.cert_pem);
    let (_, l2) = X509Certificate::from_der(&d2).unwrap();
    assert!(!l2.iter_extensions().any(|e| matches!(
        e.parsed_extension(),
        ParsedExtension::CRLDistributionPoints(_)
    )));
}

#[test]
fn verify_certificate_statuses() {
    let (mut ca, tc) = new_ca();
    let g = ca
        .issue_with_generated_key("v", &["v.example.lan".into()], &IssueOptions::default())
        .unwrap();
    let pem = g.certificate.cert_pem.clone();
    assert_eq!(ca.verify_certificate(&pem).unwrap(), CertStatus::Valid);

    // not yet valid (clock before notBefore)
    tc.set(T0 - 3600);
    assert_eq!(
        ca.verify_certificate(&pem).unwrap(),
        CertStatus::NotYetValid
    );
    tc.set(T0 + 366 * 86_400);
    assert_eq!(ca.verify_certificate(&pem).unwrap(), CertStatus::Expired);
    tc.set(T0);

    // a different CA with the same subject must not be trusted
    let (mut other, _) = new_ca();
    let og = other
        .issue_with_generated_key("v", &["v.example.lan".into()], &IssueOptions::default())
        .unwrap();
    assert_eq!(
        ca.verify_certificate(&og.certificate.cert_pem).unwrap(),
        CertStatus::UntrustedIssuer
    );
    // the CA's own cert is not a leaf of itself... it is self-signed, issuer matches, signature
    // verifies, but it is not in the ledger
    assert_eq!(
        ca.verify_certificate(ca.ca_certificate_pem()).unwrap(),
        CertStatus::UnknownSerial
    );

    // lost ledger
    let reopened = CertificateAuthority::from_parts_with_clock(
        CaConfig::default(),
        ca.ca_certificate_pem(),
        &ca.ca_private_key_pem(),
        CaState::default(),
        Arc::new(|| OffsetDateTime::from_unix_timestamp(T0).unwrap()),
    )
    .unwrap();
    assert_eq!(
        reopened.verify_certificate(&pem).unwrap(),
        CertStatus::UnknownSerial
    );
    assert!(ca.verify_certificate("garbage").is_err());
}

#[test]
fn store_roundtrip_keeps_ledger_crl_number_and_signs_under_the_same_ca() {
    let dir = tempfile::tempdir().unwrap();
    let store = CaStore::new(dir.path().join("pki"));
    assert!(!store.exists());
    let (tc, clock) = TestClock::new();
    let mut ca = store
        .load_or_create(CaConfig::default(), clock.clone())
        .unwrap();
    assert!(store.exists());
    let g1 = ca
        .issue_with_generated_key("one", &["one.example.lan".into()], &IssueOptions::default())
        .unwrap();
    ca.revoke(&g1.certificate.serial, RevokeReason::Superseded)
        .unwrap();
    ca.generate_crl().unwrap();
    let ca_pem = ca.ca_certificate_pem().to_string();
    store.save(&ca).unwrap();
    drop(ca);

    let mut ca2 = store.load_or_create(CaConfig::default(), clock).unwrap();
    assert_eq!(
        ca2.ca_certificate_pem(),
        ca_pem,
        "load must not regenerate the CA"
    );
    assert_eq!(ca2.issued().len(), 1);
    assert_eq!(ca2.state().crl_number, 1);
    assert!(matches!(
        ca2.verify_certificate(&g1.certificate.cert_pem).unwrap(),
        CertStatus::Revoked { .. }
    ));
    tc.advance_days(1);
    // new issuance after reload chains to the ORIGINAL CA certificate
    let (csr, _) = csr_pem(Some("two"), &["two.example.lan"]);
    let out = ca2.sign_csr_pem(&csr, &IssueOptions::default()).unwrap();
    let ca_der = der_of(&ca_pem);
    let (_, cac) = X509Certificate::from_der(&ca_der).unwrap();
    let ld = der_of(&out.cert_pem);
    let (_, leaf) = X509Certificate::from_der(&ld).unwrap();
    leaf.verify_signature(Some(cac.public_key())).unwrap();
    assert_eq!(leaf.issuer().as_raw(), cac.subject().as_raw());
    // AKI of the new leaf equals the CA SKI
    let ski = cac
        .iter_extensions()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
            _ => None,
        });
    let aki = leaf
        .iter_extensions()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(k) => {
                k.key_identifier.as_ref().map(|k| k.0.to_vec())
            }
            _ => None,
        });
    assert!(ski.is_some());
    assert_eq!(ski, aki);
    // CRL after reload continues numbering and still verifies under the original CA
    let crl = ca2.generate_crl().unwrap();
    assert_eq!(crl.crl_number, 2);
    parse_crl(&crl.pem, &ca2);
    let p = store.publish_crl(&crl).unwrap();
    assert_eq!(std::fs::read_to_string(p).unwrap(), crl.pem);
}

#[cfg(unix)]
#[test]
fn store_permissions_and_no_key_leakage_to_state() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = CaStore::new(dir.path().join("pki"));
    let (_tc, clock) = TestClock::new();
    let ca = store
        .load_or_create(CaConfig::default(), clock.clone())
        .unwrap();
    let mode = |f: &str| {
        std::fs::metadata(store.dir().join(f))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("ca.key"), 0o600);
    assert_eq!(mode("state.json"), 0o600);
    assert_eq!(mode("ca.crt"), 0o644);
    assert_eq!(
        std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for f in ["ca.crt", "state.json"] {
        let t = std::fs::read_to_string(store.dir().join(f)).unwrap();
        assert!(!t.contains("PRIVATE KEY"), "{f} leaks key");
    }
    // overwrite keeps mode (atomic replace)
    store.save(&ca).unwrap();
    assert_eq!(mode("ca.key"), 0o600);
    assert!(!store.dir().join("ca.tmp").exists() && !store.dir().join("ca.key.tmp").exists());
    // group/world-readable key is refused
    std::fs::set_permissions(
        store.dir().join("ca.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let err = store.load(CaConfig::default(), clock).unwrap_err();
    assert!(
        matches!(&err, CaError::Store(m) if m.contains("refusing")),
        "{err}"
    );
    assert!(!err.to_string().contains("PRIVATE"));
}

#[test]
fn from_parts_rejects_bad_material() {
    let (ca, _) = new_ca();
    let (other, _) = new_ca();
    let st = CaState::default();
    let clock = || -> Clock { Arc::new(|| OffsetDateTime::from_unix_timestamp(T0).unwrap()) };
    // key from a different CA
    let e = CertificateAuthority::from_parts_with_clock(
        CaConfig::default(),
        ca.ca_certificate_pem(),
        &other.ca_private_key_pem(),
        st.clone(),
        clock(),
    )
    .unwrap_err();
    assert!(
        matches!(&e, CaError::BadCaMaterial(m) if m.contains("does not match")),
        "{e}"
    );
    // leaf certificate is not a CA
    let mut ca_m = new_ca().0;
    let g = ca_m
        .issue_with_generated_key("l", &["l.example.lan".into()], &IssueOptions::default())
        .unwrap();
    let e = CertificateAuthority::from_parts_with_clock(
        CaConfig::default(),
        &g.certificate.cert_pem,
        g.private_key_pem(),
        st.clone(),
        clock(),
    )
    .unwrap_err();
    assert!(
        matches!(&e, CaError::BadCaMaterial(m) if m.contains("not a CA")),
        "{e}"
    );
    // garbage
    assert!(CertificateAuthority::from_parts_with_clock(
        CaConfig::default(),
        "x",
        "y",
        st.clone(),
        clock()
    )
    .is_err());
    // expired CA
    let far: Clock = Arc::new(|| OffsetDateTime::from_unix_timestamp(T0 + 4000 * 86_400).unwrap());
    let e = CertificateAuthority::from_parts_with_clock(
        CaConfig::default(),
        ca.ca_certificate_pem(),
        &ca.ca_private_key_pem(),
        st,
        far,
    )
    .unwrap_err();
    assert!(
        matches!(&e, CaError::BadCaMaterial(m) if m.contains("expired")),
        "{e}"
    );
}

#[test]
fn state_json_roundtrip_and_summary() {
    let (mut ca, tc) = new_ca();
    let a = ca
        .issue_with_generated_key(
            "a",
            &["a.example.lan".into()],
            &IssueOptions {
                profile: CertProfile::Server,
                validity_days: Some(5),
            },
        )
        .unwrap();
    let b = ca
        .issue_with_generated_key("b", &["b.example.lan".into()], &IssueOptions::default())
        .unwrap();
    let _c = ca
        .issue_with_generated_key("c", &["c.example.lan".into()], &IssueOptions::default())
        .unwrap();
    ca.revoke(&b.certificate.serial, RevokeReason::Unspecified)
        .unwrap();
    tc.advance_days(6);
    let json = serde_json::to_string(ca.state()).unwrap();
    let back: CaState = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, ca.state());
    let s = summarize(&ca, T0 + 6 * 86_400);
    assert_eq!((s["expired"], s["revoked"], s["active"]), (1, 1, 1));
    let _ = a;
}

#[test]
fn config_validation() {
    let ok = CaConfig::default();
    assert!(ok.validate().is_ok());
    let mut c = ok.clone();
    c.common_name = String::new();
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.default_leaf_validity_days = 900;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.max_leaf_validity_days = 5000;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.crl_validity_hours = 0;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.crl_distribution_urls = vec!["ftp://x".into()];
    assert!(c.validate().is_err());
    assert!(CertificateAuthority::create(c).is_err());
    // partial TOML/JSON config fills defaults
    let c: CaConfig =
        serde_json::from_str(r#"{"common_name":"Lab CA","crl_validity_hours":24}"#).unwrap();
    assert_eq!(c.common_name, "Lab CA");
    assert_eq!(c.max_leaf_validity_days, 825);
}
