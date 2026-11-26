# Certificate authority backend (`patronus-security::ca`)

Signing/revocation engine for the certificate manager. No I/O policy of its own:
callers pass PEM in and get PEM out; persistence is `CaStore` in a directory the
caller configures.

- `CaBackend` (`ca::CertificateAuthority`): `create` / `from_parts`, `sign_csr_pem`,
  `issue_with_generated_key`, `revoke`, `generate_crl`, `verify_certificate`.
- CSRs are requests only: the proof-of-possession signature is verified, then only
  the CN and DNS/IP SANs are kept and checked against `CaPolicy`. CA status, key
  usages, EKU, validity, serial and CRL pointers always come from the CA profile.
- Serials are 127-bit random, unique, recorded in the ledger (`CaState`, JSON, no key).
- CRLs: RFC 5280 v2, monotonic CRL number, reason codes, expired entries pruned;
  signed by the CA key and verifiable with the CA certificate.
- `CaStore`: `ca.key` 0600 written atomically in a 0700 dir; load refuses a
  group/world-accessible key. Keys never appear in `Debug`, logs or `state.json`.
- All values are typed in `CaConfig` (subject, lifetimes, CRL validity and
  distribution URLs, name policy); no compiled-in hosts or paths.

Not yet wired: config-store/API/UI keys, CRL publishing endpoint, scheduled CRL
refresh, ACME front end, mTLS peer verification (`MtlsManager::verify_peer` is still a stub).
