# Certificate manager: ACME (`/svc/certs`)

Certificates the router obtains and renews itself, like pfSense's ACME package and
OPNsense's os-acme-client, with a native Rust client (`patronus-security::acme`,
built on `instant-acme`, Apache-2.0). No acme.sh, certbot or shell scripts.

## Settings (all stored, exported, in the API and on the page)
- `certs.dir` (default `/var/lib/patronus/certs`): `<dir>/<name>/fullchain.pem` (0644),
  `key.pem` (0600), `account.json` (0600). Written atomically, key before chain.
- `certs.check_mins`, `certs.retry_mins` (a failed certificate is not retried sooner, so a
  broken setup cannot hit CA rate limits), `certs.notify`, `certs.challenge_iface`
  (default `@wan`, empty = write your own rule).
- Per certificate: name, domains (first = primary, `*.` needs DNS-01), account e-mail,
  terms-of-service flag, directory (`staging` default, `production`, `custom` + URL +
  extra CA bundle), challenge, DNS provider and its credentials, renew-before days,
  `use_for_web`. Secrets (Cloudflare token, TSIG secret) are never returned.

## Challenges
- HTTP-01: patronus-web's port-80 listener answers `/.well-known/acme-challenge/<token>` from an
  in-process store; only tokens of a running order are answered, everything else keeps
  redirecting to HTTPS. While an enabled certificate uses http-01 the firewall accepts tcp/80
  from `certs.challenge_iface`.
- DNS-01: `DnsProvider` trait. Providers: Cloudflare (API token, zone found by longest suffix),
  RFC 2136 (native UPDATE message + TSIG HMAC-SHA256/384/512, UDP with TCP fallback).
  The TXT record is removed after validation, also when it failed.

## Renewal, notification, reload
The web process runs the renewal task (first look 30 s after start, then every
`certs.check_mins`): missing, due (inside the renewal window) and expired certificates are
issued again. Failure -> `cert_renewal_failed` event through the normal notification hooks;
success -> `cert_renewed`. A certificate flagged `use_for_web` sets `web.tls_cert/tls_key` and the
HTTPS listeners swap it in place (existing connections continue, new handshakes get the new one).
Revoke (page button / `POST /api/svc/certs/action/revoke {"name":..}`) revokes at the CA, sets the files
aside (`*.revoked`) and the next pass requests a replacement.

## Proof
`ci/netlab/lane-h-acme.sh` (Pebble 2.10 as the CA, BIND as the RFC 2136 server on the internet
side): HTTP-01, served certificate, forced + automatic renewal, expiry, wildcard DNS-01 with TSIG,
wrong-secret failure + event, revocation (`cert-status-by-serial`), no secret in API/log.
Claim C1250. Unit tests: RFC 2136 wire format and TSIG MAC, renewal states, settings validation.

## Not yet
Trust pages for internal CAs / CSRs / CRLs on top of `CERTIFICATE-AUTHORITY.md`, other DNS providers,
picking a certificate by name in OpenVPN / IPsec / captive portal / reverse proxy, ACME on the
embedded images (size to be measured).
