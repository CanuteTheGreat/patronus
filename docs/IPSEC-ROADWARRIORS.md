# IPsec road warriors (IKEv2 remote access)

Lane F. Phones and laptops connect to the firewall with the IKEv2 client built
into iOS, macOS, Android (strongSwan app) and Windows. Code:
`crates/patronus-network/src/ipsec_rw.rs` (profiles, PKI, swanctl pieces, client
files), `ipsec.rs` (the applier writes them into `/etc/swanctl` and loads them),
`patronus-firewall/src/vpn_rules.rs` (rules), `patronus-web/src/routes/api/ipsec_rw.rs`
(API), VPN page card "IPsec road warriors". Needs USE=ipsec (strongSwan) and
`openssl` at run time. Proof: `ci/netlab/lane-f-ipsec-rw.sh` (README claim C60).

## Profiles and users

A **profile** (`ipsec_rw_profiles`) is one strongSwan connection
`patronus-rw-<name>` with a virtual-IP pool (`pools { patronus-rw-<name> }`, DNS
servers pushed to clients), the networks clients may reach (`local_ts`, default
everything = full tunnel) and the name or address clients connect to
(`server_id`: it is the IKE identity and the server certificate's subject
alternative name). Two authentication types, fixed per profile:

* `eap` - EAP-MSCHAPv2: each user has a name and a password (generated, 20
  characters, shown once, when none is given). Every phone and Windows has a
  built-in client for it. Passwords are stored in the config store (strongSwan
  needs them in clear for EAP-MSCHAPv2), written only to the 0600 swanctl file,
  and never returned by the API.
* `cert` - client certificates: Patronus issues one per user from its own CA
  and *pins* it in the connection (`remote { certs = ... }`). Deleting or
  disabling the user removes the pinned certificate, which revokes access
  without a CRL; a cert profile with no enabled user has no connection at all.

Use one profile per `server_id` (the responder picks the connection by the IKE
identity the client asks for).

## PKI

`ipsec_pki` holds an EC P-256 CA ("Patronus IPsec CA", 10 years), one server
certificate per profile (5 years, EKU serverAuth + IKE intermediate, SAN =
`server_id`) and one client certificate per cert user (5 years, EKU clientAuth),
all made with the `openssl` binary (like the OpenVPN PKI). Changing a profile's
`server_id` issues a new server certificate. Files: `/etc/swanctl/x509ca/patronus-rw-ca.pem`,
`x509/patronus-rw-<profile>.pem` (+ pinned client certificates),
`private/patronus-rw-<profile>.pem` (0600); files of deleted profiles/users are
removed on the next apply. The CA certificate is at
`GET /api/vpn/ipsec/roadwarrior/ca` (clients must trust it).

## Firewall

IKE (UDP 500/4500) and ESP are opened; traffic that came through an SA from the
pool is accepted towards `local_ts` (input and forward, after the user's rules,
so a user block wins); answers to clients are exempt from outbound NAT
(otherwise they would be masqueraded before encryption and miss the IPsec
policy). With a full-tunnel profile the pool reaches the internet through the
normal automatic outbound NAT.

## API

| | |
|---|---|
| `GET /api/vpn/ipsec/roadwarrior` | profiles with their users |
| `POST/PUT/DELETE /api/vpn/ipsec/roadwarrior/profiles[/:id]` | `name, auth, server_id, local_address, pool, dns, local_ts, enabled, description` |
| `POST /api/vpn/ipsec/roadwarrior/profiles/:id/users` | `username, password` (EAP; empty = generated, returned once) |
| `PUT/DELETE /api/vpn/ipsec/roadwarrior/users/:id` | `enabled, password, description` |
| `GET /api/vpn/ipsec/roadwarrior/ca` | CA certificate (PEM) |
| `GET /api/vpn/ipsec/roadwarrior/export/:user_id/:format` | `mobileconfig`, `sswan`, `ps1`, `p12`; cert profiles need `?password=` (the PKCS#12 password, 8+ chars) |

Changes are applied at once and undone if strongSwan refuses them. Exports are
for operators and admins only (they carry credentials).

## Client setup files

* **iOS / macOS** `.mobileconfig`: an IKEv2 VPN payload (`com.apple.vpn.managed`:
  server, EAP user or certificate, AES-256-GCM / SHA-256 / DH group 19), the CA as
  a trusted root and, for cert profiles, the user's PKCS#12 with its password.
  The UUIDs are derived from profile and user, so re-importing replaces.
* **Android** `.sswan` (strongSwan app): `ikev2-eap` or `ikev2-cert` with the CA,
  user, PKCS#12 and split tunnelling to `local_ts`.
* **Windows** PowerShell script: imports the CA into the machine's trusted roots,
  (cert) imports the PKCS#12, `Add-VpnConnection -TunnelType Ikev2` with MSChapv2
  or MachineCertificate, `Set-VpnConnectionIPsecConfiguration` to the proposals
  the server offers (GCM-AES-256, SHA-256, ECP256), routes for split tunnelling.
  The EAP password is not in the script (Windows asks for it).
