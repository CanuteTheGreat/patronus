# Captive portal

A sign-in page for the clients of a network, in the way the pfSense/OPNsense captive portals, UniFi
hotspots and OpenWrt's openNDS work. Package flag `USE=captive-portal` (cargo feature
`captive-portal`, default on in the ebuild); nothing changes until you add a **zone**.
Settings: page **Captive portal settings** (`/svc/captive`, API `/api/svc/captive`); signed-in
clients, disconnects and voucher sheets: page **Captive portal** (`/captive-portal`, API
`/api/captive-portal/...`); CLI: `patronus captive-portal sessions|disconnect|vouchers`.

## What a client of a zone sees

1. It joins the network (wired port, VLAN, bridge or Wi-Fi; DHCP hands out option 114, the
   RFC 8908 API URL, so phones and laptops open the sign-in window by themselves).
2. Any web request (HTTP to anywhere) is answered with a redirect to `https://<router>/` (the
   standard port; with `https_login` off the page is served over plain HTTP instead). Every other
   connection beyond the router is refused (TCP reset), DHCP and DNS on the router keep working.
3. It signs in by the zone's **login**: `none` (accept the terms), `local` (a portal user),
   `voucher` (a code from a roll) or `radius` (user name and password checked by a RADIUS server).
4. It is let through until the **idle timeout** (no traffic for that long), the **hard timeout**
   (the session length; for a voucher, what is left of the voucher's time; for RADIUS, the
   server's Session-Timeout when it sends one), a **logout** on the status page, or an
   administrator's **disconnect**. Then it is captured again.

## How it is built

- Own nft table `inet patronus_portal` (applier `captive`, phase services):
  - `prerouting` (nat, priority **-105**, before the main table's dstnat): an unauthenticated client's
    TCP 80 to anywhere and TCP 443 to the router are redirected to the portal listeners
    (`captive.http_port` 8002 / `captive.https_port` 8003; internal, clients use 80/443);
  - `forward` (filter, priority **-16**, before the guest network -15, segmentation and the main
    table): passthrough clients and destinations and signed-in clients fall through to the other
    tables (which still decide what they may reach), everything else from the zone is dropped;
  - per zone `z<id>`: `auth` (MAC . IPv4, element timeout = what is left of the hard timeout, so the
    kernel ends a session even if no Patronus process runs), `amac` (MACs of signed-in clients, for
    their IPv6 traffic), `seen` (idle timeout: every forwarded packet refreshes it), `mpass`/`ipass`
    (passthrough clients), `dpass` (allowed destinations, host names resolved at apply time).
- The main table (`patronus-firewall/src/svc_rules.rs`) accepts DHCP, DNS and the two portal ports
  on zone interfaces.
- Sessions are runtime state in `cp_sessions` (with `cp_voucher_use`, both outside the
  configuration export, pruned after `session_retention_days`). Every apply re-adds the live
  sessions with the time they have left, so a firewall reload or a reboot signs nobody out early.
- patronus-web runs the listeners (only while a zone is enabled; port and certificate changes are
  picked up without a restart) and a ticker every `poll_secs` that ends sessions on hard/idle
  timeout, disconnect request or a zone switched off, sends RADIUS interim accounting and prunes old
  rows. It needs CAP_NET_ADMIN (nft sets, `tc`, conntrack), which both the OpenRC script and the
  systemd unit of patronus-web grant.
- Per-client bandwidth: an HTB class (download) on the zone device's egress and an ingress policer
  (upload) per session, removed with the session.
- Which zone and session a request belongs to is decided by the client's address and its MAC in the
  router's neighbour table, never by anything the client sends.
- Portal passwords are stored as argon2id hashes (same cost rules as the web accounts,
  `PATRONUS_ARGON2_MEM_KIB` on small routers). RADIUS: PAP with Message-Authenticator (RFC 3579),
  every reply's authenticator verified, accounting Start/Interim/Stop (RFC 2866) with
  Acct-Terminate-Cause.

## Settings

Global (`captive.*`):

| Key | Default | Meaning |
|---|---|---|
| `http_port`, `https_port` | 8002, 8003 | internal portal listeners (>= 1024; never 22/53/67/68/80/443) |
| `hostname` | empty | name used in redirects and the DHCP option (empty = the router's address on the zone) |
| `tls_cert`, `tls_key` | empty | PEM files for the HTTPS portal (empty = the web UI's certificate) |
| `session_retention_days` | 30 | ended sessions kept for the session list |
| `acct_interim_secs` | 300 | RADIUS interim accounting (0 = only Start/Stop) |
| `voucher_code_length` | 10 | characters per voucher code (unambiguous alphabet) |
| `poll_secs` | 2 | how often timeouts and disconnects are checked |

Zones (`zones`): `name`, `enabled`, `interface` (`@lan`, `@optN`, a VLAN or bridge; one enabled zone
per interface), `auth`, `radius_server`, `radius_port` 1812, `radius_acct_port` 1813,
`radius_secret`, `radius_accounting` on, `radius_nas_id`, `radius_timeout_secs` 3, `idle_minutes` 30,
`hard_minutes` 480, `download_kbit`/`upload_kbit` 0 (no limit), `terms_required` on, `https_login` on,
`redirect_url` (empty = the page first asked for), `max_sessions` 0 (devices per user/voucher), and
every page text: `page_title`, `welcome_text`, `terms_text`, `button_text`, `success_text`,
`logout_text`, `user_label`, `password_label`, `voucher_label`, `error_text`, `accent_color`
(`#rrggbb`; text on it is picked black or white for WCAG AA contrast).

Portal users (`users`): `username`, `password` (stored hashed), `zone` (empty = every local zone),
`enabled`. Voucher rolls (`rolls`): `name`, `zone`, `count`, `minutes` (counted from first use); the
codes are generated when the roll is added and printed from the Captive portal page. Passthrough
(`passthrough`): `zone`, `kind` (`mac`, `ip` = client address or network, `host` = a destination
reachable before sign-in), `value`.

## The pages

Light and dark follow the device, the layout works from a 320 px phone up, every control has a
label and a visible focus ring, and errors are announced (`role="alert"`). No text is built in:
every visible string comes from the zone's settings. The status page shows the time left and the
logout button; a GET of `/logout` never signs anyone out.

## Proof

- Netlab `ci/netlab/lane-u-captive-portal.sh` (kernel, real packets, FreeRADIUS on the internet side):
  redirect and splash page, each login backend, idle/hard timeout, logout, disconnect, RADIUS
  accounting Start/Stop, bandwidth classes, MAC/IP/destination passthrough, DHCP option 114,
  switching off.
- Netlab `ci/netlab/lane-u-captive-portal-ui.sh`: the sign-in page in Firefox on a 390 px phone
  viewport, light and dark, WCAG AA contrast, labels, 44 px touch target, no sideways scrolling, then signed in through the page.
- Unit tests: `patronus-network` `captive` (table rendering, passthrough, checks),
  `patronus-captiveportal` `engine` / `pages` / `http` / `radius`.

## Not yet

- IPv6-only clients (the gate keys on MAC + IPv4; a signed-in client's IPv6 passes by MAC).
- The embedded images. Measured 2026-11-26 (patronus-cli release, aarch64, the GL-AX1800 feature set): +641 KiB
  stripped, +135 KiB xz-compressed. The GL-AX1800 image runs in the access-point role, where a portal has nothing to
  gate (the unit bridges; the main router forwards), so it is not built in: `/api/features` lists it as the main
  router's job and the image's QEMU gate checks that. A router-role embedded image would fit it by this measurement.
- Social login, per-voucher data caps, the portal on several routers sharing sessions (HA).
