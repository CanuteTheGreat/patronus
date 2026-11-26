# Security overview and the recommended baseline

Page: **Security > Security overview** (`/security`), API `/api/security*`, dashboard card "Security".
Code: `crates/patronus-web/src/security.rs` (checks, grade, baseline plan/apply/undo, sampler),
`crates/patronus-network/src/posture.rs` (live facts, read as root through `patronus applyd`),
`crates/patronus-firewall/src/exposure.rs` (is a port reachable through an interface, from the loaded
nftables ruleset). Design: `docs/design/security-suite.md` items 3, 10 and 11. Proof: netlab
`ci/netlab/lane-b-security.sh` (kernel state + real traffic) and `lane-b-security-ui.sh` (Firefox, 1280/390 px,
light/dark). Claims C211, C212.

## What it checks

Every check reads what the router is doing **now**, never only what the configuration says:

| Check | Live evidence | Fix link |
|---|---|---|
| Web UI not reachable from the WAN (critical) | listening sockets of the web UI (wildcard or a WAN address) + a walk of the loaded `inet patronus` `input` chain for each WAN device and port | Firewall rules |
| SSH not reachable from the WAN (critical) | the running sshd's / Dropbear's ports, same walk | Firewall rules |
| SSH logins with keys only | `sshd -T` with the RUNNING sshd's own arguments (`-f`, `-o`, `-p`), Dropbear's flags (`-s`) | System > SSH server |
| Two-factor login for admins | enabled admin accounts with a confirmed TOTP secret | Your account |
| Brute-force protection | switch + the `inet patronus_guard` table loaded | Security > Brute-force protection |
| Standard ports | web UI 443 (80 only redirects), SSH 22 | Web UI addresses and ports |
| Threat feeds | enabled feeds, entries, mode, the `ti_check` chain loaded | the catalog on the page |
| DNSSEC validation | running Unbound's config: validator module, trust anchor, not permissive | DNS |
| Bogon / private sources dropped on the WAN | the WAN-guard rules loaded; private sources are "not applicable" when the WAN address itself is private (behind another router) | Firewall > Hardening |
| SYN flood protection | the rate-limit rule loaded (kernel SYN cookies shown) | Firewall > Hardening |
| Intrusion detection | Suricata running; "not applicable" below `security.ids_min_ram_mb` (default 2048 MB; the ET Open set needs ~520 MB) or on a build without it | Intrusion detection |
| Automatic security updates | last update check and pending updates; this firmware has no automatic update schedule yet, so it is "review" at best | System > Updates |
| No unused services listening | every non-loopback listening socket and its process; risky ones (telnet, FTP, SMB, rpcbind, databases ...) fail, sockets of processes Patronus does not manage are "review" | System > Services |
| WireGuard peers use preshared keys | the kernel's peers (`wg show all dump`) | VPN |
| No silent WireGuard peers | last handshake (kernel + the sampler's history, the kernel forgets it at a reboot), else the peer's age; threshold `security.wg_silent_days` (90); a **Disable** button per peer | VPN |
| IPsec proposals are current | proposals strongSwan loaded (`/etc/swanctl`) and the algorithms of the SAs that are up; SHA-1, MD5, 3DES/DES, MODP-768/1024/1536 fail | VPN |
| OpenVPN uses tls-crypt | each running OpenVPN's config: tls-crypt (pass), tls-auth only (review), neither or a weak data cipher (fail) | VPN |

A check that cannot read its live state says **unknown** (it never passes).

**Grade:** pass = full weight, review/unknown = half, fail = none, not applicable = left out; A >= 90,
B >= 80, C >= 65, D >= 50, else F. A failing critical check (web UI or SSH open on the WAN) caps the grade at D.

## The recommended baseline

**Review recommended baseline** shows the change set first (a dry run, `GET /api/security/baseline`: nothing
is written, no revision is taken) with each change's before and after, and every item it leaves alone with the
reason. **Apply these changes** (`POST /api/security/baseline {token}`, admin only) recomputes the plan on the
server and refuses (409) when it differs from the dry run the admin looked at. Then it takes ONE configuration
revision ("before security baseline"), writes every change, applies the firewall, the brute-force protection,
DNS and SSH, and restores that revision if any of them fails. **Undo baseline** restores the revision (later
changes are undone too: the confirm dialog says how many); the measured hit history is never rewound.

What it changes (only what is off):

- brute-force protection on;
- the catalog feeds in `security.baseline_feeds` (default Spamhaus DROP, EDROP, DROPv6) on, blocking;
- DNSSEC validation on;
- bogon sources dropped on the WAN; private sources too, unless the WAN address is private;
- SYN flood protection on;
- SSH password logins off, only when an authorized key or a user CA is installed;
- user firewall rules that open the web UI or SSH on a WAN interface (`@wan` or a WAN device, any source)
  disabled, not deleted.

What it never does:

- **cut the management path in use**: the admin's address is looked up (`ip route get`); when the session
  arrives over the WAN, rules that may carry it are left alone, and a bogon/private-source guard that would drop
  that address is not turned on (each with the reason in the dry run);
- touch two-factor login (each admin enrols), intrusion detection (~520 MB, the watched interface is a choice),
  tunnels (the other end must change too), silent peers (may be a rarely used client), ports, or services.

## Threat-feed catalog and hit counters

The catalog on the page lists the free feeds (`patronus_firewall::feeds::CATALOG`) with an on switch and a mode:
**block** (drop) or **alert only** (`firewall_alias_sources.action = alert`: the feed's rules count and log to
the firewall log, NFLOG group 7, and let the packet through to the user's rules, so a feed can be tried before it
blocks anything). The sampler reads the feed rules' kernel counters every `security.sample_secs` (60 s), adds
the increase (the counters restart at every ruleset load) to `sec_feed_hits` per feed and hour, and keeps
`security.feed_hits_days` (30) days. The dashboard card shows the top feeds of the last 24 hours; the firewall's
Threat Intel tab has the same numbers. API: `GET /api/security/feeds?hours=N` (catalog + hourly series).

## Settings (`system_config`, export/plan/apply/rollback, `PUT /api/security/settings`)

| Key | Default | Meaning |
|---|---|---|
| `security.wg_silent_days` | 90 | a peer without a handshake this long is silent |
| `security.ids_min_ram_mb` | 2048 | below this the IDS check is not applicable |
| `security.feed_hits_days` | 30 | hit history kept |
| `security.sample_secs` | 60 | sampler interval (10-3600) |
| `security.baseline_feeds` | `spamhaus_drop,spamhaus_edrop,spamhaus_dropv6` | catalog feeds the baseline turns on |
| `security.baseline_revision` | - | revision taken before the last baseline (the Undo button) |

Measured data (`sec_feed_hits`, `sec_feed_counter_pos`, `sec_wg_seen`) is `NON_CONFIG`: no backup, revision or
rollback carries or rewinds it.

## Cost and tiers

No daemon and no package: the overview is computed on request (a few hundred ms: one `sshd -T`, `wg show`,
`swanctl --list-sas` when charon runs, one terse `nft -j` listing without set contents, a `/proc` walk); the
dashboard asks for a cached answer (30 s). The sampler is one `nft -j list chain` per minute and one
`wg show all dump` every 5 minutes while WireGuard peers exist; its tables hold one row per feed and hour
(30 days x feeds) and one per peer. Both tiers get the overview, the baseline and the VPN checks
(design tier table); items a build lacks (brute-force protection on the router images, intrusion detection)
show as not applicable with the reason. No new Gentoo package or USE flag: every input is already in the
image (`openssh`/`dropbear`, `wireguard-tools`, `strongswan`, `openvpn`, `nftables`, `iproute2`), each behind
its existing USE flag.
