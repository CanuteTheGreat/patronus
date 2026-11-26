# Built-in security suite

Status: design + phase plan (2026-11). Shipped items are marked.

A modern firewall is expected to do more than filter: pfSense and OPNsense ship
(or package) Suricata/Snort, pfBlockerNG / Unbound blocklists, ntopng, sshguard
and CrowdSec; OpenWrt users add banIP, adblock and Snort 3; commercial gear
(UniFi, Firewalla, SMB NGFWs) sells IDS/IPS, "threat management", ad and
region blocking, device and vulnerability scans and a security score. This
document decides which of those Patronus builds in, with which free component,
on which tier, and in what order.

Rules every item follows:

- free and open-source components only, packaged in Gentoo (or built into the
  Patronus binaries); no paid feeds, no paid tiers;
- every item is a typed setting in the declarative configuration (export,
  plan, apply, revisions, rollback), with the API and the page where users
  touch it; nothing hard-coded;
- OpenRC and systemd equally; standard ports;
- resource-aware: each item states what it costs, the router tier carries a
  subset, and an item a board cannot fit is listed on its System page with the
  reason, never silently hidden;
- off or conservative by default where it can block people; the one-click
  baseline (item 11) is how a user turns the recommended set on;
- measured data (alerts, hits, bans, scan results) is `NON_CONFIG`: never
  carried or rewound by a backup/rollback, always with retention.

## Benchmark

| Capability | pfSense | OPNsense | OpenWrt | Commercial (UniFi / Firewalla / SMB NGFW) | Patronus |
|---|---|---|---|---|---|
| IDS/IPS | Suricata / Snort packages, ET Open + Snort VRT | Suricata built in (inline IPS), ET Open/Abuse.ch | Snort 3 package | UniFi IDS/IPS (Suricata), Fortinet/Palo Alto paid signatures | Suricata via NFQUEUE (USE=intrusion-detection); rule-set manager, policies, alert browser landing (docs/IDS-RULESETS.md) |
| DNS filtering / ad blocking | pfBlockerNG DNSBL | Unbound blocklists | adblock / adblock-lean | UniFi ad blocking, Firewalla family | Unbound blocklists (URLs + domains), per-group policies and family preset (segmentation) |
| IP threat-intel blocklists | pfBlockerNG IP lists | firewall aliases (URL tables), CrowdSec | banIP | UniFi "threat management", Firewalla | threat-feed aliases (Spamhaus DROP/EDROP, FireHOL L1, abuse.ch, own URL) dropped ahead of user rules (docs/FIREWALL-FEEDS.md); **phase 2: catalog on the overview, per-feed hit counters, alert-only mode (shipped)** |
| GeoIP / ASN blocking | pfBlockerNG | GeoIP aliases | banIP | region blocking | GeoIP + ASN aliases |
| Brute-force protection | sshguard (built in) | sshguard / CrowdSec | banIP + dropbear | built in | **phase 1: shipped** (docs/BRUTE-FORCE.md) |
| Flow / traffic analysis | ntopng package | Insight, ntopng plugin | luci-statistics, nlbwmon | per-client/app dashboards | traffic insight, uplink health, NetFlow export; no app classification yet |
| LAN device / vulnerability scan | nmap package | nmap plugin | - | Firewalla device scan, SMB "vulnerability assessment" | missing |
| Router's own CVE exposure | update notices | update notices + changelog | opkg list-upgradable | "firmware has security fix" notices | update channel; no CVE view yet |
| Encrypted DNS | DoT upstream | DoT/DoH (Unbound, dnscrypt-proxy) | https-dns-proxy | DoH upstream | DoT upstream; DoH policy for devices with a DNS policy |
| Security log + alerting | logs, notifications | logs, Monit | logread | push alerts | firewall log viewer, structured log viewer, notification channels |
| Hardening baseline / score | wizard defaults | - | - | UniFi "security posture", Firewalla checks | **phase 2 (shipped): security overview with 18 live checks, grade, dashboard card, one-click baseline (dry run, one revision, undo, keeps the admin's path) and VPN checks** (docs/SECURITY-OVERVIEW.md) |

## Components chosen (and why)

1. **IDS/IPS: Suricata** (`net-analyzer/suricata`). Already integrated; the
   rule-set manager (ET Open, abuse.ch SSL blacklist, own URLs; per-category
   alert/drop policies; suppress/threshold; scheduled download with `-T`
   validation and rollback; alert history) is landing from its own lane.
   Standard tier only: the ET Open set needs ~520 MB to load (measured), which
   the router class cannot hold. Snort 3 stays possible (USE=snort) but is not
   the default: one engine is tested end to end.
2. **DNS filtering: Unbound** (`net-dns/unbound`), already the resolver. Add a
   curated, free list catalog (StevenBlack hosts, OISD, Hagezi tiers, URLhaus
   malware domains, Phishing Army), refreshed on a schedule with status per
   list, and **RPZ** (Unbound's `rpz:` module) so threat-intel zones in RPZ
   format work and blocked answers are logged per list. Router tier: dnsmasq
   `--address=/domain/` lists with a size cap from the board profile.
3. **IP threat intel: nftables sets** filled by the existing feeds engine. Add
   a catalog toggle on the overview page, per-feed hit counters on the
   dashboard and an "alert only" mode (**shipped**: the sampler adds the
   feed rules' kernel counter increases to an hourly `sec_feed_hits` history,
   NON_CONFIG, 30 days; alert only = count + log, no verdict). Router tier:
   capped sets (memory per element measured per board).
4. **Brute-force protection: built into Patronus** (no daemon): SSH (OpenSSH,
   Dropbear) and web UI failures -> timed bans in an own nft table, IPv6 per
   /64, escalation, LAN exemption, allow list. A CrowdSec agent was
   considered: it is free, but its community blocklist needs an account and
   it adds a resident Go daemon + local API, too heavy for the router tier;
   its role (shared reputation) is covered by the threat-feed catalog. Phase 1,
   shipped. Next: VPN sources (OpenVPN TLS/auth failures, strongSwan EAP/PSK
   failures), IDS-alert-driven bans (source of a `drop` alert above a
   threshold), the router tier (Dropbear, busybox syslog).
5. **Flow analysis: Patronus insight + nDPI.** Traffic insight already keeps
   per-client/ASN usage and uplink health; NetFlow/IPFIX export (softflowd)
   feeds external collectors. Application identification uses **nDPI**
   (`net-libs/nDPI`, LGPL) as an optional library over conntrack-marked
   flows on the standard tier, giving per-app usage and per-app block rules.
   ntopng itself (`net-analyzer/ntopng`) is GPL and heavy; it stays an
   optional package with a link from the dashboard, not the built-in view.
   Zeek is out of scope for the appliance (no Gentoo main-tree package, large
   footprint); its logs-for-SOC role is covered by eve.json + syslog export.
6. **LAN security audit: nmap + rustscan** (`net-analyzer/nmap`,
   `net-analyzer/rustscan` from the Patronus overlay where the Gentoo tree has none; always installed together). "Scan my network"
   (on demand and on a schedule, quiet hours, rate-limited) per LAN segment:
   open ports per device, service/version detection, a rule set of findings
   (telnet, FTP, SMBv1, UPnP/SSDP from WAN-facing services, admin pages on
   HTTP only, known default-credential login pages, exposed databases),
   compared with the last scan ("new device", "new open port"), report page +
   PDF/CSV export, findings into the alert routing. Router tier: a small
   built-in TCP connect scan of the top ports (no nmap on flash).
7. **Router CVE exposure.** Standard tier: the installed package set
   (`/var/db/pkg`) against Gentoo GLSAs (`glsa-check` from
   `app-portage/gentoolkit`) and OSV for the Rust crates compiled into the
   Patronus binaries (the build embeds its dependency list); router tier: the
   image's package manifest checked at build time and on the update server.
   Shows "affected / fixed in / update available", links to the advisory,
   and feeds the update policy (security updates apply in the nightly window).
8. **Encrypted DNS.** DoT upstream exists. Add Unbound's DoH and DoT server
   for LAN clients (443/853 on the LAN address, the router's certificate),
   so browsers can use the router's filtering over DoH, plus a "block public
   DoH resolvers" switch (a maintained DoH-server domain/IP list into the
   DNS and IP blocklists) for networks that want filtering to be unavoidable.
9. **Security log + alerting.** Reuse the structured log viewer, firewall
   log and notification channels. Add security event types (new ban, IDS
   drop/alert above a severity, feed hit spike, scan finding, CVE affecting
   the router, admin login from a new address) with per-type routing,
   one incident per source with an occurrence count, and a daily summary
   instead of per-event mail.
10. **VPN hardening.** Checks on the overview page: WireGuard peers without a
    preshared key, peers silent for 90 days, IPsec proposals below the
    current recommendation (no SHA-1/MODP-1024), OpenVPN without
    tls-crypt; a fix button where the change is safe (**shipped**: read from
    the kernel's peers, strongSwan's loaded proposals and live SAs, running
    OpenVPN configs; the safe fix is "Disable" on a silent peer, everything else
    needs the other end of the tunnel and links to the VPN page).
11. **Hardening baseline + security overview.** One page that grades the
    box with evidence (each check reads live state): SSH key-only and not on
    WAN, web UI not on WAN, admin 2FA, brute-force protection on, threat
    feeds on, DNSSEC on, bogon/private sources dropped on WAN, SYN flood
    protection, IDS on (when the RAM allows), automatic security updates on,
    unused services off, default ports standard. "Apply the recommended
    baseline" shows the change set first (dry run), applies it as one
    configuration revision (rollback in one click) and never touches the
    management path the admin is using. **Shipped** (docs/SECURITY-OVERVIEW.md):
    reachability from the WAN is decided by walking the loaded nftables input
    chain (`patronus_firewall::exposure`), the plan is recomputed on apply and
    refused if it differs from the dry run, the admin's address is routed
    (`ip route get`) and anything that may carry a WAN session (the WAN web
    rule, a bogon/private-source guard that would drop that source) is left
    out with the reason. Not in the baseline: two-factor login (each admin
    enrols), intrusion detection (~520 MB and the watched interface is a
    choice), tunnel algorithms (both ends), ports and services. Automatic
    security updates: the check reports that the firmware has no automatic
    update schedule yet (its own job).

### Brute-force protection by default

Decision (2026-11): **on for new installs**, seeded once at the first boot
(`patronus_config::defaults`, like DNS rebinding protection); an upgraded store
keeps what it had, and the baseline turns it on there. Before the default
changed, the whole netlab suite (`NETLAB_ALL=1 ci/netlab/run.sh`, every lane,
journey, failure and upgrade scenario) ran with it on, since every lane boots a
new store. Why it is safe on: the LAN (every subnet of a LAN-role interface)
and an allow list are never banned, a ban needs 5 failures in 10 minutes, the
first ban lasts 15 minutes, and Patronus' own CI clients sit on the LAN side.
What the run found and what changed (2026-11-26, rw-man-07 arm64, ubuntu:24.04 netlab image): 75 scenarios
passed with it on, 4 hwsim Wi-Fi lanes skipped (no radio tools in that container), 3 failed. `lane-a-foundation`
expected `patronus firewall flush` to leave no ruleset and the guard table stayed: `FirewallApplier::teardown`
now removes `inet patronus_guard` too. `lane-f-ipsec-rw` aborted on a host without `/usr/lib64` (a `find` exit
status under pipefail, nothing to do with the guard): fixed in the lane. `lane-n-tls` fails its TLS 1.2 handshake
check identically with the protection switched off (an environment difference of that image, not this change).
All three re-ran green or unchanged with the fixes; apart from lane-b-guard's deliberate bans, no lane
had a client banned.

## Tiers

| Item | Standard | Router (aarch64/MIPS images) |
|---|---|---|
| IDS/IPS | yes | no (memory); listed as not available |
| DNS filtering | Unbound + RPZ | dnsmasq lists, capped |
| IP threat feeds | yes | capped sets |
| Brute-force protection | yes (phase 1) | next (Dropbear + busybox syslog) |
| Flow analysis / apps | insight + nDPI | insight only |
| LAN audit | nmap + rustscan | built-in top-ports scan |
| CVE exposure | GLSA + OSV | image manifest |
| DoH/DoT server | Unbound | no (DoT upstream only) |
| Alerts, baseline, VPN checks | yes | yes |

## Phases

- **Phase 1 (shipped):** brute-force protection (item 4, standard tier); IDS
  rule-set manager from its lane (item 1).
- **Phase 2:** security overview + one-click baseline + VPN checks (10, 11,
  shipped); DNS filtering catalog + RPZ (2); threat-feed catalog + hit
  counters (3, shipped); security events into alert routing (9).
- **Phase 3:** LAN security audit (6); router CVE exposure (7); DoH/DoT server
  (8); application identification with nDPI (5); brute-force protection on
  the router tier, VPN sources and IDS-driven bans (4).

Each phase item is its own lane with a netlab (or QEMU) proof that shows the
kernel/daemon state and real traffic, a claims-ledger row, docs and the page
checked at desktop and phone width in light and dark.
