# Configurable everything: no hard-coded operational values

Owner rule (2026-11-17): *"honestly nothing should be hard-coded. everything should be
configurable and definable (like nix)"*. Trigger: the router-tier early boot set
`hostname slate` before `/data` was mounted, so every boot reset the name.

This document is the plan and the ledger. The machine-generated, line-by-line inventory is
[configurable-everything-inventory.md](configurable-everything-inventory.md); the gate that
keeps new hard-coded values out is `ci/hardcode-scan.py`.

## The rule, concretely

An *operational value* is anything an owner of a box could reasonably want different:
host and device names, addresses and subnets, ports, interface names, SSIDs / channels /
country, file locations of product data, timeouts, intervals, retry counts, size limits,
user/group ids, fixed lists (time zones, locales, providers), URLs of update servers and
feeds, feature defaults baked into an image.

Every such value is:

1. a **typed key with a documented default** in one registry, with bounds and validation;
2. stored in the **config store**, so it is part of `export_json`/`import_json`, backups,
   revisions/rollback, config generations and GitOps (nothing extra to write);
3. **settable through the API, the CLI and the UI** where a user would touch it;
4. **never an owner value in an image**: images ship defaults; per-unit values come from the
   unit's own config (first-run, answer file, restore) and owner-specific values live only in
   the private overlay.

What stays a constant: protocol numbers and well-known protocol ports (DNS 53, DHCP 67/68,
IKE 500/4500, ...), special-purpose address ranges (RFC 1918, link-local, documentation
ranges), file formats and netlink/RADIUS attribute numbers, OS/package layout (`/proc`,
where a third-party daemon's own init script reads its config), test fixtures, and UI
example/placeholder text. A constant that only looks operational carries
`hardcode-ok: <reason>` on its line (or a `hardcode-ok-begin:` / `hardcode-ok-end` block).

## Mechanism: the settings registry (`patronus_config::settings`)

- `crates/patronus-config/src/settings.rs`: `REGISTRY` of `Setting { key, section, label,
  doc, kind (Bool | Int{min,max} | Port | Text{max_len} | Url{optional} | Choice{options}),
  default, unit, effect, table }`. Values live in `system_config`, or in `lan_settings` next
  to a subsystem's other keys (`ha.*`, `proxy.*`); an unset key reads as its
  default; a stored value that no longer validates (bounds tightened later) reads as the
  default with a warning.
- API: `GET /api/settings` (login), `PUT /api/settings/{key}` `{"value": ...}` and
  `DELETE /api/settings/{key}` (admin, audited, 400 on invalid, 404 on unknown key).
- UI: System > **Advanced settings** (`/settings`), grouped by section, with default,
  unit, "takes effect" and a Reset per changed value. Read-only accounts see the values.
- CLI: `patronus settings list [--json] | get KEY | set KEY VALUE | reset KEY |
  env [--output FILE]`. `env` prints `PATRONUS_SET_<KEY>='value'` lines for shell boot
  scripts on the router tier (sourced, with the registered default as the fallback).
- Router-tier shell scripts: `/usr/libexec/patronus/settings-env ensure|refresh` writes
  `/run/patronus/settings.env` (`patronus-cli settings env`); `apply start` refreshes it at
  boot, after every `settings set/reset` (the `notify_changed` hook) and a script that runs
  earlier calls `ensure` itself (a copy lives on `/data/.settings.env` for the steps that run
  before the store is applied). Scripts source it and keep
  the registry default as their own fallback, so a missing file never stops a service.
  `check-rootfs.sh` refuses an image without `settings-env`.
- `Kind::Addrs` is a comma-separated IP list (resolvers); `settings::default_of(key)` gives the
  registered default to code that has no store (form pre-fills, `Default` impls). The CLI
  fills the process cache when it opens the store (`open_store`), so a default port read by
  synchronous code is the stored one in `patronus apply` too.
- Synchronous code (session checks, login throttle) reads `settings::current()`, a process
  cache that patronus-web fills at start, after every API change and every 60 s (so a
  `patronus settings set` from a shell or a GitOps/restore change reaches it); async code
  reads the store directly with `settings::get()`.
- Tests: `settings::tests::every_key_round_trips_export_import` sets every registered key to
  a non-default value, exports, imports into a fresh store and compares (and checks that an
  untouched export resets every key to its default); `registry_is_well_formed` checks
  unique keys, docs and that every default passes its own validation;
  `routes/settings_api_tests.rs` drives the API and page through the real router.

Adding a value: one `Setting` entry, read it with `settings::get`/`current`, remove the
literal, then `python3 ci/hardcode-scan.py --update` (the baseline only shrinks).

## The gate (`ci/hardcode-scan.py`, rust-ci "No new hard-coded operational values")

- Scans shipped code and image inputs (`ci/hardcode-scan.json`: the crates in the
  patronus-cli / patronus-web / installer dependency closure, web templates, router-tier
  overlays, the Gentoo package's files, the live-installer). Crates outside that closure
  ship in no binary and are not scanned.
- Categories: address, port, timing, constant (named `*_TIMEOUT|*_INTERVAL|*_MAX|...`),
  interface, wifi, hostname, url, path (product data/state locations), uid/gid, size
  (limits), fixed-list (time zones, locales).
- Every known hit is in `ci/hardcode-baseline.tsv` (line-independent fingerprint, proposed
  key). CI fails on a NEW hit that is neither a registered setting, nor a recognised
  constant, nor marked `hardcode-ok: <reason>`. `--self-test` runs the classifier against
  known lines first.
- `python3 ci/hardcode-scan.py --summary` prints the counts, `--inventory FILE` writes the
  full table, `--update` rewrites the baseline after a conversion batch.

## Inventory (at the first batch)

| category | must become config | legit constant | test fixture | total |
|---|---|---|---|---|
| address | 27 | 167 | 1425 | 1619 |
| constant | 66 | 8 | 4 | 78 |
| fixed-list | 7 | 0 | 4 | 11 |
| hostname | 2 | 0 | 0 | 2 |
| interface | 21 | 16 | 440 | 477 |
| path | 59 | 86 | 67 | 212 |
| port | 6 | 22 | 63 | 91 |
| size | 10 | 0 | 0 | 10 |
| timing | 133 | 5 | 67 | 205 |
| uid/gid | 0 | 5 | 14 | 19 |
| url | 33 | 37 | 33 | 103 |
| wifi | 7 | 6 | 10 | 23 |
| **all** | 371 | 352 | 2127 | 2850 |

Full table with file:line and proposed key: [configurable-everything-inventory.md](configurable-everything-inventory.md).

## Converted

| was (file) | key | default | API/UI/CLI |
|---|---|---|---|
| `SESSION_LIFETIME_SECS = 24*60*60` (patronus-web auth.rs) | `web.session_lifetime_secs` | 86400 s (300 .. 30 d) | yes |
| `MAX_LOGIN_FAILURES = 5` (auth.rs) | `web.login_max_failures` | 5 (1 .. 100) | yes |
| `LOGIN_FAILURE_WINDOW_SECS = 15*60` (auth.rs) | `web.login_lockout_secs` | 900 s (60 .. 86400) | yes |
| `MIN_ADMIN_PASSWORD_LEN = 12` (auth.rs) | `web.min_password_length` | 12 (8 .. 128) | yes |
| session-cleanup / secret-rotation `interval(3600)` (patronus-web lib.rs) | `web.housekeeping_interval_secs` | 3600 s | yes |
| `REFRESH_SECS = 25*86400` (patronus-network ddns.rs) | `network.ddns_refresh_secs` | 2160000 s | yes |
| `PENDING_TTL_SECS = 24*3600` (patronus-config seg_wifi.rs) | `wifi.enrolment_ttl_secs` | 86400 s | yes |
| `SYNC_PORT = 3780` (patronus-network ha.rs + patronus-firewall ha_rules.rs, kept in step by hand) | `ha.sync_port` (in `lan_settings` with the other `ha.*` keys) | 3780 | yes |
| wifi-guard `CRASH_MAX=3 CRASH_WINDOW=600 SAFE_HOLD=3600 LOOP_BOOTS=2` (router-tier AP script) | `wifi.guard_crash_max`, `wifi.guard_crash_window_secs`, `wifi.guard_safe_hold_secs`, `wifi.guard_loop_boots` | 3 / 600 s / 3600 s / 2 | yes (takes effect at the next boot) |
| `INTERCEPT_PORT = 3129` (patronus-network proxy.rs + a literal in patronus-firewall svc_rules.rs) | `proxy.intercept_port` (`lan_settings`) | 3129 (1025 .. 65535) | yes |
| `patronus-guard` `GRACE=600` (Slate) | `guard.confirm_secs` | 600 s (60 .. 86400) | yes (next boot) |
| `patronus-init` rollback after the 3rd unconfirmed boot (Slate) | `guard.max_unconfirmed_boots` | 3 (1 .. 20) | yes (next boot) |
| `sleep 45` WAN-lease fallback in the Slate `apply` | `guard.wan_lease_fallback_secs` | 45 s (5 .. 600) | yes (next boot) |
| `AP_PHY_WAIT` 90 s radio wait (`ap`, GL-AX1800) | `wifi.radio_wait_secs` | 90 s (10 .. 600) | yes (next AP start) |
| wifi-guard `RECOVER_WAIT=20` | `wifi.recover_wait_secs` | 20 s (5 .. 300) | yes (next crash) |
| `upgrade-install` ubiblock wait (10 tries) | `upgrade.ubiblock_wait_secs` | 10 s (1 .. 120) | yes (next upgrade) |
| 7 catalog feed URLs in `feeds.rs` `CATALOG` | `feeds.url_spamhaus_drop`, `_spamhaus_edrop`, `_spamhaus_dropv6`, `_firehol_level1`, `_abusech_feodo`, `_abusech_sslbl`, `_et_compromised` | the former URLs (the catalog entry is the default; a test keeps the two equal) | yes |
| DB-IP GeoIP and ASN download addresses (`default_geoip_urls`, `default_asn_urls`) | `feeds.geoip_db_template`, `feeds.asn_db_template` (`{year}` `{month}`) | DB-IP lite, this month then last month | yes |
| ipdeny.com zone addresses (`geoip.rs`) | `feeds.ipdeny_aggregated_template`, `feeds.ipdeny_country_template` (`{cc}`) | ipdeny.com | yes |
| `FAMILY_LISTS` (patronus-network seg_dns) | `dns.family_lists` (`lan_settings`, already read before; the registry now owns the default) | the two preset lists | yes |
| `DEFAULT_DOWN_URL`, `DEFAULT_UP_URL`, `DEFAULT_BYTES_*` (speedtest.rs) | `speedtest.down_url`, `speedtest.up_url`, `speedtest.bytes_down`, `speedtest.bytes_up`, `speedtest.interval_hours` (existing keys, now registered) | Cloudflare speed endpoints, 25 MB / 10 MB, off | yes |
| `dns_servers: 8.8.8.8, 8.8.4.4` in `SystemConfig::default()` | `dns.fallback_servers` (new `Kind::Addrs`) | 8.8.8.8,8.8.4.4 | yes (new configurations) |
| captive-portal landing page `http://www.google.com` and the pre-auth resolver set `8.8.8.8 8.8.4.4 1.1.1.1` | `portal.default_redirect_url`, `portal.pre_auth_dns` | same values | yes |
| `PORTAL_PORT = 8081` (seg_time.rs; the key existed, unregistered) | `seg.time_portal_port` (`lan_settings`) | 8081 (1024 .. 65535) | yes |
| UPnP control port `5000` (miniupnpd.conf and the firewall rule) | `upnp.control_port` (`lan_settings`) | 5000 | yes |
| proxy port `3128` (`unwrap_or(3128)` in svc_rules next to the page's own `.def("3128")`) | `proxy.port` (`lan_settings`, the page's own key; a test keeps the page default and the registry equal) | 3128 | yes |
| `DEFAULT_VXLAN_PORT`, WireGuard `DEFAULT_PORT`, OpenVPN `1194`, GitOps webhook `9999` | `network.vxlan_port`, `vpn.wireguard_port`, `vpn.openvpn_port`, `gitops.webhook_port` | 4789 / 51820 / 1194 / 9999 | yes |
| fixed 13-entry language list (shared live installer; changed in the Horcrux master copy, reaches `gentoo/live-iso/common` with the next `sync-common.sh --from`) | the image's glibc `SUPPORTED` list | shortlist first, fallback only without glibc data | installer |

## Remaining, in priority order

Owned elsewhere (named here so the sweep stays complete):

- **Router-tier host name** (`hostname slate` / `hostname ax1800` in the `early` boot
  scripts): job *patronus-yescrypt-slate* moves it to `/etc/hostname` + `general.hostname`
  after the `/data` overlay mounts. The full tier already has `general.hostname`.
- **Config generations / declarative export** (*dc2-pat-gen*): `system_config` is a config
  table, so every registry key is versioned by generations automatically.
- **AP Wi-Fi settings** (`/etc/patronus/ap.env`, SSIDs, channel widths in the `ap` script):
  the router-tier Wi-Fi page owns them.

This sweep, next batches (P1 = owner-visible or security, P2 = operator tuning, P3 = rare):

1. ~~**P1 router-tier script values through `settings-env`**~~ done (batch 3): guard confirm
   window, unconfirmed-boot limit, WAN-lease fallback, radio/recovery/ubiblock waits, and the
   file is refreshed when a setting changes (`settings::set`/`reset` run
   `settings-env refresh`, hook path `PATRONUS_SETTINGS_HOOK`). `settings-env` also keeps a
   copy on the data volume (`/data/.settings.env`) because the earliest boot steps
   (`patronus-init`, `patronus-guard`) run before the store is applied.
2. ~~**P1 feed and update URLs**~~ done (batch 4): catalog feeds, GeoIP/ASN/ipdeny
   templates, DNS family lists, speedtest, captive portal and `dns.fallback_servers` are
   registry keys. Left: provider API endpoints of DDNS/alert integrations
   (Cloudflare, DuckDNS, Telegram, PagerDuty: protocol endpoints of a named third party,
   kept as constants), the threat-intel URLs of the legacy `patronus-ai` crate.
3. **P1 service ports**: VXLAN `DEFAULT_VXLAN_PORT`, WireGuard/OpenVPN form defaults
   (`DEFAULT_PORT`, 1194), gitops webhook 9999, UPnP 5000 (`svc_rules.rs`), and the
   duplicated default proxy port (`unwrap_or(3128)` in `svc_rules.rs`, also `.def("3128")` on
   the svc field). The time's-up page port is already a setting (`seg.time_portal_port`);
   register it (and the other existing `lan_settings` keys with their own pages, e.g.
   `ddns.force`, `general.*`) in the registry so one page and one CLI list every setting.
4. **P2 default subnets offered by forms** (L2TP `10.88.0.x`, OpenVPN `10.8.0.0/24`,
   NAT64 `192.168.255.0/24`, SD-WAN overlay `10.99.0.0/16`, HA example `192.168.50.254`):
   one `network.default_*` key each, used as the form's pre-filled value.
5. **P2 daemon/monitor timings** (gateway monitor 1 s ping, uplink probe `EVERY_SECS = 5`,
   alert evaluation 30 s, metrics 1 s/5 s, insight poll/retention, fwlog buffers,
   `applyd` 300 s idle, SD-WAN probe intervals): registry keys under `monitor.*`,
   `insight.*`, `sdwan.*`.
6. **P2 size limits** (feed `MAX_LIST_BYTES` 64 MiB, `MAX_DB_BYTES`/`MAX_ASN_BYTES`
   256 MiB, plugin bundle 16 MiB, seg_dns read cap): `limits.*` keys with bounds.
7. **P2 product data locations** (`/var/lib/patronus/...` status/state files in
   patronus-network, `DEFAULT_DB_PATH`): one `paths.state_dir` base (env + patronus.toml),
   files derived from it; the store path already has `--db` / `$PATRONUS_DB`.
8. **P3 installer**: fixed partition sizes in `patronus-installer` (`30 * 1024`,
   `50 * 1024` MiB) and its default locale become answer-file keys; the legacy example
   addresses in the live installer's help text are UI examples.

Counts and the exact lines are in the generated inventory; `ci/hardcode-baseline.tsv` is
the work list and shrinks with each batch.
