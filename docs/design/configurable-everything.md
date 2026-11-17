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
  default, unit, effect }`. Values live in `system_config`; an unset key reads as its
  default; a stored value that no longer validates (bounds tightened later) reads as the
  default with a warning.
- API: `GET /api/settings` (login), `PUT /api/settings/{key}` `{"value": ...}` and
  `DELETE /api/settings/{key}` (admin, audited, 400 on invalid, 404 on unknown key).
- UI: System > **Advanced settings** (`/settings`), grouped by section, with default,
  unit, "takes effect" and a Reset per changed value. Read-only accounts see the values.
- CLI: `patronus settings list [--json] | get KEY | set KEY VALUE | reset KEY |
  env [--output FILE]`. `env` prints `PATRONUS_SET_<KEY>='value'` lines for shell boot
  scripts on the router tier (sourced, with the registered default as the fallback).
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
| address | 32 | 162 | 1422 | 1616 |
| constant | 76 | 8 | 4 | 88 |
| fixed-list | 7 | 0 | 4 | 11 |
| hostname | 2 | 0 | 0 | 2 |
| interface | 21 | 16 | 437 | 474 |
| path | 59 | 85 | 67 | 211 |
| port | 9 | 3 | 20 | 32 |
| size | 10 | 0 | 0 | 10 |
| timing | 133 | 5 | 66 | 204 |
| uid/gid | 0 | 5 | 14 | 19 |
| url | 43 | 21 | 33 | 97 |
| wifi | 7 | 6 | 10 | 23 |
| **all** | 399 | 311 | 2077 | 2787 |

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

1. **P1 router-tier boot scripts read settings**: `wifi-guard` crash thresholds and window
   (3 crashes / 10 min, `sleep 60`), `upgrade-install` waits, `patronus-guard` confirm
   window (600 s): source `patronus settings env` output (`/etc/patronus/settings.env`,
   regenerated by applyd on change) with today's values as registered defaults.
2. **P1 feed and update URLs** (`patronus-firewall` feeds.rs/geoip.rs catalog, seg_dns
   blocklists, `CFG_ASN_URL`/`CFG_GEO_URL` defaults, speedtest defaults, captive-portal
   probe URL and DNS servers `8.8.8.8/8.8.4.4/1.1.1.1`): catalog entries become data rows
   with an editable URL; resolver defaults become `dns.fallback_servers`.
3. **P1 service ports**: HA sync port (`ha.rs`/`ha_rules.rs` `SYNC_PORT`), time's-up page
   port (`seg_time.rs` `PORTAL_PORT`), transparent proxy `INTERCEPT_PORT`, VXLAN
   `DEFAULT_VXLAN_PORT`, WireGuard/OpenVPN form defaults (`DEFAULT_PORT`, 1194),
   gitops webhook 9999, UPnP 5000.
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
