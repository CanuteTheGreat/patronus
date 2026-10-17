# Patronus -- Instructions for AI Coding Agents

## Platform: Gentoo Linux, from the ground up

Patronus is built specifically for Gentoo Linux. This is not incidental --
it is the core design point of the project, alongside Portage's USE-flag
model (fine-grained feature selection at build time, embracing source-based
compilation). Do NOT default to generic/Debian/Ubuntu conventions just
because they are common boilerplate for a Rust project. Specifically:

- The canonical install path is the real Gentoo overlay at `gentoo/` (a
  full, self-contained Portage repo: `metadata/layout.conf`,
  `profiles/repo_name`, `net-firewall/patronus/patronus-9999.ebuild`,
  `net-firewall/patronus-installer/`). Any packaging or install-flow change
  belongs there first.
- `Dockerfile` builds through real Portage (`emerge` against that same
  overlay), NOT `cargo build` directly against a generic Debian/Ubuntu base
  image. If you ever see a Dockerfile in this repo doing `FROM rust:*` ->
  `cargo build` -> `FROM debian:*-slim`, that is WRONG and a regression --
  it was fixed once already (2026-09-24) after being silently introduced by
  an earlier AI coding session that defaulted to boilerplate instead of
  checking the project's actual target platform.
- USE flags (see `gentoo/net-firewall/patronus/patronus-9999.ebuild`'s
  `IUSE`) are a core selling point over competitors like pfSense/OPNsense --
  they let an installer choose exactly which features (web UI, eBPF/XDP,
  SD-WAN, AI detection, cloud integrations, etc.) get compiled in. Any
  container or CI build path MUST preserve this (pass USE flags through as
  a build arg to `emerge`), not silently compile a fixed feature set.
- `gentoo/catalyst/` and `gentoo/build-bootable-iso.sh` / `build-minimal-iso.sh`
  build a real bootable Gentoo installer ISO -- this is a SEPARATE, dedicated
  path from the app Dockerfile, also Gentoo-based (`gentoo/stage3`), and
  should stay that way.
- Any new documentation, README section, CI workflow, or install script
  should assume Gentoo as the primary/default target. Non-Gentoo Linux can
  be mentioned as "also runs on any modern distro" but must never replace
  or overshadow the Gentoo-first framing.

If you are an AI coding agent working on this repo and are unsure whether
something should be Gentoo-specific, ask -- do not assume "generic Linux
container" is a safe default here. It has caused real, silent architectural
drift before (same class of bug hit Horcrux, a sibling project, on the same
day).

## Architecture: one store, one Applier per subsystem, one boot apply

Every subsystem (firewall, interfaces, routes, DHCP, DNS, VPN, HA, ...)
follows the same shape. Do not add another in-memory list, fixture, or
config file that only one process knows about.

### Config store (`crates/patronus-config`)

- The single source of truth is the SQLite store
  (`patronus_config::ConfigStore`, file `/var/lib/patronus/config.db`,
  override with `--db` or `$PATRONUS_DB`). The web UI, the CLI and the
  GitOps engine write rows there; appliers read them back.
- **Schema changes are migrations.** Add ONE file
  `crates/patronus-config/migrations/NNNN_<lane>_<description>.sql`;
  `build.rs` picks it up (no Rust list to edit). Never edit a migration
  that is already on main -- add a new one. Each lane owns a number range
  and the `lane_ranges_are_respected` test enforces it:
  A 1-99, B 100-199, C 200-299, D 300-399, E 400-499, F 500-599,
  G 600-699, H 700-799, I 800-899, J 900-999, K 1000-1099, M 1100-1199.
- **Table ownership:** a lane creates and owns its own tables (prefix them
  with the subsystem, e.g. `dhcp_pools`, `wg_peers`). Shared foundation
  tables: `system_config`, `interfaces` (lane C owns the columns except
  `role`), `firewall_rules`/`nat_rules` (lane B), `routes`/`vlans`
  (lanes E/C), `sysctls`, `config_revisions`, `audit_log`.
  Typed accessors for a lane's tables live in that lane's crate next to its
  applier and use `ConfigStore::pool()`; only foundation accessors live in
  `store.rs`.
- **Interface roles:** `interfaces.role` is `wan`, `lan` or `optN`. Rules
  and services refer to roles as `@wan` / `@lan` / `@optN` (and `@mgmt` for
  anti-lockout: LAN, else WAN, else any) and resolve them at apply time,
  so re-assigning a NIC never strands config on the old device name. An
  unassigned role must skip the item with a warning, never widen it to
  "any".
- **Rule origins:** `firewall_rules.origin` / `nat_rules.origin` is
  `system` (anti-lockout; the store refuses to delete/edit it), `default`
  (seeded once on first boot, user-deletable, never re-seeded), `user`, or
  `gitops` (keyed by name).
- **Policy routing contract (B <-> E):** `firewall_rules.gateway` names a
  gateway or gateway group; lane E resolves it to an fwmark, lane B renders
  `meta mark set`.
- History: `ConfigStore::snapshot()` before a change set,
  `restore_revision()` to roll back (`patronus config revisions|rollback`).
  `export_json()`/`import_json()` cover every lane's tables automatically.

### Appliers (`patronus_config::Applier`)

Implement `Applier` once per subsystem, in the crate that owns it
(`patronus-firewall/src/applier.rs`, `patronus-network/src/sysctl.rs`, ...):

- `phase()`: `Sysctl` -> `Interfaces` -> `Routes` -> `Firewall` ->
  `Services` (boot order).
- `apply(store)`: **full state, idempotent** (read everything you own,
  make the system match; running twice is a no-op), **atomic** where the
  backend allows (one `nft -f` transaction; write a temp file + rename,
  then reload the daemon), **fail closed** (keep the previous working
  state or a lockdown state, never half-applied or wide open).
- Daemons are started through `patronus_core::ServiceManager` (systemd AND
  OpenRC) with the Patronus-generated config path passed explicitly
  (`unbound -c`, `dhcpd -cf`, `swanctl --load-all` from /etc/patronus/...).
- `render(store)`: what `apply` would do, for `patronus apply --dry-run`.
- `resource_kinds()` / `upsert_resource()` / `delete_resource()`: the
  GitOps engine (`ApplyEngine::with_target`) dispatches declarative
  resources of those kinds to you, then calls `apply` once.
- Register it with ONE line in the right phase block of
  `crates/patronus-cli/src/commands/apply.rs::registry()`. That gives you
  boot-time apply, `--phase`, `--dry-run` and GitOps for free.

### Boot

`patronus-firewall.service` / `/etc/init.d/patronus-firewall` run
`patronus apply`: open the store, on first boot assign interface roles from
`[network]` in `/etc/patronus/patronus.toml` and seed the safe defaults
(`patronus_config::defaults`: anti-lockout tcp/22+8443 on LAN, LAN->any,
WAN inbound dropped by policy, outbound masquerade on WAN, IPv4/IPv6
forwarding), then run every applier in phase order. `patronus firewall
apply` is the firewall phase only.

### Web UI (`crates/patronus-web`)

- State: `src/state/<subsystem>.rs`, a thin manager over the store + your
  applier. A mutation = validate -> write store -> `applier.apply()` -> on
  failure undo the store write and return the error ("Invalid ..." errors
  become HTTP 400). See `state/firewall.rs`. Add your manager as one field
  in `state/mod.rs::AppState`. Delete your subsystem's fixture data and
  show honest empty states.
- API: `src/routes/api/<subsystem>.rs` exposes `pub fn router()`; register
  it with ONE `.merge(api::<subsystem>::router())` line in
  `routes/mod.rs::api_routes()`. Pages: your template in
  `templates/<subsystem>.html`.

### Proving it

CI must show the kernel/daemon state, not just API responses:
`ci/netlab/` builds network namespaces + veth pairs inside one capped
container (see `ci/netlab/lane-a-foundation.sh`) and asserts on
`nft list ruleset`, `/proc/sys`, `ip route`, daemon state, and real
traffic between namespaces. Add your lane's script there and call it from
`ci/netlab/run.sh`.

Use the shared harness `ci/netlab/lib.sh` (`. "$(dirname "$0")/lib.sh"`):
`nl_up` builds LAN client / router / ISP / internet host (dnsmasq DNS for
`*.example.test`, HTTP on :80/:8080), `nl_boot DB` is a reboot (fresh
namespaces + `patronus apply`), `nl_web_start`/`nl_login`/`nl_api` drive
the real web UI from the LAN client, and `nl_expect_online`,
`nl_expect_http[_blocked]`, `nl_expect_dns`, `nl_expect_[no_]tcp`,
`nl_assert_nft_has/lacks`, `nl_assert_sysctl`, `nl_assert_conntrack`,
`nl_assert_lockdown` assert real outcomes. Name scripts `lane-*`,
`journey-*`, `failure-*` or `upgrade-*` and run.sh picks them up.

Every user-visible claim in README.md needs a row in
`docs/claims-ledger.txt` naming the tests that prove it
(`ci/claims-check.sh` enforces it). When your lane lands a feature, add
the claim and its proof together. Core modules have mutation-score floors
(`ci/mutants-floors.txt`, nightly): add tests until new code holds them.
