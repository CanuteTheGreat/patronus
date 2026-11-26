# Ideas from Proxmox VE 9.3 for Patronus

Proxmox VE 9.3 (November 2026) is a virtualization platform, not a firewall, but several of its point-release
features are things every serious router/firewall admin wants too, and its web UI sets a bar for density and
consistency that Patronus should meet. This page records, for each 9.3 highlight, whether it applies to a router,
what Patronus has today (checked in the code on `main`, file references below), what pfSense/OPNsense do, and the
plan. Each gap is built as its own change with netlab / QEMU acceptance tests, on the standard tier AND the
embedded (router/AP) tier unless the row says why a tier is out.

Source: the Proxmox VE 9.3 release highlights video and release notes; pfSense and OPNsense current documentation
(links at the end).

## Summary

| # | Proxmox VE 9.3 feature | Applies to a router? | Patronus today | Status | Plan |
|---|---|---|---|---|---|
| 1 | Structured system log viewer: colour by priority, live mode, timespan, minimum priority, per unit, syslog identifier with `*` wildcard, "kernel only", a separator at every reboot | Yes (pfSense *Status > System Logs* has an advanced filter, OPNsense per-component log views with severity filter and live view) | Monitoring page card "System journal (last 200 entries)": `journalctl` JSON when built with `journal`, else the last lines of `/var/log/messages` with the severity GUESSED from the words "error"/"warn" in the text (`crates/patronus-web/src/state/monitoring.rs` `read_syslog_file`); fixed dark box with hard-coded colours (`templates/monitoring.html`); no filter, no live mode, no time range; a standard-tier OpenRC box built with `journal` shows nothing | partial | [A](#a-structured-system-log-viewer) |
| 2 | API / admin **access log** with statistics (who, from where, which requests failed; by client, user, API token, path group, status; drill-down links back into the filtered log) | Yes, and more so for a firewall (audits, a stolen API key, brute force) | `audit_log` records configuration changes only and has NO page in the UI (`ConfigStore::audit`, `crates/patronus-config/src/store.rs`); sign-in events go to the `patronus::audit` tracing target (`auth.rs`) only; API keys keep `last_used_at` (`apikeys.rs`). No per-request log, no statistics | missing | [B](#b-access-log-and-audit-log) |
| 3 | Notification matchers nested arbitrarily (all / any / not), shown as a tree, plus a calendar (weekdays + start/end time) | Yes ("page me for WAN down at night, mail me package updates in business hours") | Notification channels exist (signed webhook, ntfy, Telegram, Discord, Slack, email; `state/telemetry.rs`, migration `0740_h_notify.sql`), each filtered by event kinds and one minimum severity. No nesting, no time windows, no preview | done (docs/NOTIFY-MATCHERS.md) | [C](#c-notification-matchers) |
| 4 | Installer sets up link aggregation (bond) and VLAN-tagged management, so a new box is reachable on the right network at first boot | Yes: ISP VLAN tags (PPPoE or DHCP over VLAN), a management VLAN on a trunk to the core switch, LACP to the switch | Runtime bonds (`patronus-network/src/bond.rs`) and VLANs (`vlan.rs`) exist, but the installer (GUI, text and answer file) only knows one plain WAN and one plain LAN port (`[network.wan]` / `[network.lan]`, docs/ISO-INSTALL.md) and skips bond NICs (`liveinst/system.py` `NIC_SKIP`) | missing | [D](#d-installer-bonds-and-vlans) |
| 5 | Node maintenance mode from the web UI that evacuates HA resources to other members | Yes, as HA-pair maintenance (pfSense/OPNsense: CARP "persistent maintenance mode") | Present: VRRP (keepalived) + conntrackd, `POST /api/ha/maintenance` advertises priority 1 so the peer becomes master (`patronus-network/src/ha.rs` `MAINTENANCE_PRIORITY`, netlab `ci/netlab/ha-services-test.sh` step 9, claim C42). Gaps: the call returns before the peer has taken over and does not refuse when the peer is unhealthy; firmware upgrade / restart on an HA node does not enter maintenance first; no HA configuration sync (pfSense XMLRPC sync / OPNsense HA sync) | partial | [E](#e-ha-maintenance-with-confirmed-hand-off) and [F](#f-ha-configuration-sync) |
| 6 | Third-party storage plugins configured through UI generated from the back end's schema (hints, limits) | The idea yes (signed Patronus plugins) | Signed plugins (`patronus-network/src/plugins.rs`) have no settings schema, so a plugin's settings need a hand-written page | missing | [G](#g-schema-driven-plugin-settings) |
| 7 | Web UI polish: resource tree, consistent toolbar + grid, dense typography, colour by severity, live panels, step wizards, inline hints | Yes | 32 server-rendered pages with per-page inline styles and scripts, tokens in `theme_head.html`; light/dark follow the device. Inconsistent tables/forms, no shared grid (sort/filter/column chooser), little inline help; findings below | partial | [H](#h-web-ui-design-system) |
| - | Multipath iSCSI / FC / NVMe-oF, LVM on SAN, Ceph 21.2, LXC 7, QEMU 11.1 | No (storage/virtualization) | - | n/a | - |

Top three by value for a firewall: **B** (access log: security audits and brute-force/API-key visibility, nothing
like it today), **A** (the log viewer is the first page an admin opens when something breaks, and on OpenRC it is
empty), **H** (the UI is what people judge first; pfSense, OPNsense and Proxmox are all denser and more consistent).

## A. Structured system log viewer

What it must do (both tiers):

- One API, `GET /api/logs/system?since=&until=&min_priority=&unit=&identifier=&kernel=&limit=&cursor=`, and a
  follow mode (`GET /api/logs/system/stream`, Server-Sent Events, resumes from a cursor) used by "Live".
- Back ends, chosen at runtime, not at build time: journald (`journalctl -o json`, `_BOOT_ID` for reboot
  separators, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `PRIORITY`, `_TRANSPORT=kernel`), and syslog files for OpenRC
  hosts and the router tier (`/var/log/messages`, path configurable, rotated `.0` files included). Busybox syslogd
  writes `facility.level` into each line, sysklogd/syslog-ng/rsyslog are configured by Patronus' syslog applier to
  do the same (`%syslogpriority%`-style template), so the priority is READ, never guessed from words. Reboot
  separators on file back ends come from the kernel's first line (`Linux version ...`) and on the router tier from
  the boot record the early boot writes.
- Filters: time span (since/until with time of day), minimum priority, unit/service (OpenRC: service name from the
  identifier map), identifier with `*` wildcard, kernel only, free text. "Reset" restores defaults. Filters live in
  the URL so a link reproduces the view.
- Rendering: monospace, compact, colour + weight per priority from theme tokens (no hard-coded hex), readable in
  light and dark, a "-- boot <id/time> --" separator row, pause/resume in live mode, download of the filtered view.
- Memory bounds for the router tier: stream the file from the end (seek, bounded read), never load whole files;
  limit 2000 lines per page.

Acceptance: unit tests for each parser (journald JSON, busybox, rsyslog/syslog-ng formats, rotated files, boot
detection); netlab lane `lane-h-syslog-viewer.sh` (writes lines with `logger -p daemon.warning -t test-ident`,
asserts filter results through the API, the live stream delivers a new line within 2 s, a fake reboot marker
yields a separator); Playwright Firefox e2e on the page at 1280 and 390 px, light and dark; embedded QEMU gates
(ax1800 `qemu-gate.sh`, Slate `qemu-gate.py`) check the API on the real busybox syslog of the image and the
patronus-web RSS budget.

## B. Access log and audit log

- Record every web/API request after it is answered: time, client address, authenticated principal (user, or API
  key id + name), method, a path GROUP (the route template, e.g. `/api/firewall/rules/:id`, never the raw path with
  ids or query strings: no secrets in the log), status, duration, bytes. Failed logins are recorded with the
  attempted user name. Kept in a bounded table outside the configuration (`NON_CONFIG_TABLES`, retention by rows
  and days, typed settings; router tier defaults smaller) written in batches, not one transaction per request.
- Page *System > Access log*: live mode or time span (date + time), filters user (exact match option), API key,
  method, path contains, client, status class (2xx/3xx/4xx/5xx), free search; double-click a row for details.
  "Statistics" for the current filter: totals (requests, client errors, server errors), requests per bucket
  chart, and tables by client, user/API key, path group and status, each value a link that applies that filter.
- The existing configuration audit log (`audit_log`) gets its own tab on the same page (who changed what, filter,
  CSV), which closes the "Audit log page" row in [FEATURE-PARITY.md](../FEATURE-PARITY.md).
- Events: a burst of failed logins or a 5xx storm becomes a `system_events` event, so notifications can route it.
- Acceptance: unit tests (path grouping never stores ids/tokens, retention, batching); netlab lane
  `lane-h-access-log.sh` (wrong password, API key GET, operator POST of a firewall rule, a 404, then assert rows,
  principals, statuses and the statistics counts through the API); Playwright e2e (filter, statistics link
  drill-down, both widths and schemes); embedded QEMU gates (row cap holds under a request burst, RSS budget).

## C. Notification matchers

- A matcher is a tree: groups `all` / `any` / `not`, leaves on event kind, severity (>=), subject/interface glob,
  and a calendar leaf (weekdays + start and end time, in the box's time zone; windows across midnight allowed).
  Each channel references one matcher; a migration turns today's kinds + minimum severity into an equivalent
  matcher per channel, so nothing changes for existing setups.
- UI: the tree with drag-and-drop between groups and keyboard move up/down/indent (drag alone is not accessible), a
  "would match" preview against the last 50 events.
- Typed in the declarative config (export, plan, apply, GitOps), validated (depth and size limits).
- Acceptance: unit tests for evaluation (nesting, not, calendar edges, DST); netlab lane `lane-h-notify-matchers.sh`
  with a local webhook receiver and the fake clock (`PATRONUS_FAKE_TIME_FILE`): an event inside the window is
  delivered, outside it is not, nested any/all behave; Playwright e2e of the tree editor; embedded QEMU gates
  (matcher evaluation on the router image, an event reaches a webhook on the emulator's host).

## D. Installer bonds and VLANs

- Installer (GUI, text and answer file, one stage list): WAN and LAN can each be a plain port, a bond (LACP
  802.3ad / active-backup / balance-xor, members, hash policy) or a VLAN on top of either (tag 1-4094), plus an
  optional separate management VLAN/port that carries the anti-lockout rule and the web UI. WAN modes stay DHCP /
  static / PPPoE, now also over a VLAN (common ISP setups: VLAN 7, 10, 35, 201, ...; no list hard-coded, the tag is
  typed).
- Answer file: `[network.wan] bond = ["eth0","eth1"]`, `bond_mode`, `vlan = 7`; `[network.mgmt] iface/vlan/address`.
  The first boot bootstrap (`[network]` in patronus.toml) accepts the same keys, so the router tier's provisioning
  uses the same format.
- Done means: the installed box answers on `https://ADDRESS/` (443) and `http://ADDRESS/` redirects, on the tagged
  management network, at its first boot, without a console.
- Acceptance: vmtest scenario `installed_lagg_vlan.py` (QEMU with two NICs into a host-side Linux bond in LACP
  mode and a VLAN-aware bridge; answer-file install; after boot the web UI and SSH answer only over VLAN-tagged
  management, LACP partner state is collecting/distributing, one member link cut keeps it reachable), GUI/text
  installer screenshots; both inits (OpenRC and systemd ISOs).

## E. HA maintenance with confirmed hand-off

- `POST /api/ha/maintenance {"enabled": true}` checks first that the peer is alive and healthy (VRRP adverts seen,
  conntrackd sync up) and refuses with a clear reason otherwise (`force` for the case where the peer is the broken
  one); then lowers priority and WAITS (bounded, typed timeout) until every VIP is held by the peer and this node
  is BACKUP, reporting progress; the HA page shows a banner while a node is in maintenance.
- Firmware upgrade, package update with restart, and restart/shutdown from the UI on an HA node enter maintenance
  first (setting, default on) and leave it after the node is back and healthy.
- Acceptance: extend `ci/netlab/ha-services-test.sh` (refusal with the peer stopped, hand-off waits until the peer
  is MASTER, an established TCP flow survives, an upgrade-style restart path enters/leaves maintenance).
- Router tier: HA is not in the embedded images today (FEATURE-PARITY row "VRRP/CARP virtual IPs": missing on Router
  and Small); keepalived's size there is measured and recorded before deciding, not assumed.

## F. HA configuration sync

- The primary pushes selected configuration sections (firewall rules, aliases, NAT, DHCP, DNS, VPN, ...; per-section
  switches, interface names mapped by role) to the backup over the HTTPS API with a dedicated API key, the backup
  applies them through its normal appliers and keeps its own revision for rollback. Same idea as pfSense/OPNsense
  XMLRPC/HA sync.
- Acceptance: netlab two-router lane: a rule added on the primary appears on the backup and is in its nftables;
  a section switched off is not touched; a failed apply on the backup is reported on the primary.

## G. Schema-driven plugin settings

- A plugin manifest may declare settings (typed: string/int/bool/enum/address/port/list, min/max, pattern, hint,
  default, secret). Patronus stores them as typed config keys and renders the form from the schema (hints on
  hover/focus, limits enforced server-side), so plugin authors write no UI code.
- Acceptance: unit tests (schema validation, rejection of out-of-range values), Playwright e2e with a signed test
  plugin, export/import round trip.

## H. Web UI design system

- Patronus adopts the shared, framework-neutral UI kit that Horcrux is building (tokens, components, optional
  vanilla JS; per-product theme so Patronus keeps its branding; size budget that fits the router tier; vendored at a
  pinned version and compiled into the binary). Pages migrate one at a time behind the existing tests.
- Findings and the screenshot comparison are below (all pages, desktop 1280 px and phone 390 px, light and dark,
  standard tier and router tier in both roles).
- Acceptance: Playwright visual-regression screenshots committed for every page (both widths, both schemes, both
  tiers), the UX crawl (`ci/ux-qa/ux_crawl.py`) clean against a live patronus-web, WCAG AA contrast scan, and the
  embedded QEMU gates' page checks.

### UI findings (2026-11-25, `main` 2c677d42)

Method: patronus-web run three ways (standard tier with the default features; the router-tier feature set in the
access-point role; the same in the router role), every page reachable from the menu crawled with
`ci/ux-qa/ux_crawl.py` in Firefox at 1280 and 390 px, light and dark (132 page loads per variant), screenshots
reviewed against Proxmox VE 9.3 (system log, access log, notification and summary views) and current
pfSense/OPNsense pages for the same tasks.

Fixed together with this document:

| Finding | Fix |
|---|---|
| `/network` (linked from the dashboard and the Interfaces page) was a standalone page without the menu or the layout: no way back on a phone, own Arial styling, red "danger" frame around the route count | extends `base.html` like every page, theme tokens only |
| Pages of features a build leaves out (`/ha`, `/qos`, `/packages`, `/segmentation`, DHCP/DNS/NTP, `/svc/*`) were bare unstyled HTML without the menu, and told router-tier users to rebuild with a USE flag they cannot set | one `not_built.html` page in the normal layout: on the router tier it says the image leaves the feature out and links the System page list; on the standard tier it names the USE flag; on an access point it says the main router does it |
| Six `<input pattern>` attributes (host name, segmentation and DNS policy names) were invalid regular expressions under the `v` flag browsers use: the browser logged an error and skipped the check | patterns escaped; `ci/check-template-js.py` now compiles every template pattern with the `v` flag |
| Monospace text (MAC addresses, keys) rendered at the browser's small monospace size because the font was the bare `monospace` generic | `--font-mono` token (font list) used everywhere |
| Plain links in page text used the browser's default blue, which clashes with the theme and is hard to read on dark cards | `.content a:not([class])` uses the theme accent |

Open (built by the UI design-system adoption, section H, with the screenshots as before/after):

- No shared data grid: tables differ per page; no toolbar (add, bulk enable/disable/delete, filter), no per-row
  action menu, no column chooser, no sort where order is not semantic. Firewall rules: the name column wraps to
  three lines while address columns have slack, rows are 95-130 px tall (pfSense/OPNsense/Proxmox: 24-34 px), and
  at 390 px only the first five columns are visible without a scroll hint.
- Forms are always expanded under the tables (Add rule ~380 px permanently); fields not relevant to the chosen
  chain stay visible; "any" is a pre-filled value instead of a placeholder; checkboxes run together inline.
  Proxmox/OPNsense: an Add button opens a dialog/drawer with conditional fields and inline hints.
- Summary cards carry one number each and waste most of their area; health values (disk at 86 %, load) are grey
  body text without thresholds; kernel stub devices (gre0, gretap0, erspan0) fill the interface lists; byte
  counters are raw integers; empty values are written four ways ("none", "N/A", zeros, blank).
- The dashboard is a snapshot ("measured when this page loaded") with no refresh; Proxmox summary panels update
  live.
- Access-point role dashboard shows router cards (firewall rules, VPN, DHCP leases) first; radios, SSIDs and
  clients are not on it.
- Header: a colour emoji as the theme toggle in a line-icon UI; one-item "Overview" nav group; "Home" breadcrumb vs
  "Dashboard" title.
- Firewall states call answers 503 where conntrack is unavailable (container) and the page shows the raw error;
  the Interfaces page asks `/api/wifi/uplinks` on builds without Wi-Fi client support and prints a USE-flag hint on
  the router tier (should read `/api/features` first).

## Links

- Proxmox VE 9.3 release notes: https://pve.proxmox.com/wiki/Roadmap
- pfSense system logs and the advanced log filter: https://docs.netgate.com/pfsense/en/latest/monitoring/logs/index.html
- OPNsense log files and live view: https://docs.opnsense.org/manual/logging_firewall.html
- OPNsense logging settings: https://docs.opnsense.org/manual/settingsmenu.html
