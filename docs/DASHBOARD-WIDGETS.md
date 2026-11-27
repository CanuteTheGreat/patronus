# Dashboard widgets, system activity and the port test

Three related pieces of the web UI, all read from the same configuration
store and all usable on every tier that ships `patronus-web`.

## Dashboard widgets

Every card of the dashboard is a *widget* with a stable id. Each signed-in
user arranges their own dashboard:

- **Customize** switches the page into edit mode. Every widget gets a drag
  handle and **Move up / Move down / Remove** buttons (real buttons, so the
  keyboard works: Tab, Enter or Space; a status line says where the widget
  went). Widgets that are switched off are listed under **Hidden widgets**
  with an **Add** button. **Done** leaves edit mode, **Reset to default**
  forgets the user's layout.
- The layout is saved on every change. The page is drawn on the server from
  the saved layout, so there is no layout shift and nothing is fetched to
  decide what to show.
- The numbers refresh in place every `dashboard.refresh_seconds` (not while
  editing, not on a hidden tab); widgets that update themselves (System
  activity, Access point) are left alone.

### Where layouts live

Table `dashboard_layouts(user, layout_json, updated_at)` (migration 1620).
It is configuration: it is part of the export, of revisions and rollbacks, of
backups and of GitOps, like every other table that is not listed in
`NON_CONFIG_TABLES`. The document is
`{"v":1,"widgets":[{"id":"internet","on":true}, ...]}` in display order.

Rules:

- A layout belongs to the **web user of the session**; the request never
  names the user. API keys are not web users and get 403.
- Every role may save its own layout (it is a display preference). Read-only
  accounts included.
- On save, an id that is not in the registry or a repeated id is refused with
  400 and nothing is stored. Ids the user's role or this build cannot show
  are dropped from the stored copy.
- On read, ids the registry no longer knows are dropped, and a widget the
  layout has never heard of (added by a later release) appears **at its
  default position** (after the nearest earlier registry widget that is in
  the layout) with its default on/off. An old layout therefore survives an
  upgrade, and a downgrade.
- A stored document that is not valid JSON reads as "no layout" (the
  default).

### API

| call | meaning |
|------|---------|
| `GET /api/v1/dashboard/layout` | the layout the user sees, `customized`, the `default` layout and the `registry` (id, title, default_on, wide) the user may use |
| `PUT /api/v1/dashboard/layout` | body `{"widgets":[{"id":"system","on":true}, ...]}`; answers like GET |
| `DELETE /api/v1/dashboard/layout` | back to the default |
| `GET /api/v1/dashboard/settings` | the typed settings below |
| `PUT /api/v1/dashboard/settings` | administrators; any of the keys below; an out-of-range value is 400 and nothing is saved |

### Settings (typed `system_config` keys)

| key (API name) | default | range |
|----------------|---------|-------|
| `dashboard.refresh_seconds` (`refresh_seconds`) | 30 | 0 (never) or 5 to 3600 |
| `dashboard.activity_sample_secs` (`activity_sample_secs`) | 3 | 1 to 60 |
| `dashboard.activity_top` (`activity_top`) | 25 | 5 to 500 |
| `diag.tcp_timeout_secs` (`tcp_timeout_secs`) | 3 | 1 to 30 |
| `diag.tcp_tests_per_minute` (`tcp_tests_per_minute`) | 30 | 1 to 600 |

A stored value that is not a number in range is ignored and the default is
used.

### Adding a widget (for other features)

1. One line in `REGISTRY` (`crates/patronus-web/src/dashboard.rs`):
   `w("ups", "UPS", false, false, MinRole::ReadOnly, Gate::AnyFeature(&["ups"]))`
   (id, title, on by default, spans the whole row, lowest role that sees it,
   build/device condition). Default order is registry order.
2. A partial `templates/widgets/<id>.html` and one
   `{% else if w.id == "<id>" %}{% include "widgets/<id>.html" %}` branch in
   `templates/dashboard.html`. A widget that fills itself from JavaScript puts
   `data-live` on its root so the periodic refresh does not wipe it.

Ids are stored in layouts: never rename one.

## System activity

Menu entry **System activity** (`/activity`) and
`GET /api/v1/system/activity`. Read from `/proc` only (no `top`/`ps`), so it
works the same on the busybox-based access-point image.

- Processes: PID, user, kernel name, **redacted** command line, CPU %, resident
  memory, threads, state, and the managed service the process belongs to.
  Query: `sort` (`cpu` default, `memory`, `pid`, `name`, `user`, `threads`),
  `order` (`desc` default, `asc`), `limit` (default `dashboard.activity_top`,
  at most 500), `daemon` (only that service's processes). Anything else is 400.
- Load average, CPU busy %, memory and swap totals, uptime.
- **Daemons**: a rollup (processes, CPU, memory, threads) of the services in
  `patronus_network::services::KNOWN_SERVICES`, matched by program name
  (`charon` counts for strongSwan).
- CPU percentages need two samples. A background sampler (started by the first
  request, sampling every `dashboard.activity_sample_secs`, stopping after two
  minutes without a request) keeps the latest result; a request only reads it
  and never waits. The very first answer is `{"ready":false}` for about a second.
  A process that appeared inside the window shows 0 % until the next sample.
- Command lines are redacted before they leave `patronus-network`: values of
  options and `NAME=value` words whose name says password, passwd, passphrase,
  secret, token, api key, credential, private key, psk, bearer, authorization,
  cookie; the value after such an option (`--password hunter2`); `Bearer x`
  and `Basic x` words; `user:password@` in URLs. Scripts passed to `sh -c` are
  scanned word by word. Control characters are replaced and a line is cut at
  400 characters. Redaction errs on the side of hiding.

## Test port (Diagnostics)

`POST /api/system/diag` with `{"tool":"tcp","host":"example.com","port":443}`
and optionally `interface` (send through this device), `source` (local
address), `family` (`4`, `6`, `auto`) and `timeout` (seconds; default
`diag.tcp_timeout_secs`). Answer: `state` = `open` (connected), `closed`
(refused), `filtered` (no answer within the timeout), `unreachable` (no route)
or `error`, plus `resolved`, `ms`, `error`. Host must be an address or DNS
name by the same rules as ping; nothing reaches a shell (the connection is
made in-process). More than `diag.tcp_tests_per_minute` tests a minute are
answered with 429. UDP is out of scope: without an answer a UDP port cannot be
told from a filtered one.

## Tests

- `patronus-network`: parsers on fixture `/proc` trees, two-sample CPU
  percentages, rollup, sorting, redaction forms, `tcp_test` open/closed and
  validation, failure classification and the rate window.
- `patronus-config`: settings validation and layout rows in the export.
- `patronus-web` (`routes/dashboard_tests.rs`, `dashboard.rs`, `state/activity.rs`):
  defaults, round trip, isolation between users, read-only role, unknown ids,
  API keys, the page drawn from the layout, settings, the activity API with a
  real process carrying secrets.
- Netlab `lane-h-diag.sh`: open, refused and timed-out connections against
  lab namespaces, source interface, hostile input, the rate limit.
- Netlab `lane-u-dashboard-ui.sh` (`ci/dashboard-page-e2e.py`, Playwright +
  Firefox, axe-core): add/remove/reorder by keyboard and by mouse, persistence,
  a second user, reset, light and dark, 1280 px and 390 px, the activity page
  and the port test through the page.
- The embedded QEMU gate (`ci/embedded-aarch64/ax1800/qemu-gate.sh`) checks
  that the activity and layout APIs answer 200 on the booted image.
