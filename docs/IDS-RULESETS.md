# Intrusion detection: rule sets, policy, alert browser

USE=intrusion-detection (Suricata), standard tier. Page: **Intrusion detection** (`/svc/ids`), alert
browser `/svc/ids/alerts`, API `/api/svc/ids/...`. Parity target: OPNsense Intrusion Detection and the
pfSense Suricata package (docs/design/pfsense-opnsense-parity.md, section 6).

## What it does

- **Rule sets** (`ids_sources`): a typed list of sources, each with a key, name, URL, format
  (`tar.gz`, `rules`, `rules.gz`), licence, size cap and an on/off switch. Seeded once, all OFF:
  ET Open, abuse.ch SSL blacklist (certificates and JA3), abuse.ch URLhaus, OISF traffic ID,
  tgreen hunting rules. Add your own by URL (a local mirror works). The Positive Technologies Research
  open set is not seeded because its upstream feed was withdrawn; add it by URL if it comes back.
  `{suricata_version}` in a URL is replaced by the installed Suricata's version (ET Open needs it).
- **Download** is the product's own task (`patronus applyd`, or patronus-web when there is no applyd):
  a rule set you switch on is fetched at once, an older one in the nightly window (settings
  `update_hour`, `update_window_hours`, `update_interval_hours`, local time of the router), a failure
  waits `update_retry_minutes` (default 60). The **Update rule sets now** button asks the root applier to fetch everything.
- **Verify before swap**: the download is unpacked (`tar.gz` entries with `..` or an absolute path are
  refused, only regular `*.rules` files are kept), then the *whole* merged candidate (this source's
  new files plus every other running set, your own rules, `threshold.config`) is loaded with
  `suricata -T`. Only a candidate Suricata accepts replaces `sources/<key>/current` (the old one
  is kept as `prev`). An empty, oversized, non-archive or rejected download changes nothing: the old
  rules keep running and the source shows `failed` / `rejected` with the reason. The same bytes again
  show `unchanged`.
- **Policy** (`ids_policies`, `ids_overrides`): an action `alert`, `drop` or `disable` per rule set, per
  category (the rule file, e.g. `emerging-malware`) or per classtype, and per SID. Most specific wins:
  SID override, then classtype, category, rule set, then the rule as shipped. A rule shipped switched
  off (`# alert ...`) stays off unless its SID is overridden to alert/drop. Bulk policies never turn a
  `pass` rule into an alert or drop. `drop` blocks only in inline (IPS) mode; in IDS mode it logs.
- **Suppress / threshold** (`ids_suppress`): suppress a rule (everywhere, or for one source/destination
  address) or limit/threshold it per source/destination; rendered to `threshold.config`.
- **Interfaces and HOME_NET**: the watch interface (`@wan`, `@lan`, `@optN` or a device) plus more
  interfaces, and the protected networks, are typed settings.
- **Alert browser**: `ids_alerts` is filled from `eve.json` by the root task. Filter by period, source,
  destination (an address or a prefix), SID, text and result (alert only / blocked); top rules, sources
  and destinations; one click on an alert makes a suppress entry for its rule, for its source or
  destination, or a limit of one alert per hour. A suppress made from an alert goes through the same
  snapshot, apply and undo path as the page's own forms.
- **Dashboard card**: running state, mode, rules loaded (and how many are set to block), last rule-set
  update and the last 24 hours of alerts.

## Not configuration

`ids_source_state`, `ids_alerts`, `ids_alert_pos` and `ids_update_request` are in `NON_CONFIG_TABLES`:
export, backup, revisions and rollback neither carry nor rewind them. The rule files live in
`<state>/suricata/sources/`. **Alert retention** is two typed settings, `alert_retention_days`
(default 30) and `alert_max_rows` (default 200000), enforced every ten minutes by the same task.

## Files and API

| | |
|---|---|
| `<state>/suricata/sources/<key>/{current,prev}/*.rules` | downloaded rule files (kept untouched; the policy is applied while merging) |
| `<state>/suricata/sources.rules` | the merged, policy-applied set Suricata loads |
| `<state>/suricata/patronus.rules`, `threshold.config`, `suricata.yaml` | your own rules, suppress/threshold, config |
| `GET /api/svc/ids` | settings, collections, status (`rule_sets`, `rules_loaded`, `alerts_24h`, ...) |
| `POST /api/svc/ids/action/update` | Update rule sets now |
| `GET /api/svc/ids/alerts?window=24h&src=&dst=&sid=&q=&action=&limit=&offset=` | alert browser |
| `GET /api/svc/ids/alerts/top?by=src\|dst\|sid` | top talkers |
| `POST /api/svc/ids/alerts/{id}/suppress` | `{"scope":"rule\|source\|destination","kind":"suppress\|limit\|threshold\|both"}` |
| `GET /api/svc/ids/summary` | the dashboard numbers |

All of it is in the declarative config (export, plan, apply, generations) except the tables above.

## Proof

`ci/netlab/lane-j-ids.sh` (real Suricata, a local HTTP rule source, no internet): scheduled download,
policy drop really drops, a category alert only logs, classtype and SID precedence, suppress from an alert
stops the alert, a broken download is refused and the old set keeps running, reboot keeps the sets.
`ci/netlab/lane-j-ids-ui.sh` + `ci/ids-page-e2e.py`: Playwright Firefox through the pages, 1280 and 390 px,
light and dark. `ci/a11y` checks both pages with axe (WCAG AA) in Firefox and Chromium.
Unit tests: `ids_sets`, `ids_alerts`, `ids` in patronus-network.

## Router (embedded) tier

Not on the router image (AP and Slate classes): the page, its API and the alert browser are compiled out
(USE=intrusion-detection is off there), `/api/features` lists intrusion detection as absent with the reason,
and the QEMU gate (`no_ids` in `ci/embedded-aarch64/ax1800/qemu-gate.sh`) checks that those pages answer
404 with that explanation. Why it does not fit, measured with the real set (below): a Suricata with ET Open
needs about 0.5 GB just to load and more while it runs, which is the whole RAM of an AP-class unit.

## Measured with the real ET Open set (x86_64, Suricata 7.0.3 from Ubuntu 24.04, 2 CPUs)

| | |
|---|---|
| download | `emerging.rules.tar.gz` 5.7 MB, 54 rule files, 56 MB unpacked, 72,601 rule lines of which 19,517 ship switched off |
| merged `sources.rules` (53,084 active rules, policy applied) | 36 MB, rendered in 80 ms; the same with a ruleset-wide `drop` policy: 53,084 dropping rules, 87 ms |
| `suricata -T` of the merged bundle (what runs before every swap) | exit 0, 12.8 s, peak 520 MB resident |
| disk per source | `current` + `prev` copy of the unpacked files (about 2 x 56 MB for ET Open) plus the merged file |

An update therefore costs one download, one 13 s check and one daemon restart (the restart reloads the
whole set; in IPS mode the firewall's `bypass` keeps forwarding while Suricata loads).
