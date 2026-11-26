# DNS filtering

The DNS page (DNS > Filter lists) blocks ads, trackers, malware and phishing names for the whole LAN with free,
community-maintained lists. Claim C1204 in the README; proof in `ci/netlab/lane-s-dns-filter.sh` (real Unbound, real
dnsmasq, real queries) and `ci/netlab/lane-s-dns-filter-ui.sh` (the page in Firefox).

## What you get

- A catalog of free lists, each with its licence recorded and linked (below), plus any list by URL
  (hosts file, domain list, or a zone in RPZ format).
- Scheduled refresh (1-168 hours, default 24) with status per list: names loaded, size, time of the last good download,
  last error. A failed download is retried after an hour and the last good copy keeps blocking. A download that holds no
  domain names (an HTML error page) or that shrank to under half of the previous copy is refused.
- Unbound: every list is one RPZ zone (`rpz:` clause, `respip` module), so a list of a million names does not bloat
  unbound.conf and is applied before the cache. Lists that are already RPZ zones (threat-intelligence feeds) load as
  they are. Blocked names answer NXDOMAIN, or `0.0.0.0` / `::` when "Blocked names answer" is set so.
- Per-list blocked-answer counts (today, 7 days, total) and a list of recently blocked names, read from Unbound's
  `rpz: applied [list]` log lines.
- An allow list that beats every list: a **domain** (the name and everything below it), a **wildcard**
  (`ads*.cdn.example.com`) or a **regular expression** (matched against the whole name, unanchored like pi-hole;
  anchor it with `^...$`). It also applies to the RPZ zones: a generated `allow` zone with `rpz-passthru` records
  comes first, and wildcards/regular expressions are expanded over the names of the subscribed lists.
- A DNS query log (switch "Log queries" on the DNS service card) with **Block this domain** (adds the name to the
  block list) and **Allow this domain** (adds it to the allow list) on every row; the recent-blocked table has
  Allow buttons.
- Router tier: dnsmasq gets the same lists as `address=/name/` lines, capped by the board's RAM.

## The catalog and its licences

| List | Kind | Format | About | Licence |
|---|---|---|---|---|
| StevenBlack unified hosts | ads, malware | hosts (names only) | 82,000 | MIT |
| OISD small | ads, trackers | domains + subdomains | 63,000 | GPL-3.0 |
| OISD big | ads, trackers, malware | domains + subdomains | 222,000 | GPL-3.0 |
| Hagezi Light / Multi Normal / Pro / Pro++ / Ultimate | ads, trackers, malware | domains + subdomains | 70,000 to 340,000 | GPL-3.0 |
| Hagezi Threat Intelligence Feeds (mini) | threat intelligence | RPZ | 329,000 | GPL-3.0 |
| Phishing Army | phishing | domains (names only) | 146,000 | free to use; "non-commercial community project", businesses must check the terms of its upstream sources ([licence page](https://phishing.army/license/)) |
| URLhaus malware hosts (abuse.ch) | threat intelligence | RPZ | a few thousand | CC0-1.0 |

Notes that matter:

- **URLhaus needs a free access key.** Since 2026-10-21 abuse.ch serves its exports only with an Auth-Key
  (https://auth.abuse.ch/). The page has a field for it; the key is stored in the configuration, never shown again by the
  API and never visible in `ps` (curl reads its URL from stdin). abuse.ch documents the export file name only behind its
  login: the catalog URL is `https://urlhaus-api.abuse.ch/v2/files/exports/{key}/rpz.txt`; if abuse.ch names it
  differently, edit the URL of the list.
- The sizes are hints from the day the catalog was written; the real count is in the list's status.
- A list does not appear in the catalog until its URL and licence were checked by hand. Free lists only: nothing needs
  a paid account.

## Cost and the board cap

The filter states what it costs and refuses what does not fit. Measured in `lane-s-dns-filter.sh` and with dnsmasq on
the same host:

| | names | resident memory |
|---|---|---|
| Unbound, RPZ zone with a `*.` twin per name | 150,000 (300,000 records) | 10 MB -> 193 MB, about 1.2 kB per name; unsubscribe + restart 3.5 s |
| dnsmasq, `address=/name/` | 150,000 | 2.1 MB -> 15.1 MB, about 90 B per name |

The limit is the smaller of the setting `dns.filter_max_domains` ("Most names", 0 = automatic) and the cap taken from the
board's RAM (`/proc/meminfo`, about 15% of it for Unbound, 5% for dnsmasq):

| RAM | Unbound (standard tier) | dnsmasq (router tier) |
|---|---|---|
| up to 200 MB | 40,000 | 90,000 |
| 200-400 MB | 40,000 | 200,000 |
| 400-512 MB | 40,000 | 400,000 |
| 512 MB - 1 GB | 60,000 | 400,000 |
| 1-2 GB | 120,000 | 800,000 |
| 2-4 GB | 250,000 | 800,000 |
| 4-8 GB | 500,000 | 800,000 |
| 8 GB and more | 1,000,000 | 800,000 |

A list is loaded as a whole or not at all (a half list would block by accident of ordering): the first lists, in
subscription order, take the budget; a list that does not fit is skipped and its status says "not loaded: N names do not
fit the limit ...". The catalog marks lists that are too big for the box. Hagezi Pro (about 240,000 names) therefore
needs a box with 2 GB or more as an Unbound resolver, Hagezi Ultimate 4 GB; a 128 MB router (dnsmasq, 90,000 names,
about 8 MB) carries StevenBlack (82,000) or OISD small (63,000), one of them, not both.

On the router tier dnsmasq blocks the name and everything below it for hosts lists too (an `address=` line is a subtree),
and has no RPZ: a list in RPZ format is loaded as its plain names. Counting blocked answers there needs
`log-queries` (the file is `/var/log/patronus-dnsmasq.log`, emptied when it passes 8 MB); a router with a flash-backed
`/var/log` should mount it as tmpfs.

## Configuration

Everything is a typed key in the store and therefore in `patronus config export`, revisions and rollback, the API and
the page. No daemon file is edited by hand.

| What | Where |
|---|---|
| Subscribed lists | table `dnsf_lists` (name, catalog id, URL, format, subdomains, enabled, RPZ action override, access key) |
| Allow list | table `dnsf_allow` (kind, pattern, description) |
| Refresh interval, name limit | settings `dns.filter_refresh_hours`, `dns.filter_max_domains` |
| Query log | setting `dns.log_queries` (existing) |
| Measured data (not configuration, kept out of exports and rollbacks) | `dnsf_status`, `dnsf_hits` (90 days), `dnsf_recent` (2,000 rows), `dnsf_querylog` (7 days, 200,000 rows), `dnsf_log_pos` |

API (all under `/api/dns-filter`, admin role): `GET /`, `POST /lists`, `PUT|DELETE /lists/:id`, `POST /refresh`
(`{"id": N}` or all), `PUT /settings`, `POST /allow`, `DELETE /allow/:id`, `GET|DELETE /log`. Blocking a name by hand uses the
existing `POST /api/dns/blocklist`.

RPZ action per list (`action`): empty = the zone's own policy; `nxdomain`, `nodata`, `drop`, `passthru` or `disabled`
(`disabled` logs and counts the hit but does not block: an "alert only" mode for a new list).

## Packaging

USE=dns (and USE=unbound for the resolver). `net-dns/unbound` must be >= 1.13 (RPZ logging and action overrides) and
`net-misc/curl` downloads the lists. The allow list's regular expressions use the `regex-lite` crate: nothing to install.
Both init systems: under systemd unbound runs in the foreground, so the same drop-in the per-device query log uses sends
its output to `/var/log/unbound/unbound.log`; under OpenRC unbound writes the file itself.

## Limits, said once

- RPZ applies to every client of the resolver. Per-device and per-group policies (device segmentation) keep their own
  views and block lists; the RPZ lists are not repeated inside those views.
- Unbound reloads (restarts) when a zone changed, about 3 s for 150,000 names; queries during the restart are retried by
  clients.
- A list changes only at its refresh time; "Refresh all now" downloads at once.
- The query log stores answers (rcode) and the list that blocked a query, not the query's answers.
