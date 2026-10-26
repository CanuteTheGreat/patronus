# Self-filling aliases and the firewall log

Lane B objects whose contents come from outside the box. All of them are
ordinary firewall aliases (`$name` in a rule, nft sets
`alias_<name>_v4|_v6|_ports`), so rules, GitOps and the API treat them like any
other alias. Code: `crates/patronus-firewall/src/feeds.rs` (parse, cap, refresh,
threat rules), `crates/patronus-web/src/state/{fwfeeds,fwlog}.rs` (web side),
UI: Firewall page, tabs **Aliases**, **GeoIP**, **Threat Intel**, **Logs**.
Proof: `ci/netlab/lane-b-feeds.sh`, `ci/netlab/lane-b-fwlog.sh`, README claims
C56-C59.

## URL-table aliases

An alias of type *URL table (IPs)* or *URL table (ports)* has a source row in
`firewall_alias_sources` (`kind = url`): an http(s) URL, a refresh interval
(5 minutes to 1 year, default 24 h) and an entry cap (default 100 000, hard
limit 500 000). The list is plain text, one address / CIDR / `a-b` range per
line (ports and `a-b` port ranges for the ports type); `#`, `;` and `//`
comments, trailing comments (Spamhaus `1.2.3.0/24 ; SBL1`) and NDJSON lines
(`{"cidr":"1.2.3.0/24"}`) are understood, unusable lines are counted and skipped.
Overlapping and adjacent entries are merged. A list of /0 to /7 (IPv4) or /0 to
/15 (IPv6) prefixes is refused entry by entry.

* A background task in `patronus-web` refreshes whatever is due once a minute; a
  failed refresh is retried after at most 15 minutes. A failed or garbage
  download keeps the previous entries and the alias's `last_status` says why.
* A changed list is swapped into the nft set in one transaction (`flush set` +
  `add element`), the ruleset is not reloaded; if that cannot run the ruleset
  is re-applied.
* The entries are stored, so boot (`patronus apply`) needs no network.
* Only `http://` and `https://` URLs are accepted (curl with `--proto
  =http,https`, `--max-filesize`, 5 minute limit).

API: `POST/PUT /api/firewall/aliases` with `"type":"urltable"` (or
`urltable_ports`) and `"source":{"kind":"url","url":...,"refresh_secs":...,
"max_entries":...}`; `POST /api/firewall/aliases/refresh {"names":[...]}` refreshes
now (empty = every self-filling alias).

## GeoIP

The database is DB-IP "IP to Country Lite" (CC BY 4.0, attribution: IP
Geolocation by DB-IP), `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz`,
published monthly; the current month is tried first, then the previous one. It is
kept decompressed at `/var/lib/patronus/feeds/dbip-country-lite.csv`
(`$PATRONUS_FEEDS_DIR`). A GeoIP alias lists country codes; its entries are the
merged ranges of those countries (IPv4 and IPv6). Use it as the source or
destination of any rule: one block rule for a whole country set.

* The database is re-downloaded every `firewall.geoip.refresh_days` (default 30),
  all GeoIP aliases are rebuilt when it changes; a failed download keeps the
  old file. `db_url` can point at a mirror (empty = DB-IP).
* `GET /api/firewall/geoip` (settings, countries, aliases), `PUT` (db_url,
  refresh_days), `POST /api/firewall/geoip/refresh` (download now and rebuild),
  `GET /api/firewall/geoip/lookup?ip=` (country of an address).
* The GeoIP tab creates a country set and, optionally, the block rule(s) in one
  step. MaxMind is not used (account and licence key required).

## Threat-intelligence feeds

A feed is a self-filling alias `ti_<id>` (`kind = threat`). The catalog on the
Threat Intel tab: Spamhaus DROP / EDROP / DROPv6, FireHOL level 1, abuse.ch Feodo
Tracker and SSLBL; any other list can be added as a custom feed. An enabled feed
with entries makes the firewall jump to the chain `ti_check` from input, forward
and output, right after the anti-lockout rule and before every user rule:

* members of the host alias `ti_allow` `return` (they continue through the
  user's rules unchanged);
* each feed drops its addresses as source (`in`), destination (`out`) or both
  (default), with a hit counter and a rate-limited log line
  `patronus[ti:<id>] drop:` (shown in the log viewer as `feed:<id>`).
* Private and reserved space (RFC 1918, CGNAT, loopback, link-local, multicast,
  ULA, ...) is removed from every threat feed whatever it lists, so a feed that
  contains `10.0.0.0/8` cannot cut the LAN off.
* Size: `max_entries` per feed and a shared budget over all enabled feeds
  (`firewall.threatintel.max_total`, default 400 000).

API: `GET /api/firewall/threatintel`, `PUT/DELETE /api/firewall/threatintel/:id`
(`enabled`, `url` for custom feeds, `direction`, `refresh_secs`, `max_entries`),
`PUT /api/firewall/threatintel-budget`.

## Firewall log

Rules with the Log flag, threat-feed drops and (switch on the Logs tab,
`firewall.log_default_deny`) the default policy's drops log to **NFLOG group 7**
with the prefix `patronus[<rule id>] <action>: ` / `patronus[ti:<id>] drop: ` /
`patronus[default] drop: `. NFLOG is used instead of the kernel log because it
works in every network namespace, needs no syslog daemon and carries the
interface indexes; `patronus-web` reads the group through a raw netfilter
netlink socket (CAP_NET_ADMIN; needs the `nfnetlink_log` module, which the
kernel loads on demand), attributes each packet to its rule and appends it to
`firewall_log` (newest 20 000 lines kept, at most 400 lines/s written).
`PATRONUS_FWLOG=0` turns the collector off.

`GET /api/firewall/logs?rule=&action=&src=&dst=&proto=&port=&iface=&q=&minutes=&since_id=&limit=`
searches (rule = id or part of its name, `src`/`dst` match by prefix); `since_id`
returns only lines newer than the cursor (`last_id` of the previous answer), which
is how the **Live** switch follows the log. `DELETE /api/firewall/logs` clears it,
`PUT /api/firewall/logs/default-deny {"enabled":true}` switches default-deny
logging.
