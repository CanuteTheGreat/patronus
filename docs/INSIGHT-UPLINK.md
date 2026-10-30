# Traffic insight history and uplink health (device segmentation, part d)

Implements section 7 of `docs/design/device-segmentation.md`. Everything is
measured: an empty router shows empty tables and says why (collection off,
database not downloaded), never sample rows.

## Traffic insight history (`/insights`, `/api/insights/*`)

- **Collector** (`patronus-web/src/state/insight.rs`): every 15 s it reads
  `/proc/net/nf_conntrack` (byte counters are switched on by the sysctl
  applier), keeps the last counters per flow and adds the *delta* to
  `ins_usage`, one row per `(hour, internal address, up|down, country, ASN)`,
  flushed once a minute. The first look after a start only sets the baseline;
  a counter that went backwards is a new flow with the same tuple (counted
  whole); a flow that vanished drops out. Direction comes from the original /
  reply tuple (`up` = from the internal side). LAN-to-LAN traffic, multicast,
  the router's own addresses and flows without counters are not recorded.
  Inbound port-forward flows are attributed to the inside server (reply tuple).
- **Enrichment**: DB-IP "IP to Country Lite" (the file the GeoIP aliases
  already use) and "IP to ASN Lite" (`patronus-firewall/src/asn.rs`, `AsnDb`
  with sorted ranges and binary search, quoted organisation names). Files:
  `$PATRONUS_FEEDS_DIR` (default `/var/lib/patronus/feeds`) `dbip-country-lite.csv`,
  `dbip-asn-lite.csv`; a file replaced under the running service is re-read.
  Both are CC BY 4.0: attribution is on the page.
- **Monthly update**: `patronus ipdb update [--force]` (and `ipdb status`),
  run by `patronus-ipdb.timer` (systemd: OnBootSec=15min, monthly, randomised,
  persistent) or `/etc/cron.monthly/patronus-ipdb` (OpenRC), both installed by
  the ebuilds with `USE=insight` (default on; RDEPEND curl, and virtual/cron
  on OpenRC). The web service also refreshes hourly-checked, 30-day-old files
  itself (`PATRONUS_IPDB_REFRESH=0` turns that off, for tests). A failed
  download keeps the old file and is retried after 15 minutes; this month's
  URL falls back to last month's.
- **Retention and size**: 30 days by default (`insight.retention_days`), top
  200 rows per hour (`insight.top_n`): the smallest fold into country `--` /
  ASN 0 of the same address and direction, so device totals stay right.
  Tables `ins_usage`, `ins_uplink_samples`, `ins_uplink_hourly` are measured
  data: excluded from config export/import and revisions (a restore or
  rollback does not rewind them).
- **Privacy**: collection can be switched off; `ins_exclude` names addresses /
  CIDRs, device names or group names that are never recorded. Adding an
  exclusion deletes what was recorded for it. "Delete all recorded history"
  clears the table. All of it is audit-logged.
- **Per device**: rows are keyed by the internal IP; the device views map
  `seg_devices` (`ip4`, `last_ip`, group) to addresses at query time, so the
  history works with and without the segmentation model, and survives a device
  changing its name. `device=` accepts an IP, a device id or a device name.

API (area `dashboard`): `GET /api/insights/countries|asns|devices|timeline`,
`GET /api/insights/devices/{key}`, `GET|PUT /api/insights/settings`,
`GET|POST|DELETE /api/insights/exclusions`, `DELETE /api/insights/history`,
`GET|PUT /api/insights/database`, `POST /api/insights/database/refresh`.
`window=1h..3650d`, `limit=1..1000`.

## Uplink health, probes, SLA (`/insights#uplinks`, `/api/uplinks/*`)

- **Monitor** (`patronus-network/src/routes.rs`, in `patronus applyd`): still
  pings every gateway once a second. New: `ins_uplink_probes` rows add TCP
  (connect), HTTP (`curl --interface`, any answer below 500) and DNS (A query,
  NOERROR with an answer) probes, every 5 s through the gateway's own device
  (`SO_BINDTODEVICE`), in the background so the ICMP tick never waits. A probe
  fails after 2 failures in a row and recovers on the first success.
- **Routing**: a probe target that is an IP literal is pinned to its gateway
  with a host route (proto 252, like a monitor IP), so a gateway that is not
  carrying the default route can still be probed. HTTP probes should use an IP
  in the URL for the same reason. A target pinned to two gateways is refused
  with a warning.
- **Failover**: a probe marked *critical* counts as a lost sample while it
  fails, so loss/down triggers of gateway groups act on it ("ping works, DNS is
  dead"). Non-critical probes only mark the uplink *degraded*.
- **History** (`patronus-web/src/state/uplink.rs`): a recorder reads the
  published results every 15 s; one sample per gateway per minute goes to
  `ins_uplink_samples` (state, RTT, loss, which probe kinds worked, degraded),
  rolled up per hour in `ins_uplink_hourly`. Raw samples are kept 7 days, the
  hourly SLA data 90 days. Availability = samples not `down`; quality =
  samples fully healthy (online and no failing probe).
- **Alerts** (the existing channels: event log, `/api/events`, signed
  webhooks, `EVENT_KINDS`): `uplink_probe_failed` (warning, critical when the
  probe is critical), `uplink_probe_recovered`, `uplink_sla_breach` /
  `uplink_sla_ok` (24 h availability against `uplink.sla_target`, off at 0),
  next to the existing gateway_down / gateway_up / gateway_degraded.

API (area `routing`): `GET /api/uplinks/status|health|sla|outages`,
`GET|POST /api/uplinks/probes`, `PUT|DELETE /api/uplinks/probes/{id}`,
`GET|PUT /api/uplinks/settings`.

## Proof

`ci/netlab/lane-s-insight.sh` and `lane-s-uplink.sh` (claims C70, C71);
unit tests in `state/insight.rs`, `state/uplink.rs`, `asn.rs`,
`uplink_probe.rs`, `routes/tests.rs`, `routes/insight_api_tests.rs`.
Test knobs: `PATRONUS_INSIGHT_TICK_SECS`, `PATRONUS_INSIGHT_FLUSH_SECS`,
`PATRONUS_UPLINK_TICK_SECS`, `PATRONUS_UPLINK_SAMPLE_SECS` (seconds between
samples; the SLA "minutes" are then sample counts), `PATRONUS_IPDB_REFRESH`.
