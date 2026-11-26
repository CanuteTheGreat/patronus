# Monitoring agents: Zabbix agent 2, Telegraf and the /metrics endpoint

Three optional pages next to the Prometheus text endpoint every Patronus web UI already serves.
They are off by default and are Gentoo USE flags (`zabbix-agent`, `telegraf`); the Metrics
endpoint page is always there. Menu: Advanced > Metrics endpoint / Zabbix agent / Telegraf.
API: `/api/svc/metrics`, `/api/svc/zabbix`, `/api/svc/telegraf` (same shape as every feature page:
`GET` settings + schema, `PUT` settings, collection rows for the Zabbix server list).

The embedded tier (access-point and Slate images) does not carry the agents: it keeps `/metrics`
and SNMP.

## Metrics endpoint

| Setting | Default | Meaning |
|---|---|---|
| enabled | on | off answers `404` to everybody |
| allowed_source | empty (any) | one network (`192.168.50.0/24`); everybody else gets `403`, a signed-in user too |
| token | empty | a scraper sends `Authorization: Bearer <token>` instead of logging in; the token opens `/metrics` and nothing else, and is never returned (`********`) |

Without a token a scraper still needs a session or an API key, as before.

## Zabbix agent 2

Package: `net-analyzer/zabbix[agent2]` (Zabbix 7.x). Installed from the Packages page or pulled in by
the USE flag.

| Setting | Default | Notes |
|---|---|---|
| enabled | off | |
| servers (rows) | none | Zabbix servers/proxies that may query the agent (`Server=`); at least one is required |
| active_server | empty | optional `ServerActive=` |
| hostname | empty = the system host name at apply time | must match the host entry on the server |
| listen_iface / listen_port | `@lan` / 10050 | the agent binds the first address of that interface and the firewall opens the port on that interface only (an unassigned role opens nothing, never "any") |
| psk_identity / psk | empty | hex key, 32 to 128 digits; stored in `psk.key` (0640, root:zabbix), never returned, removed when the agent is disabled |
| remote_commands | off (fixed) | `DenyKey=system.run[*]`, `UnsafeUserParameters=0`; the value cannot be changed |

Items beyond Zabbix's own `system.*`/`vm.*`/`net.*` keys come from one UserParameter,
`patronus.item[key,name]`, which runs `patronus zabbix-item key name`. The helper reads only the
metrics snapshot (below), as the unprivileged agent account, and exits 1 with a message when it cannot
answer (the item then shows as unsupported rather than as a made-up 0):

`host.uptime host.load1 host.load5 host.load15 host.mem.used_pct host.disk.used_pct firewall.rules
conntrack.entries conntrack.max dhcp.leases config.revision ha.master gateway.discovery
gateway.up[name] gateway.rtt_ms[name] gateway.loss_pct[name] service.up[name]`

`gateway.discovery` returns low-level-discovery JSON (`{#GATEWAY}`). UPS and S.M.A.R.T. items are
added by the lanes that bring those metrics. "Firewall counters" is the active rule count: the
metrics text carries no per-rule packet counters; Telegraf's nftables input has them.

## Telegraf

Package: `app-metrics/telegraf-bin` (the official release binary, `gentoo/app-metrics/telegraf-bin`
in the Patronus overlay; there is no Telegraf in the main Gentoo tree).

| Setting | Default | Notes |
|---|---|---|
| output | prometheus_client | or `influxdb_v2`, `influxdb_v1` |
| url | empty | InfluxDB only; `http(s)://host[:port]`, no credentials in the URL, checked before it is stored |
| token | empty | v2 API token / v1 password; never returned or shown in the dry-run render |
| organization, bucket, username | empty | v2: organization + bucket; v1: bucket = database, username |
| interval | 30 s | 5 to 3600 |
| listen_iface / listen_port | `@lan` / 9273 | Prometheus client only; the firewall opens the port on that interface only, and not at all for a push output |
| in_cpu, in_mem, in_disk, in_net, in_system, in_conntrack | on | |
| in_diskio | off | |
| in_nft + nft_tables | off, `inet patronus` | firewall counters; runs Telegraf with `CAP_NET_ADMIN` (ambient) and nothing else |
| in_patronus | on | gateways, firewall rule count, services, DHCP leases from the metrics snapshot |

The configuration is TOML written by Patronus: every string passes one escaper (quotes,
backslashes, every control character), and the tests parse hostile values back through a real TOML
parser to prove they stay one string.

## How the agents run

Both are `patronus-daemon@<instance>` units/init scripts (OpenRC and systemd alike), started under the
package's own account through `setpriv` (`zabbix`, `telegraf`). A host without that account runs them
as root and the apply report says so. A change restarts the daemon only when the generated
configuration changed; disabling stops it and deletes the credential-bearing files. Files live in
`/var/lib/patronus-monagent/<agent>/` (root:group 0750; `/var/lib/patronus` itself is closed to other
accounts).

## Metrics snapshot

While an agent that needs it is enabled, the web UI writes `/var/lib/patronus-monagent/metrics.prom`
(the text `/metrics` serves, 0644) every 30 s (`PATRONUS_MONAGENT_SNAPSHOT_SECS`). Agents read that
file: they never log in and never open the configuration database. The helper refuses a snapshot
older than 180 s (the web UI is not running) instead of reporting stale numbers.

## Proof

Rust: `patronus-network` monagent tests (renderers with hostile values, appliers with a real child
process under the supervisor, secrets), `patronus-firewall` svc_rules test, `patronus-web`
monagent_tests (API, masking, audit, undo, the `/metrics` gate over the router).
Netlab: `ci/netlab/lane-u-monagents.sh`. No Zabbix agent 2 or Telegraf package exists in the netlab
image, so the lane installs stand-in binaries that read the generated configuration and bind the
address in it; they bind every address on purpose, so the WAN-side refusal is the firewall's work.
The real daemons are covered by the ebuilds on Gentoo.
