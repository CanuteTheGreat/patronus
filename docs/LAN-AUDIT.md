# LAN security audit

> Part of the built-in security suite (`docs/design/security-suite.md`, item 6).
> USE flag `lan-audit` (on by default on the standard tier). Off until you turn
> scheduled scans on; a manual "Scan now" works at any time.

"Scan my network" looks at the devices on your LAN for open ports and the
services behind them, runs a set of rules over the result, compares it with the
last scan, and raises findings that feed the security events. It never scans the
internet side (the WAN).

## What it scans

- **Targets** are the devices Patronus already knows: active DHCP leases,
  segmentation devices, and (optionally) the kernel neighbour table for devices
  it has not met yet. Each host is named from its segmentation device name or
  DHCP hostname. A scan does not sweep a whole subnet of empty addresses by
  default — it scans the hosts that exist.
- **Per segment.** By default every non-WAN interface; set `segments` to limit
  it (`@lan`, `@opt1`, or an interface name). `@wan` is refused.
- **Open ports and versions.** On the **standard tier**, when `net-analyzer/nmap`
  and `net-analyzer/rustscan` are installed (they are pulled in by the
  `lan-audit` USE flag), a fast rustscan sweep feeds `nmap -sT -sV` for service
  and version detection. On **every tier**, and as the fallback when those tools
  are absent, a small built-in TCP connect scan of the top ports with a light
  banner read runs instead — this is all the **router tier** ships (no nmap on
  the flash images).

## Finding rules

| Rule | Severity | Raised when |
|---|---|---|
| `telnet` | critical | TCP 23 is open (passwords in the clear) |
| `ftp` | warning | TCP 21 is open (plain FTP) |
| `smb` | warning (critical for SMBv1) | TCP 139/445 reachable |
| `upnp` | warning | UPnP/SSDP (1900, 2869) or SNMP exposed |
| `http_admin` | warning | an admin page on plain HTTP with no HTTPS alternative |
| `default_creds` | critical | a device whose banner matches a known default-credential product |
| `database` | warning | a DBMS port (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, …) answers on the LAN |
| `new_device` | info | a host that was not in the previous scan |
| `new_port` | warning | a port open now that was not open in the previous scan |

## Scheduled scans and quiet hours

`interval_hours` (0 = on demand only) runs a scan automatically. It only starts
inside the **quiet window** (`quiet_start_min`/`quiet_end_min`, local time,
wrapping midnight), so scanning does not compete with the household during the
day. `max_parallel` bounds how many ports are probed at once, `max_rate` caps
nmap's packet rate, and `connect_timeout_ms` is the per-port timeout.

## Findings into the security events

Each scan's findings are routed to the notification channels through the same
pipeline as every other security event (one incident per source+rule with an
occurrence count, never one message per port), at or above
`alert_min_severity` (default `warning`, so the `new_device` info findings do
not page you). Event kinds are `audit_telnet`, `audit_database`,
`audit_new_port`, etc.

## Reports and export

The page shows the latest scan's findings and the devices with their open ports,
and lists past scans. Any scan can be exported as **CSV** (one row per open
port) or a printable **PDF** report. Measured data (scans, hosts, ports,
findings) lives in `NON_CONFIG` tables bounded by `keep_scans` retention; a
backup, restore or rollback never carries or rewinds it.

## CLI

```
patronus scan now              # run a scan and print the result
patronus scan status           # settings + which scanner this unit uses
patronus scan list             # past scans
patronus scan show ID          # one scan's findings and open ports
patronus scan export ID        # CSV to stdout
patronus scan export ID --pdf  # PDF report to lan-audit-ID.pdf
patronus scan set enabled=1 interval_hours=24 segments=@lan quiet_start_min=120 quiet_end_min=300
```

## Resource cost

The built-in scan is a handful of TCP connects per host and costs almost
nothing. nmap's `-sV` probes are heavier but bounded by `max_rate` and
`max_parallel`. The router tier runs only the built-in top-ports scan; the
System page explains that nmap service detection is a standard-tier feature.

## Settings (all typed config keys, `lanaudit.*`)

`enabled`, `segments`, `interval_hours`, `quiet_start_min`, `quiet_end_min`,
`max_parallel`, `max_rate`, `connect_timeout_ms`, `discover_neighbours`,
`keep_scans`, `alert_min_severity` — exported, planned, applied and rolled back
like every other setting; the API is `/api/lanaudit`.
