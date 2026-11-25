# System log page

`/logs` (menu: Advanced > System log, on every tier and on access points) and `GET /api/logs/system` show what the
box's services and kernel wrote, with the **priority the logger recorded**. The Monitoring page keeps a short preview
(`logview.preview_lines`, newest first) that links here.

## Back ends, chosen at run time

| Back end | When | Priority comes from |
|---|---|---|
| journald (`journalctl -o json`) | `logview.backend=auto` and journald runs (`/run/systemd/journal/socket`) and `journalctl` exists; or `journald` | `PRIORITY`; `_BOOT_ID` draws the boot separators, `_TRANSPORT=kernel` marks kernel lines, `_SYSTEMD_UNIT` / `SYSLOG_IDENTIFIER` feed the unit / identifier filters |
| syslog files | otherwise (OpenRC hosts, both router images), or `files` | the line itself, see below |

If journald is chosen but cannot run, the page falls back to the file and says so in its note.

File formats read (`crates/patronus-web/src/logview/parse.rs`, unit-tested):

- busybox syslogd: `Nov 25 12:00:00 host daemon.warn ident[pid]: text` (the router images; nothing to configure);
- rsyslog / syslog-ng with the Patronus template: `2026-11-25T12:00:00.123456-08:00 host daemon.warning ident[pid]: text`;
- RFC 5424 and any line with a leading `<PRI>`;
- the traditional format (`Nov 25 12:00:00 host ident: text`) carries **no priority**. Such a line shows as `unknown`, is
  never classified by its words, and a minimum-priority filter leaves it out; the page says so.

### Standard tier: the logger writes the priority

With `logview.manage_logger` on (default), the syslog applier (`patronus apply`, USE=syslog) configures the installed
logger to write a second file, `logview.managed_file` (`/var/log/patronus/system.log`), with facility.severity in every
line, next to the distribution's own logs (which stay untouched):

| Logger | Drop-in |
|---|---|
| rsyslog | `/etc/rsyslog.d/40-patronus-priority.conf` (validated with `rsyslogd -N1`; needs the `$IncludeConfig /etc/rsyslog.d/*.conf` line, otherwise a warning says so) |
| syslog-ng | `/etc/syslog-ng/conf.d/patronus-priority.conf` (needs `conf.d` included and a `source` in the main file) |
| sysklogd | `/etc/syslog.d/patronus-priority.conf` (`;RFC5424` format) |

plus `/etc/logrotate.d/patronus-system` (20 MB, `rotate logview.rotated_files`, `copytruncate`). The viewer prefers the
managed file when it has data, else `logview.file_path` (default `/var/log/messages`; the old `PATRONUS_SYSLOG` environment
variable still sets it). netlab runs rsyslog and busybox syslogd for real; the syslog-ng and sysklogd drop-ins are
only unit-tested.

## Query

`GET /api/logs/system?since=&until=&min_priority=&unit=&identifier=&kernel=&q=&limit=&cursor=`

- `since` / `until`: epoch seconds, RFC 3339, or `YYYY-MM-DD HH:MM[:SS]` in the box's local time; `since` after `until` is a 400;
- `min_priority`: `emerg alert crit err warning notice info debug` or 0-7: that severity and worse;
- `unit`: journald `_SYSTEMD_UNIT`; files: the identifier equal to the unit, or mapped by `logview.unit_map` (`identifier=service,...`);
- `identifier`: exact or with `*` (case-insensitive); `kernel=1`: kernel lines only; `q`: text in message or identifier;
- `limit`: newest N matching records (default `logview.default_limit` 500, at most `logview.max_limit`, never above 2000);
- `cursor`: the `older_cursor` of the previous answer for the next older page.

The answer is chronological: `entries` holds `line` items and `boot` separator items (`-- boot <id> --`), plus
`older_cursor`, `newest_cursor`, the identifiers seen (the page offers them), `scan_limited` (the scan budget ran out: narrow
the filters) and `priority_known`.

`GET /api/logs/system/stream` takes the same filters and follows new records (Server-Sent Events: `hello`, `line`, `boot`).
Every event's `id` is a resume cursor; a reconnect with `Last-Event-ID` (or `cursor=`) continues without losing or repeating
a line, also across a log rotation. A stream ends after `logview.stream_max_secs`; the page reconnects by itself. Files are
polled every `logview.live_poll_ms`.

`GET /api/logs/system/download?...&format=txt|json` returns the filtered view (at most `logview.download_max_lines`).

`GET|PUT /api/logs/system/settings` (write needs an admin): every `logview.*` key below.

## Settings (`system_config`, so export / plan / apply, backups and GitOps carry them)

`logview.backend` (auto), `file_path`, `managed_file`, `manage_logger`, `rotated_files` (3), `default_limit`, `max_limit`,
`max_scan_bytes` (8 MiB), `live_poll_ms`, `journalctl`, `boot_markers` (`Linux version |patronus-boot:`), `unit_map`,
`preview_lines`, `stream_max_secs`, `download_max_lines`. Layers: built-in < environment (`PATRONUS_LOGVIEW_*`,
`PATRONUS_SYSLOG`) < store. The System log page has a card for them.

## Boot separators

journald: the boot id changes. Files: a line carrying a boot marker (`Linux version ...` from the kernel, or the boot
record `patronus-boot: boot <boot id>` that the router images' syslogd service writes once per start). A marker with the same
boot id as the previous one (a logger restart) draws no separator.

## Memory (router tier)

Files are read backwards in 64 KiB blocks and stop at the page limit or `max_scan_bytes`; the live follower reads only
the bytes appended since its cursor and never consumes a half-written line. A page is at most 2000 records. The QEMU gates of
both router images read the log through the API on the image's real busybox syslogd and check that patronus-web's resident
memory grows by less than 8 MiB (see docs/embedded-routers.md for the measured numbers). Compressed rotated files (`.gz`) are
not read.

## Proof

Unit tests in `patronus-web` (`logview::*`), `patronus-config` (`logview`), `patronus-network` (syslog); netlab
`ci/netlab/lane-h-syslog-viewer.sh` (real rsyslog and busybox syslogd, API filters, live stream under 2 s, resume,
separators, 60 MB file) and `lane-h-syslog-viewer-ui.sh` (Firefox at 1280 and 390 px, light and dark, contrast); QEMU gates
`ci/embedded-aarch64/ax1800/qemu-gate.sh` and `ci/embedded-mips/slate/qemu-gate.py`. Claim C87.
