# S.M.A.R.T. disk health

Disk health in the way the pfSense/OPNsense S.M.A.R.T. pages and OpenWrt's smartd packages show it: which
disks the machine has, whether each says it is healthy, how hot it runs, how many sectors are bad (ATA),
how worn it is (NVMe) and what its last self-test said. Package flag `USE=smart` (cargo feature `smart`,
default on in the ebuild, pulls in `sys-apps/smartmontools`). The monitoring is **off until you switch it on**
(page: Hardware > S.M.A.R.T., API: `/api/svc/smart` for the settings and `/api/v1/smart` for the status,
CLI: `patronus smart status|poll|run`).

## How it works

- `patronus smart run` is a small supervised root daemon (`patronus-daemon@smart`; OpenRC and systemd alike).
  Every `poll_minutes` it runs `smartctl --scan --json` and `smartctl -a --json` per disk, judges the answer
  against the settings, stores the latest report (`smart_state`) and one history row (`smart_samples`, pruned
  after `retention_days`), and starts the scheduled short/long self-tests inside the configured time window.
- The web process is not root and never runs smartctl. It reads the tables; "start a self-test" writes a
  request that the poller picks up within `request_check_secs`.
- ATA, NVMe and SCSI/SAS disks are understood. A disk without S.M.A.R.T. (a virtual disk, an SD card or eMMC
  on a router or access point) is listed as "unsupported" with the reason smartctl gave and never raises an
  alert. A machine with no such disk at all gets an honest empty state on the page, and a build without
  `smartctl` says so. The embedded access-point tiers carry no disks and no extra package weight.

## What is judged

| Level | When |
|---|---|
| critical | the disk's own health check says FAILED, an ATA attribute is at or past its failure threshold, NVMe critical warning bits are set, temperature at or above `temp_crit`, or a self-test ended in a read failure |
| warning | reallocated sectors at or above `realloc_warn`, pending or uncorrectable sectors, NVMe percentage used at or above `nvme_used_warn`, temperature at or above `temp_warn` |
| ok | none of the above |

A temperature alert clears only after the disk is `temp_hysteresis` degrees below the limit.

## Settings (all of them typed, with the default shown)

`enabled` off, `poll_minutes` 30, `test_poll_secs` 60 (poll interval while a self-test runs),
`request_check_secs` 10, `short_test_hours` 24 (0 = never), `long_test_days` 7 (0 = never),
`test_window_start` 2 (hour of day), `test_window_hours` 5, `temp_warn` 50, `temp_crit` 60,
`temp_hysteresis` 3, `realloc_warn` 1, `nvme_used_warn` 90, `notify` on, `retention_days` 365.
They live in the declarative config (export, plan, apply, generations) like every other page.

## Notifications

A disk changing between ok, warning and critical becomes one event (`disk_smart_warning`,
`disk_smart_failing`, `disk_smart_ok`) on the same notification path as gateway and tunnel alerts, so
channels, matchers and webhooks apply. A change is reported once, not on every poll.

## API

- `GET /api/v1/smart`: enabled, poller state, summary counts, `empty` (the reason when there is nothing to
  show) and `devices` (name, protocol, model, serial, health `PASSED`/`FAILED`, level, reasons, temperature,
  power-on hours, reallocated/pending/uncorrectable sectors, NVMe wear/spare/critical warning, last self-test).
- `GET /api/v1/smart/{disk}`: drill-down with the attributes, the self-test log and the history.
- `POST /api/v1/smart/{disk}/test` and `POST /api/v1/smart/test` with `{"type":"short"|"long"}`: queue a
  self-test (admin only; any other type is refused).

## Proof

- Parsers run on `smartctl --json` captured from QEMU disks (SATA, NVMe, virtio) plus documented-schema
  fixtures for failing, pending-sector, worn-NVMe and SAS disks: `crates/patronus-network/tests/fixtures/smart/`
  (`tools/vmtest/smart-capture.sh` regenerates the captured ones).
- Poller, schedule, hysteresis, retention and applier: `cargo test -p patronus-network --features smart --lib smart`.
- API, page, permissions and validation: `cargo test -p patronus-web --features smart --lib smart`.
- The installed image with an emulated SATA and NVMe disk: `tools/vmtest/scenarios/installed_smart.py`
  (gate `installed-smart` in `gentoo/live-iso/project/ci-gates.sh`).

Claim C190 in `docs/claims-ledger.txt`.
