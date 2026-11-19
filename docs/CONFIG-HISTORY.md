# Configuration history

Every change made in the web UI or with `patronus config import|rollback` first keeps the configuration it started
from as a **revision** (the newest 200 are kept). Same idea as pfSense *Config History*, OPNsense *Configuration
History* and OpenWrt's LuCI rollback.

## Web UI: System > Configuration history (`/history`)

- Revisions: id, time, source (`web` or `cli`) and label ("before create firewall rule x").
- **Diff** compares a revision with the running configuration, per section: rows a restore would bring back, remove or
  change (field, old -> new). Password hashes, keys and tokens are shown as `(hidden)`, never as values.
- **Restore** asks for confirmation in a dialog, then restores and applies the revision to the whole system. The state it
  replaces is kept as a new revision, so a restore can itself be undone; if any subsystem refuses the old configuration the
  restore is undone.
- Phone (390 px): the table becomes cards, the dialog fits the screen.

## Confirm-or-revert timer (setting `history.confirm_seconds`, default 0 = off)

Typed key in `system_config` (so it is part of export / plan / apply and of every revision); settable on the history page and
at `PUT /api/system/history/settings` (0 or 10 to 3600). When set, a change on **Interfaces** or **Firewall** (and a restore
from the history page) stays in force but starts a countdown: a banner on every page offers **Keep changes** or
**Revert now**, and when the time runs out the box puts the previous configuration back by itself. The countdown runs in
`patronus-web`, so a change that cuts the admin off heals without the browser. Web accounts are never rolled back by the
timer. A restart of `patronus-web` during the countdown drops the countdown (the change stays; the revision to go back to is
in the history).

## API

| Method | Path | |
|---|---|---|
| GET | `/api/system/history` | revisions (`id`, `when`, `source`, `user`, `summary`) |
| GET | `/api/system/history/:id/diff` | per-section diff against the running configuration |
| POST | `/api/system/history/:id/restore` | restore + apply (admin) |
| GET/PUT | `/api/system/history/settings` | confirm timer seconds (PUT: admin) |
| GET | `/api/system/history/pending` | the unconfirmed change, if any |
| POST | `/api/system/history/confirm` / `revert` | keep / put back now (operator, admin) |

Restores, saved settings, confirmations and reverts are written to the audit log.

## CLI

`patronus config revisions`, `patronus config rollback ID`, `patronus config export > backup.json`,
`patronus config import backup.json`. Logging goes to **stderr** for every subcommand; stdout carries data only, so
`patronus config export > backup.json` is always valid JSON (`crates/patronus-cli/tests/config_stdout.rs`).

## Proof

- `crates/patronus-config/src/history.rs` tests (diff, secrets, setting), `lane_fh_tests` (API, timer, audit).
- `ci/netlab/lane-h-history-ui.sh` + `ci/config-history-page-e2e.py`: Firefox journey on the shipped binary (change, revision,
  diff, restore, phone width, timer banner).
