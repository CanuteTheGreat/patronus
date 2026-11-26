# Web access log (System > Access log)

Every request to the web UI and API is recorded by one middleware (`access_log_layer`, `crates/patronus-web/src/routes/mod.rs`)
into a bounded history table `web_access_log`, written in batches by a background writer (`state/accesslog.rs`).

## What is stored
Time, client address, principal (signed-in user, API key name, or anonymous with the attempted user name for a failed sign-in),
method, **route group** (ids, tokens and query strings are replaced; the raw path is never stored), status, duration, bytes.
Passwords are never read. The table is excluded from configuration export/restore (`NON_CONFIG_TABLES`).

## Settings (typed, API `/api/system/access-log/settings`, environment, store wins)
`accesslog.enabled`, `retention_rows`, `retention_days`, `flush_ms`, `queue`, `login_burst`/`login_window_secs`,
`error_burst`/`error_window_secs`, `event_cooldown_secs`. Environment: `PATRONUS_ACCESS_LOG_RETENTION_ROWS`, `_RETENTION_DAYS`,
`_FLUSH_MS`, `_QUEUE`. The router tier (`embedded.env`) ships 2000 rows / 7 days / 5 s flush / 256 queue.
When the queue is full a request is counted as dropped, never blocked.

## API (administrators only; API keys get 403)
`GET /api/system/access-log` (filters user, client, method, path, status class, text, since; cursor), `/stats`, `/csv`, `/settings`;
`GET /api/system/audit-log` (+ `/csv`) lists configuration changes. Bursts of failed sign-ins or 5xx answers raise the events
`login_failures` / `server_errors`.

## Tests
Unit/route: `state/accesslog.rs` tests, `routes/honesty_tests.rs`. Netlab: `lane-h-access-log.sh`, `lane-h-access-log-ui.sh`
(+ `ci/access-log-page-e2e.py`, Firefox, 1280/390 px, light/dark, contrast). Router tier: the ax1800 `qemu-gate.sh` and Slate
`qemu-gate.py` burst checks. Claim C87.
