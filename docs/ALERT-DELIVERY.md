# Alert delivery

Patronus watches gateways, tunnels, HA and configuration revisions and sends
each change as an event to every enabled notification channel (Settings >
Notifications, or `POST /api/system/hooks`). Channels: `webhook` (signed
JSON), `ntfy`, `telegram`, `discord`, `slack`, `email` (SMTP).

## Payloads

Webhook (`Content-Type: application/json`), one object per event:

    {"id": 41, "time": 1700000000, "kind": "gateway_down",
     "subject": "WAN", "severity": "critical",
     "detail": "gateway WAN: up -> down", "host": "<hostname>"}

`id` is the event-log id, `time` is unix seconds, `severity` is `info`,
`warning` or `critical`. Headers: `X-Patronus-Event: <kind>` and, when the
channel has a secret, `X-Patronus-Signature: sha256=<hex>` (HMAC-SHA256 of
the exact body with the secret).

ntfy: `POST <url>` with `Content-Type: text/plain`, body = a readable message,
headers `Title: [host] SEVERITY: kind subject`, `Priority: urgent|high|default`
(critical, warning, info), `Tags: <kind>`, and `Authorization: Bearer <secret>`
when a secret is set.

Email: SMTP (`smtp://host[:port]`, STARTTLS when offered, or `smtps://`),
envelope `MAIL FROM:<sender>`, one `RCPT TO` per recipient; message headers
`Subject: [host] SEVERITY: kind subject`, `X-Patronus-Event: <kind>`.

## Retry, backoff, timeouts, audit

A delivery that fails (HTTP non-2xx, connection refused, timeout, SMTP
rejection) is retried with growing waits. After the last failed attempt the
hook's `last_result` shows `attempt N: <error>` and an audit-log entry
`alert_delivery_failed` (entity `event_hook`, details: hook, channel,
event_kind, event_id, attempts, error) is written.

All values are `system_config` keys; unset or invalid values use the default.

| key | default | meaning |
| --- | --- | --- |
| `alerts.delivery.attempts` | 3 | total attempts per hook and event (max 20) |
| `alerts.delivery.backoff_ms` | 2000 | wait before the second attempt |
| `alerts.delivery.backoff_factor` | 3 | each further wait is the previous times this (2 s, 6 s, 18 s) |
| `alerts.delivery.http_timeout_secs` | 15 | time limit of one HTTP attempt |
| `alerts.delivery.mail_timeout_secs` | 30 | time limit of one SMTP attempt |

## Proof

`crates/patronus-web/src/state/alert_delivery_tests.rs` runs in CI
(`cargo test --workspace`): a real configuration change goes through the real
watcher to local webhook, ntfy and SMTP sinks (payload and headers asserted),
and 500, hanging, refused and SMTP-rejecting sinks are shown to be retried
with backoff and audited.
