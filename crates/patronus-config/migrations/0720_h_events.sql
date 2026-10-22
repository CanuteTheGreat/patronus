-- Lane H (system/admin): event log + outbound webhooks, for monitoring
-- systems (Rustinion) that want to be told about gateway up/down, failover,
-- tunnel up/down, HA state changes and configuration changes instead of
-- polling. Written by patronus-web/src/state/telemetry.rs.
CREATE TABLE IF NOT EXISTS system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    -- gateway_down | gateway_up | gateway_degraded | group_failover |
    -- tunnel_up | tunnel_down | ha_state | config_changed | ...
    kind TEXT NOT NULL,
    -- what it is about (gateway name, tunnel name, ...)
    subject TEXT NOT NULL DEFAULT '',
    -- info | warning | critical
    severity TEXT NOT NULL DEFAULT 'info',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_system_events_ts ON system_events(ts);

CREATE TABLE IF NOT EXISTS event_hooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    -- HMAC-SHA256 key for the X-Patronus-Signature header; never returned by the API
    secret TEXT NOT NULL DEFAULT '',
    -- comma-separated event kinds; empty = every event
    kinds TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_attempt_at INTEGER,
    -- 'ok' / the failure
    last_result TEXT
);
