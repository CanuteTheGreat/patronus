-- Internet speed test history (lane H, patronus-web/src/state/speedtest.rs).
-- Settings (test server URLs, sizes, schedule) live in system_config under
-- speedtest.*; the newest 500 results are kept.
CREATE TABLE IF NOT EXISTS speedtests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    server TEXT NOT NULL,
    latency_ms REAL,
    down_bps INTEGER,
    up_bps INTEGER,
    ok INTEGER NOT NULL,
    error TEXT,
    -- manual | schedule
    trigger TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS speedtests_ts ON speedtests(ts);
