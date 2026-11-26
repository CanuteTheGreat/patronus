-- Lane U (hardware + monitoring): S.M.A.R.T. disk health (USE=smart, docs/SMART.md).
-- Settings live in lan_settings (`smart.*`). Both tables are measured data, not configuration
-- (listed in NON_CONFIG_TABLES): a rollback or restore must not rewind a disk's history.

-- One row per poll and disk: the numbers worth charting, pruned by `smart.retention_days`.
CREATE TABLE IF NOT EXISTS smart_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    device TEXT NOT NULL,                      -- /dev/sda
    serial TEXT NOT NULL DEFAULT '',
    health INTEGER,                            -- 1 PASSED, 0 FAILED, NULL = not reported
    temperature INTEGER,                       -- degrees Celsius
    power_on_hours INTEGER,
    reallocated INTEGER,
    pending INTEGER,
    uncorrectable INTEGER,
    nvme_used INTEGER,                         -- NVMe percentage used
    level TEXT NOT NULL DEFAULT 'ok'           -- ok | warning | critical (the assessment at that time)
);
CREATE INDEX IF NOT EXISTS smart_samples_device_at ON smart_samples (device, at);

-- The latest look at each disk: what the API/UI show and what the alert path watches.
CREATE TABLE IF NOT EXISTS smart_state (
    device TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    level TEXT NOT NULL DEFAULT 'ok',          -- ok | warning | critical | unsupported
    temp_level TEXT NOT NULL DEFAULT 'ok',     -- ok | warning | critical (kept for the temperature hysteresis)
    reasons TEXT NOT NULL DEFAULT '[]',        -- JSON: why the level is not ok
    info TEXT NOT NULL DEFAULT '{}',           -- JSON: the parsed smartctl report
    last_short INTEGER,                        -- epoch of the last short self-test started
    last_long INTEGER,                         -- epoch of the last long self-test started
    test_request TEXT NOT NULL DEFAULT '',     -- '' | short | long: asked for by the API/UI (the web process is not root), run by the poller
    request_at INTEGER                         -- when it was asked for
);
