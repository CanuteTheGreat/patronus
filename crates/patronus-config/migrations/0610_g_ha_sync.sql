-- Lane G (HA configuration sync, docs/HA-MAINTENANCE.md): one row per push (this node is the
-- source) or receive (this node is the target). Measured history, not configuration: listed in
-- NON_CONFIG_TABLES (no export / revision / restore), pruned to `ha.cfgsync.history_keep` rows
-- by the sync code. The switches themselves are `ha.cfgsync.*` keys of lan_settings.
CREATE TABLE IF NOT EXISTS ha_sync_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    -- push | receive
    direction TEXT NOT NULL,
    peer TEXT NOT NULL DEFAULT '',
    sections TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    -- hash of the pushed sections (what the target now has when ok)
    config_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ha_sync_history_ts ON ha_sync_history(ts);
