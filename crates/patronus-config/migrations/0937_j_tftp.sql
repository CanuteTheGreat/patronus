-- TFTP server (USE=tftp, patronus-network/src/tftp.rs): one row per client network
-- that may use it (none = every client on the listening interfaces). Settings
-- (`tftp.enabled`, `tftp.root`, ...) live in lan_settings. Transfer history is not
-- stored (the daemon keeps counters and the last transfers in a run-dir file).
CREATE TABLE IF NOT EXISTS tftp_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
