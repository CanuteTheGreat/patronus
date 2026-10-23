-- Lane N: signed plugins (USE=plugins) and the Gentoo package jobs behind the
-- Packages page. `plugins.bundle` is the signed bundle exactly as installed
-- (re-verified at every apply); expose_* is what the firewall opens on the
-- LAN for the plugin's service, kept in step by the plugins applier (0 = none).
CREATE TABLE IF NOT EXISTS plugin_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS plugins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    key_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    bundle TEXT NOT NULL,
    installed_at INTEGER NOT NULL,
    expose_proto TEXT NOT NULL DEFAULT 'tcp',
    expose_port INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS package_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component TEXT NOT NULL,
    action TEXT NOT NULL,
    -- running | ok | failed
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    exit_code INTEGER,
    log_path TEXT NOT NULL DEFAULT ''
);
