-- Lane B: router CVE exposure (`patronus_network::cve`, docs/CVE-EXPOSURE.md).
-- Settings are `cve.*` keys in system_config (configuration: exported, rolled back).
-- These tables are measured data and are listed in NON_CONFIG_TABLES: a backup,
-- restore or rollback never carries or rewinds them.

-- The findings of the latest scan, one row per advisory + subject. first_seen survives
-- from scan to scan; a row the latest scan did not find again is deleted.
CREATE TABLE IF NOT EXISTS cve_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fkey TEXT NOT NULL UNIQUE,             -- source|subject|binary|advisory
    source TEXT NOT NULL,                  -- glsa | osv | image
    subject TEXT NOT NULL,                 -- category/package, crate name, image package
    binary TEXT NOT NULL DEFAULT '',       -- which Patronus binary carries the crate
    installed TEXT NOT NULL,
    advisory TEXT NOT NULL,
    aliases TEXT NOT NULL DEFAULT '',      -- comma separated CVE / GHSA ids
    title TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',     -- low | medium | high | unknown
    fixed_in TEXT NOT NULL DEFAULT '',     -- comma separated, ascending
    update_state TEXT NOT NULL DEFAULT 'unknown', -- available | none | needs-release | unknown
    update_version TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

-- One row per scan (the verdict and how old the data was), kept `cve.history_days`.
CREATE TABLE IF NOT EXISTS cve_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    tier TEXT NOT NULL,
    verdict TEXT NOT NULL,                 -- affected | clean | stale | unknown
    affected INTEGER NOT NULL DEFAULT 0,
    packages INTEGER NOT NULL DEFAULT 0,
    crates INTEGER NOT NULL DEFAULT 0,
    glsa_age INTEGER,                      -- seconds, NULL = no GLSA data
    osv_age INTEGER,                       -- seconds, NULL = no OSV data
    ms INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS cve_scans_at ON cve_scans(at);

-- What the engine did: data downloads, security updates applied, failures.
CREATE TABLE IF NOT EXISTS cve_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,                    -- fetch | apply | scan
    ok INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS cve_log_at ON cve_log(at);

-- The latest report (JSON) and the pending requests of the web UI / CLI.
CREATE TABLE IF NOT EXISTS cve_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
