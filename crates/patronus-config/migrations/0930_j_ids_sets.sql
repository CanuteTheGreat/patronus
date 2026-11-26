-- IDS/IPS rule-set management (USE=intrusion-detection): rule sources, per-ruleset/category policy,
-- per-SID overrides, suppress/threshold entries, extra watch interfaces; the alert history.
-- The settings of the page (update window, retention, ...) live in lan_settings as `ids.<key>`.

-- Rule sources: where a rule set is downloaded from. Seeded once (all OFF: nothing is downloaded
-- until the owner switches a source on); deleting a seeded row is final, it is never re-seeded.
-- `format`: rules (one plain file), rules.gz (gzip'd file) or tar.gz (an archive holding *.rules files).
-- `{suricata_version}` in the URL is replaced by the installed Suricata's version (ET Open needs it).
CREATE TABLE IF NOT EXISTS ids_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,            -- short id, also the rule-set name in policies
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'tar.gz',
    licence TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    max_mb INTEGER NOT NULL DEFAULT 64,  -- refuse a download bigger than this
    updated_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO ids_sources (key, name, url, format, licence, enabled, max_mb, updated_at) VALUES
    ('et-open', 'Emerging Threats Open', 'https://rules.emergingthreats.net/open/suricata-{suricata_version}/emerging.rules.tar.gz', 'tar.gz', 'MIT (Proofpoint ET Open)', 0, 64, 0),
    ('abuse-sslbl', 'abuse.ch SSL blacklist (certificates)', 'https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz', 'tar.gz', 'CC0-1.0 (abuse.ch)', 0, 16, 0),
    ('abuse-ja3', 'abuse.ch SSL blacklist (JA3 fingerprints)', 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz', 'tar.gz', 'CC0-1.0 (abuse.ch)', 0, 16, 0),
    ('abuse-urlhaus', 'abuse.ch URLhaus', 'https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz', 'tar.gz', 'CC0-1.0 (abuse.ch)', 0, 16, 0),
    ('oisf-trafficid', 'OISF traffic ID', 'https://openinfosecfoundation.org/rules/trafficid/trafficid.rules', 'rules', 'MIT (OISF)', 0, 8, 0),
    ('tgreen-hunting', 'Threat hunting rules (tgreen)', 'https://github.com/travisbgreen/hunting-rules/raw/master/hunting.rules.tar.gz', 'tar.gz', 'GPL-3.0 (tgreen)', 0, 16, 0);

-- What to do with every rule of a rule set / category / classtype: alert, drop or disable.
-- Most specific wins: SID override > classtype > category > rule set > the rule as shipped.
CREATE TABLE IF NOT EXISTS ids_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,                 -- ruleset | category | classtype
    target TEXT NOT NULL,                -- source key | rule file name without .rules | classtype
    action TEXT NOT NULL,                -- alert | drop | disable
    note TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ids_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid INTEGER NOT NULL,
    action TEXT NOT NULL,                -- alert | drop | disable
    note TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- threshold.config entries: suppress an alert, or limit how often it fires.
CREATE TABLE IF NOT EXISTS ids_suppress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid INTEGER NOT NULL,
    kind TEXT NOT NULL,                  -- suppress | limit | threshold | both
    track TEXT,                          -- none | by_src | by_dst
    ip TEXT,                             -- suppress only: an address/prefix the entry is limited to
    count INTEGER,
    seconds INTEGER,
    note TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- More interfaces to watch besides the one in the settings.
CREATE TABLE IF NOT EXISTS ids_ifaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- Measured / downloaded, NOT configuration (listed in NON_CONFIG_TABLES): the last download of each
-- source, the alert history (retention: `ids.alert_retention_days` and `ids.alert_max_rows`, enforced
-- by the collector), where the collector stopped reading eve.json, and the "update now" request.
CREATE TABLE IF NOT EXISTS ids_source_state (
    key TEXT PRIMARY KEY,                -- no foreign key: a rollback that re-creates the source rows must not wipe it
    checked_at INTEGER,                  -- last attempt
    ok_at INTEGER,                       -- last attempt that ended in a rule set in use
    status TEXT NOT NULL DEFAULT '',     -- ok | unchanged | rejected | failed | disabled
    message TEXT NOT NULL DEFAULT '',
    rules INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ids_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,                 -- epoch seconds
    src_ip TEXT NOT NULL DEFAULT '',
    src_port INTEGER,
    dst_ip TEXT NOT NULL DEFAULT '',
    dst_port INTEGER,
    proto TEXT NOT NULL DEFAULT '',
    sid INTEGER NOT NULL DEFAULT 0,
    rev INTEGER NOT NULL DEFAULT 0,
    signature TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    severity INTEGER NOT NULL DEFAULT 3,
    action TEXT NOT NULL DEFAULT 'allowed',   -- allowed (alert only) | blocked (dropped)
    iface TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ids_alerts_ts ON ids_alerts(ts);
CREATE INDEX IF NOT EXISTS ids_alerts_sid ON ids_alerts(sid, ts);
CREATE INDEX IF NOT EXISTS ids_alerts_src ON ids_alerts(src_ip, ts);
CREATE INDEX IF NOT EXISTS ids_alerts_dst ON ids_alerts(dst_ip, ts);
CREATE TABLE IF NOT EXISTS ids_alert_pos (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    inode INTEGER NOT NULL DEFAULT 0,
    offset INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ids_update_request (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    requested_at INTEGER NOT NULL DEFAULT 0,
    done_at INTEGER NOT NULL DEFAULT 0
);
