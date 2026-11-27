-- Lane d: DNS filtering list catalog, allow list and measured data (docs/DNS-FILTERING.md).
--
-- Configuration (exported, revisioned, rolled back):
--   dnsf_lists  one row per subscribed block list: a catalog entry (`catalog` = its id) or a custom URL.
--               format: hosts | domains | rpz. `subdomains` = a listed name blocks its subdomains too.
--               `action` = answer for a list in RPZ format ('' = the list's own policy).
--               `auth_key` is a secret (never returned by the API) for lists that need a free key.
--   dnsf_allow  allow list: `domain` (the name and its subdomains), `wildcard` (glob with *), `regex`.
-- Settings live in lan_settings: dns.filter_refresh_hours, dns.filter_max_domains.
CREATE TABLE IF NOT EXISTS dnsf_lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    catalog     TEXT,
    url         TEXT NOT NULL,
    format      TEXT NOT NULL DEFAULT 'domains',
    subdomains  INTEGER NOT NULL DEFAULT 1,
    enabled     INTEGER NOT NULL DEFAULT 1,
    action      TEXT NOT NULL DEFAULT '',
    auth_key    TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dnsf_allow (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL DEFAULT 'domain',
    pattern     TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (kind, pattern)
);

-- Measured data (NON_CONFIG_TABLES in patronus-config store.rs; retention in dnsfilter.rs):
-- per-list refresh status, per-list blocked-answer counters per day, the recent blocked
-- names, the DNS query log and the log tailer's position.
CREATE TABLE IF NOT EXISTS dnsf_status (
    list_id       INTEGER PRIMARY KEY,
    last_attempt  INTEGER NOT NULL DEFAULT 0,
    last_ok       INTEGER NOT NULL DEFAULT 0,
    entries       INTEGER NOT NULL DEFAULT 0,
    used          INTEGER NOT NULL DEFAULT 0,
    bytes         INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    force         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dnsf_hits (
    list    TEXT NOT NULL,
    day     INTEGER NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (list, day)
);

CREATE TABLE IF NOT EXISTS dnsf_recent (
    domain    TEXT NOT NULL,
    list      TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    hits      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (domain, list)
);
CREATE INDEX IF NOT EXISTS dnsf_recent_seen ON dnsf_recent (last_seen);

CREATE TABLE IF NOT EXISTS dnsf_querylog (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    client     TEXT NOT NULL,
    qname      TEXT NOT NULL,
    qtype      TEXT NOT NULL,
    rcode      TEXT NOT NULL DEFAULT '',
    blocked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS dnsf_querylog_ts ON dnsf_querylog (ts);

CREATE TABLE IF NOT EXISTS dnsf_log_pos (
    path   TEXT PRIMARY KEY,
    inode  INTEGER NOT NULL,
    offset INTEGER NOT NULL
);
