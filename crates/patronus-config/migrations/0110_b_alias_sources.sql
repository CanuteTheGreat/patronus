-- Lane B: aliases that fill themselves. A row here turns the alias of the
-- same name into a URL table (pfSense "URL Table"), a GeoIP country set or a
-- threat-intelligence feed; `patronus_firewall::feeds` refreshes the
-- alias's entries (firewall_aliases.entries) on a schedule, size-capped, and
-- keeps the old entries when a refresh fails.
CREATE TABLE IF NOT EXISTS firewall_alias_sources (
    alias TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                       -- 'url' | 'geoip' | 'threat'
    url TEXT,                                 -- url / threat feeds
    countries TEXT NOT NULL DEFAULT '[]',     -- geoip: JSON array of ISO 3166-1 alpha-2 codes
    refresh_secs INTEGER NOT NULL DEFAULT 86400,
    max_entries INTEGER NOT NULL DEFAULT 100000,
    direction TEXT NOT NULL DEFAULT 'both',   -- threat: 'in' | 'out' | 'both'
    enabled INTEGER NOT NULL DEFAULT 1,
    last_attempt INTEGER,                     -- unix time of the last try
    last_refresh INTEGER,                     -- unix time of the last success
    last_status TEXT,                         -- human readable result of the last try
    last_count INTEGER
);

-- A bounded log of what the firewall logged (rules with the Log flag, and
-- threat-intel hits), written by the patronus-web NFLOG collector so the
-- log viewer can search history and attribute each line to its rule.
CREATE TABLE IF NOT EXISTS firewall_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,                      -- unix time (seconds)
    rule_id INTEGER,                          -- firewall_rules.id when the prefix names one
    rule TEXT NOT NULL DEFAULT '',            -- rule name / 'feed:<alias>' at log time
    action TEXT NOT NULL DEFAULT '',
    chain TEXT NOT NULL DEFAULT '',
    iface_in TEXT NOT NULL DEFAULT '',
    iface_out TEXT NOT NULL DEFAULT '',
    proto TEXT NOT NULL DEFAULT '',
    src TEXT NOT NULL DEFAULT '',
    dst TEXT NOT NULL DEFAULT '',
    sport INTEGER,
    dport INTEGER,
    length INTEGER,
    prefix TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS firewall_log_ts ON firewall_log (ts);
CREATE INDEX IF NOT EXISTS firewall_log_rule ON firewall_log (rule_id);
