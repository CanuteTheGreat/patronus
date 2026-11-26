-- Lane B: brute-force protection (`patronus_firewall::guard`, docs/BRUTE-FORCE.md).
-- Settings are `guard.*` keys in system_config (configuration: exported, rolled back).
-- These three tables are measured data and are listed in NON_CONFIG_TABLES: a backup,
-- restore or rollback never carries or rewinds them.

-- Every ban ever made (active while lifted_at IS NULL and expires_at is in the future
-- or NULL = until lifted). `address` is an IPv4 address or an IPv6 prefix
-- (2001:db8:1:2::/64); `source` is sshd | dropbear | web | manual.
CREATE TABLE IF NOT EXISTS guard_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    failures INTEGER NOT NULL DEFAULT 0,
    offence INTEGER NOT NULL DEFAULT 1,     -- 1 = first ban in the escalation window
    banned_at INTEGER NOT NULL,             -- unix seconds
    expires_at INTEGER,                     -- NULL = until lifted
    lifted_at INTEGER,
    lifted_by TEXT
);
CREATE INDEX IF NOT EXISTS guard_bans_address ON guard_bans(address, banned_at);
CREATE INDEX IF NOT EXISTS guard_bans_active ON guard_bans(lifted_at, expires_at);

-- Failed logins reported by processes that cannot reach the ban engine directly
-- (patronus-web runs unprivileged); the engine consumes and deletes them.
CREATE TABLE IF NOT EXISTS guard_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    address TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    at INTEGER NOT NULL
);

-- Recent failed attempts per address (the last `guard.find_secs`), so counts survive
-- an engine restart and every process sees the same picture.
CREATE TABLE IF NOT EXISTS guard_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    source TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guard_failures_address ON guard_failures(address, at);
