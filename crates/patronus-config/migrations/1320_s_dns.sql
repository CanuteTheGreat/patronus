-- Device segmentation, DNS policy (design docs/design/device-segmentation.md 6.2).
-- A policy is attached to a group or a device (seg_groups/seg_devices
-- .dns_policy_id, device wins); unbound renders one `view:` per policy and
-- maps every device's reserved IPv4 to it (access-control-view).
CREATE TABLE IF NOT EXISTS seg_dns_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    block_mode TEXT NOT NULL DEFAULT 'nxdomain',   -- nxdomain | null
    blocklist_urls TEXT NOT NULL DEFAULT '',       -- extra lists on top of the global ones
    family INTEGER NOT NULL DEFAULT 0,             -- family preset: adult + malware lists, safe-search
    log_queries INTEGER NOT NULL DEFAULT 0,        -- DNS logs are personal data: off by default
    log_retention_days INTEGER NOT NULL DEFAULT 7,
    inherit_global INTEGER NOT NULL DEFAULT 1,     -- view-first: global block lists still apply
    updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS seg_dns_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL REFERENCES seg_dns_policies(id) ON DELETE CASCADE,
    action TEXT NOT NULL,                          -- block | allow | override
    domain TEXT NOT NULL,
    address TEXT,                                  -- override: A/AAAA answer
    UNIQUE(policy_id, action, domain)
);
CREATE TABLE IF NOT EXISTS seg_dns_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    client TEXT NOT NULL,
    device_id INTEGER,
    qname TEXT NOT NULL,
    qtype TEXT,
    rcode TEXT,
    blocked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS seg_dns_log_ts ON seg_dns_log(ts);
CREATE INDEX IF NOT EXISTS seg_dns_log_dev ON seg_dns_log(device_id, ts);
CREATE INDEX IF NOT EXISTS seg_dns_log_q ON seg_dns_log(qname);
-- where the unbound log tailer stopped (survives restarts)
CREATE TABLE IF NOT EXISTS seg_dns_log_pos (
    path TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL
);
