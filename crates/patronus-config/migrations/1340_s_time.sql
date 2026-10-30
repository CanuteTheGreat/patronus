-- Device segmentation, parental time limits (design 8.1).
-- A policy is attached to a group or a device (seg_groups/seg_devices
-- .time_policy_id, device wins).
CREATE TABLE IF NOT EXISTS seg_time_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    daily_limit_minutes INTEGER,                      -- NULL = no quota
    reset_hour INTEGER NOT NULL DEFAULT 6,            -- the "day" rolls over at 06:00 local
    active_bytes_per_min INTEGER NOT NULL DEFAULT 20000, -- a minute is "used" above this
    allow_dns INTEGER NOT NULL DEFAULT 1,             -- keep DNS/DHCP/time's-up page while blocked
    grace_minutes INTEGER NOT NULL DEFAULT 5,         -- warning this long before the cut (0 = none)
    updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS seg_time_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL REFERENCES seg_time_policies(id) ON DELETE CASCADE,
    days TEXT NOT NULL,                               -- "mon,tue,wed"
    start TEXT NOT NULL,                              -- HH:MM
    "end" TEXT NOT NULL                               -- HH:MM, end <= start wraps midnight
);
CREATE TABLE IF NOT EXISTS seg_time_usage (
    day TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    used_minutes INTEGER NOT NULL DEFAULT 0,
    bonus_minutes INTEGER NOT NULL DEFAULT 0,
    paused INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, device_id)
);
-- what the enforcement ticker decided last (read by the time's-up page and the UI)
CREATE TABLE IF NOT EXISTS seg_time_state (
    device_id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    state TEXT NOT NULL,                              -- ok | warn | blocked
    reason TEXT NOT NULL DEFAULT '',                  -- paused | window | quota
    used_minutes INTEGER NOT NULL DEFAULT 0,
    limit_minutes INTEGER,
    remaining_minutes INTEGER,
    resume_at TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
);
