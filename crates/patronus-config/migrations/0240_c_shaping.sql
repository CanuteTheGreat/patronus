-- Lane C (interfaces): traffic shaping per interface (USE=qos). Applied by
-- patronus-network/src/shaping.rs as the interface's root (egress) qdisc:
-- 'cake' (bandwidth-limited CAKE), 'fq_codel' (no limit, fights bufferbloat)
-- or 'limit' (token bucket filter at the given rate).
CREATE TABLE IF NOT EXISTS qos_shapers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- device name or role (@wan, @lan, @opt1): traffic LEAVING it is shaped
    interface TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL,
    -- kbit/s; required for cake and limit
    rate_kbit INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
