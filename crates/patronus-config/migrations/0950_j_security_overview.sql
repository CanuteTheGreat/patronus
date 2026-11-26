-- Lane J (security services): measured data of the security overview (docs/SECURITY-OVERVIEW.md).
-- All NON_CONFIG (store.rs): never carried or rewound by a backup, revision or rollback.

-- Threat-feed hits per feed and hour (packets/bytes the feed's counting rules matched),
-- kept security.feed_hits_days (default 30).
CREATE TABLE IF NOT EXISTS sec_feed_hits (
    feed TEXT NOT NULL,              -- feed id (alias ti_<id>)
    hour INTEGER NOT NULL,           -- unix time of the hour's start (UTC)
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (feed, hour)
);

-- The kernel counters last read (they restart at every ruleset load; the sampler adds deltas).
CREATE TABLE IF NOT EXISTS sec_feed_counter_pos (
    feed TEXT PRIMARY KEY,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

-- Last WireGuard handshake ever seen per peer (the kernel forgets it at every reboot),
-- for the "silent for N days" check. One row per peer key: bounded by the peer count.
CREATE TABLE IF NOT EXISTS sec_wg_seen (
    interface TEXT NOT NULL,
    public_key TEXT NOT NULL,
    last_handshake INTEGER NOT NULL,
    PRIMARY KEY (interface, public_key)
);
