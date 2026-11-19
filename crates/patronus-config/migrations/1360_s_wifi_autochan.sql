-- Lane S: automatic Wi-Fi channel choice for the standard tier (docs/WIFI-AUTO-CHANNEL.md).
-- `channel` = 0 means "auto": the channel is picked by measurement at start and re-checked nightly.
-- Existing networks keep their fixed channel (the column is untouched). Every tuning value is its own
-- typed column with the documented default, so nothing is baked into code.
ALTER TABLE seg_wifi_networks ADD COLUMN chanlist TEXT NOT NULL DEFAULT '';        -- candidate channels, '' = the band default
ALTER TABLE seg_wifi_networks ADD COLUMN width INTEGER NOT NULL DEFAULT 20;         -- 20 | 40 | 80 MHz
ALTER TABLE seg_wifi_networks ADD COLUMN chan_recheck INTEGER NOT NULL DEFAULT 1;   -- nightly re-check of an auto channel
ALTER TABLE seg_wifi_networks ADD COLUMN chan_time TEXT NOT NULL DEFAULT '03:30';   -- HH:MM local, '' = never
ALTER TABLE seg_wifi_networks ADD COLUMN chan_hyst INTEGER NOT NULL DEFAULT 20;     -- better by at least this many percent
ALTER TABLE seg_wifi_networks ADD COLUMN chan_min_gain INTEGER NOT NULL DEFAULT 10; -- and by at least this many score points
ALTER TABLE seg_wifi_networks ADD COLUMN chan_confirm INTEGER NOT NULL DEFAULT 3;   -- samples that must agree before a move
ALTER TABLE seg_wifi_networks ADD COLUMN chan_confirm_gap INTEGER NOT NULL DEFAULT 300; -- seconds between those samples
ALTER TABLE seg_wifi_networks ADD COLUMN chan_csa TEXT NOT NULL DEFAULT 'auto';     -- auto | off (off = always move by restart)
ALTER TABLE seg_wifi_networks ADD COLUMN chan_csa_count INTEGER NOT NULL DEFAULT 10; -- beacons announced before a switch
ALTER TABLE seg_wifi_networks ADD COLUMN chan_rounds INTEGER NOT NULL DEFAULT 3;    -- scans of each candidate per sample
ALTER TABLE seg_wifi_networks ADD COLUMN chan_dwell INTEGER NOT NULL DEFAULT 105;   -- ms per scan of one channel
ALTER TABLE seg_wifi_networks ADD COLUMN chan_bss_cost INTEGER NOT NULL DEFAULT 2;  -- score points per neighbour access point
ALTER TABLE seg_wifi_networks ADD COLUMN chan_min_signal INTEGER NOT NULL DEFAULT -90; -- dBm: weaker neighbours are ignored
ALTER TABLE seg_wifi_networks ADD COLUMN chan_history INTEGER NOT NULL DEFAULT 200; -- history entries kept per network

-- Measured, not configuration (listed in NON_CONFIG_TABLES): what the radio is on and why, and the history.
CREATE TABLE IF NOT EXISTS seg_wifi_chan_state (
    network_id INTEGER PRIMARY KEY REFERENCES seg_wifi_networks(id) ON DELETE CASCADE,
    channel INTEGER NOT NULL,
    width INTEGER NOT NULL,
    since INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    candidates TEXT NOT NULL DEFAULT '[]',     -- JSON: [{channel, score, busy, neighbours}] of the last decision
    csa_capable INTEGER,                       -- NULL = not known yet
    last_check INTEGER,                        -- epoch of the last nightly check
    last_day INTEGER,                          -- days since epoch of the last nightly check that ran
    requested_at INTEGER                       -- "re-check now" from the API/UI
);
CREATE TABLE IF NOT EXISTS seg_wifi_chan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES seg_wifi_networks(id) ON DELETE CASCADE,
    at INTEGER NOT NULL,
    event TEXT NOT NULL,                       -- start | sample | stay | move | note
    channel INTEGER,
    score REAL,
    busy REAL,
    neighbours INTEGER,
    best INTEGER,
    best_score REAL,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS seg_wifi_chan_history_net ON seg_wifi_chan_history(network_id, id);
