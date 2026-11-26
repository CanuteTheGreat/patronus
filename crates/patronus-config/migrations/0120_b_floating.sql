-- Lane B: floating rules, interface groups, per-rule state limits,
-- limiters and rule categories.

-- ext: JSON object with the optional rule features (floating, quick,
-- direction, interfaces, max_states, max_src_conn, max_src_rate,
-- max_src_rate_secs, overload, overload_secs, limiter, category). '{}' = a
-- plain rule, so every existing row keeps its meaning.
ALTER TABLE firewall_rules ADD COLUMN ext TEXT NOT NULL DEFAULT '{}';

-- Interface groups: a named list of interfaces (device names or @role
-- tokens). Rendered as the nft set `ifgrp_<name>` (type ifname); a rule
-- references it as `group:<name>`, so a new member only changes the set.
CREATE TABLE IF NOT EXISTS firewall_interface_groups (
    name TEXT PRIMARY KEY,
    members TEXT NOT NULL,             -- JSON array of strings
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- Limiters: a rate cap a rule can reference by name (`ext.limiter`).
-- per_source = 1 caps every client address on its own, 0 caps all matching
-- traffic together. Rendered as an nft `limit rate over` policer.
CREATE TABLE IF NOT EXISTS firewall_limiters (
    name TEXT PRIMARY KEY,
    rate_kbit INTEGER NOT NULL,        -- kbit/s
    burst_kb INTEGER NOT NULL DEFAULT 128,  -- must hold a 64 KB GSO packet
    per_source INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
