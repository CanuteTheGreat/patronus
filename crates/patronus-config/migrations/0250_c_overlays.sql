-- GRE / GRE-TAP / VXLAN overlay links (lane C). One row per kernel tunnel
-- device Patronus creates; `key` is the GRE key or the VXLAN VNI.
CREATE TABLE IF NOT EXISTS overlay_links (
    name TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    local_addr TEXT,
    remote_addr TEXT NOT NULL,
    key INTEGER,
    port INTEGER,
    ttl INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
