-- VRF (USE=vrf): routing-table isolation. A VRF is a kernel `vrf` device
-- (`vrf-<name>`) with its own routing table; member interfaces are enslaved
-- to it. Read by patronus-network/src/vrf.rs.
CREATE TABLE IF NOT EXISTS vrf_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    table_id INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vrf_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vrf TEXT NOT NULL,
    interface TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
