-- Lane W (network map & discovery, docs/design/network-map.md).
--
-- map_devices is MEASURED (every host the router has seen: DHCP leases, the
-- neighbour table, probes, LLDP); it is in NON_CONFIG_TABLES, has retention
-- (map.retention_days) and is never carried by export/rollback.
-- map_device_labels, map_class_rules and map_share_keys are configuration.
-- Settings are typed system_config keys `map.*` (patronus_config::netmap::Settings).

CREATE TABLE IF NOT EXISTS map_devices (
    mac TEXT PRIMARY KEY,               -- lower-case aa:bb:cc:dd:ee:ff
    ip TEXT,
    hostname TEXT,
    iface TEXT,                         -- kernel device it was seen on (br0, eth1.20)
    segment TEXT,                       -- role token (@lan, @opt1) when known
    sources TEXT NOT NULL DEFAULT '',   -- comma list: lease,neigh,probe,lldp
    neigh_state TEXT,                   -- REACHABLE, STALE, ... from the last read
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,         -- last time any source listed it
    last_up INTEGER                     -- last time it answered / was REACHABLE / held an active lease
);

CREATE TABLE IF NOT EXISTS map_device_labels (
    mac TEXT PRIMARY KEY,
    name TEXT,
    class TEXT,                         -- computer phone printer camera iot media infra unknown
    note TEXT,
    updated_at INTEGER NOT NULL
);

-- field: hostname | mac (glob with * and ?, case-insensitive); lower priority first
CREATE TABLE IF NOT EXISTS map_class_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    field TEXT NOT NULL DEFAULT 'hostname',
    pattern TEXT NOT NULL,
    class TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    UNIQUE(field, pattern)
);

-- read-only live view / stats keys: only the SHA-256 of the key is stored
CREATE TABLE IF NOT EXISTS map_share_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'view', -- view | stats
    detail TEXT NOT NULL DEFAULT 'basic', -- basic (no MACs/meta) | full
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used INTEGER
);
