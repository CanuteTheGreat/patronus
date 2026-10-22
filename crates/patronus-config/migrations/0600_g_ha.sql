-- Lane G (HA): virtual IPs. Applied by patronus-network/src/ha.rs (boot
-- phase "services": keepalived VRRP instances + conntrackd state sync);
-- the global switches (enabled, priority, peer, state sync...) are the
-- `ha.*` keys of lan_settings.
--
-- mode 'carp': the address floats between the HA nodes (VRRP);
-- mode 'alias': an extra address on the interface, no failover.
CREATE TABLE IF NOT EXISTS ha_vips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    -- device name or role (@lan, @wan, @opt1)
    interface TEXT NOT NULL,
    -- address/prefix
    address TEXT NOT NULL,
    vrid INTEGER NOT NULL DEFAULT 51,
    mode TEXT NOT NULL DEFAULT 'carp',
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
