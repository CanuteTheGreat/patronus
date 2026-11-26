-- LLDP (USE=lldp, patronus-network/src/lldp.rs): the interfaces lldpd
-- announces on and listens on, each with its mode (rx-and-tx, rx-only,
-- tx-only, disabled). Settings (`lldp.enabled`, `lldp.system_name`,
-- `lldp.tx_interval`, ...) live in lan_settings. The neighbour table is read
-- live from the daemon and never stored.
CREATE TABLE IF NOT EXISTS lldp_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'rx-and-tx',
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
