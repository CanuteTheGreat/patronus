-- DHCPv6 relay agent (USE=dhcp6-relay, patronus-network/src/dhcp6relay.rs): one row
-- per rule (client interface -> server, optional upstream interface). Settings
-- (`dhcp6-relay.enabled`, `.hop_limit`, `.interface_id`, `.rate_limit`) live in lan_settings.
CREATE TABLE IF NOT EXISTS dhcp6_relay_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    server TEXT NOT NULL,
    upstream TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
