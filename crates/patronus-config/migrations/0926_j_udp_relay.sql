-- UDP broadcast relay (USE=udp-relay, patronus-network/src/udprelay.rs): one row
-- per rule (listen interface, UDP ports, target interfaces). Settings
-- (`udp-relay.enabled`, `udp-relay.rate_limit`) live in lan_settings.
CREATE TABLE IF NOT EXISTS udp_relay_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    ports TEXT NOT NULL,
    targets TEXT NOT NULL,
    spoof INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
