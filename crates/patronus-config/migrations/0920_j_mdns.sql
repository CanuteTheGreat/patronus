-- mDNS repeater (USE=mdns, patronus-network/src/mdns.rs): the interfaces
-- avahi-daemon reflects mDNS between. Settings (`mdns.enabled`, `mdns.ipv6`,
-- `mdns.reflect_ipv`) live in lan_settings.
CREATE TABLE IF NOT EXISTS mdns_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
