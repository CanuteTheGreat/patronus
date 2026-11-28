-- IP tunnels (USE=tunnels, patronus-network/src/tunnels.rs): IPIP, 6in4 (sit) and
-- GIF-style (sit mode any) links named tn-<name>. One row per tunnel, one row per
-- network reached through a tunnel. Settings (`tunnels.clamp_mss`) live in lan_settings.
CREATE TABLE IF NOT EXISTS ip_tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'sit',
    remote TEXT NOT NULL,
    local TEXT,
    address TEXT,
    address2 TEXT,
    mtu INTEGER NOT NULL DEFAULT 1480,
    ttl INTEGER NOT NULL DEFAULT 64,
    default_route INTEGER NOT NULL DEFAULT 0,
    metric INTEGER NOT NULL DEFAULT 1024,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_tunnel_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tunnel TEXT NOT NULL,
    destination TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL
);
