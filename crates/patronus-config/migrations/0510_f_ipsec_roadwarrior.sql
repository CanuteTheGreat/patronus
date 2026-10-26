-- Lane F: IPsec road warriors (IKEv2 remote access, patronus_network::ipsec_rw).
-- A profile is one strongSwan connection with a virtual-IP pool; its users
-- authenticate with EAP-MSCHAPv2 (password) or a client certificate Patronus
-- issues from its own IPsec CA (stored in ipsec_pki; the CA key and every
-- password never leave the store through the API).
CREATE TABLE IF NOT EXISTS ipsec_rw_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    auth TEXT NOT NULL DEFAULT 'eap',          -- 'eap' | 'cert'
    local_address TEXT,                        -- NULL = any local address
    server_id TEXT NOT NULL,                   -- name/address clients connect to (certificate SAN, IKE id)
    pool TEXT NOT NULL,                        -- virtual IP pool (CIDR)
    dns TEXT NOT NULL DEFAULT '',              -- comma list pushed to clients
    local_ts TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
    ike_proposals TEXT NOT NULL,
    esp_proposals TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ipsec_rw_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile TEXT NOT NULL REFERENCES ipsec_rw_profiles(name) ON DELETE CASCADE ON UPDATE CASCADE,
    username TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    password TEXT,                             -- EAP profiles
    description TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE (profile, username)
);

CREATE TABLE IF NOT EXISTS ipsec_pki (
    name TEXT PRIMARY KEY,                     -- ca.crt, ca.key, server:<profile>:crt|key|id, user:<profile>:<user>:crt|key
    pem TEXT NOT NULL
);
