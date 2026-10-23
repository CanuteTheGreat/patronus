-- OpenVPN server (USE=openvpn): client accounts (certificates) and the PKI.
-- The PKI (CA, server and client keys, tls-crypt key) lives in the store so
-- it is part of backups and restores; patronus-network/src/openvpn_server.rs
-- writes it to the state dir (0600) when it starts the daemon.
CREATE TABLE IF NOT EXISTS openvpn_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS openvpn_pki (
    name TEXT PRIMARY KEY,
    pem TEXT NOT NULL
);
