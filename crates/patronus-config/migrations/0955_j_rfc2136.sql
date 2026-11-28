-- RFC 2136 dynamic DNS client (USE=rfc2136, patronus-network/src/rfc2136.rs): one row
-- per host name kept up to date on an authoritative server with a TSIG key. Settings
-- (`rfc2136.enabled`, `rfc2136.interval`, `rfc2136.refresh`, `rfc2136.timeout`) live in
-- lan_settings. key_secret is write-only in the API/UI and never rendered or audited.
CREATE TABLE IF NOT EXISTS rfc2136_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    zone TEXT NOT NULL,
    server TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 53,
    tcp INTEGER NOT NULL DEFAULT 0,
    key_name TEXT NOT NULL,
    key_algo TEXT NOT NULL DEFAULT 'hmac-sha256',
    key_secret TEXT NOT NULL,
    iface TEXT NOT NULL,
    family TEXT NOT NULL DEFAULT 'ipv4',
    ttl INTEGER NOT NULL DEFAULT 300,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
