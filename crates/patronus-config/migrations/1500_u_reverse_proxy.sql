-- Reverse proxy / load balancer (USE=reverse-proxy, patronus-network/src/revproxy.rs):
-- frontends (listeners), backends (server pools), their servers and the
-- host/path routing rules. The feature's own settings are `revproxy.*` keys of
-- lan_settings. Rows are validated by the feature page; haproxy.cfg is generated
-- from them and checked with `haproxy -c` before it replaces the running one.
CREATE TABLE IF NOT EXISTS revproxy_frontends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    interface TEXT,
    bind TEXT,
    port INTEGER NOT NULL,
    mode TEXT,
    tls INTEGER NOT NULL DEFAULT 0,
    cert_file TEXT,
    redirect_https INTEGER NOT NULL DEFAULT 0,
    default_backend TEXT,
    note TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revproxy_backends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    mode TEXT,
    balance TEXT,
    health TEXT,
    check_uri TEXT,
    check_interval INTEGER,
    rise INTEGER,
    fall INTEGER,
    sticky INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revproxy_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    backend TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    weight INTEGER,
    backup INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revproxy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    frontend TEXT NOT NULL,
    host TEXT,
    path_prefix TEXT,
    backend TEXT NOT NULL,
    priority INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);
