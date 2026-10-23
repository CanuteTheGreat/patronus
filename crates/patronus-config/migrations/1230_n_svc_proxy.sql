-- Web proxy (USE=web-proxy): blocked domains
CREATE TABLE IF NOT EXISTS proxy_blocked (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    note TEXT,
    updated_at INTEGER NOT NULL
);
