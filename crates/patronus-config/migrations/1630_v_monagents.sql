-- Zabbix agent 2 (USE=zabbix-agent): the Zabbix servers/proxies allowed to
-- query the agent (passive checks). One host name or address per row.
CREATE TABLE IF NOT EXISTS zabbix_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
