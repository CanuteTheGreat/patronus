-- Lane J: LAN security audit (`patronus_network::lanaudit`, docs/LAN-AUDIT.md).
-- "Scan my network": open ports and service versions per device, a rule set of
-- findings, compared with the last scan. Settings are `lanaudit.*` keys in
-- system_config (configuration: exported, rolled back). The four tables below
-- are measured data and are listed in NON_CONFIG_TABLES: a backup, restore or
-- rollback never carries or rewinds them. Retention bounds them.

-- One scan run (a sweep of one or more segments).
CREATE TABLE IF NOT EXISTS audit_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at INTEGER NOT NULL,              -- unix seconds
    finished_at INTEGER,                      -- NULL while running
    -- scheduled | manual
    trigger TEXT NOT NULL DEFAULT 'manual',
    -- the segments this scan covered (comma-separated specs, e.g. '@lan,@opt1')
    segments TEXT NOT NULL DEFAULT '',
    -- builtin | nmap  (which scanner ran)
    engine TEXT NOT NULL DEFAULT 'builtin',
    -- running | done | failed | cancelled
    state TEXT NOT NULL DEFAULT 'running',
    hosts_up INTEGER NOT NULL DEFAULT 0,
    ports_open INTEGER NOT NULL DEFAULT 0,
    findings INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_scans_started ON audit_scans(started_at);

-- One host seen in a scan.
CREATE TABLE IF NOT EXISTS audit_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    -- best name we have (segmentation device name, DHCP lease hostname, or '')
    name TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    segment TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES audit_scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS audit_hosts_scan ON audit_hosts(scan_id, address);

-- One open port on a host.
CREATE TABLE IF NOT EXISTS audit_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    -- tcp | udp
    proto TEXT NOT NULL DEFAULT 'tcp',
    port INTEGER NOT NULL,
    service TEXT NOT NULL DEFAULT '',          -- nmap's service name or our guess
    product TEXT NOT NULL DEFAULT '',          -- product/version banner (nmap -sV)
    version TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES audit_hosts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS audit_ports_scan ON audit_ports(scan_id, address, port);

-- One finding raised by a rule against a host/port in a scan.
CREATE TABLE IF NOT EXISTS audit_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    port INTEGER,                              -- NULL for a host-level finding (new device)
    proto TEXT NOT NULL DEFAULT 'tcp',
    -- rule id: telnet | ftp | smb | upnp | http_admin | default_creds | database |
    --          new_device | new_port
    rule TEXT NOT NULL,
    -- info | warning | critical
    severity TEXT NOT NULL DEFAULT 'warning',
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES audit_scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS audit_findings_scan ON audit_findings(scan_id, severity);
