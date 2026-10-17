-- Patronus Configuration Database Schema

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Firewall filter rules
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    chain TEXT NOT NULL, -- 'input', 'output', 'forward'
    action TEXT NOT NULL, -- 'accept', 'drop', 'reject'
    source TEXT,
    destination TEXT,
    protocol TEXT, -- 'tcp', 'udp', 'icmp', 'all'
    sport TEXT, -- JSON: single, range, or multiple ports
    dport TEXT, -- JSON: single, range, or multiple ports
    interface_in TEXT,
    interface_out TEXT,
    comment TEXT,
    priority INTEGER NOT NULL DEFAULT 0, -- Lower number = higher priority
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_chain ON firewall_rules(chain);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules(priority);

-- NAT rules
CREATE TABLE IF NOT EXISTS nat_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    nat_type TEXT NOT NULL, -- 'masquerade', 'snat', 'dnat'
    to_address TEXT, -- For SNAT/DNAT
    to_port INTEGER, -- For DNAT
    source TEXT,
    destination TEXT,
    protocol TEXT,
    dport TEXT, -- JSON
    interface_out TEXT,
    comment TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nat_rules_enabled ON nat_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_nat_rules_type ON nat_rules(nat_type);

-- Network interfaces configuration
CREATE TABLE IF NOT EXISTS interfaces (
    name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    dhcp INTEGER NOT NULL DEFAULT 0,
    mtu INTEGER,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- IP addresses assigned to interfaces
CREATE TABLE IF NOT EXISTS interface_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT NOT NULL,
    address TEXT NOT NULL,
    prefix_len INTEGER NOT NULL,
    family TEXT NOT NULL, -- 'ipv4' or 'ipv6'
    FOREIGN KEY (interface_name) REFERENCES interfaces(name) ON DELETE CASCADE,
    UNIQUE(interface_name, address)
);

CREATE INDEX IF NOT EXISTS idx_interface_addresses_interface ON interface_addresses(interface_name);

-- Static routes
CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT, -- NULL for default route
    prefix_len INTEGER,
    gateway TEXT,
    interface TEXT,
    metric INTEGER,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes(enabled);

-- VLAN interfaces
CREATE TABLE IF NOT EXISTS vlans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    parent_interface TEXT NOT NULL,
    vlan_id INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(parent_interface, vlan_id)
);

CREATE INDEX IF NOT EXISTS idx_vlans_parent ON vlans(parent_interface);
CREATE INDEX IF NOT EXISTS idx_vlans_enabled ON vlans(enabled);

-- Configuration backups
CREATE TABLE IF NOT EXISTS config_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    config_json TEXT NOT NULL, -- Full config as JSON
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_config_backups_created ON config_backups(created_at DESC);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL, -- 'firewall_rule', 'nat_rule', 'interface', etc.
    entity_id TEXT,
    details TEXT, -- JSON with change details
    user TEXT DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id);
