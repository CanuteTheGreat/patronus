-- Lane D (LAN services): DHCPv4/v6, router advertisements, DHCP relay,
-- DNS resolver/forwarder with overrides and DNSBL, NTP server, dynamic DNS.
--
-- `interface` columns hold a role token ('@lan', '@opt1', ...) or a device
-- name. Roles are resolved at apply time (see AGENTS.md), so re-assigning a
-- NIC never strands a DHCP pool on the old device; an unassigned role skips
-- the item with a warning.
--
-- Accessors and the appliers that read these tables live in
-- crates/patronus-network/src/{lan,dhcp,dhcp6,ra,dns,ntp,ddns}.rs.

-- Global switches and options, namespaced keys:
--   dhcp.backend      auto | kea | dnsmasq        (DHCPv4/v6 server daemon)
--   dhcp.ra_backend   auto | radvd | dnsmasq      (router advertisements)
--   dns.mode          resolver | forwarder | disabled
--   dns.upstreams     comma list; resolver: forward everything there
--                     instead of recursing; forwarder: required
--   dns.dnssec        0 | 1
--   dns.interfaces    comma list of roles/devices to serve (default @lan)
--   dns.blocklist_urls     comma list of http(s):// or file:// host lists
--   dns.block_mode    nxdomain | null
--   ntp.enabled       0 | 1
--   ntp.servers       comma list of upstream servers/pools
--   ntp.interfaces    comma list of roles/devices whose subnets may query
CREATE TABLE IF NOT EXISTS lan_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- DHCPv4 server pools, one per served interface.
CREATE TABLE IF NOT EXISTS dhcp_pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    range_start TEXT NOT NULL,
    range_end TEXT NOT NULL,
    lease_time INTEGER NOT NULL DEFAULT 86400,
    -- NULL = the router's own address on the interface
    gateway TEXT,
    -- comma list; NULL = the router's own address when DNS is enabled
    dns_servers TEXT,
    domain TEXT,
    -- comma list; NULL = the router's own address when NTP is enabled
    ntp_servers TEXT,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- DHCPv4 static mappings (reservations).
CREATE TABLE IF NOT EXISTS dhcp_static_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id INTEGER NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    description TEXT,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (pool_id) REFERENCES dhcp_pools(id) ON DELETE CASCADE,
    UNIQUE(pool_id, mac),
    UNIQUE(pool_id, ip)
);

-- DHCPv6 server pools (stateful addresses).
CREATE TABLE IF NOT EXISTS dhcp6_pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    range_start TEXT NOT NULL,
    range_end TEXT NOT NULL,
    prefix_len INTEGER NOT NULL DEFAULT 64,
    lease_time INTEGER NOT NULL DEFAULT 86400,
    -- comma list; NULL = the router's own address when DNS is enabled
    dns_servers TEXT,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- Router advertisements per interface.
--   mode: slaac (A flag), stateless (A+O: SLAAC + DHCPv6 options),
--         managed (M+O, addresses from DHCPv6 only),
--         assisted (M+O+A, DHCPv6 and SLAAC)
CREATE TABLE IF NOT EXISTS ra_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    mode TEXT NOT NULL DEFAULT 'slaac',
    -- NULL = every global /64 configured on the interface
    prefix TEXT,
    -- comma list of RDNSS; NULL = the router's own address when DNS is on
    dns_servers TEXT,
    min_interval INTEGER NOT NULL DEFAULT 200,
    max_interval INTEGER NOT NULL DEFAULT 600,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- DHCP relay: forward client requests arriving on `interface` to servers.
CREATE TABLE IF NOT EXISTS dhcp_relays (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- comma list of IPv4 and/or IPv6 server addresses
    servers TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- DNS host overrides (local A/AAAA + PTR).
CREATE TABLE IF NOT EXISTS dns_host_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    domain TEXT NOT NULL,
    address TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(hostname, domain, address)
);

-- DNS domain overrides: queries for `domain` go to `server`.
CREATE TABLE IF NOT EXISTS dns_domain_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    server TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(domain, server)
);

-- DNSBL: domains blocked by hand (lists from dns.blocklist_urls are
-- downloaded at apply time, not stored here).
CREATE TABLE IF NOT EXISTS dns_blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- Dynamic DNS clients. `password` is write-only through the API.
CREATE TABLE IF NOT EXISTS ddns_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enabled INTEGER NOT NULL DEFAULT 1,
    -- dyndns2 | duckdns | cloudflare | custom
    provider TEXT NOT NULL,
    hostname TEXT NOT NULL,
    -- role/device whose address is published (default @wan)
    interface TEXT NOT NULL DEFAULT '@wan',
    username TEXT,
    password TEXT,
    -- dyndns2: server host; cloudflare: zone id; custom: URL template
    -- with %h (hostname) and %i (address)
    server TEXT,
    description TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(provider, hostname)
);
