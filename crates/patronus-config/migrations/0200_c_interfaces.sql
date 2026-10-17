-- Lane C (interfaces & L2): per-interface addressing, virtual devices
-- (VLAN / QinQ, bonds, bridges, PPPoE) applied by the interfaces applier
-- (patronus-network/src/interfaces.rs, boot phase "interfaces").
--
-- A row in `interfaces` that only carries a role (written by first-boot
-- seeding) stays 'unmanaged': Patronus does not touch its addressing until
-- the admin configures it, so an installer-configured NIC keeps working.

-- IPv4: 'unmanaged' | 'none' | 'static' | 'dhcp'. PPPoE devices get their
-- address from pppd and ignore this column.
ALTER TABLE interfaces ADD COLUMN ipv4_mode TEXT NOT NULL DEFAULT 'unmanaged';
-- IPv6: 'unmanaged' | 'none' | 'static' | 'slaac' | 'dhcp6'.
ALTER TABLE interfaces ADD COLUMN ipv6_mode TEXT NOT NULL DEFAULT 'unmanaged';
-- Upstream gateways for static modes (installed as the default route via
-- this interface).
ALTER TABLE interfaces ADD COLUMN gateway4 TEXT;
ALTER TABLE interfaces ADD COLUMN gateway6 TEXT;
-- Spoofed MAC address (NULL = keep the hardware address).
ALTER TABLE interfaces ADD COLUMN mac TEXT;

-- 802.1Q (default) or 802.1ad (QinQ outer tag). A QinQ customer VLAN is an
-- 802.1Q VLAN whose parent is an 802.1ad VLAN.
ALTER TABLE vlans ADD COLUMN protocol TEXT NOT NULL DEFAULT '802.1q';

-- Link aggregation (Linux bonding).
CREATE TABLE IF NOT EXISTS l2_bonds (
    name TEXT PRIMARY KEY,
    -- 'active-backup' | '802.3ad' | 'balance-rr' | 'balance-xor' |
    -- 'broadcast' | 'balance-tlb' | 'balance-alb'
    mode TEXT NOT NULL DEFAULT 'active-backup',
    miimon INTEGER NOT NULL DEFAULT 100,
    lacp_rate TEXT,          -- 'slow' | 'fast' (802.3ad)
    xmit_hash_policy TEXT,   -- 'layer2' | 'layer2+3' | 'layer3+4' | ...
    primary_member TEXT,     -- preferred slave (active-backup)
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS l2_bond_members (
    member TEXT PRIMARY KEY,  -- a device is a member of at most one bond
    bond TEXT NOT NULL REFERENCES l2_bonds(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS l2_bridges (
    name TEXT PRIMARY KEY,
    stp INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS l2_bridge_members (
    member TEXT PRIMARY KEY,  -- a device is a port of at most one bridge
    bridge TEXT NOT NULL REFERENCES l2_bridges(name) ON DELETE CASCADE
);

-- PPPoE client links. `name` is the ppp device pppd creates (`ifname`), the
-- thing a role (usually WAN) is assigned to.
CREATE TABLE IF NOT EXISTS pppoe_links (
    name TEXT PRIMARY KEY,
    parent_interface TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    service_name TEXT,
    mtu INTEGER NOT NULL DEFAULT 1492,
    default_route INTEGER NOT NULL DEFAULT 1,
    use_peer_dns INTEGER NOT NULL DEFAULT 1,
    ipv6 INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
