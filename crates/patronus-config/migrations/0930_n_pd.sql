-- DHCPv6 prefix delegation on a WAN interface: comma-separated names of the
-- interfaces that receive a /64 slice of the delegated prefix.
ALTER TABLE interfaces ADD COLUMN pd_downstream TEXT NOT NULL DEFAULT '';
