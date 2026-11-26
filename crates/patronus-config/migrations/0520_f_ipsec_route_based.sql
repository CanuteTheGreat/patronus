-- Lane F: route-based IPsec (XFRM interfaces) and the status page's
-- connect / disconnect requests.
--
-- mode 'policy' = traffic selectors decide (the original behaviour),
-- 'route' = the child SA is bound to the XFRM interface xfrm<if_id>
-- (strongSwan if_id_in / if_id_out) and routes (static, OSPF/BGP via FRR)
-- send traffic into it.
ALTER TABLE ipsec_tunnels ADD COLUMN mode TEXT NOT NULL DEFAULT 'policy';
ALTER TABLE ipsec_tunnels ADD COLUMN if_id INTEGER;
-- this router's address on the XFRM interface, CIDR
ALTER TABLE ipsec_tunnels ADD COLUMN tunnel_address TEXT;
ALTER TABLE ipsec_tunnels ADD COLUMN mtu INTEGER;
-- device the XFRM interface is attached to (NULL = lo)
ALTER TABLE ipsec_tunnels ADD COLUMN xfrm_dev TEXT;

-- One click on the status page = one row; the applier (root) carries it
-- out on the next apply and deletes it. Not configuration (NON_CONFIG_TABLES).
CREATE TABLE IF NOT EXISTS ipsec_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tunnel TEXT NOT NULL,
    action TEXT NOT NULL,             -- 'connect' | 'disconnect'
    requested_at INTEGER NOT NULL
);
