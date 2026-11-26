-- Lane J (FRR): OSPF network type per interface. Route-based IPsec interfaces (xfrm*)
-- have no broadcast domain: 'auto' makes OSPF point-to-point on them and
-- broadcast everywhere else; 'broadcast' / 'point-to-point' force it.
ALTER TABLE frr_ospf_interfaces ADD COLUMN network TEXT NOT NULL DEFAULT 'auto';
