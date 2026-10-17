//! 802.1Q VLAN subinterfaces and QinQ (802.1ad service VLANs), created by
//! the interfaces applier (USE=vlan, cargo feature `vlan`).
//!
//! A QinQ customer VLAN is an 802.1Q VLAN whose parent is an 802.1ad VLAN
//! (`eth0` -> `eth0.100` 802.1ad -> `eth0.100.20` 802.1Q).

use crate::linkstate::KLink;
use crate::netconf::VlanConfig;

/// `ip link add` arguments for a VLAN.
pub fn create_args(v: &VlanConfig) -> Vec<String> {
    let proto = if v.protocol == "802.1ad" {
        "802.1ad"
    } else {
        "802.1Q"
    };
    [
        "link",
        "add",
        "link",
        &v.parent,
        "name",
        &v.name,
        "type",
        "vlan",
        "id",
        &v.vlan_id.to_string(),
        "protocol",
        proto,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// An existing device with this name can't be reused as this VLAN.
pub fn needs_recreate(v: &VlanConfig, k: &KLink) -> bool {
    k.kind.as_deref() != Some("vlan")
        || k.link.as_deref() != Some(v.parent.as_str())
        || k.vlan_id != Some(v.vlan_id)
        || k.vlan_protocol.as_deref().unwrap_or("802.1q") != v.protocol
}

/// VLANs ordered so every parent VLAN comes before its children (QinQ).
pub fn topo_order(vlans: &[VlanConfig]) -> Vec<&VlanConfig> {
    let mut out: Vec<&VlanConfig> = Vec::new();
    let mut left: Vec<&VlanConfig> = vlans.iter().collect();
    while !left.is_empty() {
        let before = left.len();
        left.retain(|v| {
            let parent_is_pending =
                vlans.iter().any(|p| p.name == v.parent) && !out.iter().any(|o| o.name == v.parent);
            if parent_is_pending {
                true
            } else {
                out.push(v);
                false
            }
        });
        if left.len() == before {
            // a loop (rejected by validation); keep going deterministically
            out.append(&mut left);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(name: &str, parent: &str, id: u16, proto: &str) -> VlanConfig {
        VlanConfig {
            name: name.into(),
            parent: parent.into(),
            vlan_id: id,
            protocol: proto.into(),
            enabled: true,
            description: None,
        }
    }

    #[test]
    fn qinq_parents_first_and_args() {
        let vs = vec![
            v("c20", "s100", 20, "802.1q"),
            v("s100", "eth0", 100, "802.1ad"),
        ];
        let o: Vec<&str> = topo_order(&vs).iter().map(|v| v.name.as_str()).collect();
        assert_eq!(o, vec!["s100", "c20"]);
        assert_eq!(
            create_args(&vs[1]).join(" "),
            "link add link eth0 name s100 type vlan id 100 protocol 802.1ad"
        );
        let k = KLink {
            kind: Some("vlan".into()),
            link: Some("eth0".into()),
            vlan_id: Some(100),
            vlan_protocol: Some("802.1ad".into()),
            ..Default::default()
        };
        assert!(!needs_recreate(&vs[1], &k));
        assert!(needs_recreate(&v("s100", "eth0", 101, "802.1ad"), &k));
    }
}
