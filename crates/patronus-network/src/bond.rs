//! Link aggregation (Linux bonding: LACP / 802.3ad, active-backup, ...),
//! created by the interfaces applier.

use crate::linkstate::KLink;
use crate::netconf::BondConfig;

/// `ip link add` arguments for a bond.
pub fn create_args(b: &BondConfig) -> Vec<String> {
    let mut a: Vec<String> = [
        "link",
        "add",
        "name",
        &b.name,
        "type",
        "bond",
        "mode",
        &b.mode,
        "miimon",
        &b.miimon.to_string(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if b.mode == "802.3ad" {
        if let Some(r) = &b.lacp_rate {
            a.extend(["lacp_rate".into(), r.clone()]);
        }
    }
    if let Some(h) = &b.xmit_hash_policy {
        if matches!(
            b.mode.as_str(),
            "802.3ad" | "balance-xor" | "balance-tlb" | "balance-alb"
        ) {
            a.extend(["xmit_hash_policy".into(), h.clone()]);
        }
    }
    a
}

/// Mode/LACP/hash changes need a fresh bond (the kernel refuses to change
/// them while slaves are attached).
pub fn needs_recreate(b: &BondConfig, k: &KLink) -> bool {
    if k.kind.as_deref() != Some("bond") || k.bond_mode.as_deref() != Some(b.mode.as_str()) {
        return true;
    }
    if k.bond_miimon.is_some_and(|m| m != b.miimon) {
        return true;
    }
    if b.mode == "802.3ad" {
        if let (Some(want), Some(have)) = (&b.lacp_rate, &k.bond_lacp_rate) {
            if want != have {
                return true;
            }
        }
    }
    if let (Some(want), Some(have)) = (&b.xmit_hash_policy, &k.bond_xmit_hash_policy) {
        if create_args(b).contains(want) && want != have {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_and_recreate() {
        let b = BondConfig {
            name: "bond0".into(),
            mode: "802.3ad".into(),
            miimon: 100,
            lacp_rate: Some("fast".into()),
            xmit_hash_policy: Some("layer3+4".into()),
            primary: None,
            members: vec!["eth1".into()],
            enabled: true,
            description: None,
        };
        assert_eq!(
            create_args(&b).join(" "),
            "link add name bond0 type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4"
        );
        let mut k = KLink {
            kind: Some("bond".into()),
            bond_mode: Some("802.3ad".into()),
            bond_miimon: Some(100),
            bond_lacp_rate: Some("fast".into()),
            bond_xmit_hash_policy: Some("layer3+4".into()),
            ..Default::default()
        };
        assert!(!needs_recreate(&b, &k));
        k.bond_lacp_rate = Some("slow".into());
        assert!(needs_recreate(&b, &k));
        k.bond_mode = Some("active-backup".into());
        assert!(needs_recreate(&b, &k));
    }
}
