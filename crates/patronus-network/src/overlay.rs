//! GRE, GRE-TAP and VXLAN overlay links, created by the interfaces applier
//! with plain `ip link add` (no cargo feature: the kernel modules are all
//! it needs).
//!
//! * `gre`    - L3 tunnel (IP in GRE), optional key.
//! * `gretap` - L2 tunnel (Ethernet in GRE), can be a bridge member.
//! * `vxlan`  - L2 overlay over UDP (default port: setting `network.vxlan_port`), VNI required.

use crate::linkstate::KLink;
use crate::netconf::OverlayConfig;

pub const KINDS: &[&str] = &["gre", "gretap", "vxlan"];

/// VXLAN destination port of an overlay that sets none: setting `network.vxlan_port`
/// (cached; the CLI and the web server both fill the cache at start).
fn default_vxlan_port() -> u16 {
    patronus_config::settings::current_i64("network.vxlan_port")
        .try_into()
        .unwrap_or(0)
}

/// `ip link add` arguments for an overlay link.
pub fn create_args(o: &OverlayConfig) -> Vec<String> {
    let mut a: Vec<String> = ["link", "add", "name", &o.name, "type", &o.kind]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut add = |k: &str, v: String| {
        a.push(k.to_string());
        a.push(v);
    };
    if o.kind == "vxlan" {
        add("id", o.key.unwrap_or(0).to_string());
        add(
            "dstport",
            o.port.unwrap_or_else(default_vxlan_port).to_string(),
        );
    }
    add("remote", o.remote.clone());
    if let Some(l) = o.local.as_ref().filter(|l| !l.is_empty()) {
        add("local", l.clone());
    }
    if o.kind != "vxlan" {
        if let Some(k) = o.key {
            add("key", k.to_string());
        }
    }
    if let Some(t) = o.ttl {
        add("ttl", t.to_string());
    }
    a
}

/// A kernel tunnel key as `ip -j` prints it: a number or a dotted quad.
pub fn parse_key(v: &serde_json::Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    let s = v.as_str()?;
    if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
        return Some(u32::from(ip));
    }
    s.parse().ok()
}

/// An existing device with this name can't be reused as this overlay.
pub fn needs_recreate(o: &OverlayConfig, k: &KLink) -> bool {
    if k.kind.as_deref() != Some(o.kind.as_str()) {
        return true;
    }
    if k.tun_remote.as_deref() != Some(o.remote.as_str()) {
        return true;
    }
    if let Some(l) = o.local.as_ref().filter(|l| !l.is_empty()) {
        if k.tun_local.as_deref() != Some(l.as_str()) {
            return true;
        }
    }
    if o.kind == "vxlan" {
        if k.tun_key != o.key {
            return true;
        }
        if k.tun_port.unwrap_or_else(default_vxlan_port)
            != o.port.unwrap_or_else(default_vxlan_port)
        {
            return true;
        }
    } else if k.tun_key.unwrap_or(0) != o.key.unwrap_or(0) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(kind: &str) -> OverlayConfig {
        OverlayConfig {
            name: "gre-a".into(),
            kind: kind.into(),
            local: Some("10.0.0.1".into()),
            remote: "10.0.0.2".into(),
            key: Some(42),
            port: None,
            ttl: Some(64),
            enabled: true,
            description: None,
        }
    }

    #[test]
    fn create_args_per_kind() {
        assert_eq!(
            create_args(&o("gre")).join(" "),
            "link add name gre-a type gre remote 10.0.0.2 local 10.0.0.1 key 42 ttl 64"
        );
        assert_eq!(
            create_args(&o("vxlan")).join(" "),
            "link add name gre-a type vxlan id 42 dstport 4789 remote 10.0.0.2 \
             local 10.0.0.1 ttl 64"
        );
    }

    #[test]
    fn key_parsing_accepts_numbers_and_dotted_quads() {
        assert_eq!(parse_key(&serde_json::json!(7)), Some(7));
        assert_eq!(parse_key(&serde_json::json!("0.0.0.42")), Some(42));
        assert_eq!(parse_key(&serde_json::json!("42")), Some(42));
    }

    #[test]
    fn changed_parameters_recreate() {
        let c = o("gre");
        let k = KLink {
            kind: Some("gre".into()),
            tun_remote: Some("10.0.0.2".into()),
            tun_local: Some("10.0.0.1".into()),
            tun_key: Some(42),
            ..Default::default()
        };
        assert!(!needs_recreate(&c, &k));
        let mut c2 = c.clone();
        c2.remote = "10.0.0.9".into();
        assert!(needs_recreate(&c2, &k));
        let mut c3 = c.clone();
        c3.key = Some(43);
        assert!(needs_recreate(&c3, &k));
        assert!(needs_recreate(&o("gretap"), &k));
    }
}
