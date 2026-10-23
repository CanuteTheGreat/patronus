//! Wake-on-LAN: named hosts (MAC + interface) and a "wake" button that sends
//! the magic packet (6 x 0xFF, then the MAC 16 times) as a UDP broadcast to
//! port 9 of the interface's IPv4 subnet, bound to that interface's address so
//! it leaves through the right NIC. No daemon and no root needed: the packet
//! is sent by the web process itself.

use crate::lan::{self, invalid};
use crate::svc::{self, Coll, Field, Kind, Spec, Svc};
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

static HOST_FIELDS: [Field; 3] = [
    Field::new("name", "Name", Kind::Token).req(),
    Field::new("mac", "MAC address", Kind::Mac).req(),
    Field::new("interface", "Interface", Kind::Iface)
        .def("@lan")
        .help("the network the host is on (device or @lan / @optN)"),
];

static SPEC: Spec = Spec {
    slug: "wol",
    title: "Wake-on-LAN",
    blurb: "Wake sleeping machines on your networks: save hosts by MAC address and press Wake, \
            or wake an unsaved MAC from the form. Sends the magic packet as a UDP broadcast on \
            the host's interface.",
    applier: "",
    fields: &[],
    colls: &[Coll {
        key: "hosts",
        title: "Hosts",
        table: "wol_hosts",
        fields: &HOST_FIELDS,
        unique: Some("name"),
    }],
    actions: &[("wake", "Wake")],
};

pub struct WolSvc;

/// The 102-byte magic packet for `mac` (`aa:bb:cc:dd:ee:ff`).
pub fn magic_packet(mac: &str) -> Result<Vec<u8>> {
    let m = lan::check_mac(mac)?;
    let bytes: Vec<u8> = m
        .split(':')
        .map(|p| u8::from_str_radix(p, 16).unwrap_or(0))
        .collect();
    let mut p = vec![0xffu8; 6];
    for _ in 0..16 {
        p.extend_from_slice(&bytes);
    }
    Ok(p)
}

/// Directed broadcast address of `addr/prefix`.
pub fn broadcast(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    Ipv4Addr::from(u32::from(addr) | !mask)
}

/// Send the magic packet out of every IPv4 subnet of `iface`'s devices.
/// Returns the (device, broadcast address) pairs it was sent to.
pub async fn wake(store: &ConfigStore, mac: &str, iface: &str) -> Result<Vec<(String, Ipv4Addr)>> {
    let pkt = magic_packet(mac)?;
    let devs = lan::resolve_iface(store, iface).await?;
    if devs.is_empty() {
        return Err(invalid(format!(
            "interface {iface}: not assigned to any device"
        )));
    }
    let addrs = {
        use crate::lan::AddrSource;
        lan::LiveAddrs.addrs()?
    };
    let mut sent = Vec::new();
    for a in addrs.iter().filter(|a| devs.contains(&a.ifname)) {
        let IpAddr::V4(v4) = a.addr else { continue };
        let bc = broadcast(v4, a.prefix);
        let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(v4), 0))
            .map_err(|e| Error::Network(format!("wake: bind {v4}: {e}")))?;
        sock.set_broadcast(true)
            .map_err(|e| Error::Network(format!("wake: broadcast: {e}")))?;
        sock.send_to(&pkt, SocketAddr::new(IpAddr::V4(bc), 9))
            .map_err(|e| Error::Network(format!("wake: send to {bc} on {}: {e}", a.ifname)))?;
        sent.push((a.ifname.clone(), bc));
    }
    if sent.is_empty() {
        return Err(Error::Network(format!(
            "wake: {iface} has no IPv4 address to send from"
        )));
    }
    Ok(sent)
}

#[async_trait]
impl Svc for WolSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        if name != "wake" {
            return Err(Error::Config(format!(
                "Invalid request: no action {name:?}"
            )));
        }
        let (mac, iface) = if let Some(id) = body.get("id").and_then(Value::as_i64) {
            let rows = svc::raw_rows(store, &SPEC.colls[0]).await?;
            let r = rows
                .iter()
                .find(|r| r["id"].as_i64() == Some(id))
                .ok_or_else(|| Error::Config(format!("no host {id}")))?;
            (
                r["mac"].as_str().unwrap_or("").to_string(),
                r["interface"].as_str().unwrap_or("@lan").to_string(),
            )
        } else {
            let mac = body.get("mac").and_then(Value::as_str).unwrap_or("");
            let iface = body
                .get("interface")
                .and_then(Value::as_str)
                .unwrap_or("@lan");
            (lan::check_mac(mac)?, lan::check_iface_spec(iface)?)
        };
        let sent = wake(store, &mac, &iface).await?;
        Ok(json!({
            "mac": mac,
            "sent_to": sent.iter().map(|(d, b)| format!("{d}: {b}:9")).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_packet_is_ff_then_the_mac_sixteen_times() {
        let p = magic_packet("AA-BB-CC-00-00-02").unwrap();
        assert_eq!(p.len(), 102);
        assert!(p[..6].iter().all(|b| *b == 0xff));
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..12 + i * 6], &[0xaa, 0xbb, 0xcc, 0, 0, 2]);
        }
        assert!(magic_packet("aa:bb").is_err());
    }

    #[test]
    fn directed_broadcast_of_a_subnet() {
        assert_eq!(
            broadcast("192.168.50.1".parse().unwrap(), 24).to_string(),
            "192.168.50.255"
        );
        assert_eq!(
            broadcast("10.1.2.3".parse().unwrap(), 20).to_string(),
            "10.1.15.255"
        );
        assert_eq!(
            broadcast("10.1.2.3".parse().unwrap(), 32).to_string(),
            "10.1.2.3"
        );
    }

    #[tokio::test]
    async fn hosts_are_validated_and_stored() {
        let s = crate::lan::testutil::store().await;
        let c = &SPEC.colls[0];
        assert!(
            svc::save_row(&s, c, None, &json!({"name": "nas", "mac": "nope"}))
                .await
                .is_err()
        );
        assert!(svc::save_row(
            &s,
            c,
            None,
            &json!({"name": "a b", "mac": "aa:bb:cc:dd:ee:ff"})
        )
        .await
        .is_err());
        svc::save_row(
            &s,
            c,
            None,
            &json!({"name": "nas", "mac": "AA:BB:CC:DD:EE:FF"}),
        )
        .await
        .unwrap();
        assert!(svc::save_row(
            &s,
            c,
            None,
            &json!({"name": "nas", "mac": "aa:bb:cc:dd:ee:01"})
        )
        .await
        .is_err());
        let rows = svc::list_rows(&s, c).await.unwrap();
        assert_eq!(rows[0]["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(rows[0]["interface"], "@lan");
    }
}
