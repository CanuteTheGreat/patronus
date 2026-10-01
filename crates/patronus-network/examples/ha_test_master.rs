//! Real HA failover test harness - MASTER node (hogshead)
use patronus_network::ha::{HaBackend, HaCluster, HaManager, HaRole, VirtualIp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cluster = HaCluster {
        name: "patronus-ha-test".to_string(),
        enabled: true,
        backend: HaBackend::Keepalived,
        role: HaRole::Master,
        peer_ip: "10.66.69.2".parse().unwrap(), // azkaban
        sync_interface: "wlp229s0".to_string(),
        sync_enabled: false,
        virtual_ips: vec![VirtualIp {
            name: "test-vip".to_string(),
            enabled: true,
            vip: "10.66.69.250".parse().unwrap(),
            interface: "wlp229s0".to_string(),
            vhid: 51,
            priority: 200,
            password: Some("patronustest123".to_string()),
            preempt: true,
            advskew: 0,
        }],
        config_sync_enabled: false,
        config_sync_user: "patronus".to_string(),
        config_sync_path: "/etc/patronus".into(),
    };

    let mgr = HaManager::new(HaBackend::Keepalived);
    mgr.configure(&cluster).await?;
    println!("MASTER config written to /etc/keepalived/keepalived.conf");
    Ok(())
}
