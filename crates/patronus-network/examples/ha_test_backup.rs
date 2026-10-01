//! Real HA failover test harness - BACKUP node (azkaban)
use patronus_network::ha::{HaBackend, HaCluster, HaManager, HaRole, VirtualIp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cluster = HaCluster {
        name: "patronus-ha-test".to_string(),
        enabled: true,
        backend: HaBackend::Keepalived,
        role: HaRole::Backup,
        peer_ip: "10.66.69.134".parse().unwrap(), // hogshead
        sync_interface: "vmbr0".to_string(),
        sync_enabled: false,
        virtual_ips: vec![VirtualIp {
            name: "test-vip".to_string(),
            enabled: true,
            vip: "10.66.69.250".parse().unwrap(),
            interface: "vmbr0".to_string(),
            vhid: 51,
            priority: 100,
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
    println!("BACKUP config written to /etc/keepalived/keepalived.conf");
    Ok(())
}
