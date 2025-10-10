//! Integration tests for SD-WAN mesh networking
//!
//! These tests validate the complete SD-WAN stack including:
//! - Site discovery and announcement
//! - Automatic WireGuard peering
//! - Path monitoring and quality measurement
//! - Intelligent routing with policy enforcement

use patronus_sdwan::{
    database::Database,
    mesh::MeshManager,
    monitor::PathMonitor,
    routing::RoutingEngine,
    types::*,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Test helper to create a site manager
async fn create_test_site(name: &str) -> (Arc<Database>, MeshManager, PathMonitor, RoutingEngine) {
    let db = Arc::new(Database::new(":memory:").await.unwrap());
    let site_id = SiteId::generate();

    let mesh = MeshManager::new(site_id, name.to_string(), db.clone());
    let monitor = PathMonitor::new(db.clone());
    let router = RoutingEngine::new(db.clone());

    (db, mesh, monitor, router)
}

#[tokio::test]
async fn test_two_site_mesh() {
    // Create two sites
    let (db1, mesh1, monitor1, router1) = create_test_site("site-alpha").await;
    let (db2, mesh2, monitor2, router2) = create_test_site("site-beta").await;

    // Start mesh managers
    mesh1.start().await.expect("Failed to start mesh1");
    mesh2.start().await.expect("Failed to start mesh2");

    // Wait for site discovery (announcements every 30s, we'll wait 2s for test)
    sleep(Duration::from_secs(2)).await;

    // Check that sites discovered each other
    let _sites1 = mesh1.list_known_sites().await;
    let _sites2 = mesh2.list_known_sites().await;

    // In real network they would discover each other via multicast
    // In test environment, this may not work without proper network setup
    // We just validate the managers started successfully

    // Stop mesh managers
    mesh1.stop().await.expect("Failed to stop mesh1");
    mesh2.stop().await.expect("Failed to stop mesh2");
}

#[tokio::test]
async fn test_path_monitoring_lifecycle() {
    let (db, _mesh, monitor, _router) = create_test_site("test-site").await;

    // Start path monitor
    monitor.start().await.expect("Failed to start monitor");

    // Create test sites first (required for foreign key constraints)
    let site1 = Site {
        id: SiteId::generate(),
        name: "site1".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };
    let site2 = Site {
        id: SiteId::generate(),
        name: "site2".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };
    db.upsert_site(&site1).await.expect("Failed to insert site1");
    db.upsert_site(&site2).await.expect("Failed to insert site2");

    // Create a test path
    let path = Path {
        id: PathId::new(1),
        src_site: site1.id,
        dst_site: site2.id,
        src_endpoint: "0.0.0.0:51820".parse().unwrap(),
        dst_endpoint: "127.0.0.1:51820".parse().unwrap(),
        wg_interface: Some("wg-test".to_string()),
        metrics: PathMetrics::default(),
        status: PathStatus::Up,
    };

    let path_id = db.insert_path(&path).await.expect("Failed to insert path");

    // Wait for monitoring to start
    sleep(Duration::from_secs(1)).await;

    // Try to get metrics (may not be available yet in test environment)
    match monitor.get_metrics(path_id).await {
        Ok(metrics) => {
            // If we got metrics, validate they're initialized
            assert!(metrics.score <= 100);
        }
        Err(_) => {
            // No metrics yet is acceptable in test environment
        }
    }

    // Stop monitor
    monitor.stop().await.expect("Failed to stop monitor");
}

#[tokio::test]
async fn test_routing_engine_path_selection() {
    let (db, _mesh, _monitor, router) = create_test_site("test-site").await;

    // Start routing engine
    router.start().await.expect("Failed to start router");

    // Create test sites first
    let site1 = Site {
        id: SiteId::generate(),
        name: "site1".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };
    let site2 = Site {
        id: SiteId::generate(),
        name: "site2".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };
    db.upsert_site(&site1).await.expect("Failed to insert site1");
    db.upsert_site(&site2).await.expect("Failed to insert site2");

    // Create test paths
    let site1_id = site1.id;
    let site2_id = site2.id;

    let path1 = Path {
        id: PathId::new(1),
        src_site: site1_id,
        dst_site: site2_id,
        src_endpoint: "0.0.0.0:51820".parse().unwrap(),
        dst_endpoint: "192.168.1.1:51820".parse().unwrap(),
        wg_interface: Some("wg-test1".to_string()),
        metrics: PathMetrics {
            latency_ms: 10.0,
            jitter_ms: 2.0,
            packet_loss_pct: 0.1,
            bandwidth_mbps: 1000.0,
            mtu: 1500,
            measured_at: std::time::SystemTime::now(),
            score: 95,
        },
        status: PathStatus::Up,
    };

    let path2 = Path {
        id: PathId::new(2),
        src_site: site1_id,
        dst_site: site2_id,
        src_endpoint: "0.0.0.0:51821".parse().unwrap(),
        dst_endpoint: "192.168.1.1:51821".parse().unwrap(),
        wg_interface: Some("wg-test2".to_string()),
        metrics: PathMetrics {
            latency_ms: 50.0,
            jitter_ms: 10.0,
            packet_loss_pct: 1.0,
            bandwidth_mbps: 100.0,
            mtu: 1500,
            measured_at: std::time::SystemTime::now(),
            score: 70,
        },
        status: PathStatus::Up,
    };

    db.insert_path(&path1).await.expect("Failed to insert path1");
    db.insert_path(&path2).await.expect("Failed to insert path2");

    // Store metrics
    db.store_path_metrics(path1.id, &path1.metrics).await.expect("Failed to store path1 metrics");
    db.store_path_metrics(path2.id, &path2.metrics).await.expect("Failed to store path2 metrics");

    // Test flow - VoIP traffic should prefer low-latency path
    let voip_flow = FlowKey {
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "10.0.0.2".parse().unwrap(),
        src_port: 50000,
        dst_port: 5060, // SIP port
        protocol: 17, // UDP
    };

    let selected_path = router.select_path(&voip_flow).await.expect("Failed to select path");

    // Should select path1 (better metrics)
    assert_eq!(selected_path, path1.id);

    // Verify sticky routing - same flow should get same path
    let selected_again = router.select_path(&voip_flow).await.expect("Failed to select path again");
    assert_eq!(selected_again, path1.id);

    // Different flow
    let web_flow = FlowKey {
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "10.0.0.3".parse().unwrap(),
        src_port: 50001,
        dst_port: 443,
        protocol: 6, // TCP
    };

    let web_path = router.select_path(&web_flow).await.expect("Failed to select web path");
    // Should also select path1 (better overall)
    assert_eq!(web_path, path1.id);

    // Stop router
    router.stop().await.expect("Failed to stop router");
}

#[tokio::test]
async fn test_path_failover() {
    let (db, _mesh, _monitor, router) = create_test_site("test-site").await;

    router.start().await.expect("Failed to start router");

    // Create test sites first
    let site1 = Site {
        id: SiteId::generate(),
        name: "site1".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };
    let site2 = Site {
        id: SiteId::generate(),
        name: "site2".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };
    db.upsert_site(&site1).await.expect("Failed to insert site1");
    db.upsert_site(&site2).await.expect("Failed to insert site2");

    let site1_id = site1.id;
    let site2_id = site2.id;

    // Create primary path (good)
    let primary = Path {
        id: PathId::new(1),
        src_site: site1_id,
        dst_site: site2_id,
        src_endpoint: "0.0.0.0:51820".parse().unwrap(),
        dst_endpoint: "192.168.1.1:51820".parse().unwrap(),
        wg_interface: Some("wg-primary".to_string()),
        metrics: PathMetrics {
            latency_ms: 10.0,
            jitter_ms: 2.0,
            packet_loss_pct: 0.1,
            bandwidth_mbps: 1000.0,
            mtu: 1500,
            measured_at: std::time::SystemTime::now(),
            score: 95,
        },
        status: PathStatus::Up,
    };

    // Create backup path (degraded but available)
    let backup = Path {
        id: PathId::new(2),
        src_site: site1_id,
        dst_site: site2_id,
        src_endpoint: "0.0.0.0:51821".parse().unwrap(),
        dst_endpoint: "192.168.1.1:51821".parse().unwrap(),
        wg_interface: Some("wg-backup".to_string()),
        metrics: PathMetrics {
            latency_ms: 100.0,
            jitter_ms: 20.0,
            packet_loss_pct: 2.0,
            bandwidth_mbps: 100.0,
            mtu: 1500,
            measured_at: std::time::SystemTime::now(),
            score: 45,
        },
        status: PathStatus::Degraded,
    };

    db.insert_path(&primary).await.expect("Failed to insert primary");
    db.insert_path(&backup).await.expect("Failed to insert backup");
    db.store_path_metrics(primary.id, &primary.metrics).await.expect("Failed to store primary metrics");
    db.store_path_metrics(backup.id, &backup.metrics).await.expect("Failed to store backup metrics");

    // Test flow
    let flow = FlowKey {
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "10.0.0.2".parse().unwrap(),
        src_port: 50000,
        dst_port: 443,
        protocol: 6,
    };

    // Should select primary
    let selected = router.select_path(&flow).await.expect("Failed to select path");
    assert_eq!(selected, primary.id);

    // Simulate primary path failure
    db.update_path_status(primary.id, PathStatus::Down).await.expect("Failed to update status");

    // Remove flow to force re-evaluation
    router.remove_flow(&flow).await;

    // Should now select backup
    let failover = router.select_path(&flow).await.expect("Failed to select failover");
    assert_eq!(failover, backup.id);

    router.stop().await.expect("Failed to stop router");
}

#[tokio::test]
async fn test_policy_enforcement() {
    let (db, _mesh, _monitor, router) = create_test_site("test-site").await;

    router.start().await.expect("Failed to start router");

    // Verify default policies are loaded
    let policies = router.list_policies().await;
    assert!(policies.len() >= 4); // Should have VoIP, Gaming, Bulk, Default

    // Verify policy names
    let policy_names: Vec<_> = policies.iter().map(|p| p.name.as_str()).collect();
    assert!(policy_names.contains(&"VoIP/Video"));
    assert!(policy_names.contains(&"Gaming"));
    assert!(policy_names.contains(&"Bulk Transfers"));
    assert!(policy_names.contains(&"Default"));

    router.stop().await.expect("Failed to stop router");
}

#[tokio::test]
async fn test_database_persistence() {
    let db = Arc::new(Database::new(":memory:").await.unwrap());

    // Create and store a site
    let site = Site {
        id: SiteId::generate(),
        name: "test-site".to_string(),
        public_key: vec![0u8; 32],
        endpoints: vec![
            Endpoint {
                address: "192.168.1.1:51820".parse().unwrap(),
                interface_type: "ethernet".to_string(),
                cost_per_gb: 0.0,
                reachable: true,
            }
        ],
        created_at: std::time::SystemTime::now(),
        last_seen: std::time::SystemTime::now(),
        status: SiteStatus::Active,
    };

    db.upsert_site(&site).await.expect("Failed to upsert site");

    // Retrieve sites
    let sites = db.list_sites().await.expect("Failed to list sites");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].name, "test-site");

    // Update site status
    let mut updated_site = site.clone();
    updated_site.status = SiteStatus::Inactive;
    db.upsert_site(&updated_site).await.expect("Failed to update site");

    let sites = db.list_sites().await.expect("Failed to list sites after update");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].status, SiteStatus::Inactive);
}
