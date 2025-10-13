//! Integration tests for Site CRD lifecycle

use k8s_openapi::api::core::v1::Namespace;
use kube::{
    api::{Api, DeleteParams, PostParams},
    Client, ResourceExt,
};
use patronus_operator::crd::site::{Site, SiteSpec, WireGuardConfig};

/// Test Site creation
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_site_creation() {
    let client = Client::try_default().await.expect("Failed to create client");

    // Create test namespace
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let test_ns = Namespace {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test-operator".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let _ = namespaces.create(&PostParams::default(), &test_ns).await;

    // Create Site API
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create test site
    let site = Site::new("test-site-hq", SiteSpec {
        location: Some("Test HQ".to_string()),
        wireguard: WireGuardConfig {
            public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
            listen_port: 51820,
            endpoints: vec!["203.0.113.1:51820".to_string()],
        },
        resources: None,
        mesh: None,
    });

    // Apply the site
    let created = sites.create(&PostParams::default(), &site).await
        .expect("Failed to create site");

    assert_eq!(created.name_any(), "test-site-hq");

    // Verify site exists
    let fetched = sites.get("test-site-hq").await
        .expect("Failed to get site");

    assert_eq!(fetched.name_any(), "test-site-hq");
    assert_eq!(fetched.spec.location, Some("Test HQ".to_string()));
    assert_eq!(fetched.spec.wireguard.listen_port, 51820);

    // Cleanup
    let _ = sites.delete("test-site-hq", &DeleteParams::default()).await;
}

/// Test Site update
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_site_update() {
    let client = Client::try_default().await.expect("Failed to create client");
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create initial site
    let mut site = Site::new("test-site-update", SiteSpec {
        location: Some("Original Location".to_string()),
        wireguard: WireGuardConfig {
            public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
            listen_port: 51821,
            endpoints: vec!["203.0.113.2:51821".to_string()],
        },
        resources: None,
        mesh: None,
    });

    let created = sites.create(&PostParams::default(), &site).await
        .expect("Failed to create site");

    // Update the site
    site.spec.location = Some("Updated Location".to_string());
    site.metadata.resource_version = created.metadata.resource_version;

    let updated = sites.replace("test-site-update", &PostParams::default(), &site).await
        .expect("Failed to update site");

    assert_eq!(updated.spec.location, Some("Updated Location".to_string()));

    // Cleanup
    let _ = sites.delete("test-site-update", &DeleteParams::default()).await;
}

/// Test Site deletion
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_site_deletion() {
    let client = Client::try_default().await.expect("Failed to create client");
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create site
    let site = Site::new("test-site-delete", SiteSpec {
        location: Some("To Be Deleted".to_string()),
        wireguard: WireGuardConfig {
            public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
            listen_port: 51822,
            endpoints: vec!["203.0.113.3:51822".to_string()],
        },
        resources: None,
        mesh: None,
    });

    sites.create(&PostParams::default(), &site).await
        .expect("Failed to create site");

    // Delete the site
    sites.delete("test-site-delete", &DeleteParams::default()).await
        .expect("Failed to delete site");

    // Wait a bit for deletion
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify site is gone
    let result = sites.get("test-site-delete").await;
    assert!(result.is_err());
}

/// Test multiple sites
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_multiple_sites() {
    let client = Client::try_default().await.expect("Failed to create client");
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create multiple sites
    for i in 1..=3 {
        let site = Site::new(&format!("test-site-{}", i), SiteSpec {
            location: Some(format!("Location {}", i)),
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51820 + i,
                endpoints: vec![format!("203.0.113.{}:51820", i)],
            },
            resources: None,
            mesh: None,
        });

        sites.create(&PostParams::default(), &site).await
            .expect("Failed to create site");
    }

    // List sites
    let site_list = sites.list(&Default::default()).await
        .expect("Failed to list sites");

    assert!(site_list.items.len() >= 3);

    // Cleanup
    for i in 1..=3 {
        let _ = sites.delete(&format!("test-site-{}", i), &DeleteParams::default()).await;
    }
}
