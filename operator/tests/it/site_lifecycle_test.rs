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
    let client = Client::try_default()
        .await
        .expect("Failed to create client");

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
    let site = Site::new(
        "test-site-hq",
        SiteSpec {
            location: Some("Test HQ".to_string()),
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51820,
                endpoints: vec!["203.0.113.1:51820".to_string()],
            },
            resources: None,
            mesh: None,
        },
    );

    // Apply the site
    let created = sites
        .create(&PostParams::default(), &site)
        .await
        .expect("Failed to create site");

    assert_eq!(created.name_any(), "test-site-hq");

    // Verify site exists
    let fetched = sites.get("test-site-hq").await.expect("Failed to get site");

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
    let client = Client::try_default()
        .await
        .expect("Failed to create client");
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create initial site
    let site = Site::new(
        "test-site-update",
        SiteSpec {
            location: Some("Original Location".to_string()),
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51821,
                endpoints: vec!["203.0.113.2:51821".to_string()],
            },
            resources: None,
            mesh: None,
        },
    );

    let _created = sites
        .create(&PostParams::default(), &site)
        .await
        .expect("Failed to create site");

    // Update the site. The operator reconciles the new object right away
    // (finalizer, status), bumping its resourceVersion, so a replace based
    // on the create response can lose with 409 Conflict (run 4449): do
    // what every kube client does -- re-read and retry on conflict.
    let mut updated = None;
    for _ in 0..10 {
        let mut latest = sites
            .get("test-site-update")
            .await
            .expect("Failed to read site");
        latest.spec.location = Some("Updated Location".to_string());
        match sites
            .replace("test-site-update", &PostParams::default(), &latest)
            .await
        {
            Ok(s) => {
                updated = Some(s);
                break;
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => panic!("Failed to update site: {e:?}"),
        }
    }
    let updated = updated.expect("site update kept conflicting");

    assert_eq!(updated.spec.location, Some("Updated Location".to_string()));

    // Cleanup
    let _ = sites
        .delete("test-site-update", &DeleteParams::default())
        .await;
}

/// Test Site deletion
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_site_deletion() {
    let client = Client::try_default()
        .await
        .expect("Failed to create client");
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create site
    let site = Site::new(
        "test-site-delete",
        SiteSpec {
            location: Some("To Be Deleted".to_string()),
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51822,
                endpoints: vec!["203.0.113.3:51822".to_string()],
            },
            resources: None,
            mesh: None,
        },
    );

    sites
        .create(&PostParams::default(), &site)
        .await
        .expect("Failed to create site");

    // Delete the site
    sites
        .delete("test-site-delete", &DeleteParams::default())
        .await
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
    let client = Client::try_default()
        .await
        .expect("Failed to create client");
    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");

    // Create multiple sites
    for i in 1..=3 {
        let site = Site::new(
            &format!("test-site-{}", i),
            SiteSpec {
                location: Some(format!("Location {}", i)),
                wireguard: WireGuardConfig {
                    public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                    listen_port: 51820 + i,
                    endpoints: vec![format!("203.0.113.{}:51820", i)],
                },
                resources: None,
                mesh: None,
            },
        );

        sites
            .create(&PostParams::default(), &site)
            .await
            .expect("Failed to create site");
    }

    // List sites
    let want: Vec<String> = (1..=3).map(|i| format!("test-site-{}", i)).collect();
    let site_list = crate::list_until_present(&sites, &want).await;

    let names: Vec<String> = site_list.iter().map(|s| s.name_any()).collect();
    for i in 1..=3 {
        assert!(
            names.contains(&format!("test-site-{}", i)),
            "test-site-{} missing from the site list: {:?}",
            i,
            names
        );
    }

    // Cleanup
    for i in 1..=3 {
        let _ = sites
            .delete(&format!("test-site-{}", i), &DeleteParams::default())
            .await;
    }
}

/// The operator must settle: once a Site's status says what the last
/// reconcile found, nothing more is written. Rewriting the status (with a
/// fresh lastTransitionTime) on every reconcile re-triggered the controller's
/// own watch, so every Site was reconciled -- and the Patronus API called --
/// every few milliseconds, forever.
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_site_status_settles() {
    let client = Client::try_default()
        .await
        .expect("Failed to create client");

    let namespaces: Api<Namespace> = Api::all(client.clone());
    let test_ns = Namespace {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test-operator".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = namespaces.create(&PostParams::default(), &test_ns).await;

    let sites: Api<Site> = Api::namespaced(client.clone(), "test-operator");
    let site = Site::new(
        "test-site-settle",
        SiteSpec {
            location: Some("Settle".to_string()),
            wireguard: WireGuardConfig {
                public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                listen_port: 51830,
                endpoints: vec!["203.0.113.30:51830".to_string()],
            },
            resources: None,
            mesh: None,
        },
    );
    sites
        .create(&PostParams::default(), &site)
        .await
        .expect("Failed to create site");

    // Wait for the operator's first status write.
    let mut reconciled = false;
    for _ in 0..60 {
        let s = sites
            .get("test-site-settle")
            .await
            .expect("Failed to get site");
        if s.status.as_ref().and_then(|st| st.phase.as_ref()).is_some() {
            reconciled = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(
        reconciled,
        "operator never wrote a status for test-site-settle"
    );

    // Give any follow-up reconcile (triggered by that status write) time to
    // run, then the object must stay put.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let before = sites
        .get("test-site-settle")
        .await
        .expect("Failed to get site");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let after = sites
        .get("test-site-settle")
        .await
        .expect("Failed to get site");

    let _ = sites
        .delete("test-site-settle", &DeleteParams::default())
        .await;

    assert_eq!(
        before.resource_version(),
        after.resource_version(),
        "Site status keeps being rewritten with nothing changed (status before: {:?}, after: {:?})",
        before.status,
        after.status
    );
}
