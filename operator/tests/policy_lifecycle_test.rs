//! Integration tests for Policy CRD lifecycle

use k8s_openapi::api::core::v1::Namespace;
use kube::{
    api::{Api, DeleteParams, PostParams},
    Client, ResourceExt,
};
use patronus_operator::crd::policy::{
    Policy, PolicySpec, MatchCriteria, PolicyAction, ActionType, QoSConfig, QoSClass, Protocol,
};

/// Test Policy creation
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_policy_creation() {
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

    // Create Policy API
    let policies: Api<Policy> = Api::namespaced(client.clone(), "test-operator");

    // Create test policy
    let policy = Policy::new("test-policy-voip", PolicySpec {
        priority: 100,
        match_criteria: MatchCriteria {
            protocol: Some(Protocol::Udp),
            src_port_range: None,
            dst_port_range: Some("5060-5061".to_string()),
            dscp: None,
        },
        action: PolicyAction {
            type_: ActionType::Route,
            primary_path: None,
            backup_path: None,
            qos: Some(QoSConfig {
                class: QoSClass::Realtime,
                bandwidth: Some("10Mbps".to_string()),
            }),
        },
        failover: None,
    });

    // Apply the policy
    let created = policies.create(&PostParams::default(), &policy).await
        .expect("Failed to create policy");

    assert_eq!(created.name_any(), "test-policy-voip");

    // Verify policy exists
    let fetched = policies.get("test-policy-voip").await
        .expect("Failed to get policy");

    assert_eq!(fetched.name_any(), "test-policy-voip");
    assert_eq!(fetched.spec.priority, 100);
    assert_eq!(fetched.spec.match_criteria.protocol, Some(Protocol::Udp));

    // Cleanup
    let _ = policies.delete("test-policy-voip", &DeleteParams::default()).await;
}

/// Test Policy priority ordering
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_policy_priority() {
    let client = Client::try_default().await.expect("Failed to create client");
    let policies: Api<Policy> = Api::namespaced(client.clone(), "test-operator");

    // Create policies with different priorities
    let priorities = vec![100, 50, 200];

    for priority in &priorities {
        let policy = Policy::new(&format!("test-policy-pri-{}", priority), PolicySpec {
            priority: *priority,
            match_criteria: MatchCriteria {
                protocol: Some(Protocol::Tcp),
                src_port_range: None,
                dst_port_range: Some("80".to_string()),
                dscp: None,
            },
            action: PolicyAction {
                type_: ActionType::Forward,
                primary_path: None,
                backup_path: None,
                qos: None,
            },
            failover: None,
        });

        policies.create(&PostParams::default(), &policy).await
            .expect("Failed to create policy");
    }

    // List and verify priorities
    let policy_list = policies.list(&Default::default()).await
        .expect("Failed to list policies");

    let mut found_priorities: Vec<i32> = policy_list.items
        .iter()
        .filter(|p| p.name_any().starts_with("test-policy-pri-"))
        .map(|p| p.spec.priority)
        .collect();

    found_priorities.sort();
    assert_eq!(found_priorities, vec![50, 100, 200]);

    // Cleanup
    for priority in &priorities {
        let _ = policies.delete(&format!("test-policy-pri-{}", priority), &DeleteParams::default()).await;
    }
}

/// Test Policy deletion
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_policy_deletion() {
    let client = Client::try_default().await.expect("Failed to create client");
    let policies: Api<Policy> = Api::namespaced(client.clone(), "test-operator");

    // Create policy
    let policy = Policy::new("test-policy-delete", PolicySpec {
        priority: 75,
        match_criteria: MatchCriteria {
            protocol: Some(Protocol::Icmp),
            src_port_range: None,
            dst_port_range: None,
            dscp: None,
        },
        action: PolicyAction {
            type_: ActionType::Drop,
            primary_path: None,
            backup_path: None,
            qos: None,
        },
        failover: None,
    });

    policies.create(&PostParams::default(), &policy).await
        .expect("Failed to create policy");

    // Delete the policy
    policies.delete("test-policy-delete", &DeleteParams::default()).await
        .expect("Failed to delete policy");

    // Wait a bit for deletion
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify policy is gone
    let result = policies.get("test-policy-delete").await;
    assert!(result.is_err());
}
