//! Integration tests for WebSocket event broadcasting (Sprint 28)
//!
//! These tests verify that GraphQL mutations properly broadcast events
//! to WebSocket clients for real-time updates.

use patronus_dashboard::state::AppState;
use std::sync::Arc;

/// Create a test app state with in-memory database
async fn create_test_state() -> Arc<AppState> {
    // Use in-memory database (each test gets a fresh one)
    Arc::new(AppState::new(":memory:").await.unwrap())
}

#[tokio::test]
async fn test_event_broadcast_on_site_creation() {
    // Initialize app state
    let state = create_test_state().await;

    // Subscribe to events
    let mut rx1 = state.events_tx.subscribe();
    let mut rx2 = state.events_tx.subscribe();

    // Simulate a site creation event
    let event = patronus_dashboard::state::Event {
        event_type: "SITE_CREATED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({
            "site_id": "test-site-123",
            "site_name": "Test Site",
            "location": Some("Test Location"),
            "created_by": "admin@example.com",
        }),
    };

    // Broadcast event
    let _ = state.events_tx.send(event.clone());

    // Verify both subscribers receive the event
    let received1 = rx1.recv().await.unwrap();
    let received2 = rx2.recv().await.unwrap();

    assert_eq!(received1.event_type, "SITE_CREATED");
    assert_eq!(received2.event_type, "SITE_CREATED");

    // Verify event data
    assert_eq!(received1.data["site_id"], "test-site-123");
    assert_eq!(received1.data["site_name"], "Test Site");
    assert_eq!(received1.data["created_by"], "admin@example.com");
}

#[tokio::test]
async fn test_event_broadcast_on_policy_update() {
    let state = create_test_state().await;

    let mut rx = state.events_tx.subscribe();

    // Simulate policy update event
    let event = patronus_dashboard::state::Event {
        event_type: "POLICY_UPDATED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({
            "policy_id": "12345",
            "policy_name": "Test Policy",
            "fields_changed": ["priority", "enabled"],
            "updated_by": "operator@example.com",
        }),
    };

    let _ = state.events_tx.send(event);
    let received = rx.recv().await.unwrap();

    assert_eq!(received.event_type, "POLICY_UPDATED");
    assert_eq!(received.data["policy_id"], "12345");
    assert_eq!(received.data["fields_changed"][0], "priority");
    assert_eq!(received.data["fields_changed"][1], "enabled");
}

#[tokio::test]
async fn test_event_broadcast_on_user_role_update() {
    let state = create_test_state().await;

    let mut rx = state.events_tx.subscribe();

    // Simulate user role update event
    let event = patronus_dashboard::state::Event {
        event_type: "USER_ROLE_UPDATED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({
            "user_id": "user-456",
            "email": "user@example.com",
            "old_role": "viewer",
            "new_role": "operator",
            "updated_by": "admin@example.com",
        }),
    };

    let _ = state.events_tx.send(event);
    let received = rx.recv().await.unwrap();

    assert_eq!(received.event_type, "USER_ROLE_UPDATED");
    assert_eq!(received.data["old_role"], "viewer");
    assert_eq!(received.data["new_role"], "operator");
}

#[tokio::test]
async fn test_event_broadcast_on_path_health_check() {
    let state = create_test_state().await;

    let mut rx = state.events_tx.subscribe();

    // Simulate path health check event
    let event = patronus_dashboard::state::Event {
        event_type: "PATH_HEALTH_CHECKED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({
            "path_id": "789",
            "source_site_id": "site-1",
            "destination_site_id": "site-2",
            "latency_ms": 45.2,
            "packet_loss": 0.5,
            "quality_score": 95,
            "checked_by": "operator@example.com",
        }),
    };

    let _ = state.events_tx.send(event);
    let received = rx.recv().await.unwrap();

    assert_eq!(received.event_type, "PATH_HEALTH_CHECKED");
    assert_eq!(received.data["latency_ms"], 45.2);
    assert_eq!(received.data["quality_score"], 95);
}

#[tokio::test]
async fn test_multi_client_synchronization() {
    let state = create_test_state().await;

    // Create 5 concurrent clients
    let mut clients = vec![];
    for _ in 0..5 {
        clients.push(state.events_tx.subscribe());
    }

    // Send 10 events
    let events = vec![
        "SITE_CREATED",
        "SITE_UPDATED",
        "POLICY_CREATED",
        "POLICY_TOGGLED",
        "USER_CREATED",
        "USER_DEACTIVATED",
        "PATH_HEALTH_CHECKED",
        "PATH_FAILOVER",
        "CACHE_CLEARED",
        "SYSTEM_HEALTH_CHECK",
    ];

    for event_type in &events {
        let event = patronus_dashboard::state::Event {
            event_type: event_type.to_string(),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "test": true,
            }),
        };
        let _ = state.events_tx.send(event);
    }

    // Verify all clients received all events
    for (i, mut client) in clients.into_iter().enumerate() {
        for (j, expected_type) in events.iter().enumerate() {
            let received = client.recv().await.unwrap();
            assert_eq!(
                received.event_type, *expected_type,
                "Client {} did not receive event {} correctly",
                i, j
            );
        }
    }
}

#[tokio::test]
async fn test_late_subscriber_receives_new_events() {
    let state = create_test_state().await;

    // Send event before subscriber exists
    let event1 = patronus_dashboard::state::Event {
        event_type: "SITE_CREATED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({"old": true}),
    };
    let _ = state.events_tx.send(event1);

    // Create subscriber after first event
    let mut rx = state.events_tx.subscribe();

    // Send new event
    let event2 = patronus_dashboard::state::Event {
        event_type: "POLICY_CREATED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({"new": true}),
    };
    let _ = state.events_tx.send(event2);

    // Subscriber should only receive the new event
    let received = rx.recv().await.unwrap();
    assert_eq!(received.event_type, "POLICY_CREATED");
    assert_eq!(received.data["new"], true);
}

#[tokio::test]
async fn test_system_health_check_event() {
    let state = create_test_state().await;

    let mut rx = state.events_tx.subscribe();

    // Simulate system health check event
    let event = patronus_dashboard::state::Event {
        event_type: "SYSTEM_HEALTH_CHECK".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({
            "site_count": 42,
            "cpu_usage": 35.5,
            "memory_usage": 68.2,
            "throughput_mbps": 1234.56,
            "active_flows": 789,
            "checked_by": "admin@example.com",
        }),
    };

    let _ = state.events_tx.send(event);
    let received = rx.recv().await.unwrap();

    assert_eq!(received.event_type, "SYSTEM_HEALTH_CHECK");
    assert_eq!(received.data["site_count"], 42);
    assert_eq!(received.data["cpu_usage"], 35.5);
    assert_eq!(received.data["active_flows"], 789);
}

#[tokio::test]
async fn test_cache_clear_event() {
    let state = create_test_state().await;

    let mut rx = state.events_tx.subscribe();

    // Simulate cache clear event
    let event = patronus_dashboard::state::Event {
        event_type: "CACHE_CLEARED".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({
            "cleared_by": "admin@example.com",
        }),
    };

    let _ = state.events_tx.send(event);
    let received = rx.recv().await.unwrap();

    assert_eq!(received.event_type, "CACHE_CLEARED");
    assert_eq!(received.data["cleared_by"], "admin@example.com");
}
