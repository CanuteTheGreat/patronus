//! Integration tests for health check endpoints

use reqwest::Client;
use std::time::Duration;

const HEALTH_BASE_URL: &str = "http://localhost:8081";

/// Test liveness endpoint
#[tokio::test]
#[ignore] // Requires running operator
async fn test_liveness_endpoint() {
    let client = Client::new();

    // Test /healthz
    let response = client
        .get(&format!("{}/healthz", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to health endpoint");

    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("Failed to read body");
    assert!(body.contains("OK") || body.contains("Alive"));

    // Test /health (alias)
    let response = client
        .get(&format!("{}/health", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to health endpoint");

    assert_eq!(response.status(), 200);
}

/// Test readiness endpoint
#[tokio::test]
#[ignore] // Requires running operator
async fn test_readiness_endpoint() {
    let client = Client::new();

    // Test /readyz
    let response = client
        .get(&format!("{}/readyz", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to readiness endpoint");

    // Should be 200 (ready) or 503 (not ready)
    assert!(response.status() == 200 || response.status() == 503);

    // Test /ready (alias)
    let response = client
        .get(&format!("{}/ready", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to readiness endpoint");

    assert!(response.status() == 200 || response.status() == 503);
}

/// Test alive endpoint
#[tokio::test]
#[ignore] // Requires running operator
async fn test_alive_endpoint() {
    let client = Client::new();

    // Test /livez
    let response = client
        .get(&format!("{}/livez", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to alive endpoint");

    assert_eq!(response.status(), 200);

    // Test /alive (alias)
    let response = client
        .get(&format!("{}/alive", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to alive endpoint");

    assert_eq!(response.status(), 200);
}

/// Test unknown endpoint
#[tokio::test]
#[ignore] // Requires running operator
async fn test_unknown_endpoint() {
    let client = Client::new();

    let response = client
        .get(&format!("{}/unknown", HEALTH_BASE_URL))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("Failed to connect to health server");

    assert_eq!(response.status(), 404);
}

/// Test health check response times
#[tokio::test]
#[ignore] // Requires running operator
async fn test_health_response_time() {
    let client = Client::new();

    for _ in 0..10 {
        let start = std::time::Instant::now();

        let response = client
            .get(&format!("{}/healthz", HEALTH_BASE_URL))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("Failed to connect to health endpoint");

        let elapsed = start.elapsed();

        assert_eq!(response.status(), 200);
        // Health checks should be fast (< 100ms)
        assert!(elapsed.as_millis() < 100, "Health check took {}ms", elapsed.as_millis());
    }
}

/// Test concurrent health checks
#[tokio::test]
#[ignore] // Requires running operator
async fn test_concurrent_health_checks() {
    let mut handles = vec![];

    for _ in 0..20 {
        let handle = tokio::spawn(async {
            let client = Client::new();
            let response = client
                .get(&format!("{}/healthz", HEALTH_BASE_URL))
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .expect("Failed to connect to health endpoint");

            assert_eq!(response.status(), 200);
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await.expect("Task panicked");
    }
}
