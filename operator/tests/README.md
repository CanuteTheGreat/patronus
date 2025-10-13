# Patronus Operator Integration Tests

This directory contains integration tests for the Patronus Kubernetes Operator.

## Test Organization

- `site_lifecycle_test.rs` - Site CRD create/update/delete lifecycle tests
- `policy_lifecycle_test.rs` - Policy CRD lifecycle and priority tests
- `health_check_test.rs` - Health check endpoint E2E tests

## Running Tests

### Unit Tests

Run the standard unit tests (no external dependencies):

```bash
cargo test -p patronus-operator
```

### Integration Tests

Integration tests require a running Kubernetes cluster and/or operator instance.

#### Site and Policy Lifecycle Tests

These tests require:
- A running Kubernetes cluster (kind, minikube, or real cluster)
- kubectl configured to access the cluster
- CRDs installed (`make install` from operator directory)

```bash
# Run all integration tests (requires Kubernetes)
cargo test -p patronus-operator --test site_lifecycle_test -- --ignored
cargo test -p patronus-operator --test policy_lifecycle_test -- --ignored
```

#### Health Check Tests

These tests require:
- A running instance of the operator
- Operator listening on http://localhost:8081 for health checks

```bash
# Start the operator in another terminal
cargo run -p patronus-operator

# Run health check tests
cargo test -p patronus-operator --test health_check_test -- --ignored
```

### Running All Tests

```bash
# Run all tests including integration tests
cargo test -p patronus-operator -- --ignored
```

## Test Setup

### Local Kubernetes Cluster

For local development, we recommend using `kind` (Kubernetes in Docker):

```bash
# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create cluster
kind create cluster --name patronus-test

# Install CRDs
cd operator
make install

# Run tests
cargo test --test site_lifecycle_test -- --ignored
```

### CI/CD

Integration tests are run automatically in GitHub Actions CI/CD pipeline:

- Unit tests run on every PR and push
- Integration tests run in a kind cluster
- Health check tests validate operator startup

See `.github/workflows/ci.yml` for the full CI configuration.

## Writing New Tests

### Integration Test Structure

Integration tests use `#[ignore]` attribute to prevent them from running during normal `cargo test`:

```rust
#[tokio::test]
#[ignore] // Requires Kubernetes cluster
async fn test_my_feature() {
    let client = Client::try_default().await
        .expect("Failed to create client");

    // Test code here
}
```

### Best Practices

1. **Cleanup**: Always clean up resources in tests (even if tests fail)
2. **Isolation**: Use unique names for test resources to avoid conflicts
3. **Timeouts**: Add reasonable timeouts for async operations
4. **Assertions**: Use descriptive assertion messages
5. **Documentation**: Document test requirements in comments

## Troubleshooting

### "Failed to create client"

Ensure kubectl is configured and can access a Kubernetes cluster:

```bash
kubectl cluster-info
kubectl get nodes
```

### "Failed to connect to health endpoint"

Ensure the operator is running:

```bash
# Check if operator is running
ps aux | grep patronus-operator

# Check health endpoint directly
curl http://localhost:8081/healthz
```

### CRD Not Found

Install the CRDs:

```bash
cd operator
make crdgen
make install
```

## Mock API Server

The `integration/mock_api.rs` module provides a mock Patronus API server for testing operator behavior without a real backend:

```rust
use patronus_operator::tests::integration::mock_api::MockApiServer;

let mock_api = MockApiServer::new(9999);
let state = mock_api.state();

// Run mock API in background
tokio::spawn(async move {
    mock_api.run().await.unwrap();
});

// Run tests against mock API
// ...

// Verify state
assert!(state.site_exists("test-site"));
```
