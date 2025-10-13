# Patronus SD-WAN Kubernetes Operator

**Version**: 1.0.0
**Kubernetes Version**: 1.25+

---

## Overview

The Patronus SD-WAN Kubernetes Operator provides automated deployment, configuration, and lifecycle management of Patronus SD-WAN in Kubernetes clusters.

### Features

- **Automated Deployment**: Deploy SD-WAN infrastructure using Kubernetes custom resources
- **Lifecycle Management**: Handle creation, updates, and deletion of SD-WAN components
- **Self-Healing**: Automatically recover from failures
- **Scaling**: Horizontal and vertical scaling support
- **Configuration Management**: Declarative configuration via CRDs
- **Status Reporting**: Real-time status updates for all resources
- **Event Recording**: Kubernetes events for operational visibility

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Kubernetes Cluster                      │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │         Patronus Operator Controller            │   │
│  │                                                   │   │
│  │  ┌──────────────┐         ┌──────────────┐      │   │
│  │  │ Site         │         │ Policy       │      │   │
│  │  │ Controller   │         │ Controller   │      │   │
│  │  └──────────────┘         └──────────────┘      │   │
│  │                                                   │   │
│  │  ┌──────────────┐         ┌──────────────┐      │   │
│  │  │ Path         │         │ Mesh         │      │   │
│  │  │ Controller   │         │ Controller   │      │   │
│  │  └──────────────┘         └──────────────┘      │   │
│  └─────────────────────────────────────────────────┘   │
│                        │                                │
│                        ▼                                │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Custom Resources (CRDs)             │   │
│  │  • Site         • Path                           │   │
│  │  • Policy       • Mesh                           │   │
│  └─────────────────────────────────────────────────┘   │
│                        │                                │
│                        ▼                                │
│  ┌─────────────────────────────────────────────────┐   │
│  │          Patronus SD-WAN Workloads               │   │
│  │                                                   │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐      │   │
│  │  │ SD-WAN   │  │Dashboard │  │Prometheus│      │   │
│  │  │ Core     │  │   UI     │  │ Exporter │      │   │
│  │  └──────────┘  └──────────┘  └──────────┘      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## Custom Resource Definitions (CRDs)

### Site

Represents a network site in the SD-WAN mesh.

```yaml
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Site
metadata:
  name: branch-nyc
  namespace: patronus-system
spec:
  location: "New York, NY"

  wireguard:
    publicKey: "base64-encoded-key"
    listenPort: 51820
    endpoints:
      - "203.0.113.100:51820"

  resources:
    cpu: "2"
    memory: "4Gi"
    storage: "10Gi"

  mesh:
    enabled: true
    peerWith:
      - branch-sf
      - branch-sea

status:
  phase: Active | Pending | Failed
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2025-10-12T10:00:00Z"

  peers: 2
  activePaths: 5
  healthScore: 98.5
```

### Policy

Defines routing and traffic management policies.

```yaml
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Policy
metadata:
  name: video-priority
  namespace: patronus-system
spec:
  priority: 100

  match:
    protocol: udp
    dstPortRange: "3478-3497"
    dscp: 46

  action:
    type: route
    primaryPath:
      siteRef: branch-nyc
      pathId: path-fiber
    backupPath:
      siteRef: branch-nyc
      pathId: path-lte

    qos:
      class: realtime
      bandwidth: "10Mbps"

  failover:
    threshold: 70
    cooldown: 30s

status:
  active: true
  matchedFlows: 1523
  bytesRouted: 523458912
```

### Path

Represents a network path between sites.

```yaml
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Path
metadata:
  name: nyc-to-sf
  namespace: patronus-system
spec:
  source:
    siteRef: branch-nyc
  destination:
    siteRef: branch-sf

  type: direct | vpn

  monitoring:
    enabled: true
    interval: 10s
    probesPerCheck: 5

status:
  state: up | down | degraded
  health:
    latencyMs: 45.2
    jitterMs: 2.1
    packetLossPct: 0.01
    healthScore: 98.5

  lastChecked: "2025-10-12T10:00:00Z"
```

### Mesh

Defines mesh networking configuration.

```yaml
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Mesh
metadata:
  name: production-mesh
  namespace: patronus-system
spec:
  sites:
    - branch-nyc
    - branch-sf
    - branch-sea

  topology: full-mesh | hub-spoke

  vpn:
    protocol: wireguard
    encryption: chacha20-poly1305

status:
  totalSites: 3
  activePaths: 6
  overallHealth: 97.8
```

---

## Installation

### Prerequisites

- Kubernetes cluster (1.25+)
- kubectl configured
- Helm 3.x (for Helm installation)

### Option 1: Install with Helm

```bash
# Add Patronus Helm repository
helm repo add patronus https://patronus.github.io/helm-charts
helm repo update

# Install operator
helm install patronus-operator patronus/patronus-operator \
  --namespace patronus-system \
  --create-namespace

# Verify installation
kubectl get pods -n patronus-system
```

### Option 2: Install with kubectl

```bash
# Install CRDs
kubectl apply -f https://raw.githubusercontent.com/patronus/patronus/main/operator/crds/

# Install operator
kubectl apply -f https://raw.githubusercontent.com/patronus/patronus/main/operator/deploy/

# Verify installation
kubectl get pods -n patronus-system
```

### Option 3: Build from source

```bash
# Clone repository
git clone https://github.com/patronus/patronus.git
cd patronus/operator

# Build operator image
docker build -t patronus-operator:latest .

# Deploy to cluster
kubectl apply -f crds/
kubectl apply -f deploy/
```

---

## Quick Start

### 1. Create a Site

```yaml
kubectl apply -f - <<EOF
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Site
metadata:
  name: my-site
  namespace: patronus-system
spec:
  location: "My Location"
  wireguard:
    publicKey: "$(wg genkey | wg pubkey)"
    listenPort: 51820
    endpoints:
      - "203.0.113.1:51820"
  resources:
    cpu: "2"
    memory: "4Gi"
  mesh:
    enabled: true
EOF
```

### 2. Check Site Status

```bash
kubectl get sites -n patronus-system
kubectl describe site my-site -n patronus-system
```

### 3. Create a Policy

```yaml
kubectl apply -f - <<EOF
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Policy
metadata:
  name: http-traffic
  namespace: patronus-system
spec:
  priority: 50
  match:
    protocol: tcp
    dstPortRange: "80,443"
  action:
    type: route
    qos:
      class: business-critical
EOF
```

### 4. Create a Mesh

```yaml
kubectl apply -f - <<EOF
apiVersion: sdwan.patronus.dev/v1alpha1
kind: Mesh
metadata:
  name: my-mesh
  namespace: patronus-system
spec:
  sites:
    - my-site
    - another-site
  topology: full-mesh
EOF
```

---

## Configuration

### Operator Configuration

The operator can be configured via environment variables or ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: patronus-operator-config
  namespace: patronus-system
data:
  # Reconciliation settings
  RECONCILE_INTERVAL: "30s"
  MAX_CONCURRENT_RECONCILES: "5"

  # Resource limits
  DEFAULT_CPU_REQUEST: "1"
  DEFAULT_MEMORY_REQUEST: "2Gi"

  # Monitoring
  METRICS_PORT: "8080"
  HEALTH_PROBE_PORT: "8081"
```

### Leader Election

The operator supports leader election for high availability:

```yaml
spec:
  replicas: 3
  leaderElection:
    enabled: true
    leaseDuration: 15s
    renewDeadline: 10s
    retryPeriod: 2s
```

---

## Monitoring

### Metrics

The operator exposes Prometheus metrics on `:8080/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `patronus_operator_reconcile_total` | Counter | Total reconciliations |
| `patronus_operator_reconcile_errors_total` | Counter | Reconciliation errors |
| `patronus_operator_reconcile_duration_seconds` | Histogram | Reconciliation duration |
| `patronus_operator_sites_total` | Gauge | Total sites |
| `patronus_operator_policies_total` | Gauge | Total policies |
| `patronus_operator_paths_total` | Gauge | Total paths |

### Health Probes

- **Liveness**: `GET :8081/healthz`
- **Readiness**: `GET :8081/ready`

---

## Troubleshooting

### Operator not starting

```bash
# Check operator logs
kubectl logs -n patronus-system -l app=patronus-operator

# Check RBAC permissions
kubectl auth can-i create sites.sdwan.patronus.dev --as=system:serviceaccount:patronus-system:patronus-operator
```

### Resources not reconciling

```bash
# Check operator logs
kubectl logs -n patronus-system -l app=patronus-operator --tail=100

# Check resource events
kubectl describe site <site-name> -n patronus-system

# Check operator status
kubectl get deployment patronus-operator -n patronus-system
```

### CRD installation issues

```bash
# Verify CRDs are installed
kubectl get crds | grep sdwan.patronus.dev

# Reinstall CRDs
kubectl apply -f https://raw.githubusercontent.com/patronus/patronus/main/operator/crds/
```

---

## Development

### Building the Operator

```bash
# Install dependencies
cargo build

# Run tests
cargo test

# Build release
cargo build --release

# Build Docker image
docker build -t patronus-operator:dev .
```

### Running Locally

```bash
# Set KUBECONFIG
export KUBECONFIG=~/.kube/config

# Run operator
cargo run

# Or with logging
RUST_LOG=debug cargo run
```

### Testing

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test '*'

# E2E tests (requires cluster)
./scripts/e2e-tests.sh
```

---

## Upgrading

### Upgrade Operator

```bash
# With Helm
helm upgrade patronus-operator patronus/patronus-operator \
  --namespace patronus-system

# With kubectl
kubectl apply -f https://raw.githubusercontent.com/patronus/patronus/main/operator/deploy/
```

### Upgrade CRDs

```bash
# Upgrade CRDs
kubectl apply -f https://raw.githubusercontent.com/patronus/patronus/main/operator/crds/

# Note: Existing resources are preserved
```

---

## Uninstallation

```bash
# Delete resources
kubectl delete sites --all -n patronus-system
kubectl delete policies --all -n patronus-system
kubectl delete paths --all -n patronus-system
kubectl delete meshes --all -n patronus-system

# Uninstall operator
helm uninstall patronus-operator -n patronus-system

# Delete CRDs (optional, will delete all custom resources)
kubectl delete crd sites.sdwan.patronus.dev
kubectl delete crd policies.sdwan.patronus.dev
kubectl delete crd paths.sdwan.patronus.dev
kubectl delete crd meshes.sdwan.patronus.dev

# Delete namespace
kubectl delete namespace patronus-system
```

---

## Examples

See [examples/](examples/) directory for more examples:

- [Simple site deployment](examples/simple-site.yaml)
- [Multi-site mesh](examples/multi-site-mesh.yaml)
- [Complex policy](examples/complex-policy.yaml)
- [Production setup](examples/production.yaml)

---

## API Reference

Full API reference available at:
- [API Documentation](https://docs.patronus.dev/operator/api)
- [CRD Schemas](crds/)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

---

## Support

- **Documentation**: https://docs.patronus.dev
- **Issues**: https://github.com/patronus/patronus/issues
- **Discussions**: https://github.com/patronus/patronus/discussions
- **Slack**: https://patronus-dev.slack.com

---

## License

See [LICENSE](../LICENSE) for details.

---

**Operator Version**: 1.0.0
**Last Updated**: 2025-10-12
**Maintainer**: Patronus Team
