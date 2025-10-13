# Patronus Operator Helm Chart

This Helm chart deploys the Patronus SD-WAN Kubernetes Operator.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.0+

## Installing the Chart

```bash
# Add the repository (if published)
helm repo add patronus https://patronus.github.io/helm-charts
helm repo update

# Install the chart
helm install patronus-operator patronus/patronus-operator \
  --namespace patronus-system \
  --create-namespace
```

Or install from local chart:

```bash
helm install patronus-operator ./helm/patronus-operator \
  --namespace patronus-system \
  --create-namespace
```

## Configuration

The following table lists the configurable parameters of the Patronus Operator chart:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of operator replicas | `1` |
| `image.repository` | Operator image repository | `patronus/operator` |
| `image.tag` | Operator image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `patronus.apiUrl` | Patronus API endpoint | `http://patronus-api:8081` |
| `metrics.enabled` | Enable Prometheus metrics | `true` |
| `metrics.port` | Metrics port | `8080` |
| `leaderElection.enabled` | Enable leader election | `true` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

## Uninstalling the Chart

```bash
helm uninstall patronus-operator --namespace patronus-system
```

## Examples

### Basic Installation

```bash
helm install patronus-operator ./helm/patronus-operator \
  --namespace patronus-system \
  --create-namespace
```

### Custom Patronus API URL

```bash
helm install patronus-operator ./helm/patronus-operator \
  --namespace patronus-system \
  --set patronus.apiUrl=https://patronus-api.example.com
```

### High Availability with 3 Replicas

```bash
helm install patronus-operator ./helm/patronus-operator \
  --namespace patronus-system \
  --set replicaCount=3 \
  --set leaderElection.enabled=true
```

### Custom Resource Limits

```bash
helm install patronus-operator ./helm/patronus-operator \
  --namespace patronus-system \
  --set resources.limits.cpu=1 \
  --set resources.limits.memory=1Gi
```

## Metrics

The operator exposes Prometheus metrics on port 8080 at `/metrics`.

### ServiceMonitor

If you have Prometheus Operator installed, enable ServiceMonitor:

```bash
helm install patronus-operator ./helm/patronus-operator \
  --namespace patronus-system \
  --set metrics.serviceMonitor.enabled=true
```

## Upgrading

```bash
helm upgrade patronus-operator ./helm/patronus-operator \
  --namespace patronus-system
```

## Troubleshooting

### Check operator logs

```bash
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator
```

### Check operator status

```bash
kubectl get pods -n patronus-system
kubectl describe deployment -n patronus-system patronus-operator
```

### Verify RBAC permissions

```bash
kubectl auth can-i create sites.sdwan.patronus.dev \
  --as=system:serviceaccount:patronus-system:patronus-operator
```
