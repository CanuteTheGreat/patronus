# Patronus Operator Operations Guide

This guide provides operational procedures for running the Patronus SD-WAN Kubernetes Operator in production.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Backup & Recovery](#backup--recovery)
- [Upgrades](#upgrades)
- [Security](#security)
- [Performance Tuning](#performance-tuning)

---

## Installation

### Prerequisites

- Kubernetes 1.28+
- Helm 3.0+
- `kubectl` configured with cluster admin access
- Patronus API endpoint accessible from cluster

### Quick Start

```bash
# Install the operator
helm install patronus-operator ./operator/helm/patronus-operator \
  --namespace patronus-system \
  --create-namespace \
  --set patronus.apiUrl=http://patronus-api:8081 \
  --set metrics.serviceMonitor.enabled=true

# Verify installation
kubectl get pods -n patronus-system
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator

# Check operator is ready
kubectl get deployment -n patronus-system patronus-operator
```

### Production Installation

```bash
# Install with HA configuration
helm install patronus-operator ./operator/helm/patronus-operator \
  --namespace patronus-system \
  --create-namespace \
  --values production-values.yaml
```

**production-values.yaml:**
```yaml
replicaCount: 3

image:
  repository: patronus/operator
  tag: "0.1.0"
  pullPolicy: IfNotPresent

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 200m
    memory: 256Mi

patronus:
  apiUrl: "https://patronus-api.production.example.com"

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s

leaderElection:
  enabled: true
  leaseDuration: 15s
  renewDeadline: 10s
  retryPeriod: 2s

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchLabels:
            app.kubernetes.io/name: patronus-operator
        topologyKey: kubernetes.io/hostname
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PATRONUS_API_URL` | Patronus API endpoint | `http://patronus-api:8081` |
| `METRICS_PORT` | Metrics server port | `8080` |
| `RUST_LOG` | Logging level | `info` |

### Helm Values

See `values.yaml` for complete configuration options.

**Key configurations:**

```yaml
# Replica count (set >1 for HA)
replicaCount: 3

# Resource limits
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

# Enable Prometheus metrics
metrics:
  enabled: true
  port: 8080
  serviceMonitor:
    enabled: true

# Leader election for HA
leaderElection:
  enabled: true
```

---

## Monitoring

### Prometheus Metrics

The operator exposes metrics on port 8080 at `/metrics`.

**Available Metrics:**

```prometheus
# Total reconciliations
patronus_operator_reconcile_total{controller="site",result="success"}

# Reconciliation errors
patronus_operator_reconcile_errors_total{controller="site",error_type="api_error"}

# Reconciliation duration
patronus_operator_reconcile_duration_seconds_bucket{controller="site",le="0.1"}

# Active resources
patronus_operator_active_resources{kind="site",phase="active"}
```

### Accessing Metrics

**Port forward:**
```bash
kubectl port-forward -n patronus-system svc/patronus-operator-metrics 8080:8080
curl http://localhost:8080/metrics
```

**ServiceMonitor (with Prometheus Operator):**
```bash
# Verify ServiceMonitor is created
kubectl get servicemonitor -n patronus-system

# Check Prometheus targets
kubectl port-forward -n monitoring svc/prometheus-k8s 9090:9090
# Navigate to http://localhost:9090/targets
```

### Grafana Dashboards

Import the Patronus Operator dashboard (ID: TBD) or create custom dashboards with these queries:

**Reconciliation Rate:**
```promql
rate(patronus_operator_reconcile_total[5m])
```

**Error Rate:**
```promql
rate(patronus_operator_reconcile_errors_total[5m])
```

**P95 Reconciliation Duration:**
```promql
histogram_quantile(0.95, rate(patronus_operator_reconcile_duration_seconds_bucket[5m]))
```

**Active Resources:**
```promql
patronus_operator_active_resources
```

### Logging

**View operator logs:**
```bash
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator -f
```

**Filter by level:**
```bash
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator | grep ERROR
```

**View specific pod:**
```bash
kubectl logs -n patronus-system patronus-operator-xxxxx-yyyyy
```

---

## Troubleshooting

### Operator Not Starting

**Symptoms:** Pods in CrashLoopBackOff or Error state

**Check:**
```bash
# Check pod status
kubectl get pods -n patronus-system

# View pod events
kubectl describe pod -n patronus-system patronus-operator-xxxxx

# Check logs
kubectl logs -n patronus-system patronus-operator-xxxxx
```

**Common causes:**
1. **Cannot connect to Kubernetes API**
   - Check RBAC permissions
   - Verify ServiceAccount exists

2. **Cannot connect to Patronus API**
   - Verify `PATRONUS_API_URL` is correct
   - Check network policies
   - Test connectivity: `kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- curl $PATRONUS_API_URL/health`

3. **Image pull failures**
   - Check `imagePullSecrets`
   - Verify image exists and is accessible

### Resources Not Reconciling

**Symptoms:** Sites or Policies stuck in Pending or Failed state

**Check:**
```bash
# Check resource status
kubectl get sites -n patronus-system
kubectl describe site <name> -n patronus-system

# Check operator logs for errors
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator | grep ERROR

# Check events
kubectl get events -n patronus-system --sort-by='.lastTimestamp'
```

**Common causes:**
1. **Validation failures**
   - Check Site/Policy spec for invalid values
   - Review validation error in status conditions

2. **API errors**
   - Check Patronus API is accessible
   - Verify API credentials (if required)
   - Check API logs for errors

3. **Controller errors**
   - Check operator logs for stack traces
   - Look for reconciliation errors in metrics

### High Reconciliation Errors

**Symptoms:** `patronus_operator_reconcile_errors_total` increasing rapidly

**Investigate:**
```bash
# Check error types in metrics
curl http://localhost:8080/metrics | grep reconcile_errors

# View recent errors in logs
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator --tail=100 | grep ERROR

# Check API connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- curl $PATRONUS_API_URL/health
```

**Resolution:**
1. Check Patronus API health
2. Verify network connectivity
3. Review resource specifications
4. Check for rate limiting

### Slow Reconciliation

**Symptoms:** High `patronus_operator_reconcile_duration_seconds`

**Investigate:**
```bash
# Check reconciliation duration
curl http://localhost:8080/metrics | grep reconcile_duration

# Check operator resource usage
kubectl top pod -n patronus-system

# Check API response times
# (Add timing logs or use API monitoring)
```

**Resolution:**
1. Increase operator resources (CPU/memory)
2. Optimize API calls
3. Check network latency
4. Review reconciliation frequency

---

## Backup & Recovery

### Backup CRDs

```bash
# Backup all Sites
kubectl get sites -A -o yaml > sites-backup.yaml

# Backup all Policies
kubectl get policies -A -o yaml > policies-backup.yaml

# Backup operator configuration
helm get values patronus-operator -n patronus-system > operator-values-backup.yaml
```

### Restore from Backup

```bash
# Restore Sites
kubectl apply -f sites-backup.yaml

# Restore Policies
kubectl apply -f policies-backup.yaml

# Operator will automatically reconcile restored resources
```

### Disaster Recovery

**Scenario: Complete operator loss**

1. **Reinstall operator:**
```bash
helm install patronus-operator ./operator/helm/patronus-operator \
  --namespace patronus-system \
  --values operator-values-backup.yaml
```

2. **Restore resources:**
```bash
kubectl apply -f sites-backup.yaml
kubectl apply -f policies-backup.yaml
```

3. **Verify reconciliation:**
```bash
kubectl get sites -A
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator
```

---

## Upgrades

### Upgrade Operator

```bash
# Update Helm chart
helm upgrade patronus-operator ./operator/helm/patronus-operator \
  --namespace patronus-system \
  --values production-values.yaml

# Verify upgrade
kubectl rollout status deployment/patronus-operator -n patronus-system

# Check logs
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator
```

### Upgrade CRDs

```bash
# Apply new CRD definitions
kubectl apply -f operator/crds/

# Verify CRDs updated
kubectl get crds | grep sdwan.patronus.dev
```

### Rollback

```bash
# Rollback operator deployment
helm rollback patronus-operator -n patronus-system

# Verify rollback
kubectl get pods -n patronus-system
```

---

## Security

### RBAC Permissions

The operator requires these permissions:

**Sites:**
- get, list, watch, create, update, patch, delete (sites)
- get, update, patch (sites/status)

**Policies:**
- get, list, watch, create, update, patch, delete (policies)
- get, update, patch (policies/status)

**Leader Election:**
- get, list, watch, create, update, patch, delete (leases)

**Events:**
- create, patch (events)

### Security Best Practices

1. **Use read-only root filesystem** (enabled by default)
2. **Run as non-root user** (UID 1000, enabled by default)
3. **Drop all capabilities** (enabled by default)
4. **Use network policies** to restrict operator egress
5. **Enable TLS** for Patronus API communication
6. **Rotate ServiceAccount tokens** regularly
7. **Enable audit logging** for resource changes

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: patronus-operator
  namespace: patronus-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: patronus-operator
  policyTypes:
  - Egress
  egress:
  # Allow Kubernetes API
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
  # Allow Patronus API
  - to:
    - namespaceSelector:
        matchLabels:
          name: patronus-api
    ports:
    - protocol: TCP
      port: 8081
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

---

## Performance Tuning

### Resource Allocation

**Light workload (<50 sites):**
```yaml
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

**Medium workload (50-200 sites):**
```yaml
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 200m
    memory: 256Mi
```

**Heavy workload (>200 sites):**
```yaml
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

### Reconciliation Tuning

Adjust reconciliation frequency based on workload:

**Low frequency (stable environments):**
- Success requeue: 300s (5 minutes)
- Error requeue: 60s (1 minute)

**High frequency (dynamic environments):**
- Success requeue: 60s (1 minute)
- Error requeue: 30s (30 seconds)

### High Availability

For HA deployments:

```yaml
replicaCount: 3

leaderElection:
  enabled: true
  leaseDuration: 15s
  renewDeadline: 10s
  retryPeriod: 2s

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchLabels:
            app.kubernetes.io/name: patronus-operator
        topologyKey: kubernetes.io/hostname
```

---

## Maintenance Windows

### Planned Maintenance

1. **Schedule maintenance window**
2. **Scale down to 1 replica** (for faster operations):
   ```bash
   kubectl scale deployment patronus-operator -n patronus-system --replicas=1
   ```

3. **Perform maintenance**

4. **Scale back up**:
   ```bash
   kubectl scale deployment patronus-operator -n patronus-system --replicas=3
   ```

### Emergency Maintenance

**Stop reconciliation temporarily:**
```bash
# Scale to 0 (NOT RECOMMENDED for production)
kubectl scale deployment patronus-operator -n patronus-system --replicas=0

# Perform emergency fixes

# Scale back up
kubectl scale deployment patronus-operator -n patronus-system --replicas=3
```

---

## Support

**Documentation:** https://docs.patronus.dev/operator

**Issues:** https://github.com/patronus/patronus/issues

**Slack:** https://patronus-dev.slack.com

---

## Appendix: Common Commands

```bash
# View all Sites
kubectl get sites -A

# View all Policies
kubectl get policies -A

# Describe a Site
kubectl describe site <name> -n <namespace>

# View operator logs
kubectl logs -n patronus-system -l app.kubernetes.io/name=patronus-operator -f

# Check operator metrics
kubectl port-forward -n patronus-system svc/patronus-operator-metrics 8080:8080
curl http://localhost:8080/metrics

# Restart operator
kubectl rollout restart deployment/patronus-operator -n patronus-system

# Check operator version
kubectl get deployment patronus-operator -n patronus-system -o jsonpath='{.spec.template.spec.containers[0].image}'

# Export resources for backup
kubectl get sites -A -o yaml > sites-backup-$(date +%Y%m%d).yaml
kubectl get policies -A -o yaml > policies-backup-$(date +%Y%m%d).yaml
```
