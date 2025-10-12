# High Availability Architecture

**Status**: Production Ready
**Version**: 1.0.0
**Last Updated**: 2025-10-10

## Overview

Patronus Dashboard implements a comprehensive high availability (HA) architecture to ensure:

- **Zero Downtime**: Seamless failover between dashboard instances
- **Data Consistency**: Distributed state management with strong consistency
- **Automatic Recovery**: Self-healing cluster with leader election
- **Horizontal Scalability**: Add/remove instances without service interruption
- **Session Persistence**: User sessions survive instance failures

## Architecture Components

### 1. Leader Election

**Implementation**: Simplified Raft-like consensus algorithm

**Key Features**:
- Automatic leader selection when no leader exists
- Term-based leadership to prevent split-brain
- Heartbeat mechanism for failure detection
- Configurable election timeout and heartbeat intervals

**How It Works**:

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Instance 1  │      │  Instance 2  │      │  Instance 3  │
│   (Leader)   │◄────►│  (Follower)  │◄────►│  (Follower)  │
└──────────────┘      └──────────────┘      └──────────────┘
       │                     │                     │
       ▼                     ▼                     ▼
   Heartbeat            Accept                 Accept
   (every 1s)           Heartbeat              Heartbeat
```

**Failure Scenario**:

```
Instance 1 fails
       │
       ▼
No heartbeat for 5s
       │
       ▼
Instance 2 starts election
       │
       ▼
Instance 2 becomes leader
       │
       ▼
Instance 3 accepts new leader
```

**Configuration**:

```bash
# Environment variables
PATRONUS_ELECTION_TIMEOUT=5      # seconds
PATRONUS_HEARTBEAT_INTERVAL=1    # seconds
```

### 2. Distributed State Management

**Implementation**: Sled embedded distributed database

**Key Features**:
- Key-value store with ACID guarantees
- Namespace isolation for multi-tenant data
- Snapshot and restore capabilities
- Batch operations for atomic writes
- Watch mechanism for real-time updates

**Data Stored**:
- User sessions (active logins, JWT token state)
- Cluster metadata (node list, leader info)
- Configuration cache
- Temporary state requiring cross-instance visibility

**API Example**:

```rust
use patronus_dashboard::ha::DistributedState;

// Create state manager
let state = DistributedState::new("/data/raft", "patronus")?;

// Store session
let session = SessionData::new("user123".to_string(), "token456".to_string());
state.set("session:abc123", &session)?;

// Retrieve session
let session: Option<SessionData> = state.get("session:abc123")?;

// Batch operations
state.batch_write(|batch| {
    batch.insert("key1", &value1)?;
    batch.insert("key2", &value2)?;
    Ok(())
})?;

// Watch for changes
let subscriber = state.watch("session:abc123");
while let Some(event) = subscriber.next() {
    println!("Session updated!");
}
```

### 3. Database Replication

**Implementation**: Litestream for SQLite replication

**Key Features**:
- Continuous backup with 1-second sync interval
- Point-in-time recovery
- Multiple replica targets (local, S3, MinIO, Azure, GCS)
- Automatic restoration on instance startup
- WAL-based streaming replication

**Replication Flow**:

```
┌─────────────────┐
│  Primary SQLite │
│   (dashboard1)  │
└────────┬────────┘
         │ WAL Streaming
         ▼
┌─────────────────┐
│   Litestream    │
│   Replicator    │
└─────┬─────┬─────┘
      │     │
      ▼     ▼
   ┌───┐ ┌───┐
   │S3 │ │FS │  Replicas
   └───┘ └───┘
```

**Configuration** (`litestream/litestream.yml`):

```yaml
dbs:
  - path: /data/dashboard.db
    replicas:
      - type: file
        path: /replica/dashboard
        retention: 24h
        sync-interval: 1s

      - type: s3
        bucket: patronus-backups
        path: dashboard
        region: us-east-1
        retention: 720h
```

### 4. Load Balancing

**Implementation**: HAProxy with health-based routing

**Key Features**:
- Layer 7 (HTTP) load balancing
- Least-connection algorithm
- Health check integration
- Sticky sessions with cookie insertion
- WebSocket support
- TLS termination
- Rate limiting

**Load Balancing Algorithm**:

```
Client Request
     │
     ▼
┌─────────────┐
│   HAProxy   │
│ (Port 443)  │
└──────┬──────┘
       │
       ▼
Health Check: /health/ready
       │
       ├──► Instance 1 (healthy, 10 conns)  ◄── Selected (least conns)
       ├──► Instance 2 (healthy, 25 conns)
       └──► Instance 3 (unhealthy)          ◄── Removed from pool
```

**Configuration** (`haproxy/haproxy.cfg`):

```haproxy
backend patronus_backend
    balance leastconn

    option httpchk GET /health/ready
    http-check expect status 200

    cookie PATRONUS_SERVER insert indirect nocache

    server dashboard1 127.0.0.1:8443 check cookie dash1
    server dashboard2 127.0.0.1:8444 check backup
    server dashboard3 127.0.0.1:8445 check backup
```

### 5. Health Checks

**Implementation**: Multi-level health probes

**Endpoints**:

| Endpoint | Purpose | Kubernetes | Criteria |
|----------|---------|-----------|----------|
| `/health` | Basic health | - | Always returns 200 |
| `/health/live` | Liveness | ✅ | Process is running |
| `/health/ready` | Readiness | ✅ | DB + SD-WAN engine healthy |

**Health Check Logic**:

```rust
// Readiness check includes:
1. Database connectivity (SELECT 1)
2. SD-WAN engine responsiveness
3. All critical components operational

// If ANY check fails -> 503 Service Unavailable
// HAProxy removes instance from pool
```

**Kubernetes Integration**:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8443
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8443
  initialDelaySeconds: 5
  periodSeconds: 5
```

### 6. Session Persistence

**Implementation**: Sticky sessions + distributed session store

**Strategies**:

1. **Cookie-based Affinity** (Primary)
   - HAProxy inserts `PATRONUS_SERVER` cookie
   - Routes subsequent requests to same instance
   - Survives load balancer restarts

2. **Distributed Session Store** (Fallback)
   - Sessions stored in Sled distributed state
   - Any instance can validate any session
   - Seamless failover if instance dies

**Session Flow**:

```
Login Request
     │
     ▼
Instance 1: Create session
     │
     ├──► Store in distributed state
     ├──► Return JWT + cookie
     │
Next Request (with cookie)
     │
     ▼
HAProxy: Route to Instance 1 (cookie affinity)
     │
     ▼
Instance 1: Validate JWT locally (fast)

Instance 1 Fails
     │
     ▼
HAProxy: Route to Instance 2 (fallback)
     │
     ▼
Instance 2: Fetch session from distributed state
     │
     ▼
Continue seamlessly
```

## Deployment

### Docker Compose Deployment

**Quick Start**:

```bash
# 1. Generate SSL certificate (for production)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/patronus.key \
  -out certs/patronus.crt

# Combine for HAProxy
cat certs/patronus.crt certs/patronus.key > certs/patronus.pem

# 2. Start HA cluster
docker-compose -f docker-compose.ha.yml up -d

# 3. Verify cluster health
curl https://localhost/health
curl http://localhost:8404/stats  # HAProxy stats

# 4. Check cluster status
docker-compose -f docker-compose.ha.yml ps
```

**Architecture**:

```
                    ┌──────────────┐
                    │   HAProxy    │
                    │  (Port 443)  │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
    ┌──────────┐     ┌──────────┐     ┌──────────┐
    │Dashboard1│     │Dashboard2│     │Dashboard3│
    │  :8443   │     │  :8444   │     │  :8445   │
    └─────┬────┘     └─────┬────┘     └─────┬────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────▼───────┐
                    │  Litestream  │
                    │ (Replication)│
                    └──────────────┘
```

### Kubernetes Deployment

**Deployment YAML**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: patronus-dashboard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: patronus-dashboard
  template:
    metadata:
      labels:
        app: patronus-dashboard
    spec:
      containers:
      - name: dashboard
        image: patronus/dashboard:latest
        env:
        - name: PATRONUS_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: PATRONUS_ELECTION_TIMEOUT
          value: "5"
        - name: PATRONUS_HEARTBEAT_INTERVAL
          value: "1"
        ports:
        - containerPort: 8443
          name: https
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8443
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8443
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: patronus-data

---
apiVersion: v1
kind: Service
metadata:
  name: patronus-dashboard
spec:
  type: LoadBalancer
  selector:
    app: patronus-dashboard
  ports:
  - port: 443
    targetPort: 8443
    name: https
```

**StatefulSet for Persistent Identity**:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: patronus-dashboard
spec:
  serviceName: patronus-dashboard
  replicas: 3
  selector:
    matchLabels:
      app: patronus-dashboard
  template:
    # ... (same as Deployment)
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

## Monitoring

### High Availability Metrics

**Cluster Metrics**:

| Metric | Type | Description |
|--------|------|-------------|
| `cluster_nodes_total` | Gauge | Total nodes in cluster |
| `cluster_nodes_healthy` | Gauge | Healthy nodes in cluster |
| `cluster_is_leader` | Gauge | 1 if this node is leader |
| `cluster_current_term` | Gauge | Current election term |
| `cluster_elections_total` | Counter | Total elections held |
| `cluster_heartbeats_sent_total` | Counter | Heartbeats sent |
| `cluster_heartbeats_received_total` | Counter | Heartbeats received |
| `cluster_state_replications_total` | Counter | State sync operations |
| `cluster_failovers_total` | Counter | Failover events |
| `cluster_state_size_bytes` | Gauge | Distributed state size |

**Grafana Dashboard Queries**:

```promql
# Cluster health
cluster_nodes_healthy / cluster_nodes_total

# Leader changes over time
rate(cluster_elections_total[5m])

# Failover rate
rate(cluster_failovers_total[1h])

# State replication lag
cluster_heartbeats_sent_total - cluster_heartbeats_received_total
```

### Alert Rules

**Critical Alerts**:

```yaml
# No leader elected
- alert: ClusterNoLeader
  expr: sum(cluster_is_leader) == 0
  for: 30s
  severity: critical
  annotations:
    summary: "No cluster leader elected"

# Cluster unhealthy
- alert: ClusterUnhealthy
  expr: cluster_nodes_healthy < 2
  for: 1m
  severity: critical
  annotations:
    summary: "Less than 2 healthy nodes"

# Frequent failovers
- alert: HighFailoverRate
  expr: rate(cluster_failovers_total[5m]) > 0.1
  for: 5m
  severity: warning
  annotations:
    summary: "Frequent failover events detected"
```

## Failure Scenarios

### Scenario 1: Leader Instance Failure

**Timeline**:

```
T+0s:   Instance 1 (leader) crashes
T+5s:   Election timeout expires
T+5.1s: Instance 2 starts election
T+5.2s: Instance 2 becomes leader
T+5.3s: Instance 3 accepts new leader
T+6s:   All traffic routes to Instance 2
```

**Impact**: ~5 seconds of leader unavailability, but HAProxy continues serving from healthy instances

**Recovery**: Automatic via leader election

### Scenario 2: Database Corruption

**Timeline**:

```
T+0s:   Database corruption detected on Instance 1
T+0.1s: Health check fails (/health/ready returns 503)
T+0.2s: HAProxy marks Instance 1 unhealthy
T+0.3s: All traffic routes to Instance 2 & 3
T+1m:   Admin restores from Litestream replica
T+2m:   Instance 1 rejoins cluster
```

**Impact**: Single instance degraded, no user-facing impact

**Recovery**: Restore from Litestream backup

### Scenario 3: Network Partition (Split Brain)

**Prevention**:

1. **Term-based Leadership**: Only one leader per term
2. **Quorum Requirement**: Majority of nodes must agree
3. **Heartbeat Verification**: Nodes verify leader heartbeats

**Mitigation** (if it occurs):

```bash
# Manually force re-election
curl -X POST https://dashboard1/api/v1/admin/force-election

# Or restart affected instances
docker-compose -f docker-compose.ha.yml restart dashboard1
```

### Scenario 4: Total Cluster Failure

**Recovery Steps**:

```bash
# 1. Restore database from Litestream
litestream restore -if-replica-exists /data/dashboard.db

# 2. Restore distributed state from backup
cp /backup/raft/* /data/raft/

# 3. Start first instance (will become leader)
docker-compose -f docker-compose.ha.yml up -d dashboard1

# 4. Wait for election (5s)
sleep 10

# 5. Start remaining instances
docker-compose -f docker-compose.ha.yml up -d dashboard2 dashboard3

# 6. Verify cluster health
curl https://localhost/health
```

## Testing

### Failover Testing

**Test 1: Leader Failure**:

```bash
# 1. Identify leader
curl -s https://localhost/api/v1/cluster/status | jq .leader

# 2. Kill leader instance
docker stop patronus-dashboard-1

# 3. Monitor election (should complete in ~5s)
watch -n 1 'curl -s https://localhost/api/v1/cluster/status'

# 4. Verify new leader elected
curl -s https://localhost/api/v1/cluster/status | jq .leader

# 5. Verify no service disruption
ab -n 1000 -c 10 https://localhost/health
```

**Test 2: Database Failover**:

```bash
# 1. Corrupt database on Instance 1
docker exec patronus-dashboard-1 dd if=/dev/zero of=/data/dashboard.db bs=1M count=1

# 2. Wait for health check to fail
sleep 10

# 3. Verify Instance 1 removed from pool
curl http://localhost:8404/stats | grep dashboard1

# 4. Verify traffic continues on Instance 2 & 3
ab -n 1000 -c 10 https://localhost/api/v1/sites
```

**Test 3: Rolling Restart**:

```bash
# Restart instances one at a time
for i in 1 2 3; do
    echo "Restarting dashboard$i"
    docker-compose -f docker-compose.ha.yml restart dashboard$i
    sleep 30  # Wait for health check
done

# Verify zero downtime
# (run in parallel with above)
ab -n 10000 -c 50 https://localhost/health
```

### Load Testing

**Simulate High Load**:

```bash
# Install Apache Bench and wrk
sudo apt install apache2-utils

# Test 1: HTTP load
ab -n 10000 -c 100 https://localhost/api/v1/sites

# Test 2: WebSocket load
wrk -t 10 -c 100 -d 30s \
  --latency \
  -s websocket.lua \
  https://localhost/ws/metrics

# Test 3: Concurrent logins
ab -n 1000 -c 50 -p login.json \
  -T application/json \
  https://localhost/api/v1/auth/login
```

## Operational Procedures

### Adding a Node

```bash
# 1. Update docker-compose.ha.yml
cat >> docker-compose.ha.yml <<EOF
  dashboard4:
    # ... (copy from dashboard3, change ports)
EOF

# 2. Update HAProxy config
cat >> haproxy/haproxy.cfg <<EOF
    server dashboard4 127.0.0.1:8446 check backup
EOF

# 3. Start new instance
docker-compose -f docker-compose.ha.yml up -d dashboard4

# 4. Reload HAProxy
docker-compose -f docker-compose.ha.yml exec haproxy \
  haproxy -f /usr/local/etc/haproxy/haproxy.cfg -sf $(pidof haproxy)

# 5. Verify cluster membership
curl -s https://localhost/api/v1/cluster/status
```

### Removing a Node

```bash
# 1. Drain connections (mark as maintenance in HAProxy)
# Via HAProxy stats page: http://localhost:8404/stats

# 2. Stop instance
docker-compose -f docker-compose.ha.yml stop dashboard3

# 3. Remove from cluster
curl -X DELETE https://localhost/api/v1/cluster/nodes/dashboard3

# 4. Update configurations
# Remove from docker-compose.ha.yml and haproxy.cfg
```

### Backup and Restore

**Backup**:

```bash
# Automated via Litestream (continuous)
# Manual snapshot:
docker-compose -f docker-compose.ha.yml exec litestream \
  litestream snapshots /data/dashboard.db

# Backup distributed state
docker-compose -f docker-compose.ha.yml exec dashboard1 \
  tar czf /backup/raft-$(date +%Y%m%d).tar.gz /data/raft
```

**Restore**:

```bash
# Restore database
docker-compose -f docker-compose.ha.yml exec litestream \
  litestream restore -o /data/dashboard.db.restored /data/dashboard.db

# Restore distributed state
docker-compose -f docker-compose.ha.yml exec dashboard1 \
  tar xzf /backup/raft-20251010.tar.gz -C /data
```

## Best Practices

### Configuration

1. **Odd Number of Instances**: Use 3, 5, or 7 instances for proper quorum
2. **Cross-AZ Deployment**: Distribute instances across availability zones
3. **Resource Limits**: Set appropriate CPU/memory limits to prevent resource starvation
4. **Persistent Volumes**: Use persistent storage for Raft logs and SQLite database

### Monitoring

1. **Alert on All Metrics**: Monitor cluster health, elections, failovers
2. **Dashboard per Instance**: Track individual instance health
3. **Synthetic Monitoring**: External uptime checks
4. **Log Aggregation**: Centralize logs for correlation

### Security

1. **TLS Everywhere**: Encrypt inter-node communication
2. **Mutual TLS**: Use client certificates for cluster auth
3. **Network Segmentation**: Isolate cluster network from public traffic
4. **Secret Management**: Use Vault or k8s secrets for sensitive data

## Limitations

### Current Limitations

1. **No Cross-Region Replication**: Single region deployment only
2. **Manual Scaling**: No auto-scaling based on load
3. **Simplified Raft**: Not full Raft implementation (leader-only write)
4. **SQLite Limitations**: Single-writer database (Litestream helps)

### Future Enhancements

- [ ] Multi-region active-active deployment
- [ ] Auto-scaling based on metrics
- [ ] Full Raft consensus with log replication
- [ ] PostgreSQL option for multi-writer database
- [ ] Automatic node discovery (vs. static peer list)
- [ ] Zero-downtime configuration updates
- [ ] Canary deployments

## Troubleshooting

### Issue: No Leader Elected

**Symptoms**: `cluster_is_leader` metric is 0 on all nodes

**Diagnosis**:

```bash
# Check election logs
docker-compose -f docker-compose.ha.yml logs dashboard1 | grep election

# Verify network connectivity
docker-compose -f docker-compose.ha.yml exec dashboard1 ping dashboard2
```

**Resolution**:

```bash
# Restart cluster
docker-compose -f docker-compose.ha.yml restart

# Or force election on specific node
curl -X POST https://dashboard1:8443/api/v1/admin/force-election
```

### Issue: Split Brain

**Symptoms**: Multiple nodes think they are leader

**Diagnosis**:

```bash
# Check leader count
curl -s https://localhost/metrics | grep cluster_is_leader
```

**Resolution**:

```bash
# Restart all instances sequentially
for i in 1 2 3; do
    docker-compose -f docker-compose.ha.yml restart dashboard$i
    sleep 10
done
```

### Issue: State Divergence

**Symptoms**: Inconsistent data across instances

**Diagnosis**:

```bash
# Compare state sizes
for i in 1 2 3; do
    echo "Instance $i:"
    docker exec patronus-dashboard-$i du -sh /data/raft
done
```

**Resolution**:

```bash
# Rebuild follower state from leader
docker exec patronus-dashboard-2 rm -rf /data/raft
docker-compose -f docker-compose.ha.yml restart dashboard2
```

## References

- [Raft Consensus Algorithm](https://raft.github.io/)
- [Sled Embedded Database](https://docs.rs/sled/)
- [Litestream Replication](https://litestream.io/)
- [HAProxy Documentation](http://www.haproxy.org/)
- [Kubernetes HA Best Practices](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/ha-topology/)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-10
**Maintained By**: Patronus Development Team
