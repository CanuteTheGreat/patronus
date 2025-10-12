# Patronus SD-WAN - Monitoring & Observability Guide

## Overview

Patronus SD-WAN includes comprehensive monitoring and observability features powered by Prometheus, Grafana, and Alertmanager. This guide covers metrics collection, dashboard usage, alerting, and troubleshooting.

## Architecture

```
┌─────────────┐      ┌────────────┐      ┌──────────┐
│   Patronus  │─────>│ Prometheus │─────>│ Grafana  │
│  Dashboard  │      │  (metrics) │      │(visualize│
└─────────────┘      └────────────┘      └──────────┘
                            │
                            v
                     ┌──────────────┐
                     │ Alertmanager │
                     │   (alerts)   │
                     └──────────────┘
```

## Quick Start

### 1. Start Monitoring Stack

```bash
# Start Prometheus, Grafana, and Alertmanager
docker-compose -f docker-compose.monitoring.yml up -d

# Verify services are running
docker-compose -f docker-compose.monitoring.yml ps
```

### 2. Access Dashboards

- **Grafana**: http://localhost:3000
  - Username: `admin`
  - Password: `patronus`

- **Prometheus**: http://localhost:9090
- **Alertmanager**: http://localhost:9093

### 3. View Metrics

The Patronus Dashboard exposes metrics at: `http://localhost:8443/metrics`

## Available Metrics

### HTTP Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | Request duration |
| `http_requests_errors_total` | Counter | HTTP errors (4xx, 5xx) |

Labels: `method`, `path`, `status`

### Authentication Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `auth_login_attempts_total` | Counter | Total login attempts |
| `auth_login_success_total` | Counter | Successful logins |
| `auth_login_failures_total` | Counter | Failed logins |
| `auth_token_refresh_total` | Counter | Token refreshes |

### Database Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `db_queries_total` | Counter | Total database queries |
| `db_query_duration_seconds` | Histogram | Query duration |
| `db_errors_total` | Counter | Database errors |

Labels: `type` (query type)

### WebSocket Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `websocket_connections_active` | Gauge | Active WebSocket connections |
| `websocket_messages_sent_total` | Counter | Messages sent |
| `websocket_messages_received_total` | Counter | Messages received |

### SD-WAN Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sdwan_sites_total` | Gauge | Total sites |
| `sdwan_paths_total` | Gauge | Total paths |
| `sdwan_paths_active` | Gauge | Active paths |
| `sdwan_policies_total` | Gauge | Total policies |
| `sdwan_path_latency_ms` | Histogram | Path latency |
| `sdwan_path_packet_loss_pct` | Gauge | Packet loss percentage |

Labels: `path_id`

### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `system_uptime_seconds` | Gauge | System uptime |
| `system_memory_usage_bytes` | Gauge | Memory usage |
| `active_users_total` | Gauge | Active users |

## Health Checks

### Endpoints

1. **Basic Health**: `GET /health`
   - Returns: `OK`
   - Use: Simple liveness check

2. **Liveness Probe**: `GET /health/live`
   - Returns: `alive`
   - Use: Kubernetes liveness probe

3. **Readiness Probe**: `GET /health/ready`
   - Returns: `ready`
   - Use: Kubernetes readiness probe

### Kubernetes Integration

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8443
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8443
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Grafana Dashboards

### Patronus Overview Dashboard

Located: `grafana/dashboards/patronus-overview.json`

**Panels**:
1. System Uptime
2. Total Sites
3. Active Paths
4. Active Users
5. HTTP Request Rate
6. HTTP Request Duration (p95)
7. Path Latency Distribution (heatmap)
8. Path Packet Loss
9. WebSocket Connections
10. Authentication Activity
11. Database Query Performance

### Importing Dashboards

1. Open Grafana (http://localhost:3000)
2. Navigate to **Dashboards** → **Import**
3. Upload `grafana/dashboards/patronus-overview.json`
4. Select Prometheus data source
5. Click **Import**

## Alerting

### Alert Rules

Located: `prometheus/alerts.yml`

**Alert Categories**:

1. **Service Health**
   - DashboardDown
   - HighErrorRate

2. **Authentication**
   - HighLoginFailureRate
   - NoActiveUsers

3. **SD-WAN Network**
   - PathDown
   - HighPathLatency
   - HighPacketLoss

4. **Database**
   - HighDatabaseQueryTime
   - DatabaseErrors

5. **Performance**
   - HighMemoryUsage
   - SlowHTTPResponses

6. **Capacity Planning**
   - HighSiteCount
   - HighPolicyCount

### Alert Severity Levels

- **Critical**: Immediate action required (service down, major degradation)
- **Warning**: Attention needed (performance issues, threshold breaches)
- **Info**: Informational (capacity planning, trends)

### Configuring Notifications

Edit `alertmanager/config.yml`:

#### Slack Integration

```yaml
global:
  slack_api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'

receivers:
  - name: 'critical-alerts'
    slack_configs:
      - channel: '#patronus-critical'
        title: 'CRITICAL: {{ .GroupLabels.alertname }}'
```

#### Email Integration

```yaml
receivers:
  - name: 'critical-alerts'
    email_configs:
      - to: 'ops-team@example.com'
        from: 'alertmanager@patronus.local'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alertmanager@patronus.local'
        auth_password: 'password'
```

#### PagerDuty Integration

```yaml
receivers:
  - name: 'critical-alerts'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_KEY'
```

## Querying Metrics

### Prometheus Query Examples

#### Request Rate

```promql
# Requests per second by endpoint
rate(http_requests_total[5m])

# Error rate percentage
rate(http_requests_errors_total[5m]) / rate(http_requests_total[5m]) * 100
```

#### Latency

```promql
# p95 latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# p99 latency
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))
```

#### SD-WAN Health

```promql
# Path availability percentage
sdwan_paths_active / sdwan_paths_total * 100

# Average path latency
avg(sdwan_path_latency_ms)

# Paths with high packet loss (>1%)
sdwan_path_packet_loss_pct > 1
```

#### Authentication

```promql
# Login success rate
rate(auth_login_success_total[5m]) / rate(auth_login_attempts_total[5m]) * 100

# Failed login attempts (potential attacks)
rate(auth_login_failures_total[1m]) > 0.1
```

## Troubleshooting

### No Metrics Appearing

1. **Check metrics endpoint**:
   ```bash
   curl http://localhost:8443/metrics
   ```

2. **Verify Prometheus scraping**:
   - Open Prometheus UI: http://localhost:9090
   - Go to **Status** → **Targets**
   - Check if `patronus-dashboard` target is UP

3. **Check Prometheus logs**:
   ```bash
   docker logs patronus-prometheus
   ```

### Dashboards Show No Data

1. **Verify Prometheus data source**:
   - Grafana → **Configuration** → **Data Sources**
   - Test connection to Prometheus

2. **Check time range**:
   - Ensure dashboard time range includes data points
   - Try "Last 15 minutes" initially

3. **Verify metrics exist**:
   ```promql
   {__name__=~".+"}
   ```

### Alerts Not Firing

1. **Check alert rules**:
   - Prometheus UI → **Alerts**
   - Verify rules are loaded

2. **Test alert condition**:
   - Run PromQL query manually
   - Verify threshold is crossed

3. **Check Alertmanager**:
   - Open: http://localhost:9093
   - Verify alerts are received

4. **Test notification**:
   ```bash
   # Send test alert
   curl -X POST http://localhost:9093/api/v1/alerts \
     -H 'Content-Type: application/json' \
     -d '[{
       "labels": {"alertname": "test", "severity": "info"},
       "annotations": {"summary": "Test alert"}
     }]'
   ```

## Best Practices

### Retention Policies

**Prometheus** (configure in `prometheus.yml`):
```yaml
global:
  # Keep metrics for 15 days
  storage.tsdb.retention.time: 15d
  # Max 10GB storage
  storage.tsdb.retention.size: 10GB
```

**Grafana**:
- Use Prometheus for short-term metrics (days)
- Export to long-term storage (Thanos, Cortex) for historical analysis

### Dashboard Organization

1. **Overview Dashboard**: High-level system health
2. **Component Dashboards**: Detailed metrics per component
3. **Troubleshooting Dashboards**: Diagnostic queries
4. **SLA Dashboards**: Service level tracking

### Alert Tuning

1. **Start Conservative**: Begin with high thresholds
2. **Monitor False Positives**: Track alert fatigue
3. **Use Inhibition Rules**: Prevent alert storms
4. **Group Related Alerts**: Reduce noise

### Security

1. **Enable Authentication**:
   ```yaml
   # Prometheus
   basic_auth_users:
     admin: $2y$10$...
   ```

2. **Use TLS**:
   ```yaml
   tls_config:
     cert_file: /path/to/cert.pem
     key_file: /path/to/key.pem
   ```

3. **Network Isolation**: Run monitoring stack in private network

## Performance Considerations

### Metric Cardinality

- **Avoid high-cardinality labels**: Don't use user IDs, session IDs as labels
- **Use aggregation**: Pre-aggregate high-frequency metrics
- **Limit label values**: Keep unique label value count reasonable (<1000)

### Scrape Intervals

```yaml
# Default: 15s
global:
  scrape_interval: 15s

# High-frequency (expensive)
scrape_configs:
  - job_name: 'patronus-dashboard'
    scrape_interval: 10s

# Low-frequency (cheap)
  - job_name: 'node-exporter'
    scrape_interval: 30s
```

### Query Optimization

- Use recording rules for expensive queries
- Avoid `*` in selectors
- Limit time ranges in queries
- Use `rate()` over `irate()` for alerts

## Monitoring Stack Maintenance

### Backup Configuration

```bash
# Backup Prometheus data
docker run --rm -v patronus_prometheus-data:/data \
  -v $(pwd)/backups:/backup alpine \
  tar czf /backup/prometheus-$(date +%Y%m%d).tar.gz /data

# Backup Grafana dashboards
docker exec patronus-grafana grafana-cli admin export-dashboard \
  > backups/grafana-dashboards-$(date +%Y%m%d).json
```

### Upgrade Procedure

```bash
# 1. Backup current state
docker-compose -f docker-compose.monitoring.yml down

# 2. Update images
docker-compose -f docker-compose.monitoring.yml pull

# 3. Restart with new versions
docker-compose -f docker-compose.monitoring.yml up -d

# 4. Verify health
docker-compose -f docker-compose.monitoring.yml ps
```

## References

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [PromQL Basics](https://prometheus.io/docs/prometheus/latest/querying/basics/)

---

**Last Updated**: 2025-10-10
**Version**: 1.0.0
