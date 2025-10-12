# Patronus SD-WAN Load Testing Guide

**Version**: 1.0.0
**Last Updated**: 2025-10-11

---

## Overview

This guide covers load testing and performance validation for Patronus SD-WAN at various scales.

### Testing Goals

1. **Validate Performance Targets**: Ensure system meets performance SLAs
2. **Find Breaking Points**: Determine maximum capacity
3. **Identify Bottlenecks**: Locate performance constraints
4. **Baseline Metrics**: Establish performance baselines
5. **Regression Testing**: Detect performance degradations

### Performance Targets

| Metric | Target | Acceptable | Critical |
|--------|--------|------------|----------|
| Path selection | <50μs | <100μs | <200μs |
| Health check (100 paths) | <10s | <15s | <30s |
| Failover latency | <100ms | <200ms | <500ms |
| API response time (p99) | <100ms | <200ms | <500ms |
| Memory per site | <1MB | <2MB | <5MB |
| CPU usage (steady state) | <50% | <70% | <90% |

---

## Test Scenarios

### Scenario 1: Mesh Scaling

**Objective**: Validate system can handle target number of sites

**Test Matrix**:
| Sites | Paths | Expected Setup Time | Memory Usage |
|-------|-------|---------------------|--------------|
| 100   | 9,900 | <10s | <100MB |
| 500   | 249,500 | <30s | <500MB |
| 1000  | 999,000 | <60s | <1GB |
| 2000  | 3,998,000 | <120s | <2GB |

**Metrics to Collect**:
- Setup time
- Memory usage (RSS, heap)
- Path selection latency
- Health check interval adherence

**Script**: `tests/load/mesh_scaling.sh`

```bash
#!/bin/bash
# Mesh scaling load test

SCALE=${1:-100}  # Number of sites
echo "Testing mesh with $SCALE sites..."

# Start time
START=$(date +%s)

# Create sites
for i in $(seq 1 $SCALE); do
    curl -s -X POST http://localhost:8081/v1/sites \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"site-$i\",
            \"public_key\": \"$(wg genkey | wg pubkey)\",
            \"endpoints\": [\"10.0.$((i/256)).$((i%256)):51820\"]
        }" > /dev/null
done

# End time
END=$(date +%s)
DURATION=$((END - START))

echo "Setup time: ${DURATION}s"

# Measure memory
ps aux | grep patronus | awk '{print $6/1024 " MB"}'

# Measure path selection latency
./bench-path-selection.sh

echo "Test complete"
```

### Scenario 2: Health Monitoring Load

**Objective**: Validate health monitoring at scale

**Configuration**:
- 1000 paths
- 5-second check interval
- 5 probes per check

**Expected Load**:
- 1000 paths × 5 probes × 12 checks/minute = 60,000 probes/minute
- ~1000 probes/second

**Metrics**:
- Check completion time
- Probe success rate
- Database write latency
- CPU and network usage

**Script**: `tests/load/health_monitoring.sh`

```bash
#!/bin/bash
# Health monitoring load test

PATHS=1000
DURATION=600  # 10 minutes

echo "Testing health monitoring: $PATHS paths for $DURATION seconds"

# Configure aggressive health checking
cat > /tmp/health-config.yaml <<EOF
health:
  check_interval_secs: 5
  probes_per_check: 5
  persist_to_db: true
