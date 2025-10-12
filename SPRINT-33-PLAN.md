# Sprint 33: Operations & Production Hardening

**Sprint Goal**: Enhance operational readiness and production maturity through comprehensive documentation, automation, and proven scalability.

**Duration**: 3-5 days
**Priority**: High (Production Readiness)
**Status**: Planning

---

## Executive Summary

With Sprint 32 completing real network probing, Patronus now has all core SD-WAN functionality. Sprint 33 focuses on **operational excellence** - the documentation, procedures, automation, and validation needed for confident production deployment at scale.

### Why This Sprint?

1. **Complete Feature Set**: Core functionality is production-ready
2. **Operational Gap**: Missing runbooks, DR procedures, and scale validation
3. **Risk Reduction**: Load testing and procedures prevent production incidents
4. **Deployment Confidence**: CI/CD and documentation enable reliable operations
5. **Foundation for Growth**: Operational maturity before adding complexity

---

## Objectives

### Primary Goals

1. **Operational Documentation**: Complete runbooks and troubleshooting guides
2. **Disaster Recovery**: Document and test DR procedures
3. **Scale Validation**: Prove system works at 1000+ nodes
4. **Automation**: CI/CD pipeline for reliable deployments
5. **API Documentation**: Complete OpenAPI/Swagger specs

### Success Criteria

- ✅ Operations runbook covering all common scenarios
- ✅ Disaster recovery procedures tested and documented
- ✅ Load tests demonstrating 1000+ node capability
- ✅ CI/CD pipeline with automated testing
- ✅ Complete OpenAPI specification for all APIs
- ✅ Performance tuning guide with benchmarks

---

## Deliverables

### Phase 1: Operations Runbook (Day 1-2)

**File**: `docs/OPERATIONS_RUNBOOK.md`

**Contents**:

1. **Daily Operations**
   - Health check procedures
   - Monitoring dashboard review
   - Log review and analysis
   - Performance monitoring

2. **Common Tasks**
   - Adding new sites
   - Configuring policies
   - Updating WireGuard keys
   - Database maintenance
   - Certificate rotation

3. **Troubleshooting**
   - Path down scenarios
   - High latency diagnosis
   - Packet loss investigation
   - Failover not triggering
   - Database issues
   - Authentication problems
   - WebSocket connection failures

4. **Incident Response**
   - Severity classification
   - Escalation procedures
   - Communication templates
   - Post-incident review

5. **Maintenance Windows**
   - Upgrade procedures
   - Rollback procedures
   - Zero-downtime deployments
   - Database migrations

**Format**: Step-by-step procedures with commands, expected outputs, and decision trees

---

### Phase 2: Disaster Recovery (Day 2)

**File**: `docs/DISASTER_RECOVERY.md`

**Contents**:

1. **Backup Strategy**
   - What to backup (database, configs, keys)
   - Backup frequency and retention
   - Backup verification procedures
   - Automated backup scripts

2. **Recovery Scenarios**
   - Single node failure
   - Database corruption
   - Complete datacenter loss
   - Network partition
   - Key compromise

3. **Recovery Procedures**
   - Step-by-step recovery for each scenario
   - Recovery Time Objective (RTO) estimates
   - Recovery Point Objective (RPO) guarantees
   - Validation procedures

4. **Business Continuity**
   - Failover to backup site
   - Operating in degraded mode
   - Communication during outages
   - Service restoration priority

**Includes**: Automated backup scripts in `scripts/backup/`

---

### Phase 3: Performance Tuning Guide (Day 2-3)

**File**: `docs/PERFORMANCE_TUNING.md`

**Contents**:

1. **System Requirements**
   - CPU recommendations by scale
   - Memory requirements
   - Network bandwidth needs
   - Storage IOPS requirements

2. **Kernel Tuning**
   - sysctl settings for networking
   - eBPF optimization
   - File descriptor limits
   - Connection tracking tuning

3. **Application Tuning**
   - Tokio runtime configuration
   - Database connection pooling
   - WireGuard performance
   - Metrics collection overhead

4. **Network Tuning**
   - MTU optimization
   - TCP window sizing
   - Buffer sizing
   - Offload features

5. **Monitoring Performance**
   - Key metrics to watch
   - Performance baseline establishment
   - Bottleneck identification
   - Capacity planning

**Includes**: Benchmark results and tuning scripts

---

### Phase 4: CI/CD Pipeline (Day 3)

**Files**:
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `scripts/ci/`

**CI Pipeline** (`.github/workflows/ci.yml`):

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          profile: minimal
          toolchain: stable

      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo
            target/
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Run tests
        run: cargo test --workspace --all-features

      - name: Run clippy
        run: cargo clippy --workspace --all-features -- -D warnings

      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Build release
        run: cargo build --release --workspace

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run cargo audit
        run: cargo audit

      - name: Run cargo deny
        run: cargo deny check

  integration:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v3

      - name: Start services
        run: docker-compose -f docker/compose.test.yml up -d

      - name: Run integration tests
        run: cargo test --test '*' --features integration

      - name: Collect logs
        if: failure()
        run: docker-compose logs
```

**Release Pipeline** (`.github/workflows/release.yml`):

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v3

      - name: Build release binary
        run: cargo build --release

      - name: Package release
        run: |
          tar czf patronus-${{ matrix.os }}.tar.gz \
            -C target/release \
            patronus-sdwan patronus-dashboard

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: patronus-${{ matrix.os }}
          path: patronus-${{ matrix.os }}.tar.gz

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker images
        run: docker-compose build

      - name: Push to registry
        run: |
          echo "${{ secrets.DOCKER_PASSWORD }}" | docker login -u "${{ secrets.DOCKER_USERNAME }}" --password-stdin
          docker-compose push
```

---

### Phase 5: OpenAPI Documentation (Day 3-4)

**File**: `docs/api/openapi.yaml`

**REST API Specification**:

```yaml
openapi: 3.0.3
info:
  title: Patronus SD-WAN API
  description: Enterprise SD-WAN management and monitoring API
  version: 1.0.0
  contact:
    name: Patronus Development Team
  license:
    name: MIT

servers:
  - url: https://api.patronus.example.com/v1
    description: Production API
  - url: http://localhost:8080/v1
    description: Local development

security:
  - bearerAuth: []

paths:
  /auth/login:
    post:
      summary: Authenticate user
      tags: [Authentication]
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Successful authentication
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AuthResponse'
        '401':
          description: Invalid credentials

  /sites:
    get:
      summary: List all sites
      tags: [Sites]
      parameters:
        - in: query
          name: status
          schema:
            type: string
            enum: [active, inactive, all]
      responses:
        '200':
          description: List of sites
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Site'

    post:
      summary: Create new site
      tags: [Sites]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateSiteRequest'
      responses:
        '201':
          description: Site created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Site'

  /sites/{siteId}:
    get:
      summary: Get site details
      tags: [Sites]
      parameters:
        - in: path
          name: siteId
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Site details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Site'
        '404':
          description: Site not found

  /paths:
    get:
      summary: List network paths
      tags: [Paths]
      parameters:
        - in: query
          name: siteId
          schema:
            type: string
        - in: query
          name: status
          schema:
            type: string
            enum: [up, degraded, down]
      responses:
        '200':
          description: List of paths
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Path'

  /paths/{pathId}/health:
    get:
      summary: Get path health metrics
      tags: [Health]
      parameters:
        - in: path
          name: pathId
          required: true
          schema:
            type: string
        - in: query
          name: since
          schema:
            type: string
            format: date-time
        - in: query
          name: until
          schema:
            type: string
            format: date-time
      responses:
        '200':
          description: Path health history
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/PathHealth'

  /policies:
    get:
      summary: List routing policies
      tags: [Policies]
      responses:
        '200':
          description: List of policies
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Policy'

    post:
      summary: Create routing policy
      tags: [Policies]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreatePolicyRequest'
      responses:
        '201':
          description: Policy created

  /metrics/export:
    get:
      summary: Export metrics in various formats
      tags: [Metrics]
      parameters:
        - in: query
          name: format
          schema:
            type: string
            enum: [prometheus, json]
            default: prometheus
      responses:
        '200':
          description: Metrics export
          content:
            text/plain:
              schema:
                type: string
            application/json:
              schema:
                type: object

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    LoginRequest:
      type: object
      required: [username, password]
      properties:
        username:
          type: string
        password:
          type: string
          format: password

    AuthResponse:
      type: object
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
        expires_in:
          type: integer
          description: Token expiry in seconds

    Site:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
        location:
          type: string
        public_key:
          type: string
        endpoints:
          type: array
          items:
            type: string
        status:
          type: string
          enum: [active, inactive]
        created_at:
          type: string
          format: date-time

    Path:
      type: object
      properties:
        id:
          type: string
        source_site_id:
          type: string
        dest_site_id:
          type: string
        latency_ms:
          type: number
        packet_loss_pct:
          type: number
        status:
          type: string
          enum: [up, degraded, down]

    PathHealth:
      type: object
      properties:
        path_id:
          type: string
        timestamp:
          type: string
          format: date-time
        latency_ms:
          type: number
        packet_loss_pct:
          type: number
        jitter_ms:
          type: number
        health_score:
          type: number
          minimum: 0
          maximum: 100

    Policy:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
        priority:
          type: integer
        match_criteria:
          type: object
        action:
          type: string
          enum: [route, drop, rate_limit]

    CreateSiteRequest:
      type: object
      required: [name, public_key, endpoints]
      properties:
        name:
          type: string
        location:
          type: string
        public_key:
          type: string
        endpoints:
          type: array
          items:
            type: string

    CreatePolicyRequest:
      type: object
      required: [name, priority, match_criteria, action]
      properties:
        name:
          type: string
        priority:
          type: integer
        match_criteria:
          type: object
        action:
          type: string
```

**GraphQL API Documentation**: Already complete in Sprint 21

---

### Phase 6: Load Testing Suite (Day 4-5)

**Files**:
- `tests/load/mod.rs`
- `tests/load/scenarios/`
- `scripts/load-test.sh`

**Load Test Framework**:

```rust
// tests/load/mod.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use patronus_sdwan::*;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Simulate 1000 sites with mesh connectivity
async fn benchmark_mesh_1000_sites() {
    let sites = (0..1000)
        .map(|i| create_test_site(format!("site-{}", i)))
        .collect::<Vec<_>>();

    // Measure mesh setup time
    let start = std::time::Instant::now();
    setup_mesh(&sites).await;
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_secs(30), "Mesh setup too slow");
}

/// Test path selection performance at scale
async fn benchmark_path_selection_1000_paths() {
    let engine = create_test_engine().await;

    // Create 1000 paths
    for i in 0..1000 {
        engine.add_path(create_test_path(i)).await;
    }

    // Measure path selection time
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let path = engine.select_path().await;
        black_box(path);
    }
    let elapsed = start.elapsed();

    let avg_latency = elapsed.as_micros() / 10000;
    assert!(avg_latency < 50, "Path selection avg {}us, target <50us", avg_latency);
}

/// Test health monitoring at scale
async fn benchmark_health_checks_1000_paths() {
    let monitor = create_test_monitor().await;

    // Setup 1000 paths to monitor
    let paths = (0..1000)
        .map(|i| (PathId::new(i), "8.8.8.8".parse().unwrap()))
        .collect();

    // Measure concurrent health check time
    let start = std::time::Instant::now();
    check_all_paths_concurrent(&monitor, &paths).await;
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_secs(10), "Health checks too slow");
}

/// Test failover response time
async fn benchmark_failover_latency() {
    let engine = create_failover_engine().await;

    // Setup primary and backup paths
    let primary = create_test_path(1);
    let backup = create_test_path(2);

    engine.add_path(primary.clone()).await;
    engine.add_path(backup).await;

    // Measure failover time
    let start = std::time::Instant::now();
    engine.mark_path_down(&primary.id).await;
    let new_path = engine.select_path().await.unwrap();
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_millis(100), "Failover too slow");
    assert_ne!(new_path.id, primary.id, "Didn't failover");
}

/// Test memory usage at scale
async fn benchmark_memory_usage_1000_sites() {
    let initial_mem = get_memory_usage();

    let engine = create_test_engine().await;
    for i in 0..1000 {
        engine.add_site(create_test_site(format!("site-{}", i))).await;
    }

    let final_mem = get_memory_usage();
    let mem_per_site = (final_mem - initial_mem) / 1000;

    assert!(mem_per_site < 1024 * 1024, "Memory per site > 1MB");
}

/// Test metrics export performance
async fn benchmark_metrics_export() {
    let exporter = create_metrics_exporter().await;

    // Generate metrics for 1000 paths
    for i in 0..1000 {
        record_path_metrics(i, 50.0, 0.1, 2.0).await;
    }

    // Measure export time
    let start = std::time::Instant::now();
    let metrics = exporter.export_prometheus().await;
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_millis(100), "Metrics export too slow");
    assert!(metrics.len() > 0, "No metrics exported");
}

criterion_group!(
    benches,
    bench_mesh_setup,
    bench_path_selection,
    bench_health_checks,
    bench_failover,
    bench_memory,
    bench_metrics
);

criterion_main!(benches);
```

**Load Test Script**:

```bash
#!/bin/bash
# scripts/load-test.sh

set -e

echo "=== Patronus SD-WAN Load Testing ==="
echo ""

# Configuration
SCALE="${SCALE:-1000}"
DURATION="${DURATION:-300}"  # 5 minutes
CONCURRENCY="${CONCURRENCY:-100}"

echo "Configuration:"
echo "  Scale: $SCALE sites"
echo "  Duration: $DURATION seconds"
echo "  Concurrency: $CONCURRENCY"
echo ""

# Build in release mode
echo "Building release binary..."
cargo build --release

# Run criterion benchmarks
echo ""
echo "Running performance benchmarks..."
cargo bench

# Run load tests
echo ""
echo "Running scale tests..."
cargo test --release --test load_test -- --test-threads=1 --nocapture

# Memory profiling
echo ""
echo "Running memory profiling..."
valgrind --tool=massif --massif-out-file=massif.out \
    target/release/patronus-sdwan &
PID=$!

sleep 30
kill $PID

ms_print massif.out | head -50

# CPU profiling
echo ""
echo "Running CPU profiling..."
perf record -g target/release/patronus-sdwan &
PID=$!

sleep 30
kill $PID

perf report --stdio | head -50

echo ""
echo "=== Load Testing Complete ==="
```

**Load Test Scenarios**:

1. **Mesh Scaling** (`tests/load/scenarios/mesh_scaling.rs`)
   - 100, 500, 1000, 2000 sites
   - Full mesh connectivity
   - Measure setup time, memory usage

2. **Path Selection** (`tests/load/scenarios/path_selection.rs`)
   - 10k, 50k, 100k paths
   - Concurrent path selection
   - Measure latency, throughput

3. **Health Monitoring** (`tests/load/scenarios/health_monitoring.rs`)
   - 1000 paths, 5-minute duration
   - Concurrent health checks
   - Measure check latency, database load

4. **Failover Storm** (`tests/load/scenarios/failover_storm.rs`)
   - 100 paths failing simultaneously
   - Measure failover time, recovery time

5. **Metrics Export** (`tests/load/scenarios/metrics_export.rs`)
   - Export metrics for 1000 paths
   - Prometheus and JSON formats
   - Measure export latency, memory

---

## Technical Approach

### Testing Strategy

1. **Unit Tests**: Already covered (121 passing)
2. **Integration Tests**: Test multi-component scenarios
3. **Load Tests**: Validate scale requirements
4. **Stress Tests**: Find breaking points
5. **Soak Tests**: Long-running stability validation

### Performance Targets

| Metric | Target | Load Test Validates |
|--------|--------|---------------------|
| Mesh setup (1000 sites) | <30s | ✅ |
| Path selection | <50μs | ✅ |
| Health check (1000 paths) | <10s | ✅ |
| Failover latency | <100ms | ✅ |
| Memory per site | <1MB | ✅ |
| Metrics export | <100ms | ✅ |

### Documentation Standards

All documentation will follow:
- **Clear structure**: TOC, sections, subsections
- **Step-by-step**: Numbered procedures
- **Examples**: Real commands and outputs
- **Troubleshooting**: Common issues and solutions
- **Cross-references**: Links to related docs

---

## Risk Assessment

### Low Risk ✅
- **Documentation**: No code changes, low risk
- **Load testing**: Catches issues before production
- **CI/CD**: Standard industry practices

### Medium Risk ⚠️
- **Performance tuning**: Could introduce regressions
  - **Mitigation**: Test thoroughly, document baselines
- **DR procedures**: Untested recovery could fail
  - **Mitigation**: Test all procedures in staging

---

## Dependencies

### Required

- ✅ Sprint 32 complete (real network probing)
- ✅ All tests passing (121/121)
- ✅ Clean build

### External

- GitHub Actions (CI/CD) - Free for public repos
- Docker Hub or registry (image hosting)
- Criterion.rs (benchmarking) - Already used
- Optional: Valgrind, perf (profiling)

---

## Success Metrics

### Quantitative

- ✅ Operations runbook >50 pages
- ✅ DR procedures covering 5+ scenarios
- ✅ Load tests passing at 1000+ sites
- ✅ CI/CD with <10min build time
- ✅ OpenAPI spec covering 100% of REST API
- ✅ Performance tuning guide with 10+ optimizations

### Qualitative

- ✅ Confidence in production deployment
- ✅ Clear escalation procedures
- ✅ Proven at scale (1000+ nodes)
- ✅ Automated testing and deployment
- ✅ Complete API documentation

---

## Timeline

### Day 1
- ✅ Sprint 33 planning (this document)
- ✅ Operations runbook (50%)
- ✅ Disaster recovery procedures (draft)

### Day 2
- ✅ Operations runbook (complete)
- ✅ Disaster recovery procedures (complete + scripts)
- ✅ Performance tuning guide (50%)

### Day 3
- ✅ Performance tuning guide (complete)
- ✅ CI/CD pipeline setup
- ✅ OpenAPI documentation (50%)

### Day 4
- ✅ OpenAPI documentation (complete)
- ✅ Load testing framework
- ✅ Load test scenarios (50%)

### Day 5
- ✅ Load test scenarios (complete)
- ✅ Run full load test suite
- ✅ Sprint 33 summary and documentation
- ✅ Update PROJECT_STATUS.md

---

## Next Steps After Sprint 33

With operational maturity established, good options include:

1. **Sprint 34: Multi-Tenancy** - Enable SaaS business model
2. **Sprint 34: Kubernetes Operator** - Cloud-native deployment
3. **Sprint 34: Advanced Networking** - BGP, advanced QoS
4. **Production Deployment** - Deploy to production with confidence

---

## Questions for Stakeholders

1. **Deployment target**: Where will this be deployed? (Cloud, on-prem, hybrid)
2. **Scale requirements**: What's the target node count? (We'll test 1000+)
3. **CI/CD platform**: GitHub Actions OK? (Alternative: GitLab CI, Jenkins)
4. **Image registry**: Docker Hub? (Alternative: ECR, GCR, private registry)
5. **Monitoring**: What monitoring system is in place? (Prometheus assumed)

---

**Sprint Owner**: Development Team
**Start Date**: 2025-10-11
**Target Completion**: 2025-10-16
**Status**: Planning Complete, Ready to Execute
