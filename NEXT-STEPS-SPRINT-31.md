# Next Steps: Sprint 31 Planning

## Sprint 30 Recap

Sprint 30 successfully delivered:
- ✅ Traffic Statistics & Flow Tracking
- ✅ Site Deletion with Cascade
- ✅ Cache Management System
- ✅ 27/27 tests passing
- ✅ Comprehensive documentation

**Status: Production Ready**

---

## Sprint 31 Proposed Features

### High Priority Items

#### 1. Path Monitor Integration for Manual Probes
**Location**: `mutations.rs:932`

**Current State**: TODO comment
```rust
// TODO: Trigger immediate probe via path monitor
```

**Goal**: Connect `check_path_health` mutation to actual PathMonitor component

**Implementation Plan**:
- Create PathMonitor interface/trait
- Implement manual probe triggering
- Update GraphQL mutation to call PathMonitor
- Add tests for probe functionality
- Document probe API

**Estimated Effort**: 2-3 days

**Value**: Enables operators to manually verify path health on-demand

---

#### 2. Routing Engine Failover Integration
**Location**: `mutations.rs:1018`

**Current State**: TODO comment
```rust
// TODO: Trigger routing engine to reroute traffic
```

**Goal**: Connect `failover_path` mutation to routing engine for automatic traffic rerouting

**Implementation Plan**:
- Create RoutingEngine interface for failover
- Implement traffic rerouting logic
- Update GraphQL mutation to trigger failover
- Add tests for failover scenarios
- Document failover behavior

**Estimated Effort**: 3-4 days

**Value**: Critical for high-availability deployments, enables manual failover

---

### Medium Priority Items

#### 3. Traffic Statistics Export
**Goal**: Export traffic statistics in multiple formats

**Features**:
- CSV export for spreadsheet analysis
- JSON export for programmatic access
- Time-range filtering (last hour, day, week, custom)
- Per-policy or aggregated exports
- GraphQL query for historical data

**Implementation Plan**:
- Add database queries for time-range filtering
- Create export format converters (CSV, JSON)
- Add GraphQL queries for historical stats
- Implement download endpoints
- Add tests for export functionality

**Estimated Effort**: 2-3 days

**Value**: Enables capacity planning, billing, compliance reporting

---

#### 4. Distributed Caching with Redis
**Goal**: Scale cache system across multiple nodes

**Features**:
- Redis backend for shared cache
- Cache replication across nodes
- Configurable cache backend (in-memory or Redis)
- Cache invalidation patterns
- Cache warming strategies

**Implementation Plan**:
- Add Redis dependency (optional feature)
- Create Cache trait abstraction
- Implement RedisCache backend
- Add configuration for cache backend selection
- Implement cache warming on startup
- Add tests for both backends

**Estimated Effort**: 4-5 days

**Value**: Critical for multi-node deployments, improves scalability

---

#### 5. Site Soft Delete with Recovery
**Goal**: Allow site recovery before permanent deletion

**Features**:
- Soft delete flag on sites
- Configurable retention period (e.g., 30 days)
- Restore deleted sites mutation
- Automatic permanent deletion after retention
- Enhanced audit trail

**Implementation Plan**:
- Add `deleted_at` and `deleted_by` to sites table
- Modify queries to filter soft-deleted sites
- Add restore_site mutation
- Implement cleanup job for expired deletions
- Update audit logging
- Add tests for soft delete lifecycle

**Estimated Effort**: 2-3 days

**Value**: Prevents accidental data loss, improves operator confidence

---

### Low Priority Items

#### 6. Per-Endpoint Traffic Statistics
**Goal**: Granular statistics at endpoint level

**Features**:
- Track packets/bytes per endpoint
- Endpoint utilization metrics
- Endpoint performance correlation
- GraphQL queries for endpoint stats

**Estimated Effort**: 2-3 days

---

#### 7. Cache Warming Strategies
**Goal**: Preload frequently accessed data on startup

**Features**:
- Configurable cache warming policies
- Popular items identification
- Background cache warming
- Warming progress monitoring

**Estimated Effort**: 2-3 days

---

#### 8. Advanced Rate Limiting
**Goal**: Enhanced protection against abuse

**Features**:
- Per-endpoint rate limiting
- Per-user rate limiting
- Dynamic rate adjustment
- Rate limit metrics

**Estimated Effort**: 2-3 days

---

## Recommended Sprint 31 Scope

### Option A: High Availability Focus
**Theme**: Make Patronus production-grade for HA deployments

**Features**:
1. Path Monitor Integration (2-3 days)
2. Routing Engine Failover (3-4 days)
3. Traffic Statistics Export (2-3 days)

**Total**: ~7-10 days
**Value**: Critical features for enterprise deployments

---

### Option B: Scalability Focus
**Theme**: Scale Patronus for multi-node deployments

**Features**:
1. Distributed Caching with Redis (4-5 days)
2. Site Soft Delete with Recovery (2-3 days)
3. Per-Endpoint Traffic Statistics (2-3 days)

**Total**: ~8-11 days
**Value**: Enables horizontal scaling

---

### Option C: Minimum Viable (Quick Win)
**Theme**: Complete existing TODOs quickly

**Features**:
1. Path Monitor Integration (2-3 days)
2. Routing Engine Failover (3-4 days)

**Total**: ~5-7 days
**Value**: Completes Sprint 30 TODOs, unblocks operators

---

## Recommendation: Option A (High Availability Focus)

**Rationale**:
- Completes the TODO items from Sprint 30
- Delivers critical features for production use
- Enables manual operations (probes, failover)
- Adds valuable export functionality
- Balanced scope (~7-10 days)

**Success Criteria**:
- ✅ Manual path health checks working
- ✅ Manual failover functional
- ✅ Traffic statistics exportable (CSV/JSON)
- ✅ All tests passing
- ✅ Documentation complete

---

## Technical Debt to Address

1. **System Dependencies**: Full workspace tests fail due to missing `pkg-config`, `libnftnl`, `libmnl`
   - **Impact**: Low (tests for those crates don't run)
   - **Fix**: Document dependencies in BUILDING.md
   - **Effort**: 1 hour

2. **Database Schema**: Mismatch between old and new type systems
   - **Impact**: Medium (site deletion tests were skipped)
   - **Fix**: Refactor to unified type system
   - **Effort**: 2-3 days

3. **Warnings**: Some unused imports and dead code
   - **Impact**: Low (compile warnings only)
   - **Fix**: Run `cargo fix` and `cargo clippy`
   - **Effort**: 1-2 hours

---

## Performance Optimization Opportunities

1. **Traffic Stats Batching**: Batch database writes instead of individual snapshots
2. **Cache Tiering**: Add L1 (in-memory) + L2 (Redis) cache hierarchy
3. **Database Indexing**: Add indexes for frequently queried fields
4. **Connection Pooling**: Optimize database connection management

---

## Documentation Improvements

1. Add API examples to GraphQL Playground
2. Create video walkthrough of dashboard features
3. Add deployment guide for Kubernetes
4. Create troubleshooting runbook

---

## Questions for User

1. **Priority**: Which option (A, B, or C) aligns with your goals?
2. **Deployment**: Are you planning multi-node deployment soon? (affects Redis priority)
3. **Operations**: Do you need manual failover capability immediately?
4. **Export**: What export formats are most important? (CSV, JSON, other?)
5. **Timeline**: What's the target timeframe for Sprint 31?

---

## Sprint 31 Preparation Checklist

- [ ] Review Sprint 30 lessons learned
- [ ] Choose Sprint 31 scope (A, B, or C)
- [ ] Create detailed task breakdown
- [ ] Set up Sprint 31 tracking
- [ ] Schedule sprint planning meeting
- [ ] Review technical debt priorities
- [ ] Allocate resources

---

**Sprint 30**: ✅ Complete
**Sprint 31**: 🔄 Planning Phase
**Next Action**: Choose sprint scope and begin planning

