## Reliability and Latency Budgets

This document defines the operational budgets for Cogwheel's DNS hot path.

## Reliability Targets

- Availability: 99.95% monthly for the DNS responder in steady-state home-lab and SMB deployments.
- Safe update success rate: 99.9% of scheduled source refreshes either promote a verified ruleset or automatically retain the previous active ruleset.
- Recovery objective: restart to ready within 30 seconds with the last known-good ruleset available.
- Rollback objective: operator-triggered or automatic rollback completes within 60 seconds and records an audit event.
- Control-plane degradation rule: dashboard/API failures must not stop the DNS data plane from serving cached or forwarded responses.

## DNS Hot Path Latency Budgets

Budgets are measured at the server process for a single DNS lookup under normal load.

| Path | Target p50 | Target p95 | Target p99 |
| --- | --- | --- | --- |
| Cache hit | <= 1 ms | <= 4 ms | <= 8 ms |
| Cache miss, deterministic policy only | <= 8 ms | <= 25 ms | <= 60 ms |
| Cache miss with classifier monitor path | <= 10 ms | <= 30 ms | <= 75 ms |
| Control-plane reads (dashboard/status APIs) | <= 50 ms | <= 150 ms | <= 300 ms |

## Resource Budgets

- Per-query heap allocations on the deterministic path should stay bounded and minimized; new features should justify any hot-path allocation growth.
- Background jobs (source refresh, sync import/export, resilience drills, benchmarks) must not block UDP/TCP request handling.
- Lock contention must remain off the DNS fast path wherever practical; shared state should prefer snapshotting or dedicated caches.

## Error Budgets

- Upstream resolution failure rate: < 0.5% over a rolling 24-hour window, excluding injected resilience drills.
- False-positive release budget: <= 0.1% estimated false positives for release candidates.
- Audit coverage budget: 100% of policy-changing actions must emit an audit record.

## Measurement Sources

- Runtime DNS statistics and health endpoints in `apps/cogwheel-server`.
- Phase 8 load/soak test API and Rust optimization benchmark endpoints.
- False-positive budget API and resilience drill endpoints.
- Operator spot checks from `docs/operator-quickstart.md`.

## Enforcement Guidance

- New features that affect request handling must state whether they run on the deterministic path, monitor path, or background path.
- Any feature that threatens these budgets must ship with a rollback path and an operator-readable dashboard signal.
- Changes that materially alter these numbers should update this document and `ROADMAP.md` in the same commit.
