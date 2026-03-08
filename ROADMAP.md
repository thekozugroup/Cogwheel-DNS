# Cogwheel Roadmap (Product Reset)

This roadmap replaces the previous plan.

## Product Vision

Build a Rust-native DNS adblock platform that feels as simple as an Apple product:

- Server backend runs in Docker.
- GUI uses `shadcn/ui` for a polished frontend while the backend stays Rust.
- User-facing setup is intentionally minimal: only blocklists and classifier settings.
- Real-time classifier runs in the background and improves protection without breaking browsing.
- Multi-node sync keeps settings consistent.
- Optional Tailscale exit-node mode routes tailnet traffic through Cogwheel DNS filtering.

## UX Contract (non-negotiable)

Primary controls exposed to users:

- `Blocklists`
  - Presets: `Essential`, `Balanced`, `Aggressive`.
  - Optional custom list URLs.
- `Service Toggles` (optional feature)
  - Easy allow/block toggles for common services and platforms.
  - Examples: allow Google Ads only, block TikTok, Snapchat, Nintendo services.
  - Backed by curated service-specific rule bundles and exceptions.
- `Classifier`
  - Mode: `Off`, `Monitor`, `Protect`.
  - Sensitivity: `Low`, `Balanced`, `High`.

Everything else stays auto-managed with safe defaults (hidden behind advanced diagnostics).

## System Architecture (All Rust)

Suggested workspace layout:

- `crates/cogwheel-dns-core` - DNS request/response pipeline and cache.
- `crates/cogwheel-policy` - rule model, precedence, and block action resolution.
- `crates/cogwheel-lists` - fetch, parse, normalize, verify, compile blocklists.
- `crates/cogwheel-services` - curated service/category bundles, exceptions, and toggle manifests.
- `crates/cogwheel-classifier` - feature extraction, model inference, risk scoring.
- `crates/cogwheel-sync` - node-to-node config sync and conflict resolution.
- `crates/cogwheel-storage` - SQLx models, migrations, repositories.
- `crates/cogwheel-api` - API types and handlers.
- `apps/cogwheel-server` - Dockerized backend runtime.
- `apps/cogwheel-web` - `shadcn/ui` frontend for settings, status, and recovery flows.
- `apps/cogwheel-desktop` - optional Tauri shell for native packaging around the web UI.

Core stack:

- DNS: `hickory` ecosystem.
- Async runtime: `tokio`.
- API: `axum`.
- Storage: `sqlx` + SQLite (v1), Postgres optional later.
- Caching: `moka`.
- GUI: `shadcn/ui` + React, with optional Tauri wrapper for desktop distribution.
- Observability: `tracing` + Prometheus metrics.

Rust-specific optimization/functionality tracks to lean into:

- Zero-copy parsing and compact domain/rule representations to reduce allocation pressure.
- Lock-aware concurrency with task isolation for DNS path vs update/classifier work.
- Compile-time typed configs, migrations, and API contracts to reduce runtime misconfiguration.
- Fast-path caches and prefix/suffix matching structures specialized for domain lookups.
- Optional SIMD-accelerated lexical feature extraction and string scoring.
- Optional eBPF/XDP sidecars or Rust-driven integrations for Linux fast-path monitoring later.

## Phase 0 - Reset and Product Guardrails

Goal: Lock the new product direction and remove plan ambiguity.

- [x] Replace previous roadmap with this reset plan and align all docs.
- [x] Define product principles: simplicity-first, safe-defaults, modular internals.
- [x] Document strict UX limits: only two primary user settings surfaces.
- [ ] Define reliability and latency budgets for DNS hot path.
- [ ] Create architecture decision records (ADRs) for crate boundaries.

Exit criteria:

- Team agrees on scope and constraints.
- No conflicting architecture docs remain.

## Phase 1 - Rust Monorepo Foundation

Goal: Establish clean modular boundaries and delivery pipeline.

- [x] Initialize Cargo workspace with all crates/apps listed above.
- [x] Add CI: `fmt`, `clippy`, tests, security checks (`cargo audit`, `cargo deny`).
- [ ] Add typed config layer with environment profiles (`dev`, `home`, `smb`).
- [x] Add migration framework and initial schema (`sources`, `rulesets`, `settings`, `audit_events`).
- [x] Add tracing, request IDs, and Prometheus endpoint.
- [x] Add shared error model and API error envelope across crates.
- [x] Define internal performance guidelines for Rust implementations (allocation budget, lock contention, clone minimization, bounded async queues).

Exit criteria:

- Workspace builds and tests pass.
- Modules compile independently with clean interfaces.

## Phase 2 - DNS Server Backend (Docker MVP)

Goal: Production-capable DNS filtering backend running in Docker.

- [x] Implement UDP/TCP listeners and upstream forwarding.
- [x] Add deterministic policy pipeline (allow/deny/rewrite).
- [ ] Implement cache layers (L1 in-process + resilient L2 fallback cache).
- [x] Implement block response modes (`null_ip`, `nxdomain`, `nodata`, `refused`, `custom_ip`).
- [ ] Add bounded recursive CNAME uncloaking for canonical-domain matching.
- [x] Add `/health/live`, `/health/ready`, and metrics endpoints.
- [x] Build Docker image (multi-stage) and Compose profile for Linux host networking.

Exit criteria:

- DNS backend is stable under normal home-lab load.
- Restart and recovery are predictable.

## Phase 3 - Blocklist Engine With Safe Updates

Goal: Make list updates safe, auditable, and user-invisible.

- [x] Implement source registry and scheduler.
- [x] Parse domains-only, hosts-style, and Adblock-style inputs into canonical rules.
- [x] Design service-bundle manifest format for optional common-service toggles (`service_id`, display name, category, allow rules, block rules, exceptions, risk notes).
- [x] Support layered compilation so service toggles merge cleanly with core blocklists, allowlists, and user overrides.
- [x] Add verification gates (syntax, invalid ratio, volume anomaly, protected domain collisions).
- [x] Build immutable ruleset artifacts with atomic active-pointer swap.
- [x] Add automatic rollback on post-update breakage or SLO regression.
- [x] Add update status UI/API surfaces with plain-language explanations.

Current implementation notes:

- Bootstrap source registry, scheduled/manual source refresh, ruleset recording, audit events, list/ruleset/audit APIs, and rollback flows are in place.
- Remaining Phase 3 gaps are richer regression/SLO signals beyond protected-domain rollback guards.

Exit criteria:

- No partial updates can break active filtering.
- Every update is auditable and reversible.

## Phase 3.5 - Common Service Toggles (Optional)

Goal: Let users allow or block well-known services with simple toggles instead of manual rules.

- [x] Add curated service bundle support for easy allowlist/blocklist actions.
- [ ] Support per-service modes like `allow`, `block`, `inherit`, and `allow only this service subset` where applicable.
- [x] Build precedence rules so service toggles remain predictable alongside user custom rules and global lists.
- [x] Add plain-language metadata for each service toggle: what it affects, likely breakage, privacy impact.
- [ ] Expose toggles in GUI as searchable grouped controls, but keep feature optional until curated coverage is good enough.
- [ ] Add sync support so service toggle choices replicate across nodes.

Notes:

- Initial categories/services will be defined later.
- This should be shipped only when the curated manifests are reliable enough to feel trustworthy.
- Backend API support now exists for listing service manifests and updating toggle state; GUI work is still pending.

Exit criteria:

- Service toggles compile into deterministic rulesets.
- Users can change common-service behavior without writing domains manually.

## Phase 4 - Real-Time Classifier (Background First)

Goal: Add AI-driven detection without compromising DNS latency.

- [ ] Implement lexical features (`entropy`, length, depth, digit/hyphen density, n-grams).
- [ ] Implement behavioral features (query burst patterns, temporal rarity, client-level novelty).
- [ ] Start with lightweight models (`LightGBM` or `RandomForest`) in Rust-serving path.
- [ ] Run classifier asynchronously in `Monitor` mode first (no hard blocking).
- [ ] Add confidence thresholds and fallback to deterministic policy when uncertain.
- [ ] Add model explainability payload (`top features`, confidence, reason code).
- [ ] Add drift detection and retrain triggers from live feature distributions.

Exit criteria:

- Classifier stays within latency budget in background operation.
- False-positive rate is within release budget before `Protect` default is considered.

## Phase 5 - Apple-Like `shadcn/ui` GUI

Goal: Deliver a highly polished, low-cognitive-load GUI with a Rust backend.

- [ ] Build onboarding wizard: discover server, verify health, finish in under 2 minutes.
- [ ] Create single-home dashboard with clear states: `Protected`, `Updating`, `Needs Attention`.
- [ ] Expose only the two primary settings groups: blocklists and classifier.
- [ ] Add optional `Services` view for curated allow/block toggles without exposing raw DNS complexity.
- [ ] Add one-click safe actions: `Pause 10m`, `Rollback`, `Trust Domain`.
- [ ] Add guided issue recovery flows (no jargon, plain language).
- [ ] Implement local-first UX: app remains useful during temporary server disconnects.
- [ ] Build the UI with `shadcn/ui` components and a tightly constrained design system for Apple-like clarity.
- [ ] Evaluate optional Tauri packaging for native desktop distribution without moving backend logic out of Rust.
- [ ] Add accessibility and high-clarity typography/spacing QA checklist.

Exit criteria:

- New user can install, connect, and block ads with near-zero manual tuning.
- App flows pass usability testing with non-technical users.

## Phase 6 - Node Sync (Settings Replication)

Goal: Keep multiple Cogwheel nodes in sync safely.

- [ ] Implement node identity (`ed25519`) and signed sync envelopes.
- [ ] Sync only required state: blocklists, classifier config, allowlist/denylist overrides, versioned settings.
- [ ] Add deterministic conflict resolution (`revision + vector clock` or server-authoritative mode).
- [ ] Add selective replication profiles (`full`, `settings-only`, `read-only follower`).
- [ ] Add encrypted transport and replay protection.
- [ ] Add health/status view in GUI for each node.

Exit criteria:

- Config changes propagate predictably across nodes.
- Conflicts are visible and recoverable without manual DB edits.

## Phase 7 - Tailscale Exit-Node Integration

Goal: Make Cogwheel the DNS enforcement layer for tailnet exit-node traffic.

- [ ] Add server-side integration module for `tailscaled` detection and health checks.
- [ ] Implement setup flow to enable exit-node mode and bind Cogwheel as DNS resolver.
- [ ] Add DNS interception policy for `tailscale0` traffic so queries route through Cogwheel.
- [ ] Add safe rollback flow that restores prior Tailscale DNS/exit-node settings.
- [ ] Add GUI status card: `Exit Node Active`, `Tailnet Clients`, `Filtered Queries`, `Bypass Alerts`.
- [ ] Add test harness for tailnet scenarios (client -> exit node -> filtered DNS).

Exit criteria:

- Tailnet client traffic using exit node is filtered consistently.
- Enabling/disabling exit-node mode is one guided action with reliable rollback.

## Phase 8 - Hardening, Performance, and Reliability

Goal: Reach stable beta quality for real-world always-on use.

- [ ] Run load and soak tests (mixed cache hit/miss and update windows).
- [ ] Add strict false-positive budget gates for release candidates.
- [ ] Add resilience drills: upstream outage, DB corruption simulation, failed list source, sync partition.
- [ ] Implement backup/restore and automated recovery checks.
- [ ] Add abuse protections and rate limiting on management APIs.
- [ ] Benchmark Rust-specific optimizations: compact rule storage, matcher hot paths, async task partitioning, and optional SIMD feature extraction.
- [ ] Benchmark optional Linux fast path (`eBPF`/`XDP`) as future optimization track.

Exit criteria:

- Service meets latency and reliability SLOs in 24/7 testing.
- Recovery runbook is validated end to end.

## Phase 9 - GA and Ecosystem

Goal: Ship a stable v1 and establish maintainable evolution.

- [ ] Finalize versioned config schema and migration compatibility policy.
- [ ] Publish operator docs and user docs with quick-start paths.
- [ ] Add plugin interface for optional threat-intel providers.
- [ ] Add optional privacy-preserving federated-learning interface (model updates only, no raw logs).
- [ ] Define release cadence, LTS/support windows, and contribution model.

Exit criteria:

- GA checklist complete.
- Documentation and support policy are production-ready.

## Cross-Phase Quality Gates

- [ ] Keep DNS hot path deterministic and LLM-independent.
- [ ] Track latency budgets for cache hit/miss and classifier processing.
- [ ] Enforce audit logging on every policy-changing action.
- [ ] Require rollback path for every deployment-affecting feature.
- [ ] Keep default user-facing settings minimal and understandable.
- [ ] Preserve modular crate boundaries; avoid cross-crate coupling drift.
