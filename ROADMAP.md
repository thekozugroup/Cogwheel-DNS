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
- [x] Define reliability and latency budgets for DNS hot path.
- [x] Create architecture decision records (ADRs) for crate boundaries.

Exit criteria:

- Team agrees on scope and constraints.
- No conflicting architecture docs remain.

## Phase 1 - Rust Monorepo Foundation

Goal: Establish clean modular boundaries and delivery pipeline.

- [x] Initialize Cargo workspace with all crates/apps listed above.
- [x] Add CI: `fmt`, `clippy`, tests, security checks (`cargo audit`, `cargo deny`).
- [x] Add typed config layer with environment profiles (`dev`, `home`, `smb`).
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
- [x] Implement cache layers (L1 in-process + resilient L2 fallback cache).
- [x] Implement block response modes (`null_ip`, `nxdomain`, `nodata`, `refused`, `custom_ip`).
- [x] Add bounded recursive CNAME uncloaking for canonical-domain matching.
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
- Remaining Phase 3 gaps are richer long-window regression/SLO signals beyond the current runtime guard probes and protected-domain rollback guards, though fallback/CNAME counters and runtime health APIs are now exposed for observability.
- Dashboard/settings summary APIs now exist to support future `shadcn/ui` control-plane flows without direct database access.
- Blocklist sources are now create/update/disable/delete-able through backend settings APIs, including optional immediate refresh into active rulesets and editable schedule/profile/verification metadata. Settings summaries also expose refresh status for scheduler-aware UI flows.

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

## Phase 3.6 - Device Awareness and Per-Device Policy

Goal: Let operators name devices, understand device-level risk, and optionally override the global policy for specific devices.

- [x] Persist named devices with stable identifiers such as IP address and user-friendly labels.
- [x] Support per-device policy mode (`global` by default, `custom` when overridden).
- [x] Support per-device blocklist/profile override while keeping the default model global-first.
- [x] Record and expose risky DNS events with device attribution and severity.
- [x] Add notification hooks for risky events and degraded device-level activity.

Current implementation notes:

- Backend storage and API scaffolding now exist for named devices, device policy metadata, and recent security events.
- The web control plane now includes device naming/editing, device policy override inputs, and operator-facing security event visibility.
- The DNS data plane now selects per-device policy catalogs in memory, scopes cache entries by effective policy, and records risky events from live query traffic with device attribution when a named device is known.
- The dashboard now surfaces alert severity rollups and top affected devices, and high-severity detections emit internal audit alerts as a first notification hook.
- External webhook delivery can now be configured from the control plane with a minimum severity threshold, using persisted notification settings and outbound alert delivery from the server.
- Webhook delivery now retries with backoff and records explicit delivery success/failure audit events for operator visibility.
- The control plane now surfaces recent webhook delivery outcomes so operators can see whether alert notifications were delivered or failed.
- The dashboard now summarizes notification delivery health with delivered/failed counters and recency, and operators can trigger a test webhook send directly from the control plane.
- Manual test sends now flow through the same delivery pipeline as production alerts, so retry behavior and recent delivery history stay representative.
- Notification analytics now call out recent success rate and the domains most often associated with failed deliveries, helping operators spot flaky destinations or payload patterns.
- Operators can now change the notification analytics window in the control plane, making it easier to compare short-term alert delivery issues with longer recent history.
- Operators can now tune notification analytics and recent delivery history windows independently, so a broad reliability trend view does not crowd out the most recent delivery trail.
- Notification test sends now support custom domain/severity/device labels plus dry-run validation so operators can verify payload shape and destination setup before sending a live test.
- Notification test presets can now be saved and reloaded from the control plane, reducing repeated manual setup for common validation scenarios.
- Saved notification test presets can now also be deleted from the control plane, keeping the validation workflow tidy as presets evolve.
- Runtime startup now attempts to warm the profile policy catalog from persisted sources, and rollback rebuilds profile policies while restoring the selected global artifact.
- Devices with custom policy mode can now bypass blocking entirely in addition to selecting a profile override, giving the control plane a richer per-device policy surface.
- Devices with custom policy mode can now carry per-device allowed-domain lists, letting selected domains bypass blocking for a specific device without changing the global profile.
- Devices with custom policy mode can now carry per-device service overrides that expand into device-specific allow/block behavior using the built-in service manifest catalog.
- The device editor now shows service overrides with friendly manifest labels in both edit chips and saved-device summaries, making per-device service policy easier to review.
- Device service override summaries now expose manifest category and risk notes inline, so operators can understand why each per-device service rule exists without cross-referencing the global services panel.
- The device editor now previews service override domain expansion before saving and blocks no-op additions when a service cannot produce device-specific rules for the selected mode.
- Device upsert APIs now reject invalid service override payloads with operator-readable errors, keeping custom per-device policy data consistent even outside the web editor.
- Remote notifications now cover refresh rejections plus manual and automatic rollback events, extending webhook visibility beyond risky-domain security alerts.
- Notification delivery history now distinguishes security alerts from control-plane events with explicit event-type and target labels in the dashboard.
- Operators can now trigger an active runtime health check from the control plane, recording pass/fail audit events and sending a webhook notification when the runtime is degraded.

## Phase 4 - Real-Time Classifier (Background First)

Goal: Add AI-driven detection without compromising DNS latency.

- [ ] Implement lexical features (`entropy`, length, depth, digit/hyphen density, n-grams).
- [ ] Implement behavioral features (query burst patterns, temporal rarity, client-level novelty).
- [ ] Start with lightweight models (`LightGBM` or `RandomForest`) in Rust-serving path.
- [ ] Run classifier asynchronously in `Monitor` mode first (no hard blocking).
- [ ] Add confidence thresholds and fallback to deterministic policy when uncertain.
- [ ] Add model explainability payload (`top features`, confidence, reason code).
- [ ] Add drift detection and retrain triggers from live feature distributions.

Current implementation notes:

- Classifier settings are now persisted in backend storage and exposed through settings/update APIs for future GUI control.
- Remaining work is focused on stronger models, behavioral features, richer explainability, and production-quality rollout logic.

Exit criteria:

- Classifier stays within latency budget in background operation.
- False-positive rate is within release budget before `Protect` default is considered.

## Phase 5 - Apple-Like `shadcn/ui` GUI

Goal: Deliver a highly polished, low-cognitive-load GUI with a Rust backend.

- [x] Build onboarding flow: dashboard-integrated setup checklist helps operators configure the server, verify health, and finish in under 2 minutes.
- [x] Create single-home dashboard with clear states: `Protected`, `Updating`, `Needs Attention`.
- [x] Expose only the two primary settings groups: blocklists and classifier.
- [x] Add optional `Services` view for curated allow/block toggles without exposing raw DNS complexity.
- [x] Add one-click safe actions: `Pause 10m`, `Rollback`, `Trust Domain`.
- [x] Add guided issue recovery flows (no jargon, plain language).
- [x] Implement local-first UX: app remains useful during temporary server disconnects.
- [x] Build the UI with `shadcn/ui` components and a tightly constrained design system for Apple-like clarity.
- [ ] Evaluate optional Tauri packaging for native desktop distribution without moving backend logic out of Rust.
- [ ] Add accessibility and high-clarity typography/spacing QA checklist.

Current implementation notes:

- Backend summaries already exist for future UI consumption: dashboard, settings, services, runtime health, rulesets, and audit events.
- Classifier settings are already editable via backend API, so the future UI can wire directly into persisted control-plane state.
- Blocklist source management is also API-editable, including schedule/profile/verification metadata and refresh status, so the future UI can manage blocklists without low-level database access.
- A Vite + React + shadcn-style frontend scaffold now exists in `apps/cogwheel-web` with live dashboard/settings/service/blocklist flows wired to the current backend APIs.
- The current UI already supports classifier editing, blocklist lifecycle and metadata editing, and searchable service toggles; remaining work is polish, onboarding, recovery UX, and local-first behavior.
- The operator feed now supports quick runtime/notification/device/ruleset filtering, making the current dashboard easier to triage while broader Phase 5 simplification work remains open.
- The home dashboard now calls out a single control-plane state (`Protected`, `Updating`, `Paused`, or `Needs attention`) and suggests the next recovery action inline so operators can react without scanning every panel.
- The home view now includes direct jump links into overview, recovery, settings, blocklists, and device sections so the dashboard acts as a true single-home control surface.
- A one-click "Pause 10m" action on the dashboard now globally bypasses all DNS blocking policies for temporary troubleshooting.
- The onboarding wizard is now integrated directly into the dashboard as a "Setup checklist", avoiding an intrusive modal flow while maintaining clear first-run goals.
- Local-first UX caching is now implemented, persisting dashboard and settings states to `localStorage` so the UI remains fully rendered and useful even if the control plane drops offline briefly.
- Added visual trend lines for notification deliveries, showing a sparkline of recent success/failure payloads directly on the dashboard.
- Remaining work is the actual `shadcn/ui` application, richer operator workflows, and client-side state management.

Exit criteria:

- New user can install, connect, and block ads with near-zero manual tuning.
- App flows pass usability testing with non-technical users.

## Phase 6 - Node Sync (Settings Replication)

Goal: Keep multiple Cogwheel nodes in sync safely.

Implementation notes:
- The storage layer now automatically generates and persists an `ed25519` keypair (`node_identity_v1`) on first boot, providing a stable cryptographical identity for future peer-to-peer sync envelopes.
- Sync imports now enforce deterministic conflict resolution using `revision` ordering with node public-key tie-breakers, and reject stale envelopes with HTTP 409.
- Sync replication now supports explicit profiles (`full`, `settings-only`, `read-only-follower`) and blocks stale/replayed envelopes using signed nonce + timestamp checks.
- The dashboard now shows per-node sync health including local identity, active profile, revision, replay-cache size, transport mode, and recently imported peers.
- Operators can now update sync replication profile and transport hardening mode directly from the dashboard without leaving the main control surface.

- [x] Implement node identity (`ed25519`) and signed sync envelopes.
- [x] Sync only required state: blocklists, classifier config, allowlist/denylist overrides, versioned settings.
- [x] Add deterministic conflict resolution (`revision + vector clock` or server-authoritative mode).
- [x] Add selective replication profiles (`full`, `settings-only`, `read-only follower`).
- [x] Add encrypted transport and replay protection.
- [x] Add health/status view in GUI for each node.

Exit criteria:

- Config changes propagate predictably across nodes.
- Conflicts are visible and recoverable without manual DB edits.

## Phase 7 - Tailscale Exit-Node Integration

Goal: Make Cogwheel the DNS enforcement layer for tailnet exit-node traffic.

- [x] Add server-side integration module for `tailscaled` detection and health checks.
- [x] Implement setup flow to enable exit-node mode and bind Cogwheel as DNS resolver.
- [x] Add DNS interception policy for `tailscale0` traffic so queries route through Cogwheel.
- [x] Add safe rollback flow that restores prior Tailscale DNS/exit-node settings.
- [x] Add GUI status card: `Exit Node Active`, `Tailnet Clients`, `Filtered Queries`, `Bypass Alerts`.
- [x] Add test harness for tailnet scenarios (client -> exit node -> filtered DNS).

Exit criteria:

- Tailnet client traffic using exit node is filtered consistently.
- Enabling/disabling exit-node mode is one guided action with reliable rollback.

## Phase 8 - Hardening, Performance, and Reliability

Goal: Reach stable beta quality for real-world always-on use.

- [x] Run load and soak tests (mixed cache hit/miss and update windows).
- [x] Add strict false-positive budget gates for release candidates.
- [x] Add resilience drills: upstream outage, DB corruption simulation, failed list source, sync partition.
- [x] Implement backup/restore and automated recovery checks.
- [x] Add abuse protections and rate limiting on management APIs.
- [x] Benchmark Rust-specific optimizations: compact rule storage, matcher hot paths, async task partitioning, and optional SIMD feature extraction.
- [x] Document optional Linux fast path (`eBPF`/`XDP`) as future optimization track (deferred to post-v1).

Exit criteria:

- Service meets latency and reliability SLOs in 24/7 testing.
- Recovery runbook is validated end to end.

## Phase 9 - GA and Ecosystem

Goal: Ship a stable v1 and establish maintainable evolution.

- [x] Finalize versioned config schema and migration compatibility policy.
- [x] Publish operator docs and user docs with quick-start paths.
- [x] Add plugin interface for optional threat-intel providers.
- [x] Add optional privacy-preserving federated-learning interface (model updates only, no raw logs).
- [x] Define release cadence, LTS/support windows, and contribution model.

Exit criteria:

- GA checklist complete.
- Documentation and support policy are production-ready.

## Cross-Phase Quality Gates

- [ ] Keep DNS hot path deterministic and LLM-independent.
- [x] Track latency budgets for cache hit/miss and classifier processing.
- [x] Enforce audit logging on every policy-changing action.
- [x] Require rollback path for every deployment-affecting feature.
- [ ] Keep default user-facing settings minimal and understandable.
- [ ] Preserve modular crate boundaries; avoid cross-crate coupling drift.

## UX Refinement Follow-Up

Goal: Make the control plane feel approachable for a household first, while keeping operator-grade controls available in a quieter settings surface.

- [x] Add overview-first navigation with quick health and recent domain activity visuals.
- [x] Add block profiles page with emoji, friendly naming, list composition, and save/edit flows.
- [x] Add devices page with clear labeling and profile assignment.
- [x] Move advanced sync, recovery, and operator controls into a dedicated settings page.
- [x] Polish navigation and overview layout into a simpler dashboard-first household view.
- [x] Refresh the responsive shell and redesign block profiles around OISD list selection plus manual GitHub lists.
- [x] Move classifier visuals and stats into a dedicated Grease-AI surface.
- [x] Add a standard-DNS install path that exposes host port 53 while keeping safe internal binds.
- [x] Nest profile source selection under blocklist settings so OISD and manual GitHub lists read as blocklist controls.
- [x] Add Tailscale installer/bootstrap support for exit-node-only traffic through Cogwheel when enabled in settings.
- [x] Restore profile-local source editing and add platform-specific connection guidance on the dashboard.
- [x] Fix new-profile drafting flow and advertise Android-friendly DNS targets alongside hostname guidance.
- [x] Advertise IPv6 DNS targets and dual-stack guidance so clients do not bypass IPv4-only filtering.
- [x] Keep the default Settings view focused on everyday household controls, with advanced operator features gated behind an explicit advanced mode.

## Phase 10 - Android Companion App

Goal: Provide a mobile companion app for Android focused on monitoring, safe controls, and remote-friendly administration.

- [ ] Define Android app scope: status visibility, blocklist/service toggles, classifier controls, audit/event viewing, and node health.
- [ ] Choose app architecture and packaging strategy (native Android vs shared shell around web control plane).
- [ ] Build secure pairing/auth flow with existing backend APIs.
- [ ] Add mobile-first dashboard and essential controls only; avoid full desktop complexity.
- [ ] Support remote notifications for degraded runtime health, failed refreshes, and rollback events.

Exit criteria:

- Android companion app can monitor and perform essential safe control-plane actions.
- Pairing, auth, and mobile UX are production-ready.

## Phase 11 - macOS Companion App

Goal: Provide a polished macOS companion app for local monitoring and control of Cogwheel nodes.

- [ ] Define macOS app scope: dashboard, blocklist management, service toggles, classifier controls, runtime health, and audit review.
- [ ] Choose packaging strategy (Tauri desktop wrapper vs dedicated native app) based on UX and maintainability.
- [ ] Add local discovery and secure pairing flow for home-network deployments.
- [ ] Support menu bar or lightweight background presence for quick status and actions.
- [ ] Add macOS-specific onboarding and system integration where it improves ease of use.

Exit criteria:

- macOS companion app offers a polished desktop control surface with reliable pairing and everyday usability.
- Distribution and update strategy are defined for non-technical users.
