# ADR 0001: Crate Boundaries and Ownership

## Status

Accepted

## Context

Cogwheel is a Rust monorepo with a DNS fast path, control-plane APIs, sync flows, and operator-facing UI. The roadmap already fixes the intended workspace layout, but the project still needs an explicit architecture decision record describing which crate owns which responsibility so future work does not blur boundaries or reintroduce coupling.

The most important constraint is that the DNS serving path stays deterministic, low-allocation, and operational even when control-plane or background jobs fail.

## Decision

The workspace uses the following crate ownership model:

- `crates/cogwheel-dns-core`
  - Owns DNS request parsing, response generation, cache access, upstream forwarding, and deterministic runtime stats.
  - Must not depend on web/UI concerns.
- `crates/cogwheel-policy`
  - Owns rule precedence, allow/deny/rewrite resolution, and compiled policy decisions.
  - Exposes pure decision primitives consumed by the DNS path.
- `crates/cogwheel-lists`
  - Owns blocklist fetch, parse, normalize, verify, compile, and staged activation workflows.
  - Produces artifacts that can be consumed by policy/runtime code without network access.
- `crates/cogwheel-services`
  - Owns curated service bundles, service toggles, and exception manifests.
  - Must compile down to policy-compatible artifacts rather than bypass policy rules.
- `crates/cogwheel-classifier`
  - Owns feature extraction, model inference, and risk scoring.
  - May inform control or monitor paths, but must not make the DNS hot path non-deterministic.
- `crates/cogwheel-sync`
  - Owns node identity, signed envelopes, revision conflict resolution, replication profiles, and replay protection.
  - Must remain transport-agnostic from the perspective of the rest of the workspace.
- `crates/cogwheel-storage`
  - Owns migrations, SQLx repositories, persistence models, and audit-event writes.
  - Provides storage-facing APIs for higher layers; schema details stay encapsulated here.
- `crates/cogwheel-api`
  - Owns shared API request/response types, envelopes, and API-facing validation contracts.
  - Must not own runtime orchestration or direct storage side effects.
- `apps/cogwheel-server`
  - Owns process wiring, configuration loading, route registration, background task orchestration, and runtime composition.
  - Acts as the integration boundary for all crates above.
- `apps/cogwheel-web`
  - Owns operator UI and advanced diagnostics.
  - Talks to the backend only through typed API contracts.
- `apps/cogwheel-desktop`
  - Optional packaging layer for native distribution around the web UI.
  - Must not fork core backend logic.

## Boundary Rules

- The DNS hot path must not depend directly on frontend, HTTP, or storage migration details.
- Background update, classifier, sync, and resilience tasks must degrade without taking down DNS serving.
- Cross-crate sharing should prefer typed contracts and compiled artifacts over leaking internal structs.
- New features should land in a library crate first when they introduce reusable domain behavior; app crates should mostly compose existing crates.
- Policy-changing actions must continue to flow through storage-backed audit logging regardless of which surface triggers them.

## Consequences

- Future refactors have a documented default boundary to follow.
- The workspace remains easier to test because domain logic stays in crates and app crates mostly orchestrate.
- Some short-term duplication may remain acceptable if it prevents DNS-path coupling to control-plane code.
- If a feature needs to cross these boundaries, a new ADR is required instead of ad hoc coupling.
