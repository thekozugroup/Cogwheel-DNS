# ADR 0001: Crate Boundaries and Ownership

## Status

Accepted. Revised when the workspace was cut down to the DNS-filtering core;
the previous version of this record, and the crates it described, are on the
`archive/full-featured` branch.

## Context

Cogwheel is a Rust workspace with one hot path (answering DNS queries) and one
control plane (an HTTP API and a React UI that configure it). The hot path must
stay deterministic, low-allocation and able to keep answering when a background
job fails: a blocklist refresh, a storage write, a browser holding an event
stream open. Recording which crate owns which responsibility is what keeps that
path from quietly growing dependencies on the control plane.

## Decision

The workspace has five library crates, one binary and one web app:

- `crates/cogwheel-policy`
  - Owns the rule model (`Rule`, `RulePattern`, `RuleAction`), the compiled
    `RulesetArtifact`, `PolicyEngine::evaluate`, `BlockMode`, domain
    normalisation and the `PROTECTED_SUFFIXES` safety net.
  - Pure: no I/O and no path dependencies. Everything else that filters is
    built on it.
- `crates/cogwheel-lists`
  - Owns blocklist fetch, parse (`domains`, `hosts`, Adblock), verification and
    compilation into a `PolicyEngine`.
  - Control plane only: it talks HTTP, so it is never on the DNS path.
  - Depends on `cogwheel-policy`.
- `crates/cogwheel-dns-core`
  - Owns the UDP/TCP listeners, request parsing, per-client policy selection,
    the TTL-aware response cache, CNAME uncloaking, upstream forwarding, the
    pause switch and the runtime counters.
  - Depends on `cogwheel-policy` only. Must not depend on HTTP clients, storage
    or the web app; a test in the crate enforces the first.
- `crates/cogwheel-storage`
  - Owns the SQLite schema, migrations, the `sources`, `devices` and
    `settings` repositories, and history pruning. Schema details stay inside it.
  - No path dependencies.
- `crates/cogwheel-api`
  - Owns environment configuration (`AppConfig`), the `ApiEnvelope` response
    shape, the readiness tracker, the `/health/*` routes and the upstream
    endpoint parser.
  - No path dependencies; no runtime orchestration or storage side effects.
- `apps/cogwheel-server`
  - Owns process wiring, route registration, the refresh scheduler, the
    retention task, the SSE event bus and every `/api/v1` handler.
  - The only crate allowed to depend on all of the above.
- `apps/cogwheel-web`
  - Owns the operator UI. Talks to the server only through the typed client in
    `src/lib/api.ts`.

## Boundary Rules

- The DNS hot path depends on `cogwheel-policy` and nothing else in the
  workspace.
- Blocklist refreshes, storage writes and event-stream fan-out degrade without
  taking DNS serving down: a failed refresh keeps the policy already in force,
  and a slow event subscriber loses frames rather than slowing resolution.
- A candidate policy that would block a protected name is refused before
  activation; nothing rolls a live policy back after the fact.
- Cross-crate sharing prefers compiled artifacts (`PolicyEngine`,
  `RulesetArtifact`) over leaking internal structs.
- Reusable domain behaviour lands in a library crate; the server composes.
- Any change to the path-dependency graph updates this ADR first and the
  regression test in `crates/cogwheel-api/src/lib.rs`
  (`crate_path_dependencies_match_the_adr_boundaries`) in the same change.

## Consequences

- Refactors have a documented default boundary to follow.
- Domain logic stays testable in isolation because the crates carry no process
  wiring.
- A feature that needs to cross these boundaries needs a new ADR, not ad hoc
  coupling.
