# ADR 0001: Crate Boundaries and Ownership

## Status

Accepted. Revised when the workspace was cut down to the DNS-filtering core.
The crates the previous version of this record described no longer exist, and
the boundary below is the one a test enforces.

## Context

Cogwheel is a Rust workspace with one hot path (answering DNS queries) and one
control plane (an HTTP API and a React UI that configure it). The hot path must
stay deterministic, low-allocation and able to keep answering when a background
job fails: a blocklist refresh, a storage write, a browser holding an event
stream open. Recording which crate owns which responsibility is what keeps that
path from quietly growing dependencies on the control plane.

## Decision

The workspace has four library crates, one binary and one web app:

- `crates/cogwheel-policy`
  - Owns the rule model (`ListIndex`, `RuleSet`, `Scope`, `Policy`), the
    allocation-free `evaluate`, `BlockMode`, domain normalisation and the
    `PROTECTED_SUFFIXES` safety net.
  - Pure: no I/O and no path dependencies. Everything else that filters is
    built on it.
- `crates/cogwheel-lists`
  - Owns blocklist fetch, parse (`domains`, `hosts`, Adblock) and
    verification; the server compiles the parsed lists into a `ListIndex`.
  - Control plane only: it talks HTTP, so it is never on the DNS path.
  - Depends on `cogwheel-policy`.
- `crates/cogwheel-dns-core`
  - Owns the UDP/TCP listeners, request parsing, per-client policy selection,
    the TTL-aware response cache, CNAME uncloaking, upstream forwarding, the
    pause switch and the runtime counters.
  - Depends on `cogwheel-policy` only. Must not depend on HTTP clients, storage
    or the web app; a test in the crate enforces the first.
- `crates/cogwheel-storage`
  - Owns the SQLite schema, the legacy upgrade, the `sources`, `devices`,
    `rules`, `query_log` and `settings` repositories, and history pruning.
    Schema details stay inside it.
  - No path dependencies.
- `apps/cogwheel-server`
  - Owns process wiring, environment configuration (`config.rs`), the
    `ApiEnvelope` response shape and the readiness tracker (`http.rs`), route
    registration, the refresh scheduler, the retention task, the SSE event bus
    and every `/api/v1` handler.
  - The only crate allowed to depend on all of the above. These last four used
    to live in a library crate of their own; it had no path dependencies and
    exactly one consumer, so it was a directory boundary rather than a
    boundary, and it was absorbed here.
- `apps/cogwheel-web`
  - Owns the operator UI. Talks to the server only through the typed client in
    `src/lib/api.ts`.

## Boundary Rules

- The DNS hot path depends on `cogwheel-policy` and nothing else in the
  workspace.
- Blocklist refreshes, storage writes and event-stream fan-out degrade without
  taking DNS serving down: a failed refresh keeps the policy already in force,
  and a slow event subscriber loses frames rather than slowing resolution.
- A subscribed list that names a protected suffix never takes it out: protection
  is enforced inside `evaluate`, so the name stays reachable whatever the lists
  say, and the list's `note` column reports it.
- Cross-crate sharing prefers compiled artifacts (`Policy`, `ListIndex`)
  over leaking internal structs.
- Reusable domain behaviour lands in a library crate; the server composes.
- Any change to the path-dependency graph updates this ADR first and the
  regression test in `apps/cogwheel-server/src/tests/mod.rs`
  (`crate_path_dependencies_match_the_adr_boundaries`) in the same change.

## Consequences

- Refactors have a documented default boundary to follow.
- Domain logic stays testable in isolation because the crates carry no process
  wiring.
- A feature that needs to cross these boundaries needs a new ADR, not ad hoc
  coupling.
