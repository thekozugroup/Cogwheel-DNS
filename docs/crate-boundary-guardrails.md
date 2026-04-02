# Crate Boundary Guardrails

Cogwheel keeps a small, explicit path-dependency graph between crates so the DNS core, storage, sync, and control-plane layers do not gradually collapse into one another.

Current guardrails:

- `docs/adr/0001-crate-boundaries.md` defines crate ownership and allowed responsibilities.
- `crates/cogwheel-api/src/lib.rs` includes a regression test that reads key crate manifests and fails if their path dependencies drift away from the ADR-approved graph.
- Any intentional boundary change should update the ADR first, then update the regression test in the same change.

The guard currently checks these crate relationships:

- `cogwheel-dns-core` -> `cogwheel-classifier`, `cogwheel-policy`
- `cogwheel-classifier` -> none
- `cogwheel-lists` -> `cogwheel-policy`, `cogwheel-services`
- `cogwheel-services` -> `cogwheel-policy`
- `cogwheel-storage` -> `cogwheel-policy`
- `cogwheel-sync` -> none
- `cogwheel-api` -> none

This keeps the fast path deterministic, the storage layer encapsulated, and app crates responsible for composition rather than leaking domain concerns across the workspace.
