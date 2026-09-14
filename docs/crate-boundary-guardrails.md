# Crate Boundary Guardrails

Cogwheel keeps a small, explicit path-dependency graph between crates so the DNS
core, the storage layer and the control plane do not gradually collapse into one
another.

Current guardrails:

- `docs/adr/0001-crate-boundaries.md` defines crate ownership and allowed
  responsibilities.
- `apps/cogwheel-server/src/tests/mod.rs` includes a regression test
  (`crate_path_dependencies_match_the_adr_boundaries`) that reads each library
  crate's manifest and fails if its path dependencies drift from the graph
  below.
- Any intentional boundary change should update the ADR first, then update the
  regression test in the same change.

The guard currently checks these crate relationships:

- `cogwheel-policy` -> none
- `cogwheel-dns-core` -> `cogwheel-policy`
- `cogwheel-lists` -> `cogwheel-policy`
- `cogwheel-storage` -> none

`apps/cogwheel-server` is the composition root and depends on all four; the
guard checks that it depends on those four and nothing else.

This keeps the fast path deterministic, the storage layer encapsulated, and the
server responsible for composition rather than leaking domain concerns across
the workspace.
