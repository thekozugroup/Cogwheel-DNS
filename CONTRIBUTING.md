# Contributing

## Standards

- Keep DNS request-path logic deterministic and low-allocation.
- Prefer typed APIs and explicit errors over stringly typed plumbing.
- Avoid adding user-facing settings unless they are essential.
- Every policy-changing feature must emit audit records.

## Performance Guidelines

- Avoid unnecessary clones on hot path structures.
- Use bounded async queues for background work.
- Keep lock scope small and never block inside critical sections.
- Prefer compact domain/rule representations and immutable snapshots.

## Validation

Before opening a PR, run:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
```

## Release Expectations

- Keep `main` releasable with passing checks.
- Document migration and compatibility impact for API or schema changes.
- Update `docs/operator-quickstart.md` or `docs/user-quickstart.md` when behavior changes.
- Follow `docs/release-policy.md` for support windows and release criteria.
