# Release Policy

This document defines how Cogwheel ships, how long releases are supported, and how changes should land.

## Versioning

- Cogwheel uses semantic versioning for user-visible releases.
- Schema migrations and config schema versions must remain explicitly tracked.
- Breaking configuration or API changes require a documented migration path before release.

## Release Channels

- `main`: active integration branch with passing CI required
- `beta`: release-candidate builds for broader operator validation
- `stable`: production-ready tagged releases

## Cadence

- Patch releases: as needed for regressions, reliability fixes, and security issues
- Minor releases: roughly every 4 to 6 weeks while the product is evolving quickly
- Major releases: only when compatibility guarantees or operator workflows materially change

## Support Windows

- Latest stable release: full support for fixes and documentation updates
- Previous stable minor release: security and critical regression fixes for 90 days after the next stable minor release
- Beta builds: best-effort only, no long-term support guarantee

## Security Response

- Critical vulnerabilities should be patched in the latest stable line first.
- If feasible, the previous supported stable line receives the same fix.
- Release notes must call out vulnerable dependency upgrades and required operator action.

## Release Criteria

A release candidate is not ready unless:

- formatting, clippy, tests, audit, and deny checks pass
- false-positive budget remains within the documented threshold
- rollback and backup flows are validated
- release notes include migration or compatibility notes when relevant

## Contribution Model

- Small, reviewable pull requests are preferred over large batches.
- Every policy-changing feature needs audit logging and a rollback path.
- Performance-sensitive DNS path changes should include measurements or a clear benchmark plan.
- New user-facing controls should be rejected unless they fit the minimal UX contract.

## Documentation Expectations

- Operator-facing changes must update operator docs.
- User-facing behavior changes must update user quick-start or release notes.
- Deployment-affecting changes must update deployment documentation in the same change set.
