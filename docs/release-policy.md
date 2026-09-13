# Release Policy

This document defines how Cogwheel ships, how long releases are supported, and how changes should land.

## Versioning

- Cogwheel uses semantic versioning for user-visible releases.
- Schema migrations and config schema versions must remain explicitly tracked.
- Breaking configuration or API changes require a documented migration path before release.

## How a release is cut

Releases are automated. Pushing a `v*` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml):

```sh
git tag -a v1.2.3 -m "Cogwheel 1.2.3"
git push origin v1.2.3
```

The workflow then, in order:

1. Builds `linux/amd64` and `linux/arm64` images on native runners and pushes
   them to GHCR by digest, then stitches them into one multi-arch manifest
   tagged `1.2.3`, `1.2`, and `latest`.
2. Cross-compiles `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`
   binaries and packages each with the web assets, the systemd unit and the
   install scripts.
3. Emits `SHA256SUMS` covering every attached artifact.
4. Generates SPDX SBOMs for the source tree and for the image.
5. Signs build-provenance attestations for the image and the binaries, and
   attaches an SBOM attestation to the image.
6. Creates the GitHub Release with generated notes.

Nothing is published by hand. A release that did not come out of this workflow
has no provenance and should not be trusted.

### Verifying a release

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify cogwheel-1.2.3-aarch64-unknown-linux-gnu.tar.gz -R thekozugroup/Cogwheel-DNS
gh attestation verify oci://ghcr.io/thekozugroup/cogwheel-dns:1.2.3 -R thekozugroup/Cogwheel-DNS
```

### Version pinning for operators

Production deployments pin an exact tag in `.env`
(`COGWHEEL_IMAGE=ghcr.io/thekozugroup/cogwheel-dns:1.2.3`). Tracking `latest`
turns every `docker compose pull` into an unreviewed upgrade of a household's
DNS resolver.

### Prerequisites

The image jobs use GitHub-hosted `ubuntu-24.04-arm` runners so the arm64 build
is native. Building arm64 under QEMU for a Rust workspace this size regularly
exceeds the job time limit. If those runners are unavailable to the repository,
swap the runner label and add `docker/setup-qemu-action`, and expect a much
longer release.

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
- the protected-domain safety net still refuses a candidate list that would block a protected name (covered by `cargo test --workspace`)
- an upgrade against a copy of the previous release's data directory is validated
- release notes include migration or compatibility notes when relevant

## Contribution Model

- Small, reviewable pull requests are preferred over large batches.
- Every policy-changing feature must refuse an unsafe candidate before activation rather than repair it afterwards.
- Performance-sensitive DNS path changes should include measurements or a clear benchmark plan.
- New user-facing controls should be rejected unless they fit the minimal UX contract.

## Documentation Expectations

- Operator-facing changes must update operator docs.
- User-facing behavior changes must update user quick-start or release notes.
- Deployment-affecting changes must update deployment documentation in the same change set.
