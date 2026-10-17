# Release v0.1.0

Request: publish the first GitHub release and install it on Atlas.

## Scope

- Finalize first-release documentation and changelog.
- Fix the release image smoke check's missing writable database volume.
- Update vulnerable locked dependencies before publication.
- Enable automatic updates on Atlas without an updater sidecar container.
- Pass the full CI gate on the exact release commit.
- Publish through the existing release workflow, including both architectures,
  binaries, checksums, SBOMs and provenance.
- Install the published image on Atlas with persistent appdata and an Unraid
  template. Use host networking, DNS port 53 and web port 8081.
- Verify readiness, DNS over UDP and TCP, blocking, restart persistence and the
  web interface. Preserve unrelated containers and host resolver settings.

## Current status

- Complete: v0.1.0 published and installed on Atlas. The container is healthy.
- Release commit: `3690b4852ae8b84e0c2d20fb48364fcdfeb34ed3`.
- GitHub release: https://github.com/thekozugroup/Cogwheel-DNS/releases/tag/v0.1.0
- Public multi-architecture image: `ghcr.io/thekozugroup/cogwheel-dns:0.1.0`.
  Atlas tracks `:latest` for automatic updates.
- Image index digest:
  `sha256:b3bc98978247a679122134c3b32a6467f78c57010a8d90353a8712234d1467a2`.
- Patched the release smoke test's database mount and updated quinn-proto to
  0.11.18 and rustls to 0.23.46 after the first CI audit identified advisories.
- Finalized release documentation and the first changelog. Follow-up changes
  document Unraid automatic updates and correct minor-tag formatting in future
  release notes; they do not change the released runtime.

## Verification

- Full CI on the release commit passed all six jobs:
  https://github.com/thekozugroup/Cogwheel-DNS/actions/runs/38990037403
  This includes 384 Rust tests, 15 web tests, lint, locked builds, dependency
  audit, deployment checks, and real amd64/arm64 container DNS/migration tests.
- Release workflow passed all eight jobs:
  https://github.com/thekozugroup/Cogwheel-DNS/actions/runs/38990731109
- Downloaded release archives and source SBOM match SHA256SUMS. GitHub artifact
  attestations verified for the image and x86_64 archive; the image provenance
  matches the release commit, tag and workflow. Anonymous registry access
  confirmed both linux/amd64 and linux/arm64 images.
- Atlas post-install verification passed liveness, readiness, API, bundled web,
  advertised DNS target, allowed UDP DNS, marker blocking, TCP DNS and saved
  device persistence across restart. Its Compose-specific update check was
  skipped because Atlas uses Unraid; the native path was tested separately.
- Forced a Cogwheel-only pull and replacement using Unraid's own
  `CreateDocker.php` path and saved template. A new container ID confirmed
  replacement; the published image, marker device and settings survived.
  Removed verification markers and repeated live DNS/blocking checks.
- Native registry checks report the tracked image up to date. Cogwheel is
  enabled in the existing Auto Update Applications schedule at 04:00 daily,
  America/New_York. Both persistent schedule/config and active cron verified.
  This tested same-release replacement; a future-version update cannot be
  observed until another release is published.
- Browser verified the deployed dashboard and Settings version 0.1.0/schema 2.
  UDP/TCP DNS also answered from another machine over Tailscale.
- Existing containers retained their IDs, images and start times. Host resolver
  configuration and previous automatic-update selections remained unchanged.
  A separate concurrent task added a Popcorn cleanup container during checks;
  this deployment neither created nor changed it.

## Atlas configuration and recovery

- One Cogwheel container; no updater sidecar and no Docker socket mount.
- Host networking: DNS 53 UDP/TCP, web 8081. Existing web port 8080 was occupied.
- Persistent data: `/mnt/user/Z-Appdata/cogwheel`, owned by UID/GID 10001.
- Saved Unraid template: `/boot/config/plugins/dockerMan/templates-user/my-cogwheel.xml`.
- Autostart enabled. Non-root runtime, read-only root filesystem, minimal
  capability, bounded resources and rotated logs survived native replacement.
- Default blocklist loaded 56,633 rules. AI review remains off with no key.
- Consistent stopped-container appdata snapshot, rollback helper, deployment
  fingerprints and update verification records retained on Atlas at
  `/mnt/user/Z-System/cogwheel/deployments/v0.1.0`.
- Local release evidence: `.git/release-evidence/v0.1.0`.

## Acceptance boundary

Installation does not change router DHCP/DNS settings. Network-wide use begins
when the router distributes Atlas as the DNS server.
