# Release v0.1.0

Request: publish the first GitHub release and install it on Atlas.

## Scope

- Finalize first-release documentation and changelog.
- Fix the release image smoke check's missing writable database volume.
- Pass the full CI gate on the exact release commit.
- Publish through the existing release workflow, including both architectures,
  binaries, checksums, SBOMs and provenance.
- Install the published image on Atlas with persistent appdata and an Unraid
  template. Use host networking, DNS port 53 and web port 8081.
- Verify readiness, DNS over UDP and TCP, blocking, restart persistence and the
  web interface. Preserve unrelated containers and host resolver settings.

## Current status

- Source restored from GitHub main; no local changes existed.
- Atlas inspected: no existing Cogwheel container, data or template. Port 53
  and web port 8081 are free; web port 8080 belongs to another application.
- Release preparation in progress. Publication and installation remain pending.

## Acceptance boundary

Installation does not change router DHCP/DNS settings. Network-wide use begins
when the router distributes Atlas as the DNS server.
