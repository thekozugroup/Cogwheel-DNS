# Releasing Cogwheel

How a release is cut, how to verify one, and which image tag an operator should
follow.

> Nothing has been released yet. There are no tags and no image has been pushed
> to `ghcr.io/thekozugroup/cogwheel-dns`. Everything below describes the
> machinery, which is in place and tested; `v0.1.0` will be the first time it
> runs for real.
>
> *Delete this block in the commit that tags `v0.1.0` — it is one of five,
> listed under [Before the first tag](#before-the-first-tag-v010-only).*

---

## Versioning

Semantic versioning. Before 1.0, a minor version may change behaviour — the
changelog entry says so when it does.

The one piece of version information that is not the version number is the
**database schema version**, an integer the image advertises as the OCI label
`io.cogwheel.schema-version`. It is what decides whether an upgrade is a swap or
a migration, and therefore what a rollback costs. Today it is `1`.

Every changelog entry states whether the release changes the schema. That is the
fact an operator needs and the one they cannot get anywhere else.

---

## Cutting a release

Releases are automated. Pushing a `v*` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
re-runs the full gate against the tagged tree before publishing anything.

1. **Write the `CHANGELOG.md` section** for the version, dated, in
   [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) form —
   `## [0.1.0] — 2026-01-31`. The workflow extracts that section verbatim into
   the release body; if it is missing, the release still publishes but the notes
   are a pointer, which is no use to anyone deciding whether to upgrade.

   Say whether the schema changed. If it did, say what the rollback costs.

2. **Tag and push:**

   ```sh
   git tag -a v1.2.3 -m "Cogwheel 1.2.3"
   git push origin v1.2.3
   ```

### Before the first tag, `v0.1.0`, only

Five statements in the tree are true today and become false the moment an image
exists. They are honest, not placeholders, so they stay until the tag — and
then all five go in the same commit that makes them wrong:

- [ ] `CHANGELOG.md` — rename `## [Unreleased]` to `## [0.1.0] — <date>`, add
      the link reference at the foot, and open a fresh empty `## [Unreleased]`.
- [ ] `README.md` — delete the **Before the first release** block under
      **Quick start**.
- [ ] `docs/QUICKSTART.md` — delete the **Before the first release** block.
- [ ] `docs/DEPLOYMENT.md` — delete the **Before the first release** block.
- [ ] `docs/RELEASING.md` — delete the note at the top of this file.

The three **Before the first release** banners each end with a pointer back to
this list, so one of them still in the tree after a tag is a missed step here.

Then check the two URLs that are baked into image metadata at build time and
cannot be corrected on an image already published:
`deploy/unraid/cogwheel.xml` and `deploy/unraid/cogwheel.svg` must both serve
200 from `raw.githubusercontent.com` on `main` before the tag is pushed, because
`net.unraid.docker.icon` in the Dockerfile points at the second one.

The workflow then, in order:

1. Builds `linux/amd64` and `linux/arm64` images on native runners, pushes them
   to GHCR by digest, and stitches them into one multi-arch manifest tagged
   [as described below](#which-tag-should-i-track).
2. Cross-compiles `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`
   binaries and packages each with the web assets, the systemd unit, the compose
   file, `.env.example`, the Unraid template and the install scripts.
3. Emits `SHA256SUMS` covering every attached artifact.
4. Generates SPDX SBOMs for the source tree and for the image.
5. Signs build-provenance attestations for the image and the binaries, and
   attaches an SBOM attestation to the image.
6. Creates the GitHub release from the changelog section.

**Nothing is published by hand.** A release that did not come out of this
workflow has no provenance and should not be trusted.

### One prerequisite worth knowing about

The image jobs use GitHub-hosted `ubuntu-24.04-arm` runners so the arm64 build
is native. Building arm64 under QEMU for a Rust workspace this size regularly
exceeds the job time limit. If those runners are not available to the
repository, swap the runner label and add `docker/setup-qemu-action` — and
expect a much longer release.

---

## Verifying a release

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify cogwheel-1.2.3-aarch64-unknown-linux-gnu.tar.gz -R thekozugroup/Cogwheel-DNS
gh attestation verify oci://ghcr.io/thekozugroup/cogwheel-dns:1.2.3 -R thekozugroup/Cogwheel-DNS
```

---

## Which tag should I track?

Three tags are published for every release, and a fourth once Cogwheel reaches
`1.0`. Tagging `v1.2.3` would publish all four:

| Tag | Moves to | Published |
|---|---|---|
| `:latest` | the newest final release. **Never a prerelease.** | every final release |
| `:1.2.3` | exactly this release, forever. | every release |
| `:1.2` | the newest `1.2.x`. Fixes only. | every release |
| `:1` | the newest `1.x`. | `v1.0.0` and above only — a `0` tag would promise a stable major line that `0.x` does not have |

So the first release, `v0.1.0`, publishes `:latest`, `:0.1.0` and `:0.1` — there
is no `:0`, and pinning to a major line is something you can do from `v1.0.0`
onwards.

**`:latest` is the default, and that is deliberate.** A moving tag is what makes
`docker compose pull` an upgrade at all, and it is the only thing Unraid's
update check has to compare a digest against: a pinned tag has a digest that
never moves, so the Docker tab would report "up-to-date" through a security
release. The installer, `docker-compose.yml`, `.env.example` and the Unraid
template all follow `:latest` for the same reason.

**Pinning is the informed opt-out.** Set `COGWHEEL_IMAGE` in your `.env` to an
exact tag and every upgrade becomes a change you chose. The cost is the obvious
one and it is worth stating plainly: **nobody tells you when a security fix
ships.** Nothing in Cogwheel checks — [`scripts/check-update.sh`](../scripts/check-update.sh)
is opt-in and has to be run — so a pinned host stays on whatever it was pinned
to until someone thinks to look.

Pin if you would rather review each upgrade and you have a habit that will
actually make you look. Follow `:latest` if you would rather get fixes. Both are
defensible; drifting into a pin and forgetting is not.

A tag containing a hyphen (`v1.2.3-rc.1`) is a prerelease: it is published under
that version and `latest` is deliberately not moved.

---

## Before a release goes out

A release candidate is not ready unless:

- **The gate is green.** `sh scripts/verify.sh` with nothing skipped —
  `cargo audit` and `cargo deny check` in particular, which skip themselves
  when the tool is absent, and the Dockerfile check, which needs a daemon. A
  skip is not a pass, and a release is the one time that matters most.
  [CONTRIBUTING § The checks](../CONTRIBUTING.md#the-checks) has the reasoning.

- **The protected-name invariant holds.** A list naming a protected suffix is
  still installed, the names it hit are recorded in its `note`, and those names
  still resolve — because protection is enforced in `cogwheel_policy::evaluate`
  at query time, not by refusing the list. Covered by
  `a_protected_domain_outranks_a_blocklist_entry` in
  `crates/cogwheel-policy/src/tests.rs`.

- **An upgrade against a copy of the previous release's data directory has been
  run**, and the result verified with `scripts/verify-install.sh`. CI covers the
  v0→v1 case and covers that a database from a *newer* Cogwheel is refused with
  a message naming both versions; a real release should also be tried against a
  real household database.

- **The changelog section exists, is dated, and says whether the schema
  changed.**

---

## Support

Cogwheel is pre-1.0. Fixes land on `main` and go out in the next release; there
are no backported patch branches, and no cadence is promised — a cadence nobody
has kept yet is a promise, not a policy.

Security reports go through [SECURITY.md](../SECURITY.md), never a public issue.
Read it before reporting: several of the properties most likely to look like
findings — no authentication on the control plane, a seven-day log of every
lookup, a protected-suffix set that is deliberately only 21 entries — are
documented decisions with their reasoning written down.
