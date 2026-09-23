# syntax=docker/dockerfile:1.19
#
# Cogwheel DNS — production container image.
#
# Design goals, in priority order:
#   1. Editing Rust source must NOT rebuild third-party crates. That is what
#      the cargo-chef `planner` + `cook` stage pair below buys us.
#   2. The image must build for linux/amd64 and linux/arm64 (Raspberry Pi 5).
#   3. The runtime must be non-root, minimal, and able to bind :53.
#
# Build (single arch, local):
#   docker build -t cogwheel:dev .
#
# Build (both arches, requires a buildx builder with the docker-container driver):
#   docker buildx build --platform linux/amd64,linux/arm64 -t <ref> --push .
#
# BuildKit is required (default since Docker 23) for the `--mount=type=cache`
# and `$BUILDPLATFORM` features used below.

# --------------------------------------------------------------------------
# Pinned inputs.
#
# Every base image is pinned to a MINOR version, not a floating major and not
# `latest`. A rebuild six months from now resolves the same toolchain and the
# same glibc. Bumping these is a deliberate, reviewable commit.
#
# The builder and the runtime share the same Debian suite on purpose: the
# binary is dynamically linked against glibc, so a bookworm-built binary on a
# trixie runtime (or vice versa) is a latent, arch-dependent breakage.
#
# RUST_VERSION is pinned to the exact patch and MUST equal the `channel` in
# rust-toolchain.toml -- CI fails the build if they disagree. If the image were
# older than the pin, rustup would honour the toolchain file and silently
# download a second compiler mid-build; if it were newer, the release binary
# would be built by a compiler nothing else in the project ever runs.
# --------------------------------------------------------------------------
ARG RUST_VERSION=1.97.0
ARG NODE_VERSION=22.22
ARG DEBIAN_SUITE=bookworm
ARG CARGO_CHEF_VERSION=0.1.78

# ==========================================================================
# Stage: web-builder — build the React/Vite control plane
#
# Pinned to $BUILDPLATFORM deliberately. Vite emits plain static JS/CSS/HTML
# that is byte-identical on every CPU architecture, so there is no reason to
# run npm under QEMU when producing the arm64 image. On an amd64 host building
# for arm64 this turns a multi-minute emulated npm install into a native one.
# ==========================================================================
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-${DEBIAN_SUITE}-slim AS web-builder

WORKDIR /build/apps/cogwheel-web

# Manifests first, on their own layer: `npm ci` is only re-run when a
# dependency actually changes, not on every source edit.
COPY apps/cogwheel-web/package.json apps/cogwheel-web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci --no-audit --no-fund

COPY apps/cogwheel-web/ ./
# `npm run build` is `tsc --noEmit -p tsconfig.app.json && vite build`, so a
# type error fails the image build rather than shipping broken assets.
RUN npm run build

# ==========================================================================
# Stage: chef — Rust toolchain plus cargo-chef
#
# cargo-chef is installed from crates.io into the official `rust` image rather
# than using the third-party `lukemathwalker/cargo-chef` base image. That keeps
# every FROM in this file on a Docker Official Image, which is one less
# supply-chain root to trust and one less tag to keep pinned.
#
# The full (non-slim) `rust` image is required: `rusqlite` is built with the
# `bundled` feature, which compiles SQLite's C amalgamation and therefore needs
# a working cc toolchain at build time.
# ==========================================================================
FROM rust:${RUST_VERSION}-${DEBIAN_SUITE} AS chef
ARG CARGO_CHEF_VERSION
WORKDIR /build
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install cargo-chef --locked --version ${CARGO_CHEF_VERSION}

# ==========================================================================
# Stage: planner — derive the dependency-only build recipe
#
# `cargo chef prepare` reads the workspace manifests and emits recipe.json.
# The whole workspace is copied in because cargo needs a coherent tree to
# resolve, but that is fine: recipe.json only changes when a *dependency*
# changes. BuildKit keys the next stage on the CONTENT of the copied
# recipe.json, so re-running this stage after an ordinary source edit still
# produces identical bytes and the expensive `cook` layer stays cached.
# ==========================================================================
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY apps/ apps/
RUN cargo chef prepare --recipe-path recipe.json

# ==========================================================================
# Stage: cook — compile ONLY third-party dependencies
#
# This is the layer that makes iteration cheap. It depends on nothing but
# recipe.json, so editing anything under crates/ or apps/ leaves it untouched.
#
# Note what is NOT cache-mounted: /build/target. The compiled dependency
# artifacts are deliberately baked into this image layer instead. BuildKit
# cache mounts are local to a builder and are not exported by `--cache-to`
# (GHA, registry, or otherwise), so a CI runner would find them empty every
# run. Baking them into the layer means `--cache-from type=gha` restores the
# entire cooked dependency tree across CI runs, which is the whole point.
# The cargo registry IS cache-mounted, because that only accelerates the
# download step and re-downloading on a cold CI runner is cheap.
# ==========================================================================
FROM chef AS cook
COPY --from=planner /build/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

# ==========================================================================
# Stage: builder — compile the Cogwheel workspace itself
#
# apps/cogwheel-web is intentionally NOT copied here. Rust never reads it, and
# leaving it out means a front-end change cannot invalidate the Rust build.
# ==========================================================================
FROM cook AS builder
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY apps/cogwheel-server/ apps/cogwheel-server/

# --locked: fail loudly if Cargo.lock does not satisfy the manifests, rather
# than silently resolving different dependency versions than CI tested.
# The release profile already sets strip = true, so no separate strip step.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release --locked -p cogwheel-server \
 && install -Dm0755 target/release/cogwheel-server /out/cogwheel-server

# ==========================================================================
# Stage: runtime
#
# Why debian:<suite>-slim and not distroless?
#
#   1. File capabilities. Binding :53 as a non-root user requires
#      `setcap cap_net_bind_service=+ep` on the binary. setcap must run in the
#      final stage — `COPY --from` does not reliably carry security.capability
#      extended attributes between stages — and that needs libcap2-bin, which
#      needs a package manager. Distroless has neither.
#   2. HEALTHCHECK. Docker health checks exec a command *inside* the container.
#      Distroless ships no shell and no HTTP client, so a health check there
#      means building and maintaining a second static probe binary.
#   3. Field debuggability. This is a self-hosted appliance sitting on someone's
#      home network. When DNS breaks at 11pm, `docker exec -it cogwheel sh`
#      plus `curl` is the difference between a five-minute fix and a reinstall.
#
# The cost is roughly 30 MB of base layer over distroless/cc. For an appliance
# image that is a good trade. The hardening that actually matters — non-root
# user, dropped capabilities, read-only root filesystem — is applied here and
# in docker-compose.yml, and none of it depends on the base being distroless.
# ==========================================================================
FROM debian:${DEBIAN_SUITE}-slim AS runtime

# ca-certificates: the blocklist updater fetches sources over HTTPS. reqwest is
#   built with the `rustls-tls` feature, which bundles Mozilla's roots via
#   webpki-roots, so Rust itself does not read /etc/ssl — but curl (below) does,
#   and an operator debugging with curl inside the container needs a real trust
#   store. Belt and braces, ~200 KB.
# curl: the HEALTHCHECK probe. Nothing else in the image uses it.
# libcap2-bin: provides setcap, used below to let the non-root binary bind :53.
#   It is deliberately left in the image rather than purged after use. Leaving
#   setcap in place is inert at runtime: it needs CAP_SETFCAP and a writable
#   filesystem, and the container has neither (cap_drop: ALL + read_only: true).
#
# No iproute2. The only thing the server shells out to is `hostname` /
# `hostname -I` (GET /api/v1/overview's `connect.targets`, to list the
# addresses a person should point their router at), and `hostname` ships in
# the Essential `hostname` package that every Debian base image already
# carries. Nothing in the image needs `ip` on PATH.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

# Fixed, non-root uid/gid. It is pinned to a literal value (not "whatever
# useradd picks") because host bind mounts must be chowned to the same number
# by the installer; a floating uid silently produces an unwritable data dir.
ARG COGWHEEL_UID=10001
ARG COGWHEEL_GID=10001
RUN groupadd --system --gid ${COGWHEEL_GID} cogwheel \
 && useradd --system --uid ${COGWHEEL_UID} --gid ${COGWHEEL_GID} \
            --home-dir /app --no-create-home --shell /usr/sbin/nologin cogwheel

WORKDIR /app

COPY --from=builder /out/cogwheel-server /usr/local/bin/cogwheel-server
COPY --from=web-builder /build/apps/cogwheel-web/dist /app/web

# Grant the binary permission to bind ports below 1024 without being root.
#
# `docker run --cap-add=NET_BIND_SERVICE` alone is NOT sufficient for a
# non-root USER. --cap-add only populates the container's *bounding* set, and
# an unprivileged process gains nothing from the bounding set on its own; a
# file capability is what actually transfers the privilege across execve.
#
# Measured on Linux 6.18.5 / Docker 29.3.1, uid 10001, --cap-drop ALL
# --cap-add NET_BIND_SERVICE, reading /proc/self/status:
#
#   binary WITHOUT setcap -> CapBnd 0x400, CapPrm 0x000, CapEff 0x000  (cannot bind :53)
#   binary WITH    setcap -> CapBnd 0x400, CapPrm 0x400, CapEff 0x400  (can bind :53)
#
# Docker's default bounding set already contains CAP_NET_BIND_SERVICE, so this
# works with no extra runtime flags.
#
# On `--security-opt no-new-privileges`: prctl(2) documents no_new_privs as
# rendering file capabilities non-functional, but on the kernel above the
# capability was still granted (CapEff 0x400, NoNewPrivs 1). Because that
# behaviour is not something to bet a household's DNS on across every kernel,
# docker-compose.yml leaves the flag off by default.
#
# NET_BIND_SERVICE must be in the bounding set to RUN this image at all, even
# in an arrangement that only ever binds an unprivileged port. Setting the
# effective bit above means execve(2) returns EPERM when a permitted file
# capability is absent from the bounding set, so `--cap-drop ALL` with no
# matching `--cap-add` fails with:
#
#   exec /usr/local/bin/cogwheel-server failed: Operation not permitted
#
# before any Cogwheel code runs. Measured on this image: cap-drop ALL alone
# exits 1 at exec; with --cap-add NET_BIND_SERVICE the same container reaches
# ready and resolves. There is therefore no "capability-free" way to run this
# image -- bridge networking avoids NEEDING the privilege, not carrying it.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/cogwheel-server

# /app/data is created (and owned) in the image so that a fresh Docker named
# volume mounted here inherits 10001:10001 automatically. No VOLUME instruction
# on purpose: VOLUME would force an anonymous volume on every plain
# `docker run`, which is how appliance data quietly gets orphaned on upgrade.
RUN install -d -o ${COGWHEEL_UID} -g ${COGWHEEL_GID} -m 0750 /app/data \
 && chown -R ${COGWHEEL_UID}:${COGWHEEL_GID} /app/web

# The post-install check, carried inside the image.
#
# scripts/install.sh leaves a copy at /etc/cogwheel/verify-install.sh, but a
# host that never ran the installer -- Unraid's Docker tab, a plain
# `docker run`, somebody else's Compose stack -- has neither that file nor a
# checkout, and until now had no way to check an install at all:
#
#   docker exec cogwheel sh /app/verify-install.sh
#
# It reports SKIP rather than inventing a result for anything it cannot reach
# from in here, which is the restart and upgrade checks (no docker socket) and
# the resolver checks on an image with no dig. The HTTP checks -- liveness,
# readiness, the API, the web assets and the advertised resolver address --
# all run, and those are the ones that answer "did this come up correctly?".
COPY scripts/verify-install.sh /app/verify-install.sh

# --------------------------------------------------------------------------
# Runtime configuration defaults.
#
# These are the real variable names read by apps/cogwheel-server/src/config.rs
# (spec section 8). Override any of them at run time.
# --------------------------------------------------------------------------
ENV COGWHEEL_PROFILE=home \
    COGWHEEL_SERVER__HTTP_BIND_ADDR=0.0.0.0:8080 \
    COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:53 \
    COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=0.0.0.0:53 \
    COGWHEEL_SERVER__ADVERTISED_DNS_PORT=53 \
    COGWHEEL_STORAGE__DATABASE_URL=sqlite:///app/data/cogwheel.db \
    COGWHEEL_WEB_DIST_DIR=/app/web

USER ${COGWHEEL_UID}:${COGWHEEL_GID}

EXPOSE 8080/tcp 53/udp 53/tcp

# The HTTP port is derived from the configured bind address rather than being
# duplicated, so overriding COGWHEEL_SERVER__HTTP_BIND_ADDR keeps the health
# check pointed at the right place. ${addr##*:} takes everything after the last
# colon, which is correct for both "0.0.0.0:8080" and "[::]:8080".
#
# /health/live is the liveness probe: it answers as soon as HTTP is up, which is
# what a container healthcheck should test. /health/ready is the stronger signal
# (503 until storage, policy and the DNS listeners are all up) and is the one to
# gate a rolling upgrade on -- but using it here would report the container
# unhealthy during a slow first blocklist compile, so liveness is correct for
# this probe. See docs/DEPLOYMENT.md.
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD ["/bin/sh", "-c", "addr=\"${COGWHEEL_SERVER__HTTP_BIND_ADDR:-0.0.0.0:8080}\"; exec curl -fsS -o /dev/null --max-time 4 \"http://127.0.0.1:${addr##*:}/health/live\""]

# Explicit, even though SIGTERM is the default: the shutdown path matters for
# an appliance and should not be an accident of Docker's defaults.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/cogwheel-server"]

# --------------------------------------------------------------------------
# OCI image metadata. VERSION/REVISION/CREATED are supplied by CI
# (see .github/workflows/release.yml); they are last so that a changed build
# argument only invalidates this final metadata layer.
# --------------------------------------------------------------------------
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z
ARG DEBIAN_SUITE

# The database schema version this build understands, mirroring SCHEMA_VERSION
# in crates/cogwheel-storage/src/lib.rs. CI asserts the two agree, because a
# label that drifts is worse than no label: this is the one fact that tells an
# operator, BEFORE pulling, whether a release will migrate their database --
# and therefore whether rolling back afterwards needs the .pre-vN snapshot
# restoring first. Read it without pulling the image:
#
#   docker buildx imagetools inspect ghcr.io/thekozugroup/cogwheel-dns:latest \
#     --format '{{ json .Image.Config.Labels }}'
#
# scripts/install.sh compares it across an upgrade and says what it means.
ARG SCHEMA_VERSION=1

LABEL org.opencontainers.image.title="Cogwheel DNS" \
      org.opencontainers.image.description="Network-wide DNS ad and tracker blocking, with per-device policy" \
      org.opencontainers.image.url="https://github.com/thekozugroup/Cogwheel-DNS" \
      org.opencontainers.image.source="https://github.com/thekozugroup/Cogwheel-DNS" \
      org.opencontainers.image.documentation="https://github.com/thekozugroup/Cogwheel-DNS/blob/main/docs/DEPLOYMENT.md" \
      org.opencontainers.image.vendor="The Kozu Group" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="docker.io/library/debian:${DEBIAN_SUITE}-slim" \
      io.cogwheel.schema-version="${SCHEMA_VERSION}"

# Unraid reads these two from the image when a container is added from a
# template, so the WebUI button and the icon work without the operator typing
# either. [IP] and [PORT:8080] are Unraid's own substitutions, filled in from
# the container's published ports -- they are not shell or Docker syntax and
# must reach Unraid literally.
LABEL net.unraid.docker.webui="http://[IP]:[PORT:8080]" \
      net.unraid.docker.icon="https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/deploy/unraid/cogwheel.svg"

# Watchtower: watch and report, do not replace.
#
# Watchtower's update is stop -> pull -> start with the same flags, unattended,
# on a timer. It does not wait for health, so a container that starts, migrates
# the database, fails and enters a restart loop is recorded as a successful
# update -- at 04:00, on the box that resolves every name in the house, with
# nobody watching. `monitor-only` keeps the useful half (it still tells you a
# new image exists) and drops the half that can leave a household with no DNS.
#
# What is NOT the reason for this: the migration itself is crash-safe, and
# that is measured rather than hoped for. The whole schema rewrite is one
# TransactionBehavior::Immediate transaction committed at
# crates/cogwheel-storage/src/migrate.rs (upgrade_in_transaction), so a SIGKILL
# partway through rolls it back and leaves the database exactly as it was; and
# the pre-migration `VACUUM INTO` copy, which runs outside that transaction, is
# deleted and re-taken on the next boot if it was left partial. A kill mid
# migration costs a restart, not data.
#
# The risk this guards is the other one: a release that migrates successfully
# and then cannot serve, or that you then want to leave. Going back across a
# schema change needs the .pre-vN copy restored first, and that is a decision,
# not something to discover from a crash loop the next morning.
#
# To opt in to automatic updates, override it on the container -- one line in
# docker-compose.yml, where you can see it:
#     labels:
#       com.centurylinklabs.watchtower.monitor-only: "false"
# Check io.cogwheel.schema-version on the new tag before you do.
LABEL com.centurylinklabs.watchtower.monitor-only="true"
