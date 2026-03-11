# Operator Quick Start

This guide is for people deploying and maintaining a Cogwheel node.

## What You Need

- Docker 24+ or a local Rust toolchain
- One machine that can bind DNS and HTTP ports
- Access to upstream DNS resolvers

## Fastest Local Run

Run Cogwheel directly for a local test session:

```bash
COGWHEEL_PROFILE=dev \
COGWHEEL_SERVER__HTTP_BIND_ADDR=127.0.0.1:30080 \
COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=127.0.0.1:30053 \
COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=127.0.0.1:30053 \
cargo run -p cogwheel-server
```

Then open `http://localhost:30080`.

Built-in deployment profiles:

- `dev` - loopback-only, non-privileged local ports
- `home` - default home-lab profile; pair it with host port `53` publishing for client devices
- `smb` - small-business profile with DNS on port `53` and stricter guard thresholds

## Docker Run

Build and run the server container:

```bash
docker build -t cogwheel:latest .

docker run -d \
  --name cogwheel \
  --restart unless-stopped \
  -p 53:30053/udp \
  -p 53:30053/tcp \
  -p 30080:30080 \
  -e COGWHEEL_PROFILE=dev \
  -e COGWHEEL_SERVER__HTTP_BIND_ADDR=0.0.0.0:30080 \
  -e COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:30053 \
  -e COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=0.0.0.0:30053 \
  -e COGWHEEL_SERVER__ADVERTISED_DNS_PORT=53 \
  -v cogwheel_data:/app/data \
  cogwheel:latest
```

This mirrors the way Pi-hole and AdGuard Home expose standard DNS on the host while letting the app keep a safe internal bind port.

For a reusable installer-style command, use `scripts/install-home-docker.sh`.

Optional Tailscale bootstrap:

```bash
sudo INSTALL_TAILSCALE=1 TAILSCALE_AUTH_KEY=tskey-example scripts/install-home-docker.sh
```

This installs Tailscale, authenticates when a key is supplied, and advertises the node as an exit node while keeping `--accept-dns=false` so exit-node traffic continues to flow through Cogwheel's DNS path.

For Raspberry Pi deployment details, see `DEPLOY.md` and `DEPLOYMENT.md`.

## Required Environment Variables

- `COGWHEEL_SERVER__HTTP_BIND_ADDR`
- `COGWHEEL_SERVER__DNS_UDP_BIND_ADDR`
- `COGWHEEL_SERVER__DNS_TCP_BIND_ADDR`
- `COGWHEEL_PROFILE`
- `COGWHEEL_STORAGE__DATABASE_URL`
- `COGWHEEL_UPSTREAM__SERVERS`

## Smoke Test Checklist

After startup, verify:

```bash
curl http://127.0.0.1:30080/api/v1/dashboard
curl http://127.0.0.1:30080/api/v1/config/version
curl http://127.0.0.1:30080/api/v1/false-positive-budget
```

If Tailscale integration is enabled, also check:

```bash
curl http://127.0.0.1:30080/api/v1/tailscale/status
```

## Day-2 Operations

- Use backup and restore APIs before major changes.
- Review resilience drill endpoints after upgrades.
- Check false-positive budget before release candidates.
- Use the load-test endpoint for soak and throughput verification.

## Regression Checks

Before shipping changes, run:

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check
npm run lint --prefix apps/cogwheel-web
npm run build --prefix apps/cogwheel-web
```
