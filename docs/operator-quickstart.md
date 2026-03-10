# Operator Quick Start

This guide is for people deploying and maintaining a Cogwheel node.

## What You Need

- Docker 24+ or a local Rust toolchain
- One machine that can bind DNS and HTTP ports
- Access to upstream DNS resolvers

## Fastest Local Run

Run Cogwheel directly for a local test session:

```bash
COGWHEEL_SERVER__HTTP_BIND_ADDR=127.0.0.1:30080 \
COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=127.0.0.1:30053 \
COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=127.0.0.1:30053 \
cargo run -p cogwheel-server
```

Then open `http://localhost:30080`.

## Docker Run

Build and run the server container:

```bash
docker build -t cogwheel:latest .

docker run -d \
  --name cogwheel \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  -v cogwheel_data:/app/data \
  cogwheel:latest
```

For Raspberry Pi deployment details, see `DEPLOY.md` and `DEPLOYMENT.md`.

## Required Environment Variables

- `COGWHEEL_SERVER__HTTP_BIND_ADDR`
- `COGWHEEL_SERVER__DNS_UDP_BIND_ADDR`
- `COGWHEEL_SERVER__DNS_TCP_BIND_ADDR`
- `COGWHEEL_STORAGE__DATABASE_URL`
- `COGWHEEL_UPSTREAM__SERVERS`

## Smoke Test Checklist

After startup, verify:

```bash
curl http://127.0.0.1:8080/api/v1/dashboard
curl http://127.0.0.1:8080/api/v1/config/version
curl http://127.0.0.1:8080/api/v1/false-positive-budget
```

If Tailscale integration is enabled, also check:

```bash
curl http://127.0.0.1:8080/api/v1/tailscale/status
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
