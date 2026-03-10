# Cogwheel DNS

Cogwheel DNS is a Rust-native DNS adblock platform with a Docker server backend, safe blocklist updates, and a background real-time classifier.

## Current Scope

- Phase 1: monorepo foundation and shared infrastructure
- Phase 2: DNS backend MVP with health endpoints and Docker packaging
- Phase 3: safe blocklist ingestion, verification, and atomic ruleset activation
- Phase 7: Tailscale exit-node integration and rollback flows
- Phase 8: hardening, recovery, load testing, and release gates
- Phase 9: GA documentation and ecosystem polish in progress

## Quick Links

- Operator quick start: `docs/operator-quickstart.md`
- User quick start: `docs/user-quickstart.md`
- Deployment notes: `DEPLOY.md`
- Contribution guide: `CONTRIBUTING.md`

## Local Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
cargo run -p cogwheel-server
```

For a local Web UI session that avoids privileged ports on macOS:

```bash
COGWHEEL_SERVER__HTTP_BIND_ADDR=127.0.0.1:30080 \
COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=127.0.0.1:30053 \
COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=127.0.0.1:30053 \
cargo run -p cogwheel-server
```

## Configuration

The server reads settings from environment variables with the `COGWHEEL_` prefix.

- `COGWHEEL_SERVER__HTTP_BIND_ADDR`
- `COGWHEEL_SERVER__DNS_UDP_BIND_ADDR`
- `COGWHEEL_SERVER__DNS_TCP_BIND_ADDR`
- `COGWHEEL_STORAGE__DATABASE_URL`
- `COGWHEEL_UPSTREAM__SERVERS`

## Design Notes

- The DNS hot path stays deterministic and LLM-independent.
- Blocklist updates are staged and atomically promoted.
- Unsafe or malformed list updates never replace the active ruleset.
