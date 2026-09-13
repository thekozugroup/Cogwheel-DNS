# Cogwheel

Network-wide ad and tracker blocking for your home, in one command.

Cogwheel is a DNS filtering appliance written in Rust. Point your router at it and every device on
the network — phones, TVs, consoles, anything that cannot run an ad blocker — stops loading ads and
trackers. It is built for a Raspberry Pi 5, and runs on any 64-bit Linux box.

## Install

On the machine that will run it:

```sh
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh
```

That is the whole install. It pulls the image, creates the data directory, **detects and fixes the
port 53 conflict** that trips up most self-hosted DNS servers, waits until the container reports
healthy, and prints two things:

```
  Cogwheel is running.

  Web UI        http://192.0.2.10:8080
  DNS server    192.0.2.10 port 53

  Point the DNS setting on your router at one of:
      cogwheel
      192.0.2.10
```

Open the web UI, follow the router instructions on the Overview screen, and you are done.

Changed your mind? This removes it and puts your host DNS back exactly as it was:

```sh
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh -s -- --uninstall
```

(The installer does not copy itself onto the machine, so there is no local `install.sh` to run —
fetch it the same way you did to install. From a git checkout, `sudo ./scripts/install.sh
--uninstall` works too.)

**Requirements:** 64-bit Linux (`x86_64` or `aarch64`), Docker 24+, and root — binding port 53 and
editing resolver config both need it. On a Raspberry Pi, use the 64-bit OS.

Prefer Docker Compose, or no Docker at all? Both are covered in
[DEPLOYMENT.md](./DEPLOYMENT.md), along with troubleshooting, upgrades and backups.

## How it works

A DNS resolver sits between your devices and the internet. When a device asks for a domain on an
active blocklist, Cogwheel answers immediately with a null address, so the tracker is never
contacted. Everything else is forwarded upstream and cached.

Blocklist updates are verified before they are promoted. A new ruleset that would block a
protected domain — resolver bootstrap, captive-portal checks, NTP, certificate validation — is
rejected rather than installed, so a bad upstream list cannot take your household's DNS down.

Per-device profiles let a child's tablet get strict filtering while a work laptop keeps developer
tools reachable.

## Stack

- **Rust** — Axum, Hickory DNS, Moka cache, SQLite via rusqlite. An `aarch64` build is just a
  cross-build.
- **React 19** — Vite, TypeScript, [Shark UI](https://shark.vini.one/), Tailwind CSS v4, self-hosted
  Inter. No CDN requests, because the appliance may sit on a LAN with no internet route.
- **Docker** — multi-arch images for `linux/amd64` and `linux/arm64`.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cd apps/cogwheel-web && npm ci && npm run build
```

Design and architecture notes live in [docs/architecture/](./docs/architecture/).
