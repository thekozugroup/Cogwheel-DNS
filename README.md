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

Three concepts, matching the sidebar:

- **Lists** — subscribed blocklists of ad and tracker domains, fetched on a schedule and compiled
  into the resolver's in-memory index. A protected set of domains that the network itself needs to
  keep working — resolver bootstrap, captive-portal checks, NTP, certificate validation — can never
  be blocked by a list, so a bad upstream list cannot take your household's DNS down.
- **Rules** — allow or block one domain yourself, for the whole household or for a single device.
  A rule always outranks both the lists and the protected set, so it is also how you fix a list
  that got something wrong.
- **Devices** — name an address on your network, give it its own filtering switch, its own list
  selection, its own rules, and see its own activity log with counts.

A blocked lookup gets a null address back immediately; everything else is forwarded upstream and
cached, subject to the record's own TTL.

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

Design and architecture notes live in [docs/architecture/](./docs/architecture/);
the pre-Phase-3 descriptions they replaced are kept in
[docs/archive/](./docs/archive/).

## Benchmarks

The numbers behind the before/after table in the spec come from a stdlib-only Python harness with
no dependencies of its own — see [scripts/bench/README.md](./scripts/bench/README.md) for how to
run it against a local build.
