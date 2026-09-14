# Cogwheel

Network-wide ad and tracker blocking for your home.

Cogwheel is a DNS filtering appliance written in Rust. Point your router at it and every device on
the network — phones, TVs, consoles, anything that cannot run an ad blocker — stops loading ads and
trackers. It runs as one container on any 64-bit Linux box: a Raspberry Pi, a NAS, a spare mini PC.

> **Status: not yet released.** No image has been published to the registry, so the pull-based
> installs below do not work yet. [Build it yourself](#option-d--build-it-yourself-works-today) —
> that works today and takes one command. This note disappears when `v0.1.0` is tagged.

---

## Contents

- [What you get](#what-you-get)
- [Install](#install)
  - [Option A — one command (Linux)](#option-a--one-command-linux)
  - [Option B — Docker Compose](#option-b--docker-compose)
  - [Option C — Unraid](#option-c--unraid)
  - [Option D — build it yourself (works today)](#option-d--build-it-yourself-works-today)
- [First run](#first-run)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Upgrading, backup, uninstall](#upgrading-backup-uninstall)
- [For developers](#for-developers)

---

## What you get

- **Blocking that keeps working.** Subscribe to the usual public blocklists. A protected set of
  domains the network itself needs — resolver bootstrap, captive-portal checks, NTP, certificate
  validation — can never be blocked by a list, so a bad upstream list cannot take your household
  offline.
- **Per-device control.** Name each address on your network, then give it its own filtering switch,
  its own choice of lists, and its own allow/block rules. The kids' tablet and the work laptop do
  not have to share a policy.
- **A query log that answers questions.** Every lookup, which device asked, whether it was blocked
  and which list did it — live, searchable, and kept for seven days.
- **Encrypted upstream.** Plain UDP by default; DNS-over-TLS and DNS-over-HTTPS are one environment
  variable away.
- **Small.** About 30 MB of memory with a 56,000-entry list loaded, an 11 MB binary, and a cache hit
  answered in under two microseconds of server time.

---

## Install

**Requirements:** 64-bit Linux (`x86_64` or `aarch64`), Docker 24 or newer, and root — binding port
53 needs it. On a Raspberry Pi, use the 64-bit OS.

### Option A — one command (Linux)

*Requires a published release. Use [Option D](#option-d--build-it-yourself-works-today) until then.*

```sh
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh
```

That is the whole install. It pulls the image, creates the data volume, **detects and fixes the
port 53 conflict** that trips up most self-hosted DNS servers, waits for the container to report
healthy, and prints the address to point your router at.

### Option B — Docker Compose

*Requires a published release, or a locally built image — see [Option D](#option-d--build-it-yourself-works-today).*

```sh
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS
cp .env.example .env     # optional: edit upstreams, blocking mode, retention
docker compose up -d
```

`docker-compose.yml` uses host networking by default, and documents a bridge-networking alternative
inline if you would rather publish ports.

### Option C — Unraid

Unraid has no Community Applications template yet, so add it by hand. **Custom `br0` with its own
LAN address is the recommended setup** — a DNS server wants port 53, and giving the container its
own IP keeps it out of Unraid's way entirely.

**1. Get the image.** Until `v0.1.0` is published, build it on the server (Unraid ships Docker, so
no git or toolchain is needed — Docker fetches and builds it all):

```sh
docker build -t cogwheel-dns:local https://github.com/thekozugroup/Cogwheel-DNS.git#main
```

This takes a while the first time — it compiles the Rust binary and the web UI from source.

**2. Docker tab → Add Container.** Switch to *Advanced View* (top right) so the extra fields appear,
then set:

| Field | Value |
| --- | --- |
| **Name** | `cogwheel` |
| **Repository** | `cogwheel-dns:local` (or `ghcr.io/thekozugroup/cogwheel-dns:latest` once released) |
| **Network Type** | `Custom : br0` |
| **Fixed IP address** | a free static address outside your DHCP pool, e.g. `192.168.1.53` |
| **Extra Parameters** | `--cap-add NET_BIND_SERVICE --restart unless-stopped` |
| **WebUI** | `http://[IP]:8080` |

**3. Add one path.** Click *Add another Path, Port, Variable*:

| | |
| --- | --- |
| Config Type | `Path` |
| Name | `Data` |
| Container Path | `/app/data` |
| Host Path | `/mnt/user/appdata/cogwheel` |

**4. Fix the permissions — this step is not optional.** The container runs as UID 10001, and a fresh
Unraid appdata folder is owned by `nobody:users`. Without this the database cannot be created and the
container restarts in a loop. From the Unraid terminal, **before** you start it:

```sh
mkdir -p /mnt/user/appdata/cogwheel
chown -R 10001:10001 /mnt/user/appdata/cogwheel
```

**5. Apply**, then open `http://192.168.1.53:8080`.

Two Unraid notes worth knowing:

- **`--cap-add NET_BIND_SERVICE` is required**, not a hardening nicety. The binary carries a file
  capability so that a non-root process can bind port 53; if the capability is missing from the
  container the binary fails to execute at all, and the log shows a bare permission error.
- **The Unraid host cannot reach a `br0` container by default.** That is macvlan behaviour, not a
  bug. Browsing the web UI from your desktop works fine. If you want Unraid itself to use Cogwheel
  for DNS, enable *Settings → Docker → Host access to custom networks*.

Prefer to keep it on Unraid's own IP instead? Set **Network Type** to `Host` and drop the fixed IP.
Port 53 must be free on the server — Unraid does not use it by default, but another DNS container
would conflict.

### Option D — build it yourself (works today)

No release needed. On the machine that will run it:

```sh
docker build -t cogwheel-dns:local https://github.com/thekozugroup/Cogwheel-DNS.git#main

docker run -d --name cogwheel \
  --network host \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  -v cogwheel-data:/app/data \
  --restart unless-stopped \
  cogwheel-dns:local
```

Then open `http://<that machine's address>:8080`.

Using a **named volume** (`cogwheel-data`) rather than a bind mount is deliberate: Docker copies the
image's ownership onto a fresh named volume, while a bind mount comes up root-owned and the non-root
process cannot open its database. If you do want a bind mount, `chown -R 10001:10001` the directory
first.

To run the Compose file against your local build instead:
`COGWHEEL_IMAGE=cogwheel-dns:local docker compose up -d`.

---

## First run

1. **Open the web UI** at `http://<address>:8080`. The Overview page shows the exact address to give
   your router.
2. **Point your router's DNS at it.** In the router's DHCP or LAN settings, set the DNS server to
   Cogwheel's address. Every device that renews its lease picks it up; reboot a device to hurry it
   along.
3. **Check the Activity page.** Queries should start appearing within seconds, with device
   addresses attached.
4. **Name your devices** on the Devices page so the log reads in plain language instead of IP
   addresses — and so you can give any of them their own rules.

A fresh install subscribes to one list (oisd small) and starts filtering immediately. Add more from
the preset picker on the Lists page.

**If a site breaks:** open Activity, find the blocked lookup, and use the row menu to allow it — for
everyone or just for that device. Your rule always outranks the lists.

---

## How it works

Three concepts, matching the sidebar:

- **Lists** — subscribed blocklists, fetched on a schedule and compiled into an in-memory index.
  Cached to disk, so a box that boots before its internet connection still filters.
- **Rules** — allow or block one domain yourself, for the whole household or one device. A rule
  outranks both the lists and the protected set, so it is how you fix a list that got something
  wrong.
- **Devices** — a name for an address, with its own filtering switch, list selection, rules and
  counts.

One read: the **query log** on the Activity page — every query as it happens, which device asked,
and whether it was blocked and why.

A blocked lookup gets a null address back immediately; everything else is forwarded upstream and
cached for as long as the record's own TTL allows.

---

## Configuration

Everything is set by environment variable — in `.env` for Compose, or the *Variables* section of the
Unraid template. The common ones:

| Variable | Default | What it does |
| --- | --- | --- |
| `COGWHEEL_UPSTREAM__SERVERS` | `1.1.1.1:53,1.0.0.1:53` | Where unblocked queries go. Encrypt with `tls://1.1.1.1#cloudflare-dns.com` (DoT) or `https://1.1.1.1#cloudflare-dns.com/dns-query` (DoH). |
| `COGWHEEL_BLOCKING__MODE` | `null_ip` | How a blocked name is answered: `null_ip`, `nxdomain`, `nodata` or `refused`. |
| `COGWHEEL_RETENTION__HISTORY_DAYS` | `7` | How long the query log is kept. **`0` stops logging queries entirely** while keeping the counts. |
| `COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS` | `250000` | Hard ceiling on the log, whichever limit is reached first. |
| `COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS` | `86400` | How often lists are re-fetched. A failing list retries every five minutes. |
| `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` | auto-detected | The address the UI tells you to give your router. |

The full list is in [`.env.example`](./.env.example) and [the spec](./docs/spec-dnsnet-plus-four.md).
Changing any of them needs a container restart.

---

## Troubleshooting

**The container restarts in a loop, or the log mentions permissions.**
Either the data directory is not writable by UID 10001 (bind mounts only —
`chown -R 10001:10001 <dir>`), or `NET_BIND_SERVICE` is missing from the container.

**Port 53 is already in use.**
Something else on the box is a DNS server — commonly `systemd-resolved` or `dnsmasq`. The one-command
installer detects and fixes this; by hand, see
[DEPLOYMENT.md](./DEPLOYMENT.md). On Unraid, use a `br0` address instead and the conflict disappears.

**Devices are not being filtered.**
Most devices cache their DNS setting until the DHCP lease renews — reboot one to test. Some devices
and browsers ignore the router entirely: check for DNS-over-HTTPS in the browser's settings, and for
a hardcoded resolver on smart TVs and consoles.

**A site is broken.**
Find the lookup on the Activity page and allow it from the row menu. If you are not sure a block is
the cause, the "Why?" action shows exactly which rule or list decided.

**The dashboard says "Lists not downloaded yet".**
The box has no route to the internet yet. It keeps serving from the last good copy of each list, and
picks the download back up on its own.

---

## Upgrading, backup, uninstall

```sh
# Upgrade (Compose)
docker compose pull && docker compose up -d

# Back up — the database is a single file in the volume
docker run --rm -v cogwheel-data:/data -v "$PWD":/backup debian:bookworm-slim \
  cp /data/cogwheel.db /backup/cogwheel-backup.db

# Remove it, restoring the host's DNS settings
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh -s -- --uninstall
```

Upgrading across a schema change rewrites the database in place and writes a `.pre-v1` backup beside
it first. [DEPLOYMENT.md](./DEPLOYMENT.md) covers native (non-Docker) installs, hardening, and
recovery in full.

---

## For developers

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cd apps/cogwheel-web && npm ci && npm run build
```

- **Rust** — Axum, Hickory DNS, a wire-answer cache keyed by scope and query type, SQLite via
  rusqlite.
- **React 19** — Vite, TypeScript, [Shark UI](https://shark.vini.one/), Tailwind CSS v4, self-hosted
  Inter. No CDN requests, because the appliance may sit on a LAN with no internet route.
- **Docker** — multi-arch images for `linux/amd64` and `linux/arm64`.

The full contract — every route, the schema, the block-precedence order, and the measured
before/after numbers — is [docs/spec-dnsnet-plus-four.md](./docs/spec-dnsnet-plus-four.md).
Architecture notes are in [docs/architecture/](./docs/architecture/); superseded descriptions are
kept in [docs/archive/](./docs/archive/).

Benchmarks come from a stdlib-only Python harness with no dependencies of its own — see
[scripts/bench/README.md](./scripts/bench/README.md).
