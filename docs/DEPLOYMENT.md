# Deploying Cogwheel

The operator's manual: installing, networking, upgrading, rolling back, backing
up and removing Cogwheel. If a command here does not work, that is a bug —
please [open an issue](https://github.com/thekozugroup/Cogwheel-DNS/issues).

If you just want a filtered household and not the detail, start with
**[the quick start](QUICKSTART.md)** instead; it is five minutes of attention
once an image is published, and covers every host. This file is what you read
when something here has to be decided rather than accepted.

Cogwheel is a DNS filtering appliance. It binds port 53, answers queries for
every device on your network, and serves a web control plane on port 8080. The
reference target is a **Raspberry Pi 5 running 64-bit Raspberry Pi OS**, but any
64-bit Linux host (`x86_64` or `aarch64`) works.

> ### Before the first release
>
> Nothing has been tagged and no image has been pushed to
> `ghcr.io/thekozugroup/cogwheel-dns`. Five paths in this file depend on
> published artifacts and will fail until `v0.1.0` exists: the one-line
> installer ([§2](#2-the-one-line-installer)), `docker compose
> pull` ([§3](#3-docker-compose)), the release tarball
> ([§4](#4-native-install-with-systemd)), the Unraid template
> ([§1](#1-choosing-an-install-method)) and pinning a version
> ([§10](#10-upgrades-and-rollback)). Building the image yourself works today —
> [§3](#3-docker-compose), or on Unraid
> [QUICKSTART](QUICKSTART.md#building-the-image-yourself-on-unraid).

---

## Contents

1. [Choosing an install method](#1-choosing-an-install-method)
2. [The one-line installer](#2-the-one-line-installer)
3. [Docker Compose](#3-docker-compose)
4. [Native install with systemd](#4-native-install-with-systemd)
5. [Networking: host vs bridge, and why it decides a feature](#5-networking-host-vs-bridge-and-why-it-decides-a-feature)
6. [Pointing your router at Cogwheel](#6-pointing-your-router-at-cogwheel)
7. [Post-install verification checklist](#7-post-install-verification-checklist)
8. [Troubleshooting](#8-troubleshooting)
9. [Configuration reference](#9-configuration-reference)
10. [Upgrades and rollback](#10-upgrades-and-rollback)
11. [Backup and restore](#11-backup-and-restore)
12. [Uninstall](#12-uninstall)
13. [Local development](#13-local-development)

---

## 1. Choosing an install method

| | One-line installer | Docker Compose | Native systemd |
|---|---|---|---|
| Best for | Most people | You already run a Compose stack | You do not want Docker |
| Needs Docker | yes | yes | no |
| Config lives in | `/etc/cogwheel/.env` (generated, then yours) | `.env` (yours to edit) | `/etc/cogwheel/cogwheel.env` (yours to edit) |
| Handles the port-53 conflict | automatically | you run one command | automatically |
| Upgrade | `docker compose pull && up -d` | `docker compose pull && up -d` | rebuild and re-run |

The first two rows differ only in who wrote the Compose project. The installer
writes one to `/etc/cogwheel` and then steps out of the update path entirely, so
**both Compose installs upgrade with the same two commands** —
[§10](#10-upgrades-and-rollback). A native install is rebuilt instead, and
Unraid upgrades from its Docker tab.

All three end up in the same place: a non-root process with
`CAP_NET_BIND_SERVICE`, a persistent data directory, and bounded logs.

**Unraid** is a fourth. There is no Compose project there: Unraid's Docker tab
runs the container from `deploy/unraid/cogwheel.xml`, which carries the
network, the volume and the capability, once that file is on the flash drive.
The steps are in [QUICKSTART §Unraid](QUICKSTART.md#unraid) rather than here,
because there is nothing operator-specific about them — everything in this
file from [§5](#5-networking-host-vs-bridge-and-why-it-decides-a-feature)
onwards applies to an Unraid host, with the exceptions noted in
[§10](#10-upgrades-and-rollback): the upgrade is the Docker tab's own *check
for updates*, and the post-upgrade check runs inside the container.

**Requirements**

- 64-bit Linux, `x86_64` or `aarch64`. 32-bit ARM is not a published target —
  on a Raspberry Pi, install the 64-bit OS.
- Docker 24+ (for the first two methods).
- Root, because binding port 53 and editing resolver configuration both need it.
- ~200 MB of disk for the image, plus room for the database.

---

## 2. The one-line installer

On the machine that will run Cogwheel:

```sh
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh
```

Or from a checkout:

```sh
sudo ./scripts/install.sh
```

The installer:

1. Checks the OS, the CPU architecture and that Docker is running.
2. Finds whatever owns port 53 and resolves it — see
   [§8.1](#81-port-53-is-already-in-use) for exactly what it will and will not
   touch.
3. Pulls the image and starts the container with host networking, a named
   volume, dropped capabilities, a read-only root filesystem and log rotation.
4. Waits for the container to report healthy, then **proves the resolver
   answers a real DNS query** before declaring success.
5. Prints the web URL and the addresses to point your router at.

If any step fails it rolls back: an upgrade is reverted to the previous image,
and a fresh install removes the container and undoes the resolver changes, so
the host is left exactly as it was found. Your data volume is never deleted
automatically.

What it leaves on the host, all of it under `/etc/cogwheel`:

| Path | What it is |
|---|---|
| `docker-compose.yml` | the deployment. Written by the installer — do not hand-edit it; a re-run overwrites it. |
| `.env` | **yours.** A re-run fills in missing keys and never rewrites one you have set, so your upstreams, block mode and profile survive. `--force-env` regenerates it deliberately. |
| `install.sh` | a local copy, so `sudo /etc/cogwheel/install.sh --uninstall` works on a host with no checkout |
| `verify-install.sh` | the post-install and post-upgrade check ([§7](#7-post-install-verification-checklist)) |
| `check-update.sh` | the opt-in "is there anything newer?" check ([§10](#10-upgrades-and-rollback)) |
| `install-state` | exactly which host changes were made, so `--uninstall` reverses those and nothing else |

The data volume is `cogwheel-data`, named explicitly in both compose files so a
host installed before the Compose rewrite keeps its database rather than
silently starting empty beside an orphaned volume.

Useful flags:

```sh
sudo ./scripts/install.sh --help
sudo ./scripts/install.sh --network bridge          # see §5
sudo ./scripts/install.sh --upstream 9.9.9.9:53,149.112.112.112:53
sudo ./scripts/install.sh --dns-port 5353           # do not take :53 at all
sudo ./scripts/install.sh --uninstall               # see §12
```

---

## 3. Docker Compose

```sh
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS
cp .env.example .env
$EDITOR .env

# Resolve the port-53 conflict first — Compose cannot do this for you.
sudo ./scripts/install.sh --fix-port-53

docker compose pull        # fails until v0.1.0 is published; build instead, below
docker compose up -d
docker compose ps          # wait for STATUS = healthy
```

`.env.example` documents every variable. The defaults are sized for a
Raspberry Pi 5: two CPUs, 1 GiB memory, three rotated 10 MB log files.

To build locally instead of pulling a published image — which is the only
option until `v0.1.0` is tagged:

```sh
docker build -t cogwheel-dns:dev .
COGWHEEL_IMAGE=cogwheel-dns:dev docker compose up -d
```

The build compiles the Rust server and the web app from source. As an estimate,
not a timing of this build: about 10 minutes on a four-core x86_64 machine and
30–60 minutes on a Raspberry Pi 5, plus downloading the Rust and Node build
images.

There is deliberately no `build:` block in `docker-compose.yml`. Compose builds
a missing image when a service declares both `image:` and `build:`, and on a
Raspberry Pi that turns an innocent `docker compose up -d` into an unannounced
half-hour compile. Building is a thing you ask for.

`docker-compose.yml` defaults to **host networking**. Read
[§5](#5-networking-host-vs-bridge-and-why-it-decides-a-feature) before changing
it — the choice determines whether per-device rules and list selection work.

---

## 4. Native install with systemd

For hosts where you do not want Docker at all.

```sh
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS
sudo ./scripts/install-native.sh
```

This builds the server and the web app from source (slow on a Pi — expect
20-40 minutes for a cold Rust build), creates a `cogwheel` system user, resolves
the port-53 conflict, and installs
[`deploy/cogwheel.service`](../deploy/cogwheel.service).

To skip the build and use a published release artifact instead — this is the
whole thing, copy-pasteable, and it works out the current version for you:

```sh
VERSION=$(curl -fsSL https://api.github.com/repos/thekozugroup/Cogwheel-DNS/releases/latest |
          sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
[ -n "$VERSION" ] || { echo 'No published release yet — build from source above.'; exit 1; }

TARBALL="cogwheel-${VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz"
curl -fsSLO "https://github.com/thekozugroup/Cogwheel-DNS/releases/download/v${VERSION}/${TARBALL}"
sudo ./scripts/install-native.sh --tarball "${TARBALL}"
```

The guard on the second line is not decoration. With no release published, the
API returns 404, `VERSION` comes out empty, and the line after it cheerfully
builds `cogwheel--x86_64-unknown-linux-gnu.tar.gz` — a filename with a hole in
it, which `curl` then fails to download for a reason that has nothing to do with
the real problem. One sentence beats one 404.

`uname -m` reports `aarch64` on 64-bit Raspberry Pi OS and `x86_64` on a PC,
which are exactly the two names used in the asset filenames. If it prints
`armv7l` you are on a 32-bit OS and there is no build for it — see §2.

What gets installed:

| Path | Contents |
|---|---|
| `/usr/local/bin/cogwheel-server` | the binary |
| `/usr/local/share/cogwheel/web` | web assets (`COGWHEEL_WEB_DIST_DIR`) |
| `/etc/cogwheel/cogwheel.env` | configuration — **safe to edit**, preserved across upgrades |
| `/var/lib/cogwheel` | SQLite database, owned by `cogwheel:cogwheel`, mode 0750 |
| `/etc/systemd/system/cogwheel.service` | the unit |

Day-to-day:

```sh
systemctl status cogwheel
journalctl -u cogwheel -f
sudo systemctl restart cogwheel        # after editing cogwheel.env
systemd-analyze security cogwheel      # review the hardening
```

The unit runs as a dedicated non-root user with `ProtectSystem=strict`,
`NoNewPrivileges=yes`, a capability bounding set of exactly
`CAP_NET_BIND_SERVICE`, a seccomp filter, and memory/CPU/task limits.

One path is writable: `/var/lib/cogwheel`, the data directory created by
`StateDirectory=`. Everything else, including `/usr/local/bin`, stays
read-only, so nothing the service does can replace its own binary.

---

## 5. Networking: host vs bridge, and why it decides a feature

Cogwheel applies settings **per device**, and it identifies a device by the
source IP address of its DNS query. Internally the resolver keeps a
`HashMap<IpAddr, Scope>`; a query whose client address is not in that map
resolves under the household scope.

So the networking mode is not a deployment detail. It decides whether
per-device rules, list selection and per-device statistics work at all.

### Host networking (the default)

```yaml
network_mode: host
```

- DNS sockets are bound directly on the host's interfaces. Every query arrives
  with the real LAN client address, so per-device rules and list selection work.
- No NAT hop on the DNS hot path.
- `ports:` is ignored; Cogwheel binds host `:53` and `:8080` directly, so a
  port conflict is a hard failure rather than a silent fallback.
- Linux only.

### Bridge networking with published ports

```yaml
# ports:
#   - "53:5353/udp"
#   - "53:5353/tcp"
#   - "8080:8080/tcp"
```

- Normal container isolation; works on Docker Desktop.
- Inbound queries traverse Docker's NAT/proxy path. Depending on the host's
  `userland-proxy` setting and iptables state, the source address the container
  observes is frequently rewritten to the bridge gateway (`172.x.0.1`).
  **When that happens every device looks like one client and per-device
  rules and list selection silently collapse to the household policy** — no
  error, just wrong behaviour.
- In this mode bind DNS to `5353` inside the container
  (`COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:5353`) and publish it as
  `53:5353`. No capability is then required inside the container, and you can
  safely add `security_opt: ["no-new-privileges:true"]`.
- Keep `COGWHEEL_SERVER__ADVERTISED_DNS_PORT=53` — that is the port *clients*
  use, not the port the process bound.

**Do not take this on trust — measure it.** Query the resolver from a second
machine, then check which client the query was attributed to:

```sh
dig @<cogwheel-host> example.com          # from another device on the LAN
```

Open the Activity page (`http://<cogwheel-host>:8080/activity`) and look at the
client column for that query. If it shows the Docker gateway rather than the
querying device, switch to host networking, or give the container its own LAN
address with a **macvlan** network — that preserves client IPs while keeping
container isolation.

---

## 6. Pointing your router at Cogwheel

Set DNS **on the router**, in its DHCP settings, not on each device. That way
every client — including ones you cannot configure, like a TV or a games
console — is covered automatically.

1. Find the addresses Cogwheel is advertising. The installer prints them, the
   Overview page shows them, and the API returns them:

   ```sh
   curl -s http://<cogwheel-host>:8080/api/v1/overview | grep -o '"connect":{[^}]*}'
   ```

2. Give the Pi a **static address or a DHCP reservation** first. If its address
   changes, DNS stops working for the whole house.

3. In your router: *DHCP / LAN → DNS servers* → enter the Cogwheel address.
   Remove any other entries, or clients will silently use the other resolver
   and bypass filtering.

4. **On a dual-stack network, set the IPv6 address too.** A client with an IPv6
   resolver configured will happily ignore an IPv4-only DNS setting. This is the
   single most common reason people think filtering "randomly stops working".

5. Renew leases (or reboot clients) so they pick up the new setting.

If your router will not let you change DNS, set it per-device instead, or have
the router hand out Cogwheel's address as the gateway's DNS forwarder.

---

## 7. Post-install verification checklist

Run the scripted version. The one-line installer leaves a copy on the host, so
this works on a machine that has never had a checkout, and the image carries one
for a host that only has the container:

```sh
sudo /etc/cogwheel/verify-install.sh               # the one-line installer
sudo sh scripts/verify-install.sh                  # from a checkout: Compose from a clone, or native
docker exec cogwheel sh /app/verify-install.sh     # Unraid, or any host with only the container
sh scripts/verify-install.sh --host 10.0.0.2       # remote
sh scripts/verify-install.sh --skip-restart        # no restart test
```

`sudo` on the first two because the persistence check restarts the container or
the service. A native install with non-default ports needs `--http-port` and
`--dns-port`; its closing summary prints the exact line.

It exits non-zero if anything fails, so it also works from cron or a monitor.

Or check each item by hand:

### Control plane

```sh
curl -fsS http://<host>:8080/health/live      # {"data":{"status":"ok"}}
curl -fsS http://<host>:8080/health/ready     # {"data":{"status":"ready"}}
curl -fsS http://<host>:8080/api/v1/overview | head -c 200
curl -fsSI http://<host>:8080/ | head -1      # 200 OK, the web UI
```

`/health/live` and `/health/ready` are distinct signals. Liveness is what the
container `HEALTHCHECK` probes: it answers 200 as soon as the HTTP listener is up.

**Readiness reports per-subsystem state** and returns **503 until every subsystem
is up**, so it is safe to gate a rolling upgrade on. The body names which parts
are ready:

```json
{"data":{"status":"ready","subsystems":{"storage":true,"policy":true,"dns_listeners":true}}}
```

- `storage` — the database is open and its migrations applied.
- `policy` — an initial ruleset has been compiled and installed. On a cold start
  with large blocklists this is the slow one.
- `dns_listeners` — the UDP and TCP sockets are bound and accepting.

A node that is live but not ready is running and answering HTTP, but is not yet
filtering. Do not send it traffic.

The operationally interesting counters live under `runtime` in
`GET /api/v1/overview`.

### Resolver

```sh
# An allowed domain must resolve normally.
dig @<host> example.com A +short
#   -> a real address, and specifically not 0.0.0.0

# A stock install ships no active rules of its own -- the seeded default list
# has to download first, which has not necessarily happened yet. A household
# rule takes effect immediately with no list involved, so install one to prove
# filtering works without waiting on that download.
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"domain":"blocked.test","action":"block"}' \
     http://<host>:8080/api/v1/rules
dig @<host> blocked.test A +short
#   -> 0.0.0.0

# TCP as well as UDP. Large answers fall back to TCP; if only UDP works,
# some lookups will fail in ways that are very hard to diagnose later.
dig @<host> example.com A +tcp +short
```

Blocked domains return `0.0.0.0` (and `::` for AAAA) because the default block
mode is null-IP. Remove the marker rule afterwards from the Lists page, or:
`curl -X DELETE http://<host>:8080/api/v1/rules/<id>` (the `id` came back in
the POST response above).

### Persistence

State must survive a restart. If it does not, the data volume is not mounted
where you think it is.

```sh
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"name":"persistence-check","ip_address":"192.0.2.9"}' \
     http://<host>:8080/api/v1/devices                          # note the id
docker restart cogwheel                                          # or: systemctl restart cogwheel
sleep 20
curl -s http://<host>:8080/api/v1/devices | grep persistence-check   # must still be there
curl -X DELETE http://<host>:8080/api/v1/devices/<id>            # clean up
```

`scripts/verify-install.sh` automates this properly: it writes a uniquely named
marker device, restarts Cogwheel, confirms the record survived, and deletes it
again.

### End to end

From a *different* device on the network, after pointing it at Cogwheel:

```sh
nslookup example.com
nslookup googlesyndication.com      # 0.0.0.0, once the default list has downloaded
```

Then open `http://<host>:8080` and confirm the Overview page shows the query.

---

## 8. Troubleshooting

Organised by what you are looking at, not by what is wrong — the cause is the
answer, not the index.

| What you see | |
|---|---|
| The container restarts in a loop; `Address already in use` | [8.1](#81-port-53-is-already-in-use) |
| The container is healthy but no lookup is answered | [8.2](#82-the-container-starts-but-dns-does-not-answer) |
| Every device in the house shows as one client | [8.3](#83-every-device-shows-up-as-one-client) |
| `EROFS` / read-only filesystem in the logs | [8.4](#84-the-container-exits-with-a-read-only-filesystem-error) |
| A list's Status column says it last failed | [8.5](#85-blocklists-will-not-update) |
| The web UI answers 404 | [8.6](#86-web-ui-returns-404) |
| DNS works, but nothing is ever blocked | [8.7](#87-nothing-is-filtered-even-though-dns-works) |
| Nothing resolves at all since switching to DNS-over-TLS | [8.8](#88-nothing-resolves-since-i-switched-to-dns-over-tls-or-dns-over-https) |
| The web UI will not open from another machine | [8.9](#89-i-cannot-open-the-web-ui-from-another-machine) |
| The upgrade came up healthy and then made things worse | [8.10](#810-the-upgrade-made-it-worse) |
| The container restarts in a loop; the log mentions permissions, or `Operation not permitted` | [8.11](#811-the-container-restarts-in-a-loop-and-the-log-mentions-permissions) |
| The dashboard says *Lists not downloaded yet* | [8.5](#85-blocklists-will-not-update) |
| One site is broken | [USING.md](USING.md#when-a-site-breaks) — allow it from the Activity row |

### 8.1 Port 53 is already in use

**This is the most common failure, by a wide margin.** On most Linux hosts
`systemd-resolved` runs a stub resolver on `127.0.0.53:53`, which prevents
anything else from binding port 53.

Symptoms: the container restarts in a loop, or the service fails immediately;
logs show an address-in-use error.

Diagnose:

```sh
sudo ss -lnptu '( sport = :53 )'
```

Fix, the supported way:

```sh
sudo ./scripts/install.sh --fix-port-53              # from a checkout
sudo /etc/cogwheel/install.sh --fix-port-53          # a one-line install, no checkout
```

On Unraid neither applies: the usual holders there are another DNS container on
host networking and, with the VM Manager enabled, libvirt's `dnsmasq` —
[QUICKSTART §Unraid](QUICKSTART.md#unraid) has the check and the way round it.

That command:

- writes `/etc/systemd/resolved.conf.d/10-cogwheel-stub-listener.conf`
  containing `DNSStubListener=no`,
- repairs `/etc/resolv.conf`, which on these hosts is a symlink to
  `stub-resolv.conf` and would otherwise point the machine at a resolver that
  no longer exists — it is repointed at `/run/systemd/resolve/resolv.conf`,
  the uplink file listing the real upstream servers,
- restarts `systemd-resolved`,
- records what it changed in `/etc/cogwheel/install-state` so
  `--uninstall` can reverse exactly those changes.

If it has to replace `/etc/resolv.conf` with a static file rather than
repointing a symlink, it first copies the original to
`/etc/cogwheel/resolv.conf.pre-cogwheel`. `--uninstall` restores that copy. If
the copy is missing — an install from before this was fixed, or someone deleted
it — uninstall writes a resolv.conf naming the configured upstream servers
instead. It will not leave the host without a resolver.

`/etc/resolv.conf` is deliberately **not** pointed at Cogwheel itself. If the
host resolved through Cogwheel and Cogwheel failed to start, the machine would
have no DNS — and no DNS means you cannot pull an image to fix it.

Doing it by hand instead:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/10-cogwheel-stub-listener.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

**If the port is held by a real DNS server** — `dnsmasq`, `named`/BIND,
`unbound`, CoreDNS, Knot — the installer stops and tells you, rather than
disabling it. That is deliberate: `dnsmasq` in particular is often also serving
DHCP, and turning it off without warning would take the network down. Stop it
yourself when you are ready:

```sh
sudo systemctl disable --now dnsmasq     # or named / bind9 / unbound
```

On OpenWrt, set dnsmasq's port to `0` rather than disabling it, so DHCP keeps
running.

**If you would rather not take port 53 at all**, run Cogwheel on a high port
and point clients at it explicitly:

```sh
sudo ./scripts/install.sh --dns-port 5353
```

### 8.2 The container starts but DNS does not answer

```sh
docker logs cogwheel --tail 50
docker inspect --format '{{.State.Health.Status}}' cogwheel
```

- Check the bind address matches the networking mode. With host networking DNS
  must bind `:53`; with bridge networking it must bind `:5353` and be published
  as `53:5353`. A mismatch produces a healthy container that answers nothing.
- Check a host firewall is not blocking 53:
  `sudo ufw allow 53/udp && sudo ufw allow 53/tcp && sudo ufw allow 8080/tcp`.
- Confirm both protocols are reachable: `dig @<host> example.com` and
  `dig @<host> example.com +tcp`.

### 8.3 Every device shows up as one client

Per-device rules are not applying and the Activity/Devices pages attribute
everything to a single address, usually `172.x.0.1`. That is the Docker bridge
gateway — see
[§5](#5-networking-host-vs-bridge-and-why-it-decides-a-feature). Switch to host
networking or macvlan.

### 8.4 The container exits with a read-only filesystem error

`docker-compose.yml` sets `read_only: true`. The only writable paths are the
data volume and a `tmpfs` at `/tmp`. If the server needs to write somewhere
else, you will see an `EROFS` error in the logs. Set `read_only: false` to get
running again, then please report the path it needed.

### 8.5 Blocklists will not update

The updater fetches sources over HTTPS. Check the host clock (TLS fails on a Pi
with a wrong date and no RTC), then check egress:

```sh
docker exec cogwheel curl -fsSI https://example.com | head -1
timedatectl status
```

### 8.6 Web UI returns 404

The server started without web assets. `COGWHEEL_WEB_DIST_DIR` must point at a
directory containing `index.html`; the image sets `/app/web`. On a native
install it is `/usr/local/share/cogwheel/web`. The startup log says either
`serving bundled web assets` or `web assets not found; serving API routes only`.

### 8.7 Nothing is filtered even though DNS works

Clients are reaching a different resolver. Most often: the router hands out its
own address for DNS, or IPv6 DNS is still pointing elsewhere
([§6](#6-pointing-your-router-at-cogwheel) step 4). Check what a client
actually uses with `resolvectl status` or `nslookup example.com`.

### 8.8 Nothing resolves since I switched to DNS-over-TLS or DNS-over-HTTPS

Every lookup fails, all at once, right after changing `COGWHEEL_UPSTREAM__SERVERS`
to a `tls://` or `https://` form. Nothing is partially broken — the house has no
DNS.

**This is the design working, not failing.** An encrypted upstream is registered
with *only* its encrypted transport, and there is no cleartext fallback: if TLS
cannot be established, resolution stops visibly instead of quietly continuing in
the clear. A fallback would defeat the entire reason you configured it
([§9.1](#91-encrypting-queries-to-the-upstream-resolver)).

So the question is why the TLS handshake fails. In order of how often it is the
answer:

```sh
# 1. The clock. A Pi with no RTC that booted without network has the wrong date,
#    and every certificate on earth is then either not-yet-valid or expired.
timedatectl status

# 2. Port 853 outbound, and whether TLS completes on it. Some networks allow
#    443 and nothing else. curl is in the image for exactly this.
#    A certificate printed back = reachable. A timeout = blocked.
docker exec cogwheel curl -sv --max-time 5 -o /dev/null https://1.1.1.1:853/ 2>&1 | head -20

# 3. The certificate name. The text after `#` is what the certificate must
#    match, and it is not optional. `tls://1.1.1.1#cloudflare-dns.com` is right;
#    `tls://1.1.1.1` alone will not validate against anything.
docker compose logs | grep -i 'tls\|certificate\|upstream'
```

A captive portal or a TLS-inspecting middlebox will also fail this, correctly,
and so will an internal resolver using a private CA — Cogwheel validates against
the Mozilla root set compiled into the binary and deliberately does not read the
host's certificate store.

To get the house resolving again while you work it out, put a cleartext upstream
back. On a one-line install:

```sh
cd /etc/cogwheel
sudo sed -i 's|^COGWHEEL_UPSTREAM__SERVERS=.*|COGWHEEL_UPSTREAM__SERVERS=1.1.1.1:53,1.0.0.1:53|' .env
sudo docker compose up -d
```

From a clone, run the same `sed` and `docker compose up -d` in the clone's
directory. On a native install the file is `/etc/cogwheel/cogwheel.env` and the
restart is `sudo systemctl restart cogwheel`; on Unraid, edit *Upstream
resolvers* on the container and **Apply**.

### 8.9 I cannot open the web UI from another machine

Distinct from [8.6](#86-web-ui-returns-404): there, the server answers and the
answer is a 404. Here nothing answers at all — the browser hangs or refuses the
connection.

Work outwards from the process:

```sh
# 1. Does it answer on the host itself? If this works, the server is fine and
#    the problem is between the host and you.
curl -fsS http://127.0.0.1:8080/health/live

# 2. What is it bound to? 127.0.0.1 answers only the host itself; a remote
#    machine needs 0.0.0.0. The `dev` profile binds loopback on purpose.
docker exec cogwheel sh -c 'echo $COGWHEEL_SERVER__HTTP_BIND_ADDR'
sudo ss -lntp '( sport = :8080 )'

# 3. A host firewall.
sudo ufw status && sudo ufw allow 8080/tcp
```

The most common cause on a working install is the first one inverted: the host
runs the `dev` profile, which binds `127.0.0.1:30080` deliberately, so the UI is
reachable from the host and from nowhere else. `home` is the profile for an
appliance ([§9](#9-configuration-reference)).

There is **no authentication on the control plane**. Anything that can reach
port 8080 can change what the household resolves. Keep it on the LAN; if you
need it from outside, put it behind something that authenticates, and never
forward 8080 from a router.

### 8.10 The upgrade made it worse

It pulled, it came up healthy, the checks passed — and something is behaving
worse than before. A health check answers whether the process is up, not whether
you like what it is doing, and nothing rolls back an upgrade that succeeded.

1. **Find out whether the schema moved**, because it decides which rollback you
   need:

   ```sh
   docker image inspect ghcr.io/thekozugroup/cogwheel-dns:latest \
     --format '{{ index .Config.Labels "io.cogwheel.schema-version" }}'
   ```

   Compare it against the Settings page. Same number: the plain rollback. Higher
   than what you were on: the snapshot has to go back first.

2. **Roll back** — [§10 Rolling back](#rolling-back) has both procedures.

3. **Then say what happened.** A release that comes up healthy and behaves worse
   is the failure mode CI cannot catch, so the issue report is the only way it
   gets fixed: the two version numbers, what changed in behaviour, and the output
   of the verify command for your install ([§10](#then-verify)).

### 8.11 The container restarts in a loop and the log mentions permissions

Two causes, and the log tells them apart.

**The data directory is not writable by uid 10001.** Cogwheel runs as that
user, not as root. A Docker named volume inherits the right owner from the
image and never has this problem; a bind mount does, because the host
directory keeps whatever owner it was created with. Fix it once:

```sh
sudo chown -R 10001:10001 /path/to/the/bind-mounted/directory
```

On Unraid with the data in appdata that is
`chown -R 10001:10001 /mnt/user/appdata/cogwheel`.

**`NET_BIND_SERVICE` is missing from the container.** The log line is
`exec /usr/local/bin/cogwheel-server failed: Operation not permitted`, before
Cogwheel prints anything of its own. The capability is required, not a
hardening nicety: the binary carries it as a file capability with the
effective bit set, so without it in the container's bounding set the kernel
refuses to run the binary at all, under any network mode. Every shipped
configuration adds it — `cap_add` in both Compose files, `ExtraParams` in the
Unraid template — so this means it was removed by hand.

---

## 9. Configuration reference

Every variable is read by the server itself. Names are exact — a typo is
silently ignored rather than reported.

| Variable | Default (`home` profile) | Notes |
|---|---|---|
| `COGWHEEL_PROFILE` | `home` | `dev` or `home`; `smb` is accepted as an alias of `home`. Sets the defaults below. |
| `COGWHEEL_SERVER__HTTP_BIND_ADDR` | `0.0.0.0:8080` | Web UI and API. |
| `COGWHEEL_SERVER__DNS_UDP_BIND_ADDR` | `0.0.0.0:5353` | The image overrides this to `:53`. |
| `COGWHEEL_SERVER__DNS_TCP_BIND_ADDR` | `0.0.0.0:5353` | Keep in step with UDP. |
| `COGWHEEL_SERVER__ADVERTISED_DNS_PORT` | bound DNS port | The port *clients* use. Stays `53` behind a port mapping. |
| `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` | *(empty, falls back to `hostname -I`)* | Comma-separated addresses shown to users. The installers fill this in from the host's interfaces. |
| `COGWHEEL_STORAGE__DATABASE_URL` | `sqlite://data/cogwheel.db` | `sqlite://` is stripped. Use an absolute path. |
| `COGWHEEL_UPSTREAM__SERVERS` | `1.1.1.1:53,1.0.0.1:53` | Comma-separated. `ip:port` is cleartext (UDP+TCP); `tls://ip#certname` is DNS-over-TLS and `https://ip#certname` is DNS-over-HTTPS. See [§9.1](#91-encrypting-queries-to-the-upstream-resolver). |
| `COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS` | `86400` (`3600` in `dev`) | Floored at 300 s; a list that is currently failing retries every 300 s regardless of this setting. |
| `COGWHEEL_BLOCKING__MODE` | `null_ip` | `null_ip`, `nxdomain`, `nodata` or `refused`. See [§9.2](#92-how-blocked-names-are-answered). |
| `COGWHEEL_RETENTION__HISTORY_DAYS` | `7` | Days of query-log rows to keep. `0` stops writing the query log entirely; the hourly rollups behind the Overview and Devices pages are kept either way. |
| `COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS` | `250000` | Hard cap on query-log rows, enforced by the same prune. |
| `COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS` | `3600` | How often the prune runs. Floored at 60 s. |
| `COGWHEEL_WEB_DIST_DIR` | *(search path)* | Directory containing `index.html`. |
| `RUST_LOG` | `info` | tracing/`EnvFilter` syntax. Used as-is when set — it replaces the `info` default rather than layering on top of it, so it can narrow the level too (e.g. `RUST_LOG=error`), not only widen it. |

Profile defaults:

| Setting | `dev` | `home` |
|---|---|---|
| HTTP bind | `127.0.0.1:30080` | `0.0.0.0:8080` |
| DNS bind | `127.0.0.1:30053` | `0.0.0.0:5353` |
| Refresh interval | 3600 s | 86400 s |

`smb` is not a third set of defaults — it is accepted as an alias of `home`
and behaves identically to it.

There is no configuration file. Everything is environment variables.

### 9.1 Encrypting queries to the upstream resolver

By default Cogwheel talks to its upstream in **cleartext on port 53**. Blocking
trackers while the name of every site every device asks for stays readable to
the local network and to your ISP is an odd place to stop, so upstreams can also
be DNS-over-TLS (RFC 7858) or DNS-over-HTTPS (RFC 8484):

```sh
# Cloudflare over DNS-over-TLS
sudo ./scripts/install.sh --upstream tls://1.1.1.1#cloudflare-dns.com,tls://1.0.0.1#cloudflare-dns.com

# Quad9 (malware filtering) over DNS-over-TLS
sudo ./scripts/install.sh --upstream tls://9.9.9.9#dns.quad9.net,tls://149.112.112.112#dns.quad9.net
```

| Form | Transport | Default port |
|---|---|---|
| `1.1.1.1:53` | cleartext UDP + TCP | 53 |
| `tls://1.1.1.1#cloudflare-dns.com` | DNS-over-TLS | 853 |
| `https://1.1.1.1#cloudflare-dns.com` | DNS-over-HTTPS (path `/dns-query`) | 443 |

**Why the address and the name are given separately.** The text after `#` is the
name the server's certificate must match, and it is required. The obvious
alternative — writing `tls://cloudflare-dns.com` and looking the name up — needs
a bootstrap query, and a bootstrap query is a cleartext query: the exact leak
being closed would reopen on every restart. Naming both removes the bootstrap.
There is no option to skip certificate verification, because an encrypted
channel to an unverified peer is worse than a cleartext one — it looks safe.

**Do not mix encrypted and cleartext upstreams.** Queries are spread across all
configured servers, so a single cleartext entry silently leaks a share of them.
Cogwheel logs a warning if you do, and another if every upstream is cleartext.

**No silent downgrade.** An encrypted upstream is registered with *only* its
encrypted transport. If TLS fails — a captive portal, a middlebox, an expired
certificate — resolution fails visibly instead of quietly continuing in the
clear. That is deliberate: a fallback would defeat the reason you configured it.

**Private CAs are not trusted.** Cogwheel validates against the Mozilla root set
compiled into the binary, so it does not read the host's certificate store. An
internal resolver using a private CA will not validate. (This also means DoT
keeps working on a host whose `/etc/ssl` is missing or broken.)

**What this does and does not hide.** Your ISP stops seeing the domains. The
upstream operator still sees all of them — encryption changes *who* you trust,
it does not remove the need to trust someone. Queries Cogwheel answers from its
blocklists or cache never leave the house at all, encrypted or not.

### 9.2 How blocked names are answered

`COGWHEEL_BLOCKING__MODE`, or `--block-mode` on the installer:

| Mode | Answer |
|---|---|
| `null_ip` *(default)* | `0.0.0.0` / `::` |
| `nxdomain` | `NXDOMAIN` |
| `nodata` | `NOERROR` with no answers |
| `refused` | `REFUSED` |

`null_ip` is the default because clients handle it most predictably. The others
are there because people have preferences; none of them changes what is blocked,
only how the "no" is phrased.

Cogwheel never fetches ads and never reports impressions. A DNS resolver hands
back an address; it does not load pages or fire tracking pixels, so there is no
impression for it to signal. Some sites detect DNS-level blocking and ask you to
turn it off — that is a property of blocking at this layer, and defeating it
would mean intercepting HTTPS for every device on your network, which is a much
larger security decision than ad blocking and not something this does.

### 9.3 Caching, and what to do when a site breaks

**Cogwheel caches answers.** One cache, bounded at 10,000 entries, keyed by
policy scope, query type and name. Every entry carries two lifetimes:

| Phase | Lifetime | Served |
|---|---|---|
| Fresh | the record's own TTL, clamped to 5 s – 1 h | on every matching query |
| Stale | up to 24 h past the fresh lifetime | **only** after the upstream has failed to refresh it |

The fresh phase honours the TTL the authoritative server published, taking
the shortest TTL in the answer. That matters more than it sounds: a cache that
ignores TTLs keeps handing out an address after the site has moved, and
CDN failover, geo-routing and blue/green deploys all rely on short TTLs being
respected. Answers with no records at all (`NXDOMAIN`, `NODATA`) are held for
only 60 s, so a host that has just been provisioned does not stay unreachable.

Past the fresh lifetime the same entry can still be served, but deliberately
only as a *stale* fallback once the upstream has already failed to answer — a
day-old address beats no DNS at all.

A policy change (list edit, device or rule edit) invalidates the whole cache
immediately, so an unblock takes effect on the next query rather than whenever
an entry happens to age out.

#### When a site breaks

DNS filtering breaks sites in two distinct ways, and the fix differs:

**1. Something it needs is on a blocklist.** The usual cause. Blocklists are
maintained by other people and occasionally include a domain a site genuinely
depends on — a login provider, a payment iframe, a CDN.

- Fastest check: `POST /api/v1/runtime/pause` pauses filtering entirely. If the
  site starts working, it is a blocking problem; if not, look elsewhere before
  spending time on blocklists.
- Then narrow it: the Activity page shows what was blocked while the page
  loaded. Add an allow rule for the offending name (household, or just for
  that device), or disable the list that supplied it on the Lists page
  (`PUT /api/v1/lists/{id}` with `enabled:false`, or `DELETE` to remove it).

**2. It is not blocking at all.** Worth ruling out early, because it looks
identical from the browser: a stale cached address, an upstream that is failing,
or a device that has cached the old answer itself. `GET /api/v1/overview`'s
`runtime` object reports cache hits, expiries, upstream failures and fallback
responses. Browsers and phones keep their own DNS caches, so test with `dig`
before concluding anything.

#### The safety net

Some names are never blocked, whatever a blocklist says: resolver bootstrap and
captive-portal checks, NTP, and certificate-status endpoints. Blocking those can
leave a device with no route back to working — a clock that has drifted fails
TLS everywhere, with errors that point nowhere near DNS.

That protection is a **suffix** match, so it covers subdomains, which is where
those lookups actually happen. It is deliberately short — 21 suffixes — and does
not reach broad domains like OS vendors or banks: a blocklist entry covering
those is a choice someone made, and silently overruling it would be its own
surprise.

---

## 10. Upgrades and rollback

How you upgrade depends on how you installed, and there are three answers. A
Compose install — the one-line installer's or your own — is upgraded the way
any Compose deployment is: pull a newer image, recreate the container. Unraid
does the same thing from its Docker tab. A native install has no image, so it
is rebuilt from source or re-installed from a newer release tarball. In every
case there is no self-updater, nothing in the product checks for new versions,
and the one-line installer is not in the path.

### The two commands

**Installed with the one-line installer** — the Compose project is in
`/etc/cogwheel`:

```sh
cd /etc/cogwheel
sudo docker compose pull
sudo docker compose up -d
```

`cd` first rather than passing `-f`. That makes the working directory the
project directory, which is how every version of Compose finds the `.env`
beside the compose file; some versions do not resolve it from `-f` alone, and
the failure mode is a container started with none of your settings.

**Installed from a clone, or any directory holding `docker-compose.yml`:**

```sh
docker compose pull
docker compose up -d
```

**Built from source** — the only Compose path before `v0.1.0` — has nothing to
pull. Rebuild from the clone and recreate:

```sh
git pull
docker build -t cogwheel-dns:dev .
COGWHEEL_IMAGE=cogwheel-dns:dev docker compose up -d
```

**Unraid:** Docker tab → cogwheel → *check for updates* → **Apply Update**.
That works because `deploy/unraid/cogwheel.xml` tracks the moving `:latest` tag
and Unraid compares digests; a pinned tag has a digest that never moves, so the
Docker tab would report "up-to-date" forever, through a security release
included. Pinning is a real choice — see
[Which tag should I track?](RELEASING.md#which-tag-should-i-track) — but
make it knowingly. An image you built yourself before `v0.1.0` has no registry
digest to compare: rebuild it under the same name
([QUICKSTART](QUICKSTART.md#building-the-image-yourself-on-unraid)), then
**Edit** → **Apply** on the container to recreate it from the new image.

**Native**, from the checkout you installed from:

```sh
git pull
sudo ./scripts/install-native.sh
```

Or, installed from a release tarball, fetch the newer one and pass it with
`--tarball` exactly as in [§4](#4-native-install-with-systemd).
`/etc/cogwheel/cogwheel.env` is preserved either way unless you pass
`--force-env`.

Re-running `install.sh` on a Docker host is still safe and idempotent — it never
rewrites your `.env` — but it is not how you upgrade, and there is no reason to
reach for it.

### Then verify

The same script on every host; where it lives is what differs:

```sh
sudo /etc/cogwheel/verify-install.sh              # the one-line installer
sudo sh scripts/verify-install.sh                 # from the checkout: Compose from a clone, or native
docker exec cogwheel sh /app/verify-install.sh    # Unraid
```

The one-line installer leaves a copy on the host precisely so the post-upgrade
check works somewhere that has never had a checkout; `install-native.sh` copies
nothing but `cogwheel.env` to `/etc/cogwheel`, so a native host runs it from
its checkout or unpacked release tarball — both carry `scripts/` — with
`--http-port` and `--dns-port` if you changed them. It exits non-zero on
failure — see [§7](#7-post-install-verification-checklist) for what it covers.

### Is there anything newer?

Cogwheel does not tell you. That is deliberate: the first thing a privacy appliance
should not do is open an unannounced connection on first boot, even a harmless
one, and even to answer a useful question. **Cogwheel makes no update check and
no outbound request of its own.**

So the check is something you run, and which one depends on the install:

| Installed with | Ask with |
|---|---|
| The one-line installer | `sudo /etc/cogwheel/check-update.sh` |
| Compose from a clone | `sudo sh scripts/check-update.sh`, from the clone |
| Unraid | the Docker tab's *check for updates* — Unraid's feature, not Cogwheel's |
| Native | the release-tag check [below](#a-native-install-has-no-update-check) |

The script speaks only to `ghcr.io`, the registry this host already pulls from
— the same conversation `docker pull` has, minus the download. No credentials,
no identifiers, nothing about DNS. It changes nothing, and prints the two
commands to apply an update if there is one. It compares image digests, so it
has nothing to say about an image you built yourself.

| Exit | Meaning |
|---|---|
| `0` | up to date, or pinned by digest — which can never move, so there is nothing to check |
| `10` | a newer image exists for the tag this host follows |
| `1` | could not find out |

Which makes it usable from cron, where the exit status is the whole message.
On a one-line install, in root's crontab (from a clone, use the clone's path to
the script):

```sh
# Weekly, Sunday 09:00. --quiet prints nothing when there is nothing to say,
# so cron mails you only on exit 10.
0 9 * * 0 /etc/cogwheel/check-update.sh --quiet
```

Without `--quiet` it prints on every run and cron mails you every Sunday
regardless, which trains you to ignore it. Do not append `|| true` either: the
exit status is the message, and discarding it is the same as not running the
check.

It also reports the one fact that decides how much care an upgrade needs:
whether the new image changes the database schema. That comes off the image's
own `io.cogwheel.schema-version` label, and you can read it yourself before
pulling anything:

```sh
docker buildx imagetools inspect ghcr.io/thekozugroup/cogwheel-dns:latest \
  --format '{{ json .Image.Config.Labels }}'
```

Compare `io.cogwheel.schema-version` against what the Settings page reports.
Today both are `1`.

#### A native install has no update check

Everything above compares container images, and a native install has none —
so neither the script nor the Docker tab applies, and nothing in the product
will tell you a release is out. Ask GitHub yourself, when you choose to:

```sh
/usr/local/bin/cogwheel-server --version
curl -fsSL https://api.github.com/repos/thekozugroup/Cogwheel-DNS/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'
```

The first line is the version you run; the second is one anonymous request to
`api.github.com`, made by you, which prints the newest final release's tag —
`v0.1.0`, say. Prereleases are never "latest", so it will not offer you one.
Before the first release exists, `curl` reports a 404 and nothing else prints.
If the tag is newer than what `--version` prints, upgrade as
[above](#the-two-commands). A build from `main` reports the version in
`Cargo.toml`, which is the release it is heading towards, not one that has
shipped.

### Unattended updates

The image and both compose files carry
`com.centurylinklabs.watchtower.monitor-only=true`. If you run Watchtower it
will **report** a new Cogwheel image and not apply it.

That is the right default for this particular container, and the reasoning is
narrower than "auto-updates are scary". An upgrade that does not migrate the
schema is genuinely safe to apply unattended: the schema rewrite is a single
`TransactionBehavior::Immediate` transaction in `cogwheel-storage`, so a
`SIGKILL` part-way through rolls it back, and the `VACUUM INTO` snapshot that
runs outside that transaction is deleted and re-taken on the next boot if it was
left half-written. **A kill mid-migration costs a restart, not data.**

What it does not survive is the other half: a new build that fails to *start*
for some reason the migration had nothing to do with. Then the household has no
DNS, at 04:00, with nobody watching. That is the case auto-update cannot fix,
and it is why the label says monitor-only.

### Rolling back

The commands below are for the one-line installer's project in
`/etc/cogwheel`; from a clone, run the same ones in the clone's directory
against its `.env`. On Unraid, put the older tag in the container's
*Repository* field and **Apply**. On a native install, check out the older tag
— or unpack that release's tarball — and re-run `install-native.sh`; across a
schema change, stop the service first and put `cogwheel.db.pre-vN` back in
`/var/lib/cogwheel`, deleting the `-wal` and `-shm` beside it, for the same
reason as below.

**No schema change — the normal case.** Put the tag you want back in
`/etc/cogwheel/.env` and run the two upgrade commands:

```sh
cd /etc/cogwheel
sudo sed -i 's|^COGWHEEL_IMAGE=.*|COGWHEEL_IMAGE=ghcr.io/thekozugroup/cogwheel-dns:0.1.0|' .env
sudo docker compose pull
sudo docker compose up -d
```

The volume is untouched, so everything carries over.

**Across a schema change** — only when `io.cogwheel.schema-version` went up.
Here the tag alone is not enough. The migration happened **in place**: the old
build refuses to open the new database, and `restart: unless-stopped` turns that
refusal into a crash loop. The snapshot has to go back first, and the
write-ahead log has to go with it, or the new database's `-wal` is replayed on
top of the restored old file and you are back where you started.

```sh
cd /etc/cogwheel
sudo docker compose down

sudo docker run --rm -v cogwheel-data:/data \
  --entrypoint /bin/sh ghcr.io/thekozugroup/cogwheel-dns:latest \
  -c 'rm -f /data/cogwheel.db-wal /data/cogwheel.db-shm && cp /data/cogwheel.db.pre-vN /data/cogwheel.db'

sudo sed -i 's|^COGWHEEL_IMAGE=.*|COGWHEEL_IMAGE=ghcr.io/thekozugroup/cogwheel-dns:PREVIOUS|' .env
sudo docker compose up -d
```

Substitute `N` (the schema version that was migrated *to*, which is the suffix
on the file already sitting in the volume) and `PREVIOUS` (the tag you were on).

**Use the Cogwheel image for the restore and not a general-purpose one.** It
runs as uid 10001, so the restored file comes out owned by the user that has to
open it. A `debian:bookworm-slim` running as root leaves a root-owned database
and a container that will not start, with an error about permissions rather
than about what you just did.

What it costs: everything logged since the upgrade — query history, and any
device, rule or list change you made in between. Verify afterwards with the
command for your install under [Then verify](#then-verify).

Always take a backup before an upgrade ([§11](#11-backup-and-restore)) and run
the verification checklist afterwards ([§7](#7-post-install-verification-checklist)).

---

## 11. Backup and restore

### What is actually in there

Four things, and a backup that captures only the first is not a backup:

| | |
|---|---|
| `cogwheel.db` | the database — settings, lists, devices, rules, query log |
| `cogwheel.db-wal`, `cogwheel.db-shm` | the write-ahead log and its index. SQLite runs in WAL mode, so **everything since the last checkpoint lives here and nowhere else** |
| `lists/` | the cached body of every subscribed blocklist, one file per list |
| `cogwheel.db.pre-vN` | a pre-upgrade snapshot, if a schema migration has ever run |

Two consequences follow, and they are why the procedure below stops the
container and archives the whole directory rather than copying one file:

- **Copying `cogwheel.db` out of a running container loses data silently.** The
  WAL is not in it. You get a file that opens cleanly and is missing whatever
  happened since the last checkpoint, with nothing to tell you.
- **Skipping `lists/` means a restored appliance comes up not filtering**, and
  stays that way until its first successful refresh — which on the default
  cadence is up to 24 hours away.

Config is not in here at all. It is environment-only
([§9](#9-configuration-reference)) and lives in `/etc/cogwheel/.env` or
`/etc/cogwheel/cogwheel.env`, which you should keep in whatever you already use
for machine configuration.

### Recommended: back up the data directory

This captures everything: the database, its write-ahead log, and the list
bodies.

**Docker (named volume):**

```sh
# Stop first so SQLite is not mid-write.
docker stop cogwheel
docker run --rm -v cogwheel-data:/data -v "$PWD:/backup" debian:bookworm-slim \
  tar -czf /backup/cogwheel-backup-$(date +%F).tar.gz -C /data .
docker start cogwheel
```

Restore:

```sh
docker stop cogwheel
docker run --rm -v cogwheel-data:/data -v "$PWD:/backup" debian:bookworm-slim \
  sh -c 'rm -rf /data/* && tar -xzf /backup/cogwheel-backup-YYYY-MM-DD.tar.gz -C /data && chown -R 10001:10001 /data'
docker start cogwheel
```

**Native:**

```sh
sudo systemctl stop cogwheel
sudo tar -czf "cogwheel-backup-$(date +%F).tar.gz" -C /var/lib/cogwheel .
sudo systemctl start cogwheel
```

Verify a restore with [§7](#7-post-install-verification-checklist) — a backup
you have never restored is a hypothesis, not a backup.

### Restoring the pre-upgrade snapshot

When a release migrates the database, the upgrade takes its own copy first —
`cogwheel.db.pre-vN`, beside the database in the same volume, where `N` is the
schema version being migrated *to*. It is written with `VACUUM INTO`, so it is a
consistent file rather than a copy of a moving one, and it is taken before
anything is touched.

It guards exactly one upgrade. It is not a substitute for the backups above, and
it is overwritten by the next migration.

To go back to it — this is the second half of
[rolling back across a schema change](#rolling-back), repeated here because this
is where people look. As written it is for the one-line installer's project in
`/etc/cogwheel`; [Rolling back](#rolling-back) says what differs on the other
installs.

```sh
cd /etc/cogwheel
sudo docker compose down

# Remove the -wal and -shm as well as replacing the database. They belong to the
# NEW file; left in place they are replayed on top of the restored old one.
sudo docker run --rm -v cogwheel-data:/data \
  --entrypoint /bin/sh ghcr.io/thekozugroup/cogwheel-dns:latest \
  -c 'rm -f /data/cogwheel.db-wal /data/cogwheel.db-shm && cp /data/cogwheel.db.pre-vN /data/cogwheel.db'

# Put the older tag back, or the new build migrates it again on the next start.
sudo sed -i 's|^COGWHEEL_IMAGE=.*|COGWHEEL_IMAGE=ghcr.io/thekozugroup/cogwheel-dns:PREVIOUS|' .env
sudo docker compose up -d

sudo /etc/cogwheel/verify-install.sh
```

Run it with the **Cogwheel image**, not a general-purpose one: it runs as uid
10001, so the restored file comes out owned by the user that has to open it.

**What it costs:** everything since the upgrade. The query log, and any device,
rule or list change made in between. If that matters more than getting the old
version back, take a copy of the current `cogwheel.db` first.

---

## 12. Uninstall

**Installer / Compose:**

```sh
sudo ./scripts/install.sh --uninstall            # keeps your data volume
sudo ./scripts/install.sh --uninstall --purge    # deletes it too
```

This removes the container, deletes
`/etc/systemd/resolved.conf.d/10-cogwheel-stub-listener.conf`, restores
`/etc/resolv.conf` to what it pointed at before (from
`/etc/cogwheel/resolv.conf.pre-cogwheel`, or, if that backup is missing, by
writing one naming the configured upstream servers), restarts
`systemd-resolved`, and removes `/etc/cogwheel`. Only changes recorded in
`/etc/cogwheel/install-state` are reversed — nothing else on the host is
touched.

If you installed with `--container`/`--volume`, pass the same flags to
`--uninstall`.

For a pure Compose deployment:

```sh
docker compose down                              # keeps the volume
docker compose down -v                           # deletes it
sudo ./scripts/install.sh --uninstall            # revert the resolver changes
```

**Native:**

```sh
sudo ./scripts/install-native.sh --uninstall
sudo ./scripts/install-native.sh --uninstall --purge   # also removes /var/lib/cogwheel
```

Afterwards, confirm the host still resolves and remember to point your router's
DNS back at something else:

```sh
getent hosts example.com
```

---

## 13. Local development

**[CONTRIBUTING.md](../CONTRIBUTING.md) is the full guide** — the pinned toolchain,
the repository layout, what `scripts/verify.sh` runs and why it matches CI. This
section is the two commands an operator wants when reproducing something
locally.

No Docker, no privileged ports, loopback only:

```sh
COGWHEEL_PROFILE=dev cargo run -p cogwheel-server
```

That binds `127.0.0.1:30080` for HTTP and `127.0.0.1:30053` for DNS:

```sh
curl -s http://127.0.0.1:30080/health/live
dig @127.0.0.1 -p 30053 example.com +short
```

The web app with hot reload, which is a **separate server on `:5174`**:

```sh
cd apps/cogwheel-web
npm ci
npm run dev                      # http://localhost:5174
```

Vite proxies `/api` to `http://127.0.0.1:30080`, so the dev UI is same-origin
and there is no CORS to configure. To point it at a real appliance instead:

```sh
VITE_COGWHEEL_API_TARGET=http://cogwheel.local:8080 npm run dev
```

`http://localhost:30080` serves the *built* bundle from the Rust server, which
is what an installed appliance does; `:5174` is the dev server. Both are useful;
they are not the same thing.

Before opening a pull request, run the same gate CI runs. That list lives in
one place — [CONTRIBUTING.md § The checks](../CONTRIBUTING.md#the-checks) — rather
than being restated here, because four copies of it is how they end up
disagreeing with each other and with CI.

[docs/RELEASING.md](RELEASING.md) covers how a release is cut and which
image tag to track.
