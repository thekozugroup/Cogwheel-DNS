# Cogwheel Deployment Guide

The single source of truth for installing, operating, upgrading and removing
Cogwheel. If a command here does not work, that is a bug — please report it.

Cogwheel is a DNS filtering appliance. It binds port 53, answers queries for
every device on your network, and serves a web control plane on port 8080. The
reference target is a **Raspberry Pi 5 running 64-bit Raspberry Pi OS**, but any
64-bit Linux host (`x86_64` or `aarch64`) works.

---

## Contents

1. [Choosing an install method](#1-choosing-an-install-method)
2. [Quick start — the one-line installer](#2-quick-start--the-one-line-installer)
3. [Docker Compose](#3-docker-compose)
4. [Native install with systemd](#4-native-install-with-systemd)
5. [Networking: host vs bridge, and why it decides a feature](#5-networking-host-vs-bridge-and-why-it-decides-a-feature)
6. [Pointing your router at Cogwheel](#6-pointing-your-router-at-cogwheel)
7. [Post-install verification checklist](#7-post-install-verification-checklist)
8. [Troubleshooting](#8-troubleshooting)
9. [Configuration reference](#9-configuration-reference)
10. [Upgrades](#10-upgrades)
11. [Backup and restore](#11-backup-and-restore)
12. [Uninstall](#12-uninstall)
13. [Local development](#13-local-development)

---

## 1. Choosing an install method

| | One-line installer | Docker Compose | Native systemd |
|---|---|---|---|
| Best for | Most people | You already run a Compose stack | You do not want Docker |
| Needs Docker | yes | yes | no |
| Config lives in | `/etc/cogwheel/cogwheel.env` (generated) | `.env` (yours to edit) | `/etc/cogwheel/cogwheel.env` (yours to edit) |
| Handles the port-53 conflict | automatically | you run one command | automatically |
| Upgrade | re-run the installer | `docker compose pull && up -d` | rebuild and re-run |

All three end up in the same place: a non-root process with
`CAP_NET_BIND_SERVICE`, a persistent data directory, and bounded logs.

**Requirements**

- 64-bit Linux, `x86_64` or `aarch64`. 32-bit ARM is not a published target —
  on a Raspberry Pi, install the 64-bit OS.
- Docker 24+ (for the first two methods).
- Root, because binding port 53 and editing resolver configuration both need it.
- ~200 MB of disk for the image, plus room for the database.

---

## 2. Quick start — the one-line installer

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

docker compose up -d
docker compose ps          # wait for STATUS = healthy
```

`.env.example` documents every variable. The defaults are sized for a
Raspberry Pi 5: two CPUs, 1 GiB memory, three rotated 10 MB log files.

To build locally instead of pulling a published image:

```sh
docker compose build
docker compose up -d
```

`docker-compose.yml` defaults to **host networking**. Read
[§5](#5-networking-host-vs-bridge-and-why-it-decides-a-feature) before changing
it — the choice determines whether per-device block profiles work.

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
[`deploy/cogwheel.service`](deploy/cogwheel.service).

To skip the build and use a published release artifact instead — this is the
whole thing, copy-pasteable, and it works out the current version for you:

```sh
VERSION=$(curl -fsSL https://api.github.com/repos/thekozugroup/Cogwheel-DNS/releases/latest |
          sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
TARBALL="cogwheel-${VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz"
curl -fsSLO "https://github.com/thekozugroup/Cogwheel-DNS/releases/download/v${VERSION}/${TARBALL}"
sudo ./scripts/install-native.sh --tarball "${TARBALL}"
```

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
per-device profiles and per-device statistics work at all.

### Host networking (the default)

```yaml
network_mode: host
```

- DNS sockets are bound directly on the host's interfaces. Every query arrives
  with the real LAN client address, so per-device profiles work.
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
  profiles silently collapse to the global policy** — no error, just wrong
  behaviour.
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
   dashboard shows them, and the API returns them:

   ```sh
   curl -s http://<cogwheel-host>:8080/api/v1/resolver-access
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

Run the scripted version:

```sh
sh scripts/verify-install.sh                       # local
sh scripts/verify-install.sh --host 10.0.0.2       # remote
sh scripts/verify-install.sh --skip-restart        # no restart test
```

It exits non-zero if anything fails, so it also works from cron or a monitor.

Or check each item by hand:

### Control plane

```sh
curl -fsS http://<host>:8080/health/live      # {"data":{"status":"ok"}}
curl -fsS http://<host>:8080/health/ready     # {"data":{"status":"ready"}}
curl -fsS http://<host>:8080/api/v1/dashboard | head -c 200
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

The operationally interesting counters live in `GET /api/v1/runtime`.

### Resolver

```sh
# An allowed domain must resolve normally.
dig @<host> example.com A +short
#   -> a real address, e.g. 93.184.216.34

# A blocked domain must resolve to the null address, not NXDOMAIN.
dig @<host> ads.example.com A +short
#   -> 0.0.0.0

# TCP as well as UDP. Large answers fall back to TCP; if only UDP works,
# some lookups will fail in ways that are very hard to diagnose later.
dig @<host> example.com A +tcp +short
```

`ads.example.com` is on the bootstrap blocklist that ships with a stock
install, so this works before you configure anything. Blocked domains return
`0.0.0.0` (and `::` for AAAA) because the default block mode is null-IP.

### Persistence

State must survive a restart. If it does not, the data volume is not mounted
where you think it is.

```sh
curl -s http://<host>:8080/api/v1/settings | head -c 200   # note the contents
docker restart cogwheel                                    # or: systemctl restart cogwheel
sleep 20
curl -s http://<host>:8080/api/v1/settings | head -c 200   # must be unchanged
```

`scripts/verify-install.sh` automates this properly: it writes a uniquely named
block profile, restarts Cogwheel, confirms the record survived, and deletes it
again.

### End to end

From a *different* device on the network, after pointing it at Cogwheel:

```sh
nslookup example.com
nslookup ads.example.com      # 0.0.0.0
```

Then open `http://<host>:8080` and confirm the dashboard shows the query.

---

## 8. Troubleshooting

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
sudo ./scripts/install.sh --fix-port-53
```

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

Per-device profiles are not applying and the dashboard attributes everything to
a single address, usually `172.x.0.1`. That is the Docker bridge gateway — see
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

---

## 9. Configuration reference

Every variable is read by the server itself. Names are exact — a typo is
silently ignored rather than reported.

| Variable | Default (`home` profile) | Notes |
|---|---|---|
| `COGWHEEL_PROFILE` | `home` | `dev`, `home` or `smb`. Sets the defaults below. |
| `COGWHEEL_SERVER__HTTP_BIND_ADDR` | `0.0.0.0:8080` | Web UI and API. |
| `COGWHEEL_SERVER__DNS_UDP_BIND_ADDR` | `0.0.0.0:5353` | The image overrides this to `:53`. |
| `COGWHEEL_SERVER__DNS_TCP_BIND_ADDR` | `0.0.0.0:5353` | Keep in step with UDP. |
| `COGWHEEL_SERVER__ADVERTISED_DNS_PORT` | bound DNS port | The port *clients* use. Stays `53` behind a port mapping. |
| `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` | *(empty)* | Comma-separated addresses shown to users. The installers fill this in from the host's interfaces. |
| `COGWHEEL_STORAGE__DATABASE_URL` | `sqlite://data/cogwheel.db` | `sqlite://` is stripped. Use an absolute path. |
| `COGWHEEL_UPSTREAM__SERVERS` | `1.1.1.1:53,1.0.0.1:53` | Comma-separated. `ip:port` is cleartext (UDP+TCP); `tls://ip#certname` is DNS-over-TLS and `https://ip#certname` is DNS-over-HTTPS. See [§9.1](#91-encrypting-queries-to-the-upstream-resolver). |
| `COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS` | `300` | Clamped to a 30 s floor. |
| `COGWHEEL_BLOCKING__MODE` | `null_ip` | `null_ip`, `nxdomain`, `nodata` or `refused`. See [§9.2](#92-how-blocked-names-are-answered). |
| `COGWHEEL_RETENTION__HISTORY_DAYS` | `30` | Days of recorded history to keep. `0` keeps everything forever and logs a warning. |
| `COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS` | `3600` | How often the prune runs. Floored at 60 s. |
| `COGWHEEL_WEB_DIST_DIR` | *(search path)* | Directory containing `index.html`. |
| `RUST_LOG` | `info` | tracing filter. An `info` directive is always added, so this can only widen it. |

Profile defaults:

| Setting | `dev` | `home` | `smb` |
|---|---|---|---|
| HTTP bind | `127.0.0.1:30080` | `0.0.0.0:8080` | `0.0.0.0:8080` |
| DNS bind | `127.0.0.1:30053` | `0.0.0.0:5353` | `0.0.0.0:53` |
| Refresh interval | 120 s | 300 s | 600 s |

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

**Cogwheel caches answers.** Two caches, both bounded at 10,000 entries:

| Cache | Holds | Lifetime |
|---|---|---|
| Response cache | the answer for a name, per policy scope | the record's own TTL, clamped to 5 s – 1 h |
| Fallback cache | last known-good answer per name | up to 24 h, served **only** when upstream fails |

The response cache honours the TTL the authoritative server published, taking
the shortest TTL in the answer. That matters more than it sounds: a cache that
ignores TTLs keeps handing out an address after the site has moved, and
CDN failover, geo-routing and blue/green deploys all rely on short TTLs being
respected. Answers with no records at all (`NXDOMAIN`, `NODATA`) are held for
only 60 s, so a host that has just been provisioned does not stay unreachable.

The fallback cache deliberately serves *stale* answers, but only after the
upstream has already failed — an hour-old address beats no DNS at all.

A policy change (new blocklist, device profile edit) invalidates the response
cache immediately, so an unblock takes effect on the next query rather than
whenever the entry happens to age out.

#### When a site breaks

DNS filtering breaks sites in two distinct ways, and the fix differs:

**1. Something it needs is on a blocklist.** The usual cause. Blocklists are
maintained by other people and occasionally include a domain a site genuinely
depends on — a login provider, a payment iframe, a CDN.

- Fastest check: `POST /api/v1/runtime/pause` pauses filtering entirely. If the
  site starts working, it is a blocking problem; if not, look elsewhere before
  spending time on blocklists.
- Then narrow it: the Activity view shows what was blocked while the page
  loaded. Add the offending name to a device's allowed domains, or remove the
  list that supplied it (`/api/v1/settings/blocklists`).

**2. It is not blocking at all.** Worth ruling out early, because it looks
identical from the browser: a stale cached address, an upstream that is failing,
or a device that has cached the old answer itself. `/api/v1/runtime` reports
cache hits, expiries, upstream failures and fallback responses. Browsers and
phones keep their own DNS caches, so test with `dig` before concluding anything.

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

## 10. Upgrades

**Installer:** re-run it. It is idempotent, keeps the data volume, and rolls
back to the previous image if the new one fails to become healthy. Finding
Cogwheel already bound to port 53 is expected on a re-run — the running
container is replaced, not treated as a conflict.

```sh
sudo ./scripts/install.sh
```

Run the *matching* installer: `install.sh` refuses to drop a container on top
of a native systemd install and points you at `install-native.sh` instead.

**Compose:** pin a version in `.env` rather than tracking `latest`, so an
upgrade is a reviewed change.

```sh
$EDITOR .env                    # COGWHEEL_IMAGE=ghcr.io/thekozugroup/cogwheel-dns:1.2.3
docker compose pull
docker compose up -d
docker compose ps               # wait for healthy
sh scripts/verify-install.sh
```

To roll back, put the old tag in `.env` and repeat. The volume is untouched, so
state carries over.

**Native:**

```sh
git pull
sudo ./scripts/install-native.sh
```

`/etc/cogwheel/cogwheel.env` is preserved unless you pass `--force-env`.

Always take a backup before an upgrade ([§11](#11-backup-and-restore)) and run
the verification checklist afterwards ([§7](#7-post-install-verification-checklist)).

---

## 11. Backup and restore

### Recommended: back up the data directory

This captures everything — the full SQLite database, not a subset.

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

No Docker, no privileged ports, loopback only:

```sh
COGWHEEL_PROFILE=dev cargo run -p cogwheel-server
```

That binds `127.0.0.1:30080` for HTTP and `127.0.0.1:30053` for DNS. Test it:

```sh
curl -s http://127.0.0.1:30080/health/live
dig @127.0.0.1 -p 30053 example.com +short
```

Run the web app against it with hot reload:

```sh
cd apps/cogwheel-web
npm ci
npm run dev
```

Before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo audit
cargo deny check

npm --prefix apps/cogwheel-web ci
npm --prefix apps/cogwheel-web run lint
npm --prefix apps/cogwheel-web run build

shellcheck scripts/*.sh
docker buildx build --check .
```

CI runs all of these. See [docs/release-policy.md](docs/release-policy.md) for
how releases are cut.
