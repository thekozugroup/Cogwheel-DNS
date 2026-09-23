# Quick start

From nothing to a household that is filtering, in about five minutes of your
attention. You do not need to know what a DNS server is, and nothing here asks
you to learn.

Cogwheel is one container and one database file. It answers every name the
devices on your network look up, returns nothing for the ones your blocklists
name, and serves a small web page where you can see what happened and change
your mind.

**Pick the host you are installing on:**

| | |
|---|---|
| [Linux with Docker](#linux-with-docker) | the usual case, and the shortest |
| [Raspberry Pi](#raspberry-pi) | the reference target — a few Pi-specific steps |
| [Unraid](#unraid) | a template, pasted into the Docker tab |
| [Docker Compose from a clone](#docker-compose-from-a-clone) | you already run a Compose stack |
| [Without Docker](#without-docker) | native binary under systemd |

Then, whichever you picked: **[three things to do next](#you-are-filtering--now-do-these-three-things)**
and **[the two things that go wrong first](#the-two-things-that-go-wrong-first)**.

> ### Before the first release
>
> Nothing has been tagged yet, and no image has ever been pushed to
> `ghcr.io/thekozugroup/cogwheel-dns`. Every path below that pulls a published
> image — the one-line installer, `docker compose pull`, the Unraid template,
> the release tarball — will fail until `v0.1.0` exists.
>
> Until then, [build the image yourself](#build-it-yourself-until-v010-is-tagged)
> — a clone and one long build — or install
> [without Docker](#without-docker), which also builds from source.
>
> *Delete this block in the commit that tags `v0.1.0` — it is one of five,
> listed in [RELEASING.md](RELEASING.md#before-the-first-tag-v010-only).*

---

## What you need first

Three things, and the second is the one people skip.

1. **A 64-bit Linux host** — `x86_64` or `aarch64`. On a Raspberry Pi that means
   the 64-bit OS; there is no 32-bit build. Docker 24 or newer for every path
   except [without Docker](#without-docker).

2. **A fixed address for that host.** Every device on the network is about to
   be told *"your DNS server lives at this address"*, and if the address moves
   later, name resolution stops for the whole house until you notice.

   The reliable way is a reservation made on the router, so the host cannot
   disagree with it: router admin page → *DHCP* or *LAN* → *Address
   reservation*, *Static lease* or *DHCP binding*, depending on the make. Bind
   the host's MAC address — `ip link` prints it — to an address outside the
   DHCP pool. Setting a static address on the host itself also works, as long
   as it is one the router will not hand to something else later.

   Doing this first takes two minutes; doing it afterwards means redoing the
   router step.

3. **Root on that host**, because binding port 53 and repairing the host's own
   resolver configuration both need it.

About 200 MB of disk for the image, plus room for the database — a household's
seven days of query log is tens of megabytes, not gigabytes.

---

## Linux with Docker

```sh
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh | sudo sh
```

That is the whole install. It takes under a minute once the image has pulled.

Piping a script off the internet into root is a reasonable thing to be uneasy
about, and you do not have to. Download it first and read it — `--print-compose`
needs no root, reads nothing, writes nothing, and prints the exact deployment
the real run would write:

```sh
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/install.sh -o install.sh
less install.sh
sh install.sh --print-compose      # no root, no changes
sudo sh install.sh                 # the same script, now that you have read it
```

Either way it is the same script and the same install. What it does, in order:

1. Checks the OS, the CPU architecture and that Docker is running.
2. Finds whatever already owns port 53 and deals with it. On the common case —
   `systemd-resolved`'s stub listener — it disables the stub *and* repairs
   `/etc/resolv.conf`, so the host itself can still resolve names. If a real DNS
   server holds the port (`dnsmasq`, BIND, `unbound`), it stops and tells you,
   because silently disabling someone's DNS server is not a decision an
   installer gets to make.
3. Writes a Compose project to `/etc/cogwheel` and starts it.
4. Waits for the container to report healthy, then **proves the resolver answers
   a real query** before it claims success.
5. Rolls everything back if any of that fails — including the resolver changes,
   so the host is left as it was found. Your data volume is never deleted
   automatically.

It finishes by printing the two lines that matter:

```
  Cogwheel is running.

  Web UI        http://192.168.1.10:8080
  DNS server    192.168.1.10 port 53
```

Write that address down. It is the one you are about to put in your router.

Useful flags — `--help` lists them all. These are the downloaded copy from
above; after an install the same script is at `/etc/cogwheel/install.sh`, which
is the one to use on a host that never had a checkout:

```sh
sudo sh install.sh --dns-port 5353     # do not take :53 at all
sudo sh install.sh --network bridge    # read DEPLOYMENT §5 first
sudo sh install.sh --upstream 9.9.9.9:53,149.112.112.112:53

sudo /etc/cogwheel/install.sh --uninstall      # reverses exactly what it changed
```

**You do not need the installer again.** It bootstraps a Compose project and
then gets out of the way; upgrading is
[two Compose commands](DEPLOYMENT.md#10-upgrades-and-rollback) from `/etc/cogwheel`,
the same two on every Cogwheel host however it was installed.

→ [Three things to do next](#you-are-filtering--now-do-these-three-things)

---

## Raspberry Pi

A Pi 5 is the reference target — every performance figure in this repository was
taken with one in mind. The install is the [Linux one](#linux-with-docker); four
things are worth knowing that are specific to a Pi.

1. **64-bit OS.** Raspberry Pi OS still ships a 32-bit image, and there is no
   32-bit Cogwheel build. Check with `uname -m`: `aarch64` is right, `armv7l`
   means you are on the wrong image and no amount of troubleshooting will fix
   it.

2. **Reserve its address on the router before you start.** A Pi that gets a new
   lease after a power cut takes the household's DNS with it.

3. **Port 53 is almost certainly taken** by `systemd-resolved`, on a stock
   Raspberry Pi OS. The one-line installer handles it for you. If you are
   installing with [Compose from a clone](#docker-compose-from-a-clone)
   instead, that section runs `sudo sh scripts/install.sh --fix-port-53` as its
   own first step — Compose cannot free the port on its own.

4. **The SD card is the part that wears out.** The query log is the only thing
   Cogwheel writes continuously, and it is bounded by two settings that already
   default to a household-sized figure: `COGWHEEL_RETENTION__HISTORY_DAYS=7` and
   `COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS=250000`. If you would rather the card
   outlive the Pi, set `COGWHEEL_RETENTION__HISTORY_DAYS=0` — that stops the
   per-query rows entirely while keeping the hourly rollups the Overview and
   Devices pages are built from, so you lose the Activity list and nothing else.
   Or move the volume to a USB SSD.

When it is running, `pi-acceptance.sh` is the finish line. Run it **on the Pi**:
it checks the things that are about this hardware rather than about DNS — the
userland's word size, that the service answers, that resolution and filtering
both work, the web control plane, and that state survives a container restart.

The one-line installer leaves no checkout behind — and unlike
`verify-install.sh`, this script is not copied to `/etc/cogwheel`, because it is
about one hardware target rather than about your deployment. Fetch it the same
way you fetched the installer:

```sh
# On a host installed with the one-liner, or an Unraid box: no checkout.
curl -fsSL https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/scripts/pi-acceptance.sh -o pi-acceptance.sh
sudo sh pi-acceptance.sh

# From a checkout, instead of the two lines above.
sudo sh scripts/pi-acceptance.sh
```

It restarts the container as one of its checks and waits up to 60 seconds for
it to come back ready, so give it that long before deciding it has hung.

→ [Three things to do next](#you-are-filtering--now-do-these-three-things)

---

## Unraid

1. **Docker** tab → **ADD CONTAINER**.
2. Paste this into the **Template** field:
   `https://raw.githubusercontent.com/thekozugroup/Cogwheel-DNS/main/deploy/unraid/cogwheel.xml`
3. Everything fills in — ports, data location, the capability the image needs.
   Leave **Network** on `host`.
4. **Apply.**
5. Open the WebUI link Unraid puts on the container.

Two notes, both already in the template's own comments:

- **Network must not be plain `bridge`.** Cogwheel tells devices apart by the
  source IP of their queries, and Unraid's bridge network rewrites that address
  to the Docker gateway — at which point every device in the house looks like
  one client and per-device profiles silently collapse. `host` is correct. If
  you want isolation, use a custom `br0` network with its own LAN address, which
  also preserves client IPs.
- **The template tracks `:latest` deliberately**, so the Docker tab's *check for
  updates* has a moving digest to compare against. Pin a version in the
  Repository field if you would rather review every upgrade —
  [that is a real choice](RELEASING.md#which-tag-should-i-track), just make it
  knowingly.

Updating afterwards is the Docker tab's own **check for updates** →
**Apply Update**.

**Checking it worked, on Unraid.** There is no `/etc/cogwheel` here and no
checkout, so the two forms the next section gives are both unavailable to you.
The image carries the same script; run it from Unraid's terminal:

```sh
docker exec cogwheel sh /app/verify-install.sh
```

From inside the container it checks liveness, readiness, the API, the web
assets and the advertised resolver address, and reports the restart and upgrade
checks as SKIP rather than inventing a result — those need the Docker socket it
deliberately cannot see. The end-to-end check is the human one anyway: open the
WebUI link, look something up on another device, and watch a row appear on
Activity.

→ [Three things to do next](#you-are-filtering--now-do-these-three-things)

---

## Docker Compose from a clone

```sh
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS
cp .env.example .env

# Free port 53 first. Compose cannot do this for you, and on a stock
# systemd-resolved host the container will otherwise restart in a loop.
sudo sh scripts/install.sh --fix-port-53

docker compose pull        # fails until v0.1.0 is tagged — build it yourself, below
docker compose up -d
docker compose ps          # wait for STATUS = healthy
```

`.env.example` documents every variable and explains its own defaults; it is
worth reading once. The defaults are sized for a Raspberry Pi 5 — two CPUs,
1 GiB of memory, three rotated 10 MB log files.

`docker-compose.yml` uses **host networking**. Read
[DEPLOYMENT §5](DEPLOYMENT.md#5-networking-host-vs-bridge-and-why-it-decides-a-feature)
before changing that: it is the choice that decides whether per-device rules
work at all.

### Build it yourself (until v0.1.0 is tagged)

There is no `build:` block in `docker-compose.yml`, on purpose — Compose would
then silently build a missing image, and on a Pi that turns `docker compose up`
into a surprise half-hour. Build explicitly and point the compose file at what
you built:

This block stands on its own — it does not assume you ran the clone above:

```sh
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS
cp .env.example .env

# Free port 53 first. Compose cannot do this for you, and on a stock
# systemd-resolved host the container will otherwise restart in a loop.
sudo sh scripts/install.sh --fix-port-53

docker build -t cogwheel-dns:dev .
COGWHEEL_IMAGE=cogwheel-dns:dev docker compose up -d
docker compose ps          # wait for STATUS = healthy
```

→ [Three things to do next](#you-are-filtering--now-do-these-three-things)

---

## Without Docker

For hosts where you do not want Docker at all. The service runs as a dedicated
non-root user under systemd, with `ProtectSystem=strict`, a capability bounding
set of exactly `CAP_NET_BIND_SERVICE`, and one writable path.

```sh
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS
sudo ./scripts/install-native.sh
```

This compiles the server and the web app from source. A cold release build of
the server took **3 minutes 21 seconds** on the four-core x86_64 machine this
was written on, and the web app another 11 seconds; **on a Raspberry Pi expect
20–40 minutes**, because a first Rust build is CPU-bound and a Pi has less of
it. Start it and go and do the router step while it runs.

Once a release exists, `install-native.sh --tarball` skips the build entirely —
see [DEPLOYMENT §4](DEPLOYMENT.md#4-native-install-with-systemd).

→ [Three things to do next](#you-are-filtering--now-do-these-three-things)

---

## You are filtering — now do these three things

Cogwheel is running, but at this moment exactly one device is using it: none.
Nothing on your network sends it a query until you say so.

> **Before you open the web UI: it has no authentication.** Anyone who can
> reach the address can change your filtering, and the box necessarily sees
> every name your household looks up. Both are deliberate — it is an appliance
> for one trusted network — and both have consequences. Keep it on your home
> LAN, and read [SECURITY.md](../SECURITY.md) before doing anything else with
> it.

### 1. Point the router at it

This is the step that turns an installed appliance into a filtered household,
and it is the only one that is not optional.

Set DNS **on the router**, in its DHCP settings — not on each device. That way
every client is covered, including the ones you cannot configure: a TV, a games
console, a guest's phone.

1. Open your router's admin page → *DHCP* or *LAN* → *DNS servers*.
2. Enter the address the installer printed. The Overview page shows the same
   address, under **Connect your devices**, so you do not need to have kept
   the installer's output. (Headless, with no browser to hand:
   `curl -s http://<cogwheel-host>:8080/api/v1/overview | grep -o '"connect":{[^}]*}'`.)

3. **Remove any other entry.** A second resolver in that field is not a backup;
   it is a coin flip, and half your queries bypass filtering.
4. **On a dual-stack network, set the IPv6 address too.** A device with an IPv6
   resolver configured will cheerfully ignore an IPv4-only setting. This is the
   single most common reason people say filtering "randomly stops working".
5. Renew leases — reboot the router, or just wait. Devices pick it up as their
   leases roll over.

If your router will not let you change DNS, set it per device instead, or hand
out Cogwheel's address as the gateway's forwarder.

### 2. Check the blocklist arrived

This step is usually already done. A fresh install subscribes you to **oisd
small** and downloads it on first boot, so open the web UI → **Lists** and look
for its rule count: the run behind this document reported **56,911 rules** from
that one list. If the count is missing, the box had no route to the internet
when it started; it retries on its own.

oisd small is the right first subscription — it blocks the large majority of
advertising and tracking and breaks very little. **oisd big** blocks more and
breaks more, and the picker has eleven presets besides, plus any list URL you
paste. You can always move up later, and a rule you write outranks every list,
so moving up is reversible one row at a time.

### 3. Name the devices you care about

Open **Devices** and give a few addresses names. The only thing this changes at
first is that Activity says *"Kitchen tablet"* instead of `192.168.1.20` — but
a named device is also the unit that per-device settings attach to, so it is
the prerequisite for putting one tablet on a stricter profile than the rest of
the house.

Leave everything else at its default. The defaults are chosen for a household,
and `.env.example` explains each one if you disagree with any of them.

### Then check it is actually working

```sh
sudo /etc/cogwheel/verify-install.sh          # installed with the one-liner
sh scripts/verify-install.sh                  # from a checkout
docker exec cogwheel sh /app/verify-install.sh  # container only, e.g. Unraid
```

Whichever you have, it checks liveness, readiness, the API, the web UI, the
advertised resolver addresses, an allowed lookup, a blocked lookup, DNS over
TCP, and that state survives a restart. It exits non-zero on failure, so it is
safe to run from cron. Anything it cannot reach is reported as SKIP, never as a
pass — from inside the container that is the restart and upgrade checks.

The honest end-to-end test is from a *different* device, after the router has
handed out the new setting: open any site heavy with advertising and see the
Activity page fill up.

---

## The two things that go wrong first

Between them these account for most of the installs that do not work.

### Port 53 is already in use

**Looks like:** the container restarts in a loop; `docker compose logs` shows an
address-in-use error; nothing resolves.

**Why:** on most Linux hosts `systemd-resolved` runs a stub resolver on
`127.0.0.53:53` and will not share the port.

**Find out who has it, then fix it:**

```sh
sudo ss -lnptu '( sport = :53 )'
sudo /etc/cogwheel/install.sh --fix-port-53     # after an install
sudo sh scripts/install.sh --fix-port-53        # from a checkout
```

That disables the stub listener *and* repairs `/etc/resolv.conf`, which would
otherwise leave the host itself with no working resolver — and a host with no
DNS cannot pull the image that would fix it. Both changes are recorded so
`--uninstall` can reverse exactly those and nothing else.

If the port is held by a real DNS server rather than the stub, the installer
stops and says so rather than disabling it. `dnsmasq` in particular is often
serving DHCP as well, and turning it off without warning would take the network
down. Stop it yourself when you are ready, or run Cogwheel on another port with
`--dns-port 5353`.

Full detail: [DEPLOYMENT §8.1](DEPLOYMENT.md#81-port-53-is-already-in-use).

### Every device shows up as one client

**Looks like:** the Activity and Devices pages attribute every query in the
house to a single address, usually something like `172.17.0.1`. Per-device
rules appear to do nothing.

**Why:** that is the Docker bridge gateway. Cogwheel identifies a device by the
source IP of its query, and bridge networking frequently rewrites that address.
Nothing errors — the behaviour is simply wrong.

**Fix:** use host networking (the default in every path above), or give the
container its own LAN address with a macvlan or `br0` network, which preserves
client IPs while keeping container isolation.

**Do not take this on trust — measure it.** Query the resolver from a second
machine, open the Activity page, and look at the client column for that query.
If it shows the gateway rather than the machine you queried from, you have this
problem.

Full detail:
[DEPLOYMENT §5](DEPLOYMENT.md#5-networking-host-vs-bridge-and-why-it-decides-a-feature).

---

## Where to go next

| | |
|---|---|
| [Using Cogwheel](USING.md) | for everyone in the house — the five screens, and what to do when a site breaks |
| [Security](../SECURITY.md) | no authentication, what the box can see, and what to do before exposing it |
| [Deployment](DEPLOYMENT.md) | the operator's manual: networking, upgrades, rollback, backup, hardening, troubleshooting by symptom |
| [`.env.example`](../.env.example) | every setting, annotated, with the reasoning for each default |
| [Architecture](ARCHITECTURE.md) | how a query becomes an answer, and what Cogwheel deliberately is not |
| [Releasing](RELEASING.md) | which image tag to track, and how a release is cut |
