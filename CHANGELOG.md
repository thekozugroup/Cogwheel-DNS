# Changelog

Notable changes to Cogwheel. This file is written for someone deciding whether to install or
upgrade, so it says what changed and what it means rather than listing commit subjects. Every
entry states whether it changes the database schema, because that is the fact that decides
whether an upgrade needs a snapshot taken first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Cogwheel uses
[semantic versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may change
behaviour — the entry will say so. Later entries group changes as Added / Changed / Fixed /
Removed; this first one does not, because there is nothing to have changed from.

## [Unreleased]

Nothing has been released yet. Everything below is the first release, written now rather than
assembled from commit subjects on the day — the release workflow reads the section matching the
tag verbatim as the release body, so it is worth writing while the reasoning is fresh.
[docs/RELEASING.md](docs/RELEASING.md) has the steps that turn this heading into a tagged
release.

**Database schema: v2.** A fresh install creates it. A database written by an earlier build of
this release (v1) is upgraded in place on first start, after a `cogwheel.db.pre-v2` snapshot; one
from the pre-release v0 layout is upgraded straight to v2 with a single `cogwheel.db.pre-v1`
snapshot. An image built before v2 refuses an upgraded file.

Because everything here is new, this entry describes what Cogwheel _is_ rather than what moved.

### Resolving and caching

- **A caching DNS resolver on port 53**, UDP and TCP, for every device on the network. Record
  TTLs are honoured rather than replaced with a flat number of the appliance's choosing, so a
  name that its owner wants re-resolved every 60 seconds is re-resolved every 60 seconds.
- **One cache, holding wire answers**, keyed by the query's scope and type — so a device with its
  own policy can never be served the answer computed for a different one. Hickory's own cache is
  switched off underneath it, because a second cache would hand back answers the TTL clamp never
  saw.
- **Encrypted upstream is one variable.** Plain UDP to `1.1.1.1` and `1.0.0.1` by default;
  `tls://1.1.1.1#cloudflare-dns.com` (DoT) or `https://1.1.1.1#cloudflare-dns.com/dns-query` (DoH)
  instead. The trust anchors are compiled into the binary, so an appliance with no system
  certificate store still validates the upstream's certificate against the name you gave.
- **It filters before it has internet.** List bodies are cached to disk beside the database, so a
  box that boots before its WAN link comes up serves the last good copy of every list and reports
  ready immediately, instead of waiting to become useful.
- Measured on a 4-vCPU x86_64 sandbox — **not** a Raspberry Pi, and no Pi 5 measurement exists
  yet: a cache hit costs about 2.3 µs of server time, four workers sustain around 64,000 queries
  per second, and the binary is 12 MB stripped. Resident memory is about 17 MB once an appliance
  has settled after booting from its cached lists, and about 30 MB at the peak of adding a
  56,000-entry list to a policy that is already live — the second number is the one an appliance
  has to survive, which is why it is the one quoted.

### Filtering, and a protected set a list cannot take down

- **Subscribe to the usual public blocklists** in `hosts`, `domains` or Adblock syntax. Eleven
  presets ship in the picker — oisd, HaGeZi and StevenBlack — and any other list URL works just as
  well. Lists are re-fetched daily, and a candidate that fails verification is refused: the policy
  already in force keeps serving rather than being replaced by a truncated download.
- **Twenty-one protected suffixes that no subscribed list may block**: resolver bootstrap and
  captive-portal checks, NTP, and the certificate-status endpoints of the major CAs. Blocking any
  of those does not look like "the ad blocker broke this site", it looks like the device is
  broken — a drifted clock fails TLS everywhere and points nowhere near DNS. Protection is applied
  when a query is evaluated rather than when a list is parsed, so a list containing one is
  accepted and harmless, and the names it hit are recorded against it.
- **A rule you wrote outranks everything**, including the protected set, because a rule is a
  choice somebody made on purpose and a list entry covering `pool.ntp.org` is almost always an
  accident upstream. The full order is device rule, household rule, protected set, AI list, list
  exception, list block — and inside any one of those, an allow beats a block.
- **CNAME-cloaked trackers are caught.** The names in an upstream answer's CNAME chain are
  re-checked against the lists, so a tracker reached through a first-party alias is blocked and the
  log says it was redirected to a domain on that list.
- A blocked name is answered four ways, your choice: `null_ip` (the default), `nxdomain`, `nodata`
  or `refused`.
- **An optional AI list**, off by default. Bring your own OpenRouter key, pick a decision model
  (Jev, Clef and the like answer with a choice and a confidence, not with text), pass a Test and
  turn it on, and Cogwheel asks the model about the names each website loads — after the page has
  loaded, never on the DNS path — and keeps the answers that disagree with your lists: blocks the
  lists missed, and allows that lift a list's block that broke a site, past a higher bar, a second
  question and a cap of 20 a day. Exact names only. It sits below your rules and the protected set
  and above every subscribed list, applies to every filtered device, and is reported as `Reason`
  code 9, `ai` on the wire, so Activity and "Why?" say *AI list* when it decided. Every verdict is
  a row you can read with the model's confidence, and forget; a daily spending limit of 5¢ to $1
  caps what it costs, and turning it off stops it at once. Without
  `COGWHEEL_RETENTION__HISTORY_DAYS` of at least one, it is unavailable.
  [ADR 0002](docs/adr/0002-ai-review-tier.md) records the decision.

### Per-device policy

- **Give an address a name**, and it gets its own filtering switch, its own selection of lists and
  its own allow and block rules. The kids' tablet and the work laptop do not have to share a
  policy, and a device can be set to bypass filtering entirely.
- Clients that have not been named are still counted and still shown, so naming a device is
  something you do after seeing it on the network rather than before.

### The query log

- **Every lookup, with the device that asked and the reason it was blocked** — live on the
  Activity page over a server-sent event stream, filterable by domain, device and verdict.
- The row menu turns a broken site into a fix: allow the name for everyone, or for just that one
  device, without leaving the page.
- **Kept 7 days, capped at 250,000 rows**, whichever comes first.
  `COGWHEEL_RETENTION__HISTORY_DAYS=0` switches the raw log off entirely and keeps only the hourly
  per-device counts, which are numbers rather than browsing history.

### The control plane

- Five pages — Overview, Activity, Devices, Lists, Settings — served by the same binary on port
  8080, so there is no second process, no reverse proxy to configure and no CORS policy to get
  wrong.
- Light and dark, chosen before the first paint so the theme never flashes. **Inter is
  self-hosted**, and nothing in the UI fetches from a CDN, because the appliance may sit on a LAN
  with no route to the internet.
- Colour is never the only signal — a verdict is a word as well as a dot, and red, yellow and
  green are reserved for status rather than used for decoration.
- AI review is set up on Lists, in an AI list card between the subscribed lists and the rules,
  through seven routes under `/api/v1/ai` — its status, the set-up, the live model list, a Test,
  and the AI list with Forget and Clear. The ones that change anything, spend or make the appliance
  fetch refuse requests from anywhere but the appliance's own address or a local name
  (`COGWHEEL_SERVER__ALLOWED_HOSTS` admits a reverse proxy). Settings stays read-only and gains a
  read-only AI review card.

### Installing, operating and updating

- **One command.** The installer preflights Docker and the architecture, finds whatever already
  owns port 53 and deals with it — for the common case, systemd-resolved's stub listener, it
  disables the stub _and_ repairs `/etc/resolv.conf` so the host can still resolve — then writes a
  Compose project to `/etc/cogwheel`, waits for the container to report healthy, and proves the
  resolver answers a real query before telling you it worked. If any of that fails it rolls the
  host back. `--print-compose` prints what it would write without touching anything, which is
  worth reading before piping a script into root.
- **Updating is Docker's job, not the installer's.** A host the installer set up upgrades like
  any other Compose install: `docker compose pull && docker compose up -d`. Unraid uses its Docker
  tab, and a native install is rebuilt. The installer is not in the update path at all, and
  `/etc/cogwheel/.env` is yours — a second run fills in keys that are missing and never rewrites
  one you set.
- **Nothing phones home.** Cogwheel makes no update check and opens no connection you did not ask
  for. The one optional exception is AI review: off until you add an OpenRouter key and turn it
  on, and then only domain names leave — never which device asked. `/etc/cogwheel/check-update.sh`
  answers "is there anything newer?" on demand, by asking the same registry the host already pulls
  from, and exits 10 when there is. Nothing runs it for you.
- **Three tags for this release** — `:latest`, `:0.1` and `:0.1.0`. A fourth, `:1`, starts being
  published once there is a stable major line to point at; a `0` tag would promise one that `0.x`
  explicitly does not have. `latest` is the default deliberately: a moving tag is what makes
  `docker compose pull` an upgrade, and it is the only thing an Unraid update check can compare a
  digest against. Pinning is the informed opt-out, and its cost is that nobody tells you when a
  security fix ships.
- **`linux/amd64` and `linux/arm64`**, so a Raspberry Pi 5 runs the published image with no build
  step. The container runs as uid 10001 with every capability dropped except
  `NET_BIND_SERVICE`, which is what lets a non-root process bind port 53.
- **A schema upgrade takes a snapshot first** and does the rewrite inside one immediate
  transaction, so a power cut during a migration costs a restart rather than the database.
- An Unraid Docker template with a PNG icon, a systemd unit for a native install, and a
  `verify-install.sh` left on the host so the post-upgrade check is runnable without a checkout.
  The template names the container `cogwheel`, as every other install does, so the same
  `docker exec cogwheel …` commands work on Unraid.

### Known limitations

- **The control plane has no authentication.** Anyone who can reach port 8080 can change what is
  filtered, read the query log and pause protection. It is built for a home LAN, where whatever
  answers DNS is already trusted by everything on the network. Bind it to loopback behind a
  reverse proxy if that is not your situation — see [SECURITY.md](SECURITY.md).
- **No DNSSEC validation.** Cogwheel is a DoT/DoH _client_: it can prove it is talking to the
  upstream you named, and relies on that upstream to have validated the answer. It does not check
  signatures itself.
- **Single node.** One appliance, one database. There is no second instance to fail over to, so a
  household that cannot tolerate DNS being down for a reboot should give its router a second
  resolver — which is also the thing that makes some devices skip Cogwheel, so choose knowingly.
- **The query log stops at 7 days and 250,000 rows.** A busy household reaches the row cap first.
  There is no archive and no export.
- **A device that ignores you is not filtered.** A TV with a hardcoded resolver, or a browser
  doing DNS-over-HTTPS on its own, never sends Cogwheel the query — so it is never filtered and
  never appears in the log. Per-device control and a device that ignores the network entirely are
  two halves of the same sentence.
- **AI review guesses the website.** DNS carries no referrer, so the site a name was loaded for
  is inferred from the burst of lookups around it, and can be wrong; the model is told so. Behind
  NAT, or under Docker bridge networking, several devices share one address and their lookups
  merge into one stream, which makes the guess worse.
- **An AI block does not follow CNAME aliases.** The AI list judges the names devices asked for;
  a name reached only as the target of another name's CNAME is checked against the lists alone.
  And an AI allow lifts a list's block on that name, not on a name it redirects to.
- **No Raspberry Pi measurement yet.** Every number above was taken on a 4-vCPU x86_64 sandbox.
  They are reference points, not Pi 5 figures.

[Unreleased]: https://github.com/thekozugroup/Cogwheel-DNS/commits/main
