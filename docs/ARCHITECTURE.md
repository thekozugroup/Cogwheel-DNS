# Cogwheel architecture

Cogwheel is a **DNS filtering appliance for one household network**. One Rust
binary answers DNS on port 53 for every device on the LAN, applies subscribed
blocklists, and serves a small React control plane on port 8080. One SQLite file
holds everything it remembers. There is no second service, no message broker and
no agent to install on anything.

---

## 1. Scope boundary — what Cogwheel is not

This section exists because the boundary is easy to drift across, and each of
these was considered and refused rather than overlooked.

**Cogwheel does not classify unless you turn on AI review**
([ADR 0002](adr/0002-ai-review-tier.md)). There is no heuristic scorer and no
threat feed, and no model ever sits on the DNS path. A name is blocked because a
list you subscribed to names it, because you wrote a rule, or — only once you
have added your own OpenRouter key and turned AI review on — because a decision
model judged that exact name after a website loaded it, and that verdict is a
row you can read and undo. That is the whole decision procedure, and it is the
reason `GET /api/v1/check` can tell you exactly which of thirteen steps fired for
any name.

Permanently out of scope:

| | Why |
|---|---|
| Threat-intelligence feeds | A different product, with a different update cadence and a different failure mode. Lists cover the stated job. |
| Multi-node sync | One appliance for one household. Two resolvers that disagree is worse than one. |
| VPN or exit-node integration | Out of the layer. Cogwheel answers queries; where the traffic then goes is somebody else's concern. |
| Notifications, a backup API, a metrics exporter | `GET /api/v1/overview` and `/health/*` are the operational surface, and the data directory is the backup. |
| Any form of telemetry | The appliance makes **no outbound request of its own**. It talks to the upstream resolver you configured and to the blocklist URLs you subscribed to — and, with one named exception, that is all. The exception is AI review: off by default, nothing goes to OpenRouter until someone uses its set-up form, and no household name goes until it is turned on. There is not even an update check — [`scripts/check-update.sh`](../scripts/check-update.sh) is a thing you run, not a thing that runs. |

**Model classification used to sit in that table**, on the grounds that a
household cannot audit a model's verdict and "it looked like a tracker" is not
an answer anyone can act on. That is still true of a model's reasoning, so AI
review is built so that every verdict can be audited even though the reasoning
cannot. Each one is a stored row holding the model's own confidence, the model
that answered and, for as long as the log keeps history, the website it was
judged for; Activity and `/check` name
the AI list whenever it decided; your rules and the protected suffixes outrank
it; it matches exact names only; and a household rule, Forget or Clear undoes
any of it in one click. What the model cannot be asked to explain, thresholds,
exact matching and its place in the precedence limit instead. A model on the
DNS path, a verdict nobody can see, and traffic nobody asked for stay refused.

**And it does not intercept HTTPS.** Some sites detect DNS-level blocking and
ask you to turn it off. Defeating that would mean terminating TLS for every
device on the network, which is a far larger security decision than ad blocking
and is not one this product makes.

---

## 2. The shape

```
                    ┌──────────────────────────────────────────┐
  LAN devices  ───► │ :53  UDP + TCP listeners                 │
                    │        cogwheel-dns-core                 │
                    │   parse → scope → cache → evaluate       │
                    │                       │                  │
                    │              miss ────┼──► upstream ────────►  1.1.1.1
                    │                       │    (cleartext/DoT/DoH)
                    │   ┌───────────────────▼──────────────┐   │
   a browser   ───► │   │ :8080  HTTP API + the built SPA  │   │
                    │   │        apps/cogwheel-server      │   │
                    │   └───────────┬──────────────────────┘   │
                    │               │                          │
                    │   ┌───────────▼─────────┐  ┌──────────┐  │
                    │   │ cogwheel-storage    │  │ lists/   │  │
                    │   │ cogwheel.db (SQLite)│  │ bodies   │  │
                    │   └─────────────────────┘  └──────────┘  │
                    └──────────────────────────────────────────┘
                                one process, one volume
```

Both ports are served by the same process. The web UI is built to static files
and served by the Rust server from the same origin as the API, so there is no
reverse proxy to configure and no CORS policy to get wrong.

Five threads in the steady state: the main thread and four Tokio workers on a
four-CPU host. A `spawn_blocking` thread appears while a list is being compiled
and goes away again.

---

## 3. How a query becomes an answer

The whole point of the split between `cogwheel-dns-core` and everything else is
that this path is short, allocation-free where it matters, and cannot be made
to wait on anything that is not DNS.

1. **Receive.** One shared `UdpSocket`, with `min(available_parallelism, 4)`
   receive loops, each owning a fixed 4 KiB buffer.

2. **Parse.** The name comes out as an `Arc<str>` in ASCII form, so
   internationalised names stay in their `xn--` encoding and are compared the
   same way everywhere.

3. **Pick the scope.** One `RwLock` read, no allocation. Paused → the
   unfiltered scope. Otherwise the client's IP is looked up in a
   `HashMap<IpAddr, Scope>`; an address with no device row resolves under the
   household scope, and a device with filtering switched off maps to the
   unfiltered scope.

   **This is why networking mode decides a feature.** The identity of a device
   *is* the source address of its query. Bridge networking that rewrites that
   address to the Docker gateway collapses every device in the house into one
   client, with no error — see
   [DEPLOYMENT §5](DEPLOYMENT.md#5-networking-host-vs-bridge-and-why-it-decides-a-feature).

4. **Probe the cache.** A hit is answered **inline on the receive loop** — no
   permit, no task spawn, no allocation beyond the response copy. On the
   machine this document was written on that is a couple of microseconds of
   server-internal time.

   The cache is a hand-rolled `HashMap` plus an insertion-order queue, sharded
   sixteen ways behind independent locks, bounded at 10,000 entries and keyed by
   `(scope, qtype, name)`. Not an LRU: every entry already carries its own
   freshness deadline, so recency tracking buys nothing that an eviction order
   does not already give, and a plain shard is cheaper to probe on the receive
   loop than a concurrent cache with a maintenance thread of its own.

5. **Hand off the miss.** A bounded semaphore (512 permits) gates concurrent
   misses. No permit available means SERVFAIL and a counter, rather than an
   unbounded queue that turns a slow upstream into memory exhaustion.

6. **Evaluate**, synchronously and without allocating, in this order — first
   match wins, and `GET /api/v1/check` reports which step fired:

   | | | |
   |---|---|---|
   | 1 | paused | allow |
   | 2 | client has no device row | → household scope |
   | 3 | device has filtering off | allow |
   | 4 | device allow rule | allow |
   | 5 | device block rule | block |
   | 6 | household allow rule | allow |
   | 7 | household block rule | block |
   | 8 | **protected suffix** | allow |
   | 9 | **AI list**, exact name, when AI review is on | allow or block, attributed to the AI list |
   | 10 | list allow (`@@`) within this scope's lists | allow |
   | 11 | list block within this scope's lists | block, attributed to that list |
   | 12 | a CNAME target re-runs 8, 10 and 11 | block |
   | 13 | nothing matched | allow |

   Rule matching is suffix-on-label-boundary, so a rule for `example.com`
   covers `ads.example.com` and never `notexample.com`. The AI list is the one
   tier that is not: a verdict on `cdn.site.com` says nothing about
   `img.cdn.site.com`, so a crafted name earns a verdict for itself and nothing
   else. It is household-wide and applies in every filtered scope, a device on
   "No lists" included; paused and unfiltered scopes never reach it. It costs
   one branch on a miss while it is empty and one hash probe when it is not, and
   it is not part of step 12, so no cached answer for one name can depend on
   another name's AI verdict.

   Step 8 is the safety net: 21 suffixes — resolver bootstrap and
   captive-portal checks, NTP, certificate-status endpoints — that **no list can
   take off the network**. A list that names one is still installed and still
   used; the names it hit are recorded in its `note` and keep resolving, because
   the protection is enforced here, at evaluation time, rather than by refusing
   the list. Your own block rule (steps 5 and 7) outranks it deliberately: if
   you block one of these knowingly, it stays blocked.

7. **Answer or forward.** A block is built locally and cached for 300 s. A miss
   goes upstream; unless the verdict was an explicit allow — a rule, a protected
   suffix or a list exception — the answer's CNAME chain (up to 8 hops) is
   re-checked against the lists on the way back — which costs no extra round
   trip and is what closes CNAME-cloaked tracking. An AI-list allow is still
   re-checked: the model judged the name, not where it points.

8. **When the upstream fails**, a stale entry is served if one exists,
   re-freshened for 30 s, and counted. A day-old address beats no DNS at all.
   Stale is only ever a fallback: an entry past its fresh lifetime is never
   served until the upstream has actually failed.

9. **Log it.** The query goes to a bounded channel (8,192) with `try_send`, so a
   slow writer drops log rows rather than slowing resolution. Everything after
   this point is off the hot path.

### What the hot path may not do

Enforced by a test — `hot_path_crates_remain_llm_and_network_independent` — that
reads the crate's own manifest:

- `cogwheel-dns-core` depends on `cogwheel-policy` and nothing else in the
  workspace. Not storage, not the server, not the web app.
- It may not gain an HTTP client or a model-API dependency. The only network
  call a query can make is to the configured upstream resolver.
- `cogwheel_policy::evaluate` is pure. The cache and the counters are in memory.

Answering a query must never depend on a remote service, a storage write or a
background job having succeeded.

---

## 4. Why the crates are split where they are

Four libraries and one binary. The graph is small on purpose, and a test —
`crate_path_dependencies_match_the_adr_boundaries` — fails if it drifts.

```
cogwheel-policy   ──► (nothing)
cogwheel-dns-core ──► cogwheel-policy
cogwheel-lists    ──► cogwheel-policy
cogwheel-storage  ──► (nothing)

apps/cogwheel-server ──► all four, and nothing else
```

| Crate | Owns | Why it is separate |
|---|---|---|
| `cogwheel-policy` | The rule model, the thirteen-step `evaluate`, the 64-slot list bitmask, the exact-name AI list, domain normalisation, `BlockMode`, the 21 protected suffixes. | It is pure and has no I/O, so the decision procedure can be tested exhaustively without a socket or a database — and so nothing on the hot path can reach the control plane through it. |
| `cogwheel-dns-core` | Listeners, request parsing, the response cache and its per-name invalidation, CNAME uncloaking, upstream transports, the pause switch, the counters. | This is the hot path. Keeping it in its own crate is what makes "depends on `cogwheel-policy` only" a checkable statement rather than an intention. |
| `cogwheel-lists` | Fetching blocklists over HTTPS, the three grammars (`domains`, `hosts`, Adblock), and verification. | It talks HTTP. Putting it anywhere near the resolver is exactly the drift the boundary exists to prevent. |
| `cogwheel-storage` | The schema, the migrations, the repositories (the AI list's table among them), retention. | Schema details stay inside it; nothing else in the workspace writes SQL. Every method is `async` over `spawn_blocking`, so a slow disk never blocks a reactor thread. |
| `apps/cogwheel-server` | Composition: configuration, 29 routes, the response envelope, the readiness tracker, the refresh scheduler, the event stream, and the opt-in AI reviewer (`ai/`). | The composition root is allowed to know about everything. Nothing else is. The reviewer is a module here rather than a crate, so the graph above does not change, and the one client that talks to OpenRouter is the server's, never the hot path's. |

Cross-crate sharing prefers a compiled artifact — a `Policy`, a `ListIndex` —
over leaking internal structs. Reusable domain behaviour lands in a library; the
server composes.

Changing this graph means updating
[ADR 0001](adr/0001-crate-boundaries.md) first, then the guard test, then the
code, in the same change. The ADR records the reasoning; the test records the
shape.

---

## 5. How a change becomes a new ruleset

Everything a user can change — a list toggled, a device edited, a rule added, a
refresh that brought new bodies — goes through one rebuild, on a blocking
thread, and ends in an atomic swap.

1. Build a `ListIndex` from every enabled source's cached body. When only
   devices or rules changed, the existing index is reused as the same `Arc`
   rather than recompiled.
2. Compute the household mask (the OR of every enabled list's slot) and the
   household rule set.
3. For each device, compute its own mask and rules, and reduce them to a
   signature.
4. **Intern the signatures into scope ids.** Two devices configured identically
   share a scope, and therefore share cache entries. The household default is
   scope 0 and "filtering off" is scope 1, so the two most common cases are
   constants.
5. Swap the new `Policy` into the runtime.

The cache is invalidated only where it has to be. A list rebuild or a
household-rule change clears it, so an unblock takes effect on the next query
rather than whenever an entry happens to age out. A single device edit produces
a *new* scope id instead, and that device's old entries simply age out — the
rest of the household keeps its cache.

An AI-list change is the fourth kind, and it keeps the cache too. The new AI
list is compared with the one in force, and only the cached answers for the
exact names whose verdict changed are dropped — complete because no cached
answer depends on another name's AI verdict (§3). Every rebuild reads the
stored verdicts, so a device edit makes the same comparison and can never
install a verdict the cache was not told about. The reviewer itself never
builds a policy: it commits verdicts and wakes an installer task, which
rebuilds after a 5 s pause so a burst of answers becomes one install.

A policy swap also bumps a cache epoch, so a miss that was already in flight
under the replaced policy can tell that its answer came back too late to be
cached.

Enabled lists are limited to 64 because a scope's list selection is a `u64`
bitmask; the 65th is refused with a 409 rather than silently ignored.

---

## 6. Storage

One SQLite file, WAL mode, eight tables:

| Table | Holds |
|---|---|
| `settings` | key/value appliance state: the pause deadline, and AI review's consent, model, daily limit and today's spend |
| `sources` | subscribed blocklists, their fetch state and their `note` |
| `devices` | named clients and their per-device flags |
| `device_lists` | which lists a device uses, when it does not use all of them |
| `rules` | allow/block entries, household-wide or attached to one device |
| `query_log` | the per-query rows behind the Activity page |
| `query_stats_hourly` | hourly rollups, written in the same transaction as the rows |
| `ai_verdicts` | the AI list: one row per judged name, at most 10,000, with the model's answer, its confidence and the website it was judged for |

The OpenRouter key is deliberately **not** in the database. It lives beside it
in `openrouter.key`, mode 0600, so it never reaches a `.pre-v2` snapshot, a
`VACUUM INTO` copy or the WAL.

The rollups are the reason the Overview page is cheap: top-ten queried and
top-ten blocked read the aggregate, not a `GROUP BY` over a quarter of a million
rows.

The query log is bounded twice — by age (`HISTORY_DAYS`, 7) and by row count
(`QUERY_LOG_MAX_ROWS`, 250,000) — because an appliance that fills its own SD
card is an appliance that stops resolving. Setting `HISTORY_DAYS=0` stops the
per-query rows entirely and keeps the rollups, so the Overview and Devices pages
still work and Activity does not. AI review needs the log, so `HISTORY_DAYS=0`
also makes it unavailable and empties the AI list at startup.

The AI list is bounded the same way. The website a verdict was judged for is
forgotten after `HISTORY_DAYS`; a row that left a name to the lists lives
`min(30 days, HISTORY_DAYS)`; nothing lives past 90 days; and Clear log forgets
the websites and those rows with it.

**WAL mode is why the backup procedure stops the container.** Everything since
the last checkpoint lives in `cogwheel.db-wal`, so copying `cogwheel.db` out of
a running appliance produces a file that opens cleanly and is quietly
incomplete — [DEPLOYMENT §11](DEPLOYMENT.md#11-backup-and-restore).

### Migration

Schema versions are integers, and the running image advertises the one it speaks
as the OCI label `io.cogwheel.schema-version`, so an operator can tell whether
an upgrade will migrate *before* pulling it.

A migration happens **in place**, on first start, inside one
`TransactionBehavior::Immediate` transaction — so a power cut or a `SIGKILL`
part-way through rolls it back and costs a restart, not data. Before it runs,
`VACUUM INTO` writes a consistent snapshot of the old database beside it as
`cogwheel.db.pre-v<N>`; a partially written snapshot is deleted and re-taken on
the next boot.

The open is a chain of steps, one version at a time. The current schema is v2,
which adds `ai_verdicts` and changes nothing v1 created. A v1 file gets
`cogwheel.db.pre-v2` before its step; a fresh file and an in-memory database
get no snapshot, and a pre-release v0 file is snapshotted once, as
`cogwheel.db.pre-v1`, and goes on to v2 in the same start.

A database from a *newer* Cogwheel is refused rather than opened hopefully, and
the refusal names both versions.

---

## 7. Lists

A refresh is a conditional GET per enabled source, with the stored `ETag` and
`Last-Modified`. A `304` keeps the cached body. A new body is streamed with a
32 MiB cap, parsed, and **gated**: more than one line in five unparseable and
the candidate is rejected.

The important property is what a failure does. **A refresh that fails or is
rejected leaves the policy already in force serving.** Nothing is torn down
speculatively, there is no window where the household is unfiltered, and nothing
needs rolling back — the list's row records why, and the Lists page shows it.

Bodies are cached on disk beside the database, one file per list, written
atomically. That is what lets the appliance boot filtering with no network at
all: it compiles from the files it already has rather than waiting on a
download.

---

## 8. Reaching the upstream

Cleartext on port 53 by default, with DNS-over-TLS and DNS-over-HTTPS available.
Three decisions in that path are worth knowing because each is a refusal:

- **The address and the certificate name are given separately** —
  `tls://1.1.1.1#cloudflare-dns.com`. The obvious alternative, naming only the
  hostname, needs a bootstrap lookup, and a bootstrap lookup is a cleartext
  query: the exact leak being closed would reopen on every restart.

- **There is no downgrade.** An encrypted upstream is registered with only its
  encrypted transport. If TLS fails, resolution fails visibly. A fallback would
  defeat the reason you configured it — and it would do so silently, which is
  worse.

- **No option to skip certificate verification**, and the Mozilla root set is
  compiled into the binary rather than read from the host. An encrypted channel
  to an unverified peer is worse than a cleartext one, because it looks safe.

Queries answered from the blocklists or the cache never leave the house at all,
encrypted or not — unless AI review is on, when the names (not the lookups) are
sent to OpenRouter to be judged. A repeat visit sends nothing: a name goes again
only when its verdict is due another look, which
[ADR 0002](adr/0002-ai-review-tier.md#what-leaves-the-house-and-when) spells out.

---

## 9. What degrades, and what does not

The appliance is one process, so the useful question is what happens when part
of it is unhappy.

| When this fails | This happens | DNS keeps answering |
|---|---|---|
| A blocklist refresh | The policy already in force keeps serving; the list row records why | yes |
| The upstream resolver | Stale cache entries are served, re-freshened for 30 s; otherwise SERVFAIL | yes, for what is cached |
| The query-log writer falls behind | Log rows are dropped and counted | yes |
| An event-stream subscriber falls behind | Frames are dropped for *that* subscriber past 256 behind; the 33rd concurrent subscriber is refused with 503 | yes |
| Storage is slow | Every storage call is `async` over `spawn_blocking`, so no reactor thread blocks | yes |
| A migration is interrupted | The transaction rolls back; the snapshot beside it is intact | after a restart |
| OpenRouter is unreachable, or answers 429 or 5xx | AI review retries with backoff, then says *retrying*; stored verdicts keep applying | yes |
| OpenRouter refuses the key (401/403), the account is out of credit (402), or it will not run the model (404) | AI review stops with a sentence saying which; stored verdicts keep applying | yes |
| AI review's daily limit is reached | Paused until 00:00 UTC | yes |
| The AI review tap or queue is full | Names are dropped and counted, and judged on their next sighting | yes |
| The AI reviewer task dies | AI review reads *stopped* and its send gate closes; verdicts already installed keep applying | yes |
| AI review is turned off, its key removed, or it stops for any reason | The send gate closes before the request answers: queued and grouped names are discarded and requests in flight are cancelled | yes |
| Installing the AI list fails | The previous policy stays in force, and the install is retried in 30 s | yes |

`/health/live` and `/health/ready` are deliberately different signals.
Liveness answers as soon as the HTTP listener is up. **Readiness returns 503
until storage, policy and the DNS listeners are all up**, and names which one is
lagging — on a cold start with large blocklists, compiling the policy is the
slow one. A node that is live but not ready is running and not yet filtering;
gate a rolling upgrade on readiness, not liveness. AI review is never part of
readiness: an appliance whose reviewer is stopped, or that cannot reach
OpenRouter at all, is as ready as one that never turned it on.

---

## 10. Where to read next

| | |
|---|---|
| [`docs/spec-dnsnet-plus-four.md`](spec-dnsnet-plus-four.md) | the contract: every route and its shape, the schema, the precedence order, the configuration surface |
| [`docs/adr/`](adr/) | decisions, with the reasoning that is expensive to recover |
| [`docs/DESIGN.md`](DESIGN.md) | the visual contract the five pages are held to |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | how to run it, and what to do when it misbehaves |
| [`scripts/bench/README.md`](../scripts/bench/README.md) | the benchmark harness, including the measurement bugs it documents about itself |
