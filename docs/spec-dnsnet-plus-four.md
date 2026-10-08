# Cogwheel DNS — implementation spec

Product: a DNSNet-class DNS ad-blocker for a Raspberry Pi 5 in one Docker
container: subscribe to hosts/ABP/domain lists, allow/deny rules, a query log —
plus (1) device names by IP, (2) an activity log with counts, (3) per-device
allow/block rules and per-device list selection, (4) a five-page Shark UI —
and, opt-in and off by default, (5) AI review and the AI list
([ADR 0002](adr/0002-ai-review-tier.md)). Nothing else.

Three user concepts: **Device** (name + IP), **List** (a subscription), **Rule**
(allow|block a domain, for everyone or for one device). Off by default, a
fourth: the **AI list** (exact names a decision model judged, once you add an
OpenRouter key and turn AI review on). One read: **the query log**.

Precedence (fixed, tested): pause → device filtering off → device rules →
household rules → protected suffixes → AI list (exact names, only while AI
review is on; [ADR 0002](adr/0002-ai-review-tier.md)) → list allow (`@@`) →
list block → CNAME re-check (list tier only) → allow. Explicit user rules
outrank the 21 protected suffixes; protected outranks the AI list and the
subscribed lists only.

**This document is the contract.** Everything in §1–§10 is implemented and
shipped. Where the code and this file disagree, one of them is a bug — decide
which, and fix that one, in the same change. A behaviour change that does not
amend this file has not finished.

This document describes the tree after a substantial cut-down, so any line
number here that does not match is a hint rather than an address — grep.

---

## 1 Crates

Workspace after this work: `crates/cogwheel-policy`, `crates/cogwheel-lists`,
`crates/cogwheel-dns-core`, `crates/cogwheel-storage`, `apps/cogwheel-server`,
`apps/cogwheel-web`. Removed: `cogwheel-classifier`, `cogwheel-services`,
`cogwheel-sync`, `cogwheel-api` (absorbed), `apps/cogwheel-desktop`.
Path-dependency graph (enforced by the ADR test, moved to the server crate):
dns-core → policy; lists → policy; storage → (none); server → policy, lists,
dns-core, storage.

### 1.1 cogwheel-policy (860 LOC, no I/O, deps: serde only)
- `pub const PROTECTED_SUFFIXES: [&str; 21]`.
- `pub enum BlockMode { NullIp, NxDomain, NoData, Refused }` — `Copy`.
- `pub enum Action { Allow, Block }` (Copy).
- `pub struct ListIndex { exact: HashMap<Box<str>, Masks>, suffix: HashMap<Box<str>, Masks>, names: Vec<Arc<str>> }`
  with `Masks { block: u64, allow: u64 }`; bit i = enabled list slot i (slot
  order = `sources.id` ascending among enabled rows). Lookups take `&str`
  (Borrow), zero allocation.
- `pub struct RuleSet(HashMap<Box<str>, Action>)` — user rules; suffix semantics.
  `get_at_boundaries(&str) -> Option<Action>`.
- `pub struct Scope { pub id: u32, pub filtering: bool, pub mask: u64, pub rules: Option<Arc<RuleSet>> }`.
- `pub struct AiList` (`ai.rs`, ADR 0002): exact names only, `HashMap<Box<str>, Action>`
  plus a block count fixed at build, so `blocks()`/`allows()` are O(1). `get(&str)`
  is one branch when empty and one hash probe otherwise, with no allocation;
  `changes(&next)` (control plane only) is the set of names added, removed or
  flipped. Not a `RuleSet`: suffix matching would let an allow of a site's apex
  whitelist every tracker under it.
- `pub struct Policy { index, household, ai: Arc<AiList>, by_ip, all_mask, block_mode }`;
  `Policy::new` leaves `ai` empty and `with_ai(Arc<AiList>)` sets it.
  Reserved scope ids: `SCOPE_HOUSEHOLD = 0`, `SCOPE_UNFILTERED = 1`. Device
  scopes start at 2 and are interned by signature (§6).
- `pub enum Verdict { Allow(Reason, u8 /*slot*/), Block(Reason, u8 /*slot*/) }` (Copy)
  with `pub enum Reason { NoMatch, DeviceRule, HouseholdRule, Protected, ListAllow, List, Cname, Paused, Unfiltered, Ai }`
  — codes 0–9 on the wire; `ai = 9` is the AI list, whose arm carries the
  direction and no slot.
  Both arms carry the slot because an `@@` exception has to be attributable to
  the list that granted it exactly as a block is: `Verdict::slot()` is
  `Some(slot)` for `ListAllow`, `List` and `Cname` and `None` on every tier no
  list decided, where the field itself is `0`.
- `pub fn evaluate(&Policy, &Scope, &str) -> Verdict` — allocation-free; the
  AI tier sits here, after the protected check and before the lists.
  `pub fn evaluate_lists(&Policy, mask, &str) -> Verdict` = protected + list
  tiers only: the CNAME re-check. `GET /check` runs `evaluate`.
  `Verdict::rechecks_aliases()` is true for `Allow(NoMatch)` and `Allow(Ai)`:
  the names whose answer's CNAME targets are re-checked (§5.2 step 7).
- `normalize_domain`, `normalize_rule_domain` (also strips a leading `*.`).

### 1.2 cogwheel-lists (443 LOC)
- `fetch_source_body(client, url, etag, last_modified) -> Result<FetchOutcome, FetchError>`
  where `FetchOutcome::{NotModified, Body{ text, etag, last_modified }}`; 32 MiB
  streaming cap; `data:` URLs kept.
- `parse_list(kind, body) -> ParsedList { entries: Vec<(Action, Pattern, Box<str>)>, invalid_lines }`
  with DNSNet semantics: hosts `<ip> h1 h2…` → Exact for every hostname except
  the localhost family (`localhost localhost.localdomain local broadcasthost
  ip6-localhost ip6-loopback ip6-localnet ip6-mcastprefix ip6-allnodes
  ip6-allrouters ip6-allhosts 0.0.0.0`); domains-kind bare host → Suffix;
  `*.host` → Suffix(host); ABP `||x^` → Suffix, `@@||x^` → Allow Suffix; any ABP
  line containing `#` or `$` or starting with `/` → invalid; `#`/`!` comments,
  `[Adblock Plus]`-style `[` headers and blanks skipped.
- `verify_list(parsed) -> Result<(), String>`: invalid ratio > 20% rejects THAT
  list only.
- `protected_hits(index) -> Vec<&'static str>`: surfaced as a per-list `note`,
  never a rejection (protection is enforced at evaluation).

### 1.3 cogwheel-dns-core (1,788 LOC)
- `upstream.rs` (moved from cogwheel-api) plus `build_resolver(servers)` with
  `ResolverOpts { timeout: 2 s, attempts: 2, cache_size: 0, try_tcp_on_error:
  true, preserve_intermediates: true }`.
- `DnsRuntime` (§5), `serve_with_ready_signal`, the TCP handler.
- TTL clamp (5 s floor, 1 h ceiling, 60 s negative), `error_response_for_payload`,
  `servfail`, `build_base_response`, `build_blocked_response`.
- `invalidate.rs` (ADR 0002): `DnsRuntime::swap_policy_invalidating(policy,
  &changed) -> usize` installs a policy whose verdicts differ only for the exact
  names in `changed`, and drops every cached answer for those names under every
  scope and type (not their subdomains). Epoch before sweep, as `swap_policy`
  does; each shard's write lock is taken only if a read pass found one of the
  names. Complete because the AI tier is not in `evaluate_lists`, so no cached
  answer depends on another name's AI verdict.

### 1.4 cogwheel-storage (2,351 LOC, deps: rusqlite(bundled), serde, serde_json, thiserror, tokio, tracing)
- One `Arc<Mutex<Connection>>`; PRAGMAs journal_mode=WAL, synchronous=NORMAL,
  wal_autocheckpoint=1000, foreign_keys=ON, busy_timeout=5000, cache_size=-1024
  (the page cache is 1 MiB of the process's stated memory budget rather than
  whatever the linked SQLite defaults to).
- Every public method is `async fn` running its closure under
  `tokio::task::spawn_blocking` (the DNS task and axum handlers never run
  rusqlite on a runtime worker).
- `schema_v1.sql` (frozen) + `schema_v2.sql` (the v1 → v2 step, which a fresh
  install runs too) + `migrate.rs` (legacy v0 → v1, and v1 → v2), versioned by
  `PRAGMA user_version` (§2). The eleven legacy migration files live in
  `tests/fixtures/legacy/` and are used to build the upgrade fixture.
- Ids stay TEXT UUIDs for `sources`/`devices`; the crate stores them as `String`
  (no uuid dep); the server validates at the API edge.
- Repos: sources (list/insert/update/delete/update_fetch_status), devices
  (list/upsert/delete/set_lists), rules (list/insert/delete), query_log
  (insert_batch_with_rollups, page, top_domains, clear, prune), stats
  (hourly_24h, per_client_24h, unnamed_clients_24h), settings (`pause_until`,
  plus a generic `setting`/`set_setting` for AI review's keys, §2.1a).
- `ai_verdicts.rs` (ADR 0002): `list_ai_verdicts`, `ai_verdict`,
  `page_ai_verdicts`, `ai_counts`, `record_ai_verdicts(rows, ai_spend)` (one
  transaction; `rows` may be empty, which is how a billed response with nothing
  to store persists its spend), `delete_ai_verdict`, `clear_ai_verdicts`,
  `scrub_ai_sites`, `forget_ai_negatives` (Clear log's half) and
  `prune_ai_verdicts(now, history_days, max_rows) -> AiPruned` (every deleted
  domain, and how many were decisions).
- Tests: idempotent open; v0 fixture upgrade (fixture built by executing the
  eleven legacy migration files, seeding a device with bypass + allowed_domains
  + profile override, the baseline source, one user source); prune by days and
  by row cap; rollup upsert arithmetic; HISTORY_DAYS=0 writes rollups but no log
  rows; a v1 file upgrades to v2 with a `.pre-v2` copy, a fresh one takes none,
  and a failed v1 → v2 step rolls back naming the copy; the AI list's upserts,
  paging, counts, site scrubbing, Clear log's half and every prune step; spend
  written in the same transaction as the rows, empty or not.

### 1.5 apps/cogwheel-server (10,027 LOC excluding tests, 5,961 of them AI review's own files)
`main.rs` (CLI `--version/--help`, init_tracing, startup order, background
tasks, graceful shutdown), `config.rs` (AppConfig from env), `http.rs` (router,
`/health/live`, `/health/ready` + `Readiness`, `ApiEnvelope`, `ApiError`, SPA
fallback, CompressionLayer), `state.rs`, `policy_build.rs` (§6), `refresh.rs`
(§2.7), `querylog.rs` (§7), `prune.rs`,
`api/{overview,queries,devices,rules,lists,check,settings,runtime,ai}.rs`, and
the AI reviewer, `ai/` (ADR 0002): `mod.rs` (`AiState`, the tap, `ListState`),
`gate.rs` (the send gate and the state machine), `settings.rs`, `patch.rs`
(route 24), `test_run.rs` (route 26), `models.rs` (route 25), `status.rs`,
`key.rs`, `client.rs`, `site.rs`, `burst.rs`, `prompt.rs`, `verdict.rs`,
`known.rs`, `spend.rs`, `review.rs` and `review/settle.rs` (the pure
`Pipeline`), `worker.rs` and `install.rs` (the two tasks). `ai/` is a module,
not a crate, so the ADR 0001 graph is unchanged; its unit tests live in
`ai/tests/`.
Tests: ADR path-dependency test, CLI tests, block-mode tests,
`encrypted_upstreams_have_trust_anchors_compiled_in`, EventBus tests (Query
frames only), source-due test, handler tests against an in-memory Storage, and
AI review's unit, handler and end-to-end tests against a local stub OpenRouter
(no test reaches the network).

### 1.6 apps/cogwheel-web (14,308 LOC; React 19 + Vite + Tailwind 4 + Shark UI (Ark) + Inter)
Five routes, one provider, one `api.ts` of 29 calls; approved shell reused (§4).

---

## 2 Schema + migration

Eight tables, `PRAGMA user_version = 2`: the seven of `schema_v1.sql` (§2.1),
plus `ai_verdicts` from the additive v1 → v2 step (§2.1a, ADR 0002). All
timestamps are INTEGER unix seconds. Ids for `sources`/`devices` remain TEXT
UUIDs (every existing row keeps its id).

### 2.1 `schema_v1.sql` (frozen; every install runs it, then §2.1a)
As v1 shipped it; the comment on `settings` predates v2, whose keys are in §2.1a.
```sql
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
  -- only key: 'pause_until' (unix secs; absent/0 = not paused)

CREATE TABLE sources (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('hosts','domains','adblock')),
  enabled INTEGER NOT NULL DEFAULT 1,
  etag TEXT, last_modified TEXT, last_fetched_at INTEGER, last_ok_at INTEGER,
  rule_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, note TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE devices (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE,
  filtering INTEGER NOT NULL DEFAULT 1,      -- 0 = bypass: resolve everything, still logged
  all_lists INTEGER NOT NULL DEFAULT 1,      -- 0 = only device_lists rows apply
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE device_lists (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  PRIMARY KEY (device_id, source_id));

CREATE TABLE rules (
  id INTEGER PRIMARY KEY, domain TEXT NOT NULL,           -- normalized, no leading '*.'
  action TEXT NOT NULL CHECK (action IN ('allow','block')),
  device_id TEXT REFERENCES devices(id) ON DELETE CASCADE, -- NULL = everyone
  created_at INTEGER NOT NULL);
CREATE UNIQUE INDEX rules_unique ON rules (domain, COALESCE(device_id, ''));

CREATE TABLE query_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL,
  qtype INTEGER NOT NULL, blocked INTEGER NOT NULL, reason INTEGER NOT NULL, list TEXT);
-- No index on query_log. `id` is the rowid and the log is append-only in
-- timestamp order, so the table's own order already is the (ts, id) order every
-- read wants: the page walks backwards from the end, the prune forwards from the
-- start, and both stop as soon as they have what they came for. Measured before
-- deciding: with query_log_ts and query_log_client_id present, EXPLAIN QUERY PLAN
-- on the client-filtered page still reports SCAN q -- `(?2 IS NULL OR q.client =
-- ?2)` is not sargable -- and the page took 0.6 ms either way on a 250,000-row
-- log, for 42 B/row of index (10 MB at the cap). Revisit when a Pi 5 measurement
-- exists; every figure in this file was taken on x86_64.

CREATE TABLE query_stats_hourly (
  hour INTEGER NOT NULL, client TEXT NOT NULL,            -- client '' = all devices
  queries INTEGER NOT NULL, blocked INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (hour, client));
PRAGMA user_version = 1;
```
Write rates: `sources` one UPDATE per source per refresh (daily by default);
`devices`/`device_lists`/`rules` on user edits; `query_log` +
`query_stats_hourly` one transaction per 5 s (§7); `settings` per pause click,
and once per paid OpenRouter request (`ai_spend`, in the same transaction as
any `ai_verdicts` row that request produced), which the request cap of §3a
bounds.

### 2.1a `schema_v2.sql` (the v1 → v2 step; ADR 0002)
Additive: the seven v1 tables are untouched. A fresh install runs
`schema_v1.sql` and then this file, exactly as a v1 upgrade does, so there is
one definition of v2; `schema_v1.sql` stays frozen because v0 upgrades execute
it.
```sql
CREATE TABLE ai_verdicts (
  domain            TEXT PRIMARY KEY,   -- normalize_domain form; an exact name, never a suffix
  verdict           TEXT NOT NULL CHECK (verdict IN ('block','allow','ignore')),
  why               TEXT CHECK (why IS NULL OR why IN ('agrees','unsure','limit','contested')),
  choice            TEXT NOT NULL CHECK (choice IN ('block','allow','ignore')),   -- the role answer
  confidence        REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  effect            TEXT CHECK (effect IS NULL OR effect IN ('breaks','works','unsure')),
  effect_confidence REAL CHECK (effect_confidence IS NULL OR (effect_confidence >= 0 AND effect_confidence <= 1)),
  lists             TEXT NOT NULL CHECK (lists IN ('nothing','block','exception')), -- household lists when judged
  site              TEXT,               -- the site load's website; NULLed at HISTORY_DAYS and on Clear log
  conflict_site     TEXT,               -- the other website, for why='contested'; NULLed with site
  rechecks          INTEGER NOT NULL DEFAULT 0 CHECK (rechecks BETWEEN 0 AND 2), -- 0 on every fresh judgement
  model             TEXT NOT NULL,      -- the dated snapshot the response named
  judged_at         INTEGER NOT NULL,   -- unix seconds
  review_after      INTEGER NOT NULL    -- judged_at + 30 days; + min(30, HISTORY_DAYS) days for an
                                        -- ordinary ignore; + 90 days for a contested one
) WITHOUT ROWID;
PRAGMA user_version = 2;
```
No secondary index (the table is capped at 10,000 rows), no client column (the
AI list never records which device visited a site), and no `applied` column
(whether a row applies depends on the live lists, so it is decided at compile
time). From v2, `settings` also holds AI review's keys, written through the
generic `setting`/`set_setting`:

| key | value | written by |
|---|---|---|
| `ai_enabled` | `1`, or absent | `PUT /api/v1/ai`; deleted at startup whenever AI review is unavailable, so it never resumes without a fresh Turn on |
| `ai_model` | a model id, e.g. `typesafe/jev-1.13` | `PUT /api/v1/ai` |
| `ai_model_price` | USD per million prompt tokens, as listed when the model was picked; absent if unknown | `PUT /api/v1/ai` |
| `ai_daily_limit` | `0.05` \| `0.10` \| `0.25` \| `1.00`; absent means `0.10` | `PUT /api/v1/ai` |
| `ai_spend` | `"<utc_day> <micro_usd> <requests> <overrides>"` | only the server's spend owner, always through `record_ai_verdicts`, in one transaction with any verdicts |

The OpenRouter key is never in the database: it is
`<dir of DATABASE_URL>/openrouter.key`, mode 0600, so it never reaches a
`.pre-v2` copy, a `VACUUM INTO` backup or the WAL.

### 2.2 Open sequence (`Storage::open`)
A chain of steps, one version at a time, each committed before the next, so a
crash between two steps leaves a valid older file that the next open carries
on from.
1. Open, set PRAGMAs. 2. `opened_at = v = PRAGMA user_version`. 3. Loop:
`v == 2` → done. `v == 0` and table `rulesets` exists → legacy upgrade (§2.3),
which leaves v1. `v == 0` and a `sources` table but no `rulesets` → refuse
(unknown schema). `v == 0` otherwise → execute `schema_v1.sql` in one
transaction. `v == 1` → the v2 step: `schema_v2.sql` in one `IMMEDIATE`
transaction, after a `VACUUM INTO '<db path>.pre-v2'` **only when
`opened_at == 1`** — a fresh file, a v0 file (already copied as `.pre-v1`) and
`:memory:` get no copy. Any other `v` → refuse to start with "database is from
a newer Cogwheel". A step that does not advance `user_version` is an error, not
a loop.
After open: `seed_if_empty` (§2.4).

### 2.3 Legacy v0 → v1 upgrade (`migrate.rs`), one transaction, guarded by a backup
1. `VACUUM INTO '<db path>.pre-v1'` (remove a stale file of that name first). A
   plain file copy is NOT used because the WAL may hold unflushed pages.
2. `BEGIN IMMEDIATE`.
3. Rename the three legacy tables whose names v1 reuses out of the way —
   `settings`→`settings_v0`, `sources`→`sources_v0`, `devices`→`devices_v0`
   (SQLite rewrites a child's `REFERENCES devices` when its parent is
   renamed, so `security_events` follows `devices` across without a separate
   step) — then execute `schema_v1.sql` itself, the same file a fresh install
   runs, to create the seven v1 tables under their real names. One definition
   of what v1 is: an upgraded database is the fresh schema by construction,
   with every foreign key already pointing at the final table names, rather
   than a second copy of the DDL kept in step with it by hand. (`schema_v1.sql`
   also sets `PRAGMA user_version = 1` as its last statement, so nothing
   later in this sequence needs to.)
4. `INSERT INTO sources … SELECT … FROM sources_v0 WHERE id <> '00000000-0000-0000-0000-000000000001'`
   (the built-in 2-name `baseline` data: URL is dropped;
   `refresh_interval_minutes`, `profile`, `verification_strictness` dropped).
5. `INSERT INTO devices … CASE WHEN policy_mode='custom' AND protection_override='bypass' THEN 0 ELSE 1 END, 1, … FROM devices_v0`
   — every device keeps its id, name and IP; a bypass device keeps bypassing;
   `all_lists` is always 1 (a `blocklist_profile_override` never affected DNS, so
   it is NOT mapped; each such device is named in a startup WARN).
6. `INSERT INTO rules (domain, action, device_id, created_at) SELECT lower(trim(j.value)), 'allow', d.id, unixepoch() FROM devices_v0 d, json_each(d.allowed_domains_json) j WHERE d.policy_mode='custom' AND j.value <> ''`
   (global-mode devices had their allowed_domains ignored at runtime, so
   importing them would change behaviour; skipped with a WARN naming the
   device). `service_overrides_json` is discarded (WARN). `block_profiles`
   allowlists are NOT imported (would silently unblock).
7. If the baseline source row was present: seed `ads.example.com` and
   `tracker.example.com` as household block rules so an upgraded install keeps
   answering `0.0.0.0` for the names docs/DEPLOYMENT.md §7 uses.
8. Drop the three legacy indexes first (`idx_notification_deliveries_created_at`,
   `idx_security_events_created_at`, `idx_audit_events_created_at` — `DROP
   TABLE` would take them anyway, but naming them is easier to audit against
   this list). Then `DROP TABLE`, children before parents: active_ruleset,
   rulesets, security_events, audit_events, notification_deliveries,
   config_migrations, config_schema, settings_v0, sources_v0, devices_v0.
   `active_ruleset.ruleset_id` references `rulesets`, and
   `security_events.device_id` references `devices_v0` (rewritten by step 3's
   rename); with `foreign_keys=ON`, `DROP TABLE` on the referenced side runs
   an implicit `DELETE FROM` that fails while a child row still points at it,
   so each child has to go before its parent. `COMMIT`.
9. On any error: `ROLLBACK`, log the `.pre-v1` path, exit non-zero (the old
   image still boots the untouched v0 file).

### 2.4 First-boot seed (`seed_if_empty`, fresh AND upgraded DBs)
If `sources` is empty: insert one enabled list — **oisd small**
(`https://small.oisd.nl`, kind `adblock`, name "oisd small"). Nothing else is
seeded; no hidden built-in rules.

### 2.5 Preset catalogue (`apps/cogwheel-server/src/api/lists.rs`, `const PRESETS`; returned by `GET /api/v1/lists` as `presets`)
HaGeZi Light/Multi/Pro/Pro++/Ultimate
(`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/{light,multi,pro,pro.plus,ultimate}.txt`,
adblock), StevenBlack unified
(`https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`, hosts) and
its gambling/porn/social alternates
(`…/alternates/{gambling-only,porn-only,social-only}/hosts`, hosts), oisd
small/big (`https://small.oisd.nl`, `https://big.oisd.nl`, adblock). These are
DNSNet's presets.

### 2.6 List body cache on disk
`<dir of DATABASE_URL>/lists/<source id>.txt` written atomically (write `.tmp`,
rename) after every successful fetch; deleted on list delete. Boot compiles from
these files without network; a read-only rootfs with the data volume mounted
works.

### 2.7 Refresh pipeline (`refresh.rs`)
`refresh(ids: All | One(id))`: for each enabled source → conditional GET with
stored `etag`/`last_modified` → `NotModified` keeps the cached body; `Body` is
parsed and gated; a rejected or failed fetch keeps the previous body file and
records `last_error`, `last_fetched_at`; a success writes the body, `etag`,
`last_modified`, `last_ok_at`, `rule_count`, clears `last_error`. Then
`rebuild_policy` (§6) runs on `spawn_blocking` from ALL cached bodies (never only
the due subset) and swaps `DnsRuntime.policy`, `cache.invalidate_all()`.
Toggling `enabled` or editing a device/rule rebuilds from cached bodies with no
network. One refresh in flight at a time (`AtomicBool`), 30 s minimum gap for
manual refreshes. Scheduler: tick every 60 s; a source is due when
`last_fetched_at IS NULL`, or `last_ok_at` is older than
`COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS` and `last_fetched_at` is older than
300 s (so a failing list retries every 5 min, a healthy one daily). Startup:
compile from cached bodies (or an empty index) → `mark_policy_ready()` → spawn
the first refresh in the background; `/health/ready` therefore returns 200 on a
runner with no egress and the Overview shows "Lists not downloaded yet".

---

## 3 API

Every JSON response is `{ "data": … }` (ApiEnvelope). Errors:
`{ "error": "<plain sentence>" }` with 400 (validation; a guarded AI route
called from elsewhere, §3a), 404, 409 (65th enabled list; duplicate device IP;
duplicate list name; AI review unavailable, or not ready to turn on), 429
(refresh within 30 s; a Test within 10 s; OpenRouter rate-limiting), 503 (SSE
cap / not ready; OpenRouter unreachable), 500. Ids are the UUID strings. Times
are unix seconds. 29 routes (27 + 2 health); routes 23–29 are AI review's
(ADR 0002, §3a).

| # | Method | Path | Body / query | Response `data` | Notes |
|---|---|---|---|---|---|
| 1 | GET | `/health/live` | — | `{status:"ok"}` | Docker HEALTHCHECK, install.sh — unchanged |
| 2 | GET | `/health/ready` | — | `{status, subsystems{storage,policy,dns_listeners}}` 503 until all | ci.yml, verify-install.sh — unchanged; policy ready once ANY policy (even empty) is installed |
| 3 | GET | `/api/v1/overview` | — | `{protection:{paused_until:int\|null}, runtime:{queries_total,blocked_total,cache_hits_total,cache_expired_total,stale_served_total,upstream_failures_total,cname_blocks_total,dropped_total,log_dropped_total,cache_hit_latency_avg_ns,cache_miss_latency_avg_ns}, last_24h:{queries,blocked,per_hour:[24×{hour,queries,blocked}],active_clients,named_devices,unnamed_clients}, lists:{enabled,total,rules_loaded,last_ok_at:int\|null,downloaded:bool}, top_blocked:[10×{domain,count}], top_queried:[10×{domain,count}], connect:{targets:[string],port:int}}` | Polled every 5 s. `last_24h`/`active_clients` read `query_stats_hourly`; `top_*` scan `query_log` once per 60 s (memoized); `connect.targets` = `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` else `hostname -I`. Also `ai:{state, applying, applied_block, applied_allow}`, from memory alone (atomics and the live `AiList`'s O(1) counts) |
| 4 | POST | `/api/v1/runtime/pause` | `{minutes:u32}` (1..=1440) | `{paused_until}` | AtomicU64 + `settings.pause_until`; survives restart |
| 5 | POST | `/api/v1/runtime/resume` | — | `{paused_until:null}` | |
| 6 | GET | `/api/v1/queries` | `?limit=200(max 1000)&before=<id>&client=<ip>&unnamed=true&blocked=true\|false&q=<substr>` | `{rows:[{id,ts,client,device_id\|null,device_name\|null,domain,qtype,blocked,reason,list\|null}], next_before:int\|null, logging:bool}` | Keyset newest-first; LEFT JOIN devices ON ip_address = client so renames relabel history; `logging=false` when HISTORY_DAYS=0 |
| 7 | DELETE | `/api/v1/queries` | — | `{deleted:int}` | Clear log (rollups kept). Also forgets the AI list's browsing history (§3a): every verdict's website, every ordinary `ignore` row, and the reviewer's in-memory site data. Its blocks and allows stay. Unguarded, as before |
| 8 | GET | `/api/v1/events/stream` | — | SSE, event `query`: `{ts,client,deviceName,domain,qtype,blocked,reason,list}` | 32-subscriber cap and shutdown `take_until` kept; only `query` frames |
| 9 | GET | `/api/v1/devices` | — | `{devices:[{id,name,ip_address,filtering,all_lists,lists:[source_id],rules:[{id,domain,action}],queries_24h,blocked_24h,last_seen_at\|null}], unnamed_clients:[{ip,queries_24h,blocked_24h,last_seen_at}]}` | counts from `query_stats_hourly`; unnamed = clients in rollups with no devices row |
| 10 | POST | `/api/v1/devices` | `{name,ip_address,filtering?=true,all_lists?=true,lists?=[source_id]}` | device | `ip_address` must parse as `IpAddr` (400); duplicate IP 409; rebuilds scopes |
| 11 | PUT | `/api/v1/devices/{id}` | same body | device | rename / re-address / change lists; rebuilds scopes |
| 12 | DELETE | `/api/v1/devices/{id}` | — | `{deleted:true}` | cascades device_lists + device rules |
| 13 | GET | `/api/v1/rules` | `?device_id=<id>` optional | `[{id,domain,action,device_id\|null,device_name\|null,created_at}]` | |
| 14 | POST | `/api/v1/rules` | `{domain,action:"allow"\|"block",device_id?}` | rule | domain normalized; must match `^[a-z0-9_-]+(\.[a-z0-9_-]+)+$` — the underscore because `_dns.resolver.arpa` and `_dmarc.x` reach the query log and a name Activity shows must be one you can rule on; the same predicate gates route 21, so `/check` cannot answer about a string `/rules` refuses; upsert on (domain, device_id); rebuild |
| 15 | DELETE | `/api/v1/rules/{id}` | — | `{deleted:true}` | |
| 16 | GET | `/api/v1/lists` | — | `{lists:[{id,name,url,kind,enabled,rule_count,last_ok_at,last_fetched_at,last_error,note,due}], presets:[{name,url,kind}]}` | |
| 17 | POST | `/api/v1/lists` | `{name,url,kind:"hosts"\|"domains"\|"adblock",enabled?=true}` | `{list, outcome:"updated"\|"unchanged"\|"rejected"\|"failed", note}` | URL must be http(s) or data:; 409 if it would be the 65th enabled; fetch + rebuild immediately |
| 18 | PUT | `/api/v1/lists/{id}` | `{name?,url?,kind?,enabled?}` | list | url/kind change → refetch; enabled toggle → rebuild from cache only |
| 19 | DELETE | `/api/v1/lists/{id}` | — | `{deleted:true}` | removes body file, device_lists rows; rebuild |
| 20 | POST | `/api/v1/lists/refresh` | `{id?}` | `[{id,name,outcome,rule_count,note}]` | 429 within 30 s of the previous manual refresh |
| 21 | GET | `/api/v1/check` | `?domain=&client=<ip optional>` | `{domain, verdict:"allow"\|"block", reason, list\|null, scope:"household"\|"device"\|"unfiltered"\|"paused", device_name\|null, ai:{verdict, why, choice, confidence, effect, effect_confidence, lists, site, conflict_site, model, judged_at, applied}\|null}` | runs `evaluate` on the live `Policy` — the "Why?" answer. `ai` is the AI list's row whenever one exists, whether it decided, was outranked or fell below its bar; `applied` is read from the live policy. If the AI list decided but the row was just forgotten, every field but `verdict` and `applied` is null: provenance is never invented |
| 22 | GET | `/api/v1/settings` | — | `{version, upstreams:[{spec,protocol,encrypted}], block_mode, http_bind, dns_udp_bind, dns_tcp_bind, advertised_targets, advertised_port, refresh_interval_secs, retention:{history_days,max_rows,prune_interval_secs}, db_path, db_size_bytes, lists_dir, protected_suffixes:[21], schema_version, ai:{available, unavailable_reason, enabled, key_source, model, daily_limit_usd, zero_retention, base_url, sends_to}}` | read-only; config is env-only by design, and AI review, the one feature set up in the UI, is set up on Lists |
| 23 | GET | `/api/v1/ai` | — | `{available, unavailable_reason:null\|"operator_off"\|"history_off", enabled, state, key:{source:"none"\|"saved"\|"environment", limit_usd, limit_remaining_usd, checked_at}, model:{id,name,prompt_usd_per_million}\|null, daily_limit_usd, today:{spent_usd,requests,overrides,resets_at}, verdicts:{block,allow,ignore,applied_block,applied_allow}, queue:{waiting,dropped}, zero_retention, sends_to, last_review_at, last_error}` | AI review's status. `state` is one of `unavailable off no_key reviewing paused_budget retrying key_refused out_of_credit model_refused stopped`. Never any part of the key, and no `label` (OpenRouter's label is a masked copy of the key). `last_error` is one of a fixed set of sentences |
| 24 | PUT | `/api/v1/ai` | `{enabled?, model?, key?:string\|null, daily_limit_usd?:0.05\|0.1\|0.25\|1}` | the route 23 status | **Guarded.** For `key`, absent keeps it, `null` removes it, a string replaces it after `GET {base}/api/v1/key` accepts it. Validates everything before saving anything; turning on runs a Test unless the same key and model passed one in the last 10 min; a withdrawal of consent closes the send gate before anything is written. 409 while unavailable (except a body that only removes the key), and for a body with `key` while the key is set in the environment |
| 25 | GET | `/api/v1/ai/models` | — | `{fetched_at, zero_retention_required, models:[{id,name,description,context_length,prompt_usd_per_million,usd_per_thousand_names,zero_retention,tested}]}` | **Guarded** (it makes the appliance fetch). OpenRouter's decision models, with and without `&zdr=true`, fetched without the key, 1 MiB cap each, cached 1 h, sorted by price. 409 while unavailable; 503 when the listing cannot be fetched |
| 26 | POST | `/api/v1/ai/test` | `{model?, key?}` or no body | `{ok, model, provider, latency_ms, cost_usd, answer:{website,candidate,choice,confidence,effect,effect_confidence}, sentence}` | **Guarded.** One request about a fixed public example (`www.wikipedia.org` loading `www.googletagmanager.com`), no household data. One every 10 s (429). A pass needs a role answer with a confidence. Its spend counts toward today's |
| 27 | GET | `/api/v1/ai/verdicts` | `?view=changes\|all&verdict=block\|allow\|ignore&q=&limit=200(max 500)` | `{total, counts:{block,allow,ignore}, rows:[{domain,verdict,why,choice,confidence,effect,effect_confidence,lists,lists_now,applied,not_applied,outranked_by,site,conflict_site,model,judged_at,review_after}]}` | The AI list, newest judgement first, each row read against the live policy. `Cache-Control: no-store`. Unguarded and unauthenticated, like the query log |
| 28 | DELETE | `/api/v1/ai/verdicts` | — | `{deleted:int}` | **Guarded.** Clear the AI list and rebuild before answering. Review is not halted |
| 29 | DELETE | `/api/v1/ai/verdicts/{domain}` | — | `{deleted:true}` | **Guarded.** Forget one name (400 if not a domain, 404 if no row) and rebuild before answering; it is judged again the next time a website loads it while review is on |

Removed route names that scripts reference: `/api/v1/dashboard` →
`/api/v1/overview`; `/api/v1/resolver-access` → `overview.connect`;
`/api/v1/runtime` → `overview.runtime`; `/metrics` gone; block-profiles marker →
device marker.

### 3a AI review (routes 23–29; [ADR 0002](adr/0002-ai-review-tier.md))
The record of the decision, its thresholds and caps, and exactly what leaves
the house is ADR 0002. What the API is held to:

- **The guard.** Routes 24, 25, 26, 28 and 29 answer 400 "Change AI review
  from Cogwheel's own address or a local name. Behind a reverse proxy, add its
  name to COGWHEEL_SERVER__ALLOWED_HOSTS." unless all three hold: every name
  the request was addressed to (the `Host` header and the URI authority, each
  when present) is an IP literal, `localhost`, a single label, ends in `.local`,
  `.lan`, `.home`, `.home.arpa`, `.internal` or `.localdomain`, or is in
  `COGWHEEL_SERVER__ALLOWED_HOSTS`; an `Origin`, if sent, is the same
  `host[:port]`, an allowed name, or loopback on both sides (`Origin: null` is
  refused); and `Sec-Fetch-Site`, if sent, is `same-origin`, `same-site` or
  `none`. Routes 24 and 26 read their bodies through an extractor that never
  logs a rejection, because serde's text can quote the key. Read-only routes
  (23, 27) and Clear log (7) stay unguarded.
- **The key.** Never returned, logged or stored in SQLite; it lives in
  `openrouter.key` beside the database, mode 0600.
  `COGWHEEL_AI__OPENROUTER_API_KEY` wins over a saved key, and the API then
  cannot change it. `COGWHEEL_AI__BASE_URL` is environment-only, so nobody on
  the network can point the bearer key somewhere else. The OpenRouter client
  is AI review's own: 20 s timeout, 5 s connect, no redirects followed.
- **Off means off, at once.** A PUT that turns review off, removes the key, or
  changes the key or model closes the send gate before it answers: queued and
  grouped names are discarded and requests in flight are cancelled. No request
  starts after that answer.
- **The tap.** The query-log writer offers each batch to the reviewer through a
  bounded channel (4,096) with `try_send`; a full channel drops and counts. Only
  A, AAAA and HTTPS lookups that a list, the AI list or nothing decided are
  offered — never a rule's name, a protected one, a paused or unfiltered
  device's, or a CNAME-decided one. While review is off the writer pays one
  atomic load per batch.
- **What is sent.** One Decisions request (`POST {base}/api/alpha/decisions`)
  per judged name: the website the load is taken to be for, the candidate and
  up to 24 other names from the same load, as JSON values in `state`, with
  constant question text and `provider.data_collection: "deny"` (plus
  `zdr: true` unless `COGWHEEL_AI__ZERO_RETENTION=false`, and, when the
  model's price is known, a ceiling of 1.25× it). Never client addresses,
  device names, query types, timestamps, or a name that fails the shareable
  check (ADR 0002).
- **Bounds.** 2 requests in flight, 1 s apart, 2,000 a UTC day, within the
  daily spend limit (5¢, 10¢, 25¢ or $1); at most 24 names per site load, 60
  per site key per day and 300 per client per hour; a queue of 1,024 that drops
  its oldest; 10,000 verdict rows.
- **Retention.** The website a verdict was judged for is set to NULL after
  `HISTORY_DAYS`; an ordinary `ignore` row lives `min(30 days, HISTORY_DAYS)`;
  a block, allow or contested row lives at most 90 days; the table is capped at
  10,000 rows, oldest first. The prune (hourly by default) enforces all four. Clear log
  (route 7) NULLs every website, deletes every ordinary `ignore` row and empties
  the reviewer's in-memory site data. `HISTORY_DAYS=0` makes AI review
  unavailable and empties the AI list at startup.
- **Consent.** Whenever AI review is unavailable at startup
  (`COGWHEEL_AI__AVAILABLE=false` or `HISTORY_DAYS=0`) the `ai_enabled` key is
  deleted, so it never resumes without a fresh Turn on.

---

## 4 UI pages

Shell: reuse the approved Shark UI shell — `AppLayout` with `AppSidebar` (one
`<nav aria-label="Main">` of five entries with no group label, inside an
`<aside>`; the "Appliance" group, `SidebarSeparator` and `SECONDARY_NAV`
removed). Under the nav, `ProtectionPanel`: the protection status line with the
enabled-list count, then "Pause for" 5 / 15 / 60 min, each confirmed through
`ConfirmDialog`; while paused, a yellow-tinted block with the countdown and
"Resume protection" (not confirmed). On the icon rail the mark tile carries a
status dot and one button resumes, or opens the three durations. The footer
keeps `ThemeToggle`. The top bar (`<header>`, holding `StaleBanner`) shows
`ProtectionChip` — "Paused · 12:31 left" plus Resume — whenever the sidebar is
collapsed or a phone drawer and the state is not Protected. One verb
throughout: the answer, the panel, the chip, the toast and route 4 all call it
pausing. `PageShell/PageHeader/PageSections`, `SectionCard` (24 px gutters, no
accent strips, title rendered as an `h2`), `StatTile`, `DataTable` (with the
container-query `hideBelow`/`stackBelow`; when rows open, the primary cell is a
real `<button>`; `NarrowRow` for the stacked form), `ConfirmDialog`,
`TextField/SelectField/FieldRow`, `StatusPill`/`StatusChip`, `IconButton`,
`EmptyState/ErrorState/LoadingSkeleton/NoticeBanner`, `StaleBanner`, `Toaster`,
`ErrorBoundary`. ⌘1–⌘5 on Apple platforms only — off the Mac Ctrl/Alt + digit
are the browser's tab shortcuts, so nothing is bound and no hint is printed —
and `/` focus-search; the shortcuts dialog and its `?` handler are deleted.
Black/white neutrals, red/green/yellow-400 status only (the five `--chart-*`
tokens are deleted). `nav.ts`: five `PRIMARY_NAV` entries (Overview `/`,
Activity `/activity`, Devices `/devices`, Lists `/lists`, Settings `/settings`).

Data provider: snapshot = `{overview, settings, lists, devices, rules}`, held in
an external store and read per field (`useSnapshot(field)`), so a poll that
changes `overview` re-renders only its readers and an identical response writes
nothing; `FULL_LOADERS` = all five; `LIVE_FIELDS` = `overview` only (5 s,
visible tab); localStorage cache keys kept; `mutate()` unchanged.

### `/` Overview
- Counts render in one format everywhere in the product: grouped digits from
  `formatCount`, never abbreviated. A tile does not shorten what a sentence
  spells out.
- First, the answer: an `h2` with a status dot, one supporting sentence and at
  most one action, in this order of precedence — "Cogwheel is not answering"
  with "Try again" (red tint); "Protection is paused · mm:ss left" with "Resume
  protection" (yellow tint); "Lookups are failing" with "See the upstream"
  (red tint; `upstream_failures_total` rose by at least 3 and by at least half
  of the cache misses over the last minute of polls); "No blocklists yet" / "Every blocklist is switched off" with
  "Go to Lists"; "Your blocklists have not downloaded yet" with "Refresh
  lists" (`list-refresh-all`, the Lists key); "Cogwheel is ready · no device is
  using it yet" (neutral); "Your household is protected · N blocked in the last
  24 hours" (green) with "Every device using Cogwheel is filtered except
  <unfiltered devices>." read from `devices`. No page-level Refresh lists; no
  page description.
- When `last_24h.queries = 0`: the answer, "Connect your devices", then one line
  standing in for the chart and the top names. When nothing has ever loaded
  (no answer, no cache): the answer alone.
- StatTile row (4, container queries: 1 / 2 from 18rem / 4 from 48rem):
  **Queries (24 h)** with hint "N since this process started" (suppressed at
  zero and when it equals the 24-hour count), **Blocked (24 h)** with "% of
  queries", **Devices seen (24 h)** value = `active_clients`, delta "N named · M
  unnamed" (link to /devices), **Blocklists** (enabled, or "n of m on"; "N rules
  loaded"; "Updated <relative>" / "Not downloaded yet").
- SectionCard "Queries by hour": 24 bars of plain `div`s from `per_hour` —
  blocked stacked in neutral-900 / dark neutral-100 over answered in
  neutral-300 / dark neutral-600; no library — in a `<figure>` whose sr-only
  caption is the busiest hour and the day's share blocked. The strip is one
  `role="slider"` over the hours (arrows, PageUp/PageDown by 6, Home/End; hover
  or drag to read); a readout above it prints the hovered or selected hour, else
  the busiest. Axis labels every 6 h in the reader's clock convention.
- SectionCard "Top blocked" / "Top queried" side by side from 56rem of
  container, 10 rows, mono domain (wrapping before a dot) + count; row action
  menu: "Allow for everyone" / "Block for everyone" → POST /rules; "Why?" →
  GET /check for the household, then for each filtering device whose rules
  cover the name, and (when the household blocks it) each device on a narrower
  set of lists; answered inline in a `NoticeBanner` with "Show in Activity"
  (`/activity?q=<domain>`, plus `&verdict=blocked` from Top blocked). Each
  card's ten row menus are one tab stop, as on Activity.
  For Top blocked a name every scope now allows also gets its last block from
  the log. A cleared or disabled log with traffic replaces both cards with one
  line saying which.
- SectionCard "Connect your devices": one row per `connect.targets` in 18 px
  mono with "IPv4 · port 53" / "IPv6 · port 53" under it and a copy
  `IconButton`; the three platform hints as a hairline-divided list.

### `/activity` Activity
- Filter bar: search `TextField` "Domain contains" (the `/` target), Device
  select (All devices / each named device / Unnamed devices), Verdict segment
  (All / Blocked / Allowed). Below `sm`, Device and Verdict fold behind a
  "Filters" disclosure that counts the active ones. The three are in the URL
  (`?q=`, `?verdict=`, `?client=<ip>|unnamed`), read on open and kept in step
  with `replace`.
- Live line above the list, fixed height: the **Live** switch, the stream's
  state in words (connecting / connected / holding / reconnecting / paused) and
  "Show N new". The stream (SSE, frames batched every 250 ms) stays connected
  while the screen is open; Live off holds every arriving row instead of
  closing it. Rows are also held — not prepended — while keyboard focus or an
  open row menu is in the list, a moving mouse is over it (lapses after 15 s
  still), the newest row is scrolled out of sight, or the tab is hidden. Up to
  500 are held and the rest counted; on release past that, with logging on, the
  first page is re-read. An sr-only polite line reports the count every 20 s.
- One `DataTable`: Time, Domain (mono), Device (name, else IP with a muted
  "unnamed" tag), Verdict (`StatusPill` "Blocked" = bad; "Allowed" as a plain
  muted word, because colour marks the exception) + reason text ("oisd small",
  "device rule", "household rule", "protected", "CNAME → x", "paused",
  "unfiltered"), and an actions column. Row menu, grouped by scope with a rule
  between groups: Allow/Block for everyone | Allow/Block on <device>, or Name
  this device… (unnamed → Devices with `?ip=`) | Why?. The fifty row menus are one tab stop with a roving tabindex (arrows,
  PageUp/PageDown by 10, Home/End).
- Below 768 px of card (`stackBelow="3xl"`) each row is a `NarrowRow`: the
  domain alone on the first line, then the verdict **as a word** with its
  reason, the device and the clock time — one line from 320 px of row text, the
  verdict and reason on their own line below that. The verdict is never a bare
  dot. When `logging=false`: NoticeBanner "Query logging is off", naming
  COGWHEEL_RETENTION__HISTORY_DAYS; only the live stream is shown.
- Footer: "Show 50 more" while more are loaded than drawn, "Load older than
  <clock time of the oldest loaded row>" (keyset `before`; "No older rows" when
  the cursor is spent), "Showing N of M loaded rows", and "Clear log" at the far
  end, last in the tab order (ConfirmDialog → DELETE /queries).
- Empty states distinguish filtered ("No queries match these filters", Clear
  filters), just cleared, logging off, a log emptied before this visit, and
  first run.
- History loads from GET /queries on mount and on a filter change (debounced
  250 ms); Clear empties the list rather than re-reading it. Live frames are
  deduplicated by (ts, client, domain) against the log rows among the top 50,
  and live rows the writer has not flushed yet survive a filter change.

### `/devices` Devices
- SectionCard **Named devices**, full width, header action "Add device" (a
  disclosure for the form): table Name (the row's button, "Edit <name>"), IP,
  Filtering (a `Status` dot plus a word — On with the neutral dot; Off, or
  No lists when filtering is on but no chosen list is enabled, with the yellow
  dot), Lists ("All" / "n of m" / "None"), Rules (count), Queries / Blocked
  (24 h), Last seen. It sheds columns on its own container width, not the
  viewport's — Rules first, then Lists and Last seen together — and below `md`
  becomes a purpose-built `NarrowRow`: name and IP, then filtering state, list
  selection, rule count and the 24-hour counts, with no card border inside the
  section card's own.
- **Form card** below it ("Add device" / "Edit <name>"), a real `<form>` with
  inline errors: Name, IP address (validated; malformed only once the field is
  left; an address already used names its device), **Filtering** switch ("Off:
  this device resolves everything and is still logged"), **Lists**: radio "Use
  all household lists" / "Choose lists" → checkbox per enabled list (nothing
  ticked is refused inline) / "No lists" ("Only rules apply. Nothing on a list
  is blocked for this device."; while the AI list is applying, "Only your rules
  and the AI list apply. Nothing on a subscribed list is blocked for this
  device.", because the AI list is household-wide and reaches a device on no
  lists too), **Rules for this device**: domain +
  Block/Allow segment + "Add rule", staged until Save — each marked New,
  Changed or Removed (struck through, with Undo). Footer: Save / Add device,
  Cancel, and Delete device at the far end (ConfirmDialog naming what the
  address falls back to). `?device=<id>` and `?ip=<address>` open the form.
- SectionCard **Unnamed devices**: table Address, Queries / Blocked (24 h),
  Last seen, "Name this device" → prefills the form (`?ip=` also honoured).

### `/lists` Lists
- Page header action "Refresh all" with a `title` naming its cost ("Takes up to
  a minute"); the card's busy rule shows while it runs.
- SectionCard **Subscribed lists** (description "N of M enabled · N rules
  loaded", header action "Add a list"): table Name (with the URL under it, and a
  failed download or a note such as "contains 2 protected names (ignored)" as
  words under that), Format badge ("Adblock-style" / "Hosts file" / "Domain
  list"), Enabled `Switch` (turning off a list some device uses alone asks
  first, naming the device), Rules loaded, Last updated, and a Refresh
  `IconButton` + "⋯" (Delete list…). Below `xl` a `NarrowRow`: name, switch and
  "⋯" (Refresh now, Delete list…), then format, rule count and freshness.
- SectionCard **Add a list** (opened from the header): three radio choices by
  strength — Light = oisd small, Balanced = HaGeZi Pro, Strict = HaGeZi Pro++,
  resolved by name against the §2.5 catalogue — each with its one-line
  trade-off; a subscribed tier is disabled; a fourth choice, "More lists", holds
  the Preset select (every §2.5 preset) and Name, Address, **Format** select
  (hosts / domains / adblock) and Enabled switch. The submit button names what
  it adds ("Add HaGeZi Pro").
- SectionCard **AI list** (ADR 0002), between Add a list and Rules because
  that is where it sits in precedence. Unavailable (`operator_off` /
  `history_off`): a neutral `NoticeBanner` naming the variable, and only
  "Remove key…" when a key is saved. Never set up: what AI review does, a warn
  `NoticeBanner` "Domain names leave your network while this is on", and "Set up
  AI review", which opens the set-up `<form>`: OpenRouter key (`type="password"`,
  never shown again; a saved key reads "Saved key · $x of its $y limit left",
  never any part of the key; an environment key reads "Set by
  COGWHEEL_AI__OPENROUTER_API_KEY" with no controls), Model (a native select
  from route 25, priced per 1,000 names; models with no zero-retention provider
  greyed out while that is required), Daily spending limit (5¢ / 10¢ / 25¢ /
  $1), Test, and "Turn on AI review…", which confirms through a
  `ConfirmDialog` that names what is sent and who pays. Set up: a header
  `Switch` "AI review" (optimistic, rolled back with the API's sentence) and a
  "⋯" (Change set-up, Test now, Forget every verdict…); the description is a
  status line, a dot and words ("On · judged N names today · $x of $y", "Daily
  limit reached · resumes at <time>", "Stopped · OpenRouter refused the key",
  …); a summary of what DNS is using ("Blocking N · allowing N over your lists ·
  N left to your lists"); the verdict table — a `SegmentGroup` of Changes and
  All judged, a "Find a name" search, and columns Name (with "for <website>"),
  Verdict ("Block", "Allow", or "Lists decide" with no fourth hue), Model's
  confidence, Your lists and Judged, with a row menu of Allow/Block for everyone,
  Forget this verdict and Why?; and a footer that says exact names only, the
  precedence, and when a name is judged again, with "Clear AI list…". A
  confidence is always the model's, never Cogwheel's. The key never enters the
  snapshot, `localStorage` or an optimistic patch.
- SectionCard **Rules**: `h3` "Household rules" — domain + Block/Allow segment
  + "Add rule" form and a list with delete — and `h3` "Device rules", read-only,
  grouped by device, each group linking to `/devices?device=<id>`; footnote
  "Allow beats block. A domain covers its subdomains."
- SectionCard **Check a domain** (`role="search"`, the `/` target): domain input
  + "As device" select ("The household" or a device) → verdict + reason inline
  behind a red or green status dot.

### `/settings` Settings (read-only)
- "Resolver": upstream rows with a `StatusPill` for the protocol — UDP "warn"
  (plus a "cleartext" `NoticeBanner` at the top of the card), DoT / DoH
  "good" — block response mode, bind addresses, advertised targets + port;
  "Show the variable names" discloses the env var name under each value in mono;
  footnote "Set via COGWHEEL_* in /etc/cogwheel/.env — the installer and Compose
  both read it — or /etc/cogwheel/cogwheel.env for a native systemd install.
  Restart afterwards." (`.env` is the Compose deployment's file and the one
  scripts/install.sh writes; `cogwheel.env` belongs to
  scripts/install-native.sh alone.)
- "Activity log": logging on/off, retention days, max rows, prune interval,
  database path and size, lists dir; "Clear log" button. Once AI review has been
  set up, its `ConfirmDialog` adds that the AI list forgets which websites its
  verdicts were judged for and the names it left to your lists.
- "AI review" (read-only, like the rest of the page): status, model, key
  ("Set in the environment" / "Saved on this appliance" / "None"), daily limit,
  providers ("Zero data retention only" / "Any that do not collect data") and
  where it sends, with the `COGWHEEL_AI__*` names under "Show the variable
  names" and a footer pointing to Lists, where it is set up. It is the one
  feature set up in the UI rather than the environment, and Settings still
  changes nothing.
- "Protected domains": the 21 suffixes behind "Show the list", with one
  sentence explaining they outrank lists and the AI list but not your own
  rules.
- "About": version, schema version. The theme toggle lives in the sidebar only.
- Before the first answer, a skeleton; if settings never load, "Could not read
  the settings" with Try again, never placeholder values.

---

## 5 Hot path

### 5.1 Data structures (`cogwheel-dns-core`)
```rust
pub struct DnsRuntime {
    resolver: TokioResolver,
    policy: RwLock<Arc<Policy>>,
    pause_until: AtomicU64,
    cache: WireCache,                              // max 10_000, ttl 24 h = STALE ceiling
    cache_epoch: AtomicU64,                        // bumped by every policy swap
    miss_permits: Arc<Semaphore>,                  // 512
    log_tx: mpsc::Sender<LogEntry>,                // bounded 8_192, try_send
    stats: DnsRuntimeStats,
}
pub struct CacheKey { scope: u32, qtype: u16, domain: Arc<str> }
pub struct CachedWire { bytes: Box<[u8]>, truncated: Option<Box<[u8]>>, fresh_until: Instant, stale_until: Instant, blocked: bool, verdict: Verdict }
pub struct LogEntry { ts: u32, client: IpAddr, domain: Arc<str>, qtype: u16, verdict: Verdict, list: Option<Arc<str>> }
```
There is no `block_mode` on the runtime: it reads `policy.block_mode`, so the
mode a name is blocked with cannot drift from the policy that blocked it.
`cache_epoch` lets a miss decided under a policy that has since been swapped out
tell that its answer came back too late to cache. `CachedWire` carries
`stale_until` as well as `fresh_until` because the 24 h ceiling is fixed when the
upstream last confirmed the answer; serving it stale through an outage must not
push that ceiling further out. `LogEntry` carries the resolved list name rather
than the slot, because slots are positions in the enabled-list order and a
toggle renumbers every slot above it while rows are still in the flush window.

Not `moka`: `WireCache` is a hand-rolled `HashMap` + insertion-order `VecDeque`
sharded 16 ways behind independent `RwLock`s. Every entry already carries its
own `fresh_until`/stale ceiling, so an LRU's recency tracking buys nothing an
eviction order does not already have, and a plain shard is cheaper to probe
inline on the receive loop than a concurrent cache with its own maintenance
thread. `invalidate_all()` walks all 16 shards and clears each.

Stats: queries_total, cache_hits_total, cache_expired_total, blocked_total,
upstream_failures_total, stale_served_total, cname_blocks_total, dropped_total,
log_dropped_total, hit/miss latency totals+samples.

### 5.2 UDP datagram → response
0. **Listener**: one `Arc<UdpSocket>`, `W = min(available_parallelism, 4)`
   receive loops, each owning a `[u8; 4096]` buffer.
1. **Parse** (hickory): `domain: Arc<str>` from `Name::to_ascii()` (keeps
   `xn--`), `qtype`, `edns_max` (512 when no OPT).
2. **Scope**: one RwLock read, zero allocations. Pause → `SCOPE_UNFILTERED`;
   else `policy.by_ip.get(&peer.ip())` else `SCOPE_HOUSEHOLD`; a device scope
   with `filtering == false` maps to `SCOPE_UNFILTERED`.
3. **Cache probe**: HIT → counters (including `blocked_total` when
   `entry.blocked`), send, `log_tx.try_send`, return — **inline in the receive
   loop, no permit, no spawn**.
4. **Miss hand-off**: `try_acquire_owned` on `miss_permits`; none →
   `dropped_total += 1`, SERVFAIL. Else `tokio::spawn(handle_miss(...))`.
5. **Evaluate** (sync, allocation-free).
6. **Blocked**: `build_blocked_response` → `to_vec()` → `CachedWire{fresh_until:
   now + 300 s, blocked: true}`.
7. **Upstream**: unless the verdict was an explicit allow — a rule, a
   protected suffix or a list exception — walk `lookup.answers()` for
   `RData::CNAME` targets (≤ 8) and run `evaluate_lists` on each — zero extra
   RTT. The gate is `Verdict::rechecks_aliases()`: `Allow(NoMatch)` and
   `Allow(Ai)`. An AI-list allow is still re-checked, because the model judged
   the name, not where it points.
8. **Upstream failure**: serve the stale entry if present (`stale_served += 1`),
   re-freshened for 30 s; else SERVFAIL.
9. **Insert + send + log**: `truncated` precomputed only when `bytes.len() >
   512`; send = memcpy + 2-byte id patch + RD bit.

A policy swap bumps a cache epoch so a miss already in flight cannot insert a
verdict from the replaced policy. `swap_policy_invalidating` (§1.3) bumps it
too, before its sweep, so the same holds for an AI list install.

### 5.3 Pause
`pause_protection_until(secs)` stores the AtomicU64 and the server persists
`settings.pause_until`; on boot the server reloads it (an expired value is
ignored). Pause needs no invalidation: paused clients read scope 1.

---

## 6 Per-device model

Data: `devices(id, name, ip_address, filtering, all_lists)` +
`device_lists(device_id, source_id)` + `rules(domain, action, device_id
NULL|id)`. Lists: `sources` rows; the enabled ones get slot bits 0..63 in `id`
order (max 64 enabled, 409 on the 65th).

Build (`policy_build.rs`, on spawn_blocking, after any list refresh, list
toggle, device or rule edit, or AI list change):
1. `index` = `ListIndex::build` from every enabled source's cached body (reused
   as the same `Arc` when only devices/rules changed).
2. `all_mask` = OR of enabled slots; `household: RuleSet` from
   `rules WHERE device_id IS NULL`.
3. Per device: `mask` = `all_mask` if `all_lists` else OR of the slots of its
   `device_lists` rows that are enabled; `rules` = its own rows;
   `sig = (filtering, mask, sorted rules)`.
4. Scope interning: `ScopeAllocator { by_sig: HashMap<Sig, u32>, next: u32 }`
   lives in `ServerState` and persists across rebuilds.
   `sig == (true, all_mask, [])` → `SCOPE_HOUSEHOLD (0)`; `filtering == false` →
   `SCOPE_UNFILTERED (1)`; otherwise `by_sig.entry(sig).or_insert_with(next++)`.
   A device edit produces a new sig → a fresh id, and its old cache entries age
   out (no `invalidate_all`). A list rebuild or a household-rule change calls
   `cache.invalidate_all()` and clears `by_sig`.
5. The AI list (ADR 0002): while AI review is applying (available and turned
   on), every build reads `ai_verdicts` and compiles it against the live index
   and `all_mask` — a block where no household list decides the name needs the
   model's confidence ≥ 0.85; a block over a list `@@` or an allow over a list
   block needs ≥ 0.92 on the role question and ≥ 0.90 on the effect question
   in the matching direction; a block the lists already make, an allow with
   nothing to override, an allow over a list exception, an `ignore`, and a
   protected name are never compiled. Otherwise the AI list is empty. It is
   judged against the household's lists, not each device's.
6. `Policy` is swapped into `DnsRuntime.policy`; the querylog task receives a
   fresh `Arc<HashMap<IpAddr, (Arc<str> name, String id)>>` for SSE attribution.
   A fourth rebuild kind, `Ai`, reuses the index and keeps the cache; it and the
   device kind compare the AI list in force with the new one and drop only the
   cached answers for the names that changed
   (`swap_policy_invalidating`). The reviewer never builds a policy: it commits
   verdicts and wakes an installer task that rebuilds after 5 s, so a burst of
   answers is one install.

Resolution order for client IP C and name N (first match wins):
1. pause → allow (Paused) · 2. C has no device row → household scope ·
3. `filtering = 0` → allow (Unfiltered) · 4. device allow rule → allow ·
5. device block rule → block · 6. household allow rule → allow ·
7. household block rule → block · 8. protected suffix → allow ·
9. AI list, exact name → allow or block (Ai) · 10. list allow (`@@`) under
`mask` → allow · 11. list block under `mask` → block, attributed to
`trailing_zeros(bits & mask)` · 12. CNAME targets re-run 8, 10 and 11 → block
(Cname) — only when the query reached 13 or step 9 allowed it · 13. allow.

Rule matching is suffix-on-label-boundary; the AI list alone matches exact
names. The AI list is household-wide and applies in every filtered scope,
including a device on no lists; paused and unfiltered scopes never reach it.
`GET /check` runs `evaluate` (not `evaluate_lists`, which is the CNAME
re-check alone) and reports which step fired. Unnamed clients are discovered
from `query_stats_hourly`.

---

## 7 Query log

Writer (`querylog.rs`), one task, owns everything off the hot path:
- Drains `log_rx.recv_many(&mut batch, 1024)` with a 5 s tick (flush at 500 rows
  or 5 s, whichever first).
- For each entry: if `broadcast.receiver_count() > 0`, publishes
  `StreamQueryEvent` with `deviceName` resolved from its
  `Arc<HashMap<IpAddr,…>>` snapshot. Otherwise nothing is built.
- Every 5 s: one `spawn_blocking` transaction — prepared
  `INSERT INTO query_log` for each row (skipped entirely when
  `history_days == 0`) and
  `INSERT … ON CONFLICT(hour, client) DO UPDATE SET queries = queries + ?, blocked = blocked + ?, last_seen = max(last_seen, ?)`
  into `query_stats_hourly` for the touched `(hour, '')` and `(hour, client)`
  pairs (always written: counts are not browsing history). A SQLite error drops
  the batch with a WARN; DNS never waits on it.
- Channel full → entry dropped, `log_dropped_total += 1`.
- AI review's tap (ADR 0002, §3a): once per batch the writer reads
  `state.ai.tap()` — one atomic load, `None` unless review is running — and,
  when it is `Some`, offers each A/AAAA/HTTPS entry a list, the AI list or
  nothing decided as a `Seen { ts, client, domain: Arc<str>, blocked, reason }`
  with `try_send` into a 4,096-deep channel. A full channel drops and counts;
  the writer never waits on the reviewer, and dns-core is untouched.

Size: ~55 B/row on disk; a busy household (~10 qps, 0.9 M rows/day) hits the
250,000-row cap (~15–20 MB) long before 7 days; a quiet one keeps 7 days.
Rollups ≈ 15 KB/day, pruned at 90 days, so Overview/Devices counts outlive the
raw rows and never GROUP BY the log.

Prune (`prune.rs`, hourly, first tick immediate):
`DELETE FROM query_log WHERE ts < now - history_days*86400` (skipped when
history_days == 0); `DELETE FROM query_log WHERE id <= (SELECT id FROM query_log
ORDER BY id DESC LIMIT 1 OFFSET max_rows)`; `DELETE FROM query_stats_hourly
WHERE hour < now - 90*86400`. Then, when history_days > 0, the AI list:
`prune_ai_verdicts(now, history_days, 10_000)` deletes ordinary `ignore` rows
past `review_after` or older than `HISTORY_DAYS`, contested rows past
`review_after`, any row judged 90 days ago or more, and the oldest beyond
10,000 rows; every deleted name leaves the reviewer's memory too, and the AI
list is reinstalled if a decision went. `scrub_ai_sites(now -
history_days*86400)` then sets `site` and `conflict_site` to NULL on every row
judged before the cutoff. Each failure is logged at WARN and left for the next
pass.

Reads: GET /queries keyset; Overview `top_*` memoized 60 s. Lifetime counters
come from the runtime atomics, so a cleared log does not zero them. Restart:
24 h tiles survive (rollups); a crash loses ≤ 5 s of rows.

---

## 8 Config

Read by `apps/cogwheel-server/src/config.rs`. Unknown variables are ignored;
invalid values fail startup.

| Variable | Default | Notes |
|---|---|---|
| `COGWHEEL_PROFILE` | `home` | `dev` (127.0.0.1:30080 / :30053) or `home` (0.0.0.0:8080 / :5353). `smb` is accepted as an alias of `home`. |
| `COGWHEEL_SERVER__HTTP_BIND_ADDR` / `DNS_UDP_BIND_ADDR` / `DNS_TCP_BIND_ADDR` | per profile | unchanged |
| `COGWHEEL_SERVER__ADVERTISED_DNS_PORT` | bound DNS port | in AppConfig |
| `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` | empty → `hostname -I` | install.sh fills it in |
| `COGWHEEL_STORAGE__DATABASE_URL` | `sqlite://data/cogwheel.db` | `lists/` body cache lives beside it |
| `COGWHEEL_UPSTREAM__SERVERS` | `1.1.1.1:53,1.0.0.1:53` | udp / `tls://ip#name` / `https://ip#name/path` |
| `COGWHEEL_BLOCKING__MODE` | `null_ip` | `null_ip\|nxdomain\|nodata\|refused` |
| `COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS` | `86400` (dev `3600`) | floor 300; a failed list retries every 300 s |
| `COGWHEEL_RETENTION__HISTORY_DAYS` | `7` | days of `query_log`; **`0` = do not write the query log** (rollups still kept) |
| `COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS` | `250000` | hard row cap enforced by the prune |
| `COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS` | `3600` | floor 60 |
| `COGWHEEL_SERVER__ALLOWED_HOSTS` | empty | comma list of extra hostnames (no ports; lowercased) the guarded AI routes accept, e.g. a reverse proxy's name (§3a); also never sent to OpenRouter |
| `COGWHEEL_AI__AVAILABLE` | `true` | `false` is the operator's kill switch: the reviewer never starts, the AI list compiles empty, routes 24–26 answer 409, and `ai_enabled` is deleted at startup. `true/false`, `1/0`, `yes/no`, `on/off` |
| `COGWHEEL_AI__OPENROUTER_API_KEY` | unset | wins over a key saved in the UI, which then cannot change it. Empty counts as unset; a value that cannot be a header (a byte outside 0x21–0x7E, or over 512 characters) stops startup, printed as `(hidden)`. No `sk-or-` prefix check |
| `COGWHEEL_AI__BASE_URL` | `https://openrouter.ai` | environment-only, never settable through the API. `https://`, or `http://` to a loopback host; no path but `/`, no query, fragment or credentials. A bad value stops startup |
| `COGWHEEL_AI__ZERO_RETENTION` | `true` | sends `provider.zdr` with every request; `data_collection: "deny"` is sent either way. `false` admits decision models whose providers may retain the names |
| `COGWHEEL_WEB_DIST_DIR` | search path | unchanged |
| `RUST_LOG` | `info` | unchanged |

Removed: `COGWHEEL_RUNTIME_GUARD__*`. Installer/compose-only variables are
untouched.

---

## 9 Out of scope

These are refusals, not omissions. Each was considered and declined, and a
pull request that adds one needs to argue with this list first —
[ARCHITECTURE §1](ARCHITECTURE.md#1-scope-boundary--what-cogwheel-is-not) has the
reasoning at length.

- Machine-learning classification of domains **on the DNS path, or without an
  explicit opt-in**, and threat-intelligence feeds. A name is blocked because a
  list you subscribed to names it, because you wrote a rule, or — only after
  you turned on AI review — because a decision model judged that exact name off
  the request path and the verdict is a stored, visible, undoable row. That is
  the whole decision procedure, and it is why `GET /api/v1/check` can name the
  step that fired. [ADR 0002](adr/0002-ai-review-tier.md) is the one argued
  exception, and the place to argue with it.
- Multi-node sync, VPN and exit-node integration.
- Notifications, a backup API, soak-testing tooling, a metrics exporter.
  `GET /api/v1/overview` and `/health/*` are the operational surface; the data
  directory is the backup.
- Telemetry of any kind, including an update check. The appliance's only
  outbound connections are to the configured upstream resolver, to the
  blocklist URLs you subscribed to, and, only while AI review is on (or while
  someone uses its set-up form), OpenRouter.
- Intercepting HTTPS in order to defeat anti-adblock detection.

Classifier, reliability-budget and multi-node code all existed at one point and
were cut. The classifier that was cut is not back: ADR 0002 admits a narrower,
opt-in, auditable thing, and that ADR is where to argue with it. The rest are
not coming back under a different name: §9 is the boundary, not a backlog.

---

## 10 Performance decisions on the request path

Each row is a decision the request path is held to, and the finding it came
from. Undoing one needs a measurement, not an opinion.

| Finding | What the code does instead |
|---|---|
| HIGH serial UDP loop | ≤4 receive loops on `Arc<UdpSocket>`; hits inline; misses under a 512-permit semaphore |
| HIGH cache key omits qtype | `CacheKey{scope,qtype,domain}`; test AAAA-after-A |
| HIGH CNAME pre-lookup doubles RTT | targets read from `lookup.answers()` at zero RTT |
| HIGH linear Vec<Rule> scan | `ListIndex` exact/suffix HashMaps, ≤16 probes, zero allocation |
| MED Message clones on hit | wire bytes in `CachedWire`; hit = memcpy + id patch |
| MED ruleset hash String per query | scope is a `u32` |
| MED blocked cache hits uncounted | `blocked_total += 1` on a blocked hit |
| MED activity bookkeeping with zero subscribers | `LogEntry{IpAddr, Arc<str>}` via `try_send`; publish only when `receiver_count() > 0` |
| LOW two stacked caches | one cache with `fresh_until` + 24 h stale ceiling; hickory `cache_size: 0` |
| LOW device edit flushes the cache | scope interning |
| MED query log never persisted | `query_log` + `query_stats_hourly`, batched every 5 s |
| NEW correctness | TC truncation for non-EDNS UDP clients; A-label keying |
| NEW AI review needs its verdicts on the request path (ADR 0002) | compiled into `Policy` as an exact-name `AiList`: one branch on a miss while it is empty, one hash probe when not, nothing on a hit; a change drops only the changed names' cache entries, never the whole cache (§11.1 has the measurement) |

---

## 11 Gates

Everything in §1–§10 is implemented and shipped. Two gates keep it that way.

**The check gate** is `.github/workflows/ci.yml`, and the command list lives in
[CONTRIBUTING § The checks](../CONTRIBUTING.md#the-checks) rather than being
restated here. In summary: format, clippy with `-D warnings`, the workspace
tests, a locked release build, `cargo audit`, `cargo deny`, the web lint and
build, `shellcheck`, the Dockerfile check, an aarch64 cross-compile, and an
image job that proves the container refuses to start without
`CAP_NET_BIND_SERVICE`, serves DNS and the web UI, upgrades a v0 database in
place, and refuses a database from a newer Cogwheel with a message naming both
versions.

**The benchmark gate** is `scripts/bench/run.py`: the release binary on
`127.0.0.1:35353` / `:38080` with a real list (oisd small, ~56,000 Adblock
lines) served from a local `python3 -m http.server`, a loopback stub upstream,
then the query drivers. It records hit and blocked p50/p99, first-time blocked
miss, throughput, RSS, startup-to-ready and binary size. Any change to the DNS
request path is expected to come with its output — and with
[§12.3](#123-reading-the-first-time-blocked-miss-figure) read first, because the
harness's own floor is most of that number.

### 11.1 ADR 0002, before and after

ADR 0002 touches the request path in two places: one branch (an empty AI
list) or one hash probe (a non-empty one) in `evaluate` on a cache miss, and
the CNAME re-check gate. So it came with the benchmark, run three ways:
**before**, the `a49d021` tree it was built on; **after** with an empty AI
list; and **after** with 10,000 applied AI-list blocks, the table's cap.

Method, so the numbers can be disagreed with: both binaries built with
`cargo build --release --locked -p cogwheel-server` from clean exports of the
two commits, on 2026-10-08, on a shared 4-vCPU x86_64 sandbox; oisd small
fetched that day (57,661 lines); each configuration run three times as a whole
`scripts/bench/run.py` invocation, the three configurations interleaved, every
run passing every correctness check (`blocked_total` exact, AAAA-after-A, CNAME
cloak, hung upstream, blocked answers). The 10,000-name list was written
straight into a fresh v2 database before the run — 10,000 block rows at the
model's confidence 0.95 for names on no list, and `ai_enabled=1`, with no key,
so nothing was ever sent — and every policy install in those runs logged
`ai_applied=10000`. This host has egress, so in every run the seeded default
list also downloaded at boot: the RSS and timings below include a second copy
of oisd small and are comparable with each other, not with the §12 table, which
was taken by the method in §12.2. Each cell is the lowest and highest of the
three runs.

| | Before (`a49d021`) | After, empty AI list | After, 10,000-name AI list |
|---|---|---|---|
| Binary (stripped) | 11,099,384 B | 11,863,352 B | 11,863,352 B |
| Startup → ready | 34 – 49 ms | 25 – 47 ms | 68 – 96 ms |
| List toggle (rebuild from cache) | 74 – 93 ms | 84 – 118 ms | 109 – 149 ms |
| RSS after the lists load | 48.4 – 57.0 MB | 51.9 – 53.4 MB | 66.0 – 67.4 MB |
| Cache hit, server-internal (window) | 3.20 – 4.98 µs | 3.19 – 3.70 µs | 3.43 – 3.91 µs |
| Cache hit, client p50 | 72 – 96 µs | 80 – 86 µs | 79 – 91 µs |
| Blocked (cached), client p50 | 78 – 90 µs | 74 – 87 µs | 81 – 94 µs |
| First-time blocked miss, client p50 | 92 – 115 µs | 84 – 115 µs | 84 – 99 µs |
| Cold miss, client p50 | 370 – 502 µs | 304 – 483 µs | 411 – 464 µs |
| Throughput (4 × 25,000) | 35,642 – 42,744 QPS | 35,045 – 43,395 QPS | 38,642 – 40,536 QPS |
| Server CPU per query | 32.1 – 39.2 µs | 32.6 – 39.3 µs | 35.0 – 37.2 µs |
| Cache hit, `HISTORY_DAYS=0` run | 3.22 – 3.71 µs | 2.46 – 7.07 µs | 3.34 – 4.33 µs |
| Threads, steady state | 5 | 5 | — |

What that says, and does not:

- **On the request path, nothing that this harness can separate from its own
  noise.** Every latency and throughput range for the empty and the
  10,000-name AI list overlaps the before range; the first-time blocked miss,
  the one that pays the AI probe, reads 84 – 99 µs with 10,000 names against
  92 – 115 µs before. Per §12.3 the harness's floor is most of each number, so
  this rules out a large cost and cannot see a small one.
- **A full AI list costs at startup and in memory.** With 10,000 names, startup
  to ready is about 45 ms longer, a list toggle about 30 ms longer (every
  rebuild reads and compiles the stored verdicts), and RSS after the lists load
  is about 14 MB higher than with an empty list, comparing the averages of the
  three runs. That is more than the 5 MB ADR 0002 budgets for review being on,
  and this measurement had the list applying but review not running (no key,
  so no reviewer state beyond the `known` map). Taken apart since: every
  policy build read all 10,000 full rows (`list_ai_verdicts`), ignores
  included, and glibc kept what that churned; and `AiState::load` built the
  `known` map from the same rows at every boot, review on or not. Builds now
  read only the blocks and allows, five columns each (`list_ai_decisions`),
  and the `known` map is read only while review is on. Re-measured with oisd
  small, two runs each, RSS after three list toggles and 20 rule rebuilds
  (before → after): review off 38.8–39.6 → 25.9–28.6 MB; unavailable 40.8 →
  28.6–31.5; 10,000 ignores, on, 43.5–50.2 → 32.7–38.4; 10,000 blocks, on,
  42.9–49.9 → 38.3–49.6; an empty list 25.4–28.1 either way. The last case,
  a full list of decisions, is still over ADR 0002's 5 MB: every build
  compiles all of it, and the allocator keeps the churn. `malloc_trim(0)`
  after a large compile, or `MALLOC_ARENA_MAX` in the image, is the lever
  left (§12.2).
- **The binary grew by 763,968 B (6.9%)**, against the ≤ 14 MB target.
- **Threads are unchanged**: the reviewer and the installer are Tokio tasks.
  Counted as `ls /proc/<pid>/task | wc -l` after readiness, with no AI list.

---

## 12 What it measures

Two tables. The first is the shape of the tree, and every figure in it was
re-counted against the working tree; the commands are given so anyone can
disagree with a number rather than take it. The second is performance, which
needs a harness and a host named beside it to mean anything at all.

### Shape

`Before` is commit `85ef5a6`, the tree this was cut down from.

| Metric | Before | Now | Target |
|---|---|---|---|
| Rust LOC (excl. tests) | 19,512 in 10 members | **15,469 in 5**: the core 8,893, ADR 0002's own files 6,576 | core ≤ 9,100; ADR 0002 ≤ 6,900, argued up from 3,900 in [§12.1](#121-how-the-rust-loc-figure-is-counted); total ≤ 16,000 in 5 |
| Web LOC (`apps/cogwheel-web/src`) | 17,222 | **14,308** (13,906 TS/TSX + 402 CSS) | ≤ 8,000 — over by 6,308, see below |
| HTTP routes | 44 + 4 | **27 + 2** | 27 + 2 |
| Sidebar pages | 8 | **5** | 5 |
| Library crates + binary | 10 | **5** | 5 (+ web) |
| `Cargo.lock` packages | 326 | **222** | ≤ 245 |
| SQLite tables | 12 | **8** | 8 |
| Binary (x86_64, stripped) | 15,707,800 B | **11,863,352 B** | ≤ 14 MB |
| Threads, steady state | 6 | **5** | 5 |

```sh
find apps/cogwheel-web/src -type f | xargs wc -l | tail -1   # web LOC
grep -n '\.route(' apps/cogwheel-server/src/http.rs         # 21 calls, 29 routes
grep -c '{ to: "/' apps/cogwheel-web/src/lib/nav.ts        # sidebar pages
grep -c '^\[\[package\]\]' Cargo.lock                      # lock packages
cat crates/cogwheel-storage/src/schema_v*.sql | grep -c 'CREATE TABLE'   # 8
stat -c %s target/release/cogwheel-server                   # binary bytes
ls /proc/<pid>/task | wc -l                                 # threads, once ready
```

Rust LOC needs the counting rule in [§12.1](#121-how-the-rust-loc-figure-is-counted)
rather than a `wc -l`: a plain count of every `.rs` file under the five crates'
`src/` is 29,335, because it includes the test files and `#[cfg(test)]` modules
the rule excludes.

Two of those want a word rather than a number.

**Web LOC is 6,308 over its target**, counting everything under `src/`
(14,308 lines across 81 files: 13,906 TypeScript and TSX, 402 CSS). This row was
last recorded at 8,227 (227 over, across 59 files), and the tree had reached
12,538 across 78 files by `a49d021`, the commit ADR 0002 was built on, without
the row being restated; ADR 0002's UI is 1,770 of what remains (three new files
under `routes/lists/`, and glue in twelve existing ones). The target was set
against the whole directory, so the honest reading is that it is well over, and
nothing in this row argues it up. It is recorded here rather than quietly
recounted, because a target that moves to wherever the tree happens to be is a
row that can never fail.

**Threads is five in the steady state** — the main thread plus four Tokio
workers on a four-CPU host. A sixth appears transiently while a list is being
compiled on the blocking pool and goes away again, so a reading taken during
startup says six.

### Performance

Taken with `scripts/bench/run.py` on a **4-vCPU x86_64 sandbox**, not a Pi 5,
against oisd small (~56,000 Adblock lines). Treat them as relative reference
points between two versions of this code on the same host, which is what the
harness is for. **No Raspberry Pi 5 measurement exists yet**, and the `Before`
column was taken on a different day on the same class of machine.

| Metric | Before | Now | Target |
|---|---|---|---|
| Cache hit, server-internal | 4.651 µs | **1.4 – 2.3 µs** | ≤ 4.65 µs |
| Cache hit, client p50 / p99 | 0.055 / 0.107 ms | 0.048 / 0.100 ms | no regression |
| Blocked p50 / p99 | 0.054 / 0.106 ms | 0.050 / 0.104 ms | no regression |
| First-time blocked miss, marginal cost over a cached block | 1,151.8 µs | **3.3 – 5.9 µs** | ≤ 50 µs — read [§12.3](#123-reading-the-first-time-blocked-miss-figure) |
| Throughput (4×25,000) | 25,234 QPS | 64,088 QPS | ≥ 25.2k |
| Server CPU per query | 44.3 µs | 19.9 µs | — |
| List activation | 489 ms | 30 ms | — |
| RSS with oisd small loaded ([§12.2](#122-what-the-rss-row-is-a-measurement-of)) | 52.62 MB (HWM 62.11) | **30.4 MB** | ≤ 45 MB |
| `blocked_total` accuracy | 4 counted vs 5,005 served | exact | exact |
| Upstream RTTs per new name | 2 | 1 | 1 |
| Query log | 4,096-entry ring, no client IP, not persisted | SQLite, 250k rows / 7 days, device-attributed | as now |
| Boot without network | 2-name placeholder, never ready | filters from cached bodies; ready immediately | as now |

The cache-hit row is a band rather than a figure because two sets of runs,
months apart on the same class of host, read 2.270 µs and 1.4–1.7 µs. Neither
is wrong; the host's load moved and the number moved with it. Quote the top of
the band — a measurement reported at its best reading is how a front page ends
up overstating itself.

The other two bolded rows are the ones most often misread; §12.2 and §12.3 are
their method, and quoting either without it invites a conclusion neither
supports.

### 12.1 How the Rust LOC figure is counted

**The rule:** every `.rs` file under a crate's `src/`, minus the files that
exist only for tests (`src/tests.rs`, any `tests/` directory under `src/` —
`src/tests/` and the AI reviewer's `src/ai/tests/` — and `alloc_guard.rs`) and
minus every `#[cfg(test)]` item inside the rest. Those exclusions, plus the
crates' own `tests/` directories, are 16,639 further lines.

The target this row is measured against — `≤ 4,600` — was written before any of
this code existed. It was a guess, it was never derived from the work the
product has to do, and the tree was then read line by line against it.

| Crate | At `a49d021` | Now | Of which comment | What needs them |
|---|---|---|---|---|
| `apps/cogwheel-server` | 3,741 | 10,027 | 1,877 | 29 routes across nine handler modules, the §3 envelope and its three rejection wrappers, config from eighteen environment variables, the §6 policy build with scope interning, the §2.7 refresh pipeline, the §7 query-log writer, retention, startup/shutdown for six background tasks, and the opt-in AI reviewer |
| `cogwheel-storage` | 1,760 | 2,351 | 686 | eight tables, a guarded one-way v0→v1 upgrade and an additive v1→v2 step, a batched log writer with hourly rollups in the same transaction, keyset paging, a bounded top-ten, and three retention bounds — every method `async` over `spawn_blocking` |
| `cogwheel-dns-core` | 1,708 | 1,788 | 434 | a forwarder with a sharded wire cache, serve-stale, EDNS truncation, CNAME re-check, a bounded miss pipeline, UDP and TCP listeners, DoT/DoH upstream parsing, and per-name invalidation |
| `cogwheel-policy` | 737 | 860 | 252 | the eight-tier precedence of §6, the 64-slot bitmask index, rule sets with label-boundary matching, scopes, one normaliser, and the exact-name AI list |
| `cogwheel-lists` | 443 | 443 | 109 | conditional GET with a streaming 32 MiB cap, three list grammars, verification, and the protected-name note |
| **Total** | **8,389** | **15,469** | **3,358** | |

`a49d021` is the tree ADR 0002 was built on. This section last recorded 8,269;
the same rule applied to `a49d021` gives 8,389 — 120 lines that landed after
that recording without it being restated. Both columns above
were measured with the rule, on the same day, by the same script.

Two figures put that in proportion. Roughly a fifth of it — 3,358 lines — is
comment, which is this codebase's house style: every non-obvious decision says
why it was made, and several of those comments are the only record of a measured
result. Strip them and the 1,174 blank lines and 10,937 lines of code remain.
And the comparison people reach for does not hold either: DNSNet's Rust core is
about 1,000 lines, and it has no HTTP API, no SQLite, no per-device model and no
persisted query log — four of the things this document exists to specify.

Before ADR 0002, a pass looking specifically for incidental complexity —
duplicated logic, hand-rolled code a dependency provides, abstractions with one
caller, builders that add a layer without adding safety — found and removed 130
lines (the largest: the v0→v1 upgrade now executes `schema_v1.sql` itself
instead of carrying a second copy of the DDL, and the Overview serialises the
runtime's own snapshot instead of copying it field by field into a
near-identical struct). That is what was there. What remained was the product:
4,600 was never reachable without deleting features this spec requires, and the
target became `≤ 8,600` — the measurement plus a little headroom, because a
target set to whatever the tree happens to be is a row that can never fail.

**ADR 0002, counted as one unit.** Its own files, with the same rule:

| File | Lines |
|---|---|
| `crates/cogwheel-policy/src/ai.rs` | 84 |
| `crates/cogwheel-dns-core/src/invalidate.rs` | 70 |
| `crates/cogwheel-storage/src/ai_verdicts.rs` | 461 |
| `apps/cogwheel-server/src/ai/` (excluding `ai/tests/`), 19 files | 5,427 |
| `apps/cogwheel-server/src/api/ai.rs` | 534 |
| **ADR 0002's own files** (1,206 of them comment) | **6,576** |
| Glue ADR 0002 added to files that already existed (server 325, storage 130, policy 39, dns-core 10) | 504 |
| **The core**: everything that is not ADR 0002's own files (8,389 + 504) | **8,893** |
| ADR 0002's lines in `cogwheel-policy` and `cogwheel-dns-core` together (`ai.rs` 84 + 39 glue, `invalidate.rs` 70 + 10 glue) | 203 |

The target, replacing the single `≤ 8,600`:

> The core target is `≤ 9,100`: the `≤ 8,600` this section argued, plus about
> 500 lines of glue that ADR 0002 adds to existing files. ADR 0002's own files
> are counted separately, with the same rule, against `≤ 6,900`:
> `crates/cogwheel-policy/src/ai.rs`, `crates/cogwheel-dns-core/src/invalidate.rs`,
> `crates/cogwheel-storage/src/ai_verdicts.rs`, `apps/cogwheel-server/src/ai/`
> (excluding `ai/tests/`) and `apps/cogwheel-server/src/api/ai.rs`. No more than
> 215 of all ADR 0002 lines may sit in `cogwheel-policy` and `cogwheel-dns-core`
> combined. The total is `≤ 16,000` in 5 members. The sub-budget keeps the core
> honest and makes the feature auditable as one unit: if it is ever cut, it is
> cut in one place, and the core returns to `≤ 8,600`. Needing more than any of
> these means coming back here.

**Measured against it, every row passes.** The core is 8,893, inside its 9,100;
its glue is 504, four past the 500 that figure was built from, which the 211
lines the core had left under `≤ 8,600` absorb. ADR 0002's own files are 6,576
of 6,900; its lines in `cogwheel-policy` and `cogwheel-dns-core` are 203 of
215; the total is 15,469 of 16,000.

**Why the sub-budget was argued up.** The first one was `≤ 3,900` own lines,
175 in policy plus dns-core and `≤ 13,000` in all, set from a file-by-file
estimate of 3,680 written before the code. The feature as first built measured
6,218 own lines and 183 in those two crates, and this section recorded that as
failing rather than move the targets. A review pass looking for what could go
without losing a guarantee found about 160 to 200 lines: cutting toward 3,900
would mean cutting function the ADR requires, so the ceiling is argued up
instead, file by file, from what the estimate did not foresee. The fixes that
review made added 358 lines (6,218 → 6,576), 20 of them in dns-core.

| Files | Estimate | Now | What the estimate did not foresee |
|---|---|---|---|
| State, settings and set-up: `mod.rs`, `settings.rs`, `gate.rs`, `known.rs`, `models.rs`, `patch.rs`, `spend.rs`, `status.rs`, `test_run.rs` | 740 (`mod.rs` and `settings.rs` alone) | 2,346 | the send gate and its state machine (D18: turning review off closes the gate before the write returns); route 24 validating everything before saving anything, with its Test before turning on and its key replace and remove paths; the Test itself; one spend owner in micro-USD that never counts a response as free; the status that route 23, the Overview and Settings share; a `known` map read only while review is on; and the model picker's zero-retention marking and hour-long cache |
| The pipeline: `review.rs`, `review/settle.rs` | 460 | 940 | settling as its own step: every 200 charged whether or not it can be read, an answer asked under a halted generation discarded unread, cross-site re-checks and contests, and every exit from reviewing closing the gate first |
| `client.rs` | 290 | 468 | a client of its own that follows no redirect, is HTTPS-only except to this machine, ignores proxy variables for a loopback stub, and classifies each failure into a fixed sentence |
| `api/ai.rs` | 380 | 534 | the local-origin guard on every route that writes, spends or sends, a JSON reader that never logs a rejected body, which may hold the key, and route 27's Changes view |
| `ai_verdicts.rs` | 300 | 461 | the four-step prune in one transaction, a narrow read of the blocks and allows for policy builds (the RSS fix in §11.1), and a settlement and its re-check written in one transaction |
| `verdict.rs`, `prompt.rs`, `burst.rs`, `key.rs`, `site.rs` | 1,030 | 1,342 | the cross-site re-check and contest rules, the bars applied again at compile time, the private, router and dynamic-DNS suffixes whose names are never sent, and the key file's 0600 write and zeroing remove |
| `worker.rs`, `install.rs` | 350 | 331 | under |
| `cogwheel-policy` `ai.rs`, `cogwheel-dns-core` `invalidate.rs` | 130 | 154 | an AI epoch of its own in dns-core, so an AI install drops only the names it changed and a miss in flight for any other name keeps the stale answer it may need during an outage |
| **ADR 0002's own files** | **3,680** | **6,576** | |

### 12.2 What the RSS row is a measurement of

RSS moves with *how* the list arrived, not only with how much is in it, so the
number means nothing without its method beside it. Four readings of the same
binary (11,083,000 B) against the same 55,951-line `oisd-small.txt`, each taken
the way `scripts/bench/run.py` takes it — `VmHWM` from `/proc/<pid>/status`,
after `/health/ready` and after the list has finished compiling, before a single
query is answered and before the list-toggle timing that follows — were 30.47,
30.36, 30.41 and 30.32 MB: a 0.15 MB spread. **30.4 MB** is the figure in the
column above, and this paragraph is what has to travel with it.

Readings taken any other way are lower, and what differs is transient allocation
the allocator has not handed back, not anything live:

| How the same 55,989-name index got there | VmHWM |
|---|---|
| Compiled at boot from an already-cached body | 17.00 MB |
| Fetched over HTTPS at run time into an empty policy | 24.46 MB |
| Added through `POST /api/v1/lists` while a policy is live (the harness) | 30.41 MB |

The household's steady state is the first row; the harness deliberately measures
the third, because that is the peak an appliance has to survive. Quoting one of
them without saying which invites exactly the "it regressed" reading that the
`Before` number cannot support either. If a future change wants it lower rather
than merely stated, the lever is glibc arena retention — `malloc_trim(0)`
on the blocking pool once `compile_index` returns, or `M_ARENA_MAX=2` — and it
should be measured on a Pi 5 first, because it buys an `unsafe` call and a
glibc-only path to move a number already 14 MB under target.

### 12.3 Reading the first-time-blocked-miss figure

An earlier version of this table recorded a first-time blocked miss at 27.05 µs
and a later run at about 45 µs, which reads as a 65% regression on the metric
the product exists for. It is not one. The 27.05 µs predates `scripts/bench` and
was not taken through the UDP client path — nothing in this tree can reproduce
it, which is why the row above reports a *marginal* cost instead.

What the harness measures is a client-side round trip: build a query, send it on
a UDP socket, wait for the datagram back. That path has a floor; the floor is
most of the number, and it moves with the machine. Over the same four runs as
§12.2, a *cached* blocked answer — strictly less work than a first-time block —
took 41.46, 42.39, 40.86 and 45.91 µs p50, while a first-time blocked miss
against 55,951 rules took 44.96, 45.67, 46.78 and 49.53 µs. The floor moved 5 µs
between runs; the difference between the two did not. The comparable figure is therefore that
difference — the marginal cost of a first block over a cached one: 3.3 to 5.9 µs,
call it 4 — and it is why a raw client-side reading sits within a hair of its
50 µs target on a loaded sandbox while the work being measured is under a tenth
of that. The server-internal cache-hit row above (1.4–1.7 µs on these runs) is
the one taken without the socket.

When this is re-taken on a Pi 5, record the harness's own floor beside the
figure, and do not chase 27.05 µs: no run of this harness can reach it.
