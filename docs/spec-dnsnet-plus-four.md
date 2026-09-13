# Cogwheel DNS — implementation spec

Product: a DNSNet-class DNS ad-blocker for a Raspberry Pi 5 in one Docker
container: subscribe to hosts/ABP/domain lists, allow/deny rules, a query log —
plus (1) device names by IP, (2) an activity log with counts, (3) per-device
allow/block rules and per-device list selection, (4) a five-page Shark UI.
Nothing else.

Three user concepts: **Device** (name + IP), **List** (a subscription), **Rule**
(allow|block a domain, for everyone or for one device). One read: **the query
log**.

Precedence (fixed, tested): pause → device filtering off → device rules →
household rules → protected suffixes → list allow (`@@`) → list block → CNAME
re-check (list tier only) → allow. Explicit user rules outrank the 21 protected
suffixes; protected outranks subscribed lists only.

**Status.** Phase 1 (`980f86b`) and Phase 2 (`b71865c`) have landed on `main`;
both are green in CI. Phase 3 and Phase 4 are outstanding. Line numbers in this
document refer to commit 85ef5a6 (the pre-cut tree, preserved on branch
`archive/full-featured`) and are stale for files Phases 1–2 rewrote — treat them
as hints and grep.

---

## 1 Crates

Workspace after this work: `crates/cogwheel-policy`, `crates/cogwheel-lists`,
`crates/cogwheel-dns-core`, `crates/cogwheel-storage`, `apps/cogwheel-server`,
`apps/cogwheel-web`. Removed: `cogwheel-classifier`, `cogwheel-services`,
`cogwheel-sync`, `cogwheel-api` (absorbed), `apps/cogwheel-desktop`.
Path-dependency graph (enforced by the ADR test, moved to the server crate):
dns-core → policy; lists → policy; storage → (none); server → policy, lists,
dns-core, storage.

### 1.1 cogwheel-policy (~400 LOC, no I/O, deps: serde only) — DONE in Phase 2
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
- `pub struct Policy { index, household, by_ip, all_mask, block_mode }`.
  Reserved scope ids: `SCOPE_HOUSEHOLD = 0`, `SCOPE_UNFILTERED = 1`. Device
  scopes start at 2 and are interned by signature (§6).
- `pub enum Verdict { Allow(Reason), Block(Reason, u8 /*slot*/) }` (Copy) with
  `pub enum Reason { NoMatch, DeviceRule, HouseholdRule, Protected, ListAllow, List, Cname, Paused, Unfiltered }`.
- `pub fn evaluate(&Policy, &Scope, &str) -> Verdict` — allocation-free.
  `pub fn evaluate_lists(&Policy, mask, &str) -> Verdict` = protected + list
  tiers only (CNAME re-check and `GET /check`).
- `normalize_domain`, `normalize_rule_domain` (also strips a leading `*.`).

### 1.2 cogwheel-lists (~450 LOC) — DONE in Phase 2
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

### 1.3 cogwheel-dns-core (~950 LOC) — DONE in Phase 2
- `upstream.rs` (moved from cogwheel-api) plus `build_resolver(servers)` with
  `ResolverOpts { timeout: 2 s, attempts: 2, cache_size: 0, try_tcp_on_error:
  true, preserve_intermediates: true }`.
- `DnsRuntime` (§5), `serve_with_ready_signal`, the TCP handler.
- TTL clamp (5 s floor, 1 h ceiling, 60 s negative), `error_response_for_payload`,
  `build_base_response`, `build_blocked_response`, `build_ip_response`.

### 1.4 cogwheel-storage (~700 LOC, deps: rusqlite(bundled), serde, serde_json, thiserror, tokio, tracing)
- One `Arc<Mutex<Connection>>`; PRAGMAs journal_mode=WAL, synchronous=NORMAL,
  wal_autocheckpoint=1000, foreign_keys=ON, busy_timeout=5000.
- Every public method is `async fn` running its closure under
  `tokio::task::spawn_blocking` (the DNS task and axum handlers never run
  rusqlite on a runtime worker).
- `schema_v1.sql` (fresh) + `migrate.rs` (legacy v0 → v1), versioned by
  `PRAGMA user_version` (§2). `migrations/0001..0011` move to
  `tests/fixtures/legacy/`.
- Ids stay TEXT UUIDs for `sources`/`devices`; the crate stores them as `String`
  (no uuid dep); the server validates at the API edge.
- Repos: sources (list/insert/update/delete/update_fetch_status), devices
  (list/upsert/delete/set_lists), rules (list/insert/delete), query_log
  (insert_batch_with_rollups, page, top_domains, clear, prune), stats
  (hourly_24h, per_client_24h, unnamed_clients_24h), settings (get/set for
  `pause_until` only).
- Tests: idempotent open; v0 fixture upgrade (fixture built by executing the
  eleven legacy migration files, seeding a device with bypass + allowed_domains
  + profile override, the baseline source, one user source); prune by days and
  by row cap; rollup upsert arithmetic; HISTORY_DAYS=0 writes rollups but no log
  rows.

### 1.5 apps/cogwheel-server (~1,900 LOC across modules)
`main.rs` (CLI `--version/--help`, init_tracing, startup order, background
tasks, graceful shutdown), `config.rs` (AppConfig from env), `http.rs` (router,
`/health/live`, `/health/ready` + `Readiness`, `ApiEnvelope`, `ApiError`, SPA
fallback, CompressionLayer), `state.rs`, `policy_build.rs` (§6), `refresh.rs`
(§2.7), `querylog.rs` (§7), `prune.rs`,
`api/{overview,queries,devices,rules,lists,check,settings,runtime}.rs`.
Tests: ADR path-dependency test, CLI tests, block-mode tests,
`encrypted_upstreams_have_trust_anchors_compiled_in`, EventBus tests (Query
frames only), source-due test, handler tests against an in-memory Storage.

### 1.6 apps/cogwheel-web (~8,000 LOC; React 19 + Vite + Tailwind 4 + Shark UI (Ark) + Inter)
Five routes, one provider, one `api.ts` of 22 calls; approved shell reused (§4).

---

## 2 Schema + migration

Seven tables, `PRAGMA user_version = 1`. All timestamps are INTEGER unix
seconds. Ids for `sources`/`devices` remain TEXT UUIDs (every existing row keeps
its id).

### 2.1 `schema_v1.sql` (fresh installs)
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
CREATE INDEX query_log_ts ON query_log (ts);
CREATE INDEX query_log_client_id ON query_log (client, id);

CREATE TABLE query_stats_hourly (
  hour INTEGER NOT NULL, client TEXT NOT NULL,            -- client '' = all devices
  queries INTEGER NOT NULL, blocked INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (hour, client));
PRAGMA user_version = 1;
```
Write rates: `sources` one UPDATE per source per refresh (daily by default);
`devices`/`device_lists`/`rules` on user edits; `query_log` +
`query_stats_hourly` one transaction per 5 s (§7); `settings` per pause click.

### 2.2 Open sequence (`Storage::open`)
1. Open, set PRAGMAs. 2. `v = PRAGMA user_version`. 3. If `v == 1` → done.
4. If `v == 0` and no `sources` table → execute `schema_v1.sql` in one
transaction. 5. If `v == 0` and table `rulesets` exists → legacy upgrade (§2.3).
6. Any other `v` → refuse to start with "database is from a newer Cogwheel".
After open: `seed_if_empty` (§2.4).

### 2.3 Legacy v0 → v1 upgrade (`migrate.rs`), one transaction, guarded by a backup
1. `VACUUM INTO '<db path>.pre-v1'` (remove a stale file of that name first). A
   plain file copy is NOT used because the WAL may hold unflushed pages.
2. `BEGIN IMMEDIATE`.
3. Create the seven v1 tables under `_v1` names.
4. `INSERT INTO sources_v1 … SELECT … FROM sources WHERE id <> '00000000-0000-0000-0000-000000000001'`
   (the built-in 2-name `baseline` data: URL is dropped;
   `refresh_interval_minutes`, `profile`, `verification_strictness` dropped).
5. `INSERT INTO devices_v1 … CASE WHEN policy_mode='custom' AND protection_override='bypass' THEN 0 ELSE 1 END, 1, …`
   — every device keeps its id, name and IP; a bypass device keeps bypassing;
   `all_lists` is always 1 (a `blocklist_profile_override` never affected DNS, so
   it is NOT mapped; each such device is named in a startup WARN).
6. `INSERT INTO rules (domain, action, device_id, created_at) SELECT lower(trim(j.value)), 'allow', d.id, unixepoch() FROM devices d, json_each(d.allowed_domains_json) j WHERE d.policy_mode='custom' AND j.value <> ''`
   (global-mode devices had their allowed_domains ignored at runtime, so
   importing them would change behaviour; skipped with a WARN naming the
   device). `service_overrides_json` is discarded (WARN). `block_profiles`
   allowlists are NOT imported (would silently unblock).
7. If the baseline source row was present: seed `ads.example.com` and
   `tracker.example.com` as household block rules so an upgraded install keeps
   answering `0.0.0.0` for the names DEPLOYMENT.md §7 uses.
8. `DROP TABLE` rulesets, active_ruleset, audit_events, security_events,
   notification_deliveries, config_schema, config_migrations, settings, sources,
   devices (drop the two indexes first). `ALTER TABLE … RENAME` the `_v1`
   tables. `PRAGMA user_version = 1`. `COMMIT`.
9. On any error: `ROLLBACK`, log the `.pre-v1` path, exit non-zero (the old
   image still boots the untouched v0 file).

### 2.4 First-boot seed (`seed_if_empty`, fresh AND upgraded DBs)
If `sources` is empty: insert one enabled list — **oisd small**
(`https://small.oisd.nl`, kind `adblock`, name "oisd small"). Nothing else is
seeded; no hidden built-in rules.

### 2.5 Preset catalogue (client-side `lib/presets.ts`; also returned by `GET /api/v1/lists` as `presets`)
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
`{ "error": "<plain sentence>" }` with 400 (validation), 404, 409 (65th enabled
list; duplicate device IP; duplicate list name), 429 (refresh within 30 s), 503
(SSE cap / not ready), 500. Ids are the UUID strings. Times are unix seconds.
22 routes (20 + 2 health).

| # | Method | Path | Body / query | Response `data` | Notes |
|---|---|---|---|---|---|
| 1 | GET | `/health/live` | — | `{status:"ok"}` | Docker HEALTHCHECK, install.sh — unchanged |
| 2 | GET | `/health/ready` | — | `{status, subsystems{storage,policy,dns_listeners}}` 503 until all | ci.yml, verify-install.sh — unchanged; policy ready once ANY policy (even empty) is installed |
| 3 | GET | `/api/v1/overview` | — | `{protection:{paused_until:int\|null}, runtime:{queries_total,blocked_total,cache_hits_total,cache_expired_total,stale_served_total,upstream_failures_total,cname_blocks_total,dropped_total,log_dropped_total,cache_hit_latency_avg_ns,cache_miss_latency_avg_ns}, last_24h:{queries,blocked,per_hour:[24×{hour,queries,blocked}],active_clients,named_devices,unnamed_clients}, lists:{enabled,total,rules_loaded,last_ok_at:int\|null,downloaded:bool}, top_blocked:[10×{domain,count}], top_queried:[10×{domain,count}], connect:{targets:[string],port:int}}` | Polled every 5 s. `last_24h`/`active_clients` read `query_stats_hourly`; `top_*` scan `query_log` once per 60 s (memoized); `connect.targets` = `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` else `hostname -I` |
| 4 | POST | `/api/v1/runtime/pause` | `{minutes:u32}` (1..=1440) | `{paused_until}` | AtomicU64 + `settings.pause_until`; survives restart |
| 5 | POST | `/api/v1/runtime/resume` | — | `{paused_until:null}` | |
| 6 | GET | `/api/v1/queries` | `?limit=200(max 1000)&before=<id>&client=<ip>&unnamed=true&blocked=true\|false&q=<substr>` | `{rows:[{id,ts,client,device_id\|null,device_name\|null,domain,qtype,blocked,reason,list\|null}], next_before:int\|null, logging:bool}` | Keyset newest-first; LEFT JOIN devices ON ip_address = client so renames relabel history; `logging=false` when HISTORY_DAYS=0 |
| 7 | DELETE | `/api/v1/queries` | — | `{deleted:int}` | Clear log (rollups kept) |
| 8 | GET | `/api/v1/events/stream` | — | SSE, event `query`: `{ts,client,deviceName,domain,qtype,blocked,reason,list}` | 32-subscriber cap and shutdown `take_until` kept; only `query` frames |
| 9 | GET | `/api/v1/devices` | — | `{devices:[{id,name,ip_address,filtering,all_lists,lists:[source_id],rules:[{id,domain,action}],queries_24h,blocked_24h,last_seen_at\|null}], unnamed_clients:[{ip,queries_24h,blocked_24h,last_seen_at}]}` | counts from `query_stats_hourly`; unnamed = clients in rollups with no devices row |
| 10 | POST | `/api/v1/devices` | `{name,ip_address,filtering?=true,all_lists?=true,lists?=[source_id]}` | device | `ip_address` must parse as `IpAddr` (400); duplicate IP 409; rebuilds scopes |
| 11 | PUT | `/api/v1/devices/{id}` | same body | device | rename / re-address / change lists; rebuilds scopes |
| 12 | DELETE | `/api/v1/devices/{id}` | — | `{deleted:true}` | cascades device_lists + device rules |
| 13 | GET | `/api/v1/rules` | `?device_id=<id>` optional | `[{id,domain,action,device_id\|null,device_name\|null,created_at}]` | |
| 14 | POST | `/api/v1/rules` | `{domain,action:"allow"\|"block",device_id?}` | rule | domain normalized; must match `^[a-z0-9-]+(\.[a-z0-9-]+)+$`; upsert on (domain, device_id); rebuild |
| 15 | DELETE | `/api/v1/rules/{id}` | — | `{deleted:true}` | |
| 16 | GET | `/api/v1/lists` | — | `{lists:[{id,name,url,kind,enabled,rule_count,last_ok_at,last_fetched_at,last_error,note,due}], presets:[{name,url,kind}]}` | |
| 17 | POST | `/api/v1/lists` | `{name,url,kind:"hosts"\|"domains"\|"adblock",enabled?=true}` | `{list, outcome:"updated"\|"unchanged"\|"rejected"\|"failed", note}` | URL must be http(s) or data:; 409 if it would be the 65th enabled; fetch + rebuild immediately |
| 18 | PUT | `/api/v1/lists/{id}` | `{name?,url?,kind?,enabled?}` | list | url/kind change → refetch; enabled toggle → rebuild from cache only |
| 19 | DELETE | `/api/v1/lists/{id}` | — | `{deleted:true}` | removes body file, device_lists rows; rebuild |
| 20 | POST | `/api/v1/lists/refresh` | `{id?}` | `[{id,name,outcome,rule_count,note}]` | 429 within 30 s of the previous manual refresh |
| 21 | GET | `/api/v1/check` | `?domain=&client=<ip optional>` | `{domain, verdict:"allow"\|"block", reason, list\|null, scope:"household"\|"device"\|"unfiltered"\|"paused", device_name\|null}` | runs `evaluate` on the live `Policy` — the "Why?" answer |
| 22 | GET | `/api/v1/settings` | — | `{version, upstreams:[{spec,protocol,encrypted}], block_mode, http_bind, dns_udp_bind, dns_tcp_bind, advertised_targets, advertised_port, refresh_interval_secs, retention:{history_days,max_rows,prune_interval_secs}, db_path, db_size_bytes, lists_dir, protected_suffixes:[21], schema_version}` | read-only; config is env-only by design |

Removed route names that scripts reference: `/api/v1/dashboard` →
`/api/v1/overview`; `/api/v1/resolver-access` → `overview.connect`;
`/api/v1/runtime` → `overview.runtime`; `/metrics` gone; block-profiles marker →
device marker.

---

## 4 UI pages

Shell: reuse the approved Shark UI shell exactly — `AppLayout` with `AppSidebar`
(Navigation group of five entries; the "Appliance" group, `SidebarSeparator` and
`SECONDARY_NAV` removed; footer keeps the status line, `SnoozeControl`,
`ThemeToggle`), `PageShell/PageHeader/PageSections`, `SectionCard` (24 px
gutters, no accent strips), `StatTile`, `DataTable` (with the container-query
`hideBelow`/`stackBelow`), `ConfirmDialog`, `TextField/SelectField/FieldRow`,
`StatusPill`, `EmptyState/ErrorState/LoadingSkeleton/NoticeBanner`,
`StaleBanner`, `Toaster`, `ErrorBoundary`. Keep ⌘1–⌘5 and `/` focus-search; the
shortcuts dialog and its `?` handler are deleted. Black/white neutrals,
red/green/yellow-400 status only (the five `--chart-*` tokens are deleted).
`nav.ts`: five `PRIMARY_NAV` entries (Overview `/`, Activity `/activity`,
Devices `/devices`, Lists `/lists`, Settings `/settings`).

Data provider: snapshot = `{overview, settings, lists, devices, rules}`;
`FULL_LOADERS` = all five; `LIVE_FIELDS` = `overview` only (5 s, visible tab);
localStorage cache keys kept; `mutate()` unchanged.

### `/` Overview
- StatTile row (4): **Protection** (Protected / Paused hh:mm, Resume in the
  footer when paused; hint "Lists not downloaded yet" in yellow-400 when
  `lists.downloaded=false`), **Queries (24 h)** with hint "since last restart:
  N", **Blocked (24 h)** with `%` delta, **Devices** value = `active_clients`,
  delta "N named · M unnamed" (link to /devices).
- SectionCard "Last 24 hours": 24 bars of plain `div`s from `per_hour` (blocked
  stacked in neutral-900 over queries in neutral-200; no library), hour labels
  every 6 h.
- SectionCard "Top blocked" / "Top queried" side by side, 10 rows, mono domain +
  count; row action menu: "Allow for everyone" / "Block for everyone" → POST
  /rules; "Why?" → GET /check shown inline in a `NoticeBanner`.
- SectionCard "Connect your devices": one row per `connect.targets` (IPv6
  labelled) + port, Copy button; the three platform hints kept.
- Header actions: "Refresh lists" and "Reload".

### `/activity` Activity
- Filter bar: **Live** switch (SSE; rows prepend), Device select (All / each
  named device / Unnamed), Verdict segment (All / Blocked / Allowed), search
  `TextField`.
- One `DataTable`: Time, Domain (mono), Device (name, else IP with a muted
  "unnamed" tag), Type (A/AAAA/HTTPS…), Verdict (`StatusPill` Blocked=bad /
  Allowed=good) + reason text ("oisd small", "device rule", "household rule",
  "protected", "CNAME → x", "paused", "unfiltered"). Row menu: Allow/Block for
  everyone, Allow/Block on <device>, Name this device… (unnamed → Devices with
  `?ip=`), Why?.
- Footer: "Load older" (keyset `before`), "Clear log" (ConfirmDialog → DELETE
  /queries). When `logging=false`: NoticeBanner "Query logging is off
  (COGWHEEL_RETENTION__HISTORY_DAYS=0); only the live stream is shown."
- History loads from GET /queries on mount and after Clear; live frames
  deduplicated by (ts, client, domain) against the top 50 rows.

### `/devices` Devices
- Two-column: **form card** ("Add device" / "Edit <name>") with Name, IP address
  (validated), **Filtering** switch ("Off: this device resolves everything and is
  still logged"), **Lists**: radio "Use all household lists" / "Choose lists" →
  checkbox per enabled list (unchecking every list = lists off, household/device
  rules still apply — stated inline), **Rules for this device**: domain +
  Allow/Block add row and a list with delete; Delete device (ConfirmDialog).
- **Devices table**: Name, IP, Filtering (StatusPill), Lists ("All" / "n of m"),
  Rules (count), Queries / Blocked (24 h), Last seen.
- **Unnamed clients** SectionCard: IP, queries/blocked 24 h, last seen, "Name
  this device" → prefills the form (`?ip=` also honoured).

### `/lists` Lists
- SectionCard "Add a list": Preset select (§2.5; fills name/url/kind) or Name,
  URL, **Format** select (hosts / domains / adblock); Enabled switch; Add.
- SectionCard "Lists": table Name, Format badge, Enabled `Switch`, Rules loaded,
  Last updated, Status (yellow-400 `last_error`, or `note` such as "contains 2
  protected names (ignored)"), Refresh row, Delete row; header "Refresh all".
- SectionCard "Household rules": Allow/Block for everyone — add row and table
  with delete; footnote "Allow beats block. A domain covers its subdomains."
- SectionCard "Check a domain": domain input + optional device select → verdict
  + reason inline.

### `/settings` Settings (read-only)
- "Resolver": upstream rows with badge UDP (plus "cleartext" warning) / DoT /
  DoH, block response mode, bind addresses, advertised targets + port; each
  value shows its env var name in mono; footnote "Set via COGWHEEL_* in
  /etc/cogwheel/cogwheel.env (installer) or .env (compose), then restart."
- "Activity log": logging on/off, retention days, max rows, database size, lists
  dir; "Clear log" button.
- "Protected domains": collapsible list of the 21 suffixes with one sentence
  explaining they outrank lists but not your own rules.
- "About": version, schema version, theme toggle.

---

## 5 Hot path — DONE in Phase 2

### 5.1 Data structures (`cogwheel-dns-core`)
```rust
pub struct DnsRuntime {
    resolver: TokioResolver,
    policy: RwLock<Arc<Policy>>,
    pause_until: AtomicU64,
    cache: moka::future::Cache<CacheKey, Arc<CachedWire>>, // max 10_000, ttl 24 h = STALE ceiling
    miss_permits: Arc<Semaphore>,                  // 512
    log_tx: mpsc::Sender<LogEntry>,                // bounded 8_192, try_send
    stats: DnsRuntimeStats,
    block_mode: BlockMode,
}
pub struct CacheKey { scope: u32, qtype: u16, domain: Arc<str> }
pub struct CachedWire { bytes: Box<[u8]>, truncated: Option<Box<[u8]>>, fresh_until: Instant, blocked: bool, verdict: Verdict }
pub struct LogEntry { ts: u32, client: IpAddr, domain: Arc<str>, qtype: u16, verdict: Verdict }
```
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
7. **Upstream**: unless the verdict was an explicit allow, walk
   `lookup.answers()` for `RData::CNAME` targets (≤ 8) and run `evaluate_lists`
   on each — zero extra RTT.
8. **Upstream failure**: serve the stale entry if present (`stale_served += 1`),
   re-freshened for 30 s; else SERVFAIL.
9. **Insert + send + log**: `truncated` precomputed only when `bytes.len() >
   512`; send = memcpy + 2-byte id patch + RD bit.

A policy swap bumps a cache epoch so a miss already in flight cannot insert a
verdict from the replaced policy.

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
toggle, device or rule edit):
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
5. `Policy` is swapped into `DnsRuntime.policy`; the querylog task receives a
   fresh `Arc<HashMap<IpAddr, (Arc<str> name, String id)>>` for SSE attribution.

Resolution order for client IP C and name N (first match wins):
1. pause → allow (Paused) · 2. C has no device row → household scope ·
3. `filtering = 0` → allow (Unfiltered) · 4. device allow rule → allow ·
5. device block rule → block · 6. household allow rule → allow ·
7. household block rule → block · 8. protected suffix → allow ·
9. list allow (`@@`) under `mask` → allow · 10. list block under `mask` → block,
attributed to `trailing_zeros(bits & mask)` · 11. CNAME targets re-run 8–10 →
block · 12. allow.

Rule matching is suffix-on-label-boundary. `GET /check` reports which step
fired. Unnamed clients are discovered from `query_stats_hourly`.

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

Size: ~55 B/row on disk; a busy household (~10 qps, 0.9 M rows/day) hits the
250,000-row cap (~15–20 MB) long before 7 days; a quiet one keeps 7 days.
Rollups ≈ 15 KB/day, pruned at 90 days, so Overview/Devices counts outlive the
raw rows and never GROUP BY the log.

Prune (`prune.rs`, hourly, first tick immediate):
`DELETE FROM query_log WHERE ts < now - history_days*86400` (skipped when
history_days == 0); `DELETE FROM query_log WHERE id <= (SELECT id FROM query_log
ORDER BY id DESC LIMIT 1 OFFSET max_rows)`; `DELETE FROM query_stats_hourly
WHERE hour < now - 90*86400`.

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
| `COGWHEEL_WEB_DIST_DIR` | search path | unchanged |
| `RUST_LOG` | `info` | unchanged |

Removed: `COGWHEEL_RUNTIME_GUARD__*`. Installer/compose-only variables are
untouched.

---

## 9 Deletions

Phases 1 and 2 executed §9.1–§9.9 except the module split and the schema.
Remaining for Phase 3: absorb and delete `crates/cogwheel-api`; split
`apps/cogwheel-server/src/main.rs` into the modules of §1.5; move
`crates/cogwheel-storage/migrations/*` to `tests/fixtures/legacy/`; delete the
web's remaining unused `components/ui/*` primitives (combobox, popover,
progress, hint, item, input-group, number-input, avatar, select, alert,
textarea, tooltip and friends — keep kbd, menu, sheet, switch, badge,
segment-group and anything with an importer), `routes/protection.tsx` (→
`lists.tsx`), and rewrite `routes/settings.tsx`. Phase 4 covers docs (§9.11):
`docs/architecture/05-classifier.md`, `docs/reliability-budgets.md`, `ROADMAP.md`
(→ a 20-line scope statement); rewrite `docs/hot-path-guardrails.md`,
`docs/adr/0001-crate-boundaries.md`, `docs/crate-boundary-guardrails.md`,
`README.md`, `DEPLOYMENT.md`, the quickstarts, `docs/release-policy.md`, the
architecture docs.

---

## 10 Perf fixes (all landed in Phase 2)

| Audit finding | Fix |
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
| MED query log never persisted | Phase 3: `query_log` + `query_stats_hourly` batched every 5 s |
| NEW correctness | TC truncation for non-EDNS UDP clients; A-label keying |

---

## 11 Phased execution plan

Common gate G: `cargo fmt --all -- --check` · `cargo clippy --workspace
--all-targets --all-features -- -D warnings` · `cargo test --workspace` ·
`cargo build --release --locked -p cogwheel-server` · `cargo audit` ·
`cargo deny check` · `cd apps/cogwheel-web && npm ci && npm run lint && npx tsc
--noEmit && npm run build` · `for f in scripts/*.sh; do sh -n $f; done &&
shellcheck scripts/*.sh` · `actionlint .github/workflows/*.yml` ·
`docker buildx build --check .` · the ci.yml image smoke · `sh
scripts/verify-install.sh`.

Benchmark gate B: release binary on 127.0.0.1:35353 / :38080 with a real list
(oisd small, ~55,850 ABP lines) served from a local `python3 -m http.server`, a
loopback stub upstream, then the dnsbench/mpbench drivers; record hit/blocked
p50/p99, first-time blocked miss, throughput, RSS, startup→ready, binary size.

**Phase 1 — delete in place.** LANDED as `980f86b`.
**Phase 2 — engine and hot path.** LANDED as `b71865c`.
**Phase 3 — storage v1, control plane, API, five pages.** Storage schema v1 +
`migrate.rs` + `seed_if_empty` + fixture test; server split into modules,
cogwheel-api absorbed and deleted, ADR test moved; refresh pipeline with
conditional GET and body cache (§2.7); `policy_build.rs` with scope interning
(§6); querylog writer + rollups + prune (§7); the 22 routes (§3); pause
persisted; `hostname -I` connect targets; web: `api.ts` (22 calls), provider (5
fields), `nav.ts` (5 entries), the five pages (§4), `presets.ts`; scripts and CI
updated.
Gate: G + a manual v0→v1 upgrade test + benchmark gate B.
**Phase 4 — docs, ADR, Pi numbers.** Rewrite the docs of §9; fill §12's "after"
column; measure on a Pi 5 when one is available.

---

## 12 Before / after

| Metric | Before (85ef5a6) | After Phase 2 (measured) | Target |
|---|---|---|---|
| Rust LOC | 19,512 in 10 members | 8,730 in 6 | ≤ 4,600 excl. tests |
| Web LOC (src) | 17,222 | 10,496 | ≤ 8,000 |
| HTTP routes | 44 + 4 | 16 + 2 | 20 + 2 |
| Sidebar pages | 8 | 5 (Phase 3) | 5 |
| Crates | 10 | 6 | 5 (+ web) |
| Cargo.lock packages | 326 | 298 | ≤ 245 |
| SQLite tables | 12 | 12 (Phase 3) | 7 |
| Binary (x86_64, stripped) | 15,707,800 B | 12,679,416 B | ≤ 14 MB |
| Threads | 6 | 5 | 5 |
| RSS with oisd small loaded | 52.62 MB (HWM 62.11) | 26.31 MB (HWM 27.99) | ≤ 45 MB |
| Cache hit, server-internal | 4.651 µs | 2.270 µs | ≤ 4.65 µs |
| Cache hit, client p50 / p99 | 0.055 / 0.107 ms | 0.048 / 0.100 ms | no regression |
| Blocked p50 / p99 | 0.054 / 0.106 ms | 0.050 / 0.104 ms | no regression |
| First-time blocked miss (55,852 rules) | 1,151.8 µs | 27.05 µs p50 | ≤ 50 µs |
| Throughput (4×25,000) | 25,234 QPS | 64,088 QPS | ≥ 25.2k |
| Server CPU per query | 44.3 µs | 19.9 µs | — |
| List activation | 489 ms | 30 ms | — |
| `blocked_total` accuracy | 4 counted vs 5,005 served | exact | exact |
| Upstream RTTs per new name | 2 | 1 | 1 |
| Query log | 4,096-entry ring, no client IP, not persisted | same (Phase 3) | SQLite, 250k rows / 7 days, device-attributed |
| Boot without network | 2-name placeholder, never ready | same (Phase 3) | filters from cached bodies; ready immediately |

Benchmarks were taken on a 4-vCPU x86_64 sandbox, not a Pi 5; treat them as
relative reference points. No Raspberry Pi 5 measurement exists yet.
