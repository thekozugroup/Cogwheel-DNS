# 01 — Backend HTTP API Contract Map (Cogwheel Server)

The HTTP surface of `apps/cogwheel-server` after the cut to the DNS-filtering
core: two health routes from `crates/cogwheel-api` and sixteen `/api/v1` routes
from `apps/cogwheel-server/src/main.rs`. Everything below is read from those
two files. Line numbers are omitted on purpose — the server is still one file
and they move on every edit. The pre-cut surface (48 routes) is documented on
the `archive/full-featured` branch.

---

## 1. Router composition

`build_http_app` merges two routers and wraps them in two layers:

1. `cogwheel_api::router` — `GET /health/live`, `GET /health/ready`.
2. `admin_router` — the sixteen `/api/v1` routes in §4.
3. A fallback service that serves the web bundle from the first of
   `$COGWHEEL_WEB_DIST_DIR`, `./apps/cogwheel-web/dist`, `./dist` and
   `/app/web` that contains an `index.html`. A client-side route — no `/api/`,
   `/health/` or `/assets/` prefix and no file extension in its last segment —
   that misses on disk is answered with `index.html` **and status 200**; a
   missing asset or an unknown API path stays a real 404. With no bundle on
   disk the server logs a warning and serves the API only.
4. `CompressionLayer` (brotli and gzip) over the whole router, then `TraceLayer`.

There is no authentication, no CORS layer and no body-size limit beyond
axum's default; the control plane is meant to be reachable on the LAN only.

## 2. Response and error conventions

- Every JSON success body is `{"data": <T>}` (`cogwheel_api::ApiEnvelope`).
- `POST /api/v1/runtime/pause` and `/resume` return an empty `200`.
- Errors come in two shapes, by handler:
  - a bare status with an empty body — `400` (malformed field), `404`
    (unknown id), `409` (touching the reserved baseline source), `429` (rate
    limited), `500` (storage or refresh failure);
  - `(status, "reason")` as plain text — `POST /api/v1/devices` and both
    block-profile handlers.
- `cogwheel_api::ApiError` renders as `500 {"error": "..."}` but is only
  produced by configuration parsing at startup.
- Field names are `snake_case` throughout except the SSE frame (§6), which is
  `camelCase`. Timestamps are RFC 3339 strings; ids are UUID strings; a block
  profile's id is a slug.

## 3. `ServerState` and startup

`#[derive(Clone, FromRef)] struct ServerState`:

| Field | Type | Purpose |
|---|---|---|
| `api_state` | `ApiState { readiness }` | backs `/health/ready` |
| `storage` | `Arc<Storage>` | SQLite via `cogwheel-storage` |
| `dns_runtime` | `Arc<DnsRuntime>` | the resolver; every policy swap goes through it |
| `recent_dns_activity` | `Arc<Mutex<VecDeque<DomainActivityRecord>>>` | 4,096-entry, 24-hour ring behind `domain_insights` |
| `events` | `EventBus` | broadcast channel behind the SSE endpoint |
| `shutdown` | `watch::Receiver<bool>` | ends open SSE streams on SIGTERM |
| `protected_domains` | `Arc<HashSet<String>>` | `cogwheel_policy::PROTECTED_SUFFIXES`, materialised once |
| `rate_limiter` | `Arc<RateLimiter>` | 100 requests per 60 s per key; the keys are `refresh_sources` and `upsert_blocklist` |
| `dns_udp_bind_addr`, `advertised_dns_port`, `advertised_dns_targets` | | inputs to `GET /api/v1/resolver-access` |

### Startup sequence (`main`)

1. Parse the command line. No arguments runs the server; `--version` and
   `--help` print and exit 0; anything else prints usage and exits 2 without
   binding a socket.
2. `AppConfig::load()` (§8). The block response mode is resolved once into a
   process-wide `OnceLock` because it is baked into every compiled policy.
3. `Storage::connect` (SQLite, WAL, migrations applied), then re-insert the
   reserved `baseline` source — id `00000000-0000-0000-0000-000000000001`, a
   `data:` URL carrying two example names — so the node always has a policy to
   serve. That source cannot be disabled or deleted (`409`).
4. Start the runtime on an empty `Policy` (every name resolves); the real one
   is installed by the startup refresh below.
5. `build_resolver` from `COGWHEEL_UPSTREAM__SERVERS`: cleartext `host:port`,
   `tls://host#name` and `https://host#name/path` endpoints. Mixing encrypted
   and cleartext entries logs a warning.
6. `DnsRuntime::new(resolver, policy)`, register the query-activity observer
   (it feeds the ring buffer and the event bus) and spawn the UDP/TCP
   listeners. `readiness.mark_dns_ready()` fires once both sockets are bound.
7. Fetch every enabled source, verify it, compile the policy catalog and
   activate it (`warm_runtime_policy_catalog`); on success
   `readiness.mark_policy_ready()`. On failure the node keeps serving the
   bootstrap policy and `/health/ready` stays `503`.
8. Push device policies into the runtime, spawn the refresh scheduler
   (`COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS`, floored at 30 s; each tick
   refreshes only the sources whose own `refresh_interval_minutes` has
   elapsed) and the retention task (§7).
9. Bind HTTP and serve until SIGINT or SIGTERM; then drain HTTP, broadcast
   shutdown, and give the DNS listeners five seconds to finish.

## 4. Route table

| Method | Path | Handler | `data` |
|---|---|---|---|
| GET | `/health/live` | `live` | `{"status":"ok"}` |
| GET | `/health/ready` | `ready` | `{"status":"ready"\|"starting","subsystems":{"storage","policy","dns_listeners"}}` — `503` while starting |
| GET | `/api/v1/dashboard` | `dashboard_summary` | `DashboardSummary` |
| GET | `/api/v1/settings` | `settings_summary` | `SettingsSummary` |
| POST | `/api/v1/settings/block-profiles` | `upsert_block_profile` | `BlockProfileRecord[]` (the whole list after the write) |
| POST | `/api/v1/settings/block-profiles/delete` | `delete_block_profile` | `BlockProfileRecord[]` |
| POST | `/api/v1/settings/blocklists` | `upsert_blocklist` | `RefreshResponse` |
| POST | `/api/v1/settings/blocklists/state` | `update_blocklist_state` | `RefreshResponse` |
| POST | `/api/v1/settings/blocklists/delete` | `delete_blocklist` | `RefreshResponse` |
| GET | `/api/v1/devices` | `list_devices` | `DeviceRecord[]` |
| POST | `/api/v1/devices` | `upsert_device` | `DeviceRecord` |
| GET | `/api/v1/sources` | `list_sources` | `SourceRecord[]` |
| POST | `/api/v1/sources/refresh` | `refresh_sources` | `RefreshResponse` |
| GET | `/api/v1/events/stream` | `events_stream` | SSE, §6 |
| GET | `/api/v1/runtime` | `runtime_snapshot` | `DnsRuntimeSnapshot` |
| POST | `/api/v1/runtime/pause` | `pause_runtime` | empty `200` |
| POST | `/api/v1/runtime/resume` | `resume_runtime` | empty `200` |
| GET | `/api/v1/resolver-access` | `resolver_access_status` | `ResolverAccessStatus` |

CI's image smoke test asserts that `/api/v1/definitely-not-real` is a `404`,
which is what keeps the SPA fallback from masking a removed route.

## 5. Contracts

### `DashboardSummary` — `GET /api/v1/dashboard`

```jsonc
{
  "protection_status": "Protected",            // or "Paused"
  "protection_paused_until": null,             // RFC 3339 while paused
  "policy": {
    "hash": "<sha256 of the global artifact>",
    "rule_count": 2,
    "previous_hash": null                       // hash the last activation replaced
  },
  "source_count": 1,
  "enabled_source_count": 1,
  "device_count": 0,
  "runtime": { /* DnsRuntimeSnapshot */ },
  "domain_insights": {
    "top_queried_domains": [{ "domain": "…", "count": 3 }],   // at most 6
    "top_blocked_domains": [{ "domain": "…", "count": 1 }],   // at most 6
    "observed_queries": 4
  }
}
```

`domain_insights` is computed from the in-memory ring — the last 4,096
queries, none older than 24 hours — and does not survive a restart.

### `DnsRuntimeSnapshot` — `GET /api/v1/runtime` and `dashboard.runtime`

All `u64`, counted since process start: `upstream_failures_total`,
`fallback_served_total`, `cache_hits_total`, `cache_expired_total`,
`cname_uncloaks_total`, `cname_blocks_total`, `queries_total`, `blocked_total`,
`cache_hit_latency_avg_ns`, `cache_hit_samples`, `cache_miss_latency_avg_ns`,
`cache_miss_samples`.

### `SettingsSummary` — `GET /api/v1/settings`

```jsonc
{
  "blocklists": [ /* SourceRecord */ ],
  "blocklist_statuses": [
    { "id": "<uuid>", "name": "…", "last_refresh_attempt_at": "…|null", "due_for_refresh": true }
  ],
  "block_profiles": [ /* BlockProfileRecord */ ],
  "devices": [ /* DeviceRecord */ ]
}
```

### `SourceRecord` — `GET /api/v1/sources`, `settings.blocklists`

`id`, `name`, `url`, `kind` (`domains` | `hosts` | `adblock`), `enabled`,
`refresh_interval_minutes` (≥ 1), `profile` (lowercased free text; `shared`
means "in every profile"), `verification_strictness` (`strict` | `balanced` |
`relaxed`).

### `POST /api/v1/settings/blocklists` — `UpsertBlocklistRequest`

```jsonc
{
  "id": "<uuid, optional; omit to create>",
  "name": "OISD Big",
  "url": "https://big.oisd.nl",
  "kind": "domains",
  "enabled": true,
  "refresh_interval_minutes": 60,        // optional, default 60, floored at 1
  "profile": "custom",                   // optional, default "custom"
  "verification_strictness": "balanced", // optional, default "balanced"
  "refresh_now": true                    // optional, default true
}
```

Rate limited. An unparsable URL, kind, profile or strictness is `400`. With
`refresh_now` (the default) and `enabled`, the response is the outcome of a
full refresh; otherwise `{"outcome":"saved", …}`.

### `POST /api/v1/settings/blocklists/state` — `{ id, enabled, refresh_now? }`

Disabling the baseline source is `409`; an unknown id is `404`.

### `POST /api/v1/settings/blocklists/delete` — `{ id, refresh_now? }`

Deleting the baseline source is `409`; an unknown id is `404`.

### `RefreshResponse` — every blocklist mutation and `POST /api/v1/sources/refresh`

```jsonc
{
  "outcome": "activated",   // "activated" | "rejected" | "saved"
  "hash": "<sha256>",       // present only when activated
  "rule_count": 55860,      // present only when activated
  "notes": ["refreshed 2 source(s)"]
}
```

`rejected` carries the verification notes or the list of protected names the
candidate would have blocked; the policy already in force keeps serving.
`POST /api/v1/sources/refresh` is rate limited and refreshes every enabled
source regardless of its interval.

### `BlockProfileRecord` — `settings.block_profiles`, both block-profile routes

```jsonc
{
  "id": "family",                 // slug derived from the name
  "emoji": "🛡️",                  // default "🧩"
  "name": "Family",
  "description": "…",
  "blocklists": [
    { "id": "oisd-small", "name": "OISD Small", "url": "https://small.oisd.nl", "kind": "preset", "family": "core-small" }
  ],
  "allowlists": ["pbskids.org"],
  "updated_at": "…"
}
```

Profiles are stored as one JSON blob under the `block_profiles` settings key.
Two are seeded when the key is absent: `family` (OISD Small + OISD NSFW Small)
and `focus` (OISD Small). The four presets are `oisd-small`, `oisd-big`,
`oisd-nsfw-small` and `oisd-nsfw`; within a family (`core-*`, `nsfw-*`) only
one is kept. `POST …/block-profiles` takes `{ id?, emoji, name, description?,
blocklists, allowlists }` and upserts by id (or by the slug of `name`);
`POST …/block-profiles/delete` takes `{ id }`. Both return the whole list.

A block profile is a stored preference only: nothing on the DNS path reads it.
Per-device policy is keyed on the `profile` column of `sources` (§7), not on
these records.

### `DeviceRecord` — `GET /api/v1/devices`, `settings.devices`

```jsonc
{
  "id": "<uuid>",
  "name": "Kitchen iPad",
  "ip_address": "192.0.2.20",
  "policy_mode": "global",              // "global" | "custom"
  "blocklist_profile_override": null,   // a sources.profile name; custom mode only
  "protection_override": "inherit",     // "inherit" | "bypass"; custom mode only
  "allowed_domains": [],                // suffix matches; custom mode only
  "service_overrides": []               // always empty; the column is kept for the schema
}
```

`POST /api/v1/devices` takes the same fields minus `service_overrides`; `id`
is optional (create). The mode and override strings are validated (`400` with
a reason) and `allowed_domains` is lowercased and de-duplicated. The write is
followed by a runtime device-policy reload. There is no delete route.

### `ResolverAccessStatus` — `GET /api/v1/resolver-access`

```jsonc
{
  "hostname": "cogwheel",              // $HOSTNAME or `hostname`, else null
  "dns_targets": ["192.0.2.10", "cogwheel"],
  "notes": ["Point devices at this hostname or IP directly in DNS settings; port 53 is already exposed.", "…"]
}
```

`dns_targets` is the sorted, de-duplicated union of
`COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS`, the request's `Host` header and —
when the DNS bind address is unspecified — every IPv4 from `hostname -I` that
is not `172.*` (Docker bridge noise). Hostnames carry `:port` when the
advertised port is not 53; IP literals never do.

### `POST /api/v1/runtime/pause` — `{ "minutes": 15 }`

Pauses blocking for every client until `now + minutes`; `POST …/resume` clears
it. While paused the runtime answers from an allow-all copy of the global
policy under its own cache scope, so resuming does not serve stale "allowed"
answers for blocked names.

## 6. Live stream — `GET /api/v1/events/stream`

Server-sent events with a single event name, `query`, one frame per answered
query:

```jsonc
{ "domain": "…", "client": "192.0.2.20", "deviceName": null, "blocked": false, "reason": null, "observedAt": "…" }
```

`deviceName` and `reason` are always `null` today. A `keep-alive` comment goes
out every 15 s. At most 32 subscribers; the 33rd gets `503`. Each subscriber
has a 256-frame buffer, and a lagging reader skips the frames it missed rather
than slowing the DNS path. Streams end when the server shuts down, so
`docker stop` does not hang on an open browser tab.

## 7. Refresh, verification and the per-device model

`refresh_sources_once(reason, only_source_ids)` is the one path every policy
change takes:

1. Record a refresh attempt for each selected source (settings key
   `source_refresh_state`, read back as `blocklist_statuses`).
2. Fetch and parse every selected enabled source (`cogwheel-lists`; bodies
   over 32 MiB are refused).
3. `verify_list` on each fetched body: a per-list invalid-line ratio over
   20 % returns `rejected` and nothing is installed.
4. `install_policy`: under the rebuild lock, every enabled source's kept body
   is compiled into one `ListIndex` (a list slot per source, in id order),
   devices are mapped to scopes, and the `Policy` is swapped into the runtime,
   emptying the answer cache.

Nothing about the compiled policy is written to storage.

Per-device policy, as the runtime applies it: a device is looked up by source
IP into `Policy::by_ip`; a device with filtering off resolves under the
unfiltered scope; otherwise its own allow rules (today's `allowed_domains`)
are consulted before the household rules, the protected suffixes and the
lists. The per-device **block** half is absent until the device model is
rebuilt.

Retention: `COGWHEEL_RETENTION__HISTORY_DAYS` (default 30; `0` keeps
everything and logs a warning) drives an hourly prune of the
`security_events`, `audit_events` and `notification_deliveries` tables. No
route writes those tables any more; the prune keeps upgraded databases bounded.

## 8. Configuration

Read by `cogwheel_api::AppConfig::load_from_env`, plus three variables read
directly in `main.rs`:

| Variable | Default | Notes |
|---|---|---|
| `COGWHEEL_PROFILE` | `home` | `dev` (loopback, `:30080` / `:30053`), `home` (`0.0.0.0:8080` / `:5353`), `smb` (`0.0.0.0:8080` / `:53`, 10-minute refresh). Only sets defaults. |
| `COGWHEEL_SERVER__HTTP_BIND_ADDR` | per profile | |
| `COGWHEEL_SERVER__DNS_UDP_BIND_ADDR` | per profile | |
| `COGWHEEL_SERVER__DNS_TCP_BIND_ADDR` | per profile | |
| `COGWHEEL_STORAGE__DATABASE_URL` | `sqlite://data/cogwheel.db` | prefix stripped; parent directory created |
| `COGWHEEL_UPSTREAM__SERVERS` | `1.1.1.1:53,1.0.0.1:53` | comma-separated; `tls://` and `https://` need `#name` |
| `COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS` | `300` | scheduler tick, floored at 30 |
| `COGWHEEL_BLOCKING__MODE` | `null_ip` | `null_ip` \| `nxdomain` \| `nodata` \| `refused` |
| `COGWHEEL_RETENTION__HISTORY_DAYS` | `30` | `0` disables pruning |
| `COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS` | `3600` | floored at 60 |
| `COGWHEEL_SERVER__ADVERTISED_DNS_PORT` | the DNS UDP bind port | read in `main.rs` |
| `COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS` | unset | comma-separated; read in `main.rs` |
| `COGWHEEL_WEB_DIST_DIR` | unset | read in `main.rs`; first candidate for the bundle |
| `RUST_LOG` | `info` | `EnvFilter`; `info` is always added on top |

An unparsable value aborts startup with `invalid environment value: …`.

## 9. Tests in `main.rs`

Three `event_bus_*` tests (slot release on drop, publish without subscribers,
delivery), the `normalize_*` validators, `baseline_source_id_is_reserved`,
`runtime_device_policies_clear_global_overrides`,
`build_runtime_policy_catalog_includes_shared_rules_in_profiles`,
`protected_domain_regressions_sees_through_protected_tier_and_checks_profiles`,
`source_refresh_state_tracks_attempts`,
`source_due_for_refresh_respects_interval`,
`encrypted_upstreams_have_trust_anchors_compiled_in`, the four `parse_cli`
cases and the three block-mode mapping tests. The health routes, configuration
loading and the ADR path-dependency guard are tested in `cogwheel-api`.
