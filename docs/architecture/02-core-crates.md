# 02 — Core Rust Crates: Internals Reference

The five library crates and the server binary as they stand after the cut to
the DNS-filtering core. Read from the crate sources; line numbers are omitted
because they move on every edit. The pre-cut reference (ten crates, including
machine-learning scoring, service bundles and sync) is on the `archive/full-featured`
branch.

---

## 1. Workspace map and dependency edges

### 1.1 Members (`Cargo.toml`)

| Member | Role | Lines (approx.) |
|---|---|---|
| `crates/cogwheel-policy` | rule model, `PolicyEngine::evaluate`, protected suffixes | 550 |
| `crates/cogwheel-lists` | fetch / parse / verify / compile blocklists | 520 |
| `crates/cogwheel-dns-core` | listeners, cache, per-client policy, upstream | 990 |
| `crates/cogwheel-storage` | SQLite schema, migrations, repositories, pruning | 740 |
| `crates/cogwheel-api` | env config, envelope, readiness, `/health/*`, upstream endpoint parser | 540 + 400 |
| `apps/cogwheel-server` | composition root, `/api/v1`, scheduler, SSE | 2,840 |

`resolver = "3"`, edition 2024; `[profile.release]` sets `codegen-units = 1`,
`lto = "thin"` and `strip = true`. Workspace clippy lints deny `dbg_macro`,
`todo`, `unwrap_used` and `panic`.

### 1.2 Path-dependency graph (enforced by a test)

```
cogwheel-policy      -> (none)
cogwheel-lists       -> cogwheel-policy
cogwheel-dns-core    -> cogwheel-policy
cogwheel-storage     -> (none)
cogwheel-api         -> (none)
apps/cogwheel-server -> all five
```

`crate_path_dependencies_match_the_adr_boundaries` in
`crates/cogwheel-api/src/lib.rs` reads the five library manifests and fails on
drift; see `docs/adr/0001-crate-boundaries.md` and
`docs/crate-boundary-guardrails.md`.

### 1.3 Third-party dependencies that matter

`axum` 0.8, `tower-http` 0.6 (compression, fs, trace), `hickory-proto` and
`hickory-resolver` 0.26 (`tls-ring`, `https-ring`, `webpki-roots`), `moka` 0.12
(future cache), `reqwest` 0.12 (rustls, no default features), `rusqlite` 0.37
(bundled SQLite), `tokio` 1.45, `serde`, `chrono`, `uuid`, `sha2`, `base64`,
`url`, `thiserror`, `anyhow`, `tracing`.

`webpki-roots` on hickory is not optional: without it the DoT/DoH trust store
is empty and every encrypted upstream fails validation. The server test
`encrypted_upstreams_have_trust_anchors_compiled_in` pins that.

---

## 2. `cogwheel-policy`

Leaf crate, `#![warn(missing_docs)]`, no I/O.

### 2.1 Public types

- `PROTECTED_SUFFIXES: [&str; 21]` — resolver bootstrap and connectivity-check
  names, NTP, and the CAs' status endpoints. Each is infrastructure a device
  needs to stay on the network and to explain what is wrong when it is not.
  Banking, government and health names are deliberately absent: blocking
  those is bad, but visible and reversible.
- `BlockMode` — `NullIp` (default), `NxDomain`, `NoData`, `Refused`,
  `CustomIp { ipv4, ipv6 }`. One per artifact, not per rule.
- `RulePattern` — `Exact(String)` | `Suffix(String)`.
- `RuleAction` — `Allow` | `Block`.
- `Rule { pattern, action, source, comment }`.
- `DecisionKind` — `Allowed` | `Blocked(BlockMode)`; `Decision { kind,
  matched_rule: Option<Rule> }`.
- `RulesetArtifact { id, hash, created_at, rules, protected_domains,
  block_mode }` and `RulesetArtifact::new(rules, protected, mode)`, which
  SHA-256-hashes the rules, the **sorted** protected set and the mode. The
  hash scopes the DNS response cache, so its stability across restarts is
  load-bearing (`artifact_hash_is_stable_across_protected_domain_ordering`).
- `PolicyEngine::new(artifact)`, `.artifact()`, `.evaluate(domain)`.
- `normalize_domain` — lowercase, trailing dot stripped; the one normalisation
  both rule patterns and lookups go through.

### 2.2 Evaluation order (`PolicyEngine::evaluate`)

1. Protected suffix match on a label boundary → `Allowed`, no rule.
2. First matching `Allow` rule → `Allowed`.
3. First matching `Block` rule → `Blocked(artifact.block_mode)`.
4. Otherwise `Allowed`.

Allow beats Block regardless of source order (`allow_precedes_block`). Suffix
rules match only on a label boundary
(`suffix_rules_match_only_on_label_boundaries`).

### 2.3 Performance shape

Two linear scans of `rules` per cache miss, a `String` allocation for the
normalised name, and a `format!(".{candidate}")` per suffix comparison. Cost
is proportional to ruleset size; this is the inner loop that the response
cache in `cogwheel-dns-core` exists to keep off the common path.

### 2.4 Tests (8)

Protected-tier precedence and boundary behaviour (4), hash stability and
sensitivity (2), suffix boundary matching, allow before block.

---

## 3. `cogwheel-lists`

Control-plane crate: it talks HTTP, so it is never on the DNS path.

### 3.1 Public types

- `SourceKind` — `Domains` | `Hosts` | `Adblock`.
- `SourceDefinition { id, name, url: Url, kind, enabled, profile,
  verification_strictness }`.
- `ParsedSource { source, fetched_at, etag (always None), checksum (hex
  SHA-256 of the body), rules, invalid_lines }`.
- `VerificationResult { passed, invalid_ratio, blocked_protected_domains,
  notes }`.
- `FetchError` — `Http(reqwest::Error)` | `TooLarge { bytes, limit }`.
- `MAX_SOURCE_BODY_BYTES = 32 MiB`.

### 3.2 Public functions

- `fetch_and_parse_source(client, source)` — GET with the size bound (a
  `data:` URL is decoded locally), then `parse_source`.
- `parse_source(source, body)` — blank lines and `#` / `!` comments skipped.
  `domains` never rejects a line and produces exact block rules; `hosts` takes
  the hostname field; `adblock` maps `||domain^` to a suffix block, `@@` to
  an allow, a bare name to an exact rule, and counts modifier (`$…`) and
  regex (`/…`) lines as invalid rather than approximating them.
- `verify_candidate(parsed, protected)` — aggregate invalid ratio ≤ 20 %;
  per-source ratio within its strictness (`strict` 5 %, `balanced` 20 %,
  `relaxed` 40 %); and a throwaway engine with **no** protected tier must not
  block any protected suffix. `passed` is true only when `notes` is empty.
- `compile_ruleset(parsed, protected, mode)` → `RulesetArtifact`;
  `build_policy_engine(...)` → `PolicyEngine`. Neither verifies; callers do.

### 3.3 Tests (4)

Adblock suffix and allow parsing, `data:` bodies, a suffix rule failing
protected-domain verification, a strict source rejecting a noisy body.

---

## 4. `cogwheel-dns-core` — the hot path

Depends on `cogwheel-policy` only; a test fails the build if the manifest
gains `reqwest`, `ureq`, `surf` or a known LLM client
(`docs/hot-path-guardrails.md`).

### 4.1 Public types

- `DnsRuntimeConfig { udp_bind_addr, tcp_bind_addr }`.
- `DnsRuntime` — holds the `TokioResolver`, the global `PolicyEngine`, an
  allow-all copy of it (block rules stripped; used for pause, bypass and
  device allow-lists), the per-profile engines, `devices_by_ip`, the
  query-activity observer, the pause deadline, two moka caches of 10,000
  entries each (the response cache keyed by `<scope>|<domain>`, and a fallback
  cache keyed by domain) and the counters.
- `DevicePolicyConfig { ip_address, policy_mode, blocklist_profile_override,
  protection_override, allowed_domains, blocked_domains }`.
- `QueryActivityEvent { domain, client_ip, blocked, observed_at }`.
- `DnsRuntimeStats` (atomics) and its `DnsRuntimeSnapshot`
  (`01-backend-api.md` §5).

### 4.2 Public functions

`DnsRuntime::new(resolver, policy)`, `replace_policy`,
`replace_policy_catalog(global, profiles)`, `replace_device_policies`,
`current_policy`, `set_query_activity_observer`, `snapshot`, `serve`,
`serve_with_ready_signal(config, on_ready, shutdown)`,
`pause_protection_until`, `resume_protection`, `protection_paused_until`.

### 4.3 UDP datagram → response (`handle_wire_query`)

1. `queries_total += 1`; parse the message; take the first question; lowercase
   the name and strip the trailing dot.
2. `policy_for_client(client_addr, domain)` → `(engine, cache_scope,
   forced_block_mode)`:
   - paused → the allow-all engine, scope `global-pause`;
   - no device for the source IP, or `policy_mode != custom` → the global
     engine, scope = the artifact hash;
   - a device `blocked_domains` suffix hit → the global engine, scope
     `device-block:<ip>`, forced block (never populated today);
   - a device `allowed_domains` suffix hit → allow-all, scope `device-allow:<ip>`;
   - `protection_override = bypass` → allow-all, scope `bypass`;
   - `blocklist_profile_override` naming a known profile → that engine, scope
     `profile:<name>`; otherwise the global engine.
3. Cache lookup on `<scope>|<domain>`. A live entry is a hit: counter,
   observer, latency sample, and the cached message re-stamped with the
   request id. An expired entry counts as `cache_expired_total` and is
   invalidated.
4. A forced block builds the blocked response, caches it and returns.
5. `engine.evaluate(domain)`. `Blocked` → the blocked response. `Allowed`
   without a matching allow rule → CNAME uncloaking: resolve the chain
   upstream up to `MAX_CNAME_UNCLOAK_DEPTH = 8` and block if any target is
   blocked (`cname_uncloaks_total`, `cname_blocks_total`).
6. Otherwise forward upstream (`resolver.lookup(domain, qtype)`). Success
   fills the fallback cache; failure increments `upstream_failures_total` and
   serves the fallback entry when there is one, ignoring its expiry
   (`fallback_served_total`), else the error becomes `SERVFAIL`.
7. Every answer is cached with `expires_at = now + cacheable_for(response)`:
   the smallest answer TTL clamped to 5 s … 3,600 s, or 60 s for a response
   with no answers.

TCP uses the standard two-byte length prefix and one query per connection;
both listeners stop on the shutdown watch.

### 4.4 Tests (13)

TTL clamping (5), `runtime_snapshot_starts_at_zero`, CNAME target extraction,
request-id adoption (2), `policy_cache_key_scopes_by_policy`,
`build_allow_all_policy_removes_block_rules`,
`domain_matches_override_supports_suffixes`, and the dependency guard.

---

## 5. `cogwheel-storage`

No path dependencies. One `rusqlite::Connection` behind a `Mutex`; every
method is `async fn` for call-site ergonomics but does its work synchronously
under the lock, so keep calls short.

### 5.1 Connection

`Storage::connect(url)` strips `sqlite://`, creates the parent directory,
opens the file, sets `journal_mode = WAL` and `foreign_keys = ON`, and applies
the eleven embedded migrations (`migrations/0001_init.sql` …
`0011_retention_indexes.sql`, tracked in `config_migrations`;
`SCHEMA_VERSION = 11`). A migration error is a hard failure — only the
"already applied" case is tolerated
(`a_real_migration_error_is_not_mistaken_for_already_applied`).

### 5.2 Tables

`sources`, `devices`, `settings` (key/value; holds `block_profiles` and
`source_refresh_state`), `rulesets` and `active_ruleset`, `audit_events`,
`security_events`, `notification_deliveries`, `config_schema`,
`config_migrations`. The schema is untouched by the cut: the ruleset tables,
the three history tables and the `service_overrides`, `policy_mode`,
`blocklist_profile_override`, `protection_override` and `allowed_domains`
columns on `devices` all still exist. Nothing writes the ruleset or history
tables any more; they are pruned, not populated.

### 5.3 Public API

- `upsert_setting(key, value)`, `get_setting(key)`.
- `insert_source` (`INSERT OR REPLACE`), `list_sources`, `delete_source`.
- `upsert_device`, `delete_device`, `list_devices`, `find_device_by_ip`.
- `prune_history_before(cutoff) -> PrunedHistory { security_events,
  audit_events, notification_deliveries }`.
- Dead but public until the storage rewrite: `record_security_event` /
  `recent_security_events` (`SecurityEventRecord`), `record_audit_event` /
  `recent_audit_events` (`AuditEvent`), `record_notification_delivery` /
  `recent_notification_deliveries` (`NotificationDeliveryRecord`). No route
  calls them.

### 5.4 Tests (6)

Migration idempotence and error discrimination (2); pruning (4: removes only
older rows, no-op when nothing is old, idempotent, never touches
configuration).

---

## 6. `cogwheel-api`

No path dependencies.

- `AppConfig::load()` / `load_from_env(getter)` / `for_profile` — the
  environment table in `01-backend-api.md` §8. `DeploymentProfile` is `dev`
  | `home` | `smb`.
- `BlockingConfig { mode: BlockResponseMode }` with the four modes and their
  accepted spellings; `RetentionConfig { history_days, prune_interval_secs }`;
  `UpdaterConfig`, `UpstreamConfig`, `StorageConfig`, `ServerConfig`.
- `ApiEnvelope<T> { data }`, `HealthResponse`, `ReadinessResponse`,
  `ReadinessDetail`, `Readiness` (three `AtomicBool`s with `mark_*_ready`).
- `router(state)` — `/health/live`, `/health/ready` (`503` until storage,
  policy and both DNS listeners are up).
- `upstream::{UpstreamEndpoint, UpstreamProtocol, UpstreamError}` — parses
  `host:port`, `tls://host#name` and `https://host#name/path`.
- Tests (5): profile defaults, dev ports, env override, invalid profile, the
  ADR path-dependency guard.

---

## 7. Error handling and lints

`unwrap_used` and `panic` are denied workspace-wide; `expect` appears in tests
only. Lock poisoning is recovered rather than propagated on the DNS path
(`read_recover`) — losing the policy must mean "resolve normally", never "take
the network offline" — and turned into a `StorageError::Internal` in storage,
where failing the one request is the safer choice. Public library APIs return
`thiserror` enums (`StorageError`, `ApiError`, `FetchError`); the server uses
`anyhow` at the composition boundary.
