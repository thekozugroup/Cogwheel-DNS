use anyhow::{Context, Result};
use axum::extract::{FromRef, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use cogwheel_api::{ApiEnvelope, ApiState, AppConfig, router};
use cogwheel_dns_core::{
    DnsRuntime, DnsRuntimeConfig, DnsRuntimeSnapshot, LogEntry, build_resolver,
    reserve_descriptor_table,
};
use cogwheel_lists::{
    FetchOutcome, ParsedList, SourceKind, build_index, fetch_source_body, parse_list,
    protected_hits, verify_list,
};
use cogwheel_policy::{
    Action, BlockMode, ListIndex, Policy, RuleSet, SCOPE_HOUSEHOLD, SCOPE_UNFILTERED, Scope,
    normalize_rule_domain,
};
use cogwheel_storage::{DeviceRecord, SourceRecord, Storage};
use futures::StreamExt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use url::Url;
use uuid::Uuid;

#[derive(Clone, FromRef)]
struct ServerState {
    api_state: ApiState,
    storage: Arc<Storage>,
    dns_runtime: Arc<DnsRuntime>,
    /// The last body successfully parsed for each source, by source id.
    ///
    /// The policy is always compiled from every enabled source, not just the ones a
    /// refresh happened to fetch, and a device edit recompiles scopes without touching
    /// the network at all. Both need the bodies to hand.
    lists: Arc<RwLock<HashMap<Uuid, ParsedList>>>,
    scopes: Arc<Mutex<ScopeAllocator>>,
    /// Serialises policy rebuilds so a device edit landing mid-refresh cannot install a
    /// policy compiled from the lists the refresh is about to replace.
    rebuild_lock: Arc<tokio::sync::Mutex<()>>,
    /// Device names by address, for attributing live query frames.
    device_names: Arc<RwLock<HashMap<IpAddr, String>>>,
    recent_dns_activity: Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    events: EventBus,
    shutdown: tokio::sync::watch::Receiver<bool>,
    rate_limiter: Arc<RateLimiter>,
    dns_udp_bind_addr: SocketAddr,
    advertised_dns_port: u16,
    advertised_dns_targets: Vec<String>,
}

#[derive(Clone)]
struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_secs: u64,
}

impl RateLimiter {
    fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_secs,
        }
    }

    fn is_allowed(&self, key: &str) -> bool {
        let now = Instant::now();
        // A poisoned lock means some other thread panicked mid-update. Failing open is the right
        // call here: rate limiting is a safeguard, and refusing every request afterwards would turn
        // one panic into a total outage of the control plane.
        let Ok(mut requests) = self.requests.lock() else {
            tracing::warn!("rate limiter lock poisoned; allowing request");
            return true;
        };

        let entry = requests.entry(key.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < Duration::from_secs(self.window_secs));

        if entry.len() >= self.max_requests {
            return false;
        }

        entry.push(now);
        true
    }
}

/// Enabled lists that fit in one policy: one bit of the scope mask each.
const MAX_LIST_SLOTS: usize = 64;

/// Entries taken off the query-log channel per wake-up of the drain task.
const LOG_BATCH: usize = 256;

/// The settings that make one device's filtering differ from another's: filtering on or
/// off, the list slots that apply, and its own rules in a canonical order.
type ScopeSignature = (bool, u64, Vec<(Box<str>, Action)>);

/// Hands out cache-scope ids by signature, so devices with identical settings share one.
///
/// This lives in [`ServerState`] rather than being rebuilt with each policy because the ids
/// are baked into cache keys. A device edit keeps the cache, so an id that meant "these
/// rules" before the edit must not mean different rules after it: a device whose settings
/// changed gets a fresh id and its old entries age out unread. Ids are never reused. A list
/// rebuild — which drops the cache anyway — starts a fresh table, because the same mask
/// value no longer names the same lists.
#[derive(Debug)]
struct ScopeAllocator {
    by_signature: HashMap<ScopeSignature, u32>,
    next: u32,
}

impl ScopeAllocator {
    fn new() -> Self {
        Self {
            by_signature: HashMap::new(),
            next: SCOPE_UNFILTERED + 1,
        }
    }

    /// Forget every signature; the next rebuild interns afresh, above every id ever handed out.
    fn reset(&mut self) {
        self.by_signature.clear();
    }

    /// The scope id for a device with these settings.
    ///
    /// A device whose settings equal the household's shares the household's scope and its
    /// cache, so a family of "default" devices costs nothing extra; filtering off is the
    /// reserved unfiltered scope whatever else is set.
    fn scope_id(&mut self, all_mask: u64, filtering: bool, mask: u64, rules: &RuleSet) -> u32 {
        if !filtering {
            return SCOPE_UNFILTERED;
        }
        if mask == all_mask && rules.is_empty() {
            return SCOPE_HOUSEHOLD;
        }
        let mut sorted = rules
            .iter()
            .map(|(domain, action)| (Box::<str>::from(domain), action))
            .collect::<Vec<_>>();
        sorted.sort_by(|left, right| left.0.cmp(&right.0));
        let Self { by_signature, next } = self;
        *by_signature
            .entry((filtering, mask, sorted))
            .or_insert_with(|| {
                let id = *next;
                *next += 1;
                id
            })
    }
}

/// What a refresh did with the sources it fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum RefreshOutcome {
    /// A policy compiled from the fetched bodies is now in force.
    Activated,
    /// A fetched body failed verification; nothing changed.
    Rejected,
    /// The source was saved without a refresh.
    Saved,
}

#[derive(serde::Serialize)]
struct RefreshResponse {
    outcome: RefreshOutcome,
    /// Entries in the policy now in force, when this refresh activated one.
    rule_count: Option<usize>,
    notes: Vec<String>,
}

#[derive(serde::Serialize)]
struct DashboardSummary {
    /// `Paused` or `Protected`.
    protection_status: String,
    protection_paused_until: Option<chrono::DateTime<chrono::Utc>>,
    policy: PolicySummary,
    source_count: usize,
    enabled_source_count: usize,
    device_count: usize,
    runtime: DnsRuntimeSnapshot,
    domain_insights: DomainInsights,
}

/// The policy in force.
#[derive(serde::Serialize)]
struct PolicySummary {
    /// Distinct list entries compiled into it.
    rule_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DomainInsightEntry {
    domain: String,
    count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DomainInsights {
    top_queried_domains: Vec<DomainInsightEntry>,
    top_blocked_domains: Vec<DomainInsightEntry>,
    observed_queries: usize,
}

#[derive(Debug, Clone)]
struct DomainActivityRecord {
    /// Shared with the runtime's cache key and log entry, so recording a query allocates
    /// nothing for the name.
    domain: Arc<str>,
    blocked: bool,
    observed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Serialize)]
struct SettingsSummary {
    blocklists: Vec<SourceRecord>,
    blocklist_statuses: Vec<BlocklistStatusView>,
    block_profiles: Vec<BlockProfileRecord>,
    devices: Vec<DeviceRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BlocklistStatusView {
    id: Uuid,
    name: String,
    last_refresh_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    due_for_refresh: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct SourceRefreshState {
    entries: Vec<SourceRefreshStateEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SourceRefreshStateEntry {
    source_id: Uuid,
    last_refresh_attempt_at: chrono::DateTime<chrono::Utc>,
}

impl SourceRefreshState {
    fn last_refresh_for(&self, source_id: Uuid) -> Option<chrono::DateTime<chrono::Utc>> {
        self.entries
            .iter()
            .find(|entry| entry.source_id == source_id)
            .map(|entry| entry.last_refresh_attempt_at)
    }

    fn record_attempt(&mut self, source_id: Uuid, refreshed_at: chrono::DateTime<chrono::Utc>) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.source_id == source_id)
        {
            entry.last_refresh_attempt_at = refreshed_at;
            return;
        }

        self.entries.push(SourceRefreshStateEntry {
            source_id,
            last_refresh_attempt_at: refreshed_at,
        });
    }
}

#[derive(serde::Deserialize)]
struct UpsertBlocklistRequest {
    id: Option<Uuid>,
    name: String,
    url: String,
    kind: String,
    enabled: bool,
    refresh_interval_minutes: Option<i64>,
    profile: Option<String>,
    verification_strictness: Option<String>,
    refresh_now: Option<bool>,
}

#[derive(serde::Deserialize)]
struct UpdateBlocklistStateRequest {
    id: Uuid,
    enabled: bool,
    refresh_now: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BlockProfileListRecord {
    id: String,
    name: String,
    url: String,
    kind: String,
    family: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BlockProfileRecord {
    id: String,
    emoji: String,
    name: String,
    description: String,
    blocklists: Vec<BlockProfileListRecord>,
    allowlists: Vec<String>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct UpsertBlockProfileRequest {
    id: Option<String>,
    emoji: String,
    name: String,
    description: Option<String>,
    blocklists: Vec<BlockProfileListRecord>,
    allowlists: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DeleteBlockProfileRequest {
    id: String,
}

#[derive(serde::Deserialize)]
struct DeleteBlocklistRequest {
    id: Uuid,
    refresh_now: Option<bool>,
}

#[derive(serde::Deserialize)]
struct UpsertDeviceRequest {
    id: Option<Uuid>,
    name: String,
    ip_address: String,
    policy_mode: Option<String>,
    blocklist_profile_override: Option<String>,
    protection_override: Option<String>,
    allowed_domains: Option<Vec<String>>,
}

/// Turn the configured mode into the response the DNS core will send.
fn resolve_block_mode(blocking: &cogwheel_api::BlockingConfig) -> BlockMode {
    use cogwheel_api::BlockResponseMode;

    match blocking.mode {
        BlockResponseMode::NullIp => BlockMode::NullIp,
        BlockResponseMode::NxDomain => BlockMode::NxDomain,
        BlockResponseMode::NoData => BlockMode::NoData,
        BlockResponseMode::Refused => BlockMode::Refused,
    }
}

const USAGE: &str = "\
cogwheel-server -- the Cogwheel DNS appliance

Usage:
  cogwheel-server            run the server
  cogwheel-server --version  print the version and exit
  cogwheel-server --help     print this message and exit

There are no other flags. Everything is configured by environment variable:
COGWHEEL_PROFILE, COGWHEEL_SERVER__*, COGWHEEL_STORAGE__*, COGWHEEL_UPSTREAM__*.
On an installed appliance those live in /etc/cogwheel/cogwheel.env. See
DEPLOYMENT.md for the full list.
";

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    /// Start the server.
    Run,
    /// Write this to stdout and exit 0.
    Print(String),
    /// Write this to stderr and exit 2.
    Fail(String),
}

/// Decide what to do with the command line before any side effects happen.
///
/// The important property is that an argument this binary does not understand
/// is a hard error rather than something it ignores. Previously every argument
/// except the literal `healthcheck` fell straight through and started the
/// server, so `cogwheel-server --version` on an appliance printed nothing and
/// quietly bound a SECOND resolver to :53 -- next to the one the service was
/// already running. For a process whose entire job is to take over the host's
/// DNS, refusing to start is the only safe response to input it cannot parse.
///
/// The `healthcheck` subcommand this replaces was dead code that returned
/// success unconditionally. Nothing invoked it (the container HEALTHCHECK uses
/// curl against /health/live), and a probe that reports healthy without
/// checking anything is worse than no probe at all, so it is gone rather than
/// preserved.
fn parse_cli(args: &[String]) -> CliAction {
    let Some(first) = args.first() else {
        return CliAction::Run;
    };
    match first.as_str() {
        "--version" | "-V" => {
            CliAction::Print(format!("cogwheel-server {}\n", env!("CARGO_PKG_VERSION")))
        }
        "--help" | "-h" => CliAction::Print(USAGE.to_string()),
        other => CliAction::Fail(format!(
            "cogwheel-server: unrecognised argument: {other}\n\n{USAGE}"
        )),
    }
}

/// Descriptors the table is grown to at boot: 512 misses in flight, each holding up to three
/// upstream sockets per attempt, plus the TCP fallbacks, listeners and HTTP connections — the
/// next doubling is never reached.
const DESCRIPTOR_TABLE_SLOTS: usize = 4096;

fn main() -> Result<()> {
    // Before the runtime: once its workers exist, growing the descriptor table is an RCU
    // grace period per doubling, paid on whichever worker's `socket()` call crosses the
    // boundary — under a retry wave, all of them at once.
    let descriptors = reserve_descriptor_table(DESCRIPTOR_TABLE_SLOTS);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build runtime")?
        .block_on(run(descriptors))
}

async fn run(descriptors: usize) -> Result<()> {
    // Before init_tracing: `--version` should print a version and nothing else,
    // not a version wrapped in JSON log lines.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    match parse_cli(&args) {
        CliAction::Run => {}
        CliAction::Print(message) => {
            print!("{message}");
            return Ok(());
        }
        CliAction::Fail(message) => {
            eprint!("{message}");
            std::process::exit(2);
        }
    }

    init_tracing();
    tracing::debug!(descriptors, "descriptor table reserved");

    let config = AppConfig::load()?;

    // Carried by every policy the runtime is handed, starting with the empty one it
    // boots on; later builds read it back from there rather than from a global.
    let block_mode = resolve_block_mode(&config.blocking);
    tracing::info!(mode = ?config.blocking.mode, response = ?block_mode, "blocked names will be answered with this");

    let storage = Arc::new(Storage::connect(&config.storage.database_url).await?);
    // Captured before `storage` is moved into the shared app state below.
    let retention_storage = storage.clone();

    let default_source = SourceRecord {
        id: Uuid::from_u128(1),
        name: "baseline".to_string(),
        url: "data:text/plain,ads.example.com%0Atracker.example.com".to_string(),
        kind: "domains".to_string(),
        enabled: true,
        refresh_interval_minutes: 60,
        profile: "essential".to_string(),
        verification_strictness: "strict".to_string(),
    };
    storage.insert_source(&default_source).await?;

    // Broadcast shutdown to everything that would otherwise outlive the signal: the DNS accept
    // loops, and every open SSE stream. Without this, `with_graceful_shutdown` waits forever for
    // an SSE connection that never ends on its own.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Readiness is reported per subsystem; each is marked as it genuinely comes up.
    let readiness = Arc::new(cogwheel_api::Readiness::default());
    // Storage is open and migrated by the time we get here -- `Storage::connect` applies migrations
    // and now fails loudly if any of them error.
    readiness.mark_storage_ready();

    let resolver = build_resolver(&config.upstream.servers)?;
    // The runtime boots on an empty policy -- every name resolves -- and takes the real
    // one the moment the sources below compile. The listeners come up either way, so a
    // household is never without DNS while a list downloads.
    let (dns_runtime, log_rx) = DnsRuntime::new(resolver, Arc::new(Policy::empty(block_mode)));
    let events = EventBus::new();
    let recent_dns_activity = Arc::new(Mutex::new(VecDeque::with_capacity(4096)));
    let device_names = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(drain_query_log(
        log_rx,
        events.clone(),
        Arc::clone(&recent_dns_activity),
        Arc::clone(&device_names),
    ));

    let dns_handle = tokio::spawn({
        let runtime = dns_runtime.clone();
        let dns_config = DnsRuntimeConfig {
            udp_bind_addr: config.server.dns_udp_bind_addr,
            tcp_bind_addr: config.server.dns_tcp_bind_addr,
        };
        let readiness = Arc::clone(&readiness);
        let dns_shutdown = shutdown_rx.clone();
        async move {
            runtime
                .serve_with_ready_signal(
                    dns_config,
                    move || {
                        readiness.mark_dns_ready();
                        tracing::info!("dns listeners bound");
                    },
                    dns_shutdown,
                )
                .await
        }
    });

    let app_state = ServerState {
        api_state: ApiState {
            readiness: Arc::clone(&readiness),
        },
        storage,
        dns_runtime,
        lists: Arc::new(RwLock::new(HashMap::new())),
        scopes: Arc::new(Mutex::new(ScopeAllocator::new())),
        rebuild_lock: Arc::new(tokio::sync::Mutex::new(())),
        device_names,
        recent_dns_activity,
        events,
        shutdown: shutdown_rx.clone(),
        rate_limiter: Arc::new(RateLimiter::new(100, 60)),
        dns_udp_bind_addr: config.server.dns_udp_bind_addr,
        advertised_dns_port: std::env::var("COGWHEEL_SERVER__ADVERTISED_DNS_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(config.server.dns_udp_bind_addr.port()),
        advertised_dns_targets: std::env::var("COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    };
    let activated = match refresh_sources_once(&app_state, "startup", None).await {
        Ok(response) if response.outcome == RefreshOutcome::Activated => true,
        Ok(response) => {
            tracing::warn!(notes = ?response.notes, "startup refresh did not activate a policy");
            false
        }
        Err(error) => {
            tracing::warn!(%error, "failed to compile the policy on startup");
            false
        }
    };
    if activated {
        readiness.mark_policy_ready();
    } else {
        // The node keeps serving -- an empty policy resolves everything rather than nothing --
        // but it must not advertise itself as ready, or a rolling upgrade would send traffic to
        // a node that is not actually filtering yet. Devices are still installed so bypasses
        // and the live stream's names are right from the first query.
        install_policy(&app_state, Rebuild::Devices).await?;
    }
    let refresh_handle = tokio::spawn({
        let state = app_state.clone();
        let refresh_every = config.updater.refresh_interval_secs.max(30);
        async move {
            let mut ticker = interval(Duration::from_secs(refresh_every));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let due_ids = match due_source_ids(&state).await {
                    Ok(ids) => ids,
                    Err(error) => {
                        tracing::warn!(%error, "scheduled source selection failed");
                        continue;
                    }
                };
                if due_ids.is_empty() {
                    continue;
                }
                if let Err(error) = refresh_sources_once(&state, "scheduled", Some(&due_ids)).await
                {
                    tracing::warn!(%error, "scheduled source refresh failed");
                }
            }
        }
    });
    // Retention. Without this the history tables grow for the life of the
    // appliance -- a disk problem on a small disk, and a permanent record of a
    // household's browsing on a product that exists to prevent exactly that.
    if config.retention.history_days == 0 {
        tracing::warn!(
            "history retention is disabled; observed history will be kept forever and the \
             database will grow without limit. Set COGWHEEL_RETENTION__HISTORY_DAYS to bound it."
        );
    } else {
        let history_days = i64::from(config.retention.history_days);
        let interval = Duration::from_secs(config.retention.prune_interval_secs);
        let mut retention_shutdown = shutdown_rx.clone();
        tracing::info!(
            days = config.retention.history_days,
            every_secs = config.retention.prune_interval_secs,
            "pruning observed history older than this"
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // The first tick fires immediately, which is wanted: an upgrade
            // from a version that never pruned should not wait an hour to act
            // on a database that may already be large.
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = retention_shutdown.wait_for(|stopping| *stopping) => break,
                }
                let cutoff = chrono::Utc::now() - chrono::Duration::days(history_days);
                match retention_storage.prune_history_before(cutoff).await {
                    Ok(pruned) if pruned.total() > 0 => tracing::info!(
                        rows = pruned.total(),
                        %cutoff,
                        "pruned history past the retention window"
                    ),
                    Ok(_) => tracing::debug!(%cutoff, "retention pass found nothing to prune"),
                    // A failed prune must not take the appliance down: DNS
                    // resolution does not depend on it, and a locked database
                    // during a refresh is a transient the next tick handles.
                    Err(error) => tracing::warn!(%error, "retention pass failed"),
                }
            }
        });
    }

    let app = build_http_app(app_state);
    let listener = tokio::net::TcpListener::bind(config.server.http_bind_addr)
        .await
        .context("bind http listener")?;

    // Graceful shutdown. Without this the process took the kernel default on SIGTERM and died
    // instantly, dropping every in-flight DNS query and upstream request and severing open SSE
    // streams. `docker stop` and `systemctl stop` both send SIGTERM, so this is the normal stop
    // path for the appliance, not an edge case.
    let shutdown = async {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };

        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                // If the handler cannot be installed we still want the other arm to work, so park
                // forever rather than resolving immediately and triggering a spurious shutdown.
                Err(error) => {
                    tracing::warn!(%error, "could not install SIGTERM handler");
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => tracing::info!("received SIGINT, shutting down"),
            () = terminate => tracing::info!("received SIGTERM, shutting down"),
        }
    };

    // Fan the signal out the moment it arrives, so the DNS listeners and every open SSE stream
    // begin winding down at the same time the HTTP server stops accepting.
    let shutdown_signal = async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    };

    // Borrow the handle so the select does not consume it: after the HTTP server drains we still
    // need to await the DNS task, and an early DNS failure must still abort startup.
    let mut dns_handle = dns_handle;
    tokio::select! {
        result = &mut dns_handle => {
            result.context("dns task join failure")??;
        }
        result = refresh_handle => {
            result.context("refresh task join failure")?;
        }
        // `with_graceful_shutdown` stops accepting new connections on the signal and waits for
        // in-flight requests to finish before returning.
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal) => {
            result.context("http server failure")?;
        }
    }

    // The HTTP server has drained. Give the DNS listeners a bounded window to finish whatever
    // query they were mid-way through; returning here without waiting would drop it, which is the
    // opposite of a graceful stop. The bound matters because a stuck upstream must not stop the
    // process from exiting -- supervisors escalate to SIGKILL.
    match tokio::time::timeout(Duration::from_secs(5), dns_handle).await {
        Ok(Ok(Ok(()))) => tracing::info!("dns listeners drained"),
        Ok(Ok(Err(error))) => tracing::warn!(%error, "dns listeners stopped with an error"),
        Ok(Err(error)) => tracing::warn!(%error, "dns task join failure during shutdown"),
        Err(_) => tracing::warn!("dns drain timed out; exiting anyway"),
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Read an `RwLock`, recovering the value even when the lock is poisoned.
///
/// Poisoning only records that some thread panicked while holding the lock. Every field guarded
/// this way holds a wholesale replacement, so the last committed value is still coherent, and
/// recovering it keeps a single panicking request from disabling the control plane for the rest of
/// the process lifetime.
fn read_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write to an `RwLock`, recovering the value even when the lock is poisoned. See [`read_recover`].
fn write_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Lock a `Mutex`, recovering the value even when it is poisoned. See [`read_recover`].
fn lock_recover<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::level_filters::LevelFilter::INFO.into()),
        )
        .json()
        .init();
}

/// Unix seconds now, the clock the runtime's pause deadline is measured on.
fn unix_now() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

/// Move answered queries off the runtime's channel into the live stream and the activity ring.
///
/// One task, batched. The runtime hands entries over with `try_send`, so anything slow here
/// shows up as `dropped_total` rather than as DNS latency. Frames are only built while a
/// browser is listening; the ring feeding the dashboard's top-domain tiles is always kept.
async fn drain_query_log(
    mut log_rx: mpsc::Receiver<LogEntry>,
    events: EventBus,
    recent: Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    device_names: Arc<RwLock<HashMap<IpAddr, String>>>,
) {
    let mut batch = Vec::with_capacity(LOG_BATCH);
    while log_rx.recv_many(&mut batch, LOG_BATCH).await > 0 {
        let streaming = events.sender.receiver_count() > 0;
        for entry in batch.drain(..) {
            let observed_at = chrono::DateTime::from_timestamp(i64::from(entry.ts), 0)
                .unwrap_or_else(chrono::Utc::now);
            record_recent_dns_activity(&recent, &entry, observed_at);
            if streaming {
                let device_name = read_recover(&device_names).get(&entry.client).cloned();
                events.publish(StreamEvent::Query(Box::new(query_frame(
                    &entry,
                    device_name,
                    observed_at,
                ))));
            }
        }
    }
}

/// The live-stream frame for one answered query.
fn query_frame(
    entry: &LogEntry,
    device_name: Option<String>,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> StreamQueryEvent {
    StreamQueryEvent {
        domain: entry.domain.to_string(),
        client: entry.client.to_string(),
        device_name,
        blocked: entry.verdict.is_blocked(),
        reason: Some(entry.verdict.reason().as_str().to_string()),
        observed_at: observed_at.to_rfc3339(),
    }
}

fn build_http_app(app_state: ServerState) -> Router {
    let api_app = router(app_state.clone()).merge(admin_router());

    let app = if let Some(web_dist_dir) = resolve_web_dist_dir() {
        tracing::info!(path = %web_dist_dir.display(), "serving bundled web assets");
        let index_path = web_dist_dir.join("index.html");
        // `not_found_service` serves index.html but keeps the 404 status, so every client-side
        // route (/activity, /devices, ...) returned "404 Not Found" with the app in the body.
        // Browsers render it, but uptime probes, `curl -f`, proxies and crawlers all treat a deep
        // link as broken. Rewrite the status so a served SPA route reports success.
        let spa = ServeDir::new(web_dist_dir).not_found_service(ServeFile::new(index_path));
        api_app.fallback_service(tower::service_fn(
            move |request: axum::http::Request<axum::body::Body>| {
                let spa = spa.clone();
                // Only a client-side route gets its status rewritten. A missing asset must stay a
                // real 404: rewriting those too would make every typo'd bundle path return the HTML
                // shell with 200, which hides broken deploys from caches and monitoring alike.
                let is_spa_route = {
                    let path = request.uri().path();
                    // An unmatched API path is a genuine 404, not a client-side route. Without this
                    // exclusion a typo'd or removed endpoint answered 200 with the HTML shell,
                    // which turns a broken integration into a silent one.
                    !path.starts_with("/api/")
                        && !path.starts_with("/health/")
                        && !path.starts_with("/assets/")
                        && !path
                            .rsplit('/')
                            .next()
                            .is_some_and(|segment| segment.contains('.'))
                };
                async move {
                    let mut response = tower::ServiceExt::oneshot(spa, request)
                        .await
                        .map(axum::response::IntoResponse::into_response)?;
                    if is_spa_route && response.status() == axum::http::StatusCode::NOT_FOUND {
                        *response.status_mut() = axum::http::StatusCode::OK;
                    }
                    Ok::<_, std::convert::Infallible>(response)
                }
            },
        ))
    } else {
        tracing::warn!("web assets not found; serving API routes only");
        api_app
    };

    app.with_state(app_state)
        // The control plane is served to phones over a LAN. The JS and CSS bundles compress by
        // roughly 4x, so serving them raw wastes about half a megabyte on every cold load for no
        // reason. Compression is applied to the whole router rather than just the static files so
        // large JSON responses (query logs, settings) benefit too.
        .layer(CompressionLayer::new().br(true).gzip(true))
        .layer(TraceLayer::new_for_http())
}

fn resolve_web_dist_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(path) = std::env::var("COGWHEEL_WEB_DIST_DIR") {
        candidates.push(PathBuf::from(path));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join("apps/cogwheel-web/dist"));
        candidates.push(current_dir.join("dist"));
    }

    candidates.push(PathBuf::from("/app/web"));

    candidates
        .into_iter()
        .find(|candidate| candidate.join("index.html").is_file())
}

fn admin_router() -> Router<ServerState> {
    Router::new()
        .route("/api/v1/dashboard", get(dashboard_summary))
        .route("/api/v1/settings", get(settings_summary))
        .route(
            "/api/v1/settings/block-profiles",
            post(upsert_block_profile),
        )
        .route(
            "/api/v1/settings/block-profiles/delete",
            post(delete_block_profile),
        )
        .route("/api/v1/settings/blocklists", post(upsert_blocklist))
        .route(
            "/api/v1/settings/blocklists/state",
            post(update_blocklist_state),
        )
        .route("/api/v1/settings/blocklists/delete", post(delete_blocklist))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices", post(upsert_device))
        .route("/api/v1/sources", get(list_sources))
        .route("/api/v1/sources/refresh", post(refresh_sources))
        .route("/api/v1/events/stream", get(events_stream))
        .route("/api/v1/runtime", get(runtime_snapshot))
        .route("/api/v1/runtime/pause", post(pause_runtime))
        .route("/api/v1/runtime/resume", post(resume_runtime))
        .route("/api/v1/resolver-access", get(resolver_access_status))
}

async fn list_sources(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<Vec<SourceRecord>>>, axum::http::StatusCode> {
    state
        .storage
        .list_sources()
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn list_devices(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<Vec<DeviceRecord>>>, axum::http::StatusCode> {
    state
        .storage
        .list_devices()
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn upsert_device(
    State(state): State<ServerState>,
    Json(request): Json<UpsertDeviceRequest>,
) -> Result<Json<ApiEnvelope<DeviceRecord>>, (axum::http::StatusCode, String)> {
    let policy_mode = normalize_device_policy_mode(
        request.policy_mode.as_deref().unwrap_or("global"),
    )
    .ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "device policy mode must be either global or custom".to_string(),
    ))?;
    let protection_override = normalize_device_protection_override(
        request.protection_override.as_deref().unwrap_or("inherit"),
    )
    .ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "device protection override must be either inherit or bypass".to_string(),
    ))?;
    let device = DeviceRecord {
        id: request.id.unwrap_or_else(Uuid::new_v4),
        name: request.name,
        ip_address: request.ip_address,
        policy_mode,
        blocklist_profile_override: request
            .blocklist_profile_override
            .as_deref()
            .and_then(normalize_profile_name),
        protection_override,
        allowed_domains: normalize_device_allowed_domains(
            request.allowed_domains.unwrap_or_default(),
        ),
        // Per-device block rules have no source until the device model is
        // rebuilt; the column is written empty rather than carried over from a
        // feature that no longer exists.
        service_overrides: Vec::new(),
    };

    state.storage.upsert_device(&device).await.map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist device".to_string(),
        )
    })?;

    install_policy(&state, Rebuild::Devices)
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to apply runtime device policies".to_string(),
            )
        })?;

    Ok(Json(ApiEnvelope { data: device }))
}

async fn dashboard_summary(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<DashboardSummary>>, axum::http::StatusCode> {
    let sources = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let devices = state
        .storage
        .list_devices()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let domain_insights = build_domain_insights(&state);
    let protection_paused_until = pause_deadline(&state.dns_runtime);

    Ok(Json(ApiEnvelope {
        data: DashboardSummary {
            protection_status: if protection_paused_until.is_some() {
                "Paused".to_string()
            } else {
                "Protected".to_string()
            },
            protection_paused_until,
            policy: PolicySummary {
                rule_count: state.dns_runtime.current_policy().index.len(),
            },
            source_count: sources.len(),
            enabled_source_count: sources.iter().filter(|source| source.enabled).count(),
            device_count: devices.len(),
            runtime: state.dns_runtime.snapshot(),
            domain_insights,
        },
    }))
}

/// When the current pause ends, if one is running.
fn pause_deadline(runtime: &DnsRuntime) -> Option<chrono::DateTime<chrono::Utc>> {
    let until = runtime.pause_until();
    if until <= unix_now() {
        return None;
    }
    chrono::DateTime::from_timestamp(i64::try_from(until).ok()?, 0)
}

fn record_recent_dns_activity(
    activity: &Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    entry: &LogEntry,
    observed_at: chrono::DateTime<chrono::Utc>,
) {
    let mut guard = lock_recover(activity);
    let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
    while let Some(front) = guard.front() {
        if front.observed_at >= cutoff && guard.len() < 4096 {
            break;
        }
        guard.pop_front();
    }
    guard.push_back(DomainActivityRecord {
        domain: Arc::clone(&entry.domain),
        blocked: entry.verdict.is_blocked(),
        observed_at,
    });
}

fn build_domain_insights(state: &ServerState) -> DomainInsights {
    let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
    let guard = lock_recover(&state.recent_dns_activity);

    let mut queried = HashMap::<Arc<str>, usize>::new();
    let mut blocked = HashMap::<Arc<str>, usize>::new();
    let mut observed_queries = 0usize;

    for item in guard.iter().filter(|item| item.observed_at >= cutoff) {
        observed_queries += 1;
        *queried.entry(Arc::clone(&item.domain)).or_default() += 1;
        if item.blocked {
            *blocked.entry(Arc::clone(&item.domain)).or_default() += 1;
        }
    }

    DomainInsights {
        top_queried_domains: top_domain_entries(&queried),
        top_blocked_domains: top_domain_entries(&blocked),
        observed_queries,
    }
}

fn top_domain_entries(counts: &HashMap<Arc<str>, usize>) -> Vec<DomainInsightEntry> {
    let mut entries = counts
        .iter()
        .map(|(domain, count)| DomainInsightEntry {
            domain: domain.to_string(),
            count: *count,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.domain.cmp(&right.domain))
    });
    entries.truncate(6);
    entries
}

async fn settings_summary(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<SettingsSummary>>, axum::http::StatusCode> {
    let blocklists = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let devices = state
        .storage
        .list_devices()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let blocklist_statuses = build_blocklist_status_views(&state, &blocklists)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let block_profiles = load_block_profiles(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: SettingsSummary {
            blocklists,
            blocklist_statuses,
            block_profiles,
            devices,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct ResolverAccessStatus {
    hostname: Option<String>,
    dns_targets: Vec<String>,
    notes: Vec<String>,
}

async fn resolver_access_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<ResolverAccessStatus>>, axum::http::StatusCode> {
    let dns_targets = discover_dns_targets(
        state.advertised_dns_port,
        state.dns_udp_bind_addr,
        &headers,
        &state.advertised_dns_targets,
    );
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| read_command_output("hostname", &[]));

    let mut notes = if state.advertised_dns_port == 53 {
        vec!["Point devices at this hostname or IP directly in DNS settings; port 53 is already exposed.".to_string()]
    } else {
        vec![format!(
            "Point devices at port {} for DNS on this deployment.",
            state.advertised_dns_port
        )]
    };
    if state.advertised_dns_port == 53 {
        notes.push(
            "Android tablets and phones should use the Wi-Fi network DNS setting with the LAN IP shown here; Android Private DNS expects DNS-over-TLS and is not the right mode for this deployment."
                .to_string(),
        );
        notes.push(
            "On dual-stack networks, also point clients or your router at Cogwheel's IPv6 DNS target; otherwise IPv6 lookups can bypass the IPv4-only filter path."
                .to_string(),
        );
    }

    Ok(Json(ApiEnvelope {
        data: ResolverAccessStatus {
            hostname,
            dns_targets,
            notes,
        },
    }))
}

fn discover_dns_targets(
    advertised_port: u16,
    bind_addr: SocketAddr,
    headers: &HeaderMap,
    configured_targets: &[String],
) -> Vec<String> {
    let mut targets = Vec::new();

    for target in configured_targets {
        targets.push(format_dns_target(target, advertised_port));
    }

    if let Some(host) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or(value).trim())
        .filter(|value| !value.is_empty())
    {
        targets.push(format_dns_target(host, advertised_port));
    }

    if bind_addr.ip().is_unspecified() {
        for ip in discover_local_ipv4s() {
            if !ip.starts_with("172.") {
                targets.push(format_dns_target(&ip, advertised_port));
            }
        }
    } else {
        targets.push(format_dns_target(
            &bind_addr.ip().to_string(),
            advertised_port,
        ));
    }

    if targets.is_empty() {
        targets.push(format_dns_target("127.0.0.1", advertised_port));
    }

    targets.sort();
    targets.dedup();
    targets
}

fn format_dns_target(host: &str, port: u16) -> String {
    if host.contains(':') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return host.to_string();
    }
    if port == 53 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    }
}

/// Every IPv4 address the host answers on, from `hostname -I`.
///
/// One shell-out, deliberately. Enumerating interfaces properly needs `ip` and
/// a netlink parser; `hostname -I` is on every Debian-family image this ships
/// on and is exactly the list a person would copy into a router's DNS field.
fn discover_local_ipv4s() -> Vec<String> {
    read_command_output("hostname", &["-I"])
        .map(|output| {
            output
                .split_whitespace()
                .filter(|value| value.parse::<std::net::Ipv4Addr>().is_ok())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn read_command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

async fn runtime_snapshot(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<DnsRuntimeSnapshot>>, axum::http::StatusCode> {
    Ok(Json(ApiEnvelope {
        data: state.dns_runtime.snapshot(),
    }))
}

#[derive(serde::Deserialize)]
struct PauseRuntimeRequest {
    minutes: u32,
}

async fn pause_runtime(State(state): State<ServerState>, Json(request): Json<PauseRuntimeRequest>) {
    let until = chrono::Utc::now() + chrono::Duration::minutes(i64::from(request.minutes));
    state
        .dns_runtime
        .set_pause_until(u64::try_from(until.timestamp()).unwrap_or(0));
    tracing::info!(minutes = request.minutes, %until, "protection paused");
}

async fn resume_runtime(State(state): State<ServerState>) {
    state.dns_runtime.set_pause_until(0);
    tracing::info!("protection resumed");
}

async fn refresh_sources(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
    if !state.rate_limiter.is_allowed("refresh_sources") {
        return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    refresh_sources_once(&state, "manual", None)
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn upsert_blocklist(
    State(state): State<ServerState>,
    Json(request): Json<UpsertBlocklistRequest>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
    if !state.rate_limiter.is_allowed("upsert_blocklist") {
        return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    let normalized_kind =
        normalize_source_kind(&request.kind).ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    Url::parse(&request.url).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    let source = SourceRecord {
        id: request.id.unwrap_or_else(Uuid::new_v4),
        name: request.name,
        url: request.url,
        kind: normalized_kind,
        enabled: request.enabled,
        refresh_interval_minutes: request.refresh_interval_minutes.unwrap_or(60).max(1),
        profile: normalize_profile_name(request.profile.as_deref().unwrap_or("custom"))
            .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
        verification_strictness: normalize_verification_strictness(
            request
                .verification_strictness
                .as_deref()
                .unwrap_or("balanced"),
        )
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
    };
    state
        .storage
        .insert_source(&source)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if request.refresh_now.unwrap_or(true) && source.enabled {
        return refresh_sources_once(&state, "blocklist-update", None)
            .await
            .map(|data| Json(ApiEnvelope { data }))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(ApiEnvelope {
        data: RefreshResponse {
            outcome: RefreshOutcome::Saved,
            rule_count: None,
            notes: vec![format!("saved blocklist {}", source.name)],
        },
    }))
}

async fn update_blocklist_state(
    State(state): State<ServerState>,
    Json(request): Json<UpdateBlocklistStateRequest>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
    let mut source = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .find(|source| source.id == request.id)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    if is_reserved_source_id(source.id) && !request.enabled {
        return Err(axum::http::StatusCode::CONFLICT);
    }

    source.enabled = request.enabled;
    state
        .storage
        .insert_source(&source)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if request.refresh_now.unwrap_or(true) {
        return refresh_sources_once(&state, "blocklist-state-update", None)
            .await
            .map(|data| Json(ApiEnvelope { data }))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(ApiEnvelope {
        data: RefreshResponse {
            outcome: RefreshOutcome::Saved,
            rule_count: None,
            notes: vec![format!(
                "{} blocklist {}",
                if source.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                source.name
            )],
        },
    }))
}

async fn delete_blocklist(
    State(state): State<ServerState>,
    Json(request): Json<DeleteBlocklistRequest>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
    if is_reserved_source_id(request.id) {
        return Err(axum::http::StatusCode::CONFLICT);
    }

    let source = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .find(|source| source.id == request.id)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    let deleted = state
        .storage
        .delete_source(request.id)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    if !deleted {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    if request.refresh_now.unwrap_or(true) {
        return refresh_sources_once(&state, "blocklist-delete", None)
            .await
            .map(|data| Json(ApiEnvelope { data }))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(ApiEnvelope {
        data: RefreshResponse {
            outcome: RefreshOutcome::Saved,
            rule_count: None,
            notes: vec![format!("deleted blocklist {}", source.name)],
        },
    }))
}

/// Fetch the selected enabled sources and put a policy compiled from every enabled source
/// in force.
///
/// `only_source_ids` narrows what is downloaded, not what is compiled: the scheduler passes
/// the sources whose interval has elapsed, and the rest are compiled from the bodies kept
/// since their last fetch. A body that fails verification rejects the whole refresh, exactly
/// as before -- nothing is installed and the previous policy keeps serving -- so a single bad
/// list can never take the others out with it.
async fn refresh_sources_once(
    state: &ServerState,
    reason: &str,
    only_source_ids: Option<&HashSet<Uuid>>,
) -> Result<RefreshResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("build refresh http client")?;

    let sources = state.storage.list_sources().await?;
    let selected = sources
        .iter()
        .filter(|source| source.enabled)
        .filter(|source| {
            only_source_ids
                .map(|ids| ids.contains(&source.id))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    anyhow::ensure!(!selected.is_empty(), "no enabled sources configured");

    let source_ids = selected.iter().map(|source| source.id).collect::<Vec<_>>();
    update_source_refresh_attempts(&state.storage, &source_ids, chrono::Utc::now()).await?;

    let mut fetched = Vec::with_capacity(selected.len());
    for source in &selected {
        let parsed = fetch_and_parse(&client, source)
            .await
            .with_context(|| format!("fetch source {}", source.name))?;
        if let Err(problem) = verify_list(&parsed) {
            tracing::warn!(
                reason,
                source = %source.name,
                %problem,
                "refresh rejected before activation"
            );
            return Ok(RefreshResponse {
                outcome: RefreshOutcome::Rejected,
                rule_count: None,
                notes: vec![format!("{}: {problem}", source.name)],
            });
        }
        fetched.push((source.id, parsed));
    }

    {
        let mut lists = write_recover(&state.lists);
        for (source_id, parsed) in fetched {
            lists.insert(source_id, parsed);
        }
    }

    let installed = install_policy(state, Rebuild::Lists).await?;
    tracing::info!(
        reason,
        rule_count = installed.rule_count,
        "activated refreshed policy"
    );

    let mut notes = vec![format!("refreshed {} source(s)", selected.len())];
    notes.extend(installed.notes);
    Ok(RefreshResponse {
        outcome: RefreshOutcome::Activated,
        rule_count: Some(installed.rule_count),
        notes,
    })
}

/// Download one source and parse it for its kind.
///
/// Unconditional for now: no validators are stored yet, so a 304 cannot legitimately
/// happen and is reported rather than treated as "nothing changed".
async fn fetch_and_parse(client: &reqwest::Client, source: &SourceRecord) -> Result<ParsedList> {
    let kind = source
        .kind
        .parse::<SourceKind>()
        .ok()
        .with_context(|| format!("unsupported source kind: {}", source.kind))?;
    let url = Url::parse(&source.url)?;
    match fetch_source_body(client, &url, None, None).await? {
        FetchOutcome::Body { text, .. } => Ok(parse_list(kind, &text)),
        FetchOutcome::NotModified => {
            anyhow::bail!("upstream answered 304 to an unconditional request")
        }
    }
}

async fn load_block_profiles(storage: &Storage) -> Result<Vec<BlockProfileRecord>> {
    let Some(value) = storage.get_setting("block_profiles").await? else {
        return Ok(default_block_profiles());
    };

    let parsed = serde_json::from_str::<Vec<StoredBlockProfileRecord>>(&value)
        .map(|profiles| {
            profiles
                .into_iter()
                .map(StoredBlockProfileRecord::into_block_profile)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|_| default_block_profiles());
    Ok(normalize_block_profiles(parsed))
}

async fn persist_block_profiles(storage: &Storage, profiles: &[BlockProfileRecord]) -> Result<()> {
    storage
        .upsert_setting("block_profiles", &serde_json::to_string(profiles)?)
        .await?;
    Ok(())
}

fn default_block_profiles() -> Vec<BlockProfileRecord> {
    let now = chrono::Utc::now();
    vec![
        BlockProfileRecord {
            id: "family".to_string(),
            emoji: "🛡️".to_string(),
            name: "Family".to_string(),
            description: "Covers the everyday family setup with the core OISD list plus lighter NSFW filtering."
                .to_string(),
            blocklists: ["oisd-small", "oisd-nsfw-small"]
                .into_iter()
                .filter_map(preset_block_profile_list)
                .collect(),
            allowlists: vec!["pbskids.org".to_string(), "khanacademy.org".to_string()],
            updated_at: now,
        },
        BlockProfileRecord {
            id: "focus".to_string(),
            emoji: "🌿".to_string(),
            name: "Focus".to_string(),
            description: "A quieter setup for work or school devices with the smaller OISD core list only."
                .to_string(),
            blocklists: ["oisd-small"]
                .into_iter()
                .filter_map(preset_block_profile_list)
                .collect(),
            allowlists: vec!["calendar.google.com".to_string(), "notion.so".to_string()],
            updated_at: now,
        },
    ]
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
enum StoredBlockProfileListRecord {
    Id(String),
    Record(BlockProfileListRecord),
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StoredBlockProfileRecord {
    id: String,
    emoji: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    blocklists: Vec<StoredBlockProfileListRecord>,
    #[serde(default)]
    allowlists: Vec<String>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl StoredBlockProfileRecord {
    fn into_block_profile(self) -> BlockProfileRecord {
        let now = chrono::Utc::now();
        BlockProfileRecord {
            id: self.id,
            emoji: self.emoji,
            name: self.name,
            description: self.description,
            blocklists: self
                .blocklists
                .into_iter()
                .filter_map(|entry| match entry {
                    StoredBlockProfileListRecord::Id(id) => legacy_block_profile_list(&id),
                    StoredBlockProfileListRecord::Record(record) => Some(record),
                })
                .collect(),
            allowlists: self.allowlists,
            updated_at: self.updated_at.unwrap_or(now),
        }
    }
}

fn preset_block_profile_lists() -> Vec<BlockProfileListRecord> {
    vec![
        BlockProfileListRecord {
            id: "oisd-small".to_string(),
            name: "OISD Small".to_string(),
            url: "https://small.oisd.nl".to_string(),
            kind: "preset".to_string(),
            family: "core-small".to_string(),
        },
        BlockProfileListRecord {
            id: "oisd-big".to_string(),
            name: "OISD Big".to_string(),
            url: "https://big.oisd.nl".to_string(),
            kind: "preset".to_string(),
            family: "core-full".to_string(),
        },
        BlockProfileListRecord {
            id: "oisd-nsfw-small".to_string(),
            name: "OISD NSFW Small".to_string(),
            url: "https://nsfw-small.oisd.nl".to_string(),
            kind: "preset".to_string(),
            family: "nsfw-small".to_string(),
        },
        BlockProfileListRecord {
            id: "oisd-nsfw".to_string(),
            name: "OISD NSFW".to_string(),
            url: "https://nsfw.oisd.nl".to_string(),
            kind: "preset".to_string(),
            family: "nsfw-full".to_string(),
        },
    ]
}

fn preset_block_profile_list(id: &str) -> Option<BlockProfileListRecord> {
    preset_block_profile_lists()
        .into_iter()
        .find(|entry| entry.id == id)
}

fn legacy_block_profile_list(id: &str) -> Option<BlockProfileListRecord> {
    match id {
        "essential" => preset_block_profile_list("oisd-small"),
        "balanced" => preset_block_profile_list("oisd-big"),
        "aggressive" => preset_block_profile_list("oisd-big"),
        other => preset_block_profile_list(other),
    }
}

fn normalize_block_profile_id(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() {
                char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_block_profile_name(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn normalize_domain_list(entries: Vec<String>) -> Vec<String> {
    let mut normalized = entries
        .into_iter()
        .flat_map(|entry| entry.split(',').map(str::to_string).collect::<Vec<_>>())
        .filter_map(|entry| {
            let trimmed = entry.trim().trim_matches('.').to_ascii_lowercase();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn normalize_block_profile_list_name(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn normalize_block_profile_list_url(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_block_profile_lists(
    entries: Vec<BlockProfileListRecord>,
) -> Vec<BlockProfileListRecord> {
    let mut normalized = entries
        .into_iter()
        .filter_map(|entry| {
            if let Some(preset) = preset_block_profile_list(&entry.id) {
                return Some(preset);
            }

            let name = normalize_block_profile_list_name(&entry.name)?;
            let url = normalize_block_profile_list_url(&entry.url)?;
            let id = normalize_block_profile_id(&entry.id)
                .or_else(|| normalize_block_profile_id(&name))
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            Some(BlockProfileListRecord {
                id,
                name,
                url,
                kind: if entry.kind.trim().is_empty() {
                    "custom".to_string()
                } else {
                    entry.kind.trim().to_string()
                },
                family: if entry.family.trim().is_empty() {
                    "custom".to_string()
                } else {
                    entry.family.trim().to_string()
                },
            })
        })
        .collect::<Vec<_>>();

    let has_core_full = normalized.iter().any(|entry| entry.id == "oisd-big");
    let has_nsfw_full = normalized.iter().any(|entry| entry.id == "oisd-nsfw");
    if has_core_full {
        normalized.retain(|entry| entry.id != "oisd-small");
    }
    if has_nsfw_full {
        normalized.retain(|entry| entry.id != "oisd-nsfw-small");
    }

    normalized.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    normalized.dedup_by(|left, right| left.id == right.id || left.url == right.url);
    normalized
}

fn normalize_block_profiles(mut profiles: Vec<BlockProfileRecord>) -> Vec<BlockProfileRecord> {
    for profile in &mut profiles {
        profile.id = normalize_block_profile_id(&profile.id)
            .or_else(|| normalize_block_profile_id(&profile.name))
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        profile.name = normalize_block_profile_name(&profile.name)
            .unwrap_or_else(|| "Untitled profile".to_string());
        profile.emoji = profile.emoji.trim().to_string();
        if profile.emoji.is_empty() {
            profile.emoji = "🧩".to_string();
        }
        profile.description = profile.description.trim().to_string();
        profile.blocklists = normalize_block_profile_lists(profile.blocklists.clone());
        profile.allowlists = normalize_domain_list(profile.allowlists.clone());
    }

    profiles.sort_by(|left, right| left.name.cmp(&right.name));
    profiles.dedup_by(|left, right| left.id == right.id);
    profiles
}

async fn upsert_block_profile(
    State(state): State<ServerState>,
    Json(request): Json<UpsertBlockProfileRequest>,
) -> Result<Json<ApiEnvelope<Vec<BlockProfileRecord>>>, (axum::http::StatusCode, String)> {
    let profile_id = request
        .id
        .as_deref()
        .and_then(normalize_block_profile_id)
        .or_else(|| normalize_block_profile_id(&request.name))
        .ok_or((
            axum::http::StatusCode::BAD_REQUEST,
            "block profile requires a name".to_string(),
        ))?;
    let profile_name = normalize_block_profile_name(&request.name).ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "block profile requires a friendly name".to_string(),
    ))?;

    let mut profiles = load_block_profiles(&state.storage).await.map_err(|error| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            error.to_string(),
        )
    })?;

    let next_profile = BlockProfileRecord {
        id: profile_id.clone(),
        emoji: if request.emoji.trim().is_empty() {
            "🧩".to_string()
        } else {
            request.emoji.trim().to_string()
        },
        name: profile_name,
        description: request.description.unwrap_or_default().trim().to_string(),
        blocklists: normalize_block_profile_lists(request.blocklists),
        allowlists: normalize_domain_list(request.allowlists),
        updated_at: chrono::Utc::now(),
    };

    if let Some(existing) = profiles.iter_mut().find(|profile| profile.id == profile_id) {
        *existing = next_profile;
    } else {
        profiles.push(next_profile);
    }

    let profiles = normalize_block_profiles(profiles);
    persist_block_profiles(&state.storage, &profiles)
        .await
        .map_err(|error| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
            )
        })?;

    Ok(Json(ApiEnvelope { data: profiles }))
}

async fn delete_block_profile(
    State(state): State<ServerState>,
    Json(request): Json<DeleteBlockProfileRequest>,
) -> Result<Json<ApiEnvelope<Vec<BlockProfileRecord>>>, (axum::http::StatusCode, String)> {
    let profile_id = normalize_block_profile_id(&request.id).ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "block profile requires an id".to_string(),
    ))?;

    let mut profiles = load_block_profiles(&state.storage).await.map_err(|error| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            error.to_string(),
        )
    })?;

    if !profiles.iter().any(|profile| profile.id == profile_id) {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "block profile not found".to_string(),
        ));
    }

    profiles.retain(|profile| profile.id != profile_id);

    persist_block_profiles(&state.storage, &profiles)
        .await
        .map_err(|error| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
            )
        })?;

    Ok(Json(ApiEnvelope { data: profiles }))
}

async fn load_source_refresh_state(storage: &Storage) -> Result<SourceRefreshState> {
    let Some(value) = storage.get_setting("source_refresh_state").await? else {
        return Ok(SourceRefreshState::default());
    };
    Ok(serde_json::from_str(&value).unwrap_or_default())
}

async fn build_blocklist_status_views(
    state: &ServerState,
    blocklists: &[SourceRecord],
) -> Result<Vec<BlocklistStatusView>> {
    let refresh_state = load_source_refresh_state(&state.storage).await?;
    let now = chrono::Utc::now();

    Ok(blocklists
        .iter()
        .map(|source| BlocklistStatusView {
            id: source.id,
            name: source.name.clone(),
            last_refresh_attempt_at: refresh_state.last_refresh_for(source.id),
            due_for_refresh: source_due_for_refresh(
                source,
                refresh_state.last_refresh_for(source.id),
                now,
            ),
        })
        .collect())
}

async fn persist_source_refresh_state(storage: &Storage, state: &SourceRefreshState) -> Result<()> {
    storage
        .upsert_setting("source_refresh_state", &serde_json::to_string(state)?)
        .await?;
    Ok(())
}

async fn update_source_refresh_attempts(
    storage: &Storage,
    source_ids: &[Uuid],
    refreshed_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let mut state = load_source_refresh_state(storage).await?;
    for source_id in source_ids {
        state.record_attempt(*source_id, refreshed_at);
    }
    persist_source_refresh_state(storage, &state).await
}

async fn due_source_ids(state: &ServerState) -> Result<HashSet<Uuid>> {
    let now = chrono::Utc::now();
    let refresh_state = load_source_refresh_state(&state.storage).await?;
    let sources = state.storage.list_sources().await?;

    Ok(sources
        .into_iter()
        .filter(|source| source.enabled)
        .filter(|source| {
            source_due_for_refresh(source, refresh_state.last_refresh_for(source.id), now)
        })
        .map(|source| source.id)
        .collect())
}

fn source_due_for_refresh(
    source: &SourceRecord,
    last_refresh_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(last_refresh_attempt_at) = last_refresh_attempt_at else {
        return true;
    };
    let elapsed = now
        .signed_duration_since(last_refresh_attempt_at)
        .num_minutes();
    elapsed >= source.refresh_interval_minutes.max(1)
}

fn normalize_profile_name(profile: &str) -> Option<String> {
    let normalized = profile.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// What changed, which decides what happens to the runtime's cached answers.
#[derive(Debug, Clone, Copy)]
enum Rebuild {
    /// Lists were fetched, toggled or removed: verdicts may differ for everyone, so the
    /// cache is dropped and scope ids start afresh.
    Lists,
    /// Only devices changed: cached answers stay valid, a changed device moves to a new
    /// scope id and its old entries age out.
    Devices,
}

/// What a policy build reports back.
struct PolicyBuild {
    policy: Policy,
    /// Distinct list entries compiled in.
    rule_count: usize,
    /// Things worth telling the operator that did not stop the build.
    notes: Vec<String>,
}

/// What [`install_policy`] hands back to the caller.
struct Installed {
    rule_count: usize,
    notes: Vec<String>,
}

/// Compile the current sources and devices into a policy and swap it into the runtime.
async fn install_policy(state: &ServerState, rebuild: Rebuild) -> Result<Installed> {
    let _serialised = state.rebuild_lock.lock().await;
    let sources = state.storage.list_sources().await?;
    let devices = state.storage.list_devices().await?;
    // A deleted source's body has no reader left; drop it rather than carry it until
    // restart. Done here, under the lock and against the sources as they are now, because a
    // refresh's own view of the sources is minutes old by the time its fetches finish, and
    // pruning against that would evict a list added while it was downloading.
    write_recover(&state.lists)
        .retain(|source_id, _| sources.iter().any(|source| source.id == *source_id));
    let built = {
        let lists = read_recover(&state.lists);
        let mut scopes = lock_recover(&state.scopes);
        if matches!(rebuild, Rebuild::Lists) {
            scopes.reset();
        }
        build_policy(
            &sources,
            &lists,
            &devices,
            &mut scopes,
            state.dns_runtime.block_mode(),
        )
    };
    *write_recover(&state.device_names) = devices
        .iter()
        .filter_map(|device| {
            device
                .ip_address
                .parse::<IpAddr>()
                .ok()
                .map(|ip| (ip, device.name.clone()))
        })
        .collect();
    for note in &built.notes {
        tracing::info!(note, "policy build note");
    }
    let policy = Arc::new(built.policy);
    match rebuild {
        Rebuild::Lists => state.dns_runtime.swap_policy(policy),
        Rebuild::Devices => state.dns_runtime.swap_policy_keep_cache(policy),
    }
    Ok(Installed {
        rule_count: built.rule_count,
        notes: built.notes,
    })
}

/// Build the policy today's schema describes.
///
/// Every enabled source with a parsed body takes a list slot in id order. There are no
/// household rules yet -- nothing writes them -- and every device sees every list: block
/// profiles never reached the DNS path, so a device's profile override is ignored here
/// exactly as it was. A device in `custom` mode contributes its `allowed_domains` as
/// device allow rules and, with `protection_override = bypass`, filtering off.
fn build_policy(
    sources: &[SourceRecord],
    lists: &HashMap<Uuid, ParsedList>,
    devices: &[DeviceRecord],
    scopes: &mut ScopeAllocator,
    block_mode: BlockMode,
) -> PolicyBuild {
    let mut notes = Vec::new();

    let mut enabled = sources
        .iter()
        .filter(|source| source.enabled)
        .collect::<Vec<_>>();
    enabled.sort_by_key(|source| source.id);
    let mut compiled = Vec::with_capacity(enabled.len());
    for source in enabled {
        match lists.get(&source.id) {
            Some(list) if compiled.len() < MAX_LIST_SLOTS => {
                compiled.push((source.name.as_str(), list));
            }
            Some(_) => notes.push(format!(
                "{}: not compiled; only {MAX_LIST_SLOTS} enabled lists fit in one policy",
                source.name
            )),
            None => notes.push(format!(
                "{}: not compiled; it has not been fetched yet",
                source.name
            )),
        }
    }
    let index = Arc::new(build_index(compiled.iter().copied()));
    let all_mask = (0..compiled.len()).fold(0u64, |mask, slot| mask | (1 << slot));
    notes.extend(protected_notes(&index));

    let mut by_ip = HashMap::with_capacity(devices.len());
    for device in devices {
        let Ok(ip) = device.ip_address.parse::<IpAddr>() else {
            notes.push(format!(
                "device {}: address {:?} is not an IP; it resolves as the household",
                device.name, device.ip_address
            ));
            continue;
        };
        let custom = normalize_device_policy_mode(&device.policy_mode).as_deref() == Some("custom");
        let bypass = normalize_device_protection_override(&device.protection_override).as_deref()
            == Some("bypass");
        let filtering = !(custom && bypass);
        let rules = if custom {
            device
                .allowed_domains
                .iter()
                .map(|domain| normalize_rule_domain(domain))
                .filter(|domain| !domain.is_empty())
                .map(|domain| (domain, Action::Allow))
                .collect::<RuleSet>()
        } else {
            RuleSet::new()
        };
        let id = scopes.scope_id(all_mask, filtering, all_mask, &rules);
        by_ip.insert(
            ip,
            Scope {
                id,
                filtering,
                mask: all_mask,
                rules: (!rules.is_empty()).then(|| Arc::new(rules)),
            },
        );
    }

    let rule_count = index.len();
    PolicyBuild {
        policy: Policy::new(index, Arc::new(RuleSet::new()), by_ip, all_mask, block_mode),
        rule_count,
        notes,
    }
}

/// One note per protected name the compiled lists would have blocked, naming the lists.
///
/// A note and not a rejection: protection is enforced at evaluation, so the name stays
/// reachable whatever the lists say. The operator still deserves to know a list is
/// overreaching.
fn protected_notes(index: &ListIndex) -> Vec<String> {
    protected_hits(index)
        .into_iter()
        .map(|suffix| {
            let blocked_by = index.lookup(suffix).block;
            let lists = index
                .names()
                .iter()
                .enumerate()
                .filter(|(slot, _)| blocked_by & (1u64 << slot) != 0)
                .map(|(_, name)| name.as_ref())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{suffix} is on {lists}; it stays reachable because it is a protected name")
        })
        .collect()
}

fn normalize_source_kind(kind: &str) -> Option<String> {
    let normalized = kind.trim().to_ascii_lowercase();
    normalized.parse::<SourceKind>().ok()?;
    Some(normalized)
}

fn normalize_verification_strictness(strictness: &str) -> Option<String> {
    let normalized = strictness.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "strict" | "balanced" | "relaxed" => Some(normalized),
        _ => None,
    }
}

fn normalize_device_policy_mode(mode: &str) -> Option<String> {
    let normalized = mode.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "global" | "custom" => Some(normalized),
        _ => None,
    }
}

fn normalize_device_protection_override(mode: &str) -> Option<String> {
    let normalized = mode.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "inherit" | "bypass" => Some(normalized),
        _ => None,
    }
}

fn normalize_device_allowed_domains(domains: Vec<String>) -> Vec<String> {
    let mut normalized = domains
        .into_iter()
        .filter_map(|domain| {
            let trimmed = domain.trim().trim_matches('.').to_ascii_lowercase();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn is_reserved_source_id(source_id: Uuid) -> bool {
    source_id == Uuid::from_u128(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cogwheel_policy::{Reason, Verdict, evaluate};

    /// The subscriber cap and the Drop-based slot release are the event bus's two
    /// correctness-critical behaviours. Without a test, a refactor that dropped `SubscriberGuard`
    /// or moved the `fetch_add` would leak slots until the endpoint refused every client, and
    /// nothing in the suite would notice.
    #[test]
    fn event_bus_releases_subscriber_slots_when_streams_are_dropped() {
        let bus = EventBus::new();
        let counter = Arc::clone(&bus.subscribers);

        {
            let _guards: Vec<SubscriberGuard> = (0..MAX_EVENT_SUBSCRIBERS)
                .map(|_| {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    SubscriberGuard(Arc::clone(&counter))
                })
                .collect();
            assert_eq!(
                counter.load(std::sync::atomic::Ordering::Relaxed),
                MAX_EVENT_SUBSCRIBERS,
                "every slot should be taken"
            );
        }

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "dropping the guards must return every slot"
        );
    }

    #[test]
    fn event_bus_publishes_without_subscribers() {
        // A send with no receivers must be a no-op, not an error path the DNS observers have to
        // handle on every query.
        let bus = EventBus::new();
        bus.publish(StreamEvent::Query(Box::new(StreamQueryEvent {
            domain: "example.com".to_string(),
            client: "127.0.0.1".to_string(),
            device_name: None,
            blocked: false,
            reason: None,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
        })));
        assert_eq!(
            bus.subscribers.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn event_bus_delivers_query_frames_to_a_subscriber() {
        let bus = EventBus::new();
        let mut receiver = bus.sender.subscribe();

        bus.publish(StreamEvent::Query(Box::new(StreamQueryEvent {
            domain: "ads.example.com".to_string(),
            client: "127.0.0.1".to_string(),
            device_name: None,
            blocked: true,
            reason: None,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
        })));

        let frame = receiver.try_recv();
        assert!(
            matches!(&frame, Ok(StreamEvent::Query(event)) if event.domain == "ads.example.com" && event.blocked),
            "expected a blocked query frame for ads.example.com, got {frame:?}"
        );
    }

    #[test]
    fn normalize_source_kind_accepts_known_kinds() {
        assert_eq!(normalize_source_kind("HOSTS"), Some("hosts".to_string()));
        assert_eq!(
            normalize_source_kind(" domains "),
            Some("domains".to_string())
        );
        assert_eq!(normalize_source_kind("weird"), None);
    }

    #[test]
    fn baseline_source_id_is_reserved() {
        assert!(is_reserved_source_id(Uuid::from_u128(1)));
        assert!(!is_reserved_source_id(Uuid::new_v4()));
    }

    #[test]
    fn normalize_verification_strictness_accepts_known_values() {
        assert_eq!(
            normalize_verification_strictness("STRICT"),
            Some("strict".to_string())
        );
        assert_eq!(
            normalize_verification_strictness(" balanced "),
            Some("balanced".to_string())
        );
        assert_eq!(normalize_verification_strictness("unknown"), None);
    }

    #[test]
    fn normalize_device_policy_mode_accepts_known_values() {
        assert_eq!(
            normalize_device_policy_mode("GLOBAL"),
            Some("global".to_string())
        );
        assert_eq!(
            normalize_device_policy_mode(" custom "),
            Some("custom".to_string())
        );
        assert_eq!(normalize_device_policy_mode("invalid"), None);
    }

    #[test]
    fn normalize_device_protection_override_accepts_known_values() {
        assert_eq!(
            normalize_device_protection_override(" BYPASS "),
            Some("bypass".to_string())
        );
        assert_eq!(
            normalize_device_protection_override("inherit"),
            Some("inherit".to_string())
        );
        assert_eq!(normalize_device_protection_override("block"), None);
    }

    #[test]
    fn normalize_device_allowed_domains_deduplicates_values() {
        assert_eq!(
            normalize_device_allowed_domains(vec![
                " Example.com ".to_string(),
                "example.com".to_string(),
                "cdn.example.com.".to_string(),
                " ".to_string(),
            ]),
            vec!["cdn.example.com".to_string(), "example.com".to_string()]
        );
    }

    #[test]
    fn normalize_profile_name_accepts_non_empty_values() {
        assert_eq!(
            normalize_profile_name(" Balanced "),
            Some("balanced".to_string())
        );
        assert_eq!(normalize_profile_name("   "), None);
    }

    fn source(id: u128, name: &str, enabled: bool, url: &str) -> SourceRecord {
        SourceRecord {
            id: Uuid::from_u128(id),
            name: name.to_string(),
            url: url.to_string(),
            kind: "domains".to_string(),
            enabled,
            refresh_interval_minutes: 60,
            profile: "custom".to_string(),
            verification_strictness: "balanced".to_string(),
        }
    }

    fn device(
        name: &str,
        ip: &str,
        policy_mode: &str,
        protection_override: &str,
        allowed: &[&str],
    ) -> DeviceRecord {
        DeviceRecord {
            id: Uuid::new_v4(),
            name: name.to_string(),
            ip_address: ip.to_string(),
            policy_mode: policy_mode.to_string(),
            blocklist_profile_override: Some("aggressive".to_string()),
            protection_override: protection_override.to_string(),
            allowed_domains: allowed.iter().map(|d| (*d).to_string()).collect(),
            service_overrides: Vec::new(),
        }
    }

    fn domains(body: &str) -> ParsedList {
        parse_list(SourceKind::Domains, body)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    /// One enabled list blocking `ads.example`, plus the given devices.
    fn built(devices: &[DeviceRecord], scopes: &mut ScopeAllocator) -> Policy {
        let sources = [source(1, "ads", true, "data:text/plain,ads.example")];
        let lists = HashMap::from([(sources[0].id, domains("ads.example"))]);
        build_policy(&sources, &lists, devices, scopes, BlockMode::NullIp).policy
    }

    #[test]
    fn global_mode_devices_share_the_household_scope() {
        // In global mode the per-device columns are ignored, bypass and allow list
        // included: that is what the runtime did before and the schema has not moved.
        let laptop = device(
            "Laptop",
            "192.168.1.10",
            "global",
            "bypass",
            &["ads.example"],
        );
        let policy = built(&[laptop], &mut ScopeAllocator::new());
        let scope = policy.scope_for(ip("192.168.1.10"));
        assert_eq!(scope.id, SCOPE_HOUSEHOLD);
        assert!(scope.filtering);
        assert!(scope.rules.is_none());
        assert_eq!(
            evaluate(&policy, scope, "ads.example"),
            Verdict::Block(Reason::List, 0)
        );
    }

    #[test]
    fn bypassed_devices_resolve_unfiltered() {
        let console = device("Console", "192.168.1.20", "custom", "bypass", &[]);
        let policy = built(&[console], &mut ScopeAllocator::new());
        let scope = policy.scope_for(ip("192.168.1.20"));
        assert_eq!(scope.id, SCOPE_UNFILTERED);
        assert_eq!(
            evaluate(&policy, scope, "ads.example"),
            Verdict::Allow(Reason::Unfiltered)
        );
    }

    #[test]
    fn allowed_domains_become_device_allow_rules() {
        let laptop = device(
            "Laptop",
            "192.168.1.10",
            "custom",
            "inherit",
            &["*.Ads.Example."],
        );
        let policy = built(&[laptop], &mut ScopeAllocator::new());
        let scope = policy.scope_for(ip("192.168.1.10"));
        assert!(
            scope.id > SCOPE_UNFILTERED,
            "a device with rules gets its own scope"
        );
        for name in ["ads.example", "cdn.ads.example"] {
            assert_eq!(
                evaluate(&policy, scope, name),
                Verdict::Allow(Reason::DeviceRule),
                "{name}"
            );
        }
        // The rule is the device's alone.
        assert_eq!(
            evaluate(&policy, policy.scope_for(ip("192.168.1.99")), "ads.example"),
            Verdict::Block(Reason::List, 0)
        );
    }

    #[test]
    fn devices_with_identical_rules_share_a_scope_and_an_edit_gets_a_fresh_one() {
        let mut scopes = ScopeAllocator::new();
        let phone = device("Phone", "192.168.1.11", "custom", "inherit", &["a.example"]);
        let tablet = device(
            "Tablet",
            "192.168.1.12",
            "custom",
            "inherit",
            &["a.example"],
        );
        let policy = built(&[phone.clone(), tablet.clone()], &mut scopes);
        let shared = policy.scope_for(ip("192.168.1.11")).id;
        assert_eq!(policy.scope_for(ip("192.168.1.12")).id, shared);

        // Editing the tablet moves it to a new id; the phone keeps its cache.
        let edited = device(
            "Tablet",
            "192.168.1.12",
            "custom",
            "inherit",
            &["b.example"],
        );
        let policy = built(&[phone, edited], &mut scopes);
        assert_eq!(policy.scope_for(ip("192.168.1.11")).id, shared);
        let moved = policy.scope_for(ip("192.168.1.12")).id;
        assert_ne!(moved, shared);
        assert!(moved > shared);
    }

    #[test]
    fn a_list_rebuild_never_reuses_a_scope_id() {
        // After a reset the same signature must not land on an id a cached answer may
        // still carry: the cache is dropped with the lists, but an in-flight miss can
        // still insert under the old policy after the swap.
        let mut scopes = ScopeAllocator::new();
        let phone = device("Phone", "192.168.1.11", "custom", "inherit", &["a.example"]);
        let before = built(std::slice::from_ref(&phone), &mut scopes)
            .scope_for(ip("192.168.1.11"))
            .id;
        scopes.reset();
        let after = built(&[phone], &mut scopes)
            .scope_for(ip("192.168.1.11"))
            .id;
        assert!(after > before, "{after} should be above {before}");
    }

    #[test]
    fn the_policy_is_compiled_from_every_enabled_source_in_id_order() {
        let sources = [
            source(7, "later", true, "data:text/plain,later.example"),
            source(3, "earlier", true, "data:text/plain,earlier.example"),
            source(5, "off", false, "data:text/plain,off.example"),
        ];
        let lists = HashMap::from([
            (sources[0].id, domains("later.example")),
            (sources[1].id, domains("earlier.example\nmore.example")),
            (sources[2].id, domains("off.example")),
        ]);
        let build = build_policy(
            &sources,
            &lists,
            &[],
            &mut ScopeAllocator::new(),
            BlockMode::NxDomain,
        );
        let policy = build.policy;
        assert_eq!(policy.index.names(), ["earlier".into(), "later".into()]);
        assert_eq!(policy.all_mask, 0b11);
        assert_eq!(build.rule_count, 3);
        assert_eq!(policy.block_mode, BlockMode::NxDomain);
        let household = policy.scope(SCOPE_HOUSEHOLD);
        assert_eq!(
            evaluate(&policy, household, "later.example"),
            Verdict::Block(Reason::List, 1)
        );
        assert_eq!(
            evaluate(&policy, household, "off.example"),
            Verdict::Allow(Reason::NoMatch),
            "a disabled list contributes nothing"
        );
        assert!(build.notes.is_empty(), "{:?}", build.notes);
    }

    #[test]
    fn an_enabled_source_without_a_body_is_a_note_not_a_failure() {
        let sources = [
            source(1, "fetched", true, "data:text/plain,a.example"),
            source(2, "pending", true, "https://lists.example/pending.txt"),
        ];
        let lists = HashMap::from([(sources[0].id, domains("a.example"))]);
        let build = build_policy(
            &sources,
            &lists,
            &[],
            &mut ScopeAllocator::new(),
            BlockMode::NullIp,
        );
        assert_eq!(build.policy.all_mask, 0b1);
        assert_eq!(build.notes.len(), 1, "{:?}", build.notes);
        assert!(build.notes[0].starts_with("pending: not compiled"));
    }

    #[test]
    fn a_list_blocking_a_protected_name_is_a_note_not_a_rejection() {
        let sources = [source(1, "overreach", true, "data:text/plain,pool.ntp.org")];
        let lists = HashMap::from([(sources[0].id, domains("pool.ntp.org\nads.example"))]);
        let build = build_policy(
            &sources,
            &lists,
            &[],
            &mut ScopeAllocator::new(),
            BlockMode::NullIp,
        );
        assert_eq!(build.rule_count, 2);
        assert_eq!(
            build.notes,
            vec![
                "pool.ntp.org is on overreach; it stays reachable because it is a protected name"
                    .to_string()
            ]
        );
        assert_eq!(
            evaluate(
                &build.policy,
                build.policy.scope(SCOPE_HOUSEHOLD),
                "0.pool.ntp.org"
            ),
            Verdict::Allow(Reason::Protected)
        );
    }

    #[test]
    fn query_frames_carry_the_verdict_and_the_device_name() {
        let entry = LogEntry {
            ts: 1_700_000_000,
            client: ip("192.168.1.10"),
            domain: Arc::from("ads.example"),
            qtype: 1,
            verdict: Verdict::Block(Reason::Cname, 0),
        };
        let observed_at =
            chrono::DateTime::from_timestamp(i64::from(entry.ts), 0).expect("timestamp in range");
        let frame = query_frame(&entry, Some("Laptop".to_string()), observed_at);
        assert_eq!(frame.domain, "ads.example");
        assert_eq!(frame.client, "192.168.1.10");
        assert_eq!(frame.device_name.as_deref(), Some("Laptop"));
        assert!(frame.blocked);
        assert_eq!(frame.reason.as_deref(), Some("cname"));
        assert!(frame.observed_at.starts_with("2023-11-14T22:13:20"));
    }

    /// A control plane over an in-memory database and a runtime whose upstream is never
    /// asked anything.
    async fn test_state() -> ServerState {
        let storage = Storage::connect("sqlite://:memory:")
            .await
            .expect("in-memory storage");
        let resolver = build_resolver(&["127.0.0.1:1".to_string()]).expect("resolver");
        let (dns_runtime, _log_rx) =
            DnsRuntime::new(resolver, Arc::new(Policy::empty(BlockMode::NullIp)));
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        ServerState {
            api_state: ApiState {
                readiness: Arc::default(),
            },
            storage: Arc::new(storage),
            dns_runtime,
            lists: Arc::new(RwLock::new(HashMap::new())),
            scopes: Arc::new(Mutex::new(ScopeAllocator::new())),
            rebuild_lock: Arc::new(tokio::sync::Mutex::new(())),
            device_names: Arc::new(RwLock::new(HashMap::new())),
            recent_dns_activity: Arc::new(Mutex::new(VecDeque::new())),
            events: EventBus::new(),
            shutdown,
            rate_limiter: Arc::new(RateLimiter::new(100, 60)),
            dns_udp_bind_addr: "127.0.0.1:0".parse().expect("bind address"),
            advertised_dns_port: 53,
            advertised_dns_targets: Vec::new(),
        }
    }

    /// The scheduler only fetches the sources whose interval has elapsed. That used to
    /// be all the policy was compiled from, so every other list silently fell out of
    /// force until its own turn came round.
    #[tokio::test]
    async fn a_refresh_compiles_every_enabled_source_not_only_the_fetched_ones() {
        let state = test_state().await;
        let ads = source(
            1,
            "ads",
            true,
            "data:text/plain,ads.example%0Atracker.example",
        );
        let promos = source(2, "promos", true, "data:text/plain,promo.example");
        for record in [&ads, &promos] {
            state.storage.insert_source(record).await.expect("insert");
        }

        let first = refresh_sources_once(&state, "test", None)
            .await
            .expect("first refresh");
        assert_eq!(first.outcome, RefreshOutcome::Activated);
        assert_eq!(first.rule_count, Some(3));

        let due = HashSet::from([promos.id]);
        let second = refresh_sources_once(&state, "test", Some(&due))
            .await
            .expect("second refresh");
        assert_eq!(second.outcome, RefreshOutcome::Activated);
        assert_eq!(second.rule_count, Some(3));

        let policy = state.dns_runtime.current_policy();
        assert_eq!(policy.index.names(), ["ads".into(), "promos".into()]);
        let household = policy.scope(SCOPE_HOUSEHOLD);
        assert_eq!(
            evaluate(&policy, household, "tracker.example"),
            Verdict::Block(Reason::List, 0)
        );
        assert_eq!(
            evaluate(&policy, household, "promo.example"),
            Verdict::Block(Reason::List, 1)
        );
    }

    /// Serve one list body over loopback HTTP, released only when `release` is notified, so
    /// a refresh can be parked in the middle of its download.
    async fn parked_list_server(body: &'static str, release: Arc<tokio::sync::Notify>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind list server");
        let addr = listener.local_addr().expect("list server address");
        let app = Router::new().route(
            "/list.txt",
            get(move || {
                let release = Arc::clone(&release);
                async move {
                    release.notified().await;
                    body
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}/list.txt")
    }

    /// A refresh snapshots the sources before its downloads and installs after them. A list
    /// added in between — the scheduler is mid-download when someone clicks Add — must
    /// survive the older refresh finishing, or it stays out of force until its own interval.
    #[tokio::test]
    async fn a_list_added_during_a_refresh_survives_that_refresh_finishing() {
        let state = test_state().await;
        let release = Arc::new(tokio::sync::Notify::new());
        let slow_url = parked_list_server("slow.example\n", Arc::clone(&release)).await;
        let slow = source(1, "slow", true, &slow_url);
        state.storage.insert_source(&slow).await.expect("insert");

        let parked = tokio::spawn({
            let state = state.clone();
            let only_slow = HashSet::from([slow.id]);
            async move { refresh_sources_once(&state, "scheduled", Some(&only_slow)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !parked.is_finished(),
            "the refresh should be parked on its download"
        );

        let added = source(2, "added", true, "data:text/plain,added.example");
        state.storage.insert_source(&added).await.expect("insert");
        let only_added = HashSet::from([added.id]);
        let activated = refresh_sources_once(&state, "blocklist-update", Some(&only_added))
            .await
            .expect("refresh of the added list");
        assert_eq!(activated.outcome, RefreshOutcome::Activated);

        release.notify_one();
        let finished = parked
            .await
            .expect("refresh task")
            .expect("the parked refresh completes");
        assert_eq!(finished.outcome, RefreshOutcome::Activated);
        assert_eq!(finished.rule_count, Some(2));

        let policy = state.dns_runtime.current_policy();
        assert_eq!(policy.index.names(), ["slow".into(), "added".into()]);
        assert!(
            !finished
                .notes
                .iter()
                .any(|note| note.starts_with("added: not compiled")),
            "{:?}",
            finished.notes
        );
    }

    #[tokio::test]
    async fn a_list_that_fails_verification_rejects_the_refresh_and_keeps_the_policy() {
        let state = test_state().await;
        let ads = source(1, "ads", true, "data:text/plain,ads.example");
        let mut broken = source(
            2,
            "broken",
            true,
            "data:text/plain,||ads.example^$third-party",
        );
        broken.kind = "adblock".to_string();
        for record in [&ads, &broken] {
            state.storage.insert_source(record).await.expect("insert");
        }

        let only_ads = HashSet::from([ads.id]);
        let first = refresh_sources_once(&state, "test", Some(&only_ads))
            .await
            .expect("first refresh");
        assert_eq!(first.outcome, RefreshOutcome::Activated);
        assert!(
            first
                .notes
                .iter()
                .any(|note| note.starts_with("broken: not compiled")),
            "{:?}",
            first.notes
        );

        let rejected = refresh_sources_once(&state, "test", None)
            .await
            .expect("second refresh");
        assert_eq!(rejected.outcome, RefreshOutcome::Rejected);
        assert_eq!(rejected.rule_count, None);
        assert!(
            rejected.notes[0].starts_with("broken: "),
            "{:?}",
            rejected.notes
        );

        // Nothing moved: the good list is still in force and the bad body was not kept.
        let policy = state.dns_runtime.current_policy();
        assert_eq!(policy.index.names(), ["ads".into()]);
        assert!(!read_recover(&state.lists).contains_key(&broken.id));
    }

    #[tokio::test]
    async fn a_device_edit_recompiles_scopes_without_refetching() {
        let state = test_state().await;
        let ads = source(1, "ads", true, "data:text/plain,ads.example");
        state.storage.insert_source(&ads).await.expect("insert");
        refresh_sources_once(&state, "test", None)
            .await
            .expect("refresh");
        // Take the source off the network: a rebuild that fetched would now fail.
        let mut offline = ads.clone();
        offline.url = "https://lists.example/unreachable.txt".to_string();
        state.storage.insert_source(&offline).await.expect("update");
        let laptop = device(
            "Laptop",
            "192.168.1.10",
            "custom",
            "inherit",
            &["ads.example"],
        );
        state.storage.upsert_device(&laptop).await.expect("device");

        install_policy(&state, Rebuild::Devices)
            .await
            .expect("device rebuild");

        let policy = state.dns_runtime.current_policy();
        assert_eq!(policy.index.names(), ["ads".into()]);
        assert_eq!(
            evaluate(&policy, policy.scope_for(ip("192.168.1.10")), "ads.example"),
            Verdict::Allow(Reason::DeviceRule)
        );
        assert_eq!(
            read_recover(&state.device_names).get(&ip("192.168.1.10")),
            Some(&"Laptop".to_string())
        );
    }

    #[test]
    fn source_refresh_state_tracks_attempts() {
        let mut state = SourceRefreshState::default();
        let source_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        state.record_attempt(source_id, now);
        assert_eq!(state.last_refresh_for(source_id), Some(now));
    }

    #[test]
    fn source_due_for_refresh_respects_interval() {
        let source = SourceRecord {
            id: Uuid::new_v4(),
            name: "scheduled".to_string(),
            url: "data:text/plain,scheduled.example".to_string(),
            kind: "domains".to_string(),
            enabled: true,
            refresh_interval_minutes: 30,
            profile: "balanced".to_string(),
            verification_strictness: "balanced".to_string(),
        };
        let now = chrono::Utc::now();
        assert!(!source_due_for_refresh(
            &source,
            Some(now - chrono::TimeDelta::minutes(5)),
            now,
        ));
        assert!(source_due_for_refresh(
            &source,
            Some(now - chrono::TimeDelta::minutes(45)),
            now,
        ));
    }

    /// hickory builds its TLS client config as `RootCertStore::empty()` and
    /// only fills it in under a trust-anchor feature. With `tls-ring` alone the
    /// store stays EMPTY, so every DoT/DoH certificate fails to validate: the
    /// build succeeds, the TCP connection succeeds, the handshake is rejected,
    /// and every encrypted query returns SERVFAIL forever. Measured -- that is
    /// exactly what happened before `webpki-roots` was added.
    ///
    /// Nothing else fails if this feature is dropped, which is what makes it
    /// worth pinning here. A guard on the manifest is crude, but it is the only
    /// place the mistake can be made and the only place it can be caught
    /// cheaply; the alternative is a live TLS connection in the test suite.
    #[test]
    fn encrypted_upstreams_have_trust_anchors_compiled_in() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../Cargo.toml")
            .canonicalize()
            .expect("workspace manifest should exist");
        let text = std::fs::read_to_string(&manifest).expect("read workspace manifest");
        let hickory = text
            .split("hickory-resolver = ")
            .nth(1)
            .expect("workspace should pin hickory-resolver");
        let declaration = &hickory[..hickory.find('}').unwrap_or(hickory.len())];

        assert!(
            declaration.contains("webpki-roots")
                || declaration.contains("rustls-platform-verifier"),
            "hickory-resolver must enable a trust-anchor feature or DoT/DoH silently never \
             resolves; found: {declaration}"
        );
        assert!(
            declaration.contains("tls-ring") || declaration.contains("tls-aws-lc-rs"),
            "hickory-resolver must enable a TLS feature for DoT upstreams; found: {declaration}"
        );
    }

    fn cli(args: &[&str]) -> CliAction {
        parse_cli(&args.iter().map(|a| (*a).to_string()).collect::<Vec<_>>())
    }

    // The workspace bans `panic!`, so these render the wrong variant into the
    // assertion message instead of unwrapping it.
    fn printed(action: CliAction) -> String {
        match action {
            CliAction::Print(text) => text,
            other => format!("expected Print, got {other:?}"),
        }
    }

    fn failed(action: CliAction) -> String {
        match action {
            CliAction::Fail(message) => message,
            other => format!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_starts_the_server() {
        assert_eq!(cli(&[]), CliAction::Run);
    }

    #[test]
    fn version_prints_the_crate_version_and_does_not_start_the_server() {
        for flag in ["--version", "-V"] {
            let text = printed(cli(&[flag]));
            assert!(
                text.starts_with("cogwheel-server ") && text.contains(env!("CARGO_PKG_VERSION")),
                "{flag} produced {text:?}"
            );
        }
    }

    #[test]
    fn help_prints_usage_and_does_not_start_the_server() {
        for flag in ["--help", "-h"] {
            let text = printed(cli(&[flag]));
            assert!(text.contains("Usage:"), "{flag} produced {text:?}");
        }
    }

    /// The regression that motivated all of this: an argument the binary does
    /// not understand must NOT fall through and start a DNS server. Doing so
    /// on an appliance means a second resolver racing the real one for :53.
    ///
    /// `healthcheck` is in this list deliberately -- it used to be accepted and
    /// return success without checking anything.
    #[test]
    fn an_unrecognised_argument_refuses_to_start_the_server() {
        for arg in ["--verison", "-x", "serve", "healthcheck", "/etc/cogwheel"] {
            let message = failed(cli(&[arg]));
            assert!(
                message.contains(arg) && message.contains("unrecognised"),
                "{arg} produced {message:?}"
            );
        }
    }

    fn blocking(mode: cogwheel_api::BlockResponseMode) -> cogwheel_api::BlockingConfig {
        cogwheel_api::BlockingConfig { mode }
    }

    #[test]
    fn the_default_block_response_is_unchanged_from_previous_versions() {
        assert_eq!(
            cogwheel_api::BlockingConfig::default().mode,
            cogwheel_api::BlockResponseMode::NullIp
        );
        let resolved = resolve_block_mode(&cogwheel_api::BlockingConfig::default());
        assert_eq!(resolved, BlockMode::NullIp);
    }

    #[test]
    fn each_simple_mode_maps_to_its_dns_response() {
        use cogwheel_api::BlockResponseMode as Mode;
        for (mode, expected) in [
            (Mode::NullIp, BlockMode::NullIp),
            (Mode::NxDomain, BlockMode::NxDomain),
            (Mode::NoData, BlockMode::NoData),
            (Mode::Refused, BlockMode::Refused),
        ] {
            let resolved = resolve_block_mode(&blocking(mode));
            assert_eq!(resolved, expected, "{mode:?}");
        }
    }

    #[test]
    fn block_mode_is_parsed_from_the_spellings_people_actually_write() {
        use cogwheel_api::BlockResponseMode as Mode;
        for (text, expected) in [
            (" nxdomain ", Mode::NxDomain),
            ("null_ip", Mode::NullIp),
            ("null-ip", Mode::NullIp),
            ("refused", Mode::Refused),
        ] {
            assert_eq!(text.parse::<Mode>().expect(text), expected, "{text}");
        }
        assert!("wat".parse::<Mode>().is_err());
    }
}

// ---------------------------------------------------------------- live event stream

/// Upper bound on simultaneous SSE subscribers.
///
/// Each connection holds a broadcast receiver and a task. A household needs one or two; the cap
/// exists so a misbehaving client cannot open thousands and exhaust the appliance's memory.
const MAX_EVENT_SUBSCRIBERS: usize = 32;

/// Buffered events per subscriber before the slowest one starts missing frames.
///
/// A slow reader lags rather than applying backpressure to the DNS path — losing display frames is
/// always preferable to slowing resolution.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// A frame pushed to connected control planes.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamQueryEvent {
    domain: String,
    client: String,
    device_name: Option<String>,
    blocked: bool,
    reason: Option<String>,
    observed_at: String,
}

/// Which SSE event name a frame is published under.
#[derive(Debug, Clone)]
enum StreamEvent {
    Query(Box<StreamQueryEvent>),
}

/// Fan-out for live events, with a bounded subscriber count.
#[derive(Clone)]
struct EventBus {
    sender: tokio::sync::broadcast::Sender<StreamEvent>,
    subscribers: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field(
                "subscribers",
                &self.subscribers.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl EventBus {
    fn new() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            sender,
            subscribers: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Publish a frame. Never blocks and never fails: with no subscribers the send is a no-op.
    fn publish(&self, event: StreamEvent) {
        let _ = self.sender.send(event);
    }
}

/// A subscriber slot that decrements the connection count when the stream is dropped.
///
/// Teardown has to be tied to the guard rather than the handler body, because an SSE handler
/// returns as soon as the stream is constructed — the client may stay connected for hours after.
struct SubscriberGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Live query stream.
///
/// Returns 503 once [`MAX_EVENT_SUBSCRIBERS`] connections are open rather than accepting unbounded
/// clients.
async fn events_stream(
    State(state): State<ServerState>,
) -> Result<
    axum::response::Sse<
        impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    axum::http::StatusCode,
> {
    let subscribers = Arc::clone(&state.events.subscribers);
    let previous = subscribers.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if previous >= MAX_EVENT_SUBSCRIBERS {
        subscribers.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
    let guard = SubscriberGuard(subscribers);

    // `BroadcastStream` gives us the receiver as a Stream without pulling in a generator macro.
    // The guard is moved into the closure so the subscriber count drops when the client
    // disconnects and the stream is dropped -- an SSE handler returns as soon as the stream is
    // constructed, so teardown cannot live in the handler body.
    // An SSE stream never ends on its own, so `with_graceful_shutdown` would wait on it forever --
    // one open browser tab was enough to make SIGTERM hang until the supervisor SIGKILLed us.
    // Ending the stream on the shutdown signal lets the connection close and the server exit.
    let mut shutdown = state.shutdown.clone();
    let stream = tokio_stream::wrappers::BroadcastStream::new(state.events.sender.subscribe())
        .take_until(async move {
            let _ = shutdown.changed().await;
        })
        .filter_map(move |item| {
            let _guard = &guard;
            let frame = match item {
                Ok(StreamEvent::Query(event)) => axum::response::sse::Event::default()
                    .event("query")
                    .json_data(&*event),
                // A slow reader missed frames. Skip them and keep the connection alive rather than
                // tearing down a working stream over dropped display rows.
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => {
                    return std::future::ready(None);
                }
            };
            std::future::ready(frame.ok().map(Ok))
        });

    Ok(axum::response::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}
