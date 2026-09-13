use anyhow::{Context, Result};
use axum::extract::{FromRef, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use cogwheel_api::{ApiEnvelope, ApiState, AppConfig, UpstreamEndpoint, UpstreamProtocol, router};
use cogwheel_dns_core::{
    DevicePolicyConfig, DnsRuntime, DnsRuntimeConfig, DnsRuntimeSnapshot, QueryActivityEvent,
};
use cogwheel_lists::{
    ParsedSource, SourceDefinition, SourceKind, build_policy_engine, fetch_and_parse_source,
    parse_source, verify_candidate,
};
use cogwheel_policy::{BlockMode, DecisionKind, PolicyEngine, RulesetArtifact};
use cogwheel_storage::{DeviceRecord, SourceRecord, Storage};
use futures::StreamExt;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
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
    recent_dns_activity: Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    events: EventBus,
    shutdown: tokio::sync::watch::Receiver<bool>,
    protected_domains: Arc<HashSet<String>>,
    /// The policy engine displaced by the most recent activation.
    ///
    /// Compiled policies are no longer written to storage, so this one-deep,
    /// in-memory slot is all the history there is. Its only reader is
    /// [`PolicySummary::previous_hash`] on the dashboard: nothing rolls back to
    /// it, because a candidate that would regress a protected name is refused
    /// before activation (`protected_domain_regressions`) rather than reverted
    /// after. `None` until the first activation.
    previous_policy: Arc<RwLock<Option<Arc<PolicyEngine>>>>,
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

#[derive(Clone)]
struct RuntimePolicyCatalog {
    global_policy: Arc<PolicyEngine>,
    profile_policies: HashMap<String, Arc<PolicyEngine>>,
}

#[derive(serde::Serialize)]
struct RefreshResponse {
    /// `activated`, `rejected` or `saved` (saved without a refresh).
    outcome: String,
    /// Content hash of the policy now in force, when this refresh activated one.
    hash: Option<String>,
    /// Rules in that policy, when this refresh activated one.
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

/// The policy in force and the one step of history kept in memory.
#[derive(serde::Serialize)]
struct PolicySummary {
    hash: String,
    rule_count: usize,
    /// Hash of the policy the last activation replaced, if there has been one.
    previous_hash: Option<String>,
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
    domain: String,
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

/// The response every policy is compiled to give for a blocked name.
///
/// A `OnceLock` rather than a value threaded through the call graph: policies
/// are rebuilt from three unrelated places -- startup, a blocklist refresh, and
/// a policy rebuild -- and the alternative is passing the same immutable value
/// down three chains that have no other use for it. It is written once, before
/// any policy is built, and never changes for the life of the process.
static BLOCK_MODE: std::sync::OnceLock<BlockMode> = std::sync::OnceLock::new();

/// The configured block response, or the historical default before startup has
/// resolved it (which is also what every version before this one always did).
fn configured_block_mode() -> BlockMode {
    BLOCK_MODE.get().cloned().unwrap_or(BlockMode::NullIp)
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

#[tokio::main]
async fn main() -> Result<()> {
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

    let config = AppConfig::load()?;

    // Resolved before the first policy is compiled, because the block response
    // is baked into the compiled policy rather than consulted per query.
    let block_mode = resolve_block_mode(&config.blocking);
    tracing::info!(mode = ?config.blocking.mode, response = ?block_mode, "blocked names will be answered with this");
    let _ = BLOCK_MODE.set(block_mode);

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

    let parsed = parse_source(
        SourceDefinition {
            id: default_source.id,
            name: default_source.name.clone(),
            url: Url::parse(&default_source.url)?,
            kind: SourceKind::Domains,
            enabled: true,
            profile: default_source.profile.clone(),
            verification_strictness: default_source.verification_strictness.clone(),
        },
        "ads.example.com\ntracker.example.com",
    );

    // The suffixes a subscribed list is never allowed to block: resolver
    // bootstrap, captive-portal checks, NTP and the CAs' status endpoints. See
    // `cogwheel_policy::PROTECTED_SUFFIXES` for why exactly these and no more.
    let protected_domains = Arc::new(
        cogwheel_policy::PROTECTED_SUFFIXES
            .iter()
            .map(|suffix| (*suffix).to_string())
            .collect::<HashSet<String>>(),
    );
    let verification = verify_candidate(std::slice::from_ref(&parsed), &protected_domains);
    anyhow::ensure!(
        verification.passed,
        "default policy failed verification: {:?}",
        verification.notes
    );

    let policy = Arc::new(build_policy_engine(
        vec![parsed],
        protected_domains.as_ref().clone(),
        configured_block_mode(),
    ));
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
    let recent_dns_activity = Arc::new(Mutex::new(VecDeque::with_capacity(4096)));
    let dns_runtime = Arc::new(DnsRuntime::new(resolver, policy));
    let events = EventBus::new();

    dns_runtime.set_query_activity_observer(Arc::new({
        let recent_dns_activity = recent_dns_activity.clone();
        let events = events.clone();
        move |event: cogwheel_dns_core::QueryActivityEvent| {
            events.publish(StreamEvent::Query(Box::new(StreamQueryEvent {
                domain: event.domain.clone(),
                client: event
                    .client_ip
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                device_name: None,
                blocked: event.blocked,
                reason: None,
                observed_at: event.observed_at.to_rfc3339(),
            })));
            record_recent_dns_activity(&recent_dns_activity, event)
        }
    }));

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
        recent_dns_activity,
        events,
        shutdown: shutdown_rx.clone(),
        protected_domains,
        previous_policy: Arc::new(RwLock::new(None)),
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
    match warm_runtime_policy_catalog(&app_state).await {
        Ok(()) => readiness.mark_policy_ready(),
        Err(error) => {
            // The node keeps serving -- an empty policy resolves everything rather than nothing --
            // but it must not advertise itself as ready, or a rolling upgrade would send traffic to
            // a node that is not actually filtering yet.
            tracing::warn!(%error, "failed to warm runtime policy catalog on startup");
        }
    }
    apply_runtime_device_policies(&app_state).await?;
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

fn build_resolver(servers: &[String]) -> Result<TokioResolver> {
    let mut name_servers = Vec::new();
    let mut encrypted = 0usize;

    for server in servers {
        let endpoint = UpstreamEndpoint::parse(server)
            .with_context(|| format!("invalid upstream server: {server}"))?;

        // hickory 0.26 models an upstream as one address carrying a list of connections, rather
        // than one entry per protocol. The port moved onto the connection, so it has to be copied
        // across from the configured address or every upstream would silently fall back to 53.
        let connections = match endpoint.protocol {
            UpstreamProtocol::Udp => {
                let mut udp = ConnectionConfig::udp();
                udp.port = endpoint.addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = endpoint.addr.port();
                vec![udp, tcp]
            }
            // No cleartext fallback is added alongside an encrypted transport, and that is the
            // whole point. A fallback would mean that anything making TLS fail -- a captive
            // portal, a middlebox, an expired certificate -- silently downgrades every query in
            // the house back onto the wire in plaintext, which is precisely the outcome the
            // operator configured this to avoid. If DoT is broken, resolution should fail
            // visibly and get fixed, not quietly succeed in the clear.
            UpstreamProtocol::Tls => {
                let server_name = endpoint
                    .server_name
                    .clone()
                    .context("DoT upstream without a certificate name reached the resolver")?;
                let mut tls = ConnectionConfig::tls(Arc::from(server_name.as_str()));
                tls.port = endpoint.addr.port();
                encrypted += 1;
                vec![tls]
            }
            UpstreamProtocol::Https => {
                let server_name = endpoint
                    .server_name
                    .clone()
                    .context("DoH upstream without a certificate name reached the resolver")?;
                let path = endpoint.path.clone().map(|path| Arc::from(path.as_str()));
                let mut https = ConnectionConfig::https(Arc::from(server_name.as_str()), path);
                https.port = endpoint.addr.port();
                encrypted += 1;
                vec![https]
            }
        };

        tracing::info!(
            upstream = %endpoint,
            protocol = ?endpoint.protocol,
            encrypted = endpoint.is_encrypted(),
            "configured upstream resolver"
        );
        name_servers.push(NameServerConfig::new(endpoint.addr.ip(), true, connections));
    }

    // Said once, plainly, rather than left for the operator to infer. Cleartext is still the
    // default because it is what works on every network without configuration, but running a
    // tracker blocker while handing the full browsing history of the house to whoever carries
    // the packets deserves to be stated rather than assumed.
    if encrypted == 0 {
        tracing::warn!(
            "all upstream resolvers are cleartext DNS on port 53; every domain this network \
             looks up is visible to the local network and to the ISP. Configure DNS-over-TLS \
             with e.g. COGWHEEL_UPSTREAM__SERVERS=tls://1.1.1.1#cloudflare-dns.com"
        );
    } else if encrypted < name_servers.len() {
        // Mixing is a real footgun: hickory will happily use whichever responds, so a single
        // cleartext entry in the list quietly leaks a share of the queries.
        tracing::warn!(
            encrypted,
            total = name_servers.len(),
            "some upstream resolvers are encrypted and some are cleartext; queries will be \
             spread across both, so a share of them still travel in plaintext"
        );
    }

    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(ResolverOpts::default())
        .build()
        .context("build upstream resolver")
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

    apply_runtime_device_policies(&state).await.map_err(|_| {
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
    let protection_paused_until = state.dns_runtime.protection_paused_until();

    let current = state.dns_runtime.current_policy();
    let policy = PolicySummary {
        hash: current.artifact().hash.clone(),
        rule_count: current.artifact().rules.len(),
        previous_hash: read_recover(&state.previous_policy)
            .as_ref()
            .map(|previous| previous.artifact().hash.clone()),
    };

    Ok(Json(ApiEnvelope {
        data: DashboardSummary {
            protection_status: match protection_paused_until {
                Some(until) if chrono::Utc::now() < until => "Paused".to_string(),
                _ => "Protected".to_string(),
            },
            protection_paused_until,
            policy,
            source_count: sources.len(),
            enabled_source_count: sources.iter().filter(|source| source.enabled).count(),
            device_count: devices.len(),
            runtime: state.dns_runtime.snapshot(),
            domain_insights,
        },
    }))
}

fn record_recent_dns_activity(
    activity: &Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    event: QueryActivityEvent,
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
        domain: event.domain,
        blocked: event.blocked,
        observed_at: event.observed_at,
    });
}

fn build_domain_insights(state: &ServerState) -> DomainInsights {
    let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
    let guard = lock_recover(&state.recent_dns_activity);

    let mut queried = HashMap::<String, usize>::new();
    let mut blocked = HashMap::<String, usize>::new();
    let mut observed_queries = 0usize;

    for item in guard.iter().filter(|item| item.observed_at >= cutoff) {
        observed_queries += 1;
        *queried.entry(item.domain.clone()).or_default() += 1;
        if item.blocked {
            *blocked.entry(item.domain.clone()).or_default() += 1;
        }
    }

    DomainInsights {
        top_queried_domains: top_domain_entries(&queried),
        top_blocked_domains: top_domain_entries(&blocked),
        observed_queries,
    }
}

fn top_domain_entries(counts: &HashMap<String, usize>) -> Vec<DomainInsightEntry> {
    let mut entries = counts
        .iter()
        .map(|(domain, count)| DomainInsightEntry {
            domain: domain.clone(),
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
    state.dns_runtime.pause_protection_until(until);
    tracing::info!(minutes = request.minutes, %until, "protection paused");
}

async fn resume_runtime(State(state): State<ServerState>) {
    state.dns_runtime.resume_protection();
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
            outcome: "saved".to_string(),
            hash: None,
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
            outcome: "saved".to_string(),
            hash: None,
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
            outcome: "saved".to_string(),
            hash: None,
            rule_count: None,
            notes: vec![format!("deleted blocklist {}", source.name)],
        },
    }))
}

async fn refresh_sources_once(
    state: &ServerState,
    reason: &str,
    only_source_ids: Option<&HashSet<Uuid>>,
) -> Result<RefreshResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("build refresh http client")?;

    let selected_sources = state
        .storage
        .list_sources()
        .await?
        .into_iter()
        .filter(|source| source.enabled)
        .filter(|source| {
            only_source_ids
                .map(|ids| ids.contains(&source.id))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    anyhow::ensure!(
        !selected_sources.is_empty(),
        "no enabled sources configured"
    );

    let source_ids = selected_sources
        .iter()
        .map(|source| source.id)
        .collect::<Vec<_>>();
    update_source_refresh_attempts(&state.storage, &source_ids, chrono::Utc::now()).await?;

    let enabled_sources = selected_sources
        .into_iter()
        .map(source_definition_from_record)
        .collect::<Result<Vec<_>>>()?;

    let enabled_source_count = enabled_sources.len();
    let mut parsed_sources = Vec::with_capacity(enabled_source_count);
    for source in enabled_sources {
        parsed_sources.push(fetch_and_parse_source(&client, source).await?);
    }

    let verification = verify_candidate(&parsed_sources, &state.protected_domains);
    if !verification.passed {
        tracing::warn!(
            reason,
            notes = ?verification.notes,
            "refresh rejected before activation"
        );
        return Ok(RefreshResponse {
            outcome: "rejected".to_string(),
            hash: None,
            rule_count: None,
            notes: verification.notes,
        });
    }

    let catalog = build_runtime_policy_catalog(
        &parsed_sources,
        state.protected_domains.as_ref().clone(),
        configured_block_mode(),
    );

    // The safety net runs against the candidate BEFORE it is installed. It
    // used to run after activation and roll the runtime back to the previous
    // compiled policy from storage; with that history gone, the only sound
    // order is to refuse a candidate that would take a protected name off the
    // network and keep serving whatever is already in force. `verify_candidate`
    // above already probed the flattened rule set; this pass covers what it
    // cannot see -- each per-profile engine is built from a subset of the
    // sources and can lose the allow rule that rescued a name globally.
    let regressions = protected_domain_regressions(&catalog, &state.protected_domains);
    if !regressions.is_empty() {
        tracing::warn!(
            reason,
            notes = ?regressions,
            "refresh rejected: candidate blocks protected domains"
        );
        return Ok(RefreshResponse {
            outcome: "rejected".to_string(),
            hash: None,
            rule_count: None,
            notes: regressions,
        });
    }

    let hash = catalog.global_policy.artifact().hash.clone();
    let rule_count = catalog.global_policy.artifact().rules.len();
    activate_policy_catalog(state, catalog);
    apply_runtime_device_policies(state).await?;
    tracing::info!(reason, %hash, rule_count, "activated refreshed policy");

    Ok(RefreshResponse {
        outcome: "activated".to_string(),
        hash: Some(hash),
        rule_count: Some(rule_count),
        notes: vec![format!("refreshed {} source(s)", enabled_source_count)],
    })
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

async fn warm_runtime_policy_catalog(state: &ServerState) -> Result<()> {
    let catalog = load_current_runtime_policy_catalog(state).await?;
    activate_policy_catalog(state, catalog);
    Ok(())
}

/// Install a compiled catalog and remember the engine it displaces.
///
/// The displaced engine goes into [`ServerState::previous_policy`]; nothing on
/// the DNS path reads it, so a swap costs one `Arc` move under a lock nobody
/// else contends for.
fn activate_policy_catalog(state: &ServerState, catalog: RuntimePolicyCatalog) {
    let outgoing = state.dns_runtime.current_policy();
    *write_recover(&state.previous_policy) = Some(outgoing);
    state
        .dns_runtime
        .replace_policy_catalog(catalog.global_policy, catalog.profile_policies);
}

async fn load_current_runtime_policy_catalog(state: &ServerState) -> Result<RuntimePolicyCatalog> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("build runtime policy catalog http client")?;

    let enabled_sources = state
        .storage
        .list_sources()
        .await?
        .into_iter()
        .filter(|source| source.enabled)
        .map(source_definition_from_record)
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(!enabled_sources.is_empty(), "no enabled sources configured");

    let mut parsed_sources = Vec::with_capacity(enabled_sources.len());
    for source in enabled_sources {
        parsed_sources.push(fetch_and_parse_source(&client, source).await?);
    }

    let verification = verify_candidate(&parsed_sources, &state.protected_domains);
    anyhow::ensure!(
        verification.passed,
        "runtime policy catalog verification failed: {:?}",
        verification.notes
    );

    Ok(build_runtime_policy_catalog(
        &parsed_sources,
        state.protected_domains.as_ref().clone(),
        configured_block_mode(),
    ))
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

fn source_definition_from_record(record: SourceRecord) -> Result<SourceDefinition> {
    let kind = source_kind_from_str(&record.kind)
        .ok_or_else(|| anyhow::anyhow!("unsupported source kind: {}", record.kind))?;

    Ok(SourceDefinition {
        id: record.id,
        name: record.name,
        url: Url::parse(&record.url)?,
        kind,
        enabled: record.enabled,
        profile: normalize_profile_name(&record.profile)
            .ok_or_else(|| anyhow::anyhow!("unsupported source profile: {}", record.profile))?,
        verification_strictness: record.verification_strictness,
    })
}

fn normalize_profile_name(profile: &str) -> Option<String> {
    let normalized = profile.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn build_runtime_policy_catalog(
    parsed_sources: &[ParsedSource],
    protected_domains: HashSet<String>,
    block_mode: BlockMode,
) -> RuntimePolicyCatalog {
    let global_policy = Arc::new(build_policy_engine(
        parsed_sources.to_vec(),
        protected_domains.clone(),
        block_mode.clone(),
    ));

    let profiles = parsed_sources
        .iter()
        .filter_map(|source| normalize_profile_name(&source.source.profile))
        .filter(|profile| profile != "shared")
        .collect::<HashSet<_>>();

    let mut profile_policies = HashMap::new();
    for profile in profiles {
        let scoped_sources = parsed_sources
            .iter()
            .filter(|source| {
                normalize_profile_name(&source.source.profile)
                    .is_some_and(|candidate| candidate == profile || candidate == "shared")
            })
            .cloned()
            .collect::<Vec<_>>();

        if !scoped_sources.iter().any(|source| {
            normalize_profile_name(&source.source.profile).as_deref() == Some(profile.as_str())
        }) {
            continue;
        }

        profile_policies.insert(
            profile,
            Arc::new(build_policy_engine(
                scoped_sources,
                protected_domains.clone(),
                block_mode.clone(),
            )),
        );
    }

    RuntimePolicyCatalog {
        global_policy,
        profile_policies,
    }
}

fn runtime_device_policies_from_records(devices: Vec<DeviceRecord>) -> Vec<DevicePolicyConfig> {
    devices
        .into_iter()
        .map(|device| {
            let policy_mode = normalize_device_policy_mode(&device.policy_mode)
                .unwrap_or_else(|| "global".to_string());
            let blocklist_profile_override = if policy_mode == "custom" {
                device
                    .blocklist_profile_override
                    .as_deref()
                    .and_then(normalize_profile_name)
            } else {
                None
            };
            let protection_override = if policy_mode == "custom" {
                normalize_device_protection_override(&device.protection_override)
                    .unwrap_or_else(|| "inherit".to_string())
            } else {
                "inherit".to_string()
            };
            let allowed_domains = if policy_mode == "custom" {
                normalize_device_allowed_domains(device.allowed_domains)
            } else {
                Vec::new()
            };

            DevicePolicyConfig {
                ip_address: device.ip_address,
                policy_mode,
                blocklist_profile_override,
                protection_override,
                allowed_domains,
                // Per-device block rules had no source other than the service
                // manifests, which are gone. The runtime still honours the
                // field; nothing fills it until the device model is rebuilt.
                blocked_domains: Vec::new(),
            }
        })
        .collect()
}

async fn apply_runtime_device_policies(state: &ServerState) -> Result<()> {
    let devices = state.storage.list_devices().await?;
    state
        .dns_runtime
        .replace_device_policies(runtime_device_policies_from_records(devices));
    Ok(())
}

fn normalize_source_kind(kind: &str) -> Option<String> {
    let normalized = kind.trim().to_ascii_lowercase();
    source_kind_from_str(&normalized)?;
    Some(normalized)
}

fn source_kind_from_str(kind: &str) -> Option<SourceKind> {
    match kind {
        "domains" => Some(SourceKind::Domains),
        "hosts" => Some(SourceKind::Hosts),
        "adblock" => Some(SourceKind::Adblock),
        _ => None,
    }
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

/// Protected names the candidate's rules would block, per policy scope. Empty
/// means it is safe to install.
///
/// The compiled engines cannot be probed directly: [`PolicyEngine::evaluate`]
/// answers `Allowed` for every protected suffix before it consults a single
/// rule, so evaluating the catalog as built would never find anything. Each
/// engine's rules are therefore recompiled WITHOUT a protected set -- the same
/// trick `verify_candidate` uses -- and probed in that form. Every engine in
/// the catalog is checked, not just the global one: a profile is built from a
/// subset of the sources and can lack the allow rule that rescued a name in
/// the global set.
fn protected_domain_regressions(
    catalog: &RuntimePolicyCatalog,
    protected_domains: &HashSet<String>,
) -> Vec<String> {
    let scopes = std::iter::once(("global", catalog.global_policy.as_ref())).chain(
        catalog
            .profile_policies
            .iter()
            .map(|(profile, policy)| (profile.as_str(), policy.as_ref())),
    );

    let mut blocked = Vec::new();
    for (scope, policy) in scopes {
        let artifact = policy.artifact();
        let probe = PolicyEngine::new(RulesetArtifact::new(
            artifact.rules.clone(),
            HashSet::new(),
            artifact.block_mode.clone(),
        ));
        blocked.extend(protected_domains.iter().filter_map(|domain| {
            match probe.evaluate(domain).kind {
                DecisionKind::Blocked(_) => Some(format!(
                    "protected domain blocked in {scope} policy: {domain}"
                )),
                DecisionKind::Allowed => None,
            }
        }));
    }
    blocked.sort_unstable();
    blocked
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn runtime_device_policies_clear_global_overrides() {
        let configs = runtime_device_policies_from_records(vec![DeviceRecord {
            id: Uuid::new_v4(),
            name: "Laptop".to_string(),
            ip_address: "192.168.1.10".to_string(),
            policy_mode: "global".to_string(),
            blocklist_profile_override: Some("Aggressive".to_string()),
            protection_override: "bypass".to_string(),
            allowed_domains: vec!["example.com".to_string()],
            service_overrides: Vec::new(),
        }]);

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].policy_mode, "global");
        assert_eq!(configs[0].blocklist_profile_override, None);
        assert_eq!(configs[0].protection_override, "inherit");
        assert!(configs[0].allowed_domains.is_empty());
        assert!(configs[0].blocked_domains.is_empty());
    }

    #[test]
    fn build_runtime_policy_catalog_includes_shared_rules_in_profiles() {
        let shared = parse_source(
            SourceDefinition {
                id: Uuid::new_v4(),
                name: "Shared".to_string(),
                url: Url::parse("data:text/plain,shared.example").expect("shared url"),
                kind: SourceKind::Domains,
                enabled: true,
                profile: "shared".to_string(),
                verification_strictness: "balanced".to_string(),
            },
            "shared.example",
        );
        let balanced = parse_source(
            SourceDefinition {
                id: Uuid::new_v4(),
                name: "Balanced".to_string(),
                url: Url::parse("data:text/plain,balanced.example").expect("balanced url"),
                kind: SourceKind::Domains,
                enabled: true,
                profile: "balanced".to_string(),
                verification_strictness: "balanced".to_string(),
            },
            "balanced.example",
        );

        let catalog =
            build_runtime_policy_catalog(&[shared, balanced], HashSet::new(), BlockMode::NullIp);
        let balanced_policy = catalog
            .profile_policies
            .get("balanced")
            .expect("balanced profile policy");

        assert!(matches!(
            balanced_policy.evaluate("shared.example").kind,
            DecisionKind::Blocked(_)
        ));
        assert!(matches!(
            balanced_policy.evaluate("balanced.example").kind,
            DecisionKind::Blocked(_)
        ));
    }

    /// The pre-activation safety net has to see through the protected tier: a
    /// catalog compiled with a protected set answers `Allowed` for those names no
    /// matter what its rules say, so a check that trusted the compiled engines
    /// would never fire. It also has to look at every profile, because a profile
    /// built from a subset of the sources can lose the allow rule that rescued a
    /// name in the global set.
    #[test]
    fn protected_domain_regressions_sees_through_protected_tier_and_checks_profiles() {
        let source = |name: &str, profile: &str, body: &str| {
            parse_source(
                SourceDefinition {
                    id: Uuid::new_v4(),
                    name: name.to_string(),
                    url: Url::parse(&format!("data:text/plain,{name}")).expect("url"),
                    kind: SourceKind::Adblock,
                    enabled: true,
                    profile: profile.to_string(),
                    verification_strictness: "balanced".to_string(),
                },
                body,
            )
        };
        let protected = HashSet::from(["apple.com".to_string()]);

        // Only the balanced profile carries the block; the allow that rescues it
        // globally lives in a strict-only source.
        let catalog = build_runtime_policy_catalog(
            &[
                source("balanced", "balanced", "||apple.com^"),
                source("strict", "strict", "@@||apple.com^"),
            ],
            protected.clone(),
            BlockMode::NullIp,
        );
        assert!(
            matches!(
                catalog
                    .profile_policies
                    .get("balanced")
                    .expect("balanced profile")
                    .evaluate("apple.com")
                    .kind,
                DecisionKind::Allowed
            ),
            "the compiled engine hides the regression behind the protected tier"
        );
        assert_eq!(
            protected_domain_regressions(&catalog, &protected),
            vec!["protected domain blocked in balanced policy: apple.com".to_string()]
        );

        let clean = build_runtime_policy_catalog(
            &[source("shared", "shared", "||ads.example^")],
            protected.clone(),
            BlockMode::NullIp,
        );
        assert!(protected_domain_regressions(&clean, &protected).is_empty());
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
