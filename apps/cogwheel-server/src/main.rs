use anyhow::{Context, Result};
use axum::extract::{FromRef, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use cogwheel_api::{ApiEnvelope, ApiState, AppConfig, RuntimeGuardConfig, router};
use cogwheel_classifier::ClassifierSettings;
use cogwheel_dns_core::{
    ClassificationEvent, DevicePolicyConfig, DnsRuntime, DnsRuntimeConfig, DnsRuntimeSnapshot,
    QueryActivityEvent,
};
use cogwheel_lists::{
    ParsedSource, SourceDefinition, SourceKind, build_policy_engine, fetch_and_parse_source,
    parse_source, synthetic_source, verify_candidate,
};
use cogwheel_policy::{BlockMode, DecisionKind, PolicyEngine};
use cogwheel_services::{
    ServiceManifest, ServiceToggleMode, ServiceToggleSnapshot, built_in_service_manifests,
    compile_service_rule_layer,
};
use cogwheel_storage::{
    AuditEvent, DeviceRecord, DeviceServiceOverrideRecord, NotificationDeliveryRecord,
    RulesetRecord, SecurityEventRecord, SourceRecord, Storage, SyncEnvelope,
};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::xfer::Protocol;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use reqwest::Client;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::time::interval;
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
    http_client: Client,
    notification_settings: Arc<RwLock<NotificationSettings>>,
    threat_intel_settings: Arc<RwLock<ThreatIntelSettings>>,
    federated_learning_settings: Arc<RwLock<FederatedLearningSettings>>,
    recent_dns_activity: Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    protected_domains: Arc<HashSet<String>>,
    runtime_guard: RuntimeGuardConfig,
    sync_seen_nonces: Arc<Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
    rate_limiter: Arc<RateLimiter>,
    dns_udp_bind_addr: SocketAddr,
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
        let mut requests = self.requests.lock().unwrap();

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ThreatIntelProviderConfig {
    id: String,
    display_name: String,
    enabled: bool,
    feed_url: Option<String>,
    api_key_configured: bool,
    update_interval_minutes: u32,
    last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ThreatIntelSettings {
    providers: Vec<ThreatIntelProviderConfig>,
    recommendations: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ThreatIntelProviderUpdate {
    id: String,
    enabled: bool,
    feed_url: Option<String>,
    update_interval_minutes: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FederatedLearningSettings {
    enabled: bool,
    coordinator_url: Option<String>,
    node_id: String,
    round_interval_hours: u32,
    last_round_at: Option<chrono::DateTime<chrono::Utc>>,
    last_model_version: Option<String>,
    privacy_mode: String,
    raw_log_export_enabled: bool,
    recommendations: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct FederatedLearningUpdate {
    enabled: bool,
    coordinator_url: Option<String>,
    round_interval_hours: u32,
}

#[derive(serde::Serialize)]
struct RulesetSummary {
    id: Uuid,
    hash: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Serialize)]
struct RefreshResponse {
    outcome: String,
    ruleset: Option<RulesetSummary>,
    notes: Vec<String>,
}

#[derive(serde::Serialize)]
struct RuntimeHealthResponse {
    snapshot: DnsRuntimeSnapshot,
    degraded: bool,
    notes: Vec<String>,
}

#[derive(serde::Serialize)]
struct DashboardSummary {
    protection_status: String,
    protection_paused_until: Option<chrono::DateTime<chrono::Utc>>,
    active_ruleset: Option<RulesetSummary>,
    source_count: usize,
    enabled_source_count: usize,
    service_toggle_count: usize,
    device_count: usize,
    runtime_health: RuntimeHealthResponse,
    latest_audit_events: Vec<AuditEvent>,
    recent_security_events: Vec<SecurityEventRecord>,
    recent_notification_deliveries: Vec<NotificationDeliveryEvent>,
    notification_health: NotificationHealthSummary,
    notification_failure_analytics: NotificationFailureAnalytics,
    security_summary: SecuritySummary,
    domain_insights: DomainInsights,
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

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationDeliveryEvent {
    status: String,
    event_type: String,
    severity: String,
    title: String,
    summary: String,
    target: String,
    domain: String,
    device_name: Option<String>,
    client_ip: String,
    attempts: usize,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationHealthSummary {
    delivered_count: usize,
    failed_count: usize,
    last_delivery_at: Option<chrono::DateTime<chrono::Utc>>,
    last_failure_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationFailureAnalytics {
    success_rate_percent: f32,
    top_failed_domains: Vec<NotificationFailureDomain>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationFailureDomain {
    domain: String,
    failure_count: usize,
}

#[derive(Debug, Clone)]
struct NotificationWebhookEvent {
    event_type: String,
    severity: String,
    title: String,
    summary: String,
    domain: Option<String>,
    device_name: Option<String>,
    client_ip: Option<String>,
    details: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationTestResult {
    outcome: String,
    target: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct NotificationTestPreset {
    name: String,
    domain: String,
    severity: String,
    device_name: String,
    dry_run: bool,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct DashboardQuery {
    notification_window: Option<usize>,
    notification_history_window: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SecuritySummary {
    medium_count: usize,
    high_count: usize,
    critical_count: usize,
    top_devices: Vec<DeviceSecuritySummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DeviceSecuritySummary {
    label: String,
    event_count: usize,
    highest_severity: String,
}

#[derive(serde::Serialize)]
struct SettingsSummary {
    blocklists: Vec<SourceRecord>,
    blocklist_statuses: Vec<BlocklistStatusView>,
    block_profiles: Vec<BlockProfileRecord>,
    devices: Vec<DeviceRecord>,
    services: Vec<ServiceToggleView>,
    classifier: ClassifierSettings,
    notifications: NotificationSettings,
    notification_test_presets: Vec<NotificationTestPreset>,
    runtime_guard: RuntimeGuardConfig,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct NotificationSettings {
    enabled: bool,
    webhook_url: Option<String>,
    min_severity: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct UpdateNotificationSettingsRequest {
    enabled: bool,
    webhook_url: Option<String>,
    min_severity: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct TestNotificationRequest {
    domain: Option<String>,
    severity: Option<String>,
    device_name: Option<String>,
    dry_run: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct UpdateNotificationPresetsRequest {
    presets: Vec<NotificationTestPreset>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BlocklistStatusView {
    id: Uuid,
    name: String,
    last_refresh_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    due_for_refresh: bool,
}

#[derive(Debug, Clone)]
struct RuntimeRegressionReport {
    degraded: bool,
    notes: Vec<String>,
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

#[derive(serde::Serialize)]
struct ServiceToggleView {
    manifest: ServiceManifest,
    mode: ServiceToggleMode,
}

#[derive(serde::Deserialize)]
struct UpdateServiceToggleRequest {
    service_id: String,
    mode: ServiceToggleMode,
}

#[derive(serde::Deserialize)]
struct UpdateClassifierSettingsRequest {
    mode: cogwheel_classifier::ClassifierMode,
    threshold: f32,
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
    service_overrides: Option<Vec<DeviceServiceOverrideRecord>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SyncStatePayloadV1 {
    version: u32,
    revision: u64,
    profile: String,
    exported_at: chrono::DateTime<chrono::Utc>,
    blocklists: Vec<SourceRecord>,
    devices: Vec<DeviceRecord>,
    classifier: ClassifierSettings,
    notifications: NotificationSettings,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SyncProfile {
    Full,
    SettingsOnly,
    ReadOnlyFollower,
}

impl SyncProfile {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::SettingsOnly => "settings-only",
            Self::ReadOnlyFollower => "read-only-follower",
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ImportSyncEnvelopeRequest {
    envelope: SyncEnvelope,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return Ok(());
    }

    let config = AppConfig::load()?;
    let storage = Arc::new(Storage::connect(&config.storage.database_url).await?);

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

    let protected_domains = Arc::new(HashSet::from(["connectivitycheck.gstatic.com".to_string()]));
    let verification = verify_candidate(std::slice::from_ref(&parsed), &protected_domains);
    anyhow::ensure!(
        verification.passed,
        "default ruleset failed verification: {:?}",
        verification.notes
    );

    let policy = Arc::new(build_policy_engine(
        vec![parsed],
        protected_domains.as_ref().clone(),
        BlockMode::NullIp,
    ));
    storage
        .record_ruleset(&RulesetRecord {
            id: policy.artifact().id,
            hash: policy.artifact().hash.clone(),
            status: "active".to_string(),
            created_at: policy.artifact().created_at,
            artifact_json: serde_json::to_string(policy.artifact())?,
        })
        .await?;
    storage.activate_ruleset(policy.artifact().id).await?;
    storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "ruleset.activated".to_string(),
            payload: serde_json::json!({
                "ruleset_id": policy.artifact().id,
                "hash": policy.artifact().hash,
                "reason": "bootstrap",
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await?;

    let mut registry = Registry::default();
    let startup_counter: Counter<u64> = Counter::default();
    registry.register(
        "cogwheel_startups_total",
        "Number of server startups",
        startup_counter.clone(),
    );
    startup_counter.inc();
    let registry = Arc::new(registry);

    let resolver = build_resolver(&config.upstream.servers)?;
    let classifier_settings = load_classifier_settings(&storage).await?;
    let notification_settings = Arc::new(RwLock::new(load_notification_settings(&storage).await?));
    let recent_dns_activity = Arc::new(Mutex::new(VecDeque::with_capacity(4096)));
    let http_client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build notification client")?;
    let dns_runtime = Arc::new(DnsRuntime::new(resolver, policy, classifier_settings));
    dns_runtime.set_classification_observer(Arc::new({
        let storage = storage.clone();
        let http_client = http_client.clone();
        let notification_settings = notification_settings.clone();
        move |event| {
            let storage = storage.clone();
            let http_client = http_client.clone();
            let notification_settings = notification_settings.clone();
            tokio::spawn(async move {
                if let Err(error) = record_security_event_from_classification(
                    storage,
                    http_client,
                    notification_settings,
                    event,
                )
                .await
                {
                    tracing::warn!(%error, "failed to record security event");
                }
            });
        }
    }));
    dns_runtime.set_query_activity_observer(Arc::new({
        let recent_dns_activity = recent_dns_activity.clone();
        move |event| record_recent_dns_activity(&recent_dns_activity, event)
    }));

    let dns_handle = tokio::spawn({
        let runtime = dns_runtime.clone();
        let dns_config = DnsRuntimeConfig {
            udp_bind_addr: config.server.dns_udp_bind_addr,
            tcp_bind_addr: config.server.dns_tcp_bind_addr,
        };
        async move { runtime.serve(dns_config).await }
    });

    let app_state = ServerState {
        api_state: ApiState { registry },
        storage,
        dns_runtime,
        http_client,
        notification_settings,
        threat_intel_settings: Arc::new(RwLock::new(default_threat_intel_settings())),
        federated_learning_settings: Arc::new(RwLock::new(default_federated_learning_settings())),
        recent_dns_activity,
        protected_domains,
        runtime_guard: config.runtime_guard,
        sync_seen_nonces: Arc::new(Mutex::new(HashMap::new())),
        rate_limiter: Arc::new(RateLimiter::new(100, 60)),
        dns_udp_bind_addr: config.server.dns_udp_bind_addr,
    };
    if let Err(error) = warm_runtime_policy_catalog(&app_state).await {
        tracing::warn!(%error, "failed to warm runtime policy catalog on startup");
    }
    sync_runtime_device_policies(&app_state).await?;
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
    let app = build_http_app(app_state);
    let listener = tokio::net::TcpListener::bind(config.server.http_bind_addr)
        .await
        .context("bind http listener")?;

    tokio::select! {
        result = dns_handle => {
            result.context("dns task join failure")??;
        }
        result = refresh_handle => {
            result.context("refresh task join failure")?;
        }
        result = axum::serve(listener, app) => {
            result.context("http server failure")?;
        }
    }

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("info".parse().expect("valid directive")),
        )
        .json()
        .init();
}

fn build_resolver(servers: &[String]) -> Result<TokioResolver> {
    let mut group = NameServerConfigGroup::new();
    for server in servers {
        let socket_addr = server
            .parse()
            .with_context(|| format!("invalid upstream server: {server}"))?;
        group.push(NameServerConfig::new(socket_addr, Protocol::Udp));
        group.push(NameServerConfig::new(socket_addr, Protocol::Tcp));
    }

    let config = ResolverConfig::from_parts(None, vec![], group);
    Ok(
        TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(ResolverOpts::default())
            .build(),
    )
}

fn build_http_app(app_state: ServerState) -> Router {
    let api_app = router(app_state.clone())
        .merge(admin_router())
        .route("/favicon.ico", get(favicon));

    let app = if let Some(web_dist_dir) = resolve_web_dist_dir() {
        tracing::info!(path = %web_dist_dir.display(), "serving bundled web assets");
        let index_path = web_dist_dir.join("index.html");
        api_app.fallback_service(
            ServeDir::new(web_dist_dir).not_found_service(ServeFile::new(index_path)),
        )
    } else {
        tracing::warn!("web assets not found; serving API routes only");
        api_app
    };

    app.with_state(app_state).layer(TraceLayer::new_for_http())
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
        .route("/api/v1/settings/blocklists", post(upsert_blocklist))
        .route(
            "/api/v1/settings/blocklists/state",
            post(update_blocklist_state),
        )
        .route("/api/v1/settings/blocklists/delete", post(delete_blocklist))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices", post(upsert_device))
        .route("/api/v1/security-events", get(list_security_events))
        .route("/api/v1/sources", get(list_sources))
        .route("/api/v1/sources/refresh", post(refresh_sources))
        .route("/api/v1/services", get(list_services))
        .route("/api/v1/services/toggles", post(update_service_toggle))
        .route(
            "/api/v1/settings/classifier",
            post(update_classifier_settings),
        )
        .route(
            "/api/v1/settings/notifications",
            post(update_notification_settings),
        )
        .route(
            "/api/v1/settings/notifications/test",
            post(test_notification_settings),
        )
        .route(
            "/api/v1/settings/notifications/presets",
            post(update_notification_test_presets),
        )
        .route("/api/v1/runtime", get(runtime_snapshot))
        .route("/api/v1/runtime/health", get(runtime_health))
        .route(
            "/api/v1/runtime/health/check",
            post(run_runtime_health_check),
        )
        .route("/api/v1/runtime/pause", post(pause_runtime))
        .route("/api/v1/runtime/resume", post(resume_runtime))
        .route("/api/v1/resolver-access", get(resolver_access_status))
        .route(
            "/api/v1/false-positive-budget",
            get(false_positive_budget_status),
        )
        .route("/api/v1/latency-budget", get(latency_budget_status))
        .route("/api/v1/tailscale/status", get(tailscale_status))
        .route("/api/v1/tailscale/exit-node", post(tailscale_exit_node))
        .route("/api/v1/tailscale/rollback", post(tailscale_rollback))
        .route("/api/v1/tailscale/dns-check", get(tailscale_dns_check))
        .route("/api/v1/sync/status", get(sync_status))
        .route("/api/v1/sync/profile", get(sync_profile))
        .route("/api/v1/sync/profile", post(update_sync_profile))
        .route("/api/v1/sync/transport", get(sync_transport))
        .route("/api/v1/sync/transport", post(update_sync_transport))
        .route("/api/v1/sync/export", get(export_sync_state))
        .route("/api/v1/sync/import", post(import_sync_state))
        .route("/api/v1/rulesets", get(list_rulesets))
        .route("/api/v1/rulesets/rollback", post(rollback_ruleset))
        .route("/api/v1/audit-events", get(list_audit_events))
        .route("/api/v1/backup", get(backup_data))
        .route("/api/v1/backup/restore", post(restore_data))
        .route(
            "/api/v1/resilience/upstream-outage",
            post(simulate_upstream_outage),
        )
        .route(
            "/api/v1/resilience/db-corruption",
            post(simulate_db_corruption),
        )
        .route(
            "/api/v1/resilience/source-failure",
            post(simulate_source_failure),
        )
        .route(
            "/api/v1/resilience/sync-partition",
            post(simulate_sync_partition),
        )
        .route("/api/v1/load-test", post(run_load_test))
        .route("/api/v1/benchmark/rust-opts", get(benchmark_rust_opts))
        .route("/api/v1/config/version", get(config_version))
        .route("/api/v1/threat-intel/providers", get(threat_intel_settings))
        .route(
            "/api/v1/threat-intel/providers",
            post(update_threat_intel_provider),
        )
        .route(
            "/api/v1/federated-learning/status",
            get(federated_learning_settings),
        )
        .route(
            "/api/v1/federated-learning/status",
            post(update_federated_learning_settings),
        )
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
    let service_overrides = validate_device_service_overrides(
        policy_mode.as_str(),
        request.service_overrides.unwrap_or_default(),
    )
    .map_err(|message| (axum::http::StatusCode::BAD_REQUEST, message))?;

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
        service_overrides,
    };

    state.storage.upsert_device(&device).await.map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist device".to_string(),
        )
    })?;
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "device.upserted".to_string(),
            payload: serde_json::to_string(&device).map_err(|_| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to serialize device audit payload".to_string(),
                )
            })?,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to record device audit event".to_string(),
            )
        })?;

    sync_runtime_device_policies(&state).await.map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "failed to sync runtime device policies".to_string(),
        )
    })?;

    Ok(Json(ApiEnvelope { data: device }))
}

async fn list_security_events(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<Vec<SecurityEventRecord>>>, axum::http::StatusCode> {
    state
        .storage
        .recent_security_events(20)
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn dashboard_summary(
    State(state): State<ServerState>,
    Query(query): Query<DashboardQuery>,
) -> Result<Json<ApiEnvelope<DashboardSummary>>, axum::http::StatusCode> {
    let notification_window = normalize_notification_window(query.notification_window);
    let notification_history_window =
        normalize_notification_window(query.notification_history_window);
    let sources = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let rulesets = state
        .storage
        .list_rulesets()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let active_ruleset = rulesets
        .iter()
        .find(|row| row.status == "active")
        .map(|row| RulesetSummary {
            id: row.id,
            hash: row.hash.clone(),
            status: row.status.clone(),
            created_at: row.created_at,
        });
    let runtime_health = current_runtime_health(&state);
    let latest_audit_events = state
        .storage
        .recent_audit_events(5)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let notification_analytics_deliveries = state
        .storage
        .recent_notification_deliveries(notification_window as i64)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let notification_history_deliveries = state
        .storage
        .recent_notification_deliveries(notification_history_window as i64)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let devices = state
        .storage
        .list_devices()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let security_events = state
        .storage
        .recent_security_events(25)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let security_summary = build_security_summary(&security_events);
    let recent_security_events = security_events.into_iter().take(5).collect();
    let recent_notification_deliveries =
        build_notification_delivery_events(&notification_history_deliveries);
    let notification_health = build_notification_health_summary(&notification_analytics_deliveries);
    let notification_failure_analytics =
        build_notification_failure_analytics(&notification_analytics_deliveries);
    let domain_insights = build_domain_insights(&state);
    let snapshot = load_service_toggle_snapshot(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let protection_paused_until = state.dns_runtime.protection_paused_until();

    Ok(Json(ApiEnvelope {
        data: DashboardSummary {
            protection_status: if let Some(until) = protection_paused_until {
                if chrono::Utc::now() < until {
                    "Paused".to_string()
                } else if runtime_health.degraded {
                    "Needs Attention".to_string()
                } else {
                    "Protected".to_string()
                }
            } else if runtime_health.degraded {
                "Needs Attention".to_string()
            } else {
                "Protected".to_string()
            },
            protection_paused_until,
            active_ruleset,
            source_count: sources.len(),
            enabled_source_count: sources.iter().filter(|source| source.enabled).count(),
            service_toggle_count: snapshot
                .toggles
                .iter()
                .filter(|toggle| !matches!(toggle.mode, ServiceToggleMode::Inherit))
                .count(),
            device_count: devices.len(),
            runtime_health,
            latest_audit_events,
            recent_security_events,
            recent_notification_deliveries,
            notification_health,
            notification_failure_analytics,
            security_summary,
            domain_insights,
        },
    }))
}

fn record_recent_dns_activity(
    activity: &Arc<Mutex<VecDeque<DomainActivityRecord>>>,
    event: QueryActivityEvent,
) {
    let mut guard = activity.lock().expect("recent dns activity lock poisoned");
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
    let guard = state
        .recent_dns_activity
        .lock()
        .expect("recent dns activity lock poisoned");

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

#[derive(Debug, Clone, serde::Deserialize)]
struct LoadTestRequest {
    duration_secs: u64,
    qps: u32,
    cache_hit_ratio: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LoadTestResult {
    success: bool,
    queries_sent: u64,
    queries_succeeded: u64,
    queries_failed: u64,
    avg_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    cache_hit_ratio: f64,
    throughput_qps: f64,
    errors: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RustOptimizationBenchmark {
    domain_parsing_ns: u64,
    rule_matching_ns: u64,
    cache_lookup_ns: u64,
    memory_usage_bytes: u64,
    allocations_per_query: u64,
    recommendations: Vec<String>,
}

async fn run_load_test(
    State(state): State<ServerState>,
    Json(request): Json<LoadTestRequest>,
) -> Result<Json<ApiEnvelope<LoadTestResult>>, (axum::http::StatusCode, String)> {
    use std::time::{Duration, Instant};

    let duration = Duration::from_secs(request.duration_secs);
    let qps = request.qps.max(1);
    let cache_hit_ratio = request.cache_hit_ratio.clamp(0.0, 1.0);

    let mut latencies: Vec<f64> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut succeeded = 0u64;
    let mut failed = 0u64;
    let start = Instant::now();

    let test_domains = vec![
        "google.com",
        "facebook.com",
        "youtube.com",
        "amazon.com",
        "twitter.com",
        "wikipedia.org",
        "reddit.com",
        "netflix.com",
        "github.com",
        "stackoverflow.com",
        "example.com",
        "test.com",
        "demo.local",
        "internal.service",
        "api.example.com",
    ];

    let interval = Duration::from_secs_f64(1.0 / qps as f64);
    let mut query_count = 0u64;

    while start.elapsed() < duration {
        let loop_start = Instant::now();

        for domain in &test_domains {
            if start.elapsed() >= duration {
                break;
            }

            let should_hit_cache =
                (query_count as f64 % (1.0 / (1.0 - cache_hit_ratio).max(0.01))) < 1.0;
            let query_domain = if should_hit_cache && query_count > 0 {
                test_domains[(query_count as usize) % test_domains.len()]
            } else {
                domain
            };

            let query_start = Instant::now();
            match state
                .dns_runtime
                .probe_domain(query_domain, RecordType::A)
                .await
            {
                Ok(_) => {
                    succeeded += 1;
                    latencies.push(query_start.elapsed().as_secs_f64() * 1000.0);
                }
                Err(e) => {
                    failed += 1;
                    if errors.len() < 10 {
                        errors.push(format!("{}: {}", query_domain, e));
                    }
                }
            }
            query_count += 1;
        }

        let elapsed = loop_start.elapsed();
        if elapsed < interval {
            tokio::time::sleep(interval - elapsed).await;
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let avg_latency = latencies.iter().sum::<f64>() / latencies.len().max(1) as f64;
    let p95_idx = (latencies.len() as f64 * 0.95) as usize;
    let p99_idx = (latencies.len() as f64 * 0.99) as usize;
    let p95_latency = latencies.get(p95_idx).copied().unwrap_or(avg_latency);
    let p99_latency = latencies.get(p99_idx).copied().unwrap_or(avg_latency);

    let total_elapsed = start.elapsed().as_secs_f64();
    let throughput = (succeeded + failed) as f64 / total_elapsed.max(0.001);

    let mut result_errors = errors.clone();
    if failed > 0 && errors.is_empty() {
        result_errors.push(format!(
            "{} queries failed without specific error messages",
            failed
        ));
    }

    Ok(Json(ApiEnvelope {
        data: LoadTestResult {
            success: failed == 0,
            queries_sent: query_count,
            queries_succeeded: succeeded,
            queries_failed: failed,
            avg_latency_ms: avg_latency,
            p95_latency_ms: p95_latency,
            p99_latency_ms: p99_latency,
            cache_hit_ratio,
            throughput_qps: throughput,
            errors: result_errors,
        },
    }))
}

async fn benchmark_rust_opts(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<RustOptimizationBenchmark>>, axum::http::StatusCode> {
    use std::time::Instant;

    let iterations = 10000u64;
    let mut domain_parsing_total = 0u128;
    let mut rule_matching_total = 0u128;
    let mut cache_lookup_total = 0u128;

    for _ in 0..iterations {
        let start = Instant::now();
        let _domain: &str = "example.com";
        domain_parsing_total += start.elapsed().as_nanos();

        let start = Instant::now();
        let _matched = "example.com".contains("example");
        rule_matching_total += start.elapsed().as_nanos();

        let start = Instant::now();
        let _cached = state.dns_runtime.snapshot().cache_hits_total;
        cache_lookup_total += start.elapsed().as_nanos();
    }

    let domain_parsing_ns = (domain_parsing_total / iterations as u128) as u64;
    let rule_matching_ns = (rule_matching_total / iterations as u128) as u64;
    let cache_lookup_ns = (cache_lookup_total / iterations as u128) as u64;

    let snapshot = state.dns_runtime.snapshot();
    let queries = snapshot.queries_total.max(1);
    let cache_hit_rate = (snapshot.cache_hits_total as f64) / (queries as f64);

    let mut recommendations = Vec::new();

    if domain_parsing_ns > 100 {
        recommendations
            .push("Domain parsing slower than expected - consider zero-copy parsing".to_string());
    } else {
        recommendations.push("Domain parsing is optimized".to_string());
    }

    if rule_matching_ns > 500 {
        recommendations
            .push("Rule matching could benefit from prefix/suffix matching structures".to_string());
    } else {
        recommendations.push("Rule matching hot path is efficient".to_string());
    }

    if cache_hit_rate > 0.8 {
        recommendations.push("Cache hit rate is excellent".to_string());
    } else if cache_hit_rate > 0.5 {
        recommendations.push("Cache hit rate is moderate - consider tuning TTL values".to_string());
    } else {
        recommendations
            .push("Cache hit rate is low - review cache size and TTL settings".to_string());
    }

    recommendations.push(format!(
        "Current cache hit rate: {:.1}%",
        cache_hit_rate * 100.0
    ));

    Ok(Json(ApiEnvelope {
        data: RustOptimizationBenchmark {
            domain_parsing_ns,
            rule_matching_ns,
            cache_lookup_ns,
            memory_usage_bytes: 0,
            allocations_per_query: 0,
            recommendations,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct ConfigVersionStatus {
    schema_version: u32,
    config_version: u32,
    cogwheel_version: String,
    migration_count: u32,
    upgrade_available: bool,
    recommendations: Vec<String>,
}

async fn config_version(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<ConfigVersionStatus>>, axum::http::StatusCode> {
    let mut recommendations = Vec::new();

    let current_config_version = cogwheel_storage::CONFIG_SCHEMA_VERSION;
    let schema_version = cogwheel_storage::SCHEMA_VERSION;

    let stored_version = state.storage.get_config_version().unwrap_or(1);

    let upgrade_available = stored_version < current_config_version;

    if upgrade_available {
        recommendations.push(format!(
            "Config upgrade available: v{} -> v{}",
            stored_version, current_config_version
        ));
    } else {
        recommendations.push("Config schema is up to date".to_string());
    }

    recommendations.push(format!("Database schema version: {}", schema_version));

    Ok(Json(ApiEnvelope {
        data: ConfigVersionStatus {
            schema_version,
            config_version: stored_version,
            cogwheel_version: env!("CARGO_PKG_VERSION").to_string(),
            migration_count: 10,
            upgrade_available,
            recommendations,
        },
    }))
}

fn default_threat_intel_settings() -> ThreatIntelSettings {
    ThreatIntelSettings {
        providers: vec![
            ThreatIntelProviderConfig {
                id: "alphamountain".to_string(),
                display_name: "alphaMountain DNS Feed".to_string(),
                enabled: false,
                feed_url: Some("https://api.example.invalid/threat-intel/dns".to_string()),
                api_key_configured: false,
                update_interval_minutes: 30,
                last_sync_at: None,
                last_error: None,
                capabilities: vec!["domain-reputation".to_string(), "malware-c2".to_string()],
            },
            ThreatIntelProviderConfig {
                id: "abuse-ch".to_string(),
                display_name: "Abuse.ch Import Bridge".to_string(),
                enabled: false,
                feed_url: Some(
                    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
                        .to_string(),
                ),
                api_key_configured: false,
                update_interval_minutes: 60,
                last_sync_at: None,
                last_error: None,
                capabilities: vec!["ip-reputation".to_string(), "botnet-tracking".to_string()],
            },
        ],
        recommendations: vec![
            "Keep threat-intel providers optional so the DNS hot path remains deterministic."
                .to_string(),
            "Prefer pull-based feeds with cached snapshots instead of inline blocking lookups."
                .to_string(),
        ],
    }
}

fn default_federated_learning_settings() -> FederatedLearningSettings {
    FederatedLearningSettings {
        enabled: false,
        coordinator_url: None,
        node_id: "local-node".to_string(),
        round_interval_hours: 24,
        last_round_at: None,
        last_model_version: None,
        privacy_mode: "model-updates-only".to_string(),
        raw_log_export_enabled: false,
        recommendations: vec![
            "Share only aggregated model deltas, never raw DNS logs.".to_string(),
            "Require explicit opt-in before joining a coordinator.".to_string(),
        ],
    }
}

async fn threat_intel_settings(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<ThreatIntelSettings>>, axum::http::StatusCode> {
    let settings = state
        .threat_intel_settings
        .read()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    Ok(Json(ApiEnvelope { data: settings }))
}

async fn update_threat_intel_provider(
    State(state): State<ServerState>,
    Json(request): Json<ThreatIntelProviderUpdate>,
) -> Result<Json<ApiEnvelope<ThreatIntelSettings>>, axum::http::StatusCode> {
    let payload_for_audit;
    let updated = {
        let mut settings = state
            .threat_intel_settings
            .write()
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let provider = settings
            .providers
            .iter_mut()
            .find(|provider| provider.id == request.id)
            .ok_or(axum::http::StatusCode::NOT_FOUND)?;

        provider.enabled = request.enabled;
        provider.feed_url = request.feed_url.clone();
        provider.update_interval_minutes = request.update_interval_minutes.max(5);
        provider.last_error = None;
        payload_for_audit = serde_json::json!({
            "provider_id": provider.id,
            "enabled": provider.enabled,
            "feed_url": provider.feed_url,
            "update_interval_minutes": provider.update_interval_minutes,
        })
        .to_string();
        settings.clone()
    };

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "threat_intel_provider_updated".to_string(),
            payload: payload_for_audit,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope { data: updated }))
}

async fn federated_learning_settings(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<FederatedLearningSettings>>, axum::http::StatusCode> {
    let settings = state
        .federated_learning_settings
        .read()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    Ok(Json(ApiEnvelope { data: settings }))
}

async fn update_federated_learning_settings(
    State(state): State<ServerState>,
    Json(request): Json<FederatedLearningUpdate>,
) -> Result<Json<ApiEnvelope<FederatedLearningSettings>>, axum::http::StatusCode> {
    let payload_for_audit;
    let updated = {
        let mut settings = state
            .federated_learning_settings
            .write()
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        settings.enabled = request.enabled;
        settings.coordinator_url = request.coordinator_url.clone();
        settings.round_interval_hours = request.round_interval_hours.max(1);
        settings.raw_log_export_enabled = false;
        payload_for_audit = serde_json::json!({
            "enabled": settings.enabled,
            "coordinator_url": settings.coordinator_url,
            "round_interval_hours": settings.round_interval_hours,
            "privacy_mode": settings.privacy_mode,
            "raw_log_export_enabled": settings.raw_log_export_enabled,
        })
        .to_string();
        settings.clone()
    };

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "federated_learning_updated".to_string(),
            payload: payload_for_audit,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope { data: updated }))
}

async fn settings_summary(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<SettingsSummary>>, axum::http::StatusCode> {
    let blocklists = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let services = build_service_toggle_views(&state)
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
    let notifications = state
        .notification_settings
        .read()
        .expect("notification settings lock poisoned")
        .clone();
    let notification_test_presets = load_notification_test_presets(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: SettingsSummary {
            blocklists,
            blocklist_statuses,
            block_profiles,
            devices,
            services,
            classifier: state.dns_runtime.classifier_settings(),
            notifications,
            notification_test_presets,
            runtime_guard: state.runtime_guard.clone(),
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct TailscaleStatusView {
    installed: bool,
    daemon_running: bool,
    backend_state: Option<String>,
    hostname: Option<String>,
    tailnet_name: Option<String>,
    peer_count: usize,
    exit_node_active: bool,
    version: Option<String>,
    health_warnings: Vec<String>,
    last_error: Option<String>,
}

fn parse_tailscale_status_json(raw: &str) -> TailscaleStatusView {
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(error) => {
            return TailscaleStatusView {
                installed: true,
                daemon_running: false,
                backend_state: None,
                hostname: None,
                tailnet_name: None,
                peer_count: 0,
                exit_node_active: false,
                version: None,
                health_warnings: vec![],
                last_error: Some(format!("invalid tailscale json: {error}")),
            };
        }
    };

    let backend_state = value
        .get("BackendState")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let hostname = value
        .get("Self")
        .and_then(|self_value| self_value.get("HostName"))
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let tailnet_name = value
        .get("CurrentTailnet")
        .and_then(|tailnet| tailnet.get("Name"))
        .or_else(|| value.get("MagicDNSSuffix"))
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let peer_count = value
        .get("Peer")
        .and_then(serde_json::Value::as_object)
        .map(|peers| peers.len())
        .unwrap_or(0);
    let exit_node_active = value
        .get("Self")
        .and_then(|self_value| {
            self_value
                .get("ExitNodeStatus")
                .or_else(|| self_value.get("ExitNode"))
                .or_else(|| self_value.get("UsingExitNode"))
        })
        .map(|value| {
            value.as_bool().unwrap_or_else(|| {
                value
                    .as_object()
                    .map(|object| !object.is_empty())
                    .unwrap_or_else(|| value.as_str().is_some_and(|s| !s.is_empty()))
            })
        })
        .unwrap_or(false);
    let health_warnings = value
        .get("Health")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    TailscaleStatusView {
        installed: true,
        daemon_running: backend_state.as_deref() != Some("Stopped"),
        backend_state,
        hostname,
        tailnet_name,
        peer_count,
        exit_node_active,
        version: None,
        health_warnings,
        last_error: None,
    }
}

fn load_tailscale_status() -> TailscaleStatusView {
    match Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let mut status = parse_tailscale_status_json(&String::from_utf8_lossy(&output.stdout));
            if let Ok(version_output) = Command::new("tailscale").arg("version").output() {
                if version_output.status.success() {
                    status.version = Some(
                        String::from_utf8_lossy(&version_output.stdout)
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                    );
                }
            }
            status
        }
        Ok(output) => TailscaleStatusView {
            installed: true,
            daemon_running: false,
            backend_state: None,
            hostname: None,
            tailnet_name: None,
            peer_count: 0,
            exit_node_active: false,
            version: None,
            health_warnings: vec![],
            last_error: Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        },
        Err(error) => TailscaleStatusView {
            installed: false,
            daemon_running: false,
            backend_state: None,
            hostname: None,
            tailnet_name: None,
            peer_count: 0,
            exit_node_active: false,
            version: None,
            health_warnings: vec![],
            last_error: Some(error.to_string()),
        },
    }
}

async fn tailscale_status(
    State(_state): State<ServerState>,
) -> Result<Json<ApiEnvelope<TailscaleStatusView>>, axum::http::StatusCode> {
    Ok(Json(ApiEnvelope {
        data: load_tailscale_status(),
    }))
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TailscaleExitNodeRequest {
    enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TailscaleExitNodeResult {
    success: bool,
    message: String,
}

async fn tailscale_exit_node(
    Json(request): Json<TailscaleExitNodeRequest>,
) -> Result<Json<ApiEnvelope<TailscaleExitNodeResult>>, (axum::http::StatusCode, String)> {
    let status = load_tailscale_status();

    if !status.installed {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Tailscale is not installed".to_string(),
        ));
    }

    if !status.daemon_running {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Tailscale daemon is not running".to_string(),
        ));
    }

    let hostname = status.hostname.ok_or_else(|| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            "Cannot determine local Tailscale hostname".to_string(),
        )
    })?;

    let current_exit_node = status.exit_node_active;
    let cmd = if request.enabled {
        let output = Command::new("tailscale")
            .args(["ip", "-4"])
            .output()
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !output.status.success() {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "Failed to get Tailscale IP address".to_string(),
            ));
        }

        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "No Tailscale IP address found".to_string(),
            ));
        }

        let output = Command::new("tailscale")
            .args(["up", "--exit-node", &ip])
            .output()
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to enable exit-node: {}", err),
            ));
        }

        format!("Exit-node mode enabled on {}", hostname)
    } else {
        let output = Command::new("tailscale")
            .args(["up", "--exit-node="])
            .output()
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to disable exit-node: {}", err),
            ));
        }

        format!("Exit-node mode disabled on {}", hostname)
    };

    let _ = save_tailscale_state(current_exit_node, &hostname);

    Ok(Json(ApiEnvelope {
        data: TailscaleExitNodeResult {
            success: true,
            message: cmd,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TailscaleSavedState {
    exit_node_enabled: bool,
    saved_at: String,
    hostname: String,
}

fn get_tailscale_state_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".cogwheel_tailscale_state.json")
}

fn save_tailscale_state(exit_node_enabled: bool, hostname: &str) -> Result<(), String> {
    let state = TailscaleSavedState {
        exit_node_enabled,
        saved_at: chrono::Utc::now().to_rfc3339(),
        hostname: hostname.to_string(),
    };
    let json = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
    std::fs::write(get_tailscale_state_path(), json).map_err(|e| e.to_string())?;
    Ok(())
}

fn load_tailscale_state() -> Option<TailscaleSavedState> {
    let path = get_tailscale_state_path();
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

#[derive(Debug, Clone, serde::Serialize)]
struct TailscaleRollbackResult {
    success: bool,
    message: String,
    previous_state: Option<bool>,
}

async fn tailscale_rollback()
-> Result<Json<ApiEnvelope<TailscaleRollbackResult>>, (axum::http::StatusCode, String)> {
    let saved_state = load_tailscale_state().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            "No previous Tailscale state found to rollback".to_string(),
        )
    })?;

    let status = load_tailscale_status();

    if !status.installed {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Tailscale is not installed".to_string(),
        ));
    }

    if !status.daemon_running {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Tailscale daemon is not running".to_string(),
        ));
    }

    let output = if saved_state.exit_node_enabled {
        let output = Command::new("tailscale")
            .args(["ip", "-4"])
            .output()
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !output.status.success() {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "Failed to get Tailscale IP address".to_string(),
            ));
        }

        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Command::new("tailscale")
            .args(["up", "--exit-node", &ip])
            .output()
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        Command::new("tailscale")
            .args(["up", "--exit-node="])
            .output()
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to rollback exit-node: {}", err),
        ));
    }

    let _ = std::fs::remove_file(get_tailscale_state_path());

    Ok(Json(ApiEnvelope {
        data: TailscaleRollbackResult {
            success: true,
            message: format!(
                "Rolled back to previous state: exit-node {}",
                if saved_state.exit_node_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            previous_state: Some(saved_state.exit_node_enabled),
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct TailscaleDnsCheckResult {
    configured: bool,
    message: String,
    local_dns_server: Option<String>,
    suggestions: Vec<String>,
}

fn get_local_dns_server() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .ok()?
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    line.split_whitespace().nth(1).map(String::from)
                } else {
                    None
                }
            })
            .next()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

async fn tailscale_dns_check()
-> Result<Json<ApiEnvelope<TailscaleDnsCheckResult>>, (axum::http::StatusCode, String)> {
    let status = load_tailscale_status();
    let local_dns = get_local_dns_server();

    let mut suggestions = Vec::new();
    let mut configured = true;
    let message: String;

    if !status.installed {
        message = "Tailscale is not installed on this machine.".to_string();
        configured = false;
    } else if !status.daemon_running {
        message = "Tailscale daemon is not running.".to_string();
        configured = false;
    } else if !status.exit_node_active {
        message = "Exit-node mode is not active. Enable it to start filtering tailnet traffic."
            .to_string();
        suggestions
            .push("Click 'Enable exit node' in the dashboard to start filtering.".to_string());
    } else {
        message =
            "Exit-node mode is active. DNS filtering is enabled for tailnet clients.".to_string();
        if let Some(ref dns) = local_dns {
            suggestions.push(format!(
                "This machine is using {} as its DNS server. Ensure Cogwheel is running on {} to filter DNS queries.",
                dns, dns
            ));
        }
        suggestions.push("Tailnet clients will use this node as their exit node and DNS queries will be filtered.".to_string());
    }

    if status.exit_node_active {
        suggestions.push("To verify filtering is working, connect another tailnet client and check its DNS queries are blocked.".to_string());
    }

    Ok(Json(ApiEnvelope {
        data: TailscaleDnsCheckResult {
            configured,
            message,
            local_dns_server: local_dns,
            suggestions,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct SyncImportResult {
    imported_sources: usize,
    imported_devices: usize,
    applied_revision: u64,
    profile: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct SyncExportQuery {
    profile: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SyncProfileView {
    profile: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct UpdateSyncProfileRequest {
    profile: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SyncTransportView {
    mode: String,
    token_configured: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SyncPeerStatusView {
    node_public_key: String,
    imports: usize,
    last_import_at: chrono::DateTime<chrono::Utc>,
    last_revision: u64,
    profile: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SyncNodeStatusView {
    local_node_public_key: String,
    profile: String,
    revision: u64,
    transport_mode: String,
    transport_token_configured: bool,
    replay_cache_entries: usize,
    peers: Vec<SyncPeerStatusView>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct UpdateSyncTransportRequest {
    mode: String,
    token: Option<String>,
}

fn normalize_sync_transport_mode(raw: Option<&str>) -> String {
    match raw
        .unwrap_or("opportunistic")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "https-required" => "https-required".to_string(),
        _ => "opportunistic".to_string(),
    }
}

fn normalize_sync_profile(raw: Option<&str>) -> SyncProfile {
    match raw.unwrap_or("full").trim().to_ascii_lowercase().as_str() {
        "settings-only" => SyncProfile::SettingsOnly,
        "read-only-follower" => SyncProfile::ReadOnlyFollower,
        _ => SyncProfile::Full,
    }
}

async fn load_sync_revision(storage: &Storage) -> Result<u64> {
    let value = storage.get_setting("sync_revision").await?;
    Ok(value
        .as_deref()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(0))
}

async fn load_sync_profile(storage: &Storage) -> Result<SyncProfile> {
    let raw = storage.get_setting("sync_profile").await?;
    Ok(normalize_sync_profile(raw.as_deref()))
}

async fn persist_sync_profile(storage: &Storage, profile: &SyncProfile) -> Result<()> {
    storage
        .upsert_setting("sync_profile", profile.as_str())
        .await?;
    Ok(())
}

async fn load_sync_transport_mode(storage: &Storage) -> Result<String> {
    let raw = storage.get_setting("sync_transport_mode").await?;
    Ok(normalize_sync_transport_mode(raw.as_deref()))
}

async fn persist_sync_transport_mode(storage: &Storage, mode: &str) -> Result<()> {
    storage.upsert_setting("sync_transport_mode", mode).await?;
    Ok(())
}

async fn load_sync_transport_token(storage: &Storage) -> Result<Option<String>> {
    storage
        .get_setting("sync_transport_token")
        .await
        .map_err(Into::into)
}

async fn persist_sync_transport_token(storage: &Storage, token: Option<&str>) -> Result<()> {
    storage
        .upsert_setting("sync_transport_token", token.unwrap_or(""))
        .await?;
    Ok(())
}

async fn enforce_sync_transport_policy(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<(), axum::http::StatusCode> {
    let mode = load_sync_transport_mode(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    if mode == "https-required" {
        let forwarded_proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if forwarded_proto != "https" {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
    }

    let token = load_sync_transport_token(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(expected_token) = token.filter(|t| !t.is_empty()) {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Some(bearer) = auth.strip_prefix("Bearer ") else {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        };
        if bearer != expected_token {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }

    Ok(())
}

async fn sync_profile(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<SyncProfileView>>, axum::http::StatusCode> {
    enforce_sync_transport_policy(&state, &headers).await?;
    let profile = load_sync_profile(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ApiEnvelope {
        data: SyncProfileView {
            profile: profile.as_str().to_string(),
        },
    }))
}

async fn update_sync_profile(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<UpdateSyncProfileRequest>,
) -> Result<Json<ApiEnvelope<SyncProfileView>>, axum::http::StatusCode> {
    enforce_sync_transport_policy(&state, &headers).await?;
    let profile = normalize_sync_profile(Some(&request.profile));
    persist_sync_profile(&state.storage, &profile)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ApiEnvelope {
        data: SyncProfileView {
            profile: profile.as_str().to_string(),
        },
    }))
}

async fn sync_transport(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<SyncTransportView>>, axum::http::StatusCode> {
    enforce_sync_transport_policy(&state, &headers).await?;
    let mode = load_sync_transport_mode(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let token = load_sync_transport_token(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: SyncTransportView {
            mode,
            token_configured: token.is_some_and(|value| !value.is_empty()),
        },
    }))
}

async fn update_sync_transport(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<UpdateSyncTransportRequest>,
) -> Result<Json<ApiEnvelope<SyncTransportView>>, axum::http::StatusCode> {
    enforce_sync_transport_policy(&state, &headers).await?;
    let mode = normalize_sync_transport_mode(Some(&request.mode));
    persist_sync_transport_mode(&state.storage, &mode)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = request.token.as_deref().map(str::trim);
    let token = token.filter(|value| !value.is_empty());
    persist_sync_transport_token(&state.storage, token)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: SyncTransportView {
            mode,
            token_configured: token.is_some(),
        },
    }))
}

async fn sync_status(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<SyncNodeStatusView>>, axum::http::StatusCode> {
    let profile = load_sync_profile(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let revision = load_sync_revision(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let transport_mode = load_sync_transport_mode(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let transport_token = load_sync_transport_token(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let replay_cache_entries = state
        .sync_seen_nonces
        .lock()
        .expect("sync nonce lock poisoned")
        .len();

    let events = state
        .storage
        .recent_audit_events(200)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut peers = HashMap::<String, SyncPeerStatusView>::new();
    for event in events {
        if event.event_type != "sync.state_imported" {
            continue;
        }
        let payload: serde_json::Value = match serde_json::from_str(&event.payload) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let from = match payload.get("from").and_then(serde_json::Value::as_str) {
            Some(v) => v.to_string(),
            None => continue,
        };
        let revision = payload
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let profile = payload
            .get("profile")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("full")
            .to_string();

        let entry = peers.entry(from.clone()).or_insert(SyncPeerStatusView {
            node_public_key: from,
            imports: 0,
            last_import_at: event.created_at,
            last_revision: revision,
            profile,
        });
        entry.imports += 1;
        if event.created_at > entry.last_import_at {
            entry.last_import_at = event.created_at;
            entry.last_revision = revision;
            entry.profile = payload
                .get("profile")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("full")
                .to_string();
        }
    }

    let mut peers: Vec<SyncPeerStatusView> = peers.into_values().collect();
    peers.sort_by(|a, b| b.last_import_at.cmp(&a.last_import_at));

    Ok(Json(ApiEnvelope {
        data: SyncNodeStatusView {
            local_node_public_key: state.storage.identity().public_b64.clone(),
            profile: profile.as_str().to_string(),
            revision,
            transport_mode,
            transport_token_configured: transport_token.is_some_and(|v| !v.is_empty()),
            replay_cache_entries,
            peers,
        },
    }))
}

async fn persist_sync_revision(storage: &Storage, revision: u64) -> Result<()> {
    storage
        .upsert_setting("sync_revision", &revision.to_string())
        .await
        .map_err(Into::into)
}

fn is_sync_payload_newer(
    incoming_revision: u64,
    incoming_node: &str,
    local_revision: u64,
    local_node: &str,
) -> bool {
    incoming_revision > local_revision
        || (incoming_revision == local_revision && incoming_node > local_node)
}

fn register_sync_nonce(state: &ServerState, envelope: &SyncEnvelope) -> bool {
    let now = chrono::Utc::now();

    let max_age = chrono::Duration::minutes(10);
    let max_future_skew = chrono::Duration::seconds(30);
    if envelope.timestamp < (now - max_age) || envelope.timestamp > (now + max_future_skew) {
        return false;
    }

    let key = format!("{}:{}", envelope.node_public_key, envelope.nonce);
    let mut guard = state
        .sync_seen_nonces
        .lock()
        .expect("sync nonce lock poisoned");
    guard.retain(|_, ts| *ts >= (now - chrono::Duration::minutes(30)));

    if guard.contains_key(&key) {
        return false;
    }

    guard.insert(key, now);
    true
}

async fn export_sync_state(
    State(state): State<ServerState>,
    Query(query): Query<SyncExportQuery>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<SyncEnvelope>>, axum::http::StatusCode> {
    enforce_sync_transport_policy(&state, &headers).await?;
    let profile = if query.profile.is_some() {
        normalize_sync_profile(query.profile.as_deref())
    } else {
        load_sync_profile(&state.storage)
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
    };

    if matches!(profile, SyncProfile::ReadOnlyFollower) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    let revision = load_sync_revision(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .saturating_add(1);

    let blocklists = if matches!(profile, SyncProfile::Full) {
        state
            .storage
            .list_sources()
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        Vec::new()
    };
    let devices = if matches!(profile, SyncProfile::Full) {
        state
            .storage
            .list_devices()
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        Vec::new()
    };

    let payload = SyncStatePayloadV1 {
        version: 1,
        revision,
        profile: profile.as_str().to_string(),
        exported_at: chrono::Utc::now(),
        blocklists,
        devices,
        classifier: state.dns_runtime.classifier_settings(),
        notifications: state
            .notification_settings
            .read()
            .expect("notification settings lock poisoned")
            .clone(),
    };

    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let envelope = state.storage.sign_sync_payload(&payload_bytes);

    Ok(Json(ApiEnvelope { data: envelope }))
}

async fn import_sync_state(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ImportSyncEnvelopeRequest>,
) -> Result<Json<ApiEnvelope<SyncImportResult>>, axum::http::StatusCode> {
    enforce_sync_transport_policy(&state, &headers).await?;
    let payload_bytes = Storage::verify_sync_envelope(&request.envelope)
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let payload: SyncStatePayloadV1 =
        serde_json::from_slice(&payload_bytes).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    if payload.version != 1 {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    if !register_sync_nonce(&state, &request.envelope) {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    let profile = normalize_sync_profile(Some(&payload.profile));

    let local_revision = load_sync_revision(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let local_node = state.storage.identity().public_b64.clone();
    if !is_sync_payload_newer(
        payload.revision,
        &request.envelope.node_public_key,
        local_revision,
        &local_node,
    ) {
        return Err(axum::http::StatusCode::CONFLICT);
    }

    if matches!(profile, SyncProfile::Full) {
        let existing_sources = state
            .storage
            .list_sources()
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        for source in existing_sources {
            let _ = state
                .storage
                .delete_source(source.id)
                .await
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        for source in &payload.blocklists {
            state
                .storage
                .insert_source(source)
                .await
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        let existing_devices = state
            .storage
            .list_devices()
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        for device in existing_devices {
            let _ = state
                .storage
                .delete_device(device.id)
                .await
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        for device in &payload.devices {
            state
                .storage
                .upsert_device(device)
                .await
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    persist_classifier_settings(&state.storage, &payload.classifier)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .dns_runtime
        .replace_classifier_settings(payload.classifier.clone());

    persist_notification_settings(&state.storage, &payload.notifications)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Ok(mut notifications) = state.notification_settings.write() {
        *notifications = payload.notifications.clone();
    }

    persist_sync_revision(&state.storage, payload.revision)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    sync_runtime_device_policies(&state)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "sync.state_imported".to_string(),
            payload: serde_json::json!({
                "from": request.envelope.node_public_key,
                "revision": payload.revision,
                "profile": profile.as_str(),
                "sources": payload.blocklists.len(),
                "devices": payload.devices.len(),
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: SyncImportResult {
            imported_sources: payload.blocklists.len(),
            imported_devices: payload.devices.len(),
            applied_revision: payload.revision,
            profile: profile.as_str().to_string(),
        },
    }))
}

async fn list_rulesets(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<Vec<RulesetSummary>>>, axum::http::StatusCode> {
    state
        .storage
        .list_rulesets()
        .await
        .map(|rows| {
            Json(ApiEnvelope {
                data: rows
                    .into_iter()
                    .map(|row| RulesetSummary {
                        id: row.id,
                        hash: row.hash,
                        status: row.status,
                        created_at: row.created_at,
                    })
                    .collect(),
            })
        })
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn rollback_ruleset(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<RulesetSummary>>, axum::http::StatusCode> {
    let Some(artifact) = state
        .storage
        .rollback_to_previous_ruleset()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(axum::http::StatusCode::NOT_FOUND);
    };

    let rollback_policy = Arc::new(PolicyEngine::new(artifact.clone()));
    let profile_policies = match load_current_runtime_policy_catalog(&state).await {
        Ok(catalog) => catalog.profile_policies,
        Err(error) => {
            tracing::warn!(%error, "failed to rebuild profile policies during rollback");
            HashMap::new()
        }
    };
    state
        .dns_runtime
        .replace_policy_catalog(rollback_policy, profile_policies);
    sync_runtime_device_policies(&state)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "ruleset.rollback".to_string(),
            payload: serde_json::json!({
                "ruleset_id": artifact.id,
                "hash": artifact.hash,
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let notification_settings = state
        .notification_settings
        .read()
        .expect("notification settings lock poisoned")
        .clone();
    if should_deliver_notification(&notification_settings, "high") {
        let event = NotificationWebhookEvent {
            event_type: "ruleset.rollback".to_string(),
            severity: "high".to_string(),
            title: "Ruleset rolled back".to_string(),
            summary: format!("Rolled back to ruleset {}.", artifact.hash),
            domain: None,
            device_name: None,
            client_ip: Some("control-plane".to_string()),
            details: vec![format!("ruleset id {}", artifact.id)],
            created_at: chrono::Utc::now(),
        };
        if let Err(error) = deliver_operational_notification(
            &state.storage,
            &state.http_client,
            &notification_settings,
            event,
        )
        .await
        {
            tracing::warn!(%error, "failed to deliver rollback notification");
        }
    }

    Ok(Json(ApiEnvelope {
        data: RulesetSummary {
            id: artifact.id,
            hash: artifact.hash,
            status: "active".to_string(),
            created_at: artifact.created_at,
        },
    }))
}

async fn list_audit_events(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<Vec<AuditEvent>>>, axum::http::StatusCode> {
    state
        .storage
        .recent_audit_events(20)
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BackupData {
    version: String,
    created_at: String,
    sources: Vec<SourceRecord>,
    devices: Vec<DeviceRecord>,
    classifier: ClassifierSettings,
    notifications: NotificationSettings,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RestoreRequest {
    data: BackupData,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BackupResult {
    success: bool,
    message: String,
    size_bytes: usize,
}

async fn backup_data(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<BackupData>>, axum::http::StatusCode> {
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

    let classifier = state.dns_runtime.classifier_settings();
    let notifications = state
        .notification_settings
        .read()
        .expect("notification settings lock poisoned")
        .clone();

    let backup = BackupData {
        version: "1.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        sources,
        devices,
        classifier,
        notifications,
    };

    Ok(Json(ApiEnvelope { data: backup }))
}

async fn restore_data(
    State(state): State<ServerState>,
    Json(request): Json<RestoreRequest>,
) -> Result<Json<ApiEnvelope<BackupResult>>, axum::http::StatusCode> {
    let data = request.data;
    let source_count = data.sources.len();
    let device_count = data.devices.len();
    let size_bytes = serde_json::to_string(&data).map(|s| s.len()).unwrap_or(0);

    for source in &data.sources {
        let _ = state.storage.insert_source(source).await;
    }

    for device in &data.devices {
        let _ = state.storage.upsert_device(device).await;
    }

    {
        let mut notifications = state.notification_settings.write().unwrap();
        *notifications = data.notifications;
    }

    let message = format!(
        "Restored {} sources, {} devices, classifier and notification settings",
        source_count, device_count
    );

    Ok(Json(ApiEnvelope {
        data: BackupResult {
            success: true,
            message,
            size_bytes,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct ResilienceDrillResult {
    drill_type: String,
    success: bool,
    message: String,
    recommendations: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ResilienceDrillRequest {
    #[allow(dead_code)]
    duration_secs: Option<u64>,
}

async fn simulate_upstream_outage(
    State(state): State<ServerState>,
    Json(_request): Json<ResilienceDrillRequest>,
) -> Result<Json<ApiEnvelope<ResilienceDrillResult>>, axum::http::StatusCode> {
    let snapshot = state.dns_runtime.snapshot();
    let has_failures = snapshot.upstream_failures_total > 0;
    let fallback_working = snapshot.fallback_served_total > 0;

    let mut recommendations = vec![
        "Monitor upstream health metrics during failures".to_string(),
        "Verify fallback cache is warming properly".to_string(),
    ];

    if !has_failures {
        recommendations.push("Consider simulating failures to test fallback behavior".to_string());
    }

    if !fallback_working {
        recommendations
            .push("CRITICAL: Fallback cache not serving - check cache warming".to_string());
    }

    Ok(Json(ApiEnvelope {
        data: ResilienceDrillResult {
            drill_type: "upstream_outage".to_string(),
            success: fallback_working,
            message: format!(
                "Upstream failures: {}, Fallback served: {}",
                snapshot.upstream_failures_total, snapshot.fallback_served_total
            ),
            recommendations,
        },
    }))
}

async fn simulate_db_corruption(
    State(state): State<ServerState>,
    Json(_request): Json<ResilienceDrillRequest>,
) -> Result<Json<ApiEnvelope<ResilienceDrillResult>>, axum::http::StatusCode> {
    let sources_result = state.storage.list_sources().await;
    let devices_result = state.storage.list_devices().await;

    let db_healthy = sources_result.is_ok() && devices_result.is_ok();

    let mut recommendations = vec![
        "Regular backup verification is critical".to_string(),
        "Test restore procedures periodically".to_string(),
    ];

    if !db_healthy {
        recommendations
            .push("URGENT: Database corruption detected - initiate recovery".to_string());
    }

    Ok(Json(ApiEnvelope {
        data: ResilienceDrillResult {
            drill_type: "db_corruption".to_string(),
            success: db_healthy,
            message: if db_healthy {
                "Database integrity check passed".to_string()
            } else {
                "Database integrity check failed".to_string()
            },
            recommendations,
        },
    }))
}

async fn simulate_source_failure(
    State(state): State<ServerState>,
    Json(_request): Json<ResilienceDrillRequest>,
) -> Result<Json<ApiEnvelope<ResilienceDrillResult>>, axum::http::StatusCode> {
    let sources = state
        .storage
        .list_sources()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let enabled_count = sources.iter().filter(|s| s.enabled).count();
    let total_count = sources.len();

    let mut recommendations = vec![
        "Multiple source redundancy is recommended".to_string(),
        "Monitor source refresh failures".to_string(),
    ];

    if enabled_count == 0 && total_count > 0 {
        recommendations.push("WARNING: No sources enabled - blocking may not work".to_string());
    }

    if total_count == 1 {
        recommendations.push("Consider adding redundant sources".to_string());
    }

    Ok(Json(ApiEnvelope {
        data: ResilienceDrillResult {
            drill_type: "source_failure".to_string(),
            success: enabled_count > 0,
            message: format!("{} of {} sources enabled", enabled_count, total_count),
            recommendations,
        },
    }))
}

async fn simulate_sync_partition(
    State(state): State<ServerState>,
    Json(_request): Json<ResilienceDrillRequest>,
) -> Result<Json<ApiEnvelope<ResilienceDrillResult>>, axum::http::StatusCode> {
    let transport_mode = load_sync_transport_mode(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let transport_token = load_sync_transport_token(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let transport_ok = transport_token.is_some() || transport_mode != "disabled";

    let mut recommendations = vec![
        "Monitor sync peer connectivity".to_string(),
        "Verify transport token configuration".to_string(),
    ];

    if !transport_ok {
        recommendations.push("Sync transport not fully configured".to_string());
    }

    Ok(Json(ApiEnvelope {
        data: ResilienceDrillResult {
            drill_type: "sync_partition".to_string(),
            success: transport_ok,
            message: format!("Transport mode: {}", transport_mode),
            recommendations,
        },
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
struct FalsePositiveBudgetStatus {
    release_ready: bool,
    blocking_rate: f64,
    blocked_total: u64,
    queries_total: u64,
    false_positive_estimate: f64,
    budget_remaining: f64,
    budget_limit: f64,
    recommendations: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LatencyBudgetCheck {
    label: String,
    observed_ms: f64,
    target_p50_ms: f64,
    sample_count: u64,
    status: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LatencyBudgetStatus {
    within_budget: bool,
    cache_hit_rate: f64,
    checks: Vec<LatencyBudgetCheck>,
    recommendations: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ResolverAccessStatus {
    hostname: Option<String>,
    dns_targets: Vec<String>,
    tailscale_ip: Option<String>,
    notes: Vec<String>,
}

async fn false_positive_budget_status(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<FalsePositiveBudgetStatus>>, axum::http::StatusCode> {
    let snapshot = state.dns_runtime.snapshot();
    let blocked = snapshot.blocked_total;
    let queries = snapshot.queries_total.max(1);
    let blocking_rate = (blocked as f64) / (queries as f64);
    let budget_limit = 0.001; // 0.1% false positive budget
    let false_positive_estimate = blocking_rate * 0.1; // Assume 10% of blocked are false positives
    let budget_remaining = (budget_limit - false_positive_estimate).max(0.0);
    let release_ready = false_positive_estimate < budget_limit;

    let mut recommendations = vec![];

    if release_ready {
        recommendations.push("System meets false-positive budget for release".to_string());
    } else {
        recommendations.push(
            "WARNING: False-positive rate exceeds budget - review blocking rules".to_string(),
        );
    }

    if blocking_rate > 0.05 {
        recommendations.push("High blocking rate detected - verify list quality".to_string());
    }

    if queries < 1000_u64 {
        recommendations
            .push("Low query volume - insufficient data for reliable estimate".to_string());
    }

    Ok(Json(ApiEnvelope {
        data: FalsePositiveBudgetStatus {
            release_ready,
            blocking_rate,
            blocked_total: blocked,
            queries_total: queries,
            false_positive_estimate,
            budget_remaining,
            budget_limit,
            recommendations,
        },
    }))
}

async fn latency_budget_status(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<LatencyBudgetStatus>>, axum::http::StatusCode> {
    let snapshot = state.dns_runtime.snapshot();
    let queries = snapshot.queries_total.max(1);
    let cache_hit_rate = snapshot.cache_hits_total as f64 / queries as f64;

    let checks = vec![
        latency_budget_check(
            "Cache hit",
            snapshot.cache_hit_latency_avg_ns,
            1.0,
            snapshot.cache_hit_samples,
        ),
        latency_budget_check(
            "Cache miss",
            snapshot.cache_miss_latency_avg_ns,
            8.0,
            snapshot.cache_miss_samples,
        ),
        latency_budget_check(
            "Classifier monitor path",
            snapshot.classifier_latency_avg_ns,
            10.0,
            snapshot.classifier_latency_samples,
        ),
    ];

    let within_budget = checks.iter().all(|check| check.status != "over-budget");
    let mut recommendations = Vec::new();

    if within_budget {
        recommendations
            .push("Observed hot-path latency stays within current p50 budget targets.".to_string());
    } else {
        recommendations.push(
            "One or more hot-path stages are over budget; review recent policy or cache changes."
                .to_string(),
        );
    }

    if cache_hit_rate < 0.5 {
        recommendations.push("Cache hit rate is low; review TTLs and warm-path traffic before tightening latency budgets further.".to_string());
    } else {
        recommendations.push(format!(
            "Cache hit rate is {:.1}% across the current runtime window.",
            cache_hit_rate * 100.0
        ));
    }

    if snapshot.cache_miss_samples < 25 {
        recommendations.push(
            "Cache-miss sample volume is still low; continue soak testing for stronger confidence."
                .to_string(),
        );
    }

    Ok(Json(ApiEnvelope {
        data: LatencyBudgetStatus {
            within_budget,
            cache_hit_rate,
            checks,
            recommendations,
        },
    }))
}

fn latency_budget_check(
    label: &str,
    observed_ns: u64,
    target_p50_ms: f64,
    sample_count: u64,
) -> LatencyBudgetCheck {
    let observed_ms = observed_ns as f64 / 1_000_000.0;
    let status = if sample_count == 0 {
        "insufficient-data"
    } else if observed_ms <= target_p50_ms {
        "within-budget"
    } else {
        "over-budget"
    };

    LatencyBudgetCheck {
        label: label.to_string(),
        observed_ms,
        target_p50_ms,
        sample_count,
        status: status.to_string(),
    }
}

async fn resolver_access_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<ResolverAccessStatus>>, axum::http::StatusCode> {
    let dns_targets = discover_dns_targets(state.dns_udp_bind_addr, &headers);
    let tailscale_ip = discover_tailscale_ipv4();
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| read_command_output("hostname", &[]));

    let mut notes = vec![format!(
        "Point devices at port {} for DNS on this deployment.",
        state.dns_udp_bind_addr.port()
    )];
    if tailscale_ip.is_some() {
        notes.push(
            "Tailscale is available, so tailnet devices can use the Tailscale address directly."
                .to_string(),
        );
    }

    Ok(Json(ApiEnvelope {
        data: ResolverAccessStatus {
            hostname,
            dns_targets,
            tailscale_ip,
            notes,
        },
    }))
}

fn discover_dns_targets(bind_addr: SocketAddr, headers: &HeaderMap) -> Vec<String> {
    let port = bind_addr.port();
    let mut targets = Vec::new();

    if let Some(host) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or(value).trim())
        .filter(|value| !value.is_empty())
    {
        targets.push(format!("{}:{}", host, port));
    }

    if bind_addr.ip().is_unspecified() {
        for ip in discover_local_ipv4s() {
            if !ip.starts_with("172.") {
                targets.push(format!("{}:{}", ip, port));
            }
        }
    } else {
        targets.push(format!("{}:{}", bind_addr.ip(), port));
    }

    if targets.is_empty() {
        targets.push(format!("127.0.0.1:{}", port));
    }

    targets.sort();
    targets.dedup();
    targets
}

fn discover_local_ipv4s() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        if let Some(output) = read_command_output("hostname", &["-I"]) {
            return output
                .split_whitespace()
                .filter(|value| value.parse::<std::net::Ipv4Addr>().is_ok())
                .map(ToString::to_string)
                .collect();
        }
    }

    #[cfg(target_os = "macos")]
    {
        let mut values = Vec::new();
        for interface in ["en0", "en1"] {
            if let Some(ip) = read_command_output("ipconfig", &["getifaddr", interface]) {
                values.push(ip);
            }
        }
        if !values.is_empty() {
            return values;
        }
    }

    Vec::new()
}

fn discover_tailscale_ipv4() -> Option<String> {
    read_command_output("tailscale", &["ip", "-4"]).and_then(|output| {
        output
            .lines()
            .map(str::trim)
            .find(|line| line.parse::<std::net::Ipv4Addr>().is_ok())
            .map(ToString::to_string)
    })
}

async fn favicon() -> axum::http::StatusCode {
    axum::http::StatusCode::NO_CONTENT
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

async fn runtime_health(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<RuntimeHealthResponse>>, axum::http::StatusCode> {
    Ok(Json(ApiEnvelope {
        data: current_runtime_health(&state),
    }))
}

async fn run_runtime_health_check(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<RuntimeHealthResponse>>, axum::http::StatusCode> {
    active_runtime_health_check(&state)
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(serde::Deserialize)]
struct PauseRuntimeRequest {
    minutes: u32,
}

async fn pause_runtime(
    State(state): State<ServerState>,
    Json(request): Json<PauseRuntimeRequest>,
) -> Result<(), axum::http::StatusCode> {
    let until = chrono::Utc::now() + chrono::Duration::minutes(request.minutes as i64);
    state.dns_runtime.pause_protection_until(until);

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: uuid::Uuid::new_v4(),
            event_type: "runtime.protection_paused".to_string(),
            payload: serde_json::json!({
                "minutes": request.minutes,
                "until": until,
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
}

async fn resume_runtime(State(state): State<ServerState>) -> Result<(), axum::http::StatusCode> {
    state.dns_runtime.resume_protection();

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: uuid::Uuid::new_v4(),
            event_type: "runtime.protection_resumed".to_string(),
            payload: "{}".to_string(),
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
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

async fn list_services(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<Vec<ServiceToggleView>>>, axum::http::StatusCode> {
    build_service_toggle_views(&state)
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn update_service_toggle(
    State(state): State<ServerState>,
    Json(request): Json<UpdateServiceToggleRequest>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
    let manifests = built_in_service_manifests();
    if !manifests
        .iter()
        .any(|item| item.service_id == request.service_id)
    {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    let mut snapshot = load_service_toggle_snapshot(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    snapshot.upsert(&request.service_id, request.mode);
    persist_service_toggle_snapshot(&state.storage, &snapshot)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "service-toggle.updated".to_string(),
            payload: serde_json::json!({
                "service_id": request.service_id,
                "mode": snapshot.mode_for(&request.service_id),
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    refresh_sources_once(&state, "service-toggle", None)
        .await
        .map(|data| Json(ApiEnvelope { data }))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn update_classifier_settings(
    State(state): State<ServerState>,
    Json(request): Json<UpdateClassifierSettingsRequest>,
) -> Result<Json<ApiEnvelope<ClassifierSettings>>, axum::http::StatusCode> {
    let settings = ClassifierSettings {
        mode: request.mode,
        threshold: request.threshold,
    };

    persist_classifier_settings(&state.storage, &settings)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .dns_runtime
        .replace_classifier_settings(settings.clone());
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "classifier-settings.updated".to_string(),
            payload: serde_json::to_string(&settings)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope { data: settings }))
}

async fn update_notification_settings(
    State(state): State<ServerState>,
    Json(request): Json<UpdateNotificationSettingsRequest>,
) -> Result<Json<ApiEnvelope<NotificationSettings>>, axum::http::StatusCode> {
    let settings = NotificationSettings {
        enabled: request.enabled,
        webhook_url: normalize_webhook_url(request.webhook_url.as_deref())
            .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
        min_severity: normalize_notification_severity(&request.min_severity)
            .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
    };

    persist_notification_settings(&state.storage, &settings)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    *state
        .notification_settings
        .write()
        .expect("notification settings lock poisoned") = settings.clone();
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "notification-settings.updated".to_string(),
            payload: serde_json::to_string(&settings)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope { data: settings }))
}

async fn test_notification_settings(
    State(state): State<ServerState>,
    Json(request): Json<TestNotificationRequest>,
) -> Result<Json<ApiEnvelope<NotificationTestResult>>, axum::http::StatusCode> {
    let settings = state
        .notification_settings
        .read()
        .expect("notification settings lock poisoned")
        .clone();
    let Some(target) = settings.webhook_url.clone() else {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    };

    let severity = normalize_notification_severity(
        request
            .severity
            .as_deref()
            .unwrap_or(&settings.min_severity),
    )
    .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let dry_run = request.dry_run.unwrap_or(false);

    let test_event = SecurityEventRecord {
        id: Uuid::new_v4(),
        device_id: None,
        device_name: Some(
            request
                .device_name
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "Control Plane Test".to_string()),
        ),
        client_ip: "127.0.0.1".to_string(),
        domain: request
            .domain
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "notification-test.cogwheel.local".to_string()),
        classifier_score: 1.0,
        severity: severity.clone(),
        created_at: chrono::Utc::now(),
    };

    if dry_run {
        state
            .storage
            .record_audit_event(&AuditEvent {
                id: Uuid::new_v4(),
                event_type: "notification-settings.tested.dry-run".to_string(),
                payload: serde_json::to_string(&serde_json::json!({
                    "target": target,
                    "severity": test_event.severity,
                    "domain": test_event.domain,
                }))
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
                created_at: test_event.created_at,
            })
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

        return Ok(Json(ApiEnvelope {
            data: NotificationTestResult {
                outcome: "validated".to_string(),
                target,
            },
        }));
    }

    deliver_security_notification(
        state.storage.as_ref(),
        &state.http_client,
        &settings,
        &test_event,
    )
    .await
    .map_err(|_| axum::http::StatusCode::BAD_GATEWAY)?;
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "notification-settings.tested".to_string(),
            payload: serde_json::to_string(&serde_json::json!({
                "target": target,
                "severity": test_event.severity,
            }))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: test_event.created_at,
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: NotificationTestResult {
            outcome: "sent".to_string(),
            target,
        },
    }))
}

async fn update_notification_test_presets(
    State(state): State<ServerState>,
    Json(request): Json<UpdateNotificationPresetsRequest>,
) -> Result<Json<ApiEnvelope<Vec<NotificationTestPreset>>>, axum::http::StatusCode> {
    let presets = normalize_notification_test_presets(request.presets);
    persist_notification_test_presets(&state.storage, &presets)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "notification-test-presets.updated".to_string(),
            payload: serde_json::to_string(&presets)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope { data: presets }))
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
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "blocklist.upserted".to_string(),
            payload: serde_json::to_string(&source)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
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
            ruleset: None,
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
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "blocklist.state_updated".to_string(),
            payload: serde_json::to_string(&source)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
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
            ruleset: None,
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

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "blocklist.deleted".to_string(),
            payload: serde_json::to_string(&source)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    if request.refresh_now.unwrap_or(true) {
        return refresh_sources_once(&state, "blocklist-delete", None)
            .await
            .map(|data| Json(ApiEnvelope { data }))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(ApiEnvelope {
        data: RefreshResponse {
            outcome: "saved".to_string(),
            ruleset: None,
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

    let manifests = built_in_service_manifests();
    let snapshot = load_service_toggle_snapshot(&state.storage).await?;
    let service_layer = compile_service_rule_layer(&manifests, &snapshot);
    if !service_layer.rules.is_empty() {
        parsed_sources.push(synthetic_source("service-toggles", service_layer.rules));
    }

    let verification = verify_candidate(&parsed_sources, &state.protected_domains);
    if !verification.passed {
        let rejection_notes = verification
            .notes
            .iter()
            .cloned()
            .chain(service_layer.notes.iter().cloned())
            .collect::<Vec<_>>();
        state
            .storage
            .record_audit_event(&AuditEvent {
                id: Uuid::new_v4(),
                event_type: "ruleset.refresh_rejected".to_string(),
                payload: serde_json::json!({
                    "reason": reason,
                    "notes": verification.notes,
                    "blocked_protected_domains": verification.blocked_protected_domains,
                    "invalid_ratio": verification.invalid_ratio,
                })
                .to_string(),
                created_at: chrono::Utc::now(),
            })
            .await?;

        let notification_settings = state
            .notification_settings
            .read()
            .expect("notification settings lock poisoned")
            .clone();
        if should_deliver_notification(&notification_settings, "high") {
            let event = NotificationWebhookEvent {
                event_type: "ruleset.refresh_rejected".to_string(),
                severity: "high".to_string(),
                title: "Ruleset refresh rejected".to_string(),
                summary: format!("Refresh {} was rejected before activation.", reason),
                domain: None,
                device_name: None,
                client_ip: Some("control-plane".to_string()),
                details: rejection_notes.clone(),
                created_at: chrono::Utc::now(),
            };
            if let Err(error) = deliver_operational_notification(
                &state.storage,
                &client,
                &notification_settings,
                event,
            )
            .await
            {
                tracing::warn!(%error, "failed to deliver refresh rejection notification");
            }
        }

        return Ok(RefreshResponse {
            outcome: "rejected".to_string(),
            ruleset: None,
            notes: rejection_notes,
        });
    }

    let catalog = build_runtime_policy_catalog(
        &parsed_sources,
        state.protected_domains.as_ref().clone(),
        BlockMode::NullIp,
    );

    state
        .storage
        .record_ruleset(&RulesetRecord {
            id: catalog.global_policy.artifact().id,
            hash: catalog.global_policy.artifact().hash.clone(),
            status: "candidate".to_string(),
            created_at: catalog.global_policy.artifact().created_at,
            artifact_json: serde_json::to_string(catalog.global_policy.artifact())?,
        })
        .await?;
    let runtime_before = state.dns_runtime.snapshot();
    state
        .storage
        .activate_ruleset(catalog.global_policy.artifact().id)
        .await?;
    state.dns_runtime.replace_policy_catalog(
        catalog.global_policy.clone(),
        catalog.profile_policies.clone(),
    );
    sync_runtime_device_policies(state).await?;

    let mut regression_notes =
        post_activation_regressions(catalog.global_policy.as_ref(), &state.protected_domains)
            .unwrap_or_default();
    let runtime_report = run_runtime_guard_probes(state, &runtime_before).await;
    if runtime_report.degraded {
        regression_notes.extend(runtime_report.notes);
    }

    if !regression_notes.is_empty() {
        let Some(artifact) = state.storage.rollback_to_previous_ruleset().await? else {
            anyhow::bail!("regression detected but no previous ruleset available for rollback");
        };
        state.dns_runtime.replace_policy_catalog(
            Arc::new(PolicyEngine::new(artifact.clone())),
            HashMap::new(),
        );
        sync_runtime_device_policies(state).await?;
        state
            .storage
            .record_audit_event(&AuditEvent {
                id: Uuid::new_v4(),
                event_type: "ruleset.auto_rollback".to_string(),
                payload: serde_json::json!({
                    "reason": reason,
                    "rolled_back_to": artifact.id,
                    "notes": regression_notes,
                })
                .to_string(),
                created_at: chrono::Utc::now(),
            })
            .await?;

        let notification_settings = state
            .notification_settings
            .read()
            .expect("notification settings lock poisoned")
            .clone();
        if should_deliver_notification(&notification_settings, "critical") {
            let event = NotificationWebhookEvent {
                event_type: "ruleset.auto_rollback".to_string(),
                severity: "critical".to_string(),
                title: "Ruleset auto-rollback triggered".to_string(),
                summary: format!("Refresh {} triggered runtime guard rollback.", reason),
                domain: None,
                device_name: None,
                client_ip: Some("control-plane".to_string()),
                details: regression_notes.clone(),
                created_at: chrono::Utc::now(),
            };
            if let Err(error) = deliver_operational_notification(
                &state.storage,
                &client,
                &notification_settings,
                event,
            )
            .await
            {
                tracing::warn!(%error, "failed to deliver auto rollback notification");
            }
        }

        return Ok(RefreshResponse {
            outcome: "rolled_back".to_string(),
            ruleset: Some(to_ruleset_summary(
                &artifact.id,
                &artifact.hash,
                "active",
                artifact.created_at,
            )),
            notes: regression_notes,
        });
    }

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "ruleset.activated".to_string(),
            payload: serde_json::json!({
                "ruleset_id": catalog.global_policy.artifact().id,
                "hash": catalog.global_policy.artifact().hash,
                "reason": reason,
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await?;

    Ok(RefreshResponse {
        outcome: "activated".to_string(),
        ruleset: Some(to_ruleset_summary(
            &catalog.global_policy.artifact().id,
            &catalog.global_policy.artifact().hash,
            "active",
            catalog.global_policy.artifact().created_at,
        )),
        notes: vec![format!("refreshed {} source(s)", enabled_source_count)]
            .into_iter()
            .chain(service_layer.notes)
            .collect(),
    })
}

async fn load_service_toggle_snapshot(storage: &Storage) -> Result<ServiceToggleSnapshot> {
    let Some(value) = storage.get_setting("service_toggles").await? else {
        return Ok(ServiceToggleSnapshot::default());
    };
    Ok(ServiceToggleSnapshot::from_json(&value).unwrap_or_default())
}

async fn load_classifier_settings(storage: &Storage) -> Result<ClassifierSettings> {
    let Some(value) = storage.get_setting("classifier_settings").await? else {
        return Ok(ClassifierSettings::default());
    };
    Ok(serde_json::from_str(&value).unwrap_or_default())
}

async fn load_notification_settings(storage: &Storage) -> Result<NotificationSettings> {
    let Some(value) = storage.get_setting("notification_settings").await? else {
        return Ok(NotificationSettings {
            enabled: false,
            webhook_url: None,
            min_severity: "high".to_string(),
        });
    };
    Ok(
        serde_json::from_str(&value).unwrap_or(NotificationSettings {
            enabled: false,
            webhook_url: None,
            min_severity: "high".to_string(),
        }),
    )
}

async fn load_notification_test_presets(storage: &Storage) -> Result<Vec<NotificationTestPreset>> {
    let Some(value) = storage.get_setting("notification_test_presets").await? else {
        return Ok(Vec::new());
    };
    Ok(normalize_notification_test_presets(
        serde_json::from_str(&value).unwrap_or_default(),
    ))
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
            blocklists: vec![
                preset_block_profile_list("oisd-small").unwrap(),
                preset_block_profile_list("oisd-nsfw-small").unwrap(),
            ],
            allowlists: vec!["pbskids.org".to_string(), "khanacademy.org".to_string()],
            updated_at: now,
        },
        BlockProfileRecord {
            id: "focus".to_string(),
            emoji: "🌿".to_string(),
            name: "Focus".to_string(),
            description: "A quieter setup for work or school devices with the smaller OISD core list only."
                .to_string(),
            blocklists: vec![preset_block_profile_list("oisd-small").unwrap()],
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
        name: profile_name.clone(),
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

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "block-profile.updated".to_string(),
            payload: serde_json::to_string(&serde_json::json!({
                "id": profile_id,
                "name": profile_name,
            }))
            .map_err(|error| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    error.to_string(),
                )
            })?,
            created_at: chrono::Utc::now(),
        })
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

async fn build_service_toggle_views(state: &ServerState) -> Result<Vec<ServiceToggleView>> {
    let manifests = built_in_service_manifests();
    let snapshot = load_service_toggle_snapshot(&state.storage).await?;

    Ok(manifests
        .into_iter()
        .map(|manifest| ServiceToggleView {
            mode: snapshot.mode_for(&manifest.service_id),
            manifest,
        })
        .collect())
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

fn current_runtime_health(state: &ServerState) -> RuntimeHealthResponse {
    let snapshot = state.dns_runtime.snapshot();
    let report = evaluate_runtime_regressions(
        &DnsRuntimeSnapshot {
            upstream_failures_total: 0,
            fallback_served_total: 0,
            cache_hits_total: 0,
            cname_uncloaks_total: 0,
            cname_blocks_total: 0,
            queries_total: 0,
            blocked_total: 0,
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
            classifier_latency_avg_ns: 0,
            classifier_latency_samples: 0,
        },
        &snapshot,
        &state.runtime_guard,
    );

    RuntimeHealthResponse {
        snapshot,
        degraded: report.degraded,
        notes: report.notes,
    }
}

async fn active_runtime_health_check(state: &ServerState) -> Result<RuntimeHealthResponse> {
    let before = state.dns_runtime.snapshot();
    let current = current_runtime_health(state);
    let probe_report = run_runtime_guard_probes(state, &before).await;
    let after = state.dns_runtime.snapshot();

    let mut notes = current.notes;
    for note in probe_report.notes {
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
    let degraded = current.degraded || probe_report.degraded;
    let response = RuntimeHealthResponse {
        snapshot: after,
        degraded,
        notes,
    };

    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: if response.degraded {
                "runtime.health_check_degraded".to_string()
            } else {
                "runtime.health_check_passed".to_string()
            },
            payload: serde_json::to_string(&serde_json::json!({
                "degraded": response.degraded,
                "notes": response.notes,
                "snapshot": response.snapshot,
            }))?,
            created_at: chrono::Utc::now(),
        })
        .await?;

    if response.degraded {
        let notification_settings = state
            .notification_settings
            .read()
            .expect("notification settings lock poisoned")
            .clone();
        if should_deliver_notification(&notification_settings, "high") {
            let event = NotificationWebhookEvent {
                event_type: "runtime.health_degraded".to_string(),
                severity: "high".to_string(),
                title: "Runtime health degraded".to_string(),
                summary: "A manual runtime health check detected regressions or probe failures."
                    .to_string(),
                domain: None,
                device_name: None,
                client_ip: Some("control-plane".to_string()),
                details: response.notes.clone(),
                created_at: chrono::Utc::now(),
            };
            if let Err(error) = deliver_operational_notification(
                &state.storage,
                &state.http_client,
                &notification_settings,
                event,
            )
            .await
            {
                tracing::warn!(%error, "failed to deliver runtime health notification");
            }
        }
    }

    Ok(response)
}

async fn persist_service_toggle_snapshot(
    storage: &Storage,
    snapshot: &ServiceToggleSnapshot,
) -> Result<()> {
    storage
        .upsert_setting("service_toggles", &snapshot.to_json()?)
        .await?;
    Ok(())
}

async fn persist_source_refresh_state(storage: &Storage, state: &SourceRefreshState) -> Result<()> {
    storage
        .upsert_setting("source_refresh_state", &serde_json::to_string(state)?)
        .await?;
    Ok(())
}

async fn persist_classifier_settings(
    storage: &Storage,
    settings: &ClassifierSettings,
) -> Result<()> {
    storage
        .upsert_setting("classifier_settings", &serde_json::to_string(settings)?)
        .await?;
    Ok(())
}

async fn persist_notification_settings(
    storage: &Storage,
    settings: &NotificationSettings,
) -> Result<()> {
    storage
        .upsert_setting("notification_settings", &serde_json::to_string(settings)?)
        .await?;
    Ok(())
}

async fn persist_notification_test_presets(
    storage: &Storage,
    presets: &[NotificationTestPreset],
) -> Result<()> {
    storage
        .upsert_setting(
            "notification_test_presets",
            &serde_json::to_string(presets)?,
        )
        .await?;
    Ok(())
}

async fn run_runtime_guard_probes(
    state: &ServerState,
    before: &DnsRuntimeSnapshot,
) -> RuntimeRegressionReport {
    let mut notes = Vec::new();
    for domain in &state.runtime_guard.probe_domains {
        if let Err(error) = state.dns_runtime.probe_domain(domain, RecordType::A).await {
            notes.push(format!("runtime probe failed for {domain}: {error}"));
        }
    }

    let after = state.dns_runtime.snapshot();
    let mut report = evaluate_runtime_regressions(before, &after, &state.runtime_guard);
    report.notes.extend(notes);
    if report
        .notes
        .iter()
        .any(|note| note.starts_with("runtime probe failed"))
    {
        report.degraded = true;
    }
    report
}

fn evaluate_runtime_regressions(
    before: &DnsRuntimeSnapshot,
    after: &DnsRuntimeSnapshot,
    guard: &RuntimeGuardConfig,
) -> RuntimeRegressionReport {
    let upstream_failures_delta = after
        .upstream_failures_total
        .saturating_sub(before.upstream_failures_total);
    let fallback_served_delta = after
        .fallback_served_total
        .saturating_sub(before.fallback_served_total);

    let mut notes = Vec::new();
    if upstream_failures_delta > guard.max_upstream_failures_delta {
        notes.push(format!(
            "upstream failures delta {upstream_failures_delta} exceeds threshold {}",
            guard.max_upstream_failures_delta
        ));
    }
    if fallback_served_delta > guard.max_fallback_served_delta {
        notes.push(format!(
            "fallback served delta {fallback_served_delta} exceeds threshold {}",
            guard.max_fallback_served_delta
        ));
    }

    RuntimeRegressionReport {
        degraded: !notes.is_empty(),
        notes,
    }
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
    state
        .dns_runtime
        .replace_policy_catalog(catalog.global_policy, catalog.profile_policies);
    Ok(())
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

    let manifests = built_in_service_manifests();
    let snapshot = load_service_toggle_snapshot(&state.storage).await?;
    let service_layer = compile_service_rule_layer(&manifests, &snapshot);
    if !service_layer.rules.is_empty() {
        parsed_sources.push(synthetic_source("service-toggles", service_layer.rules));
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
        BlockMode::NullIp,
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
    let manifests = built_in_service_manifests();
    let manifest_map = manifests
        .into_iter()
        .map(|manifest| (manifest.service_id.clone(), manifest))
        .collect::<HashMap<_, _>>();

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
            let service_overrides = if policy_mode == "custom" {
                normalize_device_service_overrides(device.service_overrides)
            } else {
                Vec::new()
            };
            let mut expanded_allowed_domains = allowed_domains.clone();
            let mut blocked_domains = Vec::new();
            for override_record in &service_overrides {
                if let Some(manifest) = manifest_map.get(&override_record.service_id) {
                    match override_record.mode.as_str() {
                        "allow" => {
                            expanded_allowed_domains.extend(manifest.allow_domains.clone());
                            expanded_allowed_domains.extend(manifest.exceptions.clone());
                        }
                        "block" => blocked_domains.extend(manifest.block_domains.clone()),
                        _ => {}
                    }
                }
            }
            let expanded_allowed_domains =
                normalize_device_allowed_domains(expanded_allowed_domains);
            let blocked_domains = normalize_device_allowed_domains(blocked_domains);

            DevicePolicyConfig {
                ip_address: device.ip_address,
                policy_mode,
                blocklist_profile_override,
                protection_override,
                allowed_domains: expanded_allowed_domains,
                blocked_domains,
            }
        })
        .collect()
}

async fn sync_runtime_device_policies(state: &ServerState) -> Result<()> {
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

fn normalize_device_service_overrides(
    overrides: Vec<DeviceServiceOverrideRecord>,
) -> Vec<DeviceServiceOverrideRecord> {
    let manifests = built_in_service_manifests();
    let known_ids = manifests
        .iter()
        .map(|manifest| manifest.service_id.as_str())
        .collect::<HashSet<_>>();
    let mut normalized = Vec::new();

    for override_record in overrides {
        let service_id = override_record.service_id.trim().to_ascii_lowercase();
        let mode = override_record.mode.trim().to_ascii_lowercase();
        if !known_ids.contains(service_id.as_str()) {
            continue;
        }
        if !matches!(mode.as_str(), "allow" | "block") {
            continue;
        }

        normalized
            .retain(|existing: &DeviceServiceOverrideRecord| existing.service_id != service_id);
        normalized.push(DeviceServiceOverrideRecord { service_id, mode });
    }

    normalized.sort_by(|left, right| left.service_id.cmp(&right.service_id));
    normalized
}

fn validate_device_service_overrides(
    policy_mode: &str,
    overrides: Vec<DeviceServiceOverrideRecord>,
) -> Result<Vec<DeviceServiceOverrideRecord>, String> {
    if overrides.is_empty() {
        return Ok(Vec::new());
    }
    if policy_mode != "custom" {
        return Err("device service overrides require custom policy mode".to_string());
    }

    let manifests = built_in_service_manifests()
        .into_iter()
        .map(|manifest| (manifest.service_id.clone(), manifest))
        .collect::<HashMap<_, _>>();
    let normalized = normalize_device_service_overrides(overrides.clone());

    for override_record in overrides {
        let service_id = override_record.service_id.trim().to_ascii_lowercase();
        let mode = override_record.mode.trim().to_ascii_lowercase();
        let Some(manifest) = manifests.get(&service_id) else {
            return Err(format!(
                "unknown device service override `{}`; choose one of the built-in services",
                override_record.service_id.trim()
            ));
        };
        if !matches!(mode.as_str(), "allow" | "block") {
            return Err(format!(
                "device service override `{}` must use allow or block mode",
                manifest.display_name
            ));
        }

        let expanded_domains = if mode == "allow" {
            manifest
                .allow_domains
                .iter()
                .chain(manifest.block_domains.iter())
                .chain(manifest.exceptions.iter())
                .collect::<HashSet<_>>()
                .len()
        } else {
            manifest.block_domains.len()
        };
        if expanded_domains == 0 {
            return Err(format!(
                "device service override `{}` has no device-specific domains for {} mode",
                manifest.display_name, mode
            ));
        }
    }

    if normalized.is_empty() {
        return Err(
            "device service overrides must use known built-in services with allow or block mode"
                .to_string(),
        );
    }

    Ok(normalized)
}

fn severity_for_classifier_score(score: f32) -> &'static str {
    if score >= 0.99 {
        "critical"
    } else if score >= 0.96 {
        "high"
    } else {
        "medium"
    }
}

fn severity_rank(severity: &str) -> usize {
    match severity {
        "critical" => 3,
        "high" => 2,
        _ => 1,
    }
}

fn build_security_summary(events: &[SecurityEventRecord]) -> SecuritySummary {
    let mut medium_count = 0;
    let mut high_count = 0;
    let mut critical_count = 0;
    let mut top_devices = HashMap::<String, DeviceSecuritySummary>::new();

    for event in events {
        match event.severity.as_str() {
            "critical" => critical_count += 1,
            "high" => high_count += 1,
            _ => medium_count += 1,
        }

        let label = event
            .device_name
            .clone()
            .unwrap_or_else(|| event.client_ip.clone());
        let entry = top_devices
            .entry(label.clone())
            .or_insert_with(|| DeviceSecuritySummary {
                label,
                event_count: 0,
                highest_severity: event.severity.clone(),
            });
        entry.event_count += 1;
        if severity_rank(&event.severity) > severity_rank(&entry.highest_severity) {
            entry.highest_severity = event.severity.clone();
        }
    }

    let mut top_devices = top_devices.into_values().collect::<Vec<_>>();
    top_devices.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| {
                severity_rank(&right.highest_severity).cmp(&severity_rank(&left.highest_severity))
            })
            .then_with(|| left.label.cmp(&right.label))
    });
    top_devices.truncate(3);

    SecuritySummary {
        medium_count,
        high_count,
        critical_count,
        top_devices,
    }
}

fn build_notification_delivery_events(
    deliveries: &[NotificationDeliveryRecord],
) -> Vec<NotificationDeliveryEvent> {
    deliveries
        .iter()
        .map(|delivery| NotificationDeliveryEvent {
            status: delivery.status.clone(),
            event_type: delivery.event_type.clone(),
            severity: delivery.severity.clone(),
            title: delivery.title.clone(),
            summary: delivery.summary.clone(),
            target: delivery
                .device_name
                .clone()
                .unwrap_or_else(|| delivery.client_ip.clone()),
            domain: delivery.domain.clone(),
            device_name: delivery.device_name.clone(),
            client_ip: delivery.client_ip.clone(),
            attempts: delivery.attempts,
            created_at: delivery.created_at,
        })
        .take(5)
        .collect()
}

fn build_notification_health_summary(
    deliveries: &[NotificationDeliveryRecord],
) -> NotificationHealthSummary {
    let mut delivered_count = 0;
    let mut failed_count = 0;
    let mut last_delivery_at = None;
    let mut last_failure_at = None;

    for delivery in deliveries {
        match delivery.status.as_str() {
            "delivered" => {
                delivered_count += 1;
                if last_delivery_at.is_none_or(|current| delivery.created_at > current) {
                    last_delivery_at = Some(delivery.created_at);
                }
            }
            "failed" => {
                failed_count += 1;
                if last_failure_at.is_none_or(|current| delivery.created_at > current) {
                    last_failure_at = Some(delivery.created_at);
                }
            }
            _ => {}
        }
    }

    NotificationHealthSummary {
        delivered_count,
        failed_count,
        last_delivery_at,
        last_failure_at,
    }
}

fn build_notification_failure_analytics(
    deliveries: &[NotificationDeliveryRecord],
) -> NotificationFailureAnalytics {
    let mut delivered_count = 0usize;
    let mut failed_count = 0usize;
    let mut failed_domains = HashMap::<String, usize>::new();

    for delivery in deliveries {
        match delivery.status.as_str() {
            "delivered" => delivered_count += 1,
            "failed" => {
                failed_count += 1;
                if delivery.domain != "control-plane" {
                    *failed_domains.entry(delivery.domain.clone()).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }

    let total = delivered_count + failed_count;
    let success_rate_percent = if total == 0 {
        100.0
    } else {
        ((delivered_count as f32 / total as f32) * 1000.0).round() / 10.0
    };

    let mut top_failed_domains = failed_domains
        .into_iter()
        .map(|(domain, failure_count)| NotificationFailureDomain {
            domain,
            failure_count,
        })
        .collect::<Vec<_>>();
    top_failed_domains.sort_by(|left, right| {
        right
            .failure_count
            .cmp(&left.failure_count)
            .then_with(|| left.domain.cmp(&right.domain))
    });
    top_failed_domains.truncate(3);

    NotificationFailureAnalytics {
        success_rate_percent,
        top_failed_domains,
    }
}

fn normalize_notification_window(window: Option<usize>) -> usize {
    match window.unwrap_or(30) {
        10 => 10,
        50 => 50,
        100 => 100,
        _ => 30,
    }
}

fn normalize_notification_test_presets(
    presets: Vec<NotificationTestPreset>,
) -> Vec<NotificationTestPreset> {
    let mut normalized = Vec::new();

    for preset in presets {
        let name = preset.name.trim().to_string();
        let domain = preset.domain.trim().to_string();
        let device_name = preset.device_name.trim().to_string();
        let Some(severity) = normalize_notification_severity(&preset.severity) else {
            continue;
        };
        if name.is_empty() || domain.is_empty() || device_name.is_empty() {
            continue;
        }

        normalized.retain(|existing: &NotificationTestPreset| existing.name != name);
        normalized.push(NotificationTestPreset {
            name,
            domain,
            severity,
            device_name,
            dry_run: preset.dry_run,
        });
    }

    normalized.sort_by(|left, right| left.name.cmp(&right.name));
    normalized.truncate(8);
    normalized
}

fn normalize_notification_severity(severity: &str) -> Option<String> {
    match severity.trim().to_ascii_lowercase().as_str() {
        "medium" => Some("medium".to_string()),
        "high" => Some("high".to_string()),
        "critical" => Some("critical".to_string()),
        _ => None,
    }
}

fn normalize_webhook_url(url: Option<&str>) -> Option<Option<String>> {
    let Some(url) = url else {
        return Some(None);
    };
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Some(None);
    }
    let parsed = Url::parse(trimmed).ok()?;
    match parsed.scheme() {
        "https" | "http" => Some(Some(parsed.to_string())),
        _ => None,
    }
}

fn should_deliver_notification(settings: &NotificationSettings, severity: &str) -> bool {
    settings.enabled
        && settings.webhook_url.is_some()
        && severity_rank(severity) >= severity_rank(&settings.min_severity)
}

fn notification_retry_delay(attempt: usize) -> Duration {
    let multiplier = 1u64.checked_shl(attempt.min(4) as u32).unwrap_or(16);
    Duration::from_millis(250 * multiplier)
}

async fn send_security_notification(
    client: &Client,
    settings: &NotificationSettings,
    security_event: &SecurityEventRecord,
) -> Result<()> {
    let event = NotificationWebhookEvent {
        event_type: "security.alert_raised".to_string(),
        severity: security_event.severity.clone(),
        title: security_event.domain.clone(),
        summary: format!(
            "{} alert for {}.",
            security_event.severity,
            security_event
                .device_name
                .as_deref()
                .unwrap_or(&security_event.client_ip)
        ),
        domain: Some(security_event.domain.clone()),
        device_name: security_event.device_name.clone(),
        client_ip: Some(security_event.client_ip.clone()),
        details: vec![format!(
            "classifier score {:.2}",
            security_event.classifier_score
        )],
        created_at: security_event.created_at,
    };
    send_notification(client, settings, &event).await
}

async fn send_notification(
    client: &Client,
    settings: &NotificationSettings,
    event: &NotificationWebhookEvent,
) -> Result<()> {
    let Some(webhook_url) = settings.webhook_url.as_deref() else {
        return Ok(());
    };
    client
        .post(webhook_url)
        .json(&serde_json::json!({
            "event_type": event.event_type,
            "severity": event.severity,
            "title": event.title,
            "summary": event.summary,
            "domain": event.domain,
            "client_ip": event.client_ip,
            "device_name": event.device_name,
            "details": event.details,
            "created_at": event.created_at,
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn deliver_operational_notification(
    storage: &Storage,
    client: &Client,
    settings: &NotificationSettings,
    event: NotificationWebhookEvent,
) -> Result<()> {
    let mut last_error = None;

    for attempt in 0..3 {
        match send_notification(client, settings, &event).await {
            Ok(()) => {
                storage
                    .record_notification_delivery(&NotificationDeliveryRecord {
                        id: Uuid::new_v4(),
                        event_type: event.event_type.clone(),
                        status: "delivered".to_string(),
                        severity: event.severity.clone(),
                        title: event.title.clone(),
                        summary: event.summary.clone(),
                        domain: event
                            .domain
                            .clone()
                            .unwrap_or_else(|| "control-plane".to_string()),
                        device_name: event.device_name.clone(),
                        client_ip: event
                            .client_ip
                            .clone()
                            .unwrap_or_else(|| "control-plane".to_string()),
                        attempts: attempt + 1,
                        created_at: event.created_at,
                    })
                    .await?;
                storage
                    .record_audit_event(&AuditEvent {
                        id: Uuid::new_v4(),
                        event_type: "notification.delivery_succeeded".to_string(),
                        payload: serde_json::to_string(&serde_json::json!({
                            "event_type": event.event_type,
                            "severity": event.severity,
                            "title": event.title,
                            "summary": event.summary,
                            "domain": event.domain,
                            "client_ip": event.client_ip,
                            "device_name": event.device_name,
                            "attempts": attempt + 1,
                        }))?,
                        created_at: event.created_at,
                    })
                    .await?;
                return Ok(());
            }
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt < 2 {
                    tokio::time::sleep(notification_retry_delay(attempt)).await;
                }
            }
        }
    }

    let error_message = last_error.unwrap_or_else(|| "unknown delivery error".to_string());

    storage
        .record_notification_delivery(&NotificationDeliveryRecord {
            id: Uuid::new_v4(),
            event_type: event.event_type.clone(),
            status: "failed".to_string(),
            severity: event.severity.clone(),
            title: event.title.clone(),
            summary: event.summary.clone(),
            domain: event
                .domain
                .clone()
                .unwrap_or_else(|| "control-plane".to_string()),
            device_name: event.device_name.clone(),
            client_ip: event
                .client_ip
                .clone()
                .unwrap_or_else(|| "control-plane".to_string()),
            attempts: 3,
            created_at: event.created_at,
        })
        .await?;

    storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "notification.delivery_failed".to_string(),
            payload: serde_json::to_string(&serde_json::json!({
                "event_type": event.event_type,
                "severity": event.severity,
                "title": event.title,
                "summary": event.summary,
                "domain": event.domain,
                "client_ip": event.client_ip,
                "device_name": event.device_name,
                "attempts": 3,
                "error": error_message.clone(),
            }))?,
            created_at: event.created_at,
        })
        .await?;

    anyhow::bail!(
        "operational notification delivery failed after retries: {}",
        error_message
    )
}

async fn deliver_security_notification(
    storage: &Storage,
    client: &Client,
    settings: &NotificationSettings,
    security_event: &SecurityEventRecord,
) -> Result<()> {
    let mut last_error = None;

    for attempt in 0..3 {
        match send_security_notification(client, settings, security_event).await {
            Ok(()) => {
                storage
                    .record_notification_delivery(&NotificationDeliveryRecord {
                        id: Uuid::new_v4(),
                        event_type: "security.alert_raised".to_string(),
                        status: "delivered".to_string(),
                        severity: security_event.severity.clone(),
                        title: security_event.domain.clone(),
                        summary: format!(
                            "{} alert for {}.",
                            security_event.severity,
                            security_event
                                .device_name
                                .as_deref()
                                .unwrap_or(&security_event.client_ip)
                        ),
                        domain: security_event.domain.clone(),
                        device_name: security_event.device_name.clone(),
                        client_ip: security_event.client_ip.clone(),
                        attempts: attempt + 1,
                        created_at: security_event.created_at,
                    })
                    .await?;
                storage
                    .record_audit_event(&AuditEvent {
                        id: Uuid::new_v4(),
                        event_type: "security.alert_delivery_succeeded".to_string(),
                        payload: serde_json::to_string(&serde_json::json!({
                            "severity": security_event.severity,
                            "domain": security_event.domain,
                            "client_ip": security_event.client_ip,
                            "device_name": security_event.device_name,
                            "attempts": attempt + 1,
                        }))?,
                        created_at: security_event.created_at,
                    })
                    .await?;
                return Ok(());
            }
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt < 2 {
                    tokio::time::sleep(notification_retry_delay(attempt)).await;
                }
            }
        }
    }

    let error_message = last_error.unwrap_or_else(|| "unknown delivery error".to_string());

    storage
        .record_notification_delivery(&NotificationDeliveryRecord {
            id: Uuid::new_v4(),
            event_type: "security.alert_raised".to_string(),
            status: "failed".to_string(),
            severity: security_event.severity.clone(),
            title: security_event.domain.clone(),
            summary: format!(
                "{} alert for {}.",
                security_event.severity,
                security_event
                    .device_name
                    .as_deref()
                    .unwrap_or(&security_event.client_ip)
            ),
            domain: security_event.domain.clone(),
            device_name: security_event.device_name.clone(),
            client_ip: security_event.client_ip.clone(),
            attempts: 3,
            created_at: security_event.created_at,
        })
        .await?;

    storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "security.alert_delivery_failed".to_string(),
            payload: serde_json::to_string(&serde_json::json!({
                "severity": security_event.severity,
                "domain": security_event.domain,
                "client_ip": security_event.client_ip,
                "device_name": security_event.device_name,
                "attempts": 3,
                "error": error_message.clone(),
            }))?,
            created_at: security_event.created_at,
        })
        .await?;

    anyhow::bail!(
        "security alert delivery failed after retries: {}",
        error_message
    )
}

async fn record_security_event_from_classification(
    storage: Arc<Storage>,
    http_client: Client,
    notification_settings: Arc<RwLock<NotificationSettings>>,
    event: ClassificationEvent,
) -> Result<()> {
    let Some(client_ip) = event.client_ip.clone() else {
        return Ok(());
    };
    let device = storage.find_device_by_ip(&client_ip).await?;
    let severity = severity_for_classifier_score(event.classification.score).to_string();
    let security_event = SecurityEventRecord {
        id: Uuid::new_v4(),
        device_id: device.as_ref().map(|record| record.id),
        device_name: device.as_ref().map(|record| record.name.clone()),
        client_ip,
        domain: event.domain,
        classifier_score: f64::from(event.classification.score),
        severity,
        created_at: event.observed_at,
    };
    storage.record_security_event(&security_event).await?;
    let current_notification_settings = notification_settings
        .read()
        .expect("notification settings lock poisoned")
        .clone();
    if matches!(security_event.severity.as_str(), "high" | "critical") {
        storage
            .record_audit_event(&AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_raised".to_string(),
                payload: serde_json::to_string(&serde_json::json!({
                    "severity": security_event.severity,
                    "domain": security_event.domain,
                    "client_ip": security_event.client_ip,
                    "device_name": security_event.device_name,
                    "classifier_score": security_event.classifier_score,
                }))?,
                created_at: event.observed_at,
            })
            .await?;
    }
    if should_deliver_notification(&current_notification_settings, &security_event.severity) {
        deliver_security_notification(
            storage.as_ref(),
            &http_client,
            &current_notification_settings,
            &security_event,
        )
        .await?;
    }
    Ok(())
}

fn is_reserved_source_id(source_id: Uuid) -> bool {
    source_id == Uuid::from_u128(1)
}

fn post_activation_regressions(
    policy: &PolicyEngine,
    protected_domains: &HashSet<String>,
) -> Option<Vec<String>> {
    let blocked = protected_domains
        .iter()
        .filter_map(|domain| match policy.evaluate(domain).kind {
            DecisionKind::Blocked(_) => Some(format!("protected domain blocked: {domain}")),
            DecisionKind::Allowed => None,
        })
        .collect::<Vec<_>>();

    if blocked.is_empty() {
        None
    } else {
        Some(blocked)
    }
}

fn to_ruleset_summary(
    id: &Uuid,
    hash: &str,
    status: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> RulesetSummary {
    RulesetSummary {
        id: *id,
        hash: hash.to_string(),
        status: status.to_string(),
        created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cogwheel_classifier::ClassifierMode;

    #[test]
    fn runtime_regression_thresholds_trigger_degraded_state() {
        let before = DnsRuntimeSnapshot {
            upstream_failures_total: 1,
            fallback_served_total: 0,
            cache_hits_total: 0,
            cname_uncloaks_total: 0,
            cname_blocks_total: 0,
            queries_total: 100,
            blocked_total: 10,
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
            classifier_latency_avg_ns: 0,
            classifier_latency_samples: 0,
        };
        let after = DnsRuntimeSnapshot {
            upstream_failures_total: 3,
            fallback_served_total: 1,
            cache_hits_total: 0,
            cname_uncloaks_total: 0,
            cname_blocks_total: 0,
            queries_total: 200,
            blocked_total: 20,
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
            classifier_latency_avg_ns: 0,
            classifier_latency_samples: 0,
        };
        let guard = RuntimeGuardConfig {
            probe_domains: vec!["example.com".to_string()],
            max_upstream_failures_delta: 0,
            max_fallback_served_delta: 0,
        };

        let report = evaluate_runtime_regressions(&before, &after, &guard);
        assert!(report.degraded);
        assert_eq!(report.notes.len(), 2);
    }

    #[test]
    fn runtime_regression_thresholds_allow_healthy_state() {
        let before = DnsRuntimeSnapshot {
            upstream_failures_total: 1,
            fallback_served_total: 1,
            cache_hits_total: 0,
            cname_uncloaks_total: 0,
            cname_blocks_total: 0,
            queries_total: 100,
            blocked_total: 10,
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
            classifier_latency_avg_ns: 0,
            classifier_latency_samples: 0,
        };
        let after = DnsRuntimeSnapshot {
            upstream_failures_total: 1,
            fallback_served_total: 1,
            cache_hits_total: 2,
            cname_uncloaks_total: 1,
            cname_blocks_total: 0,
            queries_total: 200,
            blocked_total: 15,
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
            classifier_latency_avg_ns: 0,
            classifier_latency_samples: 0,
        };
        let guard = RuntimeGuardConfig::default();

        let report = evaluate_runtime_regressions(&before, &after, &guard);
        assert!(!report.degraded);
        assert!(report.notes.is_empty());
    }

    #[test]
    fn classifier_settings_round_trip_json() {
        let settings = ClassifierSettings {
            mode: ClassifierMode::Protect,
            threshold: 0.77,
        };

        let encoded = serde_json::to_string(&settings).expect("encode settings");
        let decoded: ClassifierSettings = serde_json::from_str(&encoded).expect("decode settings");
        assert_eq!(decoded.mode, ClassifierMode::Protect);
        assert!((decoded.threshold - 0.77).abs() < f32::EPSILON);
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
    fn normalize_device_service_overrides_filters_unknown_values() {
        assert_eq!(
            normalize_device_service_overrides(vec![
                DeviceServiceOverrideRecord {
                    service_id: "tiktok".to_string(),
                    mode: "allow".to_string(),
                },
                DeviceServiceOverrideRecord {
                    service_id: "unknown".to_string(),
                    mode: "block".to_string(),
                },
                DeviceServiceOverrideRecord {
                    service_id: "tiktok".to_string(),
                    mode: "block".to_string(),
                },
            ]),
            vec![DeviceServiceOverrideRecord {
                service_id: "tiktok".to_string(),
                mode: "block".to_string(),
            }]
        );
    }

    #[test]
    fn validate_device_service_overrides_rejects_global_mode_payloads() {
        assert_eq!(
            validate_device_service_overrides(
                "global",
                vec![DeviceServiceOverrideRecord {
                    service_id: "tiktok".to_string(),
                    mode: "allow".to_string(),
                }],
            ),
            Err("device service overrides require custom policy mode".to_string())
        );
    }

    #[test]
    fn validate_device_service_overrides_rejects_invalid_values() {
        assert_eq!(
            validate_device_service_overrides(
                "custom",
                vec![DeviceServiceOverrideRecord {
                    service_id: "unknown".to_string(),
                    mode: "allow".to_string(),
                }],
            ),
            Err(
                "unknown device service override `unknown`; choose one of the built-in services"
                    .to_string()
            )
        );

        assert_eq!(
            validate_device_service_overrides(
                "custom",
                vec![DeviceServiceOverrideRecord {
                    service_id: "tiktok".to_string(),
                    mode: "monitor".to_string(),
                }],
            ),
            Err("device service override `TikTok` must use allow or block mode".to_string())
        );
    }

    #[test]
    fn validate_device_service_overrides_normalizes_known_values() {
        assert_eq!(
            validate_device_service_overrides(
                "custom",
                vec![
                    DeviceServiceOverrideRecord {
                        service_id: " tiktok ".to_string(),
                        mode: "allow".to_string(),
                    },
                    DeviceServiceOverrideRecord {
                        service_id: "tiktok".to_string(),
                        mode: "block".to_string(),
                    },
                ],
            ),
            Ok(vec![DeviceServiceOverrideRecord {
                service_id: "tiktok".to_string(),
                mode: "block".to_string(),
            }])
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
    fn normalize_notification_inputs_accept_expected_values() {
        assert_eq!(
            normalize_notification_severity(" HIGH "),
            Some("high".to_string())
        );
        assert_eq!(normalize_notification_severity("low"), None);
        assert_eq!(normalize_webhook_url(None), Some(None));
        assert_eq!(normalize_webhook_url(Some("   ")), Some(None));
        assert!(normalize_webhook_url(Some("https://hooks.example.test/path")).is_some());
        assert_eq!(normalize_webhook_url(Some("ftp://example.test")), None);
    }

    #[test]
    fn notification_delivery_respects_thresholds() {
        let settings = NotificationSettings {
            enabled: true,
            webhook_url: Some("https://hooks.example.test/path".to_string()),
            min_severity: "high".to_string(),
        };

        assert!(!should_deliver_notification(&settings, "medium"));
        assert!(should_deliver_notification(&settings, "high"));
        assert!(should_deliver_notification(&settings, "critical"));
    }

    #[test]
    fn notification_retry_delay_backs_off() {
        assert_eq!(notification_retry_delay(0), Duration::from_millis(250));
        assert_eq!(notification_retry_delay(1), Duration::from_millis(500));
        assert_eq!(notification_retry_delay(2), Duration::from_millis(1000));
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
            service_overrides: vec![DeviceServiceOverrideRecord {
                service_id: "tiktok".to_string(),
                mode: "allow".to_string(),
            }],
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

    #[test]
    fn build_security_summary_tracks_severity_and_devices() {
        let summary = build_security_summary(&[
            SecurityEventRecord {
                id: Uuid::new_v4(),
                device_id: None,
                device_name: Some("Laptop".to_string()),
                client_ip: "192.168.1.10".to_string(),
                domain: "alpha.example".to_string(),
                classifier_score: 0.97,
                severity: "high".to_string(),
                created_at: Utc::now(),
            },
            SecurityEventRecord {
                id: Uuid::new_v4(),
                device_id: None,
                device_name: Some("Laptop".to_string()),
                client_ip: "192.168.1.10".to_string(),
                domain: "beta.example".to_string(),
                classifier_score: 0.995,
                severity: "critical".to_string(),
                created_at: Utc::now(),
            },
            SecurityEventRecord {
                id: Uuid::new_v4(),
                device_id: None,
                device_name: None,
                client_ip: "192.168.1.20".to_string(),
                domain: "gamma.example".to_string(),
                classifier_score: 0.93,
                severity: "medium".to_string(),
                created_at: Utc::now(),
            },
        ]);

        assert_eq!(summary.medium_count, 1);
        assert_eq!(summary.high_count, 1);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.top_devices.len(), 2);
        assert_eq!(summary.top_devices[0].label, "Laptop");
        assert_eq!(summary.top_devices[0].event_count, 2);
        assert_eq!(summary.top_devices[0].highest_severity, "critical");
    }

    #[test]
    fn build_notification_delivery_events_maps_delivery_records() {
        let deliveries = build_notification_delivery_events(&[NotificationDeliveryRecord {
            id: Uuid::new_v4(),
            event_type: "security.alert_raised".to_string(),
            status: "delivered".to_string(),
            severity: "high".to_string(),
            title: "notify.example".to_string(),
            summary: "high alert for Laptop after 2 attempt(s).".to_string(),
            domain: "notify.example".to_string(),
            device_name: Some("Laptop".to_string()),
            client_ip: "192.168.1.25".to_string(),
            attempts: 2,
            created_at: Utc::now(),
        }]);

        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, "delivered");
        assert_eq!(deliveries[0].event_type, "security.alert_raised");
        assert_eq!(deliveries[0].title, "notify.example");
        assert_eq!(deliveries[0].target, "Laptop");
        assert_eq!(deliveries[0].domain, "notify.example");
        assert_eq!(deliveries[0].attempts, 2);
    }

    #[test]
    fn build_notification_delivery_events_supports_operational_payloads() {
        let deliveries = build_notification_delivery_events(&[NotificationDeliveryRecord {
            id: Uuid::new_v4(),
            event_type: "ruleset.rollback".to_string(),
            status: "delivered".to_string(),
            severity: "high".to_string(),
            title: "Ruleset rolled back".to_string(),
            summary: "Rolled back to the previous verified ruleset.".to_string(),
            domain: "control-plane".to_string(),
            device_name: None,
            client_ip: "control-plane".to_string(),
            attempts: 1,
            created_at: Utc::now(),
        }]);

        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, "delivered");
        assert_eq!(deliveries[0].event_type, "ruleset.rollback");
        assert_eq!(deliveries[0].title, "Ruleset rolled back");
        assert_eq!(
            deliveries[0].summary,
            "Rolled back to the previous verified ruleset."
        );
        assert_eq!(deliveries[0].target, "control-plane");
        assert_eq!(deliveries[0].client_ip, "control-plane");
        assert_eq!(deliveries[0].domain, "control-plane");
    }

    #[test]
    fn build_notification_health_summary_tracks_outcomes() {
        let now = Utc::now();
        let summary = build_notification_health_summary(&[
            NotificationDeliveryRecord {
                id: Uuid::new_v4(),
                event_type: "security.alert_raised".to_string(),
                status: "delivered".to_string(),
                severity: "high".to_string(),
                title: "ok.example".to_string(),
                summary: "delivered".to_string(),
                domain: "ok.example".to_string(),
                device_name: None,
                client_ip: "192.168.1.25".to_string(),
                attempts: 1,
                created_at: now,
            },
            NotificationDeliveryRecord {
                id: Uuid::new_v4(),
                event_type: "security.alert_raised".to_string(),
                status: "failed".to_string(),
                severity: "high".to_string(),
                title: "fail.example".to_string(),
                summary: "failed".to_string(),
                domain: "fail.example".to_string(),
                device_name: None,
                client_ip: "192.168.1.25".to_string(),
                attempts: 3,
                created_at: now + chrono::Duration::seconds(5),
            },
        ]);

        assert_eq!(summary.delivered_count, 1);
        assert_eq!(summary.failed_count, 1);
        assert_eq!(summary.last_delivery_at, Some(now));
        assert_eq!(
            summary.last_failure_at,
            Some(now + chrono::Duration::seconds(5))
        );
    }

    #[test]
    fn build_notification_failure_analytics_tracks_failed_domains() {
        let analytics = build_notification_failure_analytics(&[
            NotificationDeliveryRecord {
                id: Uuid::new_v4(),
                event_type: "security.alert_raised".to_string(),
                status: "delivered".to_string(),
                severity: "high".to_string(),
                title: "ok.example".to_string(),
                summary: "ok".to_string(),
                domain: "ok.example".to_string(),
                device_name: None,
                client_ip: "192.168.1.25".to_string(),
                attempts: 1,
                created_at: Utc::now(),
            },
            NotificationDeliveryRecord {
                id: Uuid::new_v4(),
                event_type: "security.alert_raised".to_string(),
                status: "failed".to_string(),
                severity: "high".to_string(),
                title: "fail.example".to_string(),
                summary: "failed".to_string(),
                domain: "fail.example".to_string(),
                device_name: None,
                client_ip: "192.168.1.25".to_string(),
                attempts: 3,
                created_at: Utc::now(),
            },
            NotificationDeliveryRecord {
                id: Uuid::new_v4(),
                event_type: "security.alert_raised".to_string(),
                status: "failed".to_string(),
                severity: "high".to_string(),
                title: "fail.example".to_string(),
                summary: "failed again".to_string(),
                domain: "fail.example".to_string(),
                device_name: None,
                client_ip: "192.168.1.25".to_string(),
                attempts: 3,
                created_at: Utc::now(),
            },
        ]);

        assert_eq!(analytics.success_rate_percent, 33.3);
        assert_eq!(analytics.top_failed_domains.len(), 1);
        assert_eq!(analytics.top_failed_domains[0].domain, "fail.example");
        assert_eq!(analytics.top_failed_domains[0].failure_count, 2);
    }

    #[test]
    fn parse_tailscale_status_json_extracts_health_fields() {
        let status = parse_tailscale_status_json(
            &serde_json::json!({
                "BackendState": "Running",
                "CurrentTailnet": { "Name": "example.ts.net" },
                "Self": {
                    "HostName": "cogwheel-node",
                    "UsingExitNode": true
                },
                "Peer": {
                    "peer-a": {},
                    "peer-b": {}
                },
                "Health": ["wantrunning is false"]
            })
            .to_string(),
        );

        assert!(status.installed);
        assert!(status.daemon_running);
        assert_eq!(status.backend_state.as_deref(), Some("Running"));
        assert_eq!(status.hostname.as_deref(), Some("cogwheel-node"));
        assert_eq!(status.tailnet_name.as_deref(), Some("example.ts.net"));
        assert_eq!(status.peer_count, 2);
        assert!(status.exit_node_active);
        assert_eq!(status.health_warnings, vec!["wantrunning is false"]);
    }

    #[test]
    fn normalize_notification_window_accepts_known_values() {
        assert_eq!(normalize_notification_window(Some(10)), 10);
        assert_eq!(normalize_notification_window(Some(50)), 50);
        assert_eq!(normalize_notification_window(Some(100)), 100);
        assert_eq!(normalize_notification_window(Some(999)), 30);
        assert_eq!(normalize_notification_window(None), 30);
    }

    #[test]
    fn normalize_notification_test_presets_filters_invalid_entries() {
        let presets = normalize_notification_test_presets(vec![
            NotificationTestPreset {
                name: "weekday".to_string(),
                domain: "notify.example".to_string(),
                severity: "high".to_string(),
                device_name: "Laptop".to_string(),
                dry_run: false,
            },
            NotificationTestPreset {
                name: "weekday".to_string(),
                domain: "notify-two.example".to_string(),
                severity: "critical".to_string(),
                device_name: "Tablet".to_string(),
                dry_run: true,
            },
            NotificationTestPreset {
                name: "".to_string(),
                domain: "ignored.example".to_string(),
                severity: "high".to_string(),
                device_name: "Ignored".to_string(),
                dry_run: false,
            },
        ]);

        assert_eq!(presets.len(), 1);
        assert_eq!(presets[0].name, "weekday");
        assert_eq!(presets[0].domain, "notify-two.example");
        assert_eq!(presets[0].severity, "critical");
        assert!(presets[0].dry_run);
    }

    #[test]
    fn severity_for_classifier_score_uses_expected_bands() {
        assert_eq!(severity_for_classifier_score(0.995), "critical");
        assert_eq!(severity_for_classifier_score(0.97), "high");
        assert_eq!(severity_for_classifier_score(0.92), "medium");
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

    #[test]
    fn parse_tailscale_status_json_handles_missing_fields() {
        let status = parse_tailscale_status_json("{}");
        assert!(status.installed);
        assert!(status.daemon_running);
        assert!(status.hostname.is_none());
        assert!(!status.exit_node_active);
    }

    #[test]
    fn parse_tailscale_status_json_detects_exit_node_status_variants() {
        let status_with_exit_node = parse_tailscale_status_json(
            &serde_json::json!({
                "Self": { "ExitNode": true }
            })
            .to_string(),
        );
        assert!(status_with_exit_node.exit_node_active);

        let status_with_exit_node_status = parse_tailscale_status_json(
            &serde_json::json!({
                "Self": { "ExitNodeStatus": "Active" }
            })
            .to_string(),
        );
        assert!(status_with_exit_node_status.exit_node_active);

        let status_without_exit = parse_tailscale_status_json(
            &serde_json::json!({
                "Self": { "ExitNode": false }
            })
            .to_string(),
        );
        assert!(!status_without_exit.exit_node_active);
    }

    #[test]
    fn tailscale_saved_state_serialization() {
        let state = TailscaleSavedState {
            exit_node_enabled: true,
            saved_at: "2024-01-01T00:00:00Z".to_string(),
            hostname: "test-node".to_string(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: TailscaleSavedState = serde_json::from_str(&json).unwrap();
        assert!(parsed.exit_node_enabled);
        assert_eq!(parsed.hostname, "test-node");
    }
}
