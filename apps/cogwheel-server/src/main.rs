use anyhow::{Context, Result};
use axum::extract::{FromRef, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use cogwheel_api::{ApiEnvelope, ApiState, AppConfig, RuntimeGuardConfig, router};
use cogwheel_classifier::ClassifierSettings;
use cogwheel_dns_core::{
    ClassificationEvent, DevicePolicyConfig, DnsRuntime, DnsRuntimeConfig, DnsRuntimeSnapshot,
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
    AuditEvent, DeviceRecord, DeviceServiceOverrideRecord, RulesetRecord, SecurityEventRecord,
    SourceRecord, Storage,
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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tokio::time::interval;
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
    protected_domains: Arc<HashSet<String>>,
    runtime_guard: RuntimeGuardConfig,
}

#[derive(Clone)]
struct RuntimePolicyCatalog {
    global_policy: Arc<PolicyEngine>,
    profile_policies: HashMap<String, Arc<PolicyEngine>>,
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
}

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationDeliveryEvent {
    status: String,
    severity: String,
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

#[derive(Debug, Clone, serde::Serialize)]
struct NotificationTestResult {
    outcome: String,
    target: String,
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
    devices: Vec<DeviceRecord>,
    services: Vec<ServiceToggleView>,
    classifier: ClassifierSettings,
    notifications: NotificationSettings,
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
        protected_domains,
        runtime_guard: config.runtime_guard,
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
    let app = router(app_state.clone())
        .merge(admin_router())
        .with_state(app_state)
        .layer(TraceLayer::new_for_http());
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

fn admin_router() -> Router<ServerState> {
    Router::new()
        .route("/api/v1/dashboard", get(dashboard_summary))
        .route("/api/v1/settings", get(settings_summary))
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
        .route("/api/v1/runtime", get(runtime_snapshot))
        .route("/api/v1/runtime/health", get(runtime_health))
        .route("/api/v1/rulesets", get(list_rulesets))
        .route("/api/v1/rulesets/rollback", post(rollback_ruleset))
        .route("/api/v1/audit-events", get(list_audit_events))
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
) -> Result<Json<ApiEnvelope<DeviceRecord>>, axum::http::StatusCode> {
    let device = DeviceRecord {
        id: request.id.unwrap_or_else(Uuid::new_v4),
        name: request.name,
        ip_address: request.ip_address,
        policy_mode: normalize_device_policy_mode(
            request.policy_mode.as_deref().unwrap_or("global"),
        )
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
        blocklist_profile_override: request
            .blocklist_profile_override
            .as_deref()
            .and_then(normalize_profile_name),
        protection_override: normalize_device_protection_override(
            request.protection_override.as_deref().unwrap_or("inherit"),
        )
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
        allowed_domains: normalize_device_allowed_domains(
            request.allowed_domains.unwrap_or_default(),
        ),
        service_overrides: normalize_device_service_overrides(
            request.service_overrides.unwrap_or_default(),
        ),
    };

    state
        .storage
        .upsert_device(&device)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .storage
        .record_audit_event(&AuditEvent {
            id: Uuid::new_v4(),
            event_type: "device.upserted".to_string(),
            payload: serde_json::to_string(&device)
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
            created_at: chrono::Utc::now(),
        })
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    sync_runtime_device_policies(&state)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

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
) -> Result<Json<ApiEnvelope<DashboardSummary>>, axum::http::StatusCode> {
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
    let notification_audit_events = state
        .storage
        .recent_audit_events(30)
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
        build_notification_delivery_events(&notification_audit_events);
    let notification_health = build_notification_health_summary(&notification_audit_events);
    let notification_failure_analytics =
        build_notification_failure_analytics(&notification_audit_events);
    let snapshot = load_service_toggle_snapshot(&state.storage)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiEnvelope {
        data: DashboardSummary {
            protection_status: if runtime_health.degraded {
                "Needs Attention".to_string()
            } else {
                "Protected".to_string()
            },
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
        },
    }))
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

    Ok(Json(ApiEnvelope {
        data: SettingsSummary {
            blocklists,
            blocklist_statuses,
            devices,
            services,
            classifier: state.dns_runtime.classifier_settings(),
            notifications: state
                .notification_settings
                .read()
                .expect("notification settings lock poisoned")
                .clone(),
            runtime_guard: state.runtime_guard.clone(),
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

async fn refresh_sources(
    State(state): State<ServerState>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
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

async fn upsert_blocklist(
    State(state): State<ServerState>,
    Json(request): Json<UpsertBlocklistRequest>,
) -> Result<Json<ApiEnvelope<RefreshResponse>>, axum::http::StatusCode> {
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

        return Ok(RefreshResponse {
            outcome: "rejected".to_string(),
            ruleset: None,
            notes: verification
                .notes
                .into_iter()
                .chain(service_layer.notes)
                .collect(),
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
    audit_events: &[AuditEvent],
) -> Vec<NotificationDeliveryEvent> {
    audit_events
        .iter()
        .filter_map(|event| {
            let status = match event.event_type.as_str() {
                "security.alert_delivery_succeeded" => "delivered",
                "security.alert_delivery_failed" => "failed",
                _ => return None,
            };
            let payload: serde_json::Value = serde_json::from_str(&event.payload).ok()?;
            Some(NotificationDeliveryEvent {
                status: status.to_string(),
                severity: payload
                    .get("severity")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                domain: payload
                    .get("domain")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                device_name: payload
                    .get("device_name")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                client_ip: payload
                    .get("client_ip")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                attempts: payload
                    .get("attempts")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as usize,
                created_at: event.created_at,
            })
        })
        .take(5)
        .collect()
}

fn build_notification_health_summary(audit_events: &[AuditEvent]) -> NotificationHealthSummary {
    let mut delivered_count = 0;
    let mut failed_count = 0;
    let mut last_delivery_at = None;
    let mut last_failure_at = None;

    for event in audit_events {
        match event.event_type.as_str() {
            "security.alert_delivery_succeeded" => {
                delivered_count += 1;
                if last_delivery_at.is_none_or(|current| event.created_at > current) {
                    last_delivery_at = Some(event.created_at);
                }
            }
            "security.alert_delivery_failed" => {
                failed_count += 1;
                if last_failure_at.is_none_or(|current| event.created_at > current) {
                    last_failure_at = Some(event.created_at);
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
    audit_events: &[AuditEvent],
) -> NotificationFailureAnalytics {
    let mut delivered_count = 0usize;
    let mut failed_count = 0usize;
    let mut failed_domains = HashMap::<String, usize>::new();

    for event in audit_events {
        match event.event_type.as_str() {
            "security.alert_delivery_succeeded" => delivered_count += 1,
            "security.alert_delivery_failed" => {
                failed_count += 1;
                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&event.payload) {
                    if let Some(domain) = payload.get("domain").and_then(serde_json::Value::as_str)
                    {
                        *failed_domains.entry(domain.to_string()).or_insert(0) += 1;
                    }
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
    let Some(webhook_url) = settings.webhook_url.as_deref() else {
        return Ok(());
    };
    client
        .post(webhook_url)
        .json(&serde_json::json!({
            "event_type": "security.alert_raised",
            "severity": security_event.severity,
            "domain": security_event.domain,
            "client_ip": security_event.client_ip,
            "device_name": security_event.device_name,
            "classifier_score": security_event.classifier_score,
            "created_at": security_event.created_at,
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
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
        };
        let after = DnsRuntimeSnapshot {
            upstream_failures_total: 3,
            fallback_served_total: 1,
            cache_hits_total: 0,
            cname_uncloaks_total: 0,
            cname_blocks_total: 0,
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
        };
        let after = DnsRuntimeSnapshot {
            upstream_failures_total: 1,
            fallback_served_total: 1,
            cache_hits_total: 2,
            cname_uncloaks_total: 1,
            cname_blocks_total: 0,
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
    fn build_notification_delivery_events_filters_audit_payloads() {
        let deliveries = build_notification_delivery_events(&[
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_delivery_succeeded".to_string(),
                payload: serde_json::json!({
                    "severity": "high",
                    "domain": "notify.example",
                    "device_name": "Laptop",
                    "client_ip": "192.168.1.25",
                    "attempts": 2,
                })
                .to_string(),
                created_at: Utc::now(),
            },
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "device.upserted".to_string(),
                payload: "{}".to_string(),
                created_at: Utc::now(),
            },
        ]);

        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status, "delivered");
        assert_eq!(deliveries[0].domain, "notify.example");
        assert_eq!(deliveries[0].attempts, 2);
    }

    #[test]
    fn build_notification_health_summary_tracks_outcomes() {
        let now = Utc::now();
        let summary = build_notification_health_summary(&[
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_delivery_succeeded".to_string(),
                payload: "{}".to_string(),
                created_at: now,
            },
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_delivery_failed".to_string(),
                payload: "{}".to_string(),
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
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_delivery_succeeded".to_string(),
                payload: serde_json::json!({ "domain": "ok.example" }).to_string(),
                created_at: Utc::now(),
            },
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_delivery_failed".to_string(),
                payload: serde_json::json!({ "domain": "fail.example" }).to_string(),
                created_at: Utc::now(),
            },
            AuditEvent {
                id: Uuid::new_v4(),
                event_type: "security.alert_delivery_failed".to_string(),
                payload: serde_json::json!({ "domain": "fail.example" }).to_string(),
                created_at: Utc::now(),
            },
        ]);

        assert_eq!(analytics.success_rate_percent, 33.3);
        assert_eq!(analytics.top_failed_domains.len(), 1);
        assert_eq!(analytics.top_failed_domains[0].domain, "fail.example");
        assert_eq!(analytics.top_failed_domains[0].failure_count, 2);
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
}
