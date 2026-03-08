use anyhow::{Context, Result};
use axum::extract::{FromRef, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use cogwheel_api::{ApiEnvelope, ApiState, AppConfig, RuntimeGuardConfig, router};
use cogwheel_classifier::ClassifierSettings;
use cogwheel_dns_core::{DnsRuntime, DnsRuntimeConfig, DnsRuntimeSnapshot};
use cogwheel_lists::{
    SourceDefinition, SourceKind, build_policy_engine, fetch_and_parse_source, parse_source,
    synthetic_source, verify_candidate,
};
use cogwheel_policy::{BlockMode, DecisionKind, PolicyEngine};
use cogwheel_services::{
    ServiceManifest, ServiceToggleMode, ServiceToggleSnapshot, built_in_service_manifests,
    compile_service_rule_layer,
};
use cogwheel_storage::{AuditEvent, RulesetRecord, SourceRecord, Storage};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::xfer::Protocol;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use std::collections::HashSet;
use std::sync::Arc;
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
    protected_domains: Arc<HashSet<String>>,
    runtime_guard: RuntimeGuardConfig,
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
    runtime_health: RuntimeHealthResponse,
    latest_audit_events: Vec<AuditEvent>,
}

#[derive(serde::Serialize)]
struct SettingsSummary {
    blocklists: Vec<SourceRecord>,
    services: Vec<ServiceToggleView>,
    classifier: ClassifierSettings,
    runtime_guard: RuntimeGuardConfig,
}

#[derive(Debug, Clone)]
struct RuntimeRegressionReport {
    degraded: bool,
    notes: Vec<String>,
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
    };
    storage.insert_source(&default_source).await?;

    let parsed = parse_source(
        SourceDefinition {
            id: default_source.id,
            name: default_source.name.clone(),
            url: Url::parse(&default_source.url)?,
            kind: SourceKind::Domains,
            enabled: true,
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
    let dns_runtime = Arc::new(DnsRuntime::new(resolver, policy, classifier_settings));

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
        protected_domains,
        runtime_guard: config.runtime_guard,
    };
    let refresh_handle = tokio::spawn({
        let state = app_state.clone();
        let refresh_every = config.updater.refresh_interval_secs.max(30);
        async move {
            let mut ticker = interval(Duration::from_secs(refresh_every));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(error) = refresh_sources_once(&state, "scheduled").await {
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
        .route("/api/v1/sources", get(list_sources))
        .route("/api/v1/sources/refresh", post(refresh_sources))
        .route("/api/v1/services", get(list_services))
        .route("/api/v1/services/toggles", post(update_service_toggle))
        .route(
            "/api/v1/settings/classifier",
            post(update_classifier_settings),
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
            runtime_health,
            latest_audit_events,
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

    Ok(Json(ApiEnvelope {
        data: SettingsSummary {
            blocklists,
            services,
            classifier: state.dns_runtime.classifier_settings(),
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

    state
        .dns_runtime
        .replace_policy(Arc::new(PolicyEngine::new(artifact.clone())));
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
    refresh_sources_once(&state, "manual")
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

    refresh_sources_once(&state, "service-toggle")
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

async fn refresh_sources_once(state: &ServerState, reason: &str) -> Result<RefreshResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("build refresh http client")?;

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

    let policy = Arc::new(build_policy_engine(
        parsed_sources,
        state.protected_domains.as_ref().clone(),
        BlockMode::NullIp,
    ));

    state
        .storage
        .record_ruleset(&RulesetRecord {
            id: policy.artifact().id,
            hash: policy.artifact().hash.clone(),
            status: "candidate".to_string(),
            created_at: policy.artifact().created_at,
            artifact_json: serde_json::to_string(policy.artifact())?,
        })
        .await?;
    let runtime_before = state.dns_runtime.snapshot();
    state.storage.activate_ruleset(policy.artifact().id).await?;
    state.dns_runtime.replace_policy(policy.clone());

    let mut regression_notes =
        post_activation_regressions(policy.as_ref(), &state.protected_domains).unwrap_or_default();
    let runtime_report = run_runtime_guard_probes(state, &runtime_before).await;
    if runtime_report.degraded {
        regression_notes.extend(runtime_report.notes);
    }

    if !regression_notes.is_empty() {
        let Some(artifact) = state.storage.rollback_to_previous_ruleset().await? else {
            anyhow::bail!("regression detected but no previous ruleset available for rollback");
        };
        state
            .dns_runtime
            .replace_policy(Arc::new(PolicyEngine::new(artifact.clone())));
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
                "ruleset_id": policy.artifact().id,
                "hash": policy.artifact().hash,
                "reason": reason,
            })
            .to_string(),
            created_at: chrono::Utc::now(),
        })
        .await?;

    Ok(RefreshResponse {
        outcome: "activated".to_string(),
        ruleset: Some(to_ruleset_summary(
            &policy.artifact().id,
            &policy.artifact().hash,
            "active",
            policy.artifact().created_at,
        )),
        notes: vec![format!(
            "refreshed {} source(s)",
            state.storage.list_sources().await?.len()
        )]
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

async fn persist_classifier_settings(
    storage: &Storage,
    settings: &ClassifierSettings,
) -> Result<()> {
    storage
        .upsert_setting("classifier_settings", &serde_json::to_string(settings)?)
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

fn source_definition_from_record(record: SourceRecord) -> Result<SourceDefinition> {
    let kind = match record.kind.as_str() {
        "domains" => SourceKind::Domains,
        "hosts" => SourceKind::Hosts,
        "adblock" => SourceKind::Adblock,
        other => anyhow::bail!("unsupported source kind: {other}"),
    };

    Ok(SourceDefinition {
        id: record.id,
        name: record.name,
        url: Url::parse(&record.url)?,
        kind,
        enabled: record.enabled,
    })
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
}
