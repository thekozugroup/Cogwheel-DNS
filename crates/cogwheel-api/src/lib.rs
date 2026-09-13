use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfile {
    Dev,
    #[default]
    Home,
    Smb,
}

impl FromStr for DeploymentProfile {
    type Err = ApiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dev" => Ok(Self::Dev),
            "home" => Ok(Self::Home),
            "smb" => Ok(Self::Smb),
            _ => Err(ApiError::InvalidEnv(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub bind_addr: SocketAddr,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub http_bind_addr: SocketAddr,
    pub dns_udp_bind_addr: SocketAddr,
    pub dns_tcp_bind_addr: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            dns_udp_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
            dns_tcp_bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_url: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_url: "sqlite://data/cogwheel.db".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub servers: Vec<String>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec!["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterConfig {
    pub refresh_interval_secs: u64,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub profile: DeploymentProfile,
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub upstream: UpstreamConfig,
    pub updater: UpdaterConfig,
    pub blocking: BlockingConfig,
    pub retention: RetentionConfig,
}

/// How long observed history is kept before it is deleted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Days of observed history to keep. `0` disables pruning and keeps
    /// everything forever, which is what every version before this one did.
    pub history_days: u32,
    /// How often the prune runs. Hourly by default: often enough that the
    /// window is honoured closely, rare enough to be invisible on a Pi.
    pub prune_interval_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            // Bounded by default, deliberately. These tables previously grew
            // without limit, which is both a disk problem on an appliance disk
            // and -- for a product whose purpose is to stop other people
            // recording what a household browses -- an odd thing to do with
            // that same information. 30 days is long enough to investigate
            // "why did this break last week" and short enough that the box is
            // not a permanent archive.
            history_days: 30,
            prune_interval_secs: 3_600,
        }
    }
}

/// How a blocked name is answered.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockingConfig {
    /// Response returned for a blocked name.
    pub mode: BlockResponseMode,
}

/// The answer a blocked lookup receives.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseMode {
    /// `0.0.0.0` / `::`. The default.
    #[default]
    NullIp,
    /// `NXDOMAIN`, as though the name did not exist.
    NxDomain,
    /// `NOERROR` with no answers.
    NoData,
    /// `REFUSED`.
    Refused,
}

impl FromStr for BlockResponseMode {
    type Err = ApiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "null_ip" | "null-ip" | "nullip" | "zero" => Ok(Self::NullIp),
            "nxdomain" | "nx_domain" => Ok(Self::NxDomain),
            "nodata" | "no_data" => Ok(Self::NoData),
            "refused" => Ok(Self::Refused),
            _ => Err(ApiError::InvalidEnv(value.to_string())),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ApiError> {
        Self::load_from_env(|key| std::env::var(key).ok())
    }

    pub fn load_from_env<F>(env_get: F) -> Result<Self, ApiError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let profile = env_get("COGWHEEL_PROFILE")
            .map(|value| DeploymentProfile::from_str(&value))
            .transpose()?
            .unwrap_or_default();
        let mut config = Self::for_profile(profile);

        if let Some(value) = env_get("COGWHEEL_SERVER__HTTP_BIND_ADDR") {
            config.server.http_bind_addr =
                SocketAddr::from_str(&value).map_err(|_| ApiError::InvalidEnv(value.clone()))?;
        }
        if let Some(value) = env_get("COGWHEEL_SERVER__DNS_UDP_BIND_ADDR") {
            config.server.dns_udp_bind_addr =
                SocketAddr::from_str(&value).map_err(|_| ApiError::InvalidEnv(value.clone()))?;
        }
        if let Some(value) = env_get("COGWHEEL_SERVER__DNS_TCP_BIND_ADDR") {
            config.server.dns_tcp_bind_addr =
                SocketAddr::from_str(&value).map_err(|_| ApiError::InvalidEnv(value.clone()))?;
        }
        if let Some(value) = env_get("COGWHEEL_STORAGE__DATABASE_URL") {
            config.storage.database_url = value;
        }
        if let Some(value) = env_get("COGWHEEL_RETENTION__HISTORY_DAYS") {
            config.retention.history_days = value
                .trim()
                .parse::<u32>()
                .map_err(|_| ApiError::InvalidEnv(value.clone()))?;
        }
        if let Some(value) = env_get("COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS") {
            let seconds = value
                .trim()
                .parse::<u64>()
                .map_err(|_| ApiError::InvalidEnv(value.clone()))?;
            // A floor, not a rejection: a misconfigured 1-second interval would
            // have the appliance running a delete across its largest tables
            // continuously, which is a worse failure than ignoring the number.
            config.retention.prune_interval_secs = seconds.max(60);
        }
        if let Some(value) = env_get("COGWHEEL_BLOCKING__MODE") {
            config.blocking.mode = BlockResponseMode::from_str(&value)?;
        }
        if let Some(value) = env_get("COGWHEEL_UPSTREAM__SERVERS") {
            config.upstream.servers = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect();
        }
        if let Some(value) = env_get("COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS") {
            config.updater.refresh_interval_secs = value
                .parse::<u64>()
                .map_err(|_| ApiError::InvalidEnv(value.clone()))?;
        }
        Ok(config)
    }

    pub fn for_profile(profile: DeploymentProfile) -> Self {
        let mut config = Self {
            profile,
            ..Self::default()
        };

        match profile {
            DeploymentProfile::Dev => {
                config.server.http_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30080);
                config.server.dns_udp_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30053);
                config.server.dns_tcp_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30053);
                config.storage.database_url = "sqlite://data/cogwheel-dev.db".to_string();
                config.updater.refresh_interval_secs = 120;
            }
            DeploymentProfile::Home => {
                config.server.http_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
                config.server.dns_udp_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353);
                config.server.dns_tcp_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353);
                config.storage.database_url = "sqlite://data/cogwheel.db".to_string();
                config.updater.refresh_interval_secs = 300;
            }
            DeploymentProfile::Smb => {
                config.server.http_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
                config.server.dns_udp_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53);
                config.server.dns_tcp_bind_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53);
                config.storage.database_url = "sqlite://data/cogwheel-smb.db".to_string();
                config.updater.refresh_interval_secs = 600;
            }
        }

        config
    }
}

#[derive(Debug, Clone)]
pub struct ApiState {
    /// Subsystem readiness, reported by `/health/ready`.
    pub readiness: Arc<Readiness>,
}

/// Tracks whether each subsystem required to answer real traffic has come up.
///
/// Liveness and readiness must not be the same signal. `/health/ready` previously returned 200 the
/// instant axum bound its listener, which made it strictly weaker than useless: an orchestrator
/// could not tell "the process exists" from "this node can actually resolve DNS", so a rolling
/// upgrade would shift traffic to a node whose blocklists had not compiled yet.
#[derive(Debug, Default)]
pub struct Readiness {
    storage: AtomicBool,
    policy: AtomicBool,
    dns_listeners: AtomicBool,
}

impl Readiness {
    /// Storage is open and its migrations have applied.
    pub fn mark_storage_ready(&self) {
        self.storage.store(true, Ordering::Release);
    }

    /// An initial policy artifact has been compiled and installed in the runtime.
    pub fn mark_policy_ready(&self) {
        self.policy.store(true, Ordering::Release);
    }

    /// Both DNS listeners are bound and accepting.
    pub fn mark_dns_ready(&self) {
        self.dns_listeners.store(true, Ordering::Release);
    }

    /// Whether every subsystem is up.
    pub fn is_ready(&self) -> bool {
        self.storage.load(Ordering::Acquire)
            && self.policy.load(Ordering::Acquire)
            && self.dns_listeners.load(Ordering::Acquire)
    }

    /// Per-subsystem detail, so a failing probe says which part is not up.
    pub fn detail(&self) -> ReadinessDetail {
        ReadinessDetail {
            storage: self.storage.load(Ordering::Acquire),
            policy: self.policy.load(Ordering::Acquire),
            dns_listeners: self.dns_listeners.load(Ordering::Acquire),
        }
    }
}

/// Per-subsystem readiness breakdown.
#[derive(Debug, Serialize)]
pub struct ReadinessDetail {
    /// Storage open and migrated.
    pub storage: bool,
    /// Initial policy compiled and installed.
    pub policy: bool,
    /// UDP and TCP DNS listeners bound.
    pub dns_listeners: bool,
}

/// Body of a readiness probe.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    /// `ready` or `starting`.
    pub status: &'static str,
    /// Which subsystems are up.
    pub subsystems: ReadinessDetail,
}

#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("invalid environment value: {0}")]
    InvalidEnv(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.to_string() }));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

pub fn router<S>(state: S) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    ApiState: FromRef<S>,
{
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(state)
}

async fn live() -> Json<ApiEnvelope<HealthResponse>> {
    Json(ApiEnvelope {
        data: HealthResponse { status: "ok" },
    })
}

/// Readiness probe.
///
/// Returns 503 until every subsystem is up, so an orchestrator or the container healthcheck can
/// distinguish "starting" from "serving".
async fn ready(State(state): State<ApiState>) -> Response {
    let detail = state.readiness.detail();
    let ready = state.readiness.is_ready();
    let body = Json(ApiEnvelope {
        data: ReadinessResponse {
            status: if ready { "ready" } else { "starting" },
            subsystems: detail,
        },
    });
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, DeploymentProfile};
    use std::collections::HashMap;
    use std::fs;

    #[test]
    fn defaults_to_home_profile() {
        let config = AppConfig::load_from_env(|_| None).expect("home profile should load");
        assert_eq!(config.profile, DeploymentProfile::Home);
        assert_eq!(config.server.http_bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(config.server.dns_udp_bind_addr.to_string(), "0.0.0.0:5353");
    }

    #[test]
    fn dev_profile_applies_local_safe_ports() {
        let env = HashMap::from([(String::from("COGWHEEL_PROFILE"), String::from("dev"))]);
        let config =
            AppConfig::load_from_env(|key| env.get(key).cloned()).expect("dev profile should load");
        assert_eq!(config.profile, DeploymentProfile::Dev);
        assert_eq!(config.server.http_bind_addr.to_string(), "127.0.0.1:30080");
        assert_eq!(
            config.server.dns_udp_bind_addr.to_string(),
            "127.0.0.1:30053"
        );
        assert_eq!(config.storage.database_url, "sqlite://data/cogwheel-dev.db");
    }

    #[test]
    fn explicit_env_overrides_profile_defaults() {
        let env = HashMap::from([
            (String::from("COGWHEEL_PROFILE"), String::from("smb")),
            (
                String::from("COGWHEEL_SERVER__HTTP_BIND_ADDR"),
                String::from("127.0.0.1:39090"),
            ),
        ]);
        let config = AppConfig::load_from_env(|key| env.get(key).cloned())
            .expect("smb profile with overrides should load");
        assert_eq!(config.profile, DeploymentProfile::Smb);
        assert_eq!(config.server.http_bind_addr.to_string(), "127.0.0.1:39090");
        assert_eq!(config.server.dns_udp_bind_addr.to_string(), "0.0.0.0:53");
    }

    #[test]
    fn invalid_profile_is_rejected() {
        let env = HashMap::from([(String::from("COGWHEEL_PROFILE"), String::from("invalid"))]);
        let error = AppConfig::load_from_env(|key| env.get(key).cloned())
            .expect_err("invalid profile should fail");
        assert_eq!(error.to_string(), "invalid environment value: invalid");
    }

    #[test]
    fn crate_path_dependencies_match_the_adr_boundaries() {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("workspace root");

        let expected = [
            ("crates/cogwheel-policy/Cargo.toml", &[][..]),
            (
                "crates/cogwheel-dns-core/Cargo.toml",
                &["cogwheel-policy"][..],
            ),
            ("crates/cogwheel-lists/Cargo.toml", &["cogwheel-policy"][..]),
            ("crates/cogwheel-storage/Cargo.toml", &[][..]),
            ("crates/cogwheel-api/Cargo.toml", &[][..]),
        ];

        for (relative_path, allowed) in expected {
            let manifest = fs::read_to_string(workspace_root.join(relative_path))
                .unwrap_or_else(|error| unreachable!("failed to read {relative_path}: {error}"));
            let actual = path_dependencies(&manifest);
            assert_eq!(
                actual, allowed,
                "{relative_path} drifted from ADR 0001 crate boundaries; update the ADR first if this coupling is intentional"
            );
        }
    }

    /// Collect the names of path dependencies declared in a manifest.
    ///
    /// Only dependency tables are considered. Scanning every `path =` line in the file would also
    /// match `[[bin]]`, `[[example]]` and `[[bench]]` targets, which are not couplings between
    /// crates at all — that false positive is what this section tracking exists to avoid.
    fn path_dependencies(manifest: &str) -> Vec<&str> {
        let mut dependencies = Vec::new();
        let mut in_dependency_table = false;

        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                // `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, and the
                // `[target.'cfg(...)'.dependencies]` forms all end in a dependency table name.
                let header = trimmed.trim_start_matches('[').trim_end_matches(']');
                in_dependency_table = header == "dependencies"
                    || header == "dev-dependencies"
                    || header == "build-dependencies"
                    || header.ends_with(".dependencies")
                    || header.ends_with(".dev-dependencies")
                    || header.ends_with(".build-dependencies");
                continue;
            }
            if in_dependency_table && trimmed.contains("path =") {
                if let Some(name) = trimmed.split('=').next() {
                    dependencies.push(name.trim());
                }
            }
        }

        dependencies.sort_unstable();
        dependencies
    }
}
