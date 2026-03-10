use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
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
            bind_addr: "0.0.0.0:8080".parse().expect("valid default addr"),
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
            http_bind_addr: "0.0.0.0:8080".parse().expect("valid default addr"),
            dns_udp_bind_addr: "0.0.0.0:5353".parse().expect("valid default addr"),
            dns_tcp_bind_addr: "0.0.0.0:5353".parse().expect("valid default addr"),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeGuardConfig {
    pub probe_domains: Vec<String>,
    pub max_upstream_failures_delta: u64,
    pub max_fallback_served_delta: u64,
}

impl Default for RuntimeGuardConfig {
    fn default() -> Self {
        Self {
            probe_domains: vec![
                "example.com".to_string(),
                "connectivitycheck.gstatic.com".to_string(),
            ],
            max_upstream_failures_delta: 0,
            max_fallback_served_delta: 0,
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
    pub runtime_guard: RuntimeGuardConfig,
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
        if let Some(value) = env_get("COGWHEEL_RUNTIME_GUARD__PROBE_DOMAINS") {
            config.runtime_guard.probe_domains = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect();
        }
        if let Some(value) = env_get("COGWHEEL_RUNTIME_GUARD__MAX_UPSTREAM_FAILURES_DELTA") {
            config.runtime_guard.max_upstream_failures_delta = value
                .parse::<u64>()
                .map_err(|_| ApiError::InvalidEnv(value.clone()))?;
        }
        if let Some(value) = env_get("COGWHEEL_RUNTIME_GUARD__MAX_FALLBACK_SERVED_DELTA") {
            config.runtime_guard.max_fallback_served_delta = value
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
                    "127.0.0.1:30080".parse().expect("valid dev http bind addr");
                config.server.dns_udp_bind_addr = "127.0.0.1:30053"
                    .parse()
                    .expect("valid dev dns udp bind addr");
                config.server.dns_tcp_bind_addr = "127.0.0.1:30053"
                    .parse()
                    .expect("valid dev dns tcp bind addr");
                config.storage.database_url = "sqlite://data/cogwheel-dev.db".to_string();
                config.updater.refresh_interval_secs = 120;
                config.runtime_guard.max_upstream_failures_delta = 2;
                config.runtime_guard.max_fallback_served_delta = 5;
            }
            DeploymentProfile::Home => {
                config.server.http_bind_addr =
                    "0.0.0.0:8080".parse().expect("valid home http bind addr");
                config.server.dns_udp_bind_addr = "0.0.0.0:5353"
                    .parse()
                    .expect("valid home dns udp bind addr");
                config.server.dns_tcp_bind_addr = "0.0.0.0:5353"
                    .parse()
                    .expect("valid home dns tcp bind addr");
                config.storage.database_url = "sqlite://data/cogwheel.db".to_string();
                config.updater.refresh_interval_secs = 300;
            }
            DeploymentProfile::Smb => {
                config.server.http_bind_addr =
                    "0.0.0.0:8080".parse().expect("valid smb http bind addr");
                config.server.dns_udp_bind_addr =
                    "0.0.0.0:53".parse().expect("valid smb dns udp bind addr");
                config.server.dns_tcp_bind_addr =
                    "0.0.0.0:53".parse().expect("valid smb dns tcp bind addr");
                config.storage.database_url = "sqlite://data/cogwheel-smb.db".to_string();
                config.updater.refresh_interval_secs = 600;
                config.runtime_guard.max_upstream_failures_delta = 1;
                config.runtime_guard.max_fallback_served_delta = 2;
            }
        }

        config
    }
}

#[derive(Debug, Clone)]
pub struct ApiState {
    pub registry: Arc<Registry>,
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
    #[error("internal server error")]
    Internal,
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
        .route("/health/check", post(live))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn live() -> Json<ApiEnvelope<HealthResponse>> {
    Json(ApiEnvelope {
        data: HealthResponse { status: "ok" },
    })
}

async fn ready() -> Json<ApiEnvelope<HealthResponse>> {
    Json(ApiEnvelope {
        data: HealthResponse { status: "ready" },
    })
}

async fn metrics(State(state): State<ApiState>) -> Result<Response, ApiError> {
    let mut output = String::new();
    encode(&mut output, &state.registry).map_err(|_| ApiError::Internal)?;
    Ok((StatusCode::OK, output).into_response())
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, DeploymentProfile};
    use std::collections::HashMap;

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
}
