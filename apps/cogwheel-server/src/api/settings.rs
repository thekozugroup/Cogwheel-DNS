//! The read-only configuration dump (§3 route 22).
//!
//! Configuration is environment-only by design, so this route exists to answer "what is this box
//! actually running with" without an SSH session — including the two numbers that are otherwise
//! invisible, the database size and the protected-suffix list the evaluator enforces.

use crate::http::{ApiResult, ok};
use crate::state::ServerState;
use axum::extract::State;
use cogwheel_dns_core::{UpstreamEndpoint, UpstreamProtocol};
use cogwheel_policy::PROTECTED_SUFFIXES;
use serde::Serialize;

/// One configured upstream, as parsed.
#[derive(Debug, Clone, Serialize)]
pub struct Upstream {
    /// The specification as configured.
    pub spec: String,
    pub protocol: UpstreamProtocol,
    /// Whether queries to it are hidden from the local network.
    pub encrypted: bool,
}

/// Retention, as configured (§8).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Retention {
    pub history_days: u32,
    pub max_rows: u64,
    pub prune_interval_secs: u64,
}

/// Everything §3 route 22 reports.
#[derive(Debug, Clone, Serialize)]
pub struct Settings {
    pub version: &'static str,
    pub upstreams: Vec<Upstream>,
    pub block_mode: &'static str,
    pub http_bind: String,
    pub dns_udp_bind: String,
    pub dns_tcp_bind: String,
    pub advertised_targets: Vec<String>,
    pub advertised_port: u16,
    pub refresh_interval_secs: u64,
    pub retention: Retention,
    pub db_path: String,
    pub db_size_bytes: i64,
    pub lists_dir: String,
    pub protected_suffixes: Vec<&'static str>,
    pub schema_version: i64,
}

/// Route 22: the configuration this process is running with.
pub async fn settings(State(state): State<ServerState>) -> ApiResult<Settings> {
    let config = &state.config;
    let upstreams = config
        .upstream_servers
        .iter()
        .map(|spec| {
            // Every spec was parsed at startup, so this cannot fail; falling back to plain UDP
            // rather than erroring keeps a settings page from being the thing that breaks.
            let protocol = UpstreamEndpoint::parse(spec)
                .map_or(UpstreamProtocol::Udp, |endpoint| endpoint.protocol);
            Upstream {
                spec: spec.clone(),
                protocol,
                encrypted: protocol.is_encrypted(),
            }
        })
        .collect();

    ok(Settings {
        version: env!("CARGO_PKG_VERSION"),
        upstreams,
        block_mode: config.block_mode.as_str(),
        http_bind: config.http_bind_addr.to_string(),
        dns_udp_bind: config.dns_udp_bind_addr.to_string(),
        dns_tcp_bind: config.dns_tcp_bind_addr.to_string(),
        advertised_targets: config.advertised_dns_targets.clone(),
        advertised_port: config.advertised_dns_port,
        refresh_interval_secs: config.refresh_interval_secs,
        retention: Retention {
            history_days: config.history_days,
            max_rows: config.max_rows,
            prune_interval_secs: config.prune_interval_secs,
        },
        db_path: config.database_path().display().to_string(),
        db_size_bytes: state.storage.database_size_bytes().await?,
        lists_dir: state.lists_dir.display().to_string(),
        protected_suffixes: PROTECTED_SUFFIXES.to_vec(),
        schema_version: cogwheel_storage::SCHEMA_VERSION,
    })
}
