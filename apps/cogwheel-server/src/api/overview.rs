//! The Overview page's single call (§3 route 3).
//!
//! Polled every five seconds by every open tab, so nothing here may scan the query log: the
//! 24-hour figures come from the hourly rollups, and the two top-ten tables — the only reads that
//! do touch the log — are memoized for a minute and shared by every caller.

use crate::api::runtime::paused_until;
use crate::http::{ApiResult, ok};
use crate::state::{ServerState, now_secs};
use axum::extract::State;
use cogwheel_storage::{DomainCount, HourBucket};
use serde::Serialize;
use std::net::Ipv4Addr;

/// Rows in each top-domain table.
const TOP_DOMAINS: u32 = 10;

/// The window every figure on the page covers.
const DAY_SECS: i64 = 86_400;

/// Whether protection is on.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Protection {
    pub paused_until: Option<i64>,
}

/// The lifetime counters the runtime keeps (§5.1).
///
/// A subset of the runtime's snapshot: the sample counts behind the two averages are debugging
/// detail, and putting them on a page that polls every five seconds would invite someone to
/// build a dashboard on them.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuntimeCounters {
    pub queries_total: u64,
    pub blocked_total: u64,
    pub cache_hits_total: u64,
    pub cache_expired_total: u64,
    pub stale_served_total: u64,
    pub upstream_failures_total: u64,
    pub cname_blocks_total: u64,
    /// Misses refused because the runtime was saturated; answered SERVFAIL.
    pub dropped_total: u64,
    /// Answered queries whose log entry was dropped because the writer was behind.
    pub log_dropped_total: u64,
    pub cache_hit_latency_avg_ns: u64,
    pub cache_miss_latency_avg_ns: u64,
}

/// The last 24 hours, entirely from the rollups.
#[derive(Debug, Clone, Serialize)]
pub struct Last24h {
    pub queries: i64,
    pub blocked: i64,
    /// Exactly 24 buckets, oldest first, zero-filled.
    pub per_hour: Vec<HourBucket>,
    pub active_clients: usize,
    pub named_devices: usize,
    pub unnamed_clients: usize,
}

/// What the subscribed lists add up to.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Lists {
    pub enabled: usize,
    pub total: usize,
    /// Distinct names in the compiled index.
    pub rules_loaded: usize,
    pub last_ok_at: Option<i64>,
    /// False until at least one list body has been fetched or found in the cache.
    pub downloaded: bool,
}

/// Where to point a router.
#[derive(Debug, Clone, Serialize)]
pub struct Connect {
    pub targets: Vec<String>,
    pub port: u16,
}

/// Everything the Overview draws.
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub protection: Protection,
    pub runtime: RuntimeCounters,
    pub last_24h: Last24h,
    pub lists: Lists,
    pub top_blocked: Vec<DomainCount>,
    pub top_queried: Vec<DomainCount>,
    pub connect: Connect,
}

/// Route 3: the whole Overview in one call.
pub async fn overview(State(state): State<ServerState>) -> ApiResult<Overview> {
    let now = now_secs();
    let snapshot = state.runtime.snapshot();
    let policy = state.runtime.current_policy();

    let per_hour = state.storage.hourly_24h(now).await?;
    let clients = state.storage.per_client_24h(now).await?;
    let unnamed = state.storage.unnamed_clients_24h(now).await?;
    let sources = state.storage.list_sources().await?;
    let (top_blocked, top_queried) = top_domains(&state, now).await?;

    ok(Overview {
        protection: Protection {
            paused_until: paused_until(&state),
        },
        runtime: RuntimeCounters {
            queries_total: snapshot.queries_total,
            blocked_total: snapshot.blocked_total,
            cache_hits_total: snapshot.cache_hits_total,
            cache_expired_total: snapshot.cache_expired_total,
            stale_served_total: snapshot.stale_served_total,
            upstream_failures_total: snapshot.upstream_failures_total,
            cname_blocks_total: snapshot.cname_blocks_total,
            dropped_total: snapshot.dropped_total,
            log_dropped_total: snapshot.log_dropped_total,
            cache_hit_latency_avg_ns: snapshot.cache_hit_latency_avg_ns,
            cache_miss_latency_avg_ns: snapshot.cache_miss_latency_avg_ns,
        },
        last_24h: Last24h {
            queries: per_hour.iter().map(|bucket| bucket.queries).sum(),
            blocked: per_hour.iter().map(|bucket| bucket.blocked).sum(),
            per_hour,
            active_clients: clients.len(),
            named_devices: clients.len().saturating_sub(unnamed.len()),
            unnamed_clients: unnamed.len(),
        },
        lists: Lists {
            enabled: sources.iter().filter(|source| source.enabled).count(),
            total: sources.len(),
            rules_loaded: policy.index.len(),
            last_ok_at: sources.iter().filter_map(|source| source.last_ok_at).max(),
            downloaded: sources.iter().any(|source| source.last_ok_at.is_some()),
        },
        top_blocked,
        top_queried,
        connect: Connect {
            targets: connect_targets(&state).await,
            port: state.config.advertised_dns_port,
        },
    })
}

/// The two top-ten tables, scanned at most once a minute however many tabs are open.
async fn top_domains(
    state: &ServerState,
    now: i64,
) -> Result<(Vec<DomainCount>, Vec<DomainCount>), crate::http::ApiError> {
    if let Some(memoized) = state.top_domains.get() {
        return Ok(memoized);
    }
    let since = now - DAY_SECS;
    let blocked = state.storage.top_domains(true, since, TOP_DOMAINS).await?;
    let queried = state.storage.top_domains(false, since, TOP_DOMAINS).await?;
    let fresh = (blocked, queried);
    state.top_domains.set(fresh.clone());
    Ok(fresh)
}

/// The addresses to type into a router's DNS field.
///
/// Configured targets win: an installer that knows the appliance's reserved address has better
/// information than this process does. Otherwise the host is asked, which is the one shell-out
/// left in the server — enumerating interfaces properly needs a netlink parser, and `hostname -I`
/// is present on every image this ships on and prints exactly the list a person would copy.
async fn connect_targets(state: &ServerState) -> Vec<String> {
    if !state.config.advertised_dns_targets.is_empty() {
        return state.config.advertised_dns_targets.clone();
    }
    if let Some(memoized) = state.connect_targets.get() {
        return memoized;
    }
    let mut targets = host_addresses().await;
    if targets.is_empty() {
        let bound = state.config.dns_udp_bind_addr.ip();
        targets.push(if bound.is_unspecified() {
            "127.0.0.1".to_owned()
        } else {
            bound.to_string()
        });
    }
    state.connect_targets.set(targets.clone());
    targets
}

/// Every IPv4 address the host answers on, from `hostname -I`.
async fn host_addresses() -> Vec<String> {
    let Ok(output) = tokio::process::Command::new("hostname")
        .arg("-I")
        .output()
        .await
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|value| value.parse::<Ipv4Addr>().ok())
        .filter(|address| !is_docker_bridge(*address))
        .map(|address| address.to_string())
        .collect()
}

/// Whether this is the address of Docker's own default bridge.
///
/// That address is on `hostname -I` inside the container and is reachable from nothing a
/// household owns, so advertising it sends people to an address that times out. Matched as
/// 172.17.0.0/16 and not as the text prefix `172.`, which is the whole of 172.16.0.0/12: plenty
/// of prosumer and small-business routers hand out 172.16–172.31 addresses, and an appliance on
/// one of those would have advertised nothing at all and fallen back to its bind address — which
/// on the `home` profile is 0.0.0.0.
fn is_docker_bridge(address: Ipv4Addr) -> bool {
    let [a, b, ..] = address.octets();
    a == 172 && b == 17
}
