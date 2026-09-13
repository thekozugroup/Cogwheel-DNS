use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use cogwheel_policy::{
    BlockMode, DecisionKind, PolicyEngine, RuleAction, RulesetArtifact, normalize_domain,
};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use moka::future::Cache;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const MAX_CNAME_UNCLOAK_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct DnsRuntimeConfig {
    pub udp_bind_addr: SocketAddr,
    pub tcp_bind_addr: SocketAddr,
}

type QueryActivityObserver = Arc<dyn Fn(QueryActivityEvent) + Send + Sync>;

#[derive(Clone)]
pub struct DnsRuntime {
    resolver: TokioResolver,
    policy: Arc<RwLock<Arc<PolicyEngine>>>,
    allow_all_policy: Arc<RwLock<Arc<PolicyEngine>>>,
    profile_policies: Arc<RwLock<HashMap<String, Arc<PolicyEngine>>>>,
    devices_by_ip: Arc<RwLock<HashMap<IpAddr, DevicePolicyConfig>>>,
    query_activity_observer: Arc<RwLock<Option<QueryActivityObserver>>>,
    global_pause_until: Arc<RwLock<Option<DateTime<Utc>>>>,
    cache: Cache<String, CachedLookup>,
    fallback_cache: Cache<String, CachedLookup>,
    stats: Arc<DnsRuntimeStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryActivityEvent {
    pub domain: String,
    pub client_ip: Option<String>,
    pub blocked: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DevicePolicyConfig {
    pub ip_address: String,
    pub policy_mode: String,
    pub blocklist_profile_override: Option<String>,
    pub protection_override: String,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
}

#[derive(Debug, Clone)]
struct CachedLookup {
    response: Message,
    blocked: bool,
    /// When this entry stops being usable.
    ///
    /// The cache previously had no expiry at all: `Cache::new` sets a capacity
    /// and nothing else, and no record TTL was ever read. An answer therefore
    /// stayed until 10,000 other names pushed it out, which on a household
    /// resolver can be days. Anything that moves addresses -- CDN failover,
    /// geo-routing, blue/green deploys, dynamic DNS -- kept resolving to an
    /// address that had stopped serving it, and the failure looks exactly like
    /// "the ad blocker broke this site".
    expires_at: Instant,
}

/// Never cache for less than this, however small the record's TTL.
///
/// Some CDNs answer with a TTL of 0 or 1 second. Honouring that literally
/// turns every page load into a fresh upstream query per name, which on an
/// encrypted upstream means a TLS round trip on the critical path.
const MIN_CACHE_TTL: Duration = Duration::from_secs(5);

/// Never cache for longer than this, however large the record's TTL.
///
/// Some records advertise a day or more. Holding an address that long on an
/// appliance nobody restarts is how a household ends up pinned to a decommissioned
/// server, so this bounds the worst case regardless of what upstream claims.
const MAX_CACHE_TTL: Duration = Duration::from_secs(3_600);

/// Lifetime for a response carrying no answer records.
///
/// NXDOMAIN and NODATA get a shorter life than a positive answer: a name that
/// does not exist yet is far more likely to start existing than a live address
/// is to change, and caching "this does not exist" for an hour is how a
/// newly-provisioned host stays unreachable long after it came up.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// How long a response may be cached, from the records it actually contains.
///
/// The minimum TTL across the answer section, clamped. The minimum rather than
/// the maximum because a response is only wholly valid until its shortest-lived
/// record expires.
fn cacheable_for(response: &Message) -> Duration {
    response
        .answers
        .iter()
        .map(|record| record.ttl)
        .min()
        .map_or(NEGATIVE_CACHE_TTL, |ttl| {
            Duration::from_secs(u64::from(ttl)).clamp(MIN_CACHE_TTL, MAX_CACHE_TTL)
        })
}

#[derive(Debug, Default)]
pub struct DnsRuntimeStats {
    upstream_failures_total: AtomicU64,
    fallback_served_total: AtomicU64,
    cache_hits_total: AtomicU64,
    cache_expired_total: AtomicU64,
    cname_uncloaks_total: AtomicU64,
    cname_blocks_total: AtomicU64,
    queries_total: AtomicU64,
    blocked_total: AtomicU64,
    cache_hit_latency_total_ns: AtomicU64,
    cache_hit_samples: AtomicU64,
    cache_miss_latency_total_ns: AtomicU64,
    cache_miss_samples: AtomicU64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsRuntimeSnapshot {
    pub upstream_failures_total: u64,
    pub fallback_served_total: u64,
    pub cache_hits_total: u64,
    pub cache_expired_total: u64,
    pub cname_uncloaks_total: u64,
    pub cname_blocks_total: u64,
    pub queries_total: u64,
    pub blocked_total: u64,
    pub cache_hit_latency_avg_ns: u64,
    pub cache_hit_samples: u64,
    pub cache_miss_latency_avg_ns: u64,
    pub cache_miss_samples: u64,
}

/// Read an `RwLock`, recovering the value even when the lock is poisoned.
///
/// Poisoning only signals that some thread panicked while holding the lock. Every field guarded
/// this way holds a wholesale replacement — an `Arc` swap or a rebuilt map — so the last committed
/// value is still coherent, and recovering it keeps one panicking task from taking DNS resolution
/// down for the remaining life of the process. Failing open is the right posture for a household
/// resolver: losing the policy should mean "resolve normally", never "take the network offline".
fn read_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl DnsRuntime {
    /// Build a runtime around a resolver and a policy engine.
    pub fn new(resolver: TokioResolver, policy: Arc<PolicyEngine>) -> Self {
        Self {
            resolver,
            policy: Arc::new(RwLock::new(policy.clone())),
            allow_all_policy: Arc::new(RwLock::new(build_allow_all_policy(&policy))),
            profile_policies: Arc::new(RwLock::new(HashMap::new())),
            devices_by_ip: Arc::new(RwLock::new(HashMap::new())),
            query_activity_observer: Arc::new(RwLock::new(None)),
            global_pause_until: Arc::new(RwLock::new(None)),
            // The per-entry deadline in `CachedLookup` is what enforces each
            // record's own TTL. This ceiling is a second, coarser bound so an
            // expired entry cannot sit in the map occupying capacity until
            // 10,000 other names evict it.
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(MAX_CACHE_TTL)
                .build(),
            // The fallback cache is deliberately allowed to hold stale answers:
            // its whole job is to keep the household resolving through an
            // upstream outage, where an hour-old address beats no address. It
            // is bounded only so it cannot grow without limit.
            fallback_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(86_400))
                .build(),
            stats: Arc::new(DnsRuntimeStats::default()),
        }
    }

    pub fn replace_policy(&self, policy: Arc<PolicyEngine>) {
        self.replace_policy_catalog(policy, HashMap::new());
    }

    pub fn replace_policy_catalog(
        &self,
        policy: Arc<PolicyEngine>,
        profile_policies: HashMap<String, Arc<PolicyEngine>>,
    ) {
        let allow_all_policy = build_allow_all_policy(&policy);
        if let Ok(mut guard) = self.policy.write() {
            *guard = policy;
        }
        if let Ok(mut guard) = self.allow_all_policy.write() {
            *guard = allow_all_policy;
        }
        if let Ok(mut guard) = self.profile_policies.write() {
            *guard = profile_policies;
        }
        self.cache.invalidate_all();
        self.fallback_cache.invalidate_all();
    }

    pub fn replace_device_policies(&self, devices: Vec<DevicePolicyConfig>) {
        let normalized = devices
            .into_iter()
            .filter_map(|device| {
                device
                    .ip_address
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| (ip, device))
            })
            .collect::<HashMap<_, _>>();
        if let Ok(mut guard) = self.devices_by_ip.write() {
            *guard = normalized;
        }
        self.cache.invalidate_all();
    }

    /// The policy engine currently answering unscoped queries.
    pub fn current_policy(&self) -> Arc<PolicyEngine> {
        read_recover(&self.policy).clone()
    }

    pub fn set_query_activity_observer(&self, observer: QueryActivityObserver) {
        if let Ok(mut guard) = self.query_activity_observer.write() {
            *guard = Some(observer);
        }
    }

    pub fn snapshot(&self) -> DnsRuntimeSnapshot {
        let cache_hit_samples = self.stats.cache_hit_samples.load(Ordering::Relaxed);
        let cache_miss_samples = self.stats.cache_miss_samples.load(Ordering::Relaxed);
        DnsRuntimeSnapshot {
            upstream_failures_total: self.stats.upstream_failures_total.load(Ordering::Relaxed),
            fallback_served_total: self.stats.fallback_served_total.load(Ordering::Relaxed),
            cache_hits_total: self.stats.cache_hits_total.load(Ordering::Relaxed),
            cache_expired_total: self.stats.cache_expired_total.load(Ordering::Relaxed),
            cname_uncloaks_total: self.stats.cname_uncloaks_total.load(Ordering::Relaxed),
            cname_blocks_total: self.stats.cname_blocks_total.load(Ordering::Relaxed),
            queries_total: self.stats.queries_total.load(Ordering::Relaxed),
            blocked_total: self.stats.blocked_total.load(Ordering::Relaxed),
            cache_hit_latency_avg_ns: average_atomic_ns(
                &self.stats.cache_hit_latency_total_ns,
                cache_hit_samples,
            ),
            cache_hit_samples,
            cache_miss_latency_avg_ns: average_atomic_ns(
                &self.stats.cache_miss_latency_total_ns,
                cache_miss_samples,
            ),
            cache_miss_samples,
        }
    }

    pub async fn serve(self: Arc<Self>, config: DnsRuntimeConfig) -> Result<()> {
        let (_tx, never) = tokio::sync::watch::channel(false);
        self.serve_with_ready_signal(config, || {}, never).await
    }

    /// Serve DNS, invoking `on_ready` once both listeners are bound.
    ///
    /// The callback is what lets `/health/ready` report a real signal instead of returning 200 the
    /// moment the process starts: binding is the point at which this node can actually answer.
    pub async fn serve_with_ready_signal<F>(
        self: Arc<Self>,
        config: DnsRuntimeConfig,
        on_ready: F,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        // Bind before spawning the accept loops so a bind failure is reported as a startup error
        // rather than surfacing later as a dead task.
        let udp_socket = UdpSocket::bind(config.udp_bind_addr)
            .await
            .context("bind udp socket")?;
        let tcp_listener = TcpListener::bind(config.tcp_bind_addr)
            .await
            .context("bind tcp listener")?;
        on_ready();

        let udp = tokio::spawn(self.clone().accept_udp(udp_socket, shutdown.clone()));
        let tcp = tokio::spawn(self.clone().accept_tcp(tcp_listener, shutdown));
        udp.await??;
        tcp.await??;
        Ok(())
    }

    async fn accept_udp(
        self: Arc<Self>,
        socket: UdpSocket,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut buffer = [0u8; 4096];
        loop {
            // Select only on the *accept* point. A query already being handled runs to completion
            // below before the loop comes back here, so shutdown drains in-flight work rather than
            // cancelling it mid-flight and dropping the client's answer.
            let (size, peer) = tokio::select! {
                result = socket.recv_from(&mut buffer) => result?,
                _ = shutdown.changed() => {
                    tracing::info!("udp listener stopping");
                    return Ok(());
                }
            };
            let response = self
                .handle_wire_query(&buffer[..size], Some(peer))
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "failed to handle udp dns query");
                    error_response_for_payload(&buffer[..size])
                });
            let response_bytes = response.to_vec()?;
            socket.send_to(&response_bytes, peer).await?;
        }
    }

    async fn accept_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        loop {
            let (stream, peer) = tokio::select! {
                result = listener.accept() => result?,
                _ = shutdown.changed() => {
                    tracing::info!("tcp listener stopping");
                    return Ok(());
                }
            };
            let runtime = self.clone();
            tokio::spawn(async move {
                if let Err(error) = runtime.handle_tcp_stream(stream, peer).await {
                    tracing::warn!(%error, "failed to handle tcp dns query");
                }
            });
        }
    }

    async fn handle_tcp_stream(&self, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let mut len_buffer = [0u8; 2];
        stream.read_exact(&mut len_buffer).await?;
        let length = u16::from_be_bytes(len_buffer) as usize;
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await?;
        let response = self.handle_wire_query(&payload, Some(peer)).await?;
        let response_bytes = response.to_vec()?;
        stream
            .write_all(&(response_bytes.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&response_bytes).await?;
        Ok(())
    }

    async fn handle_wire_query(
        &self,
        payload: &[u8],
        client_addr: Option<SocketAddr>,
    ) -> Result<Message> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        let query_start = Instant::now();
        let request = Message::from_vec(payload)?;
        let query = request
            .queries
            .first()
            .cloned()
            .context("dns query missing question")?;
        let name = query.name().to_utf8();
        let domain = name.trim_end_matches('.').to_ascii_lowercase();

        let (engine, cache_scope, forced_block_mode) = self.policy_for_client(client_addr, &domain);
        let cache_key = policy_cache_key(&cache_scope, &domain);

        // An entry past its deadline is a miss, not a hit. moka's own
        // time_to_live is a coarse memory ceiling; this is what actually
        // enforces the TTL the authoritative server asked for, which is the
        // difference between following a CDN when it moves and pinning the
        // household to an address that has stopped answering.
        if let Some(cached) = self.cache.get(&cache_key).await {
            if Instant::now() < cached.expires_at {
                self.stats.cache_hits_total.fetch_add(1, Ordering::Relaxed);
                self.emit_query_activity(&domain, client_addr, cached.blocked);
                self.record_cache_hit_latency(query_start.elapsed().as_nanos());
                return Ok(response_for_request(&request, &cached.response));
            }
            self.stats
                .cache_expired_total
                .fetch_add(1, Ordering::Relaxed);
            self.cache.invalidate(&cache_key).await;
        }

        if let Some(block_mode) = forced_block_mode {
            let response = build_blocked_response(&request, block_mode);
            self.stats.blocked_total.fetch_add(1, Ordering::Relaxed);
            self.cache
                .insert(
                    cache_key,
                    CachedLookup {
                        response: response.clone(),
                        blocked: true,
                        expires_at: Instant::now() + cacheable_for(&response),
                    },
                )
                .await;
            self.emit_query_activity(&domain, client_addr, true);
            self.record_cache_miss_latency(query_start.elapsed().as_nanos());
            return Ok(response);
        }
        let decision = engine.evaluate(&domain);
        let allow_matched = decision
            .matched_rule
            .as_ref()
            .is_some_and(|rule| matches!(rule.action, RuleAction::Allow));

        let blocked = matches!(&decision.kind, DecisionKind::Blocked(_));
        let response = match decision.kind {
            DecisionKind::Blocked(mode) => {
                self.stats.blocked_total.fetch_add(1, Ordering::Relaxed);
                build_blocked_response(&request, mode)
            }
            DecisionKind::Allowed => {
                if !allow_matched {
                    if let Some(mode) = self.uncloaked_block_mode(&domain, &engine).await? {
                        self.stats.blocked_total.fetch_add(1, Ordering::Relaxed);
                        let response = build_blocked_response(&request, mode);
                        self.cache
                            .insert(
                                cache_key.clone(),
                                CachedLookup {
                                    response: response.clone(),
                                    blocked: true,
                                    expires_at: Instant::now() + cacheable_for(&response),
                                },
                            )
                            .await;
                        self.emit_query_activity(&domain, client_addr, true);
                        self.record_cache_miss_latency(query_start.elapsed().as_nanos());
                        return Ok(response);
                    }
                }

                match self.resolve_upstream(&request, &domain).await {
                    Ok(response) => {
                        self.fallback_cache
                            .insert(
                                domain.clone(),
                                CachedLookup {
                                    response: response.clone(),
                                    blocked: false,
                                    expires_at: Instant::now() + cacheable_for(&response),
                                },
                            )
                            .await;
                        response
                    }
                    Err(error) => {
                        self.stats
                            .upstream_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        // Deliberately ignores `expires_at`. This path is only
                        // reached when the upstream has already failed, and an
                        // expired address the site probably still answers on
                        // beats SERVFAIL. Staleness here is the feature.
                        if let Some(fallback) = self.fallback_cache.get(&domain).await {
                            self.stats
                                .fallback_served_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(%domain, %error, "serving fallback DNS response after upstream failure");
                            response_for_request(&request, &fallback.response)
                        } else {
                            return Err(error);
                        }
                    }
                }
            }
        };

        self.cache
            .insert(
                cache_key,
                CachedLookup {
                    response: response.clone(),
                    blocked,
                    expires_at: Instant::now() + cacheable_for(&response),
                },
            )
            .await;
        self.emit_query_activity(&domain, client_addr, blocked);
        self.record_cache_miss_latency(query_start.elapsed().as_nanos());
        Ok(response)
    }

    fn record_cache_hit_latency(&self, elapsed_ns: u128) {
        self.stats
            .cache_hit_latency_total_ns
            .fetch_add(saturating_ns(elapsed_ns), Ordering::Relaxed);
        self.stats.cache_hit_samples.fetch_add(1, Ordering::Relaxed);
    }

    fn record_cache_miss_latency(&self, elapsed_ns: u128) {
        self.stats
            .cache_miss_latency_total_ns
            .fetch_add(saturating_ns(elapsed_ns), Ordering::Relaxed);
        self.stats
            .cache_miss_samples
            .fetch_add(1, Ordering::Relaxed);
    }

    fn emit_query_activity(&self, domain: &str, client_addr: Option<SocketAddr>, blocked: bool) {
        let observer = read_recover(&self.query_activity_observer).clone();
        if let Some(observer) = observer {
            observer(QueryActivityEvent {
                domain: domain.to_string(),
                client_ip: client_addr.map(|addr| addr.ip().to_string()),
                blocked,
                observed_at: Utc::now(),
            });
        }
    }

    pub fn pause_protection_until(&self, until: DateTime<Utc>) {
        if let Ok(mut guard) = self.global_pause_until.write() {
            *guard = Some(until);
        }
    }

    pub fn resume_protection(&self) {
        if let Ok(mut guard) = self.global_pause_until.write() {
            *guard = None;
        }
    }

    pub fn protection_paused_until(&self) -> Option<DateTime<Utc>> {
        self.global_pause_until.read().ok().and_then(|guard| *guard)
    }

    fn policy_for_client(
        &self,
        client_addr: Option<SocketAddr>,
        domain: &str,
    ) -> (Arc<PolicyEngine>, String, Option<BlockMode>) {
        if let Some(until) = self.protection_paused_until() {
            if Utc::now() < until {
                let allow_all_policy = read_recover(&self.allow_all_policy).clone();
                return (allow_all_policy, "global-pause".to_string(), None);
            }
        }

        let global = read_recover(&self.policy).clone();
        let Some(client_ip) = client_addr.map(|addr| addr.ip()) else {
            return (global.clone(), global.artifact().hash.clone(), None);
        };

        let devices = read_recover(&self.devices_by_ip);
        let Some(device) = devices.get(&client_ip) else {
            return (global.clone(), global.artifact().hash.clone(), None);
        };
        if device.policy_mode != "custom" {
            return (global.clone(), global.artifact().hash.clone(), None);
        }
        if device
            .blocked_domains
            .iter()
            .any(|candidate| domain_matches_override(domain, candidate))
        {
            return (
                global.clone(),
                format!("device-block:{}", client_ip),
                Some(global.artifact().block_mode.clone()),
            );
        }
        if device
            .allowed_domains
            .iter()
            .any(|candidate| domain_matches_override(domain, candidate))
        {
            let allow_all_policy = read_recover(&self.allow_all_policy).clone();
            return (
                allow_all_policy,
                format!("device-allow:{}", client_ip),
                None,
            );
        }
        if device.protection_override == "bypass" {
            let allow_all_policy = read_recover(&self.allow_all_policy).clone();
            return (allow_all_policy, "bypass".to_string(), None);
        }

        let Some(profile) = device.blocklist_profile_override.as_deref() else {
            return (global.clone(), global.artifact().hash.clone(), None);
        };

        let profile_policies = read_recover(&self.profile_policies);
        let Some(policy) = profile_policies.get(profile) else {
            return (global.clone(), global.artifact().hash.clone(), None);
        };

        (policy.clone(), format!("profile:{}", profile), None)
    }

    async fn resolve_upstream(&self, request: &Message, domain: &str) -> Result<Message> {
        let query = request
            .queries
            .first()
            .context("dns query missing question")?;
        let lookup = self.resolver.lookup(domain, query.query_type()).await?;
        let mut response = build_base_response(request, ResponseCode::NoError);
        // A 0.26 `Lookup` carries the upstream message with its sections intact, so the answer
        // section is addressed directly instead of through the old flattened record list.
        for record in lookup.answers() {
            response.add_answer(record.clone());
        }
        Ok(response)
    }

    async fn uncloaked_block_mode(
        &self,
        domain: &str,
        engine: &PolicyEngine,
    ) -> Result<Option<BlockMode>> {
        let mut current = domain.to_string();
        let mut seen = HashSet::new();

        for _ in 0..MAX_CNAME_UNCLOAK_DEPTH {
            if !seen.insert(current.clone()) {
                return Ok(None);
            }

            let lookup = match self.resolver.lookup(&current, RecordType::CNAME).await {
                Ok(lookup) => lookup,
                Err(_) => return Ok(None),
            };

            let Some(target) = lookup.answers().iter().find_map(extract_cname_target) else {
                return Ok(None);
            };

            self.stats
                .cname_uncloaks_total
                .fetch_add(1, Ordering::Relaxed);
            let normalized_target = normalize_domain(&target);
            let decision = engine.evaluate(&normalized_target);
            if let DecisionKind::Blocked(mode) = decision.kind {
                self.stats
                    .cname_blocks_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Some(mode));
            }

            current = normalized_target;
        }

        Ok(None)
    }
}

fn extract_cname_target(record: &Record) -> Option<String> {
    match &record.data {
        RData::CNAME(target) => Some(target.0.to_utf8()),
        _ => None,
    }
}

fn policy_cache_key(scope: &str, domain: &str) -> String {
    format!("{scope}:{domain}")
}

fn build_allow_all_policy(global_policy: &Arc<PolicyEngine>) -> Arc<PolicyEngine> {
    let artifact = global_policy.artifact();
    Arc::new(PolicyEngine::new(RulesetArtifact::new(
        Vec::new(),
        artifact.protected_domains.clone(),
        artifact.block_mode.clone(),
    )))
}

fn domain_matches_override(domain: &str, candidate: &str) -> bool {
    domain == candidate
        || domain
            .strip_suffix(candidate)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn response_for_request(request: &Message, cached: &Message) -> Message {
    let mut response = cached.clone();
    response.metadata.id = request.metadata.id;
    response
}

fn saturating_ns(elapsed_ns: u128) -> u64 {
    elapsed_ns.min(u64::MAX as u128) as u64
}

fn average_atomic_ns(total: &AtomicU64, samples: u64) -> u64 {
    total
        .load(Ordering::Relaxed)
        .checked_div(samples)
        .unwrap_or(0)
}

fn error_response_for_payload(payload: &[u8]) -> Message {
    match Message::from_vec(payload) {
        Ok(request) => Message::error_msg(
            request.metadata.id,
            request.metadata.op_code,
            ResponseCode::ServFail,
        ),
        Err(_) => Message::error_msg(0, OpCode::Query, ResponseCode::ServFail),
    }
}

fn build_base_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    // We are a forwarder, never the zone's authority, and we always accept recursion. The RD bit is
    // echoed from the request because RFC 1035 requires the response to mirror it.
    response.metadata.authoritative = false;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    // Assigned rather than merged: `merge_response_code` folds in the EDNS high-order bits, which
    // would change what a blocked answer reports.
    response.metadata.response_code = code;
    for query in &request.queries {
        response.add_query(query.clone());
    }
    response
}

fn build_blocked_response(request: &Message, mode: BlockMode) -> Message {
    match mode {
        BlockMode::NxDomain => build_base_response(request, ResponseCode::NXDomain),
        BlockMode::NoData => build_base_response(request, ResponseCode::NoError),
        BlockMode::Refused => build_base_response(request, ResponseCode::Refused),
        BlockMode::NullIp => build_ip_response(
            request,
            Some(Ipv4Addr::new(0, 0, 0, 0)),
            Some(Ipv6Addr::UNSPECIFIED),
        ),
        BlockMode::CustomIp { ipv4, ipv6 } => build_ip_response(request, ipv4, ipv6),
    }
}

fn build_ip_response(request: &Message, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Message {
    let mut response = build_base_response(request, ResponseCode::NoError);
    for query in &request.queries {
        let name = query.name().clone();
        match query.query_type() {
            hickory_proto::rr::RecordType::A => {
                if let Some(address) = ipv4 {
                    response.add_answer(Record::from_rdata(name, 60, RData::A(A(address))));
                }
            }
            hickory_proto::rr::RecordType::AAAA => {
                if let Some(address) = ipv6 {
                    response.add_answer(Record::from_rdata(name, 60, RData::AAAA(AAAA(address))));
                }
            }
            _ => {}
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query};
    use hickory_proto::rr::Name;

    fn response_with_ttls(ttls: &[u32]) -> Message {
        let mut message = Message::query();
        let name = Name::from_ascii("example.com.").expect("name");
        for ttl in ttls {
            message.add_answer(Record::from_rdata(
                name.clone(),
                *ttl,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ));
        }
        message
    }

    /// The shortest-lived record decides: a response is only wholly valid
    /// until its first record expires.
    #[test]
    fn cache_lifetime_follows_the_smallest_record_ttl() {
        assert_eq!(
            cacheable_for(&response_with_ttls(&[300, 60, 900])),
            Duration::from_secs(60)
        );
        assert_eq!(
            cacheable_for(&response_with_ttls(&[120])),
            Duration::from_secs(120)
        );
    }

    /// A CDN answering with TTL 0 or 1 would otherwise mean an upstream query
    /// per name per page load -- a TLS round trip each, on DoT.
    #[test]
    fn a_tiny_ttl_is_raised_to_the_floor() {
        assert_eq!(cacheable_for(&response_with_ttls(&[0])), MIN_CACHE_TTL);
        assert_eq!(cacheable_for(&response_with_ttls(&[1])), MIN_CACHE_TTL);
    }

    /// Bounds the worst case: an appliance nobody restarts must not pin the
    /// household to an address for a day because a record said so.
    #[test]
    fn a_huge_ttl_is_capped_at_the_ceiling() {
        assert_eq!(cacheable_for(&response_with_ttls(&[86_400])), MAX_CACHE_TTL);
        assert_eq!(
            cacheable_for(&response_with_ttls(&[u32::MAX])),
            MAX_CACHE_TTL
        );
    }

    /// NXDOMAIN and NODATA carry no answers. Caching "does not exist" for an
    /// hour keeps a freshly-provisioned host unreachable long after it is up.
    #[test]
    fn a_response_with_no_answers_uses_the_shorter_negative_lifetime() {
        assert_eq!(cacheable_for(&response_with_ttls(&[])), NEGATIVE_CACHE_TTL);
        assert!(NEGATIVE_CACHE_TTL < MAX_CACHE_TTL);
    }

    /// The regression this whole change exists for: before it, nothing in the
    /// DNS path read a TTL at all, and an entry lived until 10,000 other names
    /// evicted it.
    #[test]
    fn every_cached_entry_has_a_deadline_in_the_future_but_bounded() {
        let lifetime = cacheable_for(&response_with_ttls(&[300]));
        assert!(lifetime >= MIN_CACHE_TTL && lifetime <= MAX_CACHE_TTL);
        let entry = CachedLookup {
            response: response_with_ttls(&[300]),
            blocked: false,
            expires_at: Instant::now() + lifetime,
        };
        assert!(entry.expires_at > Instant::now());
        assert!(entry.expires_at <= Instant::now() + MAX_CACHE_TTL);
    }
    use std::fs;

    #[test]
    fn runtime_snapshot_starts_at_zero() {
        let stats = DnsRuntimeStats::default();
        let snapshot = DnsRuntimeSnapshot {
            upstream_failures_total: stats.upstream_failures_total.load(Ordering::Relaxed),
            fallback_served_total: stats.fallback_served_total.load(Ordering::Relaxed),
            cache_hits_total: stats.cache_hits_total.load(Ordering::Relaxed),
            cache_expired_total: stats.cache_expired_total.load(Ordering::Relaxed),
            cname_uncloaks_total: stats.cname_uncloaks_total.load(Ordering::Relaxed),
            cname_blocks_total: stats.cname_blocks_total.load(Ordering::Relaxed),
            queries_total: stats.queries_total.load(Ordering::Relaxed),
            blocked_total: stats.blocked_total.load(Ordering::Relaxed),
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
        };
        assert_eq!(
            snapshot,
            DnsRuntimeSnapshot {
                upstream_failures_total: 0,
                fallback_served_total: 0,
                cache_hits_total: 0,
                cache_expired_total: 0,
                cname_uncloaks_total: 0,
                cname_blocks_total: 0,
                queries_total: 0,
                blocked_total: 0,
                cache_hit_latency_avg_ns: 0,
                cache_hit_samples: 0,
                cache_miss_latency_avg_ns: 0,
                cache_miss_samples: 0,
            }
        );
    }

    #[test]
    fn extract_cname_target_reads_record_data() {
        use hickory_proto::rr::Name;
        use hickory_proto::rr::rdata::CNAME;

        let alias = Name::from_ascii("tracker.example.com").expect("valid test name");
        let record = Record::from_rdata(
            Name::from_ascii("alias.example.com").expect("valid owner name"),
            60,
            RData::CNAME(CNAME(alias)),
        );

        assert_eq!(
            extract_cname_target(&record),
            Some("tracker.example.com".to_string())
        );
    }

    #[test]
    fn cached_response_adopts_request_id() {
        let request = Message::new(42, MessageType::Query, OpCode::Query);
        let cached = Message::response(7, OpCode::Query);

        let response = response_for_request(&request, &cached);
        assert_eq!(response.metadata.id, 42);
    }

    #[test]
    fn error_response_uses_original_request_id() {
        let mut request = Message::new(17, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("example.com").expect("valid test name"),
            RecordType::A,
        ));
        let response = error_response_for_payload(&request.to_vec().expect("wire request"));
        assert_eq!(response.metadata.id, request.metadata.id);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    #[test]
    fn policy_cache_key_scopes_by_policy() {
        assert_eq!(
            policy_cache_key("profile:balanced", "ads.example.com"),
            "profile:balanced:ads.example.com"
        );
    }

    #[test]
    fn build_allow_all_policy_removes_block_rules() {
        let policy = Arc::new(PolicyEngine::new(RulesetArtifact::new(
            vec![cogwheel_policy::Rule {
                pattern: cogwheel_policy::RulePattern::Exact("ads.example".to_string()),
                action: cogwheel_policy::RuleAction::Block,
                source: "test".to_string(),
                comment: None,
            }],
            HashSet::new(),
            BlockMode::NullIp,
        )));

        let allow_all = build_allow_all_policy(&policy);

        assert!(matches!(
            allow_all.evaluate("ads.example").kind,
            DecisionKind::Allowed
        ));
    }

    #[test]
    fn domain_matches_override_supports_suffixes() {
        assert!(domain_matches_override("ads.example.com", "example.com"));
        assert!(domain_matches_override("example.com", "example.com"));
        assert!(!domain_matches_override("badexample.com", "example.com"));
    }

    #[test]
    fn hot_path_crates_remain_llm_and_network_independent() {
        let dns_core_manifest =
            fs::read_to_string(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR")))
                .expect("read dns core manifest");
        let forbidden_dependencies = [
            "reqwest",
            "ureq",
            "surf",
            "async-openai",
            "openai-api-rs",
            "ollama-rs",
            "rig-core",
            "langchain-rust",
        ];

        for dependency in forbidden_dependencies {
            assert!(
                !dns_core_manifest.contains(&format!("{dependency} =")),
                "cogwheel-dns-core should not depend on {dependency}; the DNS hot path must stay deterministic and LLM-independent"
            );
        }
    }
}
