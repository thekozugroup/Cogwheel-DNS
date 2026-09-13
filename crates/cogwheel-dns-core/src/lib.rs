//! The DNS hot path: listeners, one cache of wire-format answers, and the miss pipeline.
//!
//! One [`DnsRuntime`] per process. It owns the upstream resolver, the current [`Policy`] and a
//! single cache keyed by `(scope, qtype, name)`. A hit is answered inside the receive loop — a
//! memcpy plus a two-byte id patch — so a slow or dead upstream can never starve the names the
//! household already knows. A miss is handed to a task under a semaphore, and the loop is back at
//! `recv_from` before the upstream has been asked anything.
//!
//! The decision itself lives in `cogwheel-policy`; this crate only decides *when* to ask it
//! (once per miss, never per hit) and what to do with the upstream's answer.

use anyhow::{Context, Result};
use cogwheel_policy::{
    BlockMode, Policy, Reason, SCOPE_UNFILTERED, Verdict, evaluate, evaluate_lists,
    normalize_domain,
};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError};
use moka::future::Cache;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, watch};

mod response;
#[cfg(test)]
mod tests;
pub mod upstream;

pub use upstream::{
    UpstreamEndpoint, UpstreamError, UpstreamProtocol, build_resolver, resolver_options,
};

use response::{
    BLOCKED_CACHE_TTL, build_base_response, build_blocked_response, cacheable_for,
    error_response_for_payload,
};

/// Names held at once. Each entry is one wire-format answer, so the whole cache is a few
/// megabytes even when full.
const CACHE_CAPACITY: u64 = 10_000;

/// How long an entry may outlive its own freshness.
///
/// A stale entry is only ever served after the upstream has failed, where a day-old address the
/// site probably still answers on beats SERVFAIL. Past this the entry is evicted outright.
const STALE_CEILING: Duration = Duration::from_secs(86_400);

/// How long a stale answer stays fresh once the upstream has failed to refresh it.
///
/// RFC 8767 §5's figure. Without it every query for a known name during an outage is a miss
/// that waits out the full upstream timeout before the stale bytes go out — longer than a stub
/// waits for us, so serve-stale would reach nobody — and holds a miss permit the whole time.
/// Half a minute makes an outage cost one timeout per name per 30 s, with hits answered inline.
const STALE_REFRESH: Duration = Duration::from_secs(30);

/// Misses in flight at once. Past this a miss is answered SERVFAIL and counted as dropped rather
/// than queued behind an upstream that is not answering.
const MISS_PERMITS: usize = 512;

/// Log entries buffered between the hot path and whoever drains them.
///
/// Entries are handed off with `try_send` and dropped when this is full; the writer flushes every
/// few seconds, so this is minutes of headroom at household rates and DNS never waits on SQLite.
pub const LOG_QUEUE_DEPTH: usize = 8_192;

/// Receive loops sharing the UDP socket. Four is plenty for the syscall rate one household can
/// produce; the loops do nothing slow, so more would only contend on the socket.
const MAX_UDP_WORKERS: usize = 4;

/// One datagram's worth of buffer per receive loop; a query is never larger.
const UDP_BUFFER: usize = 4096;

/// The largest UDP answer a client without EDNS accepts (RFC 1035 §4.2.1).
const MAX_PLAIN_UDP_PAYLOAD: usize = 512;

/// CNAME targets checked per upstream answer.
const MAX_CNAME_TARGETS: usize = 8;

/// The RD flag, bit 0 of the third header byte.
const RD_BIT: u8 = 0x01;

/// Where the listeners bind.
#[derive(Debug, Clone)]
pub struct DnsRuntimeConfig {
    pub udp_bind_addr: SocketAddr,
    pub tcp_bind_addr: SocketAddr,
}

/// One answered query, handed off the hot path for the query log.
///
/// No `String`s: `domain` is the same allocation the cache key shares, so building an entry costs
/// one refcount bump and a `try_send`.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Unix seconds.
    pub ts: u32,
    pub client: IpAddr,
    pub domain: Arc<str>,
    pub qtype: u16,
    pub verdict: Verdict,
}

/// What the runtime has done since it started.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsRuntimeSnapshot {
    pub queries_total: u64,
    pub blocked_total: u64,
    pub cache_hits_total: u64,
    pub cache_expired_total: u64,
    pub upstream_failures_total: u64,
    pub stale_served_total: u64,
    pub cname_blocks_total: u64,
    pub dropped_total: u64,
    pub cache_hit_latency_avg_ns: u64,
    pub cache_hit_samples: u64,
    pub cache_miss_latency_avg_ns: u64,
    pub cache_miss_samples: u64,
}

/// The DNS forwarder: listeners, cache, policy and the upstream resolver.
pub struct DnsRuntime {
    resolver: TokioResolver,
    policy: RwLock<Arc<Policy>>,
    /// Unix seconds; 0 when not paused.
    pause_until: AtomicU64,
    cache: Cache<CacheKey, Arc<CachedWire>>,
    /// Bumped by every swap that empties the cache, so a miss decided under the policy being
    /// replaced can tell that its answer came back too late to be cached.
    cache_epoch: AtomicU64,
    miss_permits: Arc<Semaphore>,
    log_tx: mpsc::Sender<LogEntry>,
    stats: DnsRuntimeStats,
}

/// What an answer depends on: who asked (by scope, not by address), for what, and the name.
///
/// `qtype` is part of the key because an A answer cached under a bare name would be served to
/// the AAAA query that follows it, which is the one that must never happen on a dual-stack
/// network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    scope: u32,
    qtype: u16,
    domain: Arc<str>,
}

/// One cached answer, already on the wire.
///
/// A hit copies `bytes` and patches the id and RD bit; nothing is re-encoded per request. The
/// question name is therefore replayed in whatever case the first requester used. That is
/// deliberate — 0x20-strict stubs are not a household concern, and rebuilding a `Message` per
/// hit is what this design exists to avoid.
struct CachedWire {
    bytes: Box<[u8]>,
    /// The TC form, present only when `bytes` cannot fit a plain 512-byte datagram.
    truncated: Option<Box<[u8]>>,
    fresh_until: Instant,
    /// Past this the answer is not served even as a fallback. Fixed when the upstream last
    /// confirmed it, so serving it stale through an outage does not push the ceiling out.
    stale_until: Instant,
    blocked: bool,
    verdict: Verdict,
}

impl CachedWire {
    fn from_message(response: &Message, fresh_for: Duration, verdict: Verdict) -> Result<Self> {
        let bytes = response
            .to_vec()
            .context("encode response")?
            .into_boxed_slice();
        // Precomputed once here rather than per hit: a non-EDNS client asking for a large
        // answer is common (every `dig +noedns`, some IoT stubs), and encoding on the hot path
        // is exactly what the cache is meant to remove.
        let truncated = if bytes.len() > MAX_PLAIN_UDP_PAYLOAD {
            Some(
                response
                    .truncate()
                    .to_vec()
                    .context("encode truncated response")?
                    .into_boxed_slice(),
            )
        } else {
            None
        };
        let now = Instant::now();
        Ok(Self {
            bytes,
            truncated,
            fresh_until: now + fresh_for,
            stale_until: now + STALE_CEILING,
            blocked: verdict.is_blocked(),
            verdict,
        })
    }

    /// The same answer, fresh again for `fresh_for`, under the original stale ceiling.
    fn refreshed(&self, fresh_for: Duration) -> Self {
        Self {
            bytes: self.bytes.clone(),
            truncated: self.truncated.clone(),
            fresh_until: Instant::now() + fresh_for,
            stale_until: self.stale_until,
            blocked: self.blocked,
            verdict: self.verdict,
        }
    }
}

/// A parsed query with everything the hit and miss paths need, owned so a miss can move to a task.
struct Admitted {
    request: Message,
    key: CacheKey,
    policy: Arc<Policy>,
    /// The cache epoch `policy` was read under.
    epoch: u64,
    client: IpAddr,
    /// Whether the scope was reached through the household pause rather than a bypassed device;
    /// the two share [`SCOPE_UNFILTERED`] and only the log tells them apart.
    paused: bool,
    /// The largest datagram the client accepts.
    edns_max: usize,
    ts: u32,
    started: Instant,
}

enum Probe {
    Hit(Arc<CachedWire>),
    /// Carries the expired entry, if any, so an upstream failure can fall back to it.
    Miss(Option<Arc<CachedWire>>),
}

#[derive(Debug, Default)]
struct DnsRuntimeStats {
    queries_total: AtomicU64,
    blocked_total: AtomicU64,
    cache_hits_total: AtomicU64,
    cache_expired_total: AtomicU64,
    upstream_failures_total: AtomicU64,
    stale_served_total: AtomicU64,
    cname_blocks_total: AtomicU64,
    dropped_total: AtomicU64,
    cache_hit_latency_total_ns: AtomicU64,
    cache_hit_samples: AtomicU64,
    cache_miss_latency_total_ns: AtomicU64,
    cache_miss_samples: AtomicU64,
}

impl DnsRuntimeStats {
    fn record_hit(&self, elapsed: Duration) {
        self.cache_hit_latency_total_ns
            .fetch_add(saturating_ns(elapsed), Ordering::Relaxed);
        bump(&self.cache_hit_samples);
    }

    fn record_miss(&self, elapsed: Duration) {
        self.cache_miss_latency_total_ns
            .fetch_add(saturating_ns(elapsed), Ordering::Relaxed);
        bump(&self.cache_miss_samples);
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn saturating_ns(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

fn average_ns(total: &AtomicU64, samples: u64) -> u64 {
    total
        .load(Ordering::Relaxed)
        .checked_div(samples)
        .unwrap_or(0)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Grow the process's file-descriptor table to `slots` while the process is still
/// single-threaded. Returns how many descriptors were actually opened, which is fewer than
/// asked when `RLIMIT_NOFILE` is smaller.
///
/// Every upstream send binds a fresh UDP socket, and a retry wave against a dead upstream opens
/// a batch of them at once. Linux doubles the descriptor table on demand, and once a process has
/// more than one thread each doubling waits out an RCU grace period — 7 to 20 ms measured
/// here — with every concurrent `socket()` queued behind it. Four workers stuck in that wait is
/// four receive loops not answering hits. Opening and closing the descriptors before the
/// runtime spawns its workers pays for the growth once, when it is cheap; the table never
/// shrinks.
pub fn reserve_descriptor_table(slots: usize) -> usize {
    let Ok(anchor) = std::fs::File::open("/dev/null") else {
        return 0;
    };
    let mut held = Vec::with_capacity(slots);
    while held.len() < slots {
        match anchor.try_clone() {
            Ok(descriptor) => held.push(descriptor),
            Err(_) => break,
        }
    }
    held.len()
}

/// Read an `RwLock`, recovering the value even when the lock is poisoned.
///
/// Poisoning only signals that some thread panicked while holding the lock. The policy is swapped
/// wholesale — an `Arc` replacement — so the last committed value is still coherent, and
/// recovering it keeps one panicking task from taking DNS resolution down for the remaining life
/// of the process. Failing open is the right posture for a household resolver: losing the policy
/// should mean "resolve normally", never "take the network offline".
fn read_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl DnsRuntime {
    /// Build a runtime around a resolver and an initial policy.
    ///
    /// The receiver carries one [`LogEntry`] per answered query; whoever owns it must keep
    /// draining or entries are dropped (and counted) once [`LOG_QUEUE_DEPTH`] is reached.
    pub fn new(
        resolver: TokioResolver,
        policy: Arc<Policy>,
    ) -> (Arc<Self>, mpsc::Receiver<LogEntry>) {
        let (log_tx, log_rx) = mpsc::channel(LOG_QUEUE_DEPTH);
        let runtime = Self {
            resolver,
            policy: RwLock::new(policy),
            pause_until: AtomicU64::new(0),
            // `fresh_until` on each entry is what enforces the record's own TTL; moka's
            // time-to-live is only the ceiling on how long a stale entry stays available for
            // an outage before it is evicted outright.
            cache: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(STALE_CEILING)
                .build(),
            cache_epoch: AtomicU64::new(0),
            miss_permits: Arc::new(Semaphore::new(MISS_PERMITS)),
            log_tx,
            stats: DnsRuntimeStats::default(),
        };
        (Arc::new(runtime), log_rx)
    }

    /// Install a policy whose verdicts may differ from the current one's — a list rebuild or a
    /// household-rule edit — and drop every cached answer with it.
    pub fn swap_policy(&self, policy: Arc<Policy>) {
        self.swap_policy_keep_cache(policy);
        // The sweep only covers entries already inserted. A miss that read the old policy and
        // is still waiting on the upstream will insert after it; bumping the epoch first is
        // what lets that miss notice (see `insert`).
        self.cache_epoch.fetch_add(1, Ordering::Release);
        self.cache.invalidate_all();
    }

    /// Install a policy that only re-maps clients to scopes (a device edit).
    ///
    /// Cached answers stay valid because a scope's verdicts are a function of the lists and
    /// household rules, which did not change; a device whose settings changed simply lands on a
    /// fresh scope id and its old entries age out unread.
    pub fn swap_policy_keep_cache(&self, policy: Arc<Policy>) {
        let mut guard = self
            .policy
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = policy;
    }

    /// The policy answering queries right now.
    pub fn current_policy(&self) -> Arc<Policy> {
        read_recover(&self.policy).clone()
    }

    /// How blocked names are answered under the current policy.
    pub fn block_mode(&self) -> BlockMode {
        read_recover(&self.policy).block_mode
    }

    /// Unix seconds until which every client resolves unfiltered; 0 when not paused.
    pub fn pause_until(&self) -> u64 {
        self.pause_until.load(Ordering::Relaxed)
    }

    /// Pause protection until the given unix second (0 resumes).
    ///
    /// No cache invalidation is needed: blocked answers live under scope 0 and the device
    /// scopes, and a paused client reads [`SCOPE_UNFILTERED`].
    pub fn set_pause_until(&self, until: u64) {
        self.pause_until.store(until, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DnsRuntimeSnapshot {
        let stats = &self.stats;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let cache_hit_samples = load(&stats.cache_hit_samples);
        let cache_miss_samples = load(&stats.cache_miss_samples);
        DnsRuntimeSnapshot {
            queries_total: load(&stats.queries_total),
            blocked_total: load(&stats.blocked_total),
            cache_hits_total: load(&stats.cache_hits_total),
            cache_expired_total: load(&stats.cache_expired_total),
            upstream_failures_total: load(&stats.upstream_failures_total),
            stale_served_total: load(&stats.stale_served_total),
            cname_blocks_total: load(&stats.cname_blocks_total),
            dropped_total: load(&stats.dropped_total),
            cache_hit_latency_avg_ns: average_ns(
                &stats.cache_hit_latency_total_ns,
                cache_hit_samples,
            ),
            cache_hit_samples,
            cache_miss_latency_avg_ns: average_ns(
                &stats.cache_miss_latency_total_ns,
                cache_miss_samples,
            ),
            cache_miss_samples,
        }
    }

    pub async fn serve(self: Arc<Self>, config: DnsRuntimeConfig) -> Result<()> {
        let (_tx, never) = watch::channel(false);
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
        shutdown: watch::Receiver<bool>,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        // Bind before spawning the loops so a bind failure is reported as a startup error rather
        // than surfacing later as a dead task.
        let udp_socket = Arc::new(
            UdpSocket::bind(config.udp_bind_addr)
                .await
                .context("bind udp socket")?,
        );
        let tcp_listener = TcpListener::bind(config.tcp_bind_addr)
            .await
            .context("bind tcp listener")?;
        on_ready();

        // Several loops share the one socket so a hit on one core is answered while another is
        // parsing; a single loop was the serial bottleneck this replaces.
        let workers = std::thread::available_parallelism()
            .map_or(1, |cores| cores.get())
            .min(MAX_UDP_WORKERS);
        let udp_loops: Vec<_> = (0..workers)
            .map(|_| tokio::spawn(self.clone().recv_loop(udp_socket.clone(), shutdown.clone())))
            .collect();
        let tcp = tokio::spawn(self.clone().accept_tcp(tcp_listener, shutdown));
        for udp in udp_loops {
            udp.await??;
        }
        tcp.await??;
        Ok(())
    }

    async fn recv_loop(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut buffer = [0u8; UDP_BUFFER];
        loop {
            // Select only on the receive point. A hit being answered runs to completion below
            // before the loop comes back here, so shutdown drains in-flight work rather than
            // cancelling it and dropping the client's answer.
            let (size, peer) = tokio::select! {
                result = socket.recv_from(&mut buffer) => result?,
                _ = shutdown.changed() => {
                    tracing::info!("udp listener stopping");
                    return Ok(());
                }
            };
            let payload = &buffer[..size];
            if let Err(error) = self.handle_udp(&socket, payload, peer).await {
                tracing::warn!(%error, "failed to handle udp dns query");
                if let Ok(bytes) = error_response_for_payload(payload).to_vec() {
                    // The client is retrying either way; a second failure adds nothing.
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        }
    }

    /// One UDP datagram: answer a hit here, hand a miss to a task, never wait on the upstream.
    async fn handle_udp(
        self: &Arc<Self>,
        socket: &Arc<UdpSocket>,
        payload: &[u8],
        peer: SocketAddr,
    ) -> Result<()> {
        let started = Instant::now();
        let admitted = match self.admit(payload, peer.ip(), started) {
            Ok(admitted) => admitted,
            Err(rejection) => {
                socket.send_to(&rejection.to_vec()?, peer).await?;
                return Ok(());
            }
        };
        match self.probe(&admitted.key, started).await {
            Probe::Hit(entry) => {
                self.count_hit(&entry);
                let bytes = wire_for(&entry, &admitted.request, admitted.edns_max);
                self.log(&admitted, entry.verdict);
                // Sampled before the send: the latency counters measure this server's own
                // work, and the loopback delivery plus the client's wake-up is the kernel's.
                self.stats.record_hit(started.elapsed());
                socket
                    .send_to(&bytes, peer)
                    .await
                    .context("send udp response")?;
            }
            Probe::Miss(stale) => {
                let Ok(permit) = Arc::clone(&self.miss_permits).try_acquire_owned() else {
                    bump(&self.stats.dropped_total);
                    let servfail = Message::error_msg(
                        admitted.request.metadata.id,
                        admitted.request.metadata.op_code,
                        ResponseCode::ServFail,
                    );
                    socket.send_to(&servfail.to_vec()?, peer).await?;
                    return Ok(());
                };
                let runtime = Arc::clone(self);
                let socket = Arc::clone(socket);
                tokio::spawn(async move {
                    let _permit = permit;
                    runtime
                        .finish_udp_miss(&socket, admitted, stale, peer)
                        .await;
                });
            }
        }
        Ok(())
    }

    async fn finish_udp_miss(
        &self,
        socket: &UdpSocket,
        admitted: Admitted,
        stale: Option<Arc<CachedWire>>,
        peer: SocketAddr,
    ) {
        let (bytes, verdict) = match self.resolve_miss(&admitted, stale).await {
            Ok(wire) => (
                wire_for(&wire, &admitted.request, admitted.edns_max),
                wire.verdict,
            ),
            Err(error) => {
                tracing::warn!(%error, domain = %admitted.key.domain, "failed to resolve query");
                let servfail = Message::error_msg(
                    admitted.request.metadata.id,
                    admitted.request.metadata.op_code,
                    ResponseCode::ServFail,
                );
                match servfail.to_vec() {
                    Ok(bytes) => (bytes, Verdict::Allow(Reason::NoMatch)),
                    Err(error) => {
                        tracing::warn!(%error, "failed to encode servfail");
                        return;
                    }
                }
            }
        };
        self.log(&admitted, verdict);
        self.stats.record_miss(admitted.started.elapsed());
        if let Err(error) = socket.send_to(&bytes, peer).await {
            tracing::warn!(%error, "failed to send udp dns response");
        }
    }

    async fn accept_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
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
        let length = usize::from(u16::from_be_bytes(len_buffer));
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await?;
        let response = match self.answer_tcp(&payload, peer.ip()).await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "failed to resolve tcp dns query");
                error_response_for_payload(&payload).to_vec()?
            }
        };
        let length = u16::try_from(response.len()).context("tcp response exceeds 64 KiB")?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&response).await?;
        Ok(())
    }

    /// TCP is the retry path for a truncated UDP answer, so it never truncates, and it runs the
    /// miss inline: a connection is already a per-client resource, so no permit is needed.
    async fn answer_tcp(&self, payload: &[u8], client: IpAddr) -> Result<Vec<u8>> {
        let started = Instant::now();
        let admitted = match self.admit(payload, client, started) {
            Ok(admitted) => admitted,
            Err(rejection) => return Ok(rejection.to_vec()?),
        };
        let (wire, hit) = match self.probe(&admitted.key, started).await {
            Probe::Hit(entry) => {
                self.count_hit(&entry);
                (entry, true)
            }
            Probe::Miss(stale) => (self.resolve_miss(&admitted, stale).await?, false),
        };
        let bytes = wire_for(&wire, &admitted.request, usize::MAX);
        self.log(&admitted, wire.verdict);
        if hit {
            self.stats.record_hit(started.elapsed());
        } else {
            self.stats.record_miss(started.elapsed());
        }
        Ok(bytes)
    }

    /// Parse and classify a query. `Err` carries the error response to send instead.
    ///
    /// This is the whole per-hit cost besides the cache probe: one `Message` parse, one `String`
    /// for the lowercased name (shared by the key and the log entry), one policy `Arc` clone.
    fn admit(
        &self,
        payload: &[u8],
        client: IpAddr,
        started: Instant,
    ) -> Result<Admitted, Box<Message>> {
        let request = match Message::from_vec(payload) {
            Ok(request) => request,
            Err(_) => {
                // The id is the first two bytes whether or not the rest parsed; echoing it lets
                // the client match the FORMERR to its query instead of waiting for a timeout.
                let id = payload
                    .first_chunk::<2>()
                    .map_or(0, |id| u16::from_be_bytes(*id));
                return Err(Box::new(Message::error_msg(
                    id,
                    OpCode::Query,
                    ResponseCode::FormErr,
                )));
            }
        };
        let id = request.metadata.id;
        let op_code = request.metadata.op_code;
        if op_code != OpCode::Query {
            return Err(Box::new(Message::error_msg(
                id,
                op_code,
                ResponseCode::NotImp,
            )));
        }
        let [query] = request.queries.as_slice() else {
            return Err(Box::new(Message::error_msg(
                id,
                op_code,
                ResponseCode::FormErr,
            )));
        };
        bump(&self.stats.queries_total);

        // `to_ascii`, not `to_utf8`: lists carry `xn--` labels as they appear on the wire, and
        // the UTF-8 form decodes them to Unicode, which nothing would ever match against. It
        // also sizes the String exactly, where the UTF-8 form grows it through `format!`.
        let domain = {
            let mut name = query.name().to_ascii();
            name.make_ascii_lowercase();
            Arc::<str>::from(name.trim_end_matches('.'))
        };
        let qtype = u16::from(query.query_type());
        let edns_max = usize::from(request.max_payload());

        // Epoch before policy: a swap that lands between the two is then seen as a new epoch
        // with the new policy, never as the old policy under the new epoch.
        let epoch = self.cache_epoch.load(Ordering::Acquire);
        let policy = read_recover(&self.policy).clone();
        let now = unix_now();
        let pause_until = self.pause_until.load(Ordering::Relaxed);
        let paused = pause_until != 0 && now < pause_until;
        let scope = if paused {
            SCOPE_UNFILTERED
        } else {
            let scope = policy.scope_for(client);
            if scope.filtering {
                scope.id
            } else {
                SCOPE_UNFILTERED
            }
        };

        Ok(Admitted {
            request,
            key: CacheKey {
                scope,
                qtype,
                domain,
            },
            policy,
            epoch,
            client,
            paused,
            edns_max,
            ts: u32::try_from(now).unwrap_or(u32::MAX),
            started,
        })
    }

    /// An entry past its freshness is a miss, not a hit — but it is kept in hand, because if the
    /// upstream then fails it is the answer the household gets.
    async fn probe(&self, key: &CacheKey, now: Instant) -> Probe {
        match self.cache.get(key).await {
            Some(entry) if now < entry.fresh_until => Probe::Hit(entry),
            Some(stale) => {
                bump(&self.stats.cache_expired_total);
                Probe::Miss((now < stale.stale_until).then_some(stale))
            }
            None => Probe::Miss(None),
        }
    }

    fn count_hit(&self, entry: &CachedWire) {
        bump(&self.stats.cache_hits_total);
        // A blocked answer served from cache is still a block the household saw; counting only
        // the first one made `blocked_total` a count of distinct names, not of queries.
        if entry.blocked {
            bump(&self.stats.blocked_total);
        }
    }

    /// Decide the name, ask the upstream if allowed, cache what came back.
    ///
    /// Returns the entry to send. It is in the cache unless it is a SERVFAIL, which is never
    /// cached, or the stale entry handed in, which already is.
    async fn resolve_miss(
        &self,
        admitted: &Admitted,
        stale: Option<Arc<CachedWire>>,
    ) -> Result<Arc<CachedWire>> {
        let Admitted {
            request,
            key,
            policy,
            paused,
            ..
        } = admitted;
        let scope = policy.scope(key.scope);
        let mut verdict = evaluate(policy, scope, &key.domain);
        if *paused {
            verdict = Verdict::Allow(Reason::Paused);
        }
        if verdict.is_blocked() {
            return self.insert_blocked(admitted, verdict).await;
        }

        let response = match self
            .resolver
            .lookup(&*key.domain, RecordType::from(key.qtype))
            .await
        {
            Ok(lookup) => {
                // Only a name nothing matched is re-checked through its aliases. An explicit
                // allow — a rule, a protected suffix, a list exception — named the query, and
                // a pause or bypass switched filtering off altogether.
                if verdict.reason() == Reason::NoMatch
                    && let Some(blocked) = cname_block(policy, scope.mask, lookup.answers())
                {
                    bump(&self.stats.cname_blocks_total);
                    return self.insert_blocked(admitted, blocked).await;
                }
                let mut response = build_base_response(request, ResponseCode::NoError);
                for record in lookup.answers() {
                    response.add_answer(record.clone());
                }
                response
            }
            // hickory reports NXDOMAIN and NODATA as errors, but to the client they are answers:
            // the name does not exist, or has no record of that type. Forward the code (and the
            // SOA, which tells the stub how long it may remember that) rather than SERVFAIL,
            // which would make the client retry elsewhere.
            Err(NetError::Dns(DnsError::NoRecordsFound(negative))) => {
                let mut response = build_base_response(request, negative.response_code);
                if let Some(soa) = negative.soa {
                    response.add_authority(soa.into_record_of_rdata());
                }
                response
            }
            Err(error) => {
                bump(&self.stats.upstream_failures_total);
                if let Some(stale) = stale {
                    bump(&self.stats.stale_served_total);
                    tracing::warn!(
                        %error,
                        domain = %key.domain,
                        "serving stale answer after upstream failure"
                    );
                    let refreshed = Arc::new(stale.refreshed(STALE_REFRESH));
                    self.insert(admitted, Arc::clone(&refreshed)).await;
                    return Ok(refreshed);
                }
                let servfail = build_base_response(request, ResponseCode::ServFail);
                return CachedWire::from_message(&servfail, Duration::ZERO, verdict).map(Arc::new);
            }
        };

        let fresh_for = cacheable_for(&response);
        let wire = Arc::new(CachedWire::from_message(&response, fresh_for, verdict)?);
        self.insert(admitted, Arc::clone(&wire)).await;
        Ok(wire)
    }

    async fn insert_blocked(
        &self,
        admitted: &Admitted,
        verdict: Verdict,
    ) -> Result<Arc<CachedWire>> {
        let response = build_blocked_response(&admitted.request, admitted.policy.block_mode);
        let wire = Arc::new(CachedWire::from_message(
            &response,
            BLOCKED_CACHE_TTL,
            verdict,
        )?);
        bump(&self.stats.blocked_total);
        self.insert(admitted, Arc::clone(&wire)).await;
        Ok(wire)
    }

    /// Cache an answer, unless the policy it was decided under was replaced while it was in
    /// flight.
    ///
    /// Checked after the insert rather than before so there is no window: a swap that bumps
    /// the epoch after this check runs its sweep after this insert, and the sweep takes the
    /// entry; a swap that bumped before is seen here, and the entry is taken back.
    async fn insert(&self, admitted: &Admitted, wire: Arc<CachedWire>) {
        self.cache.insert(admitted.key.clone(), wire).await;
        if self.cache_epoch.load(Ordering::Acquire) != admitted.epoch {
            self.cache.invalidate(&admitted.key).await;
        }
    }

    fn log(&self, admitted: &Admitted, verdict: Verdict) {
        let entry = LogEntry {
            ts: admitted.ts,
            client: admitted.client,
            domain: Arc::clone(&admitted.key.domain),
            qtype: admitted.key.qtype,
            verdict: logged_verdict(admitted, verdict),
        };
        match self.log_tx.try_send(entry) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => bump(&self.stats.dropped_total),
            // Nobody is draining the log; there is nothing to lose.
            Err(TrySendError::Closed(_)) => {}
        }
    }
}

/// The verdict the query log records.
///
/// Paused households and bypassed devices share one cache scope, so an entry under it remembers
/// whichever of the two inserted it. The requester's own route to that scope is what the log
/// should say.
fn logged_verdict(admitted: &Admitted, stored: Verdict) -> Verdict {
    if admitted.key.scope != SCOPE_UNFILTERED {
        return stored;
    }
    Verdict::Allow(if admitted.paused {
        Reason::Paused
    } else {
        Reason::Unfiltered
    })
}

/// A list-tier block for any CNAME target in `answers`, attributed to [`Reason::Cname`].
///
/// Read from the answer the upstream already returned, so the check costs no round trip. Only
/// the list tier applies: a user's rule names the query, not the aliases behind it.
fn cname_block(policy: &Policy, mask: u64, answers: &[Record]) -> Option<Verdict> {
    answers
        .iter()
        .filter_map(cname_target)
        .take(MAX_CNAME_TARGETS)
        .find_map(|target| {
            let target = normalize_domain(&target.to_ascii());
            match evaluate_lists(policy, mask, &target) {
                Verdict::Block(_, slot) => Some(Verdict::Block(Reason::Cname, slot)),
                Verdict::Allow(_) => None,
            }
        })
}

fn cname_target(record: &Record) -> Option<&Name> {
    match &record.data {
        RData::CNAME(target) => Some(&target.0),
        _ => None,
    }
}

/// The bytes to send for `request`: the cached answer, or its TC form when the answer would not
/// fit the client's datagram, with the header patched to this request.
fn wire_for(entry: &CachedWire, request: &Message, max_payload: usize) -> Vec<u8> {
    let bytes = match &entry.truncated {
        Some(truncated) if entry.bytes.len() > max_payload => truncated,
        _ => &entry.bytes,
    };
    let mut out = bytes.to_vec();
    patch_header(
        &mut out,
        request.metadata.id,
        request.metadata.recursion_desired,
    );
    out
}

/// Make a cached response answer this request: its id, and its RD bit (RFC 1035 §4.1.1 says
/// the response copies it from the query).
fn patch_header(bytes: &mut [u8], id: u16, recursion_desired: bool) {
    if let Some([hi, lo, flags]) = bytes.first_chunk_mut::<3>() {
        [*hi, *lo] = id.to_be_bytes();
        *flags = (*flags & !RD_BIT) | (u8::from(recursion_desired) * RD_BIT);
    }
}
