//! The DNS hot path: listeners, one cache of wire-format answers, and the miss pipeline.
//!
//! One [`DnsRuntime`] per process. It owns the upstream resolver, the current [`Policy`] and a
//! single cache keyed by `(scope, qtype, name)`. A hit is answered inside the receive loop — a
//! memcpy plus a two-byte id patch — so a slow or dead upstream can never starve the names the
//! household already knows, and so is a block, which is decided from the question alone. Only a
//! miss that has to ask the upstream is handed to a task under a semaphore, and the loop is back
//! at `recv_from` before the upstream has been asked anything.
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
use serde::Serialize;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc};

#[cfg(test)]
mod alloc_guard;
mod response;
mod runtime_support;
mod serve;
#[cfg(test)]
mod tests;
pub mod upstream;

pub use runtime_support::reserve_descriptor_table;
pub use upstream::{
    UpstreamEndpoint, UpstreamError, UpstreamProtocol, build_resolver, resolver_options,
};

use runtime_support::{DnsRuntimeStats, average_ns, bump, read_recover, unix_now, write_recover};

use response::{BLOCKED_CACHE_TTL, build_base_response, build_blocked_response, cacheable_for};

/// Names held at once. Each entry is one wire-format answer, so the whole cache is a few
/// megabytes even when full.
const CACHE_CAPACITY: usize = 10_000;

/// Independent locks the cache is split across. Four receive loops probe it, so the point is
/// only that they do not queue behind one shard's writer; sixteen makes that collision rare
/// without making `invalidate_all` a long walk.
const CACHE_SHARDS: usize = 16;

/// How long an entry may outlive its own freshness.
///
/// A stale entry is only ever served after the upstream has failed, where a day-old address the
/// site probably still answers on beats SERVFAIL. Past this it is not served at all, and its slot
/// goes to the next name that needs one.
const STALE_CEILING: Duration = Duration::from_secs(86_400);

/// How long a stale answer stays fresh once the upstream has failed to refresh it.
///
/// RFC 8767 §5's figure. Without it every query for a known name during an outage is a miss
/// that waits out the full upstream timeout before the stale bytes go out — longer than a stub
/// waits for us, so serve-stale would reach nobody — and holds a miss permit the whole time.
/// Half a minute makes an outage cost one timeout per name per 30 s, with hits answered inline.
const STALE_REFRESH: Duration = Duration::from_secs(30);

/// Upstream lookups in flight at once. Past this a miss is answered SERVFAIL and counted as
/// dropped rather than queued behind an upstream that is not answering.
///
/// A blocked name takes no permit: nothing about it waits on the network, so a device hammering
/// a tracker cannot spend the budget the household's real lookups need.
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

/// The longest name the wire can carry (RFC 1035 §2.3.4), which is also the longest text form
/// `admit` can be asked to spell: every label byte is one character and the dots replace the
/// length octets.
const MAX_NAME_BYTES: usize = 255;

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
    /// The list the verdict is attributed to, resolved against the policy that produced it.
    ///
    /// Carried here rather than looked up by the writer because slots are positions in the
    /// enabled-list order: adding, deleting or toggling a list renumbers every slot above it,
    /// and a row waiting in the five-second flush window would then be attributed to whichever
    /// list happens to hold that bit by the time it is written.
    pub list: Option<Arc<str>>,
}

/// What the runtime has done since it started.
///
/// Serialised straight into `GET /api/v1/overview`, so the two sample counts behind the averages
/// are `skip`ped rather than dropped: they are how a test or a benchmark tells "0 ns because it
/// was fast" from "0 ns because nothing was measured", and they are not something a five-second
/// poll should invite anyone to build a dashboard on.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsRuntimeSnapshot {
    pub queries_total: u64,
    pub blocked_total: u64,
    pub cache_hits_total: u64,
    pub cache_expired_total: u64,
    pub upstream_failures_total: u64,
    pub stale_served_total: u64,
    pub cname_blocks_total: u64,
    /// Misses refused because every permit was taken; answered SERVFAIL.
    pub dropped_total: u64,
    /// Answered queries whose log entry was dropped because the writer was behind.
    pub log_dropped_total: u64,
    pub cache_hit_latency_avg_ns: u64,
    #[serde(skip)]
    pub cache_hit_samples: u64,
    pub cache_miss_latency_avg_ns: u64,
    #[serde(skip)]
    pub cache_miss_samples: u64,
}

/// The DNS forwarder: listeners, cache, policy and the upstream resolver.
pub struct DnsRuntime {
    resolver: TokioResolver,
    policy: RwLock<Arc<Policy>>,
    /// Unix seconds; 0 when not paused.
    pause_until: AtomicU64,
    cache: WireCache,
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

/// The bounded table of wire answers.
///
/// Not an LRU, and deliberately so: every entry already carries `fresh_until` and `stale_until`,
/// so recency tells us nothing a TTL has not, and the eviction order only picks which name pays
/// one extra upstream round trip on the day the table is full. A household's working set is a
/// few thousand names against a 10,000 ceiling, so that day does not come. What it does have to
/// be is cheap on the receive loop, which probes it inline: a hit is a shard pick, a read lock
/// and an `Arc` clone.
struct WireCache {
    shards: Box<[RwLock<Shard>]>,
    hasher: RandomState,
    /// Ceiling per shard. Hashing spreads keys evenly enough that the sum is the real bound.
    per_shard: usize,
}

/// One shard: the entries, and the order to evict them in.
///
/// `order` holds exactly the keys of `entries`, oldest insertion first — both mutations keep
/// that true, which is what makes eviction a `pop_front`.
#[derive(Default)]
struct Shard {
    entries: HashMap<CacheKey, Arc<CachedWire>>,
    order: VecDeque<CacheKey>,
}

impl WireCache {
    fn new(capacity: usize) -> Self {
        Self {
            shards: (0..CACHE_SHARDS)
                .map(|_| RwLock::new(Shard::default()))
                .collect(),
            hasher: RandomState::new(),
            per_shard: capacity.div_ceil(CACHE_SHARDS),
        }
    }

    fn shard(&self, key: &CacheKey) -> &RwLock<Shard> {
        let index = self.hasher.hash_one(key) % CACHE_SHARDS as u64;
        &self.shards[index as usize]
    }

    fn get(&self, key: &CacheKey) -> Option<Arc<CachedWire>> {
        read_recover(self.shard(key)).entries.get(key).cloned()
    }

    fn insert(&self, key: CacheKey, wire: Arc<CachedWire>) {
        let mut guard = write_recover(self.shard(&key));
        let Shard { entries, order } = &mut *guard;
        // A key that is already here keeps its place in the queue: re-inserting is refreshing an
        // answer, not asking for it to outlive the ones queued behind it.
        if entries.insert(key.clone(), wire).is_some() {
            return;
        }
        order.push_back(key);
        while entries.len() > self.per_shard {
            let Some(oldest) = order.pop_front() else {
                break;
            };
            entries.remove(&oldest);
        }
    }

    fn invalidate(&self, key: &CacheKey) {
        let mut guard = write_recover(self.shard(key));
        let Shard { entries, order } = &mut *guard;
        if entries.remove(key).is_some() {
            // Dropped from the queue too, so it cannot come back as a duplicate on the next
            // insert and leave the queue growing without bound.
            order.retain(|queued| queued != key);
        }
    }

    fn invalidate_all(&self) {
        for shard in &self.shards {
            let mut guard = write_recover(shard);
            guard.entries.clear();
            guard.order.clear();
        }
    }
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
            cache: WireCache::new(CACHE_CAPACITY),
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
        *write_recover(&self.policy) = policy;
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
            log_dropped_total: load(&stats.log_dropped_total),
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

        // One allocation: the `Arc` the key and the log entry share. The name is spelled into a
        // stack buffer first, because `Name::to_ascii` would build a `String` that exists only
        // to be copied into that `Arc` and dropped.
        let mut buffer = [0u8; MAX_NAME_BYTES];
        let domain = match ascii_lowercase(query.name(), &mut buffer) {
            Some(name) => Arc::<str>::from(name),
            // `to_ascii`, not `to_utf8`: lists carry `xn--` labels as they appear on the wire,
            // and the UTF-8 form decodes them to Unicode, which nothing would ever match
            // against.
            None => {
                let mut name = query.name().to_ascii();
                name.make_ascii_lowercase();
                Arc::<str>::from(name.trim_end_matches('.'))
            }
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
    fn probe(&self, key: &CacheKey, now: Instant) -> Probe {
        match self.cache.get(key) {
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

    /// What the policy says about a name that was not in the cache — §6 steps 1 to 10.
    ///
    /// A few hash probes and no I/O, which is what lets the receive loop run it: a block decided
    /// here is answered without ever reaching [`Self::resolve_miss`] and its upstream.
    fn decide(&self, admitted: &Admitted) -> Verdict {
        if admitted.paused {
            return Verdict::allow(Reason::Paused);
        }
        let scope = admitted.policy.scope(admitted.key.scope);
        evaluate(&admitted.policy, scope, &admitted.key.domain)
    }

    /// Answer a miss under the verdict [`Self::decide`] reached: a block from the question
    /// itself, anything else from the upstream, and cache what came back.
    ///
    /// Returns the entry to send. It is in the cache unless it is a SERVFAIL, which is never
    /// cached, or the stale entry handed in, which already is.
    async fn resolve_miss(
        &self,
        admitted: &Admitted,
        verdict: Verdict,
        stale: Option<Arc<CachedWire>>,
    ) -> Result<Arc<CachedWire>> {
        let Admitted {
            request,
            key,
            policy,
            ..
        } = admitted;
        if verdict.is_blocked() {
            return self.insert_blocked(admitted, verdict);
        }
        let scope = policy.scope(key.scope);

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
                    return self.insert_blocked(admitted, blocked);
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
                    self.insert(admitted, Arc::clone(&refreshed));
                    return Ok(refreshed);
                }
                let servfail = build_base_response(request, ResponseCode::ServFail);
                return CachedWire::from_message(&servfail, Duration::ZERO, verdict).map(Arc::new);
            }
        };

        let fresh_for = cacheable_for(&response);
        let wire = Arc::new(CachedWire::from_message(&response, fresh_for, verdict)?);
        self.insert(admitted, Arc::clone(&wire));
        Ok(wire)
    }

    fn insert_blocked(&self, admitted: &Admitted, verdict: Verdict) -> Result<Arc<CachedWire>> {
        let response = build_blocked_response(&admitted.request, admitted.policy.block_mode);
        let wire = Arc::new(CachedWire::from_message(
            &response,
            BLOCKED_CACHE_TTL,
            verdict,
        )?);
        bump(&self.stats.blocked_total);
        self.insert(admitted, Arc::clone(&wire));
        Ok(wire)
    }

    /// Cache an answer, unless the policy it was decided under was replaced while it was in
    /// flight.
    ///
    /// Checked after the insert rather than before so there is no window: a swap that bumps
    /// the epoch after this check runs its sweep after this insert, and the sweep takes the
    /// entry; a swap that bumped before is seen here, and the entry is taken back.
    fn insert(&self, admitted: &Admitted, wire: Arc<CachedWire>) {
        self.cache.insert(admitted.key.clone(), wire);
        if self.cache_epoch.load(Ordering::Acquire) != admitted.epoch {
            self.cache.invalidate(&admitted.key);
        }
    }

    fn log(&self, admitted: &Admitted, verdict: Verdict) {
        let verdict = logged_verdict(admitted, verdict);
        let entry = LogEntry {
            ts: admitted.ts,
            client: admitted.client,
            domain: Arc::clone(&admitted.key.domain),
            qtype: admitted.key.qtype,
            verdict,
            list: verdict
                .slot()
                .and_then(|slot| admitted.policy.index.name(slot))
                .cloned(),
        };
        match self.log_tx.try_send(entry) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => bump(&self.stats.log_dropped_total),
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
    Verdict::allow(if admitted.paused {
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
                Verdict::Allow(..) => None,
            }
        })
}

fn cname_target(record: &Record) -> Option<&Name> {
    match &record.data {
        RData::CNAME(target) => Some(&target.0),
        _ => None,
    }
}

/// Spell `name` into `buffer` in the form the cache key and every list entry use: lowercase
/// A-labels joined by dots, with no trailing root dot.
///
/// `None` for a name carrying a byte that [`Name::to_ascii`] would escape — a dot or a control
/// character inside a label — which the caller then spells the allocating way. Escaping is
/// hickory's rule to define, and re-implementing it here to save an allocation on names no stub
/// ever asks for would be the wrong side of that trade.
fn ascii_lowercase<'a>(name: &Name, buffer: &'a mut [u8; MAX_NAME_BYTES]) -> Option<&'a str> {
    let mut written = 0;
    for label in name.iter() {
        if written > 0 {
            *buffer.get_mut(written)? = b'.';
            written += 1;
        }
        for (at, byte) in label.iter().enumerate() {
            if !kept_as_itself(*byte, at == 0) {
                return None;
            }
            *buffer.get_mut(written)? = byte.to_ascii_lowercase();
            written += 1;
        }
    }
    std::str::from_utf8(buffer.get(..written)?).ok()
}

/// Whether `byte` survives hickory's ASCII escaping as itself, per `Label::write_ascii`: the two
/// spellings must agree, or a name would be looked up in a form no list entry has.
fn kept_as_itself(byte: u8, first: bool) -> bool {
    byte.is_ascii_alphanumeric()
        || byte == b'_'
        || (byte == b'-' && !first)
        || (byte == b'*' && first)
}
