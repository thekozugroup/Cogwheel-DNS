//! Runtime tests against a stub upstream on loopback: no network, no real resolver.
//!
//! The stub answers from a fixed zone, or SERVFAILs, or never replies, switched per test. The
//! runtime under test is driven through a real UDP socket so the receive loop, the miss hand-off
//! and the header patching are all exercised exactly as in production.

use super::*;
use crate::response::MAX_CACHE_TTL;
use crate::serve::{patch_header, wire_for};
use cogwheel_policy::{Action, ListIndex, Pattern, RuleSet, SCOPE_HOUSEHOLD, Scope};
use hickory_proto::op::{Edns, MessageType, Query};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicUsize};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const ANSWER: u8 = 0;
const SERVFAIL: u8 = 1;
const HANG: u8 = 2;

type Zone = HashMap<(String, RecordType), Vec<Record>>;

pub(crate) fn name(owner: &str) -> Name {
    Name::from_ascii(format!("{owner}.")).expect("valid test name")
}

fn a(owner: &str, address: [u8; 4]) -> Record {
    Record::from_rdata(name(owner), 300, RData::A(A(Ipv4Addr::from(address))))
}

fn aaaa(owner: &str, address: Ipv6Addr) -> Record {
    Record::from_rdata(name(owner), 300, RData::AAAA(AAAA(address)))
}

fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
}

fn zone(records: &[(&str, RecordType, Vec<Record>)]) -> Zone {
    records
        .iter()
        .map(|(owner, qtype, records)| (((*owner).to_string(), *qtype), records.clone()))
        .collect()
}

fn v4(response: &Message) -> Vec<Ipv4Addr> {
    response
        .answers
        .iter()
        .filter_map(|record| match record.data {
            RData::A(A(address)) => Some(address),
            _ => None,
        })
        .collect()
}

/// A policy with one list (slot 0) blocking `blocked`, the given household rules, and
/// `block_mode` `null_ip`.
pub(crate) fn policy(
    blocked: &[&str],
    household: &[(&str, Action)],
    by_ip: HashMap<IpAddr, Scope>,
) -> Arc<Policy> {
    let mut builder = ListIndex::builder();
    builder.name(0, "test list");
    for domain in blocked {
        builder.insert(0, Action::Block, Pattern::Suffix, domain);
    }
    let rules: RuleSet = household
        .iter()
        .map(|(domain, action)| (*domain, *action))
        .collect();
    Arc::new(Policy::new(
        Arc::new(builder.build()),
        Arc::new(rules),
        by_ip,
        0b1,
        BlockMode::NullIp,
    ))
}

pub(crate) fn resolver_for(upstream: SocketAddr) -> TokioResolver {
    let mut udp = ConnectionConfig::udp();
    udp.port = upstream.port();
    let name_server = NameServerConfig::new(upstream.ip(), true, vec![udp]);
    let config = ResolverConfig::from_parts(None, vec![], vec![name_server]);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(resolver_options())
        .build()
        .expect("resolver against the stub")
}

struct Stub {
    addr: SocketAddr,
    mode: Arc<AtomicU8>,
    queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Stub {
    async fn spawn(zone: Zone) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = socket.local_addr().expect("stub address");
        let mode = Arc::new(AtomicU8::new(ANSWER));
        let queries = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(Self::serve(
            socket,
            zone,
            Arc::clone(&mode),
            Arc::clone(&queries),
        ));
        Self {
            addr,
            mode,
            queries,
            task,
        }
    }

    async fn serve(socket: UdpSocket, zone: Zone, mode: Arc<AtomicU8>, queries: Arc<AtomicUsize>) {
        let mut buffer = [0u8; UDP_BUFFER];
        loop {
            let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(request) = Message::from_vec(&buffer[..size]) else {
                continue;
            };
            let Some(query) = request.queries.first() else {
                continue;
            };
            queries.fetch_add(1, Ordering::Relaxed);
            let response = match mode.load(Ordering::Relaxed) {
                HANG => continue,
                SERVFAIL => build_base_response(&request, ResponseCode::ServFail),
                _ => {
                    let mut response = build_base_response(&request, ResponseCode::NoError);
                    let owner = normalize_domain(&query.name().to_utf8());
                    if let Some(records) = zone.get(&(owner, query.query_type())) {
                        for record in records {
                            response.add_answer(record.clone());
                        }
                    }
                    response
                }
            };
            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::Relaxed);
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Harness {
    runtime: Arc<DnsRuntime>,
    server: SocketAddr,
    client: UdpSocket,
    stub: Stub,
    log_rx: mpsc::Receiver<LogEntry>,
    _shutdown: watch::Sender<bool>,
    next_id: AtomicU16,
}

impl Harness {
    async fn start(zone: Zone, policy: Arc<Policy>) -> Self {
        let stub = Stub::spawn(zone).await;
        let (runtime, log_rx) = DnsRuntime::new(resolver_for(stub.addr), policy);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind server"));
        let server = socket.local_addr().expect("server address");
        let (shutdown, shutdown_rx) = watch::channel(false);
        tokio::spawn(Arc::clone(&runtime).recv_loop(socket, shutdown_rx));
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        Self {
            runtime,
            server,
            client,
            stub,
            log_rx,
            _shutdown: shutdown,
            next_id: AtomicU16::new(1),
        }
    }

    fn request(&self, owner: &str, qtype: RecordType, edns_max: Option<u16>) -> Message {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = Message::new(id, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name(owner), qtype));
        if let Some(max_payload) = edns_max {
            let mut edns = Edns::new();
            edns.set_max_payload(max_payload);
            request.set_edns(edns);
        }
        request
    }

    async fn send(&self, request: &Message) {
        self.client
            .send_to(&request.to_vec().expect("encode query"), self.server)
            .await
            .expect("send query");
    }

    /// Send one query and return the raw answer bytes.
    async fn query_raw(&self, owner: &str, qtype: RecordType, edns_max: Option<u16>) -> Vec<u8> {
        let request = self.request(owner, qtype, edns_max);
        self.send(&request).await;
        let mut buffer = [0u8; 65_535];
        loop {
            let (size, _) = timeout(Duration::from_secs(10), self.client.recv_from(&mut buffer))
                .await
                .expect("an answer within 10 s")
                .expect("receive answer");
            let bytes = buffer[..size].to_vec();
            // A late SERVFAIL for an earlier query that hung upstream can arrive first.
            if Message::from_vec(&bytes)
                .is_ok_and(|answer| answer.metadata.id == request.metadata.id)
            {
                return bytes;
            }
        }
    }

    async fn query(&self, owner: &str, qtype: RecordType) -> Message {
        Message::from_vec(&self.query_raw(owner, qtype, None).await).expect("parse answer")
    }

    async fn next_log(&mut self) -> LogEntry {
        timeout(Duration::from_secs(5), self.log_rx.recv())
            .await
            .expect("a log entry within 5 s")
            .expect("log channel open")
    }

    fn key(owner: &str, qtype: RecordType) -> CacheKey {
        CacheKey {
            scope: SCOPE_HOUSEHOLD,
            qtype: u16::from(qtype),
            domain: Arc::from(owner),
        }
    }

    /// Age a cached entry past its freshness without waiting for it.
    fn expire(&self, key: &CacheKey) {
        let entry = self.runtime.cache.get(key).expect("entry is cached");
        let stale = CachedWire {
            bytes: entry.bytes.clone(),
            truncated: entry.truncated.clone(),
            fresh_until: Instant::now(),
            stale_until: entry.stale_until,
            blocked: entry.blocked,
            verdict: entry.verdict,
        };
        self.runtime.cache.insert(key.clone(), Arc::new(stale));
    }
}

/// The reason the key carries the query type: a bare-name key answered the AAAA query that
/// follows every A query with the A records, which is a dual-stack household's worst bug.
#[tokio::test]
async fn aaaa_after_a_never_returns_a_records() {
    let zone = zone(&[
        (
            "dual.test",
            RecordType::A,
            vec![a("dual.test", [192, 0, 2, 1])],
        ),
        (
            "dual.test",
            RecordType::AAAA,
            vec![aaaa("dual.test", "2001:db8::1".parse().expect("v6"))],
        ),
    ]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    let by_a = harness.query("dual.test", RecordType::A).await;
    assert_eq!(v4(&by_a), vec![Ipv4Addr::new(192, 0, 2, 1)]);

    let by_aaaa = harness.query("dual.test", RecordType::AAAA).await;
    assert_eq!(by_aaaa.answers.len(), 1, "{:?}", by_aaaa.answers);
    assert!(
        by_aaaa
            .answers
            .iter()
            .all(|record| matches!(record.data, RData::AAAA(_))),
        "{:?}",
        by_aaaa.answers
    );
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 0);
}

/// The alias is read out of the answer the upstream already gave, so blocking a cloaked
/// tracker costs the same one round trip as resolving it.
#[tokio::test]
async fn a_cname_to_a_blocked_target_is_blocked_with_reason_cname() {
    let zone = zone(&[(
        "alias.test",
        RecordType::A,
        vec![
            cname("alias.test", "tracker.test"),
            a("tracker.test", [192, 0, 2, 9]),
        ],
    )]);
    let mut harness = Harness::start(zone, policy(&["tracker.test"], &[], HashMap::new())).await;

    let response = harness.query("alias.test", RecordType::A).await;
    assert_eq!(v4(&response), vec![Ipv4Addr::UNSPECIFIED]);
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.cname_blocks_total, 1);
    assert_eq!(snapshot.blocked_total, 1);
    assert_eq!(snapshot.upstream_failures_total, 0);
    let logged = harness.next_log().await;
    assert_eq!(logged.verdict, Verdict::Block(Reason::Cname, 0));
    assert_eq!(
        logged.list.as_deref(),
        Some("test list"),
        "Activity has to be able to say which list the alias matched"
    );

    // The block is cached like any other, so the second query never reaches the upstream.
    harness.query("alias.test", RecordType::A).await;
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 1);
    assert_eq!(harness.runtime.snapshot().blocked_total, 2);
}

/// §6 step 11 sits below steps 4 to 10, and end to end is where that shows: the re-check runs
/// only for a name nothing earlier had an opinion about, and what it runs against the target is
/// steps 8 to 10 — so a protected target is spared there too.
#[tokio::test]
async fn the_cname_recheck_runs_only_below_the_steps_above_it() {
    let zone = zone(&[
        (
            "allowed.test",
            RecordType::A,
            vec![
                cname("allowed.test", "tracker.test"),
                a("tracker.test", [192, 0, 2, 9]),
            ],
        ),
        (
            "clock.test",
            RecordType::A,
            vec![
                cname("clock.test", "ntp.time.apple.com"),
                a("ntp.time.apple.com", [192, 0, 2, 10]),
            ],
        ),
    ]);
    let mut harness = Harness::start(
        zone,
        policy(
            &["tracker.test", "time.apple.com"],
            &[("allowed.test", Action::Allow)],
            HashMap::new(),
        ),
    )
    .await;

    // Step 6 decided this name, so the alias behind it is never looked at: a rule is about the
    // name a person typed, and re-checking it would make an explicit allow mean nothing.
    let allowed = harness.query("allowed.test", RecordType::A).await;
    assert_eq!(v4(&allowed), vec![Ipv4Addr::new(192, 0, 2, 9)]);
    assert_eq!(
        harness.next_log().await.verdict,
        Verdict::allow(Reason::HouseholdRule)
    );

    // Nothing matched this one, so the re-check does run — and finds a protected target, which
    // step 8 spares however wrong the subscribed list is about it.
    let protected = harness.query("clock.test", RecordType::A).await;
    assert_eq!(v4(&protected), vec![Ipv4Addr::new(192, 0, 2, 10)]);
    assert_eq!(
        harness.next_log().await.verdict,
        Verdict::allow(Reason::NoMatch)
    );
    assert_eq!(harness.runtime.snapshot().cname_blocks_total, 0);
}

/// An unknown client and a device whose settings equal the household's produce the same key,
/// so a family of default devices shares one set of answers.
#[tokio::test]
async fn the_household_scope_is_shared_by_unknown_clients_and_default_devices() {
    let device: IpAddr = "10.0.0.5".parse().expect("ip");
    let bypassed: IpAddr = "10.0.0.6".parse().expect("ip");
    let unknown: IpAddr = "192.168.1.77".parse().expect("ip");
    let mut by_ip = HashMap::new();
    by_ip.insert(device, Scope::household(0b1));
    by_ip.insert(bypassed, Scope::unfiltered());
    let zone = zone(&[(
        "shared.test",
        RecordType::A,
        vec![a("shared.test", [192, 0, 2, 3])],
    )]);
    let harness = Harness::start(zone, policy(&[], &[], by_ip)).await;
    let payload = harness
        .request("shared.test", RecordType::A, None)
        .to_vec()
        .expect("encode");
    let admit = |client| {
        harness
            .runtime
            .admit(&payload, client, Instant::now())
            .expect("a well-formed query is admitted")
    };

    let from_unknown = admit(unknown);
    let from_device = admit(device);
    assert_eq!(from_unknown.key, from_device.key);
    assert_eq!(from_device.key.scope, SCOPE_HOUSEHOLD);

    let from_bypassed = admit(bypassed);
    assert_eq!(from_bypassed.key.scope, SCOPE_UNFILTERED);
    assert!(!from_bypassed.paused);

    harness.runtime.set_pause_until(u64::MAX);
    let while_paused = admit(device);
    assert_eq!(while_paused.key.scope, SCOPE_UNFILTERED);
    assert!(while_paused.paused);
    harness.runtime.set_pause_until(0);

    // The key is what the cache is probed with: a second query under it is a hit.
    harness.query("shared.test", RecordType::A).await;
    harness.query("shared.test", RecordType::A).await;
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 1);
}

#[tokio::test]
async fn a_blocked_cache_hit_counts_as_a_block() {
    let harness = Harness::start(
        Zone::new(),
        policy(&[], &[("ads.test", Action::Block)], HashMap::new()),
    )
    .await;
    let mut harness = harness;

    for _ in 0..2 {
        let response = harness.query("ads.test", RecordType::A).await;
        assert_eq!(v4(&response), vec![Ipv4Addr::UNSPECIFIED]);
        assert_eq!(
            harness.next_log().await.verdict,
            Verdict::Block(Reason::HouseholdRule, 0)
        );
    }
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.queries_total, 2);
    assert_eq!(snapshot.cache_hits_total, 1);
    assert_eq!(snapshot.blocked_total, 2);
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 0);
}

/// An expired entry is a miss while the upstream answers, and the answer while it does not.
#[tokio::test]
async fn a_stale_entry_is_served_only_after_the_upstream_errors() {
    let zone = zone(&[(
        "stale.test",
        RecordType::A,
        vec![a("stale.test", [192, 0, 2, 1])],
    )]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;
    let key = Harness::key("stale.test", RecordType::A);

    let first = harness.query("stale.test", RecordType::A).await;
    assert_eq!(v4(&first), vec![Ipv4Addr::new(192, 0, 2, 1)]);

    // Expired, upstream healthy: refreshed from upstream, nothing served stale.
    harness.expire(&key);
    harness.query("stale.test", RecordType::A).await;
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.cache_expired_total, 1);
    assert_eq!(snapshot.stale_served_total, 0);
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 2);

    // Expired, upstream failing: the old answer beats SERVFAIL.
    harness.expire(&key);
    harness.stub.set_mode(SERVFAIL);
    let during_outage = harness.query("stale.test", RecordType::A).await;
    assert_eq!(during_outage.metadata.response_code, ResponseCode::NoError);
    assert_eq!(v4(&during_outage), vec![Ipv4Addr::new(192, 0, 2, 1)]);
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.upstream_failures_total, 1);
    assert_eq!(snapshot.stale_served_total, 1);

    // Served stale, the entry is fresh again for a while: the next query is a hit answered
    // inline, not another wait on the failing upstream.
    let stub_queries = harness.stub.queries.load(Ordering::Relaxed);
    let again = harness.query("stale.test", RecordType::A).await;
    assert_eq!(v4(&again), vec![Ipv4Addr::new(192, 0, 2, 1)]);
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.cache_hits_total, 1);
    assert_eq!(snapshot.upstream_failures_total, 1);
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), stub_queries);

    // A name never seen has nothing to fall back to.
    let unknown = harness.query("never.test", RecordType::A).await;
    assert_eq!(unknown.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(harness.runtime.snapshot().stale_served_total, 1);
}

/// A client without EDNS gets a 512-byte datagram with TC set and retries over TCP; a client
/// that advertised room gets the whole answer. Both from the same cached entry.
#[tokio::test]
async fn large_answers_are_truncated_for_plain_udp_clients() {
    let records = (1..=40u8)
        .map(|host| a("big.test", [192, 0, 2, host]))
        .collect();
    let zone = zone(&[("big.test", RecordType::A, records)]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    let plain = harness.query_raw("big.test", RecordType::A, None).await;
    let plain_message = Message::from_vec(&plain).expect("parse");
    assert!(
        plain.len() <= MAX_PLAIN_UDP_PAYLOAD,
        "{} bytes",
        plain.len()
    );
    assert!(plain_message.metadata.truncation);
    assert!(plain_message.answers.is_empty());

    let with_edns = harness
        .query_raw("big.test", RecordType::A, Some(4096))
        .await;
    let edns_message = Message::from_vec(&with_edns).expect("parse");
    assert!(with_edns.len() > MAX_PLAIN_UDP_PAYLOAD);
    assert!(!edns_message.metadata.truncation);
    assert_eq!(v4(&edns_message).len(), 40);

    let plain_again = harness.query_raw("big.test", RecordType::A, None).await;
    assert!(
        Message::from_vec(&plain_again)
            .expect("parse")
            .metadata
            .truncation
    );
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 2);
}

/// The property the whole listener design exists for: a miss waiting on a dead upstream holds
/// a task and a permit, never the receive loop.
#[tokio::test]
async fn a_hung_upstream_does_not_delay_a_cache_hit() {
    let zone = zone(&[(
        "fast.test",
        RecordType::A,
        vec![a("fast.test", [192, 0, 2, 5])],
    )]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;
    harness.query("fast.test", RecordType::A).await;

    harness.stub.set_mode(HANG);
    harness
        .send(&harness.request("hang.test", RecordType::A, None))
        .await;

    let mut fastest = Duration::MAX;
    for _ in 0..5 {
        let started = Instant::now();
        let response = harness.query("fast.test", RecordType::A).await;
        fastest = fastest.min(started.elapsed());
        assert_eq!(v4(&response), vec![Ipv4Addr::new(192, 0, 2, 5)]);
    }
    assert!(fastest < Duration::from_millis(5), "hit took {fastest:?}");
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 5);
}

/// Lists carry internationalised names as `xn--` labels, exactly as they travel on the wire;
/// the key must keep that form or no such entry can ever match.
#[tokio::test]
async fn an_a_label_list_entry_blocks_the_query_for_it() {
    let mut harness = Harness::start(
        Zone::new(),
        policy(&["xn--80ak6aa92e.test"], &[], HashMap::new()),
    )
    .await;
    let payload = harness
        .request("XN--80AK6AA92E.test", RecordType::A, None)
        .to_vec()
        .expect("encode");
    let admitted = harness
        .runtime
        .admit(&payload, "10.0.0.9".parse().expect("ip"), Instant::now())
        .expect("admitted");
    assert_eq!(&*admitted.key.domain, "xn--80ak6aa92e.test");

    let response = harness.query("xn--80ak6aa92e.test", RecordType::A).await;
    assert_eq!(v4(&response), vec![Ipv4Addr::UNSPECIFIED]);
    assert_eq!(
        harness.next_log().await.verdict,
        Verdict::Block(Reason::List, 0)
    );
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 0);
}

/// A miss that read the old policy and is still waiting on the upstream when the policy is
/// swapped must not land its verdict after the sweep, or the household serves it for an hour.
#[tokio::test]
async fn a_policy_swap_during_a_miss_does_not_cache_the_old_verdict() {
    let zone = zone(&[(
        "late.test",
        RecordType::A,
        vec![a("late.test", [192, 0, 2, 7])],
    )]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    // The miss goes out under a policy that allows the name, and parks on a silent upstream.
    harness.stub.set_mode(HANG);
    let parked = harness.request("late.test", RecordType::A, None);
    harness.send(&parked).await;
    timeout(Duration::from_secs(2), async {
        while harness.stub.queries.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the miss reached the upstream");

    harness
        .runtime
        .swap_policy(policy(&[], &[("late.test", Action::Block)], HashMap::new()));
    // The upstream's retry now answers, and the parked miss completes under the old policy.
    harness.stub.set_mode(ANSWER);
    let mut buffer = [0u8; 512];
    let (size, _) = timeout(
        Duration::from_secs(5),
        harness.client.recv_from(&mut buffer),
    )
    .await
    .expect("the parked miss is answered")
    .expect("receive");
    let late = Message::from_vec(&buffer[..size]).expect("parse");
    assert_eq!(late.metadata.id, parked.metadata.id);
    assert_eq!(v4(&late), vec![Ipv4Addr::new(192, 0, 2, 7)]);

    let next = harness.query("late.test", RecordType::A).await;
    assert_eq!(v4(&next), vec![Ipv4Addr::UNSPECIFIED]);
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 0);
}

#[tokio::test]
async fn runtime_snapshot_starts_at_zero() {
    let (runtime, _log_rx) = DnsRuntime::new(
        resolver_for("127.0.0.1:1".parse().expect("addr")),
        Arc::new(Policy::empty(BlockMode::NullIp)),
    );
    assert_eq!(
        runtime.snapshot(),
        DnsRuntimeSnapshot {
            queries_total: 0,
            blocked_total: 0,
            cache_hits_total: 0,
            cache_expired_total: 0,
            upstream_failures_total: 0,
            stale_served_total: 0,
            cname_blocks_total: 0,
            dropped_total: 0,
            log_dropped_total: 0,
            cache_hit_latency_avg_ns: 0,
            cache_hit_samples: 0,
            cache_miss_latency_avg_ns: 0,
            cache_miss_samples: 0,
        }
    );
    assert_eq!(runtime.pause_until(), 0);
    assert_eq!(runtime.block_mode(), BlockMode::NullIp);
}

#[test]
fn patch_header_sets_the_id_and_the_rd_bit() {
    let mut bytes = [0x00, 0x00, 0x80, 0x00];
    patch_header(&mut bytes, 0x1234, true);
    assert_eq!(bytes, [0x12, 0x34, 0x81, 0x00]);
    patch_header(&mut bytes, 0xabcd, false);
    assert_eq!(bytes, [0xab, 0xcd, 0x80, 0x00]);
}

#[test]
fn the_truncated_form_is_sent_only_when_the_answer_cannot_fit() {
    let mut request = Message::new(7, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(name("big.test"), RecordType::A));
    let mut response = build_base_response(&request, ResponseCode::NoError);
    for host in 1..=40u8 {
        response.add_answer(a("big.test", [192, 0, 2, host]));
    }
    let entry = CachedWire::from_message(&response, MAX_CACHE_TTL, Verdict::allow(Reason::NoMatch))
        .expect("encode");
    assert!(entry.bytes.len() > MAX_PLAIN_UDP_PAYLOAD);
    let truncated = entry.truncated.as_ref().expect("a TC form was precomputed");

    assert_eq!(&wire_for(&entry, &request, 512)[..], &truncated[..]);
    assert_eq!(&wire_for(&entry, &request, 4096)[..], &entry.bytes[..]);
    assert_eq!(
        &wire_for(&entry, &request, usize::MAX)[..],
        &entry.bytes[..]
    );

    let small = build_base_response(&request, ResponseCode::NXDomain);
    let small = CachedWire::from_message(&small, MAX_CACHE_TTL, Verdict::allow(Reason::NoMatch))
        .expect("encode");
    assert!(small.truncated.is_none());
    assert_eq!(&wire_for(&small, &request, 512)[..], &small.bytes[..]);
}

/// The stack-buffer spelling and hickory's own must agree on every name a stub can ask for, or
/// the key would carry a form no list entry has.
#[test]
fn the_name_written_into_the_key_matches_hickorys_ascii_form() {
    let mut buffer = [0u8; MAX_NAME_BYTES];
    for owner in [
        "Ads.Example.COM.",
        "xn--80ak6aa92e.test",
        "_dmarc.example.com",
        "*.example.com",
        "com",
    ] {
        let parsed = Name::from_ascii(owner).expect("valid test name");
        let mut spelled = parsed.to_ascii();
        spelled.make_ascii_lowercase();
        let expected = spelled.trim_end_matches('.');
        assert_eq!(
            ascii_lowercase(&parsed, &mut buffer),
            Some(expected),
            "{owner}"
        );
    }

    // A label carrying a byte hickory escapes is spelled the allocating way instead, because
    // agreeing with `to_ascii` matters more than saving the allocation on a name nothing asks for.
    let escaped = Name::from_ascii("a\\.b.test.").expect("valid test name");
    assert_eq!(
        escaped.iter().count(),
        2,
        "the dot is inside the first label"
    );
    assert_eq!(ascii_lowercase(&escaped, &mut buffer), None);
}

#[test]
fn cname_targets_are_checked_against_the_list_tier_only() {
    let policy = policy(&["tracker.test", "time.apple.com"], &[], HashMap::new());
    let blocked = [cname("alias.test", "cdn.tracker.test")];
    assert_eq!(
        cname_block(&policy, policy.all_mask, &blocked),
        Some(Verdict::Block(Reason::Cname, 0))
    );
    // A protected target is an allow even when a list names it; a mask without the list
    // does not see the entry at all.
    let protected = [cname("alias.test", "ntp.time.apple.com")];
    assert_eq!(cname_block(&policy, policy.all_mask, &protected), None);
    assert_eq!(cname_block(&policy, 0, &blocked), None);
    let plain = [a("alias.test", [192, 0, 2, 1])];
    assert_eq!(cname_block(&policy, policy.all_mask, &plain), None);
}

#[test]
fn extract_cname_target_reads_record_data() {
    let record = cname("alias.example.com", "tracker.example.com");
    assert_eq!(cname_target(&record), Some(&name("tracker.example.com")));
    assert_eq!(cname_target(&a("alias.example.com", [192, 0, 2, 1])), None);
}

#[test]
fn hot_path_crates_remain_llm_and_network_independent() {
    let dns_core_manifest =
        std::fs::read_to_string(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR")))
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
