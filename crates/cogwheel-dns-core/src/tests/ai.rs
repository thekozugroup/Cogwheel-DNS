//! The AI list (ADR 0002) through the runtime: its tier on a miss, where it stops in the CNAME
//! re-check, and the install that drops only the answers for the names whose verdict changed.
//!
//! A child of `tests` so it can drive the same private `Harness` and stub upstream.

use super::*;
use cogwheel_policy::AiList;
use std::collections::HashSet;

/// `policy` with `verdicts` as its AI list.
fn with_ai(policy: Arc<Policy>, verdicts: &[(&str, Action)]) -> Arc<Policy> {
    let ai: AiList = verdicts.iter().copied().collect();
    Arc::new(Arc::unwrap_or_clone(policy).with_ai(Arc::new(ai)))
}

fn changed(names: &[&str]) -> HashSet<Box<str>> {
    names.iter().map(|name| Box::from(*name)).collect()
}

/// Put an answer in the cache the way a real miss does, for a client the harness socket is not.
async fn fill(harness: &Harness, owner: &str, qtype: RecordType, client: IpAddr) {
    let payload = harness
        .request(owner, qtype, None)
        .to_vec()
        .expect("encode");
    let admitted = harness
        .runtime
        .admit(&payload, client, Instant::now())
        .expect("a well-formed query is admitted");
    let verdict = harness.runtime.decide(&admitted);
    harness
        .runtime
        .resolve_miss(&admitted, verdict, None)
        .await
        .expect("resolved against the stub");
}

fn key(scope: u32, owner: &str, qtype: RecordType) -> CacheKey {
    CacheKey {
        scope,
        qtype: u16::from(qtype),
        domain: Arc::from(owner),
    }
}

/// Every shard's eviction queue holds exactly its entries' keys, once each. A key a sweep left
/// in `order` is queued again when its name is next answered, and eviction then pops the stale
/// copy and takes the live entry early.
fn assert_order_matches_entries(cache: &WireCache) {
    for shard in &cache.shards {
        let shard = read_recover(shard);
        let queued: HashSet<&CacheKey> = shard.order.iter().collect();
        assert_eq!(
            shard.order.len(),
            shard.entries.len(),
            "one queue slot per entry"
        );
        assert_eq!(
            queued,
            shard.entries.keys().collect(),
            "the queue is the entries' keys"
        );
    }
}

/// A block is decided from the question alone, so an AI block is as cheap as a list's.
#[tokio::test]
async fn an_ai_blocked_name_is_answered_without_the_upstream() {
    let zone = zone(&[(
        "pixel.test",
        RecordType::A,
        vec![a("pixel.test", [192, 0, 2, 4])],
    )]);
    let policy = with_ai(
        policy(&[], &[], HashMap::new()),
        &[("pixel.test", Action::Block)],
    );
    let mut harness = Harness::start(zone, policy).await;

    let response = harness.query("pixel.test", RecordType::A).await;
    assert_eq!(v4(&response), vec![Ipv4Addr::UNSPECIFIED]);
    let logged = harness.next_log().await;
    assert_eq!(logged.verdict, Verdict::Block(Reason::Ai, 0));
    assert_eq!(logged.list, None, "the AI list is not a list slot");
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 0);
    assert_eq!(harness.runtime.snapshot().blocked_total, 1);
}

/// D4: the model judged the name, not the aliases behind it. Its allow lifts the list's block on
/// the name, and the list still gets to block the tracker the name turns out to point at.
#[tokio::test]
async fn an_ai_allow_over_a_list_block_resolves_and_still_rechecks_its_aliases() {
    let zone = zone(&[(
        "shop.test",
        RecordType::A,
        vec![
            cname("shop.test", "metrics.tracker.test"),
            a("metrics.tracker.test", [192, 0, 2, 9]),
        ],
    )]);
    let policy = with_ai(
        policy(&["shop.test", "tracker.test"], &[], HashMap::new()),
        &[("shop.test", Action::Allow)],
    );
    let mut harness = Harness::start(zone, policy).await;

    let response = harness.query("shop.test", RecordType::A).await;
    assert_eq!(v4(&response), vec![Ipv4Addr::UNSPECIFIED]);
    let logged = harness.next_log().await;
    assert_eq!(logged.verdict, Verdict::Block(Reason::Cname, 0));
    assert_eq!(logged.list.as_deref(), Some("test list"));
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 1);
    assert_eq!(harness.runtime.snapshot().cname_blocks_total, 1);
}

#[tokio::test]
async fn an_ai_allow_without_a_listed_alias_resolves_as_ai() {
    let zone = zone(&[(
        "shop.test",
        RecordType::A,
        vec![
            cname("shop.test", "edge.cdn.test"),
            a("edge.cdn.test", [192, 0, 2, 8]),
        ],
    )]);
    let policy = with_ai(
        policy(&["shop.test"], &[], HashMap::new()),
        &[("shop.test", Action::Allow)],
    );
    let mut harness = Harness::start(zone, policy).await;

    let response = harness.query("shop.test", RecordType::A).await;
    assert_eq!(v4(&response), vec![Ipv4Addr::new(192, 0, 2, 8)]);
    let logged = harness.next_log().await;
    assert_eq!(logged.verdict, Verdict::allow(Reason::Ai));
    assert_eq!(logged.list, None);
    assert_eq!(harness.runtime.snapshot().cname_blocks_total, 0);
}

/// D1, the cost it accepts: the AI tier is not part of the re-check, so an AI block on a name
/// reached only as an alias is not enforced through it. That is what keeps every cached answer
/// dependent on its own name's AI verdict alone, and so the exact-name sweep complete.
#[tokio::test]
async fn a_cname_target_the_ai_list_blocks_is_left_to_the_lists() {
    let zone = zone(&[(
        "alias.test",
        RecordType::A,
        vec![
            cname("alias.test", "pixel.test"),
            a("pixel.test", [192, 0, 2, 9]),
        ],
    )]);
    let policy = with_ai(
        policy(&[], &[], HashMap::new()),
        &[("pixel.test", Action::Block)],
    );
    let mut harness = Harness::start(zone, policy).await;

    let alias = harness.query("alias.test", RecordType::A).await;
    assert_eq!(v4(&alias), vec![Ipv4Addr::new(192, 0, 2, 9)]);
    assert_eq!(
        harness.next_log().await.verdict,
        Verdict::allow(Reason::NoMatch)
    );
    assert_eq!(harness.runtime.snapshot().cname_blocks_total, 0);

    // Asked for by name, the same target is the AI list's to block.
    let direct = harness.query("pixel.test", RecordType::A).await;
    assert_eq!(v4(&direct), vec![Ipv4Addr::UNSPECIFIED]);
    assert_eq!(
        harness.next_log().await.verdict,
        Verdict::Block(Reason::Ai, 0)
    );
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_invalidating_swap_drops_only_the_changed_names() {
    let device: IpAddr = "10.0.0.5".parse().expect("ip");
    let device_scope = Scope {
        id: 2,
        filtering: true,
        mask: 0b1,
        rules: None,
    };
    let by_ip = HashMap::from([(device, device_scope)]);
    let zone = zone(&[
        (
            "changed.test",
            RecordType::A,
            vec![a("changed.test", [192, 0, 2, 1])],
        ),
        (
            "changed.test",
            RecordType::AAAA,
            vec![aaaa("changed.test", "2001:db8::1".parse().expect("v6"))],
        ),
        (
            "www.changed.test",
            RecordType::A,
            vec![a("www.changed.test", [192, 0, 2, 2])],
        ),
        (
            "steady.test",
            RecordType::A,
            vec![a("steady.test", [192, 0, 2, 3])],
        ),
    ]);
    let harness = Harness::start(zone, policy(&[], &[], by_ip.clone())).await;
    let household: IpAddr = "10.0.0.9".parse().expect("ip");
    for client in [household, device] {
        fill(&harness, "changed.test", RecordType::A, client).await;
        fill(&harness, "changed.test", RecordType::AAAA, client).await;
        fill(&harness, "steady.test", RecordType::A, client).await;
    }
    fill(&harness, "www.changed.test", RecordType::A, household).await;
    let dropped_keys = [
        key(SCOPE_HOUSEHOLD, "changed.test", RecordType::A),
        key(SCOPE_HOUSEHOLD, "changed.test", RecordType::AAAA),
        key(2, "changed.test", RecordType::A),
        key(2, "changed.test", RecordType::AAAA),
    ];
    let kept_keys = [
        key(SCOPE_HOUSEHOLD, "steady.test", RecordType::A),
        key(2, "steady.test", RecordType::A),
        // Exact names only: the AI list's verdict on a name says nothing about the names below it.
        key(SCOPE_HOUSEHOLD, "www.changed.test", RecordType::A),
    ];
    for cached in dropped_keys.iter().chain(&kept_keys) {
        assert!(harness.runtime.cache.get(cached).is_some(), "{cached:?}");
    }

    let next = with_ai(policy(&[], &[], by_ip), &[("changed.test", Action::Block)]);
    let dropped = harness
        .runtime
        .swap_policy_invalidating(next, &changed(&["changed.test"]));
    assert_eq!(dropped, 4, "both types under both scopes");
    for gone in &dropped_keys {
        assert!(harness.runtime.cache.get(gone).is_none(), "{gone:?}");
    }
    for kept in &kept_keys {
        assert!(harness.runtime.cache.get(kept).is_some(), "{kept:?}");
    }
    assert_order_matches_entries(&harness.runtime.cache);

    // The unrelated name is still a hit; the changed one is decided afresh under the new list.
    let asked = harness.stub.queries.load(Ordering::Relaxed);
    let steady = harness.query("steady.test", RecordType::A).await;
    assert_eq!(v4(&steady), vec![Ipv4Addr::new(192, 0, 2, 3)]);
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 1);
    let decided = harness.query("changed.test", RecordType::A).await;
    assert_eq!(v4(&decided), vec![Ipv4Addr::UNSPECIFIED]);
    assert_eq!(harness.stub.queries.load(Ordering::Relaxed), asked);
    // Answered again, the name is queued once, not behind a copy the sweep left.
    assert_order_matches_entries(&harness.runtime.cache);
}

/// The twin of `a_policy_swap_during_a_miss_does_not_cache_the_old_verdict`: the targeted swap
/// bumps the epoch before it sweeps, so a miss that read the old AI list cannot land after it.
#[tokio::test]
async fn an_invalidating_swap_during_a_miss_does_not_cache_the_old_verdict() {
    let zone = zone(&[(
        "late.test",
        RecordType::A,
        vec![a("late.test", [192, 0, 2, 7])],
    )]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    // The miss goes out under an AI list that does not name it, and parks on a silent upstream.
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

    let next = with_ai(
        policy(&[], &[], HashMap::new()),
        &[("late.test", Action::Block)],
    );
    let dropped = harness
        .runtime
        .swap_policy_invalidating(next, &changed(&["late.test"]));
    assert_eq!(
        dropped, 0,
        "nothing is cached yet: only the epoch can catch this miss"
    );
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
    // The late entry was taken back by key, and the block that replaced it is queued once.
    assert_order_matches_entries(&harness.runtime.cache);
}

/// An install that changes one name must not cost a miss for another name its entry. When that
/// miss is the refresh of an expired answer during an outage, the entry is the stale answer the
/// name falls back to, and without it every later query for the name is SERVFAIL until the
/// upstream returns.
#[tokio::test]
async fn an_invalidating_swap_keeps_the_stale_fallback_of_another_name() {
    let zone = zone(&[(
        "stale.test",
        RecordType::A,
        vec![a("stale.test", [192, 0, 2, 1])],
    )]);
    let harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;
    let key = Harness::key("stale.test", RecordType::A);
    harness.query("stale.test", RecordType::A).await;
    harness.expire(&key);

    // The refresh parks on a silent upstream, holding the expired answer as its fallback.
    harness.stub.set_mode(HANG);
    let parked = harness.request("stale.test", RecordType::A, None);
    harness.send(&parked).await;
    timeout(Duration::from_secs(2), async {
        while harness.stub.queries.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the refresh reached the upstream");

    let next = with_ai(
        policy(&[], &[], HashMap::new()),
        &[("unrelated.test", Action::Block)],
    );
    harness
        .runtime
        .swap_policy_invalidating(next, &changed(&["unrelated.test"]));
    // The upstream's retry now fails outright, and the refresh falls back to the stale answer.
    harness.stub.set_mode(SERVFAIL);
    let mut buffer = [0u8; 512];
    let (size, _) = timeout(
        Duration::from_secs(5),
        harness.client.recv_from(&mut buffer),
    )
    .await
    .expect("the parked refresh is answered")
    .expect("receive");
    let fallback = Message::from_vec(&buffer[..size]).expect("parse");
    assert_eq!(fallback.metadata.id, parked.metadata.id);
    assert_eq!(v4(&fallback), vec![Ipv4Addr::new(192, 0, 2, 1)]);
    assert_eq!(harness.runtime.snapshot().stale_served_total, 1);

    assert!(
        harness.runtime.cache.get(&key).is_some(),
        "the stale answer is still cached"
    );
    let again = harness.query("stale.test", RecordType::A).await;
    assert_eq!(again.metadata.response_code, ResponseCode::NoError);
    assert_eq!(v4(&again), vec![Ipv4Addr::new(192, 0, 2, 1)]);
    assert_order_matches_entries(&harness.runtime.cache);
}

/// The sweep takes each shard's write lock only for that shard's own `retain`, so a hit queues
/// behind one shard's worth of work at most, never behind the whole walk.
///
/// The test holds the shard walked just after the hit's, so every hit runs while the sweep is
/// parked mid-walk, and a hit that waits on the walk waits forever. The hits go out on a blocking
/// socket with a read timeout: a receive loop stuck behind the sweep blocks its worker, and with
/// it the runtime's timers, so only a timeout outside the runtime fails the test instead of
/// hanging it. Multi-threaded so the receive loop runs while the test thread blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cache_hit_stays_fast_while_a_sweep_runs() {
    // Several names, so one can be hit whose shard is not the last one walked.
    let owners: Vec<String> = (0..8).map(|n| format!("fast{n}.test")).collect();
    let records: Vec<_> = owners
        .iter()
        .map(|owner| {
            (
                owner.as_str(),
                RecordType::A,
                vec![a(owner, [192, 0, 2, 5])],
            )
        })
        .collect();
    let harness = Harness::start(zone(&records), policy(&[], &[], HashMap::new())).await;
    let cache = &harness.runtime.cache;
    let shard_index = |owner: &str| {
        let shard = cache.shard(&key(SCOPE_HOUSEHOLD, owner, RecordType::A));
        cache
            .shards
            .iter()
            .position(|each| std::ptr::eq(each, shard))
    };
    let (fast, hit_shard) = owners
        .iter()
        .find_map(|owner| {
            let index = shard_index(owner)?;
            (index + 1 < CACHE_SHARDS).then_some((owner.as_str(), index))
        })
        .expect("eight names do not all hash to the last shard");

    // A full cache of names the AI list is about to change, planted directly: the misses that
    // would otherwise put them there are not what is being measured.
    let request = harness.request("planted.test", RecordType::A, None);
    let response = build_base_response(&request, ResponseCode::NoError);
    let wire = Arc::new(
        CachedWire::from_message(&response, MAX_CACHE_TTL, Verdict::allow(Reason::NoMatch))
            .expect("encode"),
    );
    let names: Vec<String> = (0..CACHE_CAPACITY).map(|n| format!("p{n}.test")).collect();
    for name in &names {
        let planted = key(SCOPE_HOUSEHOLD, name, RecordType::A);
        cache.insert(planted, Arc::clone(&wire));
    }
    // Cached after the planting, so it is the newest entry in its shard and evicts, not evicted.
    harness.query(fast, RecordType::A).await;
    let cached: usize = cache
        .shards
        .iter()
        .map(|shard| read_recover(shard).entries.len())
        .sum();
    let changed: HashSet<Box<str>> = names.iter().map(|name| Box::from(name.as_str())).collect();

    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("read timeout");
    // Correct, the sweep parks here holding no lock; one that kept earlier shards' locks across
    // the walk would be holding the hit's too.
    let barrier = write_recover(&cache.shards[hit_shard + 1]);
    let runtime = Arc::clone(&harness.runtime);
    let next = runtime.current_policy();
    let sweep =
        tokio::task::spawn_blocking(move || runtime.swap_policy_invalidating(next, &changed));
    // Past the hit's shard once only the hit is left in it, or once the sweep holds its lock.
    let past_hit_shard = || match cache.shards[hit_shard].try_read() {
        Ok(shard) => shard.entries.len() == 1,
        Err(_) => true,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !past_hit_shard() {
        assert!(
            Instant::now() < deadline,
            "the sweep never reached the hit's shard"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    let mut fastest = Duration::MAX;
    let mut buffer = [0u8; 512];
    for _ in 0..5 {
        let request = harness.request(fast, RecordType::A, None);
        let started = Instant::now();
        client
            .send_to(&request.to_vec().expect("encode"), harness.server)
            .expect("send");
        let (size, _) = client
            .recv_from(&mut buffer)
            .expect("a hit does not wait for the sweep");
        fastest = fastest.min(started.elapsed());
        let response = Message::from_vec(&buffer[..size]).expect("parse");
        assert_eq!(response.metadata.id, request.metadata.id);
        assert_eq!(v4(&response), vec![Ipv4Addr::new(192, 0, 2, 5)]);
    }
    assert!(!sweep.is_finished(), "every hit overlapped the sweep");
    drop(barrier);
    let dropped = sweep.await.expect("the sweep finished");
    assert_eq!(
        dropped,
        cached - 1,
        "every planted name, and not the one being hit"
    );
    // Every hit is bounded by the read timeout above; this is the hit path's own speed, taken as
    // the fastest of five like the hung-upstream test, since one slow wake-up is the scheduler.
    assert!(fastest < Duration::from_millis(5), "hit took {fastest:?}");
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 5);
}
