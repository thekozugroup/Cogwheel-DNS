//! `review.rs` (§6.6, §6.13, §6.14): the pipeline on a synthetic clock, with no HTTP. A job that
//! `next_start` hands out counts as started, and its outcome is whatever the test settles it with.
//! Each bound of §6.14 the pipeline owns has its own test.

use super::{config, consent, load, storage, with_env_key};
use crate::ai::burst::{LATE, QUIET};
use crate::ai::client::{Reply, classify};
use crate::ai::review::{Now, Outcome, Pipeline};
use crate::ai::spend::{Cost, usd_to_micro, utc_day};
use crate::ai::{AiState, AliveGuard, DAY, Seen, State};
use crate::config::AppConfig;
use crate::state::now_secs;
use cogwheel_policy::{Action, BlockMode, ListIndex, Pattern, Policy, Reason, RuleSet};
use cogwheel_storage::Storage;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

/// A reviewing `AiState` with a live reviewer, the database behind it, and a pipeline over it.
pub(super) struct Rig {
    pub ai: Arc<AiState>,
    pub storage: Storage,
    pub pipeline: Pipeline,
    _alive: AliveGuard,
    _tap: mpsc::Receiver<Seen>,
}

pub(super) async fn rig() -> Rig {
    rig_on(storage().await, config()).await
}

/// The same over `storage`, loaded from `config` with an environment key.
pub(super) async fn rig_on(storage: Storage, config: AppConfig) -> Rig {
    consent(&storage).await;
    let (ai, tap) = load(&with_env_key(config), &storage).await;
    let alive = ai.reviewer_alive();
    Rig {
        pipeline: Pipeline::new(Arc::clone(&ai)),
        ai,
        storage,
        _alive: alive,
        _tap: tap,
    }
}

/// Noon UTC, today by the wall clock: the synthetic clock the pipeline and its spend run on.
pub(crate) fn noon() -> i64 {
    i64::from(utc_day(now_secs())) * DAY + DAY / 2
}

pub(crate) fn at(secs: i64) -> Now {
    Now::from_secs(secs)
}

pub(super) fn device(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n))
}

/// A third-party name with a site key of its own.
pub(crate) fn name(n: usize) -> String {
    format!("t{n}.site{n}.com")
}

pub(crate) fn names(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(name).collect()
}

pub(super) fn empty() -> Policy {
    Policy::empty(BlockMode::NullIp)
}

/// The household's lists block each of `blocked`.
pub(super) fn blocking(blocked: &[&str]) -> Policy {
    let mut builder = ListIndex::builder();
    for domain in blocked {
        builder.insert(0, Action::Block, Pattern::Exact, domain);
    }
    let index = Arc::new(builder.build());
    Policy::new(
        index,
        Arc::new(RuleSet::new()),
        HashMap::new(),
        1,
        BlockMode::NullIp,
    )
}

pub(super) fn sighting(client: IpAddr, ts: i64, domain: &str, reason: Reason) -> Seen {
    Seen {
        ts: u32::try_from(ts).expect("a timestamp that fits"),
        client,
        domain: Arc::from(domain),
        blocked: matches!(reason, Reason::List),
        reason,
    }
}

/// `client` opens `website`, which loads `members` (each logged with `reason`), all at `ts`.
pub(super) fn push_load(
    pipeline: &mut Pipeline,
    client: IpAddr,
    ts: i64,
    website: &str,
    members: &[String],
    reason: Reason,
) {
    pipeline.push(sighting(client, ts, website, Reason::NoMatch));
    for member in members {
        pipeline.push(sighting(client, ts, member, reason));
    }
}

/// The same, then the tick that closes the burst.
pub(super) fn visit(
    pipeline: &mut Pipeline,
    policy: &Policy,
    client: IpAddr,
    ts: i64,
    website: &str,
    members: &[String],
) {
    push_load(pipeline, client, ts, website, members, Reason::NoMatch);
    pipeline.tick(at(ts + QUIET + LATE), policy);
}

/// A 200 whose role answer is `choice` at `confidence`, costing `cost`.
pub(super) fn answered(choice: &str, confidence: Option<f64>, cost: f64) -> Outcome {
    let mut role = json!({ "type": "choice", "choice": choice });
    if let Some(confidence) = confidence {
        role["confidence"] = json!(confidence);
    }
    reply(json!({
        "model": "typesafe/jev-1.13-20260917",
        "answers": { "role": role },
        "usage": { "input_tokens": 480, "output_tokens": 70, "cost": cost },
    }))
}

pub(super) fn reply(body: Value) -> Outcome {
    Outcome::Answered(Reply::Body(serde_json::to_vec(&body).expect("a JSON body")))
}

pub(super) fn failed(status: u16, retry_after: Option<&str>) -> Outcome {
    Outcome::Failed(classify(status, b"{}", retry_after))
}

pub(super) fn request(body: &[u8]) -> Value {
    serde_json::from_slice(body).expect("the request is JSON")
}

#[tokio::test]
async fn at_most_two_requests_are_in_flight() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..10),
    );
    assert_eq!(rig.pipeline.waiting(), 10);

    let first = rig.pipeline.next_start(at(t + 10)).expect("a first start");
    assert!(rig.pipeline.next_start(at(t + 11)).is_some());
    assert!(
        rig.pipeline.next_start(at(t + 12)).is_none(),
        "never three at once"
    );
    assert!(rig.pipeline.next_start(at(t + 60)).is_none());
    assert_eq!(rig.pipeline.in_flight(), 2);

    rig.pipeline
        .settle(at(t + 61), first.id, answered("ignore", Some(0.6), 0.00002));
    assert!(
        rig.pipeline.next_start(at(t + 61)).is_some(),
        "one settled, one more starts"
    );
    assert_eq!(rig.pipeline.in_flight(), 2);
}

#[tokio::test]
async fn starts_are_at_least_one_second_apart() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..5),
    );
    let start = (t + 10) * 1_000;
    let first = rig
        .pipeline
        .next_start(Now::from_millis(start))
        .expect("a start");
    // Settled at once, so the gap is the only thing holding the next one back.
    rig.pipeline.settle(
        Now::from_millis(start),
        first.id,
        answered("ignore", Some(0.6), 0.00002),
    );
    assert!(
        rig.pipeline
            .next_start(Now::from_millis(start + 999))
            .is_none()
    );
    assert!(
        rig.pipeline
            .next_start(Now::from_millis(start + 1_000))
            .is_some()
    );
}

#[tokio::test]
async fn the_daily_request_cap_pauses_until_utc_midnight() {
    let mut rig = rig().await;
    let t = noon();
    let earlier = Cost {
        micro_usd: 100,
        requests: 1_999,
        overrides: 0,
    };
    rig.ai
        .settle(&rig.storage, t, earlier, Vec::new())
        .await
        .expect("record earlier requests");
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..3),
    );

    let last = rig
        .pipeline
        .next_start(at(t + 10))
        .expect("the 2,000th request");
    let settled = rig
        .pipeline
        .settle(at(t + 11), last.id, answered("ignore", Some(0.6), 0.00002));
    rig.ai
        .settle(&rig.storage, t + 11, settled.cost, settled.rows)
        .await
        .expect("settle the 2,000th");
    assert_eq!(rig.ai.today(t + 11).requests, 2_000);

    assert!(rig.pipeline.next_start(at(t + 12)).is_none());
    assert_eq!(rig.ai.state(), State::PausedBudget);
    assert!(rig.ai.tap().is_none());
    assert_eq!(rig.pipeline.waiting(), 0, "the queue went with the halt");
    rig.pipeline.tick(at(t + 3_600), &empty());
    assert_eq!(
        rig.ai.state(),
        State::PausedBudget,
        "paused for the rest of the day"
    );

    let midnight = (t.div_euclid(DAY) + 1) * DAY;
    rig.pipeline.tick(at(midnight), &empty());
    assert_eq!(rig.ai.state(), State::Reviewing);
    assert!(rig.ai.tap().is_some());
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        midnight,
        "www.news-site.com",
        &names(5..8),
    );
    assert!(rig.pipeline.next_start(at(midnight + 10)).is_some());
}

#[tokio::test]
async fn the_daily_limit_pauses_until_utc_midnight() {
    let mut rig = rig().await;
    let t = noon();
    // Names of one length, so every job reserves the same.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(1..4),
    );
    rig.pipeline.next_start(at(t + 10)).expect("a start");
    let reserve = rig.pipeline.reserved();
    assert!(reserve > 0);
    // Room for one more reservation only if the one in flight did not count.
    let spent = rig.ai.daily_limit_micro() - reserve - reserve / 2;
    rig.ai
        .settle(&rig.storage, t + 11, Cost::request(spent), Vec::new())
        .await
        .expect("record the day's spend");

    assert!(rig.pipeline.next_start(at(t + 11)).is_none());
    assert_eq!(rig.ai.state(), State::PausedBudget);
    assert!(rig.ai.tap().is_none());

    let midnight = (t.div_euclid(DAY) + 1) * DAY;
    rig.pipeline.tick(at(midnight - 1), &empty());
    assert_eq!(rig.ai.state(), State::PausedBudget);
    rig.pipeline.tick(at(midnight), &empty());
    assert_eq!(rig.ai.state(), State::Reviewing);
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        midnight,
        "www.news-site.com",
        &names(5..8),
    );
    assert!(
        rig.pipeline.next_start(at(midnight + 10)).is_some(),
        "a new day's limit"
    );
}

#[tokio::test]
async fn a_full_queue_drops_its_oldest_job() {
    let mut rig = rig().await;
    let t = noon();
    // 43 devices open a website each: 42 loads of 24 new names, and one of 17.
    let mut next = 0;
    for client in 1..=43 {
        let count = if client == 43 { 17 } else { 24 };
        let members = names(next..next + count);
        next += count;
        let website = format!("www.w{client}.com");
        push_load(
            &mut rig.pipeline,
            device(client),
            t,
            &website,
            &members,
            Reason::NoMatch,
        );
    }
    assert_eq!(next, 1_025);
    rig.pipeline.tick(at(t + QUIET + LATE), &empty());

    assert_eq!(rig.pipeline.waiting(), 1_024);
    assert_eq!(rig.ai.counters.dropped.load(Ordering::Relaxed), 1);
    assert!(!rig.pipeline.is_pending(&name(0)), "the first offered went");
    assert!(rig.pipeline.is_pending(&name(1)));
    assert!(rig.pipeline.is_pending(&name(1_024)));
}

#[tokio::test]
async fn a_site_load_yields_at_most_24_candidates() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..30),
    );
    assert_eq!(rig.pipeline.waiting(), 24);
    assert!(rig.pipeline.is_pending(&name(23)));
    assert!(!rig.pipeline.is_pending(&name(24)));

    let start = rig.pipeline.next_start(at(t + 10)).expect("a start");
    let body = request(&start.body);
    let context = body["state"]["looked_up_with_it"]
        .as_array()
        .expect("the context names");
    assert_eq!(context.len(), 24, "29 others, and 24 of them sent");
    assert_eq!(body["state"]["website"], "www.news-site.com");
    assert_eq!(body["state"]["candidate"], name(0).as_str());
    assert!(!context.contains(&json!(name(0))));
    assert!(!context.contains(&json!("www.news-site.com")));
}

#[tokio::test]
async fn a_site_key_admits_at_most_60_new_names_a_day() {
    let mut rig = rig().await;
    let t = noon();
    // Three websites each load 24 names under one tracker's site key: 60 go up, not 72.
    for client in 1..=3 {
        let members: Vec<String> = (0..24)
            .map(|n| format!("x{}.tracker.com", client * 100 + n))
            .collect();
        let website = format!("www.w{client}.com");
        let ts = t + 10 * i64::from(client);
        push_load(
            &mut rig.pipeline,
            device(client),
            ts,
            &website,
            &members,
            Reason::List,
        );
        rig.pipeline.tick(at(ts + QUIET + LATE), &empty());
    }
    assert_eq!(rig.pipeline.waiting(), 60);

    // The next UTC day it has room again.
    let tomorrow = (t.div_euclid(DAY) + 1) * DAY;
    let members = vec!["x999.tracker.com".to_owned()];
    visit(
        &mut rig.pipeline,
        &empty(),
        device(4),
        tomorrow,
        "www.w4.com",
        &members,
    );
    assert!(rig.pipeline.is_pending("x999.tracker.com"));

    // The map holds 4,096 site keys. Once it is full a new one counts as capped until the day
    // turns, and one it holds keeps its room.
    let mut full = self::rig().await;
    let mut next = 0;
    for client in 1..=171 {
        let count = (4_096 - next).min(24);
        let members = names(next..next + count);
        next += count;
        let website = format!("www.w{client}.com");
        push_load(
            &mut full.pipeline,
            device(client),
            t,
            &website,
            &members,
            Reason::NoMatch,
        );
    }
    assert_eq!(next, 4_096);
    full.pipeline.tick(at(t + QUIET + LATE), &empty());
    let members = vec!["y.site0.com".to_owned(), "y.fresh-site.com".to_owned()];
    visit(
        &mut full.pipeline,
        &empty(),
        device(172),
        t + 20,
        "www.w172.com",
        &members,
    );
    assert!(full.pipeline.is_pending("y.site0.com"));
    assert!(!full.pipeline.is_pending("y.fresh-site.com"));
}

#[tokio::test]
async fn a_client_admits_at_most_300_new_names_an_hour() {
    let mut rig = rig().await;
    let t = noon();
    // One device opens 13 websites of 24 new names each within the hour: 300 go up.
    for load in 0..13 {
        let members = names(load * 24..(load + 1) * 24);
        let ts = t + 10 * i64::try_from(load).expect("a small number");
        visit(
            &mut rig.pipeline,
            &empty(),
            device(1),
            ts,
            &format!("www.w{load}.com"),
            &members,
        );
    }
    assert_eq!(rig.pipeline.waiting(), 300);
    // The next hour it has room again.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t + 3_600,
        "www.later.com",
        &names(500..501),
    );
    assert!(rig.pipeline.is_pending(&name(500)));

    // The map holds 1,024 devices. Once it is full a new one counts as capped until the hour
    // turns, and one it holds keeps its room.
    let mut full = self::rig().await;
    let clients = 1_024;
    for batch in 0..6u32 {
        let ts = t + 10 * i64::from(batch);
        for client in batch * 200 + 1..=(batch * 200 + 200).min(clients) {
            let n = usize::try_from(client).expect("a small number");
            let website = "www.news-site.com";
            push_load(
                &mut full.pipeline,
                device(client),
                ts,
                website,
                &names(n..n + 1),
                Reason::NoMatch,
            );
        }
        full.pipeline.tick(at(ts + QUIET + LATE), &empty());
    }
    assert!(full.pipeline.is_pending(&name(1_024)));
    let website = "www.news-site.com";
    visit(
        &mut full.pipeline,
        &empty(),
        device(clients + 1),
        t + 100,
        website,
        &names(2_000..2_001),
    );
    assert!(
        !full.pipeline.is_pending(&name(2_000)),
        "a 1,025th device is capped"
    );
    visit(
        &mut full.pipeline,
        &empty(),
        device(1),
        t + 110,
        website,
        &names(2_001..2_002),
    );
    assert!(full.pipeline.is_pending(&name(2_001)));
}

#[tokio::test]
async fn spend_is_reserved_then_settled_and_never_free() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(1..4),
    );

    // Reserved while in flight, then charged what `usage.cost` says.
    let first = rig.pipeline.next_start(at(t + 10)).expect("a start");
    let reserve = rig.pipeline.reserved();
    assert!(reserve > 0, "a request always counts against the limit");
    let settled = rig.pipeline.settle(
        at(t + 10),
        first.id,
        answered("ignore", Some(0.6), 0.000021),
    );
    assert_eq!(settled.cost, Cost::request(usd_to_micro(0.000021)));
    assert_eq!(rig.pipeline.reserved(), 0);
    assert_eq!(rig.ai.counters.unpriced.load(Ordering::Relaxed), 0);

    // No cost: the input tokens at the price ceiling ($1 per million when the price is unknown).
    let second = rig.pipeline.next_start(at(t + 11)).expect("a start");
    let tokens_only = reply(json!({
        "answers": { "role": { "type": "choice", "choice": "ignore", "confidence": 0.6 } },
        "usage": { "input_tokens": 500 },
    }));
    let settled = rig.pipeline.settle(at(t + 11), second.id, tokens_only);
    assert!((500..=501).contains(&settled.cost.micro_usd));
    assert_eq!(rig.ai.counters.unpriced.load(Ordering::Relaxed), 1);

    // No usage at all: twice the reservation.
    let third = rig.pipeline.next_start(at(t + 12)).expect("a start");
    let reserve = rig.pipeline.reserved();
    let unpriced = reply(json!({
        "answers": { "role": { "type": "choice", "choice": "ignore", "confidence": 0.6 } },
    }));
    let settled = rig.pipeline.settle(at(t + 12), third.id, unpriced);
    assert_eq!(settled.cost, Cost::request(2 * reserve));
    assert_eq!(rig.ai.counters.unpriced.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn an_aborted_request_is_charged_its_reservation() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..2),
    );
    let start = rig.pipeline.next_start(at(t + 10)).expect("a start");
    let reserve = rig.pipeline.reserved();
    let settled = rig.pipeline.settle(at(t + 11), start.id, Outcome::Aborted);
    assert_eq!(settled.cost, Cost::request(reserve));
    assert!(settled.rows.is_empty());
    assert!(
        !rig.pipeline.is_pending(&name(0)),
        "released, to be asked about again"
    );

    // Withdrawn before it was sent: nothing to charge.
    let start = rig.pipeline.next_start(at(t + 12)).expect("a start");
    let settled = rig
        .pipeline
        .settle(at(t + 12), start.id, Outcome::Withdrawn);
    assert_eq!(settled.cost, Cost::default());
}

/// The 2,000-a-day cap counts the requests in flight: with 1,999 settled and one on the wire, no
/// second one starts, even though the gap and the in-flight bound would allow it.
#[tokio::test]
async fn the_daily_request_cap_counts_requests_in_flight() {
    let mut rig = rig().await;
    let t = noon();
    let earlier = Cost {
        micro_usd: 100,
        requests: 1_999,
        overrides: 0,
    };
    rig.ai
        .settle(&rig.storage, t, earlier, Vec::new())
        .await
        .expect("record earlier requests");
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..3),
    );
    rig.pipeline
        .next_start(at(t + 10))
        .expect("the 2,000th request");
    assert!(
        rig.pipeline.next_start(at(t + 11)).is_none(),
        "a 2,001st would start while the 2,000th is on the wire"
    );
    assert_eq!(rig.ai.state(), State::PausedBudget);
}

/// A 200 that clears both override bars for a list-blocked name.
fn overriding_allow() -> Outcome {
    reply(json!({
        "model": "typesafe/jev-1.13-20260917",
        "answers": {
            "role": { "type": "choice", "choice": "allow", "confidence": 0.99 },
            "effect": { "type": "choice", "choice": "breaks", "confidence": 0.99 },
        },
        "usage": { "input_tokens": 480, "output_tokens": 70, "cost": 0.00002 },
    }))
}

/// D6 through the pipeline: a hostile page whose list-blocked names all come back as confident
/// allows whitelists three of them, not the batch; and the twentieth of the day is the last.
#[tokio::test]
async fn allows_over_a_list_are_capped_per_load_and_per_day() {
    let mut rig = rig().await;
    let t = noon();
    let (members, later) = (names(0..5), names(10..12));
    let all: Vec<&str> = members.iter().chain(&later).map(String::as_str).collect();
    let listed = blocking(&all);
    visit(
        &mut rig.pipeline,
        &listed,
        device(1),
        t,
        "www.hostile-site.com",
        &members,
    );
    let mut verdicts = Vec::new();
    let mut clock = t + 10;
    for _ in 0..5 {
        let start = rig.pipeline.next_start(at(clock)).expect("a start");
        let settled = rig.pipeline.settle(at(clock), start.id, overriding_allow());
        verdicts.extend(
            settled
                .rows
                .iter()
                .map(|row| (row.verdict.clone(), row.why.clone())),
        );
        rig.ai
            .settle(&rig.storage, clock, settled.cost, settled.rows)
            .await
            .expect("settle");
        clock += 2;
    }
    let allows = verdicts.iter().filter(|(verdict, _)| verdict == "allow");
    let limited = verdicts
        .iter()
        .filter(|(verdict, why)| verdict == "ignore" && why.as_deref() == Some("limit"));
    assert_eq!((allows.count(), limited.count()), (3, 2), "three a load");
    assert_eq!(rig.ai.today(clock).overrides, 3);

    // Seventeen more earlier today: the day's twentieth was the last.
    let earlier = Cost {
        micro_usd: 0,
        requests: 0,
        overrides: 17,
    };
    rig.ai
        .settle(&rig.storage, clock, earlier, Vec::new())
        .await
        .expect("earlier overrides");
    visit(
        &mut rig.pipeline,
        &listed,
        device(2),
        clock,
        "www.other-site.com",
        &later,
    );
    let start = rig.pipeline.next_start(at(clock + 10)).expect("a start");
    let settled = rig
        .pipeline
        .settle(at(clock + 10), start.id, overriding_allow());
    let row = settled.rows.first().expect("a fresh row");
    assert_eq!(
        (row.verdict.as_str(), row.why.as_deref()),
        ("ignore", Some("limit")),
        "twenty a day"
    );
}
