//! AI review end to end, against a scripted OpenRouter on loopback (§16): site loads in, requests
//! out, answers stored and installed, and every way a request can fail or be withdrawn.
//!
//! The reviewer is driven by hand on a synthetic clock — `push`, `tick` and `next_start` — and
//! every job it hands out is started through `worker::spawn_job`, the function the worker task
//! uses, so each is registered for `halt()` to abort exactly as in production. Only the waiting is
//! the test's; everything that decides is the reviewer's own.

mod egress;
mod isolation;

use super::openrouter_stub::{
    CONSENT, Canned, DECISIONS, JEV, KEY_INFO, LISTING, Stub, call, decision, key_info, listings,
    parsed, passing, realistic_key, wired,
};
use super::{Harness, device_input};
use crate::ai::burst::{LATE, QUIET};
use crate::ai::review::Pipeline;
use crate::ai::tests::review::{at, name, names, noon};
use crate::ai::worker::{Jobs, persist, spawn_job};
use crate::ai::{AliveGuard, Cost, KEY_REFUSED, Seen, State};
use crate::api::devices;
use crate::http::ApiJson;
use crate::policy_build::{Rebuild, rebuild};
use crate::state::ServerState;
use axum::extract::State as Extract;
use axum::http::StatusCode;
use cogwheel_policy::{Action, Reason};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

const WEBSITE: &str = "www.news-site.com";

fn device() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))
}

fn micro(usd: f64) -> u64 {
    (usd * 1e6).ceil() as u64
}

/// A reviewing appliance wired to a stub: the harness, the reviewer's pipeline and its jobs, with
/// the reviewer marked alive so the send gate is open.
struct Rig {
    harness: Harness,
    stub: Stub,
    pipeline: Pipeline,
    jobs: Jobs,
    _alive: AliveGuard,
}

async fn rig(script: Vec<(&'static str, Canned)>, stored: &[(&'static str, &str)]) -> Rig {
    let stub = Stub::serve(script);
    let harness = Harness::with_ai(wired(&stub, Some(&realistic_key())), stored).await;
    reviewer(harness, stub)
}

fn reviewer(harness: Harness, stub: Stub) -> Rig {
    let ai = Arc::clone(&harness.state.ai);
    let alive = ai.reviewer_alive();
    Rig {
        pipeline: Pipeline::new(Arc::clone(&ai)),
        jobs: Jobs::new(ai),
        harness,
        stub,
        _alive: alive,
    }
}

impl Rig {
    fn state(&self) -> &ServerState {
        &self.harness.state
    }

    /// `client` opens [`WEBSITE`] at `t`, which loads `members`; the burst then closes.
    fn visit_from(&mut self, client: IpAddr, t: i64, members: &[String]) {
        let ts = u32::try_from(t).expect("a timestamp that fits");
        for domain in std::iter::once(WEBSITE).chain(members.iter().map(String::as_str)) {
            self.pipeline.push(Seen {
                ts,
                client,
                domain: Arc::from(domain),
                blocked: false,
                reason: Reason::NoMatch,
            });
        }
        let policy = self.state().runtime.current_policy();
        self.pipeline.tick(at(t + QUIET + LATE), &policy);
    }

    fn visit(&mut self, t: i64, members: &[String]) {
        self.visit_from(device(), t, members);
    }

    /// Start the one job that may start at `t`, if any.
    fn start(&mut self, t: i64) -> bool {
        match self.pipeline.next_start(at(t)) {
            Some(start) => {
                spawn_job(&mut self.jobs, start);
                true
            }
            None => false,
        }
    }

    /// Wait for every job in flight, settle each at `t`, and write what it asks, as the worker does.
    async fn settle(&mut self, t: i64) {
        while let Some((id, outcome)) = self.jobs.next().await {
            let settlement = self.pipeline.settle(at(t), id, outcome);
            persist(&self.harness.state, t, settlement).await;
        }
    }

    /// A second at a time from `from` to `to`: tick, start what may start, settle it.
    async fn run(&mut self, from: i64, to: i64) {
        for t in from..=to {
            let policy = self.state().runtime.current_policy();
            self.pipeline.tick(at(t), &policy);
            if self.start(t) {
                self.settle(t).await;
            }
        }
    }

    /// Today's spend, on the day of `t`.
    fn spent(&self, t: i64) -> Cost {
        self.state().ai.today(t)
    }
}

fn answer(choice: &str, confidence: f64, cost: f64) -> Canned {
    Canned::json(200, decision(choice, Some(confidence), None, Some(cost)))
}

// --------------------------------------------------------------------- the happy path

#[tokio::test]
async fn a_site_load_becomes_verdicts_and_reaches_dns() {
    let script = (0..3)
        .map(|_| (DECISIONS, answer("block", 0.95, 0.00002)))
        .collect();
    let mut rig = rig(script, &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..3));
    rig.run(t + 10, t + 20).await;

    let state = rig.state().clone();
    for n in 0..3 {
        let row = state
            .storage
            .ai_verdict(name(n))
            .await
            .expect("read")
            .expect("stored");
        assert_eq!(
            (row.verdict.as_str(), row.site.as_deref()),
            ("block", Some(WEBSITE))
        );
    }
    // The installer was woken; what it runs is this rebuild.
    tokio::time::timeout(Duration::from_secs(1), state.ai.install.notified())
        .await
        .expect("the installer is told");
    let stats = rebuild(&state, Rebuild::Ai).await.expect("the install");
    assert_eq!(
        stats.ai_changed, 3,
        "exactly the judged names change, so exactly they drop"
    );
    for n in 0..3 {
        assert_eq!(
            state.runtime.current_policy().ai.get(&name(n)),
            Some(Action::Block)
        );
    }
    let (_, text) = call(
        &state,
        "GET",
        &format!("/api/v1/check?domain={}", name(0)),
        None,
    )
    .await;
    let checked = parsed(&text)["data"].clone();
    assert_eq!(
        (checked["reason"].clone(), checked["ai"]["applied"].clone()),
        (json!("ai"), json!(true))
    );
    assert_eq!(rig.stub.sent(DECISIONS), 3);
    // The second visit asks nothing.
    rig.visit(t + 60, &names(0..3));
    assert_eq!(rig.pipeline.waiting(), 0);
}

// --------------------------------------------------------------------- off means off

/// D18: the send gate closes before the write that withdraws consent returns. A request on the
/// wire is cancelled, nothing queued is sent, and the held answer, when it does come, is not
/// stored, though the request is charged its reservation (OpenRouter may bill it).
#[tokio::test]
async fn turning_review_off_stops_requests_at_once() {
    for stop in ["off", "key removed", "key refused"] {
        let key = realistic_key();
        let first = if stop == "key refused" {
            Canned::json(401, "{}")
        } else {
            answer("block", 0.95, 0.00002).held()
        };
        let script = vec![
            (KEY_INFO, Canned::json(200, key_info(&key))),
            (DECISIONS, passing()),
            (DECISIONS, first),
        ];
        let stub = Stub::serve(script);
        let harness = Harness::with_ai(wired(&stub, None), &CONSENT).await;
        // A saved key, so that removing it is a choice the household has.
        let body = json!({ "key": key }).to_string();
        let (status, text) = call(&harness.state, "PUT", "/api/v1/ai", Some(&body)).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let mut rig = reviewer(harness, stub);
        let state = rig.state().clone();
        assert_eq!(state.ai.state(), State::Reviewing, "{stop}");

        let t = noon();
        rig.visit(t, &names(0..8));
        assert_eq!(rig.pipeline.waiting(), 8);
        let before = rig.spent(t);
        assert!(rig.start(t + 10));
        let reserve = rig.pipeline.reserved();
        assert!(rig.stub.wait_for(3).await, "request 1 reached OpenRouter");

        match stop {
            "off" | "key removed" => {
                let body = if stop == "off" {
                    r#"{"enabled":false}"#
                } else {
                    r#"{"key":null}"#
                };
                let (status, text) = call(&state, "PUT", "/api/v1/ai", Some(body)).await;
                assert_eq!(status, StatusCode::OK, "{text}");
            }
            _ => rig.settle(t + 10).await,
        }
        assert_eq!(
            rig.stub.sent(DECISIONS),
            2,
            "{stop}: the Test and request 1, nothing since"
        );

        for s in 11..=70 {
            let policy = state.runtime.current_policy();
            rig.pipeline.tick(at(t + s), &policy);
            assert!(!rig.start(t + s), "{stop}: nothing starts after the stop");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(rig.stub.sent(DECISIONS), 2, "{stop}");
        assert_eq!(
            (rig.pipeline.waiting(), rig.pipeline.bursts()),
            (0, 0),
            "{stop}"
        );
        assert!(
            names(0..8)
                .iter()
                .all(|name| !rig.pipeline.is_pending(name)),
            "{stop}"
        );
        assert!(state.ai.tap().is_none(), "{stop}");

        rig.stub.release();
        rig.settle(t + 71).await;
        assert!(
            state
                .storage
                .list_ai_verdicts()
                .await
                .expect("read")
                .is_empty(),
            "{stop}"
        );
        let after = rig.spent(t);
        if stop == "key refused" {
            assert_eq!(state.ai.state(), State::KeyRefused);
            assert_eq!(state.ai.last_error(), Some(KEY_REFUSED));
            assert_eq!(after, before, "an error status is not billed");
        } else {
            assert_eq!(after.micro_usd, before.micro_usd + reserve, "{stop}");
            assert_eq!(after.requests, before.requests + 1, "{stop}");
        }
    }
}

// --------------------------------------------------------------------- what is sent

#[tokio::test]
async fn the_request_carries_only_names_and_the_privacy_preferences() {
    let mut script = listings(&[JEV], &[JEV]);
    script.push((DECISIONS, answer("ignore", 0.6, 0.00002)));
    script.push((DECISIONS, answer("ignore", 0.6, 0.00002)));
    let key = realistic_key();
    let stub = Stub::serve(script);
    let stored = [CONSENT[0], CONSENT[1], ("ai_model_price", "0.042")];
    let harness = Harness::with_ai(wired(&stub, Some(&key)), &stored).await;
    let state = harness.state.clone();
    devices::create(
        Extract(state.clone()),
        ApiJson(device_input("Kitchen tablet", "192.168.1.20")),
    )
    .await
    .expect("a named device");
    crate::api::rules::create(
        Extract(state.clone()),
        ApiJson(super::rule_input("family.example.org", "allow", None)),
    )
    .await
    .expect("a household rule");
    let mut rig = reviewer(harness, stub);

    let t = noon();
    let mut members = names(0..2);
    // Never shareable: a private suffix, a service label, an embedded address, and a name the
    // household keeps out with a rule.
    for unshareable in [
        "printer.lan",
        "_dmarc.example.com",
        "10-0-0-5.nip.io",
        "family.example.org",
    ] {
        members.push(unshareable.to_owned());
    }
    rig.visit(t, &members);
    assert_eq!(
        rig.pipeline.waiting(),
        2,
        "only the shareable names are candidates"
    );
    rig.run(t + 10, t + 20).await;
    let (status, _) = call(&state, "GET", "/api/v1/ai/models", None).await;
    assert_eq!(status, StatusCode::OK);

    let requests = rig.stub.requests();
    let decisions: Vec<_> = requests.iter().filter(|r| r.target == DECISIONS).collect();
    assert_eq!(decisions.len(), 2);
    for request in decisions {
        assert_eq!(request.method, "POST");
        let body = request.json();
        assert_eq!(body["provider"]["data_collection"], "deny");
        assert_eq!(body["provider"]["zdr"], true);
        assert_eq!(body["provider"]["max_price"]["prompt"], "0.0525");
        for field in ["session_id", "user", "trace"] {
            assert!(body.get(field).is_none(), "{field} is never sent");
        }
        assert_eq!(body["state"]["website"], WEBSITE);
        let text = String::from_utf8_lossy(&request.body).into_owned();
        for private in [
            "192.168.1.20",
            "Kitchen",
            "printer.lan",
            "_dmarc",
            "10-0-0-5",
            "family.example.org",
        ] {
            assert!(!text.contains(private), "{private} left the house: {text}");
        }
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {key}").as_str())
        );
    }
    let listing_requests: Vec<_> = requests
        .iter()
        .filter(|r| r.target.starts_with(LISTING))
        .collect();
    assert_eq!(listing_requests.len(), 2);
    assert!(
        listing_requests.iter().all(|request| {
            request.method == "GET" && request.header("authorization").is_none()
        })
    );
}

// --------------------------------------------------------------------- failures

#[tokio::test]
async fn a_429_with_retry_after_is_retried_once() {
    let script = vec![
        (
            DECISIONS,
            Canned::json(429, "{}").header("Retry-After", "2"),
        ),
        (DECISIONS, answer("block", 0.95, 0.00002)),
    ];
    let mut rig = rig(script, &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..1));
    assert!(rig.start(t + 10));
    rig.settle(t + 10).await;
    assert!(rig.pipeline.is_pending(&name(0)), "kept to try again");
    assert!(!rig.start(t + 11), "the Retry-After is honoured");
    assert!(rig.start(t + 12));
    rig.settle(t + 12).await;
    assert_eq!(rig.stub.sent(DECISIONS), 2);
    let row = rig.state().storage.ai_verdict(name(0)).await.expect("read");
    assert!(row.is_some_and(|row| row.verdict == "block"));
    assert_eq!(
        rig.state().ai.state(),
        State::Reviewing,
        "one failure is not retrying"
    );
}

#[tokio::test]
async fn four_server_errors_drop_the_job_and_release_the_name() {
    let script = (0..4)
        .map(|_| (DECISIONS, Canned::json(500, "{}")))
        .collect();
    let mut rig = rig(script, &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..1));
    let mut now = t + 10;
    for _ in 0..4 {
        assert!(rig.start(now), "an attempt at {now}");
        rig.settle(now).await;
        // Past the longest backoff: 8 s and a quarter.
        now += 11;
    }
    assert_eq!(rig.stub.sent(DECISIONS), 4);
    assert!(!rig.pipeline.is_pending(&name(0)), "released");
    assert_eq!(rig.state().ai.known(&name(0)), None, "never judged");
    assert!(
        rig.state()
            .storage
            .list_ai_verdicts()
            .await
            .expect("read")
            .is_empty()
    );
    rig.visit(now, &names(0..1));
    assert_eq!(rig.pipeline.waiting(), 1, "the next sighting asks again");
}

#[tokio::test]
async fn a_refused_key_stops_after_one_request() {
    let mut rig = rig(vec![(DECISIONS, Canned::json(401, "{}"))], &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..3));
    rig.run(t + 10, t + 60).await;
    assert_eq!(rig.stub.sent(DECISIONS), 1);
    let (_, text) = call(rig.state(), "GET", "/api/v1/ai", None).await;
    let status = parsed(&text)["data"].clone();
    assert_eq!(
        (status["state"].clone(), status["last_error"].clone()),
        (json!("key_refused"), json!(KEY_REFUSED))
    );
    assert!(rig.state().ai.tap().is_none());
}

#[tokio::test]
async fn an_in_flight_402_is_retried_and_a_credit_402_stops() {
    let in_flight = r#"{"error":{"code":402,"message":"Too much at once",
        "metadata":{"limit_source":"openrouter_in_flight_budget"}}}"#;
    let credit = r#"{"error":{"code":402,"message":"Insufficient credits"}}"#;
    let script = vec![
        (DECISIONS, Canned::json(402, in_flight)),
        (DECISIONS, Canned::json(402, credit)),
    ];
    let mut rig = rig(script, &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..2));
    assert!(rig.start(t + 10));
    rig.settle(t + 10).await;
    assert_eq!(
        rig.state().ai.state(),
        State::Reviewing,
        "a 402 for the in-flight budget waits"
    );
    assert!(rig.pipeline.is_pending(&name(0)));
    rig.run(t + 11, t + 30).await;
    assert_eq!(rig.stub.sent(DECISIONS), 2);
    assert_eq!(rig.state().ai.state(), State::OutOfCredit);
    assert!(rig.state().ai.tap().is_none());
}

#[tokio::test]
async fn a_response_without_cost_is_charged_an_estimate() {
    let unpriced = Canned::json(200, decision("block", Some(0.95), None, None));
    let mut rig = rig(vec![(DECISIONS, unpriced)], &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..1));
    rig.run(t + 10, t + 12).await;
    // 480 input tokens at the ceiling for an unknown price, $1 a million: never free.
    assert_eq!(rig.spent(t).micro_usd, 480);
    assert_eq!(rig.state().ai.counters.unpriced.load(Ordering::Relaxed), 1);
    assert!(
        rig.state()
            .storage
            .ai_verdict(name(0))
            .await
            .expect("read")
            .is_some()
    );
}

#[tokio::test]
async fn the_budget_stops_dispatch_and_survives_a_restart() {
    let stored = [CONSENT[0], CONSENT[1], ("ai_daily_limit", "0.05")];
    let mut rig = rig(vec![(DECISIONS, answer("block", 0.95, 0.06))], &stored).await;
    let t = noon();
    rig.visit(t, &names(0..3));
    rig.run(t + 10, t + 30).await;
    assert_eq!(
        rig.stub.sent(DECISIONS),
        1,
        "the first answer spent the day's limit"
    );
    assert_eq!(rig.state().ai.state(), State::PausedBudget);
    let spent = rig.spent(t);
    assert_eq!(spent.micro_usd, micro(0.06));

    // A new process, from what was stored: the same spend, and still nothing to send.
    let (state, _tap) = rig.harness.restarted_ai().await;
    assert_eq!(state.ai.today(t), spent);
    let (_, text) = call(&state, "GET", "/api/v1/ai", None).await;
    assert_eq!(parsed(&text)["data"]["today"]["spent_usd"], 0.06);
    let mut again = reviewer(
        Harness {
            state,
            ..rig.harness
        },
        rig.stub,
    );
    again.visit(t + 60, &names(3..6));
    assert!(!again.start(t + 70));
    assert_eq!(again.state().ai.state(), State::PausedBudget);
    assert_eq!(again.stub.sent(DECISIONS), 1);
}

/// A billed answer that cannot be read stores nothing and changes nothing the reviewer knows, but
/// it is charged, in memory and in `settings`.
#[tokio::test]
async fn a_malformed_answer_is_dropped_and_not_stored() {
    let malformed = r#"{"answers":{"role":{"type":"choice","choice":"maybe","confidence":0.9}},
                        "usage":{"input_tokens":480,"cost":0.00003}}"#;
    let mut rig = rig(vec![(DECISIONS, Canned::json(200, malformed))], &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..1));
    rig.run(t + 10, t + 12).await;
    assert!(
        rig.state()
            .storage
            .list_ai_verdicts()
            .await
            .expect("read")
            .is_empty()
    );
    assert_eq!(rig.state().ai.known(&name(0)), None);
    assert_eq!(rig.spent(t).micro_usd, micro(0.00003));
    let (state, _tap) = rig.harness.restarted_ai().await;
    let stored = state.ai.today(t).micro_usd;
    assert_eq!(stored, micro(0.00003), "and stored with the day's spend");
}

/// The Test and the reviewer settle at once; the stored spend is the in-memory total, never an
/// older figure written last.
#[tokio::test]
async fn test_and_reviewer_spend_writes_never_go_backwards() {
    let script = vec![(DECISIONS, passing()), (DECISIONS, passing())];
    let mut rig = rig(script, &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..1));
    assert!(rig.start(t + 10));
    let state = rig.state().clone();
    let (tested, ()) = tokio::join!(
        call(&state, "POST", "/api/v1/ai/test", Some("{}")),
        rig.settle(t + 10),
    );
    assert_eq!(tested.0, StatusCode::OK, "{}", tested.1);
    let today = rig.spent(t);
    assert_eq!(
        (today.requests, today.micro_usd),
        (2, 2 * micro(0.000_021_3))
    );
    let stored = state
        .storage
        .setting("ai_spend")
        .await
        .expect("read")
        .expect("stored");
    let fields: Vec<u64> = stored
        .split(' ')
        .filter_map(|field| field.parse().ok())
        .collect();
    assert_eq!(fields[1..], [today.micro_usd, u64::from(today.requests), 0]);
}
