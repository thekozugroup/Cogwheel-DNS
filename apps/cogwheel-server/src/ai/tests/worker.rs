//! `worker.rs`, and the pipeline's retry, backoff and terminal states (§6.12, §6.15): what a
//! failed request does to the queue and the state, how a job checks the gate, and the reviewer
//! task's drop guard. The jobs talk to a scripted listener on loopback, never to OpenRouter.

use super::review::{
    Rig, answered, at, device, empty, failed, name, names, noon, rig, rig_on, visit,
};
use super::stub::{Reply as Canned, Stub};
use super::{KEY, config, consent, load, with_env_key};
use crate::ai::client::Reply;
use crate::ai::review::{ATTEMPTS, Outcome};
use crate::ai::spend::{Cost, usd_to_micro};
use crate::ai::worker::{self, Jobs, persist, spawn_job};
use crate::ai::{
    Halt, KEY_REFUSED, MODEL_GONE, MODEL_UNREADABLE, NO_ANSWER, OUT_OF_CREDIT, REDIRECTED, State,
};
use crate::state::ServerState;
use crate::tests::Harness;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[tokio::test]
async fn a_retryable_failure_pauses_all_dispatch_and_retries_the_job() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..3),
    );
    let first = rig.pipeline.next_start(at(t + 10)).expect("a start");
    let settled = rig
        .pipeline
        .settle(at(t + 10), first.id, failed(429, Some("5")));
    assert_eq!(
        settled.cost,
        Cost::default(),
        "an error status is not charged"
    );
    assert!(rig.pipeline.is_pending(&name(0)), "kept to try again");

    // Every job waits out the Retry-After, not only the one that got it.
    assert!(rig.pipeline.next_start(at(t + 14)).is_none());
    let again = rig.pipeline.next_start(at(t + 15)).expect("a retry");
    assert_eq!(again.body, first.body, "the same job, first in line");
    assert_eq!(
        rig.ai.state(),
        State::Reviewing,
        "one failure is not retrying"
    );
}

#[tokio::test]
async fn four_attempts_drop_a_job_and_five_drops_mean_retrying() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..6),
    );
    let mut now = t + 10;
    let mut last = now;
    for job in 0..5 {
        for _ in 0..ATTEMPTS {
            let start = rig.pipeline.next_start(at(now)).expect("an attempt");
            rig.pipeline.settle(at(now), start.id, failed(503, None));
            last = now;
            // Past the longest backoff: 8 s, plus a quarter.
            now += 11;
        }
        let name = name(job);
        assert!(
            !rig.pipeline.is_pending(&name),
            "dropped after four, and released"
        );
        let expected = if job < 4 {
            State::Reviewing
        } else {
            State::Retrying
        };
        assert_eq!(rig.ai.state(), expected);
    }
    assert_eq!(rig.ai.last_error(), Some(NO_ANSWER));
    assert!(rig.ai.tap().is_some(), "retrying is still reviewing");

    // Dispatch pauses a minute after the fifth drop.
    assert!(rig.pipeline.next_start(at(last + 59)).is_none());
    let start = rig
        .pipeline
        .next_start(at(last + 60))
        .expect("after the pause");
    rig.pipeline.settle(
        at(last + 60),
        start.id,
        answered("ignore", Some(0.6), 0.00002),
    );
    assert_eq!(
        (rig.ai.state(), rig.ai.last_error()),
        (State::Reviewing, None)
    );
}

#[tokio::test]
async fn terminal_answers_close_the_gate_and_empty_the_queue() {
    let cases = [
        (401, State::KeyRefused, KEY_REFUSED),
        (403, State::KeyRefused, KEY_REFUSED),
        (402, State::OutOfCredit, OUT_OF_CREDIT),
        (404, State::ModelRefused, MODEL_GONE),
        (307, State::ModelRefused, REDIRECTED),
    ];
    let t = noon();
    for (status, state, sentence) in cases {
        let mut rig = rig().await;
        visit(
            &mut rig.pipeline,
            &empty(),
            device(1),
            t,
            "www.news-site.com",
            &names(0..3),
        );
        let start = rig.pipeline.next_start(at(t + 10)).expect("a start");
        rig.pipeline
            .settle(at(t + 10), start.id, failed(status, None));
        assert_eq!(rig.ai.state(), state, "{status}");
        assert_eq!(rig.ai.last_error(), Some(sentence), "{status}");
        assert!(rig.ai.tap().is_none(), "{status}");
        assert_eq!(rig.pipeline.waiting(), 0, "{status}");
        assert!(rig.pipeline.next_start(at(t + 60)).is_none(), "{status}");

        // Out of credit waits for the next UTC day; the others for the household.
        let midnight = (t.div_euclid(crate::ai::DAY) + 1) * crate::ai::DAY;
        rig.pipeline.tick(at(midnight), &empty());
        let resumed = if status == 402 {
            State::Reviewing
        } else {
            state
        };
        assert_eq!(rig.ai.state(), resumed, "{status}");
    }
}

#[tokio::test]
async fn three_refused_requests_or_unreadable_answers_stop_the_model() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..8),
    );
    let unreadable = || Outcome::Answered(Reply::Unreadable);
    let outcomes = [
        failed(400, None),
        failed(400, None),
        // A usable answer starts the count again.
        answered("ignore", Some(0.6), 0.00002),
        failed(413, None),
        unreadable(),
    ];
    for (second, outcome) in (10..).zip(outcomes) {
        let start = rig.pipeline.next_start(at(t + second)).expect("a start");
        rig.pipeline.settle(at(t + second), start.id, outcome);
        assert_eq!(rig.ai.state(), State::Reviewing);
    }
    let start = rig.pipeline.next_start(at(t + 20)).expect("a start");
    let reserve = rig.pipeline.reserved();
    let settled = rig.pipeline.settle(at(t + 20), start.id, unreadable());
    assert_eq!(
        settled.cost,
        Cost::request(2 * reserve),
        "billed, so charged"
    );
    assert_eq!(rig.ai.state(), State::ModelRefused);
    assert_eq!(rig.ai.last_error(), Some(MODEL_UNREADABLE));
}

// --------------------------------------------------------------------- jobs

/// A decisions answer, as the stub sends it.
fn decision(choice: &str, confidence: f64, cost: f64) -> String {
    json!({
        "id": "gen-dec-1",
        "model": "typesafe/jev-1.13-20260917",
        "provider": "TypeSafe",
        "answers": { "role": { "type": "choice", "choice": choice, "confidence": confidence } },
        "usage": { "input_tokens": 480, "output_tokens": 70, "cost": cost },
    })
    .to_string()
}

/// A harness whose AI review talks to `stub`, and a reviewing pipeline over its database.
async fn wired(stub: &Stub) -> (Harness, ServerState, Rig) {
    let harness = Harness::new().await;
    let mut config = config();
    config.ai_base_url = stub.base.clone();
    let rig = rig_on(harness.state.storage.clone(), config).await;
    let state = ServerState {
        ai: Arc::clone(&rig.ai),
        ..harness.state.clone()
    };
    (harness, state, rig)
}

#[tokio::test]
async fn a_job_halted_before_it_starts_sends_nothing_and_costs_nothing() {
    let stub = Stub::serve(vec![Canned::json(200, decision("block", 0.95, 0.00002))]);
    let (_harness, _state, mut rig) = wired(&stub).await;
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

    rig.ai.halt(Halt::Off);
    let mut jobs = Jobs::new(Arc::clone(&rig.ai));
    spawn_job(&mut jobs, start);
    let (id, outcome) = jobs.next().await.expect("the job comes back");
    assert!(matches!(outcome, Outcome::Withdrawn));
    let settled = rig.pipeline.settle(at(t + 11), id, outcome);
    assert_eq!(settled.cost, Cost::default());
    assert!(stub.requests().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_job_halted_after_it_was_spawned_is_aborted_and_charged_its_reservation() {
    let stub = Stub::serve(vec![Canned::json(200, decision("block", 0.95, 0.00002))]);
    let (_harness, _state, mut rig) = wired(&stub).await;
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

    let mut jobs = Jobs::new(Arc::clone(&rig.ai));
    spawn_job(&mut jobs, start);
    // Synchronous: the job is cancelled before this test's runtime ever polls it.
    rig.ai.halt(Halt::Off);
    let (id, outcome) = jobs.next().await.expect("the job comes back");
    assert!(matches!(outcome, Outcome::Aborted));
    let settled = rig.pipeline.settle(at(t + 11), id, outcome);
    assert_eq!(settled.cost, Cost::request(reserve));
    assert!(settled.rows.is_empty());
    assert!(stub.requests().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_started_job_sends_its_request_and_its_answer_is_written() {
    let stub = Stub::serve(vec![Canned::json(200, decision("block", 0.95, 0.00002))]);
    let (_harness, state, mut rig) = wired(&stub).await;
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
    let body = start.body.clone();

    let mut jobs = Jobs::new(Arc::clone(&rig.ai));
    spawn_job(&mut jobs, start);
    assert!(!jobs.is_empty());
    let (id, outcome) = jobs.next().await.expect("the job comes back");
    assert!(matches!(outcome, Outcome::Answered(Reply::Body(_))));
    let settlement = rig.pipeline.settle(at(t + 11), id, outcome);
    persist(&state, settlement).await;

    let sent = stub.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].target, "/api/alpha/decisions");
    assert_eq!(
        sent[0].header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert_eq!(sent[0].body, body);

    let row = state
        .storage
        .ai_verdict(name(0))
        .await
        .expect("read the AI list")
        .expect("the answer was stored");
    assert_eq!(
        (row.verdict.as_str(), row.model.as_str()),
        ("block", "typesafe/jev-1.13-20260917")
    );
    assert_eq!(rig.ai.today(t + 11).micro_usd, usd_to_micro(0.00002));
    // The installer was woken; its permit is waiting.
    tokio::time::timeout(Duration::from_secs(1), rig.ai.install.notified())
        .await
        .expect("the installer is told about the row");
}

#[tokio::test]
async fn the_reviewer_reads_stopped_once_its_task_ends() {
    for abort in [false, true] {
        let harness = Harness::new().await;
        consent(&harness.state.storage).await;
        let (ai, tap) = load(&with_env_key(config()), &harness.state.storage).await;
        let (stop, shutdown) = watch::channel(false);
        let state = ServerState {
            ai: Arc::clone(&ai),
            shutdown,
            ..harness.state.clone()
        };
        let reviewer = tokio::spawn(worker::task(state, tap));
        for _ in 0..100 {
            if ai.tap().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(ai.tap().is_some(), "a live reviewer opens the gate");

        // Shutdown, or an abort (a panic drops the guard the same way).
        if abort {
            reviewer.abort();
            assert!(reviewer.await.expect_err("aborted").is_cancelled());
        } else {
            stop.send(true).expect("signal shutdown");
            reviewer.await.expect("the reviewer returns");
        }
        assert_eq!(ai.state(), State::Stopped);
        assert!(ai.tap().is_none());
        assert!(ai.applying(), "stored verdicts keep applying");
    }
}
