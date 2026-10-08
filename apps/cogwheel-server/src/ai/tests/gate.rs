//! `gate.rs`, `known.rs` and the tap: the send gate and its state machine (D18), what is offered
//! to the reviewer (§6.2), and the `known` map and its cap (§6.6).

use super::{config, consent, load, storage, with_env_key};
use crate::ai::{
    AiState, Halt, KEY_REFUSED, KNOWN_CAP, Known, ListState, MODEL_UNRATED, NO_ANSWER,
    RATE_LIMITED, STOPPED, State, offer,
};
use cogwheel_dns_core::LogEntry;
use cogwheel_policy::{Action, Reason, Verdict};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

/// A reviewing state: consent, a model and an environment key.
async fn reviewing() -> Arc<AiState> {
    let storage = storage().await;
    consent(&storage).await;
    load(&with_env_key(config()), &storage).await.0
}

#[tokio::test]
async fn the_gate_opens_only_while_reviewing_with_a_live_reviewer() {
    // Nothing configured: off (the card offers set-up), and the gate shut. `no_key` is for a
    // review that is on and has lost its key.
    let (fresh, _rx) = load(&config(), &storage().await).await;
    assert_eq!(fresh.state(), State::Off);
    assert!(fresh.tap().is_none());
    assert!(!fresh.applying());
    assert!(!fresh.may_send(fresh.generation()));

    // Consent, a model and a key: reviewing, but nothing is sent until a reviewer is alive.
    let ai = reviewing().await;
    assert_eq!(ai.state(), State::Reviewing);
    assert!(ai.applying());
    assert!(ai.tap().is_none(), "no reviewer, no tap");
    let alive = ai.reviewer_alive();
    assert!(ai.tap().is_some());
    let generation = ai.generation();
    assert!(ai.may_send(generation));
    assert!(
        !ai.may_send(generation - 1),
        "a job from an older generation never sends"
    );
    drop(alive);
}

/// The UTC rollover resumes only from the pause it is ending, in one step under the machine lock:
/// a Turn off that halted after it read the state stays off, and the gate stays closed.
#[tokio::test]
async fn a_rollover_resume_never_reopens_review_turned_off_meanwhile() {
    let ai = reviewing().await;
    let _alive = ai.reviewer_alive();
    let paused = [State::PausedBudget, State::OutOfCredit];
    ai.halt(Halt::Budget);
    assert!(ai.resume_from(&paused), "a new day ends the pause");
    assert!(ai.tap().is_some());

    ai.halt(Halt::Budget);
    // `PUT {enabled:false}` halts before it writes the switch.
    ai.halt(Halt::Off);
    assert!(!ai.resume_from(&paused));
    assert_eq!(ai.machine_state(), State::Off);
    assert!(ai.tap().is_none());
}

#[tokio::test]
async fn halting_closes_the_gate_and_aborts_in_flight_requests() {
    let ai = reviewing().await;
    let _alive = ai.reviewer_alive();
    let generation = ai.generation();
    let request = tokio::spawn(std::future::pending::<()>());
    ai.track(7, generation, request.abort_handle());

    ai.halt(Halt::Off);
    // Synchronous: by the time `halt` returns the gate is shut and the request is cancelled.
    assert!(ai.tap().is_none());
    assert!(!ai.may_send(generation));
    assert!(ai.generation() > generation);
    assert_eq!(ai.machine_state(), State::Off);
    assert!(request.await.expect_err("aborted").is_cancelled());

    // A job spawned under the old generation is aborted as it registers: a halt raced it.
    let late = tokio::spawn(std::future::pending::<()>());
    ai.track(8, generation, late.abort_handle());
    assert!(late.await.expect_err("aborted").is_cancelled());

    // Resuming opens a new generation, and clears the sentence of a terminal state.
    ai.halt(Halt::KeyRefused);
    assert_eq!(ai.state(), State::KeyRefused);
    assert_eq!(ai.last_error(), Some(KEY_REFUSED));
    let before = ai.generation();
    ai.resume();
    assert_eq!(ai.state(), State::Reviewing);
    assert_eq!(ai.last_error(), None);
    assert!(ai.generation() > before);
    assert!(ai.may_send(ai.generation()));

    // `model_refused` carries the sentence its cause sets; a change of key or model keeps the
    // state for the same write to resume from.
    ai.halt_because(Halt::ModelRefused, Some(MODEL_UNRATED));
    assert_eq!(
        (ai.state(), ai.last_error()),
        (State::ModelRefused, Some(MODEL_UNRATED))
    );
    ai.resume();
    ai.halt(Halt::ModelChanged);
    assert_eq!(ai.state(), State::Reviewing);
    assert!(ai.tap().is_none(), "but the gate is shut until it does");
    ai.resume();
    assert!(ai.tap().is_some());
}

#[tokio::test]
async fn retrying_keeps_the_gate_open_and_any_exit_ends_it() {
    let ai = reviewing().await;
    let _alive = ai.reviewer_alive();
    ai.mark_retrying(RATE_LIMITED);
    assert_eq!(ai.state(), State::Retrying);
    assert!(ai.tap().is_some(), "retrying is still reviewing");
    ai.mark_recovered(1_791_480_000);
    assert_eq!((ai.state(), ai.last_error()), (State::Reviewing, None));

    ai.mark_retrying(NO_ANSWER);
    ai.halt(Halt::Budget);
    assert_eq!(ai.state(), State::PausedBudget);
    assert_eq!(ai.last_error(), None, "the retrying sentence went with it");
    assert!(ai.tap().is_none());
    // Not reviewing, so a failure elsewhere cannot make it look like it is.
    ai.mark_retrying(NO_ANSWER);
    assert_eq!(ai.state(), State::PausedBudget);
}

#[tokio::test]
async fn a_dead_reviewer_reads_stopped_and_stays_stopped() {
    let ai = reviewing().await;
    let alive = ai.reviewer_alive();
    assert!(ai.tap().is_some());
    drop(alive);
    assert_eq!(ai.state(), State::Stopped);
    assert_eq!(ai.last_error(), Some(STOPPED));
    assert!(ai.tap().is_none());
    assert!(!ai.may_send(ai.generation()));
    // Nothing reopens it: there is no reviewer to send.
    ai.resume();
    ai.halt(Halt::Off);
    assert_eq!(ai.state(), State::Stopped);
    assert!(ai.tap().is_none());
    assert!(ai.applying(), "stored verdicts keep applying");
}

/// A lookup of `cdn.example.com` that the upstream answered with public addresses, so only its
/// type and verdict decide whether it is offered.
fn entry(qtype: u16, verdict: Verdict) -> LogEntry {
    LogEntry {
        ts: 1_791_480_000,
        client: "192.168.1.20".parse().expect("an address"),
        domain: Arc::from("cdn.example.com"),
        qtype,
        verdict,
        list: None,
        answered_public: true,
    }
}

#[tokio::test]
async fn the_tap_offers_only_reviewable_reasons_and_types() {
    let ai = reviewing().await;
    let (tap, mut seen) = mpsc::channel(64);
    let offered = [
        (1, Verdict::allow(Reason::NoMatch), true),
        (28, Verdict::Allow(Reason::ListAllow, 2), true),
        (65, Verdict::Block(Reason::List, 1), true),
        (1, Verdict::Block(Reason::Ai, 0), true),
        (1, Verdict::allow(Reason::Ai), true),
        // Decided by a person, by protection, by a pause, or by an alias: never reviewed.
        (1, Verdict::Block(Reason::DeviceRule, 0), false),
        (1, Verdict::allow(Reason::HouseholdRule), false),
        (1, Verdict::allow(Reason::Protected), false),
        (1, Verdict::allow(Reason::Paused), false),
        (1, Verdict::allow(Reason::Unfiltered), false),
        (1, Verdict::Block(Reason::Cname, 1), false),
        // PTR, TXT, SRV, MX: never.
        (12, Verdict::allow(Reason::NoMatch), false),
        (16, Verdict::allow(Reason::NoMatch), false),
        (33, Verdict::allow(Reason::NoMatch), false),
        (15, Verdict::allow(Reason::NoMatch), false),
    ];
    for (qtype, verdict, _) in offered {
        offer(&tap, &entry(qtype, verdict), &ai);
    }
    let expected: Vec<(Reason, bool)> = offered
        .iter()
        .filter(|(_, _, taken)| *taken)
        .map(|(_, verdict, _)| (verdict.reason(), verdict.is_blocked()))
        .collect();
    let mut got = Vec::new();
    while let Ok(item) = seen.try_recv() {
        assert_eq!(&*item.domain, "cdn.example.com");
        got.push((item.reason, item.blocked));
    }
    assert_eq!(got, expected);
    assert_eq!(ai.counters.tap_dropped.load(Ordering::Relaxed), 0);

    // A full channel drops and counts; it never waits.
    let (tap, _held) = mpsc::channel(1);
    for _ in 0..3 {
        offer(&tap, &entry(1, Verdict::allow(Reason::NoMatch)), &ai);
    }
    assert_eq!(ai.counters.tap_dropped.load(Ordering::Relaxed), 2);
}

/// F01: an allowed lookup is offered only when its answer was public. One that failed, came back
/// empty or resolved inside the house is never offered, whatever its suffix, so it can be neither
/// a candidate nor a website nor context; a name a list or the AI list blocked is offered either
/// way, because a block carries no answer and its listing already made it a public name.
#[tokio::test]
async fn the_tap_offers_an_allowed_lookup_only_when_its_answer_was_public() {
    let ai = reviewing().await;
    let (tap, mut seen) = mpsc::channel(64);
    let offered = [
        (1, Verdict::allow(Reason::NoMatch), true, true),
        (1, Verdict::allow(Reason::NoMatch), false, false),
        (28, Verdict::allow(Reason::NoMatch), false, false),
        (65, Verdict::allow(Reason::NoMatch), false, false),
        (1, Verdict::Allow(Reason::ListAllow, 2), false, false),
        (28, Verdict::Allow(Reason::ListAllow, 2), true, true),
        (1, Verdict::allow(Reason::Ai), false, false),
        (1, Verdict::allow(Reason::Ai), true, true),
        // Blocked: offered whatever the flag says, which for a block is always false.
        (1, Verdict::Block(Reason::List, 1), false, true),
        (65, Verdict::Block(Reason::List, 1), false, true),
        (28, Verdict::Block(Reason::Ai, 0), false, true),
        // A public answer does not reopen what the reason filter shuts.
        (1, Verdict::allow(Reason::HouseholdRule), true, false),
        (1, Verdict::Block(Reason::Cname, 1), false, false),
    ];
    for (qtype, verdict, answered_public, _) in offered {
        let entry = LogEntry {
            answered_public,
            ..entry(qtype, verdict)
        };
        offer(&tap, &entry, &ai);
    }
    let expected: Vec<(Reason, bool)> = offered
        .iter()
        .filter(|(_, _, _, taken)| *taken)
        .map(|(_, verdict, _, _)| (verdict.reason(), verdict.is_blocked()))
        .collect();
    let mut got = Vec::new();
    while let Ok(item) = seen.try_recv() {
        got.push((item.reason, item.blocked));
    }
    assert_eq!(got, expected);
    assert_eq!(ai.counters.tap_dropped.load(Ordering::Relaxed), 0);
}

fn known(judged_at: i64) -> Known {
    Known {
        verdict: Some(Action::Block),
        lists: ListState::Nothing,
        judged_at,
        review_after: judged_at + 30 * 86_400,
        site_key: Some("example.com".into()),
        rechecks: 0,
        last_recheck_day: 0,
    }
}

#[tokio::test]
async fn the_known_map_is_capped() {
    let (ai, _rx) = load(&config(), &storage().await).await;
    // Inserted newest-judged first, so eviction cannot just be insertion order.
    for at in (0..=KNOWN_CAP as i64).rev() {
        ai.remember(Arc::from(format!("n{at}.example").as_str()), known(at));
    }
    assert!(ai.known_len() <= KNOWN_CAP);
    let evicted = KNOWN_CAP / 10;
    assert_eq!(ai.known_len(), KNOWN_CAP + 1 - evicted);
    assert_eq!(ai.known("n0.example"), None, "the oldest judged went first");
    assert_eq!(ai.known(&format!("n{}.example", evicted - 1)), None);
    assert!(ai.known(&format!("n{evicted}.example")).is_some());
    assert!(ai.known(&format!("n{KNOWN_CAP}.example")).is_some());

    // Clear log forgets the websites, and tells an answer in flight to land without one.
    let epoch = ai.sites_epoch();
    ai.forget_sites();
    assert!(ai.sites_epoch() > epoch);
    assert_eq!(
        ai.known(&format!("n{KNOWN_CAP}.example"))
            .and_then(|entry| entry.site_key),
        None
    );
    ai.forget_known(&[format!("n{KNOWN_CAP}.example")]);
    assert_eq!(ai.known(&format!("n{KNOWN_CAP}.example")), None);
    ai.forget_all_known();
    assert_eq!(ai.known_len(), 0);
}
