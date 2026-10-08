//! `review.rs`, continued (§6.6, §6.10, D18): which names become candidates, what an answer does
//! to a name already judged, and what a halt leaves behind. The same synthetic clock and rig as
//! the bounds in `review.rs`, and no HTTP.

use super::review::{
    answered, at, blocking, device, empty, name, names, noon, push_load, request, rig, sighting,
    visit,
};
use super::verdict as stored;
use crate::ai::burst::{LATE, QUIET};
use crate::ai::spend::{Cost, usd_to_micro};
use crate::ai::verdict::Recheck;
use crate::ai::{DAY, Halt, KNOWN_CAP, Known, ListState, MODEL_UNRATED, State, offer};
use cogwheel_dns_core::LogEntry;
use cogwheel_policy::{Action, AiList, Reason, Verdict};
use std::sync::Arc;
use tokio::sync::mpsc;

fn entry(qtype: u16, domain: &str, verdict: Verdict) -> LogEntry {
    LogEntry {
        ts: u32::try_from(noon()).expect("a timestamp that fits"),
        client: device(1),
        domain: Arc::from(domain),
        qtype,
        verdict,
        list: None,
    }
}

#[tokio::test]
async fn the_tap_offers_only_reviewable_reasons_and_types() {
    let mut rig = rig().await;
    let t = noon();
    let (tap, mut taken) = mpsc::channel(64);
    let offered = [
        entry(1, "www.news-site.com", Verdict::allow(Reason::NoMatch)),
        entry(28, "ads.listed.com", Verdict::Block(Reason::List, 0)),
        entry(65, "img.excepted.com", Verdict::Allow(Reason::ListAllow, 0)),
        entry(1, "t.applied.com", Verdict::Block(Reason::Ai, 0)),
        entry(1, "mine.ruled.com", Verdict::allow(Reason::HouseholdRule)),
        entry(1, "kid.ruled.com", Verdict::Block(Reason::DeviceRule, 0)),
        entry(1, "alias.cname.com", Verdict::Block(Reason::Cname, 0)),
        entry(1, "paused.example.com", Verdict::allow(Reason::Paused)),
        entry(12, "ptr.news-site.com", Verdict::allow(Reason::NoMatch)),
        entry(16, "txt.news-site.com", Verdict::allow(Reason::NoMatch)),
        entry(33, "srv.news-site.com", Verdict::allow(Reason::NoMatch)),
    ];
    for entry in &offered {
        offer(&tap, entry, &rig.ai);
    }
    while let Ok(seen) = taken.try_recv() {
        rig.pipeline.push(seen);
    }
    // Pushed straight in, past the tap: the pipeline's own rule refuses it too.
    rig.pipeline.push(sighting(
        device(1),
        t,
        "safe.protected.com",
        Reason::Protected,
    ));
    rig.pipeline.tick(at(t + QUIET + LATE), &empty());

    for reviewable in ["ads.listed.com", "img.excepted.com", "t.applied.com"] {
        assert!(rig.pipeline.is_pending(reviewable), "{reviewable}");
    }
    assert_eq!(rig.pipeline.waiting(), 3);
}

#[tokio::test]
async fn the_home_context_rule_skips_another_opened_sites_names() {
    let mut rig = rig().await;
    let t = noon();
    let bank = vec!["cdn.bank-site.com".to_owned()];
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.bank-site.com",
        &bank,
    );
    assert!(
        rig.pipeline.is_pending("cdn.bank-site.com"),
        "judged in its own website's load"
    );

    // A junk page loads the bank's sign-in: never judged in that context.
    let junk = vec![
        "cdn.junk-site.com".to_owned(),
        "login.bank-site.com".to_owned(),
    ];
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t + 20,
        "www.junk-site.com",
        &junk,
    );
    assert!(rig.pipeline.is_pending("cdn.junk-site.com"));
    assert!(!rig.pipeline.is_pending("login.bank-site.com"));
}

/// A name judged recently with the lists' opinion `lists`.
fn judged(t: i64, verdict: Option<Action>, lists: ListState, site_key: &str) -> Known {
    Known {
        verdict,
        lists,
        judged_at: t - DAY,
        review_after: t + 29 * DAY,
        site_key: Some(site_key.into()),
        rechecks: 0,
        last_recheck_day: 0,
    }
}

#[tokio::test]
async fn a_lists_change_makes_a_known_name_due() {
    let mut rig = rig().await;
    let t = noon();
    let tracker = vec!["t.tracker-site.com".to_owned()];
    let contested = vec!["c.tracker-site.com".to_owned()];
    let agreed = judged(t, None, ListState::Nothing, "news-site.com");
    rig.ai
        .remember(Arc::from("t.tracker-site.com"), agreed.clone());
    let disputed = Known {
        review_after: t + 89 * DAY,
        ..agreed
    };
    rig.ai.remember(Arc::from("c.tracker-site.com"), disputed);

    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &tracker,
    );
    assert!(
        !rig.pipeline.is_pending("t.tracker-site.com"),
        "known, and not due"
    );

    // A list now blocks it: judged afresh, with the effect question this time.
    let listed = blocking(&["t.tracker-site.com", "c.tracker-site.com"]);
    visit(
        &mut rig.pipeline,
        &listed,
        device(1),
        t + 20,
        "www.news-site.com",
        &tracker,
    );
    assert!(rig.pipeline.is_pending("t.tracker-site.com"));
    let start = rig.pipeline.next_start(at(t + 30)).expect("a start");
    let body = request(&start.body);
    assert!(body["questions"]["effect"].is_object());

    // A contested row waits out its 90 days whatever the lists do.
    visit(
        &mut rig.pipeline,
        &listed,
        device(1),
        t + 40,
        "www.news-site.com",
        &contested,
    );
    assert!(!rig.pipeline.is_pending("c.tracker-site.com"));
}

#[tokio::test]
async fn an_applied_verdict_is_judged_again_after_review_after() {
    let mut rig = rig().await;
    let t = noon();
    let blocked = Known {
        judged_at: t - 31 * DAY,
        review_after: t - DAY,
        ..judged(t, Some(Action::Block), ListState::Nothing, "old-site.com")
    };
    rig.ai.remember(Arc::from("t.tracker-site.com"), blocked);
    let list: AiList = [("t.tracker-site.com", Action::Block)]
        .into_iter()
        .collect();
    let applying = empty().with_ai(Arc::new(list));

    // Seen as the AI list blocking it, 31 days after it was judged.
    let pipeline = &mut rig.pipeline;
    pipeline.push(sighting(device(1), t, "www.news-site.com", Reason::NoMatch));
    let mut applied = sighting(device(1), t, "t.tracker-site.com", Reason::Ai);
    applied.blocked = true;
    pipeline.push(applied);
    pipeline.tick(at(t + QUIET + LATE), &applying);
    assert!(pipeline.is_pending("t.tracker-site.com"));

    let start = pipeline.next_start(at(t + 10)).expect("a start");
    let settled = pipeline.settle(at(t + 11), start.id, answered("block", Some(0.95), 0.00002));
    let row = settled.rows.first().expect("a fresh row");
    assert_eq!(row.verdict, "block");
    assert_eq!(row.rechecks, 0);
    assert_eq!(row.site.as_deref(), Some("www.news-site.com"));
    assert_eq!(row.judged_at, t + 11);
    let known = rig.ai.known("t.tracker-site.com").expect("still known");
    assert_eq!(known.judged_at, t + 11);
    assert_eq!(known.site_key.as_deref(), Some("news-site.com"));
}

#[tokio::test]
async fn a_cross_site_recheck_keeps_the_row_and_counts_it() {
    let mut rig = rig().await;
    let t = noon();
    let tracker = vec!["t.tracker-site.com".to_owned()];
    let row = stored("t.tracker-site.com", "block", t - DAY);
    rig.ai
        .remember(Arc::from("t.tracker-site.com"), Known::of(&row));

    // Its own website again (the row was judged for www.example.com): not due.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.example.com",
        &tracker,
    );
    assert!(!rig.pipeline.is_pending("t.tracker-site.com"));
    // Another website: asked again, in that context.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t + 20,
        "www.other-site.com",
        &tracker,
    );
    let start = rig.pipeline.next_start(at(t + 30)).expect("a re-check");
    assert_eq!(
        request(&start.body)["state"]["website"],
        "www.other-site.com"
    );
    let settled = rig
        .pipeline
        .settle(at(t + 31), start.id, answered("block", Some(0.9), 0.00002));
    assert!(settled.rows.is_empty(), "the row is kept, not replaced");
    let recheck = settled.recheck.expect("a re-check to apply");
    assert_eq!(recheck.outcome, Recheck::Kept);
    let kept = recheck.apply(row.clone());
    assert_eq!((kept.verdict.as_str(), kept.rechecks), ("block", 1));
    assert_eq!(kept.judged_at, row.judged_at);
    let known = rig.ai.known("t.tracker-site.com").expect("known");
    assert_eq!((known.rechecks, known.last_recheck_day), (1, at(t).day()));

    // At most one a day.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t + 60,
        "www.third-site.com",
        &tracker,
    );
    assert!(!rig.pipeline.is_pending("t.tracker-site.com"));

    // The next day, an opposite answer above the bar hands the name back to the lists.
    let tomorrow = t + DAY;
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        tomorrow,
        "www.third-site.com",
        &tracker,
    );
    let start = rig
        .pipeline
        .next_start(at(tomorrow + 10))
        .expect("a second re-check");
    let settled = rig.pipeline.settle(
        at(tomorrow + 11),
        start.id,
        answered("allow", Some(0.9), 0.00002),
    );
    let recheck = settled.recheck.expect("a re-check to apply");
    assert_eq!(recheck.outcome, Recheck::Contested);
    let contested = recheck.apply(kept);
    assert_eq!(contested.verdict, "ignore");
    assert_eq!(contested.why.as_deref(), Some("contested"));
    assert_eq!(
        contested.conflict_site.as_deref(),
        Some("www.third-site.com")
    );
    assert_eq!(contested.rechecks, 2);
    let known = rig.ai.known("t.tracker-site.com").expect("known");
    assert_eq!(known.verdict, None);

    // Contested: not asked again, in any website's context.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        tomorrow + DAY,
        "www.fourth-site.com",
        &tracker,
    );
    assert!(!rig.pipeline.is_pending("t.tracker-site.com"));
}

#[tokio::test]
async fn halting_empties_the_queue_bursts_and_pending_set() {
    let mut rig = rig().await;
    let t = noon();
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..4),
    );
    let started = rig.pipeline.next_start(at(t + 10)).expect("a start");
    push_load(
        &mut rig.pipeline,
        device(2),
        t + 10,
        "www.w2.com",
        &names(10..12),
        Reason::NoMatch,
    );
    assert_eq!((rig.pipeline.waiting(), rig.pipeline.bursts()), (3, 1));

    rig.ai.halt(Halt::Off);
    // A tick alone sees the halt: a missed wake-up costs at most one tick.
    rig.pipeline.tick(at(t + 11), &empty());
    assert_eq!((rig.pipeline.waiting(), rig.pipeline.bursts()), (0, 0));
    for n in [1, 2, 3, 10, 11] {
        assert!(!rig.pipeline.is_pending(&name(n)));
    }
    assert!(rig.pipeline.next_start(at(t + 60)).is_none());
    rig.pipeline.halt_local();
    assert!(rig.pipeline.next_start(at(t + 61)).is_none());

    // The answer to the request that was in flight is charged and never stored.
    let settled = rig.pipeline.settle(
        at(t + 62),
        started.id,
        answered("block", Some(0.99), 0.00002),
    );
    assert!(settled.rows.is_empty() && settled.recheck.is_none());
    assert_eq!(settled.cost, Cost::request(usd_to_micro(0.00002)));
    assert!(rig.ai.known(&name(0)).is_none());
}

#[tokio::test]
async fn the_known_map_is_capped() {
    let mut rig = rig().await;
    let t = noon();
    for n in 0..KNOWN_CAP {
        let age = i64::try_from(n).expect("a small number");
        let entry = judged(t - 40 * DAY + age, None, ListState::Nothing, "old.com");
        rig.ai
            .remember(Arc::from(format!("k{n}.old.com").as_str()), entry);
    }
    assert_eq!(rig.ai.known_len(), KNOWN_CAP);

    // The reviewer's answer is one more insert: the oldest tenth goes.
    visit(
        &mut rig.pipeline,
        &empty(),
        device(1),
        t,
        "www.news-site.com",
        &names(0..1),
    );
    let start = rig.pipeline.next_start(at(t + 10)).expect("a start");
    rig.pipeline
        .settle(at(t + 11), start.id, answered("block", Some(0.95), 0.00002));
    assert!(rig.ai.known_len() <= KNOWN_CAP);
    assert!(rig.ai.known(&name(0)).is_some());
    assert!(
        rig.ai.known("k0.old.com").is_none(),
        "the oldest judged went first"
    );
    assert!(
        rig.ai
            .known(&format!("k{}.old.com", KNOWN_CAP - 1))
            .is_some()
    );
}

#[tokio::test]
async fn three_unrated_answers_stop_the_model() {
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
    for (second, n) in [(10, 0), (11, 1), (12, 2)] {
        assert_eq!(rig.ai.state(), State::Reviewing);
        let start = rig.pipeline.next_start(at(t + second)).expect("a start");
        let settled =
            rig.pipeline
                .settle(at(t + second), start.id, answered("block", None, 0.00002));
        let row = settled.rows.first().expect("stored, as unsure");
        assert_eq!(row.domain, name(n));
        assert_eq!(
            (row.verdict.as_str(), row.why.as_deref()),
            ("ignore", Some("unsure"))
        );
    }
    assert_eq!(rig.ai.state(), State::ModelRefused);
    assert_eq!(rig.ai.last_error(), Some(MODEL_UNRATED));
    assert!(rig.ai.tap().is_none());
    assert!(rig.pipeline.next_start(at(t + 20)).is_none());
    assert_eq!(rig.pipeline.waiting(), 0);
}
