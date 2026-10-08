//! `verdict.rs`: an answer to a stored verdict (§6.9), cross-site re-checks (§6.10), how long a
//! row lasts (§6.11), and `compile` with `ListState` (§5.1), the one place rows become policy.

use crate::ai::prompt::{self, Answer, Choice, Outcome};
use crate::ai::verdict::{
    self, ALLOWS_PER_DAY, ALLOWS_PER_LOAD, Allowed, Decision, Judgement, Recheck, Why, contest,
    decide, recheck_due, review_after,
};
use crate::ai::{DAY, Known, ListState};
use cogwheel_policy::{Action, AiList, ListIndex, Pattern};
use cogwheel_storage::{AiDecision, AiVerdict};

/// 2026-10-08 00:00 UTC.
const T: i64 = 1_791_417_600;

/// One list in slot 0 that blocks `blocked.example`, excepts `excepted.example` and blocks every
/// name under `cdn.example` but one; and a second list, in slot 1, that blocks `other.example`.
fn index() -> ListIndex {
    let mut builder = ListIndex::builder();
    builder
        .name(0, "Ads")
        .name(1, "Other")
        .insert(0, Action::Block, Pattern::Exact, "blocked.example")
        .insert(0, Action::Allow, Pattern::Exact, "excepted.example")
        .insert(0, Action::Block, Pattern::Exact, "excepted.example")
        .insert(0, Action::Block, Pattern::Suffix, "cdn.example")
        .insert(0, Action::Allow, Pattern::Exact, "img.cdn.example")
        .insert(1, Action::Block, Pattern::Exact, "other.example");
    builder.build()
}

fn row(domain: &str, verdict: &str, confidence: Option<f64>) -> AiVerdict {
    AiVerdict {
        domain: domain.to_owned(),
        verdict: verdict.to_owned(),
        why: None,
        choice: verdict.to_owned(),
        confidence,
        effect: None,
        effect_confidence: None,
        lists: "nothing".to_owned(),
        site: Some("www.example.com".to_owned()),
        conflict_site: None,
        rechecks: 0,
        model: "typesafe/jev-1.13-20260917".to_owned(),
        judged_at: 1_791_480_000,
        review_after: 1_794_072_000,
    }
}

fn with_effect(mut row: AiVerdict, effect: &str, confidence: Option<f64>) -> AiVerdict {
    row.effect = Some(effect.to_owned());
    row.effect_confidence = confidence;
    row
}

/// `verdict::compile` over what a policy build reads of `rows`.
fn compile(rows: &[AiVerdict], index: &ListIndex, mask: u64) -> AiList {
    let decisions: Vec<AiDecision> = rows.iter().map(AiDecision::from).collect();
    verdict::compile(&decisions, index, mask)
}

fn compiled(rows: &[AiVerdict], index: &ListIndex, mask: u64) -> Vec<(String, Action)> {
    let mut names: Vec<(String, Action)> = compile(rows, index, mask)
        .iter()
        .map(|(name, action)| (name.to_owned(), action))
        .collect();
    names.sort_by(|left, right| left.0.cmp(&right.0));
    names
}

#[test]
fn list_state_is_an_exception_over_a_block_under_the_mask() {
    let index = index();
    assert_eq!(
        ListState::of(&index, 0b11, "blocked.example"),
        ListState::Block
    );
    assert_eq!(
        ListState::of(&index, 0b11, "excepted.example"),
        ListState::Exception
    );
    assert_eq!(
        ListState::of(&index, 0b11, "a.cdn.example"),
        ListState::Block
    );
    assert_eq!(
        ListState::of(&index, 0b11, "img.cdn.example"),
        ListState::Exception
    );
    assert_eq!(
        ListState::of(&index, 0b11, "plain.example"),
        ListState::Nothing
    );
    // Only the lists under the mask count.
    assert_eq!(
        ListState::of(&index, 0b10, "blocked.example"),
        ListState::Nothing
    );
    assert_eq!(
        ListState::of(&index, 0b10, "other.example"),
        ListState::Block
    );
    for state in [ListState::Nothing, ListState::Block, ListState::Exception] {
        assert_eq!(ListState::parse(state.as_str()), Some(state));
    }
    assert_eq!(ListState::parse("allow"), None);
}

#[test]
fn compile_applies_bars_against_the_live_lists() {
    let index = index();
    let rows = [
        // A plain block needs 0.85.
        row("tracker.example", "block", Some(0.85)),
        row("weak.example", "block", Some(0.84)),
        row("unrated.example", "block", None),
        row("nan.example", "block", Some(f64::NAN)),
        // An allow over a list block needs 0.92 and a "breaks" answer at 0.90.
        with_effect(
            row("blocked.example", "allow", Some(0.92)),
            "breaks",
            Some(0.90),
        ),
        with_effect(
            row("a.cdn.example", "allow", Some(0.95)),
            "breaks",
            Some(0.89),
        ),
        with_effect(
            row("b.cdn.example", "allow", Some(0.91)),
            "breaks",
            Some(0.99),
        ),
        with_effect(
            row("c.cdn.example", "allow", Some(0.99)),
            "unsure",
            Some(0.99),
        ),
        with_effect(row("d.cdn.example", "allow", Some(0.99)), "breaks", None),
        // A block over a list exception needs 0.92 and a "works" answer at 0.90.
        with_effect(
            row("excepted.example", "block", Some(0.93)),
            "works",
            Some(0.95),
        ),
        with_effect(
            row("img.cdn.example", "block", Some(0.93)),
            "breaks",
            Some(0.95),
        ),
        // Ignores never compile, whatever they carry.
        row("ignored.example", "ignore", Some(0.99)),
    ];
    assert_eq!(
        compiled(&rows, &index, 0b11),
        [
            ("blocked.example".to_owned(), Action::Allow),
            ("excepted.example".to_owned(), Action::Block),
            ("tracker.example".to_owned(), Action::Block),
        ]
    );

    // The lists change under the verdicts. The allow has no list block left to override, so it
    // stops applying; the lists now block `tracker.example` themselves, so the AI block steps
    // back; and the two blocks judged over an exception that is gone are plain blocks now, which
    // their 0.93 clears.
    let mut builder = ListIndex::builder();
    builder.insert(0, Action::Block, Pattern::Exact, "tracker.example");
    let changed = builder.build();
    assert_eq!(
        compiled(&rows, &changed, 0b1),
        [
            ("excepted.example".to_owned(), Action::Block),
            ("img.cdn.example".to_owned(), Action::Block),
        ]
    );

    // Judged against the household's lists only: with no slot enabled no list has an opinion,
    // so no allow has anything to override and every block is a plain one.
    assert_eq!(
        compiled(&rows, &index, 0),
        [
            ("excepted.example".to_owned(), Action::Block),
            ("img.cdn.example".to_owned(), Action::Block),
            ("tracker.example".to_owned(), Action::Block),
        ]
    );
}

#[test]
fn an_allow_never_compiles_over_a_list_exception() {
    // The `@@` inversion: a list exception skips the CNAME re-check, an AI allow runs it, so
    // turning one into the other is how a "whitelist" could end up blocking.
    let index = index();
    let rows = [
        with_effect(
            row("excepted.example", "allow", Some(0.99)),
            "breaks",
            Some(0.99),
        ),
        with_effect(
            row("img.cdn.example", "allow", Some(0.99)),
            "breaks",
            Some(0.99),
        ),
        // And an allow with nothing to whitelist is nothing.
        with_effect(
            row("plain.example", "allow", Some(0.99)),
            "breaks",
            Some(0.99),
        ),
    ];
    assert!(compile(&rows, &index, 0b11).is_empty());
}

#[test]
fn a_block_the_lists_already_make_is_left_to_the_lists() {
    // At decision time it is stored as agreeing, however sure the model is...
    for confidence in [0.5, 0.99] {
        assert_eq!(
            decide(
                ListState::Block,
                &rated(Choice::Block, confidence),
                Allowed::default()
            ),
            Decision::Ignore(Why::Agrees)
        );
    }
    // ...and a stored block on a name the lists block is never compiled.
    let index = index();
    let rows = [
        row("blocked.example", "block", Some(0.99)),
        row("deep.a.cdn.example", "block", Some(0.99)),
        row("other.example", "block", Some(0.99)),
    ];
    // Every one is blocked by a household list already, which keeps the attribution.
    assert!(compile(&rows, &index, 0b11).is_empty());
}

#[test]
fn compile_takes_exact_normalised_names_and_never_a_protected_one() {
    let index = index();
    let rows = [
        row("Ads.Tracker.Example.", "block", Some(0.9)),
        row("not a name", "block", Some(0.9)),
        row("bare", "block", Some(0.9)),
        // Protected names outrank the AI list, so a verdict on one is never installed.
        row("captive.apple.com", "block", Some(0.99)),
        row("connectivitycheck.gstatic.com", "block", Some(0.99)),
    ];
    let list = compile(&rows, &index, 0b11);
    assert_eq!(
        list.iter().collect::<Vec<_>>(),
        [("ads.tracker.example", Action::Block)]
    );
    assert_eq!(list.get("tracker.example"), None, "exact names only");
    assert_eq!((list.blocks(), list.allows()), (1, 0));
}

// --------------------------------------------------------------------- answer → verdict

fn rated(choice: Choice, confidence: f64) -> Answer {
    Answer {
        choice,
        confidence: Some(confidence),
        effect: None,
    }
}

fn effect(choice: Choice, confidence: f64, outcome: Outcome, sure: Option<f64>) -> Answer {
    Answer {
        effect: Some((outcome, sure)),
        ..rated(choice, confidence)
    }
}

#[test]
fn answers_map_to_verdicts_per_the_table() {
    use Choice::{Allow, Block, Ignore};
    use ListState::{Exception, Nothing};
    use Outcome::{Breaks, Unsure, Works};
    let listed = ListState::Block;
    let unsure = Decision::Ignore(Why::Unsure);
    let agrees = Decision::Ignore(Why::Agrees);
    let room = Allowed::default();
    for (lists, answer, expected) in [
        // Nothing lists it: a block needs 0.85; an allow agrees.
        (Nothing, rated(Block, 0.85), Decision::Block),
        (Nothing, rated(Block, 0.849), unsure),
        (Nothing, rated(Allow, 0.99), agrees),
        (Nothing, rated(Allow, 0.10), agrees),
        // The lists block it: a block agrees; an allow needs 0.92 and "breaks" at 0.90.
        (listed, rated(Block, 0.99), agrees),
        (
            listed,
            effect(Allow, 0.92, Breaks, Some(0.90)),
            Decision::Allow,
        ),
        (listed, effect(Allow, 0.919, Breaks, Some(0.99)), unsure),
        (listed, effect(Allow, 0.99, Breaks, Some(0.899)), unsure),
        (listed, effect(Allow, 0.99, Breaks, None), unsure),
        (listed, effect(Allow, 0.99, Works, Some(0.99)), unsure),
        (listed, effect(Allow, 0.99, Unsure, Some(0.99)), unsure),
        (listed, rated(Allow, 0.99), unsure),
        // The lists make an exception: a block needs 0.92 and "works" at 0.90; an allow agrees.
        (
            Exception,
            effect(Block, 0.92, Works, Some(0.90)),
            Decision::Block,
        ),
        (Exception, effect(Block, 0.91, Works, Some(0.99)), unsure),
        (Exception, effect(Block, 0.99, Breaks, Some(0.99)), unsure),
        (Exception, effect(Block, 0.99, Works, Some(0.89)), unsure),
        (Exception, rated(Block, 0.99), unsure),
        (Exception, rated(Allow, 0.99), agrees),
        // Ignore, from anyone, about anything.
        (Nothing, rated(Ignore, 0.99), unsure),
        (listed, effect(Ignore, 0.99, Breaks, Some(0.99)), unsure),
        (Exception, effect(Ignore, 0.99, Works, Some(0.99)), unsure),
        // A confidence that is not a number is no confidence.
        (Nothing, rated(Block, f64::NAN), unsure),
        (listed, effect(Allow, 0.99, Breaks, Some(f64::NAN)), unsure),
    ] {
        assert_eq!(
            decide(lists, &answer, room),
            expected,
            "{lists:?} {answer:?}"
        );
    }
    // The one row with a cap: the same answer over a full cap.
    let full = Allowed {
        this_load: ALLOWS_PER_LOAD,
        today: 0,
    };
    assert_eq!(
        decide(listed, &effect(Allow, 0.99, Breaks, Some(0.99)), full),
        Decision::Ignore(Why::Limit)
    );
    for (decision, verdict, why) in [
        (Decision::Block, "block", None),
        (Decision::Allow, "allow", None),
        (agrees, "ignore", Some("agrees")),
        (unsure, "ignore", Some("unsure")),
        (Decision::Ignore(Why::Limit), "ignore", Some("limit")),
        (
            Decision::Ignore(Why::Contested),
            "ignore",
            Some("contested"),
        ),
    ] {
        assert_eq!(decision.verdict(), verdict);
        assert_eq!(decision.why().map(Why::as_str), why);
    }
}

#[test]
fn confidence_not_probabilities_sets_the_bar() {
    // The tutorial's answer: 0.78 for the choice among the probabilities, a confidence of 0.67.
    // The bar is on the confidence, which is what the documented calibration is about (D6).
    let leaning = r#"{"answers":{"role":{"type":"choice","choice":"block","confidence":0.67,
        "probabilities":{"block":0.97,"allow":0.02,"ignore":0.01}}}}"#;
    let answer = prompt::parse(leaning.as_bytes(), false)
        .answer
        .expect("a readable answer");
    let decision = decide(ListState::Nothing, &answer, Allowed::default());
    assert_eq!(decision, Decision::Ignore(Why::Unsure));
    // Stored as it leaned, with the model's own figure, and never compiled.
    let stored = judged("ads.tracker.example", ListState::Nothing, answer, decision);
    assert_eq!(
        (stored.choice.as_str(), stored.confidence),
        ("block", Some(0.67))
    );
    assert!(compile(&[stored], &index(), 0b11).is_empty());

    let sure = r#"{"answers":{"role":{"type":"choice","choice":"block","confidence":0.9,
        "probabilities":{"block":0.5,"allow":0.3,"ignore":0.2}}}}"#;
    let answer = prompt::parse(sure.as_bytes(), false)
        .answer
        .expect("a readable answer");
    let decision = decide(ListState::Nothing, &answer, Allowed::default());
    assert_eq!(decision, Decision::Block);
    let stored = judged("ads.tracker.example", ListState::Nothing, answer, decision);
    assert_eq!(compile(&[stored], &index(), 0b11).len(), 1);
}

#[test]
fn override_caps_record_limit() {
    let answer = effect(Choice::Allow, 0.95, Outcome::Breaks, Some(0.95));
    let decide = |this_load, today| decide(ListState::Block, &answer, Allowed { this_load, today });
    assert_eq!(
        decide(ALLOWS_PER_LOAD - 1, ALLOWS_PER_DAY - 1),
        Decision::Allow
    );
    assert_eq!(decide(ALLOWS_PER_LOAD, 0), Decision::Ignore(Why::Limit));
    assert_eq!(decide(0, ALLOWS_PER_DAY), Decision::Ignore(Why::Limit));
    assert_eq!((ALLOWS_PER_LOAD, ALLOWS_PER_DAY), (3, 20));
    // A capped answer keeps everything the model said, and is never compiled: the list block
    // stands.
    let decision = decide(ALLOWS_PER_LOAD, 0);
    let stored = judged("blocked.example", ListState::Block, answer, decision);
    assert_eq!(
        (
            stored.verdict.as_str(),
            stored.why.as_deref(),
            stored.choice.as_str(),
            stored.effect.as_deref(),
            stored.effect_confidence
        ),
        ("ignore", Some("limit"), "allow", Some("breaks"), Some(0.95))
    );
    assert!(compile(&[stored], &index(), 0b11).is_empty());
}

/// A row as the reviewer writes it, judged at `T` for `www.news-site.com`.
fn judged(domain: &str, lists: ListState, answer: Answer, decision: Decision) -> AiVerdict {
    Judgement {
        domain,
        lists,
        answer,
        decision,
        site: Some("www.news-site.com"),
        model: "typesafe/jev-1.13-20260917",
        judged_at: T,
    }
    .row(30)
}

#[test]
fn a_fresh_judgement_keeps_every_answer_and_no_rechecks() {
    let judgement = Judgement {
        domain: "blocked.example",
        lists: ListState::Block,
        answer: effect(Choice::Allow, 0.93, Outcome::Breaks, Some(0.95)),
        decision: Decision::Allow,
        site: Some("www.news-site.com"),
        model: "typesafe/jev-1.13-20260917",
        judged_at: T,
    };
    assert_eq!(
        judgement.row(30),
        AiVerdict {
            domain: "blocked.example".to_owned(),
            verdict: "allow".to_owned(),
            why: None,
            choice: "allow".to_owned(),
            confidence: Some(0.93),
            effect: Some("breaks".to_owned()),
            effect_confidence: Some(0.95),
            lists: "block".to_owned(),
            site: Some("www.news-site.com".to_owned()),
            conflict_site: None,
            rechecks: 0,
            model: "typesafe/jev-1.13-20260917".to_owned(),
            judged_at: T,
            review_after: T + 30 * DAY,
        }
    );
    // Clear log ran while it was in flight: it lands with no website.
    let unsited = Judgement {
        site: None,
        ..judgement
    };
    assert_eq!(unsited.row(30).site, None);
}

#[test]
fn review_after_depends_on_the_kind_of_row() {
    for history_days in [1, 7, 30, 90] {
        let ignore_days = i64::from(history_days).min(30);
        for (decision, days) in [
            (Decision::Block, 30),
            (Decision::Allow, 30),
            (Decision::Ignore(Why::Agrees), ignore_days),
            (Decision::Ignore(Why::Unsure), ignore_days),
            (Decision::Ignore(Why::Limit), ignore_days),
            (Decision::Ignore(Why::Contested), 90),
        ] {
            assert_eq!(
                review_after(decision, T, history_days),
                T + days * DAY,
                "{decision:?} with HISTORY_DAYS={history_days}"
            );
        }
    }
}

// --------------------------------------------------------------------- cross-site re-checks

fn known(verdict: Option<Action>, site_key: Option<&str>) -> Known {
    Known {
        verdict,
        lists: ListState::Nothing,
        judged_at: T,
        review_after: T + 30 * DAY,
        site_key: site_key.map(Box::from),
        rechecks: 0,
        last_recheck_day: 0,
    }
}

#[test]
fn a_recheck_is_due_in_another_websites_load_at_most_once_a_day() {
    let today = 20_369;
    let block = known(Some(Action::Block), Some("news-site.com"));
    assert!(recheck_due(&block, "shop.com", today));
    assert!(
        !recheck_due(&block, "news-site.com", today),
        "its own website"
    );
    assert!(!recheck_due(
        &Known {
            last_recheck_day: today,
            ..block.clone()
        },
        "shop.com",
        today
    ));
    assert!(!recheck_due(
        &Known {
            rechecks: 2,
            ..block.clone()
        },
        "shop.com",
        today
    ));
    // Only a decision is re-checked; an ignore of any kind is left to expire.
    assert!(!recheck_due(
        &known(None, Some("news-site.com")),
        "shop.com",
        today
    ));
    // A website Clear log forgot counts as another one.
    assert!(recheck_due(
        &known(Some(Action::Allow), None),
        "news-site.com",
        today
    ));
}

#[test]
fn opposite_answers_from_two_sites_hand_the_name_back_to_the_lists() {
    let now = T + 3 * DAY;
    let block = judged(
        "cdn.example-cdn.net",
        ListState::Nothing,
        rated(Choice::Block, 0.9),
        Decision::Block,
    );
    let allow = judged(
        "blocked.example",
        ListState::Block,
        effect(Choice::Allow, 0.95, Outcome::Breaks, Some(0.95)),
        Decision::Allow,
    );
    // The opposite direction above the plain bar.
    assert_eq!(
        contest(Action::Block, &rated(Choice::Allow, 0.85)),
        Recheck::Contested
    );
    assert_eq!(
        contest(Action::Allow, &rated(Choice::Block, 0.85)),
        Recheck::Contested
    );
    // The same direction, ignore, below the bar, or no confidence at all: the verdict stands.
    for (stored, answer) in [
        (Action::Block, rated(Choice::Block, 0.99)),
        (Action::Block, rated(Choice::Ignore, 0.99)),
        (Action::Block, rated(Choice::Allow, 0.849)),
        (Action::Allow, rated(Choice::Allow, 0.99)),
        (Action::Allow, rated(Choice::Block, 0.80)),
        (
            Action::Allow,
            Answer {
                confidence: None,
                ..rated(Choice::Block, 0.0)
            },
        ),
    ] {
        assert_eq!(
            contest(stored, &answer),
            Recheck::Kept,
            "{stored:?} {answer:?}"
        );
    }

    let kept = Recheck::Kept.apply(block.clone(), Some("www.shop.com"), now);
    assert_eq!(
        kept,
        AiVerdict {
            rechecks: 1,
            ..block.clone()
        }
    );
    let contested = Recheck::Contested.apply(block.clone(), Some("www.shop.com"), now);
    assert_eq!(
        contested,
        AiVerdict {
            verdict: "ignore".to_owned(),
            why: Some("contested".to_owned()),
            conflict_site: Some("www.shop.com".to_owned()),
            rechecks: 1,
            review_after: now + 90 * DAY,
            ..block.clone()
        },
        "the first answer and website stay; the other website is named"
    );
    let contested_allow = Recheck::Contested.apply(allow.clone(), None, now);
    assert_eq!(
        (
            contested_allow.verdict.as_str(),
            contested_allow.conflict_site.as_deref()
        ),
        ("ignore", None)
    );
    // Back to the lists: neither compiles any more, so the lists decide for both names.
    assert_eq!(
        compile(&[block.clone(), allow.clone()], &index(), 0b11).len(),
        2
    );
    assert!(compile(&[contested.clone(), contested_allow], &index(), 0b11).is_empty());
    // And it is no longer a decision to re-check.
    assert!(!recheck_due(&Known::of(&contested), "other.com", 0));
    // The schema allows two re-checks, and no more.
    let twice = Recheck::Kept.apply(Recheck::Kept.apply(block, None, now), None, now);
    assert_eq!(Recheck::Kept.apply(twice, None, now).rechecks, 2);
}

#[tokio::test]
async fn a_contested_row_is_kept_for_ninety_days() {
    let storage = super::storage().await;
    let contested = Recheck::Contested.apply(
        judged(
            "cdn.example-cdn.net",
            ListState::Nothing,
            rated(Choice::Block, 0.9),
            Decision::Block,
        ),
        Some("www.shop.com"),
        T + 10 * DAY,
    );
    assert_eq!(contested.judged_at, T);
    assert_eq!(contested.review_after, T + 100 * DAY);
    // An ordinary ignore judged the same day, with one day of history kept.
    let ordinary = Judgement {
        domain: "fonts.example-cdn.net",
        lists: ListState::Nothing,
        answer: rated(Choice::Ignore, 0.9),
        decision: Decision::Ignore(Why::Unsure),
        site: Some("www.news-site.com"),
        model: "typesafe/jev-1.13-20260917",
        judged_at: T,
    }
    .row(1);
    assert_eq!(ordinary.review_after, T + DAY);
    storage
        .record_ai_verdicts(vec![contested, ordinary], "20369 0 0 0".to_owned())
        .await
        .expect("store both rows");

    // A month on, the ordinary ignore has long gone; the contested row is still a decision.
    let pruned = storage
        .prune_ai_verdicts(T + 31 * DAY, 1, 10_000)
        .await
        .expect("prune");
    assert_eq!(
        (pruned.domains, pruned.decisions),
        (vec!["fonts.example-cdn.net".to_owned()], 0)
    );
    let pruned = storage
        .prune_ai_verdicts(T + 90 * DAY - 1, 1, 10_000)
        .await
        .expect("prune");
    assert!(pruned.domains.is_empty(), "kept for ninety days");
    // Ninety days after it was judged, like a block or allow, it goes.
    let pruned = storage
        .prune_ai_verdicts(T + 90 * DAY, 1, 10_000)
        .await
        .expect("prune");
    assert_eq!(
        (pruned.domains, pruned.decisions),
        (vec!["cdn.example-cdn.net".to_owned()], 1)
    );
}
