//! The AI list's table, its retention and the settings it shares a transaction with (ADR 0002).

mod common;

use common::*;

/// A day's spend as the server encodes it; storage only ever stores the string.
const SPEND: &str = "20369 1200 3 0";

/// A verdict with the fields most tests do not care about filled in. `review_after` is the 30 days
/// a block, an allow or an ordinary ignore gets with `HISTORY_DAYS >= 30`.
fn row(domain: &str, verdict: &str, why: Option<&str>, judged_at: i64) -> AiVerdict {
    AiVerdict {
        domain: domain.to_owned(),
        verdict: verdict.to_owned(),
        why: why.map(str::to_owned),
        choice: verdict.to_owned(),
        confidence: Some(0.9),
        effect: None,
        effect_confidence: None,
        lists: "nothing".to_owned(),
        site: Some("www.example.com".to_owned()),
        conflict_site: None,
        rechecks: 0,
        model: "example/decider-20260917".to_owned(),
        judged_at,
        review_after: judged_at + 30 * DAY,
    }
}

/// A contested row: judged in two websites' loads that disagreed, kept 90 days.
fn contested(domain: &str, judged_at: i64) -> AiVerdict {
    AiVerdict {
        conflict_site: Some("shop.example.org".to_owned()),
        review_after: judged_at + 90 * DAY,
        ..row(domain, "ignore", Some("contested"), judged_at)
    }
}

/// Store `rows` with the standard spend string, failing the test on any error.
async fn record(storage: &Storage, rows: Vec<AiVerdict>) {
    storage
        .record_ai_verdicts(rows, SPEND.to_owned())
        .await
        .expect("record verdicts");
}

/// Every domain left in the table, in domain order.
async fn domains(storage: &Storage) -> Vec<String> {
    storage
        .list_ai_verdicts()
        .await
        .expect("list verdicts")
        .into_iter()
        .map(|verdict| verdict.domain)
        .collect()
}

fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names
}

fn names(list: &[&str]) -> Vec<String> {
    sorted(list.iter().map(|name| (*name).to_owned()).collect())
}

// ---------------------------------------------------------------- writes

#[tokio::test]
async fn ai_verdicts_upsert_by_domain() {
    let (_dir, storage) = fresh("ai-upsert").await;
    // Every column distinct, so a column bound to the wrong place cannot round-trip.
    let first = AiVerdict {
        domain: "metrics.example.com".to_owned(),
        verdict: "block".to_owned(),
        why: None,
        choice: "block".to_owned(),
        confidence: Some(0.93),
        effect: Some("works".to_owned()),
        effect_confidence: Some(0.81),
        lists: "exception".to_owned(),
        site: Some("www.example.com".to_owned()),
        conflict_site: Some("news.example.net".to_owned()),
        rechecks: 2,
        model: "example/decider-20260917".to_owned(),
        judged_at: NOW,
        review_after: NOW + 30 * DAY,
    };
    record(&storage, vec![first.clone()]).await;
    assert_eq!(
        storage
            .ai_verdict("metrics.example.com".to_owned())
            .await
            .expect("read"),
        Some(first.clone())
    );

    // A fresh judgement of the same name replaces every column, `rechecks` and the sites included.
    let second = AiVerdict {
        verdict: "ignore".to_owned(),
        why: Some("unsure".to_owned()),
        choice: "allow".to_owned(),
        confidence: None,
        effect: None,
        effect_confidence: None,
        lists: "block".to_owned(),
        site: None,
        conflict_site: None,
        rechecks: 0,
        model: "example/decider-20261001".to_owned(),
        judged_at: NOW + 60,
        review_after: NOW + 60 + 7 * DAY,
        ..first.clone()
    };
    record(&storage, vec![second.clone()]).await;
    let all = storage.list_ai_verdicts().await.expect("list");
    assert_eq!(all, vec![second.clone()], "one row per domain");

    record(&storage, vec![row("cdn.example.com", "allow", None, NOW)]).await;
    assert_eq!(
        domains(&storage).await,
        ["cdn.example.com", "metrics.example.com"],
        "listed in domain order"
    );
    assert_eq!(
        storage
            .ai_verdict("nothing.example.com".to_owned())
            .await
            .expect("read"),
        None
    );

    // Forget hands back exactly the row it removed, and a second Forget finds nothing.
    assert_eq!(
        storage
            .delete_ai_verdict("metrics.example.com".to_owned())
            .await
            .expect("delete"),
        Some(second)
    );
    assert_eq!(
        storage
            .delete_ai_verdict("metrics.example.com".to_owned())
            .await
            .expect("delete again"),
        None
    );
    assert_eq!(domains(&storage).await, ["cdn.example.com"]);
}

#[tokio::test]
async fn ai_verdicts_refuse_an_unknown_verdict() {
    let (_dir, storage) = fresh("ai-check").await;
    let base = row("ads.example.com", "block", None, NOW);
    let refused = [
        AiVerdict {
            verdict: "whitelist".to_owned(),
            ..base.clone()
        },
        AiVerdict {
            why: Some("because".to_owned()),
            ..base.clone()
        },
        AiVerdict {
            choice: "maybe".to_owned(),
            ..base.clone()
        },
        AiVerdict {
            confidence: Some(1.5),
            ..base.clone()
        },
        AiVerdict {
            effect: Some("fine".to_owned()),
            ..base.clone()
        },
        AiVerdict {
            effect_confidence: Some(-0.1),
            ..base.clone()
        },
        AiVerdict {
            lists: "everything".to_owned(),
            ..base.clone()
        },
        AiVerdict {
            rechecks: 3,
            ..base.clone()
        },
    ];
    for bad in refused {
        let error = storage
            .record_ai_verdicts(vec![bad.clone()], SPEND.to_owned())
            .await
            .expect_err("a value outside the CHECK must be refused");
        assert!(
            error.to_string().contains("CHECK constraint failed"),
            "{bad:?}: {error}"
        );
    }
    assert!(domains(&storage).await.is_empty(), "nothing was stored");
    assert_eq!(
        storage.setting("ai_spend").await.expect("spend"),
        None,
        "and no refused batch wrote its spend"
    );
}

#[tokio::test]
async fn record_ai_verdicts_writes_spend_in_the_same_transaction() {
    let (_dir, storage) = fresh("ai-spend").await;
    record(&storage, vec![row("ads.example.com", "block", None, NOW)]).await;
    assert_eq!(
        storage.setting("ai_spend").await.expect("spend").as_deref(),
        Some(SPEND)
    );

    // A batch that fails part-way stores none of its rows and none of its spend: the spend that
    // paid for verdicts can never be ahead of, or behind, the verdicts themselves.
    let error = storage
        .record_ai_verdicts(
            vec![
                row("cdn.example.com", "allow", None, NOW),
                row("pixel.example.com", "maybe", None, NOW),
            ],
            "20369 2400 6 1".to_owned(),
        )
        .await
        .expect_err("the second row breaks the CHECK");
    assert!(error.to_string().contains("CHECK"), "{error}");
    assert_eq!(domains(&storage).await, ["ads.example.com"]);
    assert_eq!(
        storage.setting("ai_spend").await.expect("spend").as_deref(),
        Some(SPEND),
        "the earlier spend stands"
    );
}

#[tokio::test]
async fn record_ai_verdicts_with_no_rows_still_writes_spend() {
    let (_dir, storage) = fresh("ai-spend-empty").await;
    storage
        .record_ai_verdicts(Vec::new(), SPEND.to_owned())
        .await
        .expect("an empty settlement");
    assert_eq!(
        storage.setting("ai_spend").await.expect("spend").as_deref(),
        Some(SPEND)
    );
    assert!(domains(&storage).await.is_empty());

    storage
        .record_ai_verdicts(Vec::new(), "20370 0 0 0".to_owned())
        .await
        .expect("the next day's first settlement");
    assert_eq!(
        storage.setting("ai_spend").await.expect("spend").as_deref(),
        Some("20370 0 0 0"),
        "a later settlement replaces the earlier one"
    );
}

// ---------------------------------------------------------------- reads

#[tokio::test]
async fn ai_verdict_pages_filter_count_and_cap_at_500() {
    let (_dir, storage) = fresh("ai-pages").await;
    let mut rows = Vec::new();
    for index in 0..520 {
        rows.push(row(
            &format!("block-{index}.example.com"),
            "block",
            None,
            NOW + index,
        ));
    }
    for index in 0..50 {
        rows.push(row(
            &format!("allow-{index}.example.com"),
            "allow",
            None,
            NOW + 1_000 + index,
        ));
    }
    for index in 0..30 {
        rows.push(row(
            &format!("ignore-{index}.example.com"),
            "ignore",
            Some("agrees"),
            NOW - index,
        ));
    }
    record(&storage, rows).await;
    let whole = AiCounts {
        block: 520,
        allow: 50,
        ignore: 30,
    };

    let everything = storage
        .page_ai_verdicts(AiVerdictFilter {
            limit: 10_000,
            ..AiVerdictFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(everything.rows.len(), 500, "a page is capped at 500 rows");
    assert_eq!(everything.total, 600, "the total is not");
    assert_eq!(everything.counts, whole);
    assert_eq!(
        everything.rows[0].domain, "allow-49.example.com",
        "newest first"
    );
    assert!(
        everything
            .rows
            .windows(2)
            .all(|pair| pair[0].judged_at >= pair[1].judged_at)
    );

    let changes = storage
        .page_ai_verdicts(AiVerdictFilter {
            changes_only: true,
            limit: 10_000,
            ..AiVerdictFilter::default()
        })
        .await
        .expect("changes");
    assert_eq!(changes.total, 570, "changes are blocks and allows");
    assert!(changes.rows.iter().all(|row| row.verdict != "ignore"));
    assert_eq!(changes.counts, whole, "counts are the whole table's");

    let allows = storage
        .page_ai_verdicts(AiVerdictFilter {
            verdict: Some("allow".to_owned()),
            limit: 20,
            ..AiVerdictFilter::default()
        })
        .await
        .expect("allows");
    assert_eq!(allows.rows.len(), 20);
    assert_eq!(allows.total, 50);
    assert!(allows.rows.iter().all(|row| row.verdict == "allow"));
    assert_eq!(allows.counts, whole);

    let searched = storage
        .page_ai_verdicts(AiVerdictFilter {
            q: Some("ALLOW-1".to_owned()),
            limit: 100,
            ..AiVerdictFilter::default()
        })
        .await
        .expect("search");
    // allow-1 and allow-10 to allow-19.
    assert_eq!(searched.total, 11, "a case-insensitive substring");
    assert_eq!(searched.rows.len(), 11);
    assert!(
        searched
            .rows
            .iter()
            .all(|row| row.domain.contains("allow-1"))
    );

    let narrowed = storage
        .page_ai_verdicts(AiVerdictFilter {
            changes_only: true,
            verdict: Some("ignore".to_owned()),
            limit: 100,
            ..AiVerdictFilter::default()
        })
        .await
        .expect("contradictory filters");
    assert_eq!(narrowed.total, 0, "the filters narrow together");

    let blank = storage
        .page_ai_verdicts(AiVerdictFilter {
            q: Some(String::new()),
            limit: 0,
            ..AiVerdictFilter::default()
        })
        .await
        .expect("blank search, no rows");
    assert!(blank.rows.is_empty(), "a zero limit returns no rows");
    assert_eq!(blank.total, 600, "an empty search matches everything");
    assert_eq!(blank.counts, whole);
}

#[tokio::test]
async fn ai_counts_count_the_whole_table() {
    let (_dir, storage) = fresh("ai-counts").await;
    assert_eq!(
        storage.ai_counts().await.expect("counts"),
        AiCounts::default()
    );

    record(
        &storage,
        vec![
            row("a.example.com", "block", None, NOW),
            row("b.example.com", "block", None, NOW),
            row("c.example.com", "block", None, NOW),
            row("d.example.com", "allow", None, NOW),
            row("e.example.com", "allow", None, NOW),
            row("f.example.com", "ignore", Some("agrees"), NOW),
            row("g.example.com", "ignore", Some("unsure"), NOW),
            row("h.example.com", "ignore", Some("limit"), NOW),
            contested("i.example.com", NOW),
        ],
    )
    .await;
    assert_eq!(
        storage.ai_counts().await.expect("counts"),
        AiCounts {
            block: 3,
            allow: 2,
            ignore: 4,
        },
        "a contested row is an ignore"
    );

    assert_eq!(storage.clear_ai_verdicts().await.expect("clear"), 9);
    assert_eq!(
        storage.ai_counts().await.expect("counts"),
        AiCounts::default()
    );
}

// ---------------------------------------------------------------- browsing history

#[tokio::test]
async fn ai_sites_are_scrubbed_by_age_and_all_at_once() {
    let (_dir, storage) = fresh("ai-scrub").await;
    let old = contested("old.example.com", NOW - 10 * DAY);
    let siteless = AiVerdict {
        site: None,
        ..row("siteless.example.com", "block", None, NOW - 10 * DAY)
    };
    record(
        &storage,
        vec![
            old,
            siteless,
            row("new.example.com", "allow", None, NOW - HOUR),
        ],
    )
    .await;

    let site_of = |rows: &[AiVerdict], domain: &str| {
        rows.iter()
            .find(|row| row.domain == domain)
            .map(|row| (row.site.clone(), row.conflict_site.clone()))
            .expect("row present")
    };

    assert_eq!(
        storage
            .scrub_ai_sites(Some(NOW - 7 * DAY))
            .await
            .expect("scrub by age"),
        1,
        "only the old row had a site to lose"
    );
    let rows = storage.list_ai_verdicts().await.expect("list");
    assert_eq!(rows.len(), 3, "scrubbing removes history, not rows");
    assert_eq!(site_of(&rows, "old.example.com"), (None, None));
    assert_eq!(
        site_of(&rows, "new.example.com"),
        (Some("www.example.com".to_owned()), None),
        "a row newer than the cutoff keeps its site"
    );

    assert_eq!(
        storage.scrub_ai_sites(None).await.expect("scrub all"),
        1,
        "Clear log takes the rest"
    );
    let rows = storage.list_ai_verdicts().await.expect("list");
    assert!(
        rows.iter()
            .all(|row| row.site.is_none() && row.conflict_site.is_none())
    );
    assert_eq!(
        storage.scrub_ai_sites(None).await.expect("scrub again"),
        0,
        "nothing left to change"
    );
}

#[tokio::test]
async fn forgetting_ai_negatives_keeps_decisions() {
    let (_dir, storage) = fresh("ai-forget").await;
    let unexplained = row("unexplained.example.com", "ignore", None, NOW);
    record(
        &storage,
        vec![
            row("block.example.com", "block", None, NOW),
            row("allow.example.com", "allow", None, NOW),
            contested("contested.example.com", NOW),
            row("agrees.example.com", "ignore", Some("agrees"), NOW),
            row("unsure.example.com", "ignore", Some("unsure"), NOW),
            row("limit.example.com", "ignore", Some("limit"), NOW),
            unexplained,
        ],
    )
    .await;

    let gone = storage.forget_ai_negatives().await.expect("forget");
    assert_eq!(
        sorted(gone),
        names(&[
            "agrees.example.com",
            "limit.example.com",
            "unexplained.example.com",
            "unsure.example.com",
        ]),
        "every ordinary ignore goes, one with no reason included"
    );
    assert_eq!(
        domains(&storage).await,
        names(&[
            "allow.example.com",
            "block.example.com",
            "contested.example.com",
        ]),
        "blocks, allows and contested rows are policy, and stay"
    );
    assert!(
        storage
            .forget_ai_negatives()
            .await
            .expect("forget again")
            .is_empty()
    );
}

// ---------------------------------------------------------------- retention

#[tokio::test]
async fn ai_prune_returns_every_deleted_domain_and_counts_decisions() {
    let (_dir, storage) = fresh("ai-prune").await;
    let mut rows = vec![
        // Step 1: an ordinary ignore past its 30 days.
        row(
            "expired-ignore.example.com",
            "ignore",
            Some("agrees"),
            NOW - 31 * DAY,
        ),
        // Step 2: a contested row past its 90 days.
        AiVerdict {
            review_after: NOW - 5 * DAY,
            ..contested("old-contested.example.com", NOW - 95 * DAY)
        },
        // Step 3: a block judged 91 days ago.
        row("old-block.example.com", "block", None, NOW - 91 * DAY),
        // Step 4: the two oldest survivors, once the bulk below fills the table to the cap.
        row("capped-allow.example.com", "allow", None, NOW - 60 * DAY),
        row("capped-block.example.com", "block", None, NOW - 50 * DAY),
        // Kept: an allow past `review_after` keeps applying until it is judged again.
        row("due-allow.example.com", "allow", None, NOW - 31 * DAY),
        row("kept-block.example.com", "block", None, NOW - DAY),
    ];
    for index in 0..9_998 {
        rows.push(row(
            &format!("bulk-{index}.example.com"),
            "ignore",
            Some("agrees"),
            NOW - 20 * DAY + index,
        ));
    }
    record(&storage, rows).await;

    let pruned = storage
        .prune_ai_verdicts(NOW, 30, 10_000)
        .await
        .expect("prune");
    assert_eq!(
        sorted(pruned.domains.clone()),
        names(&[
            "capped-allow.example.com",
            "capped-block.example.com",
            "expired-ignore.example.com",
            "old-block.example.com",
            "old-contested.example.com",
        ]),
        "every deleted name is reported, whichever step took it"
    );
    assert_eq!(
        pruned.decisions, 4,
        "the expired ignore is the one deletion that was not a decision"
    );

    let left = domains(&storage).await;
    assert_eq!(left.len(), 10_000, "the table is held to the cap");
    for kept in ["due-allow.example.com", "kept-block.example.com"] {
        assert!(left.iter().any(|domain| domain == kept), "{kept} stays");
    }

    assert_eq!(
        storage
            .prune_ai_verdicts(NOW, 30, 10_000)
            .await
            .expect("prune again"),
        AiPruned::default(),
        "a second pass finds nothing"
    );
}

#[tokio::test]
async fn ai_prune_holds_ignores_to_history_days() {
    let (_dir, storage) = fresh("ai-prune-history").await;
    record(
        &storage,
        vec![
            // Written while HISTORY_DAYS was 30, so `review_after` alone would keep it 28 more days.
            row(
                "old-ignore.example.com",
                "ignore",
                Some("unsure"),
                NOW - 2 * DAY,
            ),
            row(
                "new-ignore.example.com",
                "ignore",
                Some("unsure"),
                NOW - 12 * HOUR,
            ),
            row("old-block.example.com", "block", None, NOW - 2 * DAY),
            contested("old-contested.example.com", NOW - 2 * DAY),
        ],
    )
    .await;

    let pruned = storage
        .prune_ai_verdicts(NOW, 1, 10_000)
        .await
        .expect("prune");
    assert_eq!(
        pruned,
        AiPruned {
            domains: names(&["old-ignore.example.com"]),
            decisions: 0,
        }
    );
    assert_eq!(
        domains(&storage).await,
        names(&[
            "new-ignore.example.com",
            "old-block.example.com",
            "old-contested.example.com",
        ]),
        "decisions are policy and outlive HISTORY_DAYS"
    );
}

#[tokio::test]
async fn ai_prune_keeps_contested_rows_ninety_days() {
    let (_dir, storage) = fresh("ai-prune-contested").await;
    record(
        &storage,
        vec![
            contested("month.example.com", NOW - 31 * DAY),
            contested("almost.example.com", NOW - 89 * DAY),
            contested("expired.example.com", NOW - 90 * DAY),
        ],
    )
    .await;

    let pruned = storage
        .prune_ai_verdicts(NOW, 1, 10_000)
        .await
        .expect("prune");
    assert_eq!(
        pruned,
        AiPruned {
            domains: names(&["expired.example.com"]),
            decisions: 1,
        },
        "a contested row is a decision, not the 30-day negative cache"
    );
    assert_eq!(
        domains(&storage).await,
        names(&["almost.example.com", "month.example.com"])
    );
}

// ---------------------------------------------------------------- settings

#[tokio::test]
async fn generic_settings_round_trip_and_delete() {
    let (_dir, storage) = fresh("settings").await;
    assert_eq!(storage.setting("ai_model").await.expect("read"), None);

    storage
        .set_setting("ai_model", Some("example/decider".to_owned()))
        .await
        .expect("write");
    storage
        .set_setting("ai_enabled", Some("1".to_owned()))
        .await
        .expect("write");
    assert_eq!(
        storage.setting("ai_model").await.expect("read").as_deref(),
        Some("example/decider")
    );

    storage
        .set_setting("ai_model", Some("example/other".to_owned()))
        .await
        .expect("overwrite");
    assert_eq!(
        storage.setting("ai_model").await.expect("read").as_deref(),
        Some("example/other")
    );

    storage
        .set_setting("ai_enabled", None)
        .await
        .expect("delete");
    assert_eq!(storage.setting("ai_enabled").await.expect("read"), None);
    assert_eq!(
        storage.setting("ai_model").await.expect("read").as_deref(),
        Some("example/other"),
        "deleting one key leaves the others"
    );
    storage
        .set_setting("ai_enabled", None)
        .await
        .expect("deleting an absent key is not an error");
}

#[tokio::test]
async fn pause_until_still_reads_and_writes() {
    let (_dir, storage) = fresh("pause-generic").await;
    storage
        .set_pause_until(Some(NOW + 1800))
        .await
        .expect("pause");
    assert_eq!(storage.pause_until().await.expect("read"), Some(NOW + 1800));
    assert_eq!(
        storage
            .setting("pause_until")
            .await
            .expect("raw")
            .as_deref(),
        Some("1700001800"),
        "stored as plain unix seconds, as v1 stored it"
    );

    for unreadable in ["0", "-5", "soon", ""] {
        storage
            .set_setting("pause_until", Some(unreadable.to_owned()))
            .await
            .expect("write raw");
        assert_eq!(
            storage.pause_until().await.expect("read"),
            None,
            "{unreadable:?} fails open to filtering"
        );
    }

    storage
        .set_setting("pause_until", Some(format!(" {} ", NOW + 60)))
        .await
        .expect("write raw");
    assert_eq!(storage.pause_until().await.expect("read"), Some(NOW + 60));

    storage.set_pause_until(Some(0)).await.expect("zero");
    assert_eq!(
        storage.setting("pause_until").await.expect("raw"),
        None,
        "a zero deadline deletes the row rather than storing a zero"
    );
}
