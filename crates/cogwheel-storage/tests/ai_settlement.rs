//! What the server reads and writes of `ai_verdicts` around a settlement: the narrow read every
//! policy build makes, and a cross-site re-check written after a Forget or a Clear log (ADR 0002).

mod common;

use common::*;

/// A day's spend as the server encodes it.
const SPEND: &str = "20369 1200 3 0";

/// A verdict with the fields these tests do not care about filled in.
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

async fn record(storage: &Storage, rows: Vec<AiVerdict>) {
    storage
        .record_ai_verdicts(rows, SPEND.to_owned())
        .await
        .expect("record verdicts");
}

/// A policy build reads the blocks and allows alone, and only the columns their bars judge.
#[tokio::test]
async fn ai_decisions_are_the_blocks_and_allows_alone() {
    let (_dir, storage) = fresh("ai-decisions").await;
    let block = row("ads.example.com", "block", None, NOW);
    let allow = AiVerdict {
        effect: Some("breaks".to_owned()),
        effect_confidence: Some(0.95),
        ..row("cdn.example.com", "allow", None, NOW)
    };
    record(
        &storage,
        vec![
            block.clone(),
            allow.clone(),
            row("quiet.example.com", "ignore", Some("unsure"), NOW),
            AiVerdict {
                conflict_site: Some("shop.example.org".to_owned()),
                review_after: NOW + 90 * DAY,
                ..row("torn.example.com", "ignore", Some("contested"), NOW)
            },
        ],
    )
    .await;
    assert_eq!(
        storage.list_ai_decisions().await.expect("decisions"),
        vec![AiDecision::from(&block), AiDecision::from(&allow)],
        "in domain order, with no ignore of either kind"
    );
}

/// A cross-site re-check reads the row, and is written later: a Forget or a Clear log in between
/// is not undone by it.
#[tokio::test]
async fn a_recheck_never_restores_a_forgotten_row_or_a_scrubbed_site() {
    let (_dir, storage) = fresh("ai-recheck").await;
    let block = row("ads.example.com", "block", None, NOW);
    record(&storage, vec![block.clone()]).await;
    // The row as the re-check read it, contested in another website's load.
    let contested = AiVerdict {
        verdict: "ignore".to_owned(),
        why: Some("contested".to_owned()),
        conflict_site: Some("shop.example.org".to_owned()),
        rechecks: 1,
        review_after: NOW + 90 * DAY,
        ..block.clone()
    };

    // Clear log in between: the re-check applies, and the website it scrubbed stays scrubbed.
    storage.scrub_ai_sites(None).await.expect("scrub");
    let changed = storage
        .record_ai_settlement(Vec::new(), Some(contested.clone()), SPEND.to_owned())
        .await
        .expect("record");
    assert!(changed);
    assert_eq!(
        storage
            .ai_verdict("ads.example.com".to_owned())
            .await
            .expect("read"),
        Some(AiVerdict {
            site: None,
            ..contested.clone()
        })
    );

    // Forget in between: nothing comes back.
    record(&storage, vec![block]).await;
    storage
        .delete_ai_verdict("ads.example.com".to_owned())
        .await
        .expect("forget");
    let changed = storage
        .record_ai_settlement(Vec::new(), Some(contested), SPEND.to_owned())
        .await
        .expect("record");
    assert!(!changed, "nothing left to re-check");
    assert!(storage.list_ai_verdicts().await.expect("list").is_empty());
}
