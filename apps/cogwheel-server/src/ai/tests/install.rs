//! `install.rs`, the AI half of `policy_build.rs` (§5.2) and the AI prune (§12): committed rows
//! reach the policy by every install that keeps the cache, and leave it with the table.

use super::verdict;
use super::{KEY, MODEL};
use crate::ai::{Cost, Known, ListState, apply_patch, install};
use crate::policy_build::{Rebuild, rebuild};
use crate::state::now_secs;
use crate::tests::Harness;
use crate::tests::openrouter_stub::keyed;
use cogwheel_policy::Action;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

const ON: (&str, &str) = ("ai_enabled", "1");
const DAY: i64 = 86_400;

#[tokio::test]
async fn every_install_that_keeps_the_cache_installs_the_committed_verdicts() {
    let fixture = Harness::with_ai(keyed(KEY), &[ON, MODEL]).await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    assert!(ai.applying());
    let now = now_secs();
    // Committed the way the reviewer commits, and nobody told the installer.
    ai.settle(
        &state.storage,
        now,
        Cost::default(),
        vec![
            verdict("ads.example.net", "block", now),
            // Nothing to whitelist: an allow with no list block is never compiled.
            verdict("cdn.example.net", "allow", now),
            verdict("quiet.example.net", "ignore", now),
        ],
    )
    .await
    .expect("committed");

    // The Devices trap (D9): a device rename installs what was committed, by the targeted path.
    let stats = rebuild(state, Rebuild::Devices)
        .await
        .expect("a device rebuild");
    assert_eq!((stats.ai_changed, stats.ai_dropped), (1, 0));
    let policy = state.runtime.current_policy();
    assert_eq!(policy.ai.get("ads.example.net"), Some(Action::Block));
    assert_eq!(policy.ai.len(), 1);

    // Nothing changed since: nothing is dropped.
    let stats = rebuild(state, Rebuild::Ai).await.expect("an AI rebuild");
    assert_eq!(stats.ai_changed, 0);
    // A list rebuild drops the whole cache, so it names nothing, but still installs the list.
    let stats = rebuild(state, Rebuild::Lists)
        .await
        .expect("a list rebuild");
    assert_eq!(stats.ai_changed, 0);
    assert_eq!(
        state.runtime.current_policy().ai.get("ads.example.net"),
        Some(Action::Block)
    );

    // Turning review off withdraws the AI list before the PUT answers.
    apply_patch(
        state,
        serde_json::from_str(r#"{"enabled":false}"#).expect("a patch"),
    )
    .await
    .expect("turned off");
    assert!(state.runtime.current_policy().ai.is_empty());
    let stats = rebuild(state, Rebuild::Devices)
        .await
        .expect("a device rebuild");
    assert_eq!(
        stats.ai_changed, 0,
        "off compiles nothing, so nothing comes back"
    );
    assert!(state.runtime.current_policy().ai.is_empty());
}

#[tokio::test]
async fn the_installer_installs_what_was_committed_after_a_notify() {
    let fixture = Harness::with_ai(keyed(KEY), &[ON, MODEL]).await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    let installer = tokio::spawn(install::task(state.clone()));
    ai.settle(
        &state.storage,
        now_secs(),
        Cost::default(),
        vec![verdict("ads.example.net", "block", now_secs())],
    )
    .await
    .expect("committed");
    ai.notify_install();

    // The real five-second debounce: this test waits for it once.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while ai.counters.installs.load(Ordering::Relaxed) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the installer never ran"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        state.runtime.current_policy().ai.get("ads.example.net"),
        Some(Action::Block)
    );
    installer.abort();
}

fn remembered(ai: &crate::ai::AiState, domain: &str, judged_at: i64) {
    ai.remember(
        Arc::from(domain),
        Known {
            verdict: None,
            lists: ListState::Nothing,
            judged_at,
            review_after: judged_at + 30 * DAY,
            site_key: Some("example.com".into()),
            rechecks: 0,
            last_recheck_day: 0,
        },
    );
}

#[tokio::test]
async fn pruning_the_ai_list_shrinks_the_known_map_and_scrubs_old_sites() {
    let fixture = Harness::with_ai(keyed(KEY), &[ON, MODEL]).await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    let now = now_secs();
    let rows = [
        ("expired.example.net", "ignore", now - 31 * DAY),
        // Within its 30 days, but older than one day of history.
        ("history.example.net", "ignore", now - 2 * DAY),
        ("fresh.example.net", "ignore", now - 60),
        ("kept.example.net", "block", now - 2 * DAY),
        ("ancient.example.net", "block", now - 91 * DAY),
    ];
    ai.settle(
        &state.storage,
        now,
        Cost::default(),
        rows.iter()
            .map(|(domain, kind, at)| verdict(domain, kind, *at))
            .collect(),
    )
    .await
    .expect("committed");
    for (domain, _, at) in rows {
        remembered(ai, domain, at);
    }

    crate::prune::prune_ai_list(state, 1).await;

    let mut left: Vec<(String, Option<String>)> = state
        .storage
        .list_ai_verdicts()
        .await
        .expect("read")
        .into_iter()
        .map(|row| (row.domain, row.site))
        .collect();
    left.sort();
    assert_eq!(
        left,
        [
            (
                "fresh.example.net".to_owned(),
                Some("www.example.com".to_owned())
            ),
            // A decision stays; the website it was judged for is history, and goes.
            ("kept.example.net".to_owned(), None),
        ]
    );
    for gone in [
        "expired.example.net",
        "history.example.net",
        "ancient.example.net",
    ] {
        assert_eq!(
            ai.known(gone),
            None,
            "{gone} left the table, so it leaves memory"
        );
    }
    assert!(ai.known("kept.example.net").is_some());
    // A decision went, so the installer was told; a stored permit is waiting for it.
    tokio::time::timeout(Duration::from_millis(100), ai.install.notified())
        .await
        .expect("the installer was notified");

    // A pass that removes nothing tells nobody.
    crate::prune::prune_ai_list(state, 1).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ai.install.notified())
            .await
            .is_err()
    );
}
