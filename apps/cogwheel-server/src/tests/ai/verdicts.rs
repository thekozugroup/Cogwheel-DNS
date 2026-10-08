//! The AI list's own routes (§10 routes 27–29), `/check`'s provenance, Clear log, the prune, and
//! the installs that put committed verdicts into the policy (§5.2, §5.3, D9).

use super::row;
use crate::ai::review::{Now, Pipeline};
use crate::ai::{Cost, Halt, STOPPED, State, install, worker};
use crate::api::devices;
use crate::http::ApiJson;
use crate::policy_build::{Rebuild, rebuild};
use crate::state::{ServerState, now_secs};
use crate::tests::openrouter_stub::{
    CONSENT, call, exchange, keyed, parsed, realistic_key, sentence,
};
use crate::tests::{Harness, device_input, rule_input};
use axum::extract::{Path, State as Extract};
use axum::http::StatusCode;
use cogwheel_policy::{Action, Reason};
use cogwheel_storage::{AiVerdict, NewSource};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

const DAY: i64 = 86_400;

/// A harness reviewing with a key from the environment, its stored consent and model.
async fn reviewing() -> Harness {
    Harness::with_ai(keyed(&realistic_key()), &CONSENT).await
}

/// Commit rows the way the reviewer does: through the spend owner, without telling the installer.
async fn commit(state: &ServerState, rows: Vec<AiVerdict>) {
    state
        .ai
        .settle(&state.storage, Cost::default(), rows)
        .await
        .expect("committed");
}

fn applied(state: &ServerState, domain: &str) -> Option<Action> {
    state.runtime.current_policy().ai.get(domain)
}

/// Whether a notify is waiting for the installer: a stored permit resolves at once.
async fn installer_told(state: &ServerState) -> bool {
    tokio::time::timeout(Duration::from_millis(100), state.ai.install.notified())
        .await
        .is_ok()
}

async fn check(state: &ServerState, domain: &str) -> Value {
    let (status, text) = call(
        state,
        "GET",
        &format!("/api/v1/check?domain={domain}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    parsed(&text)["data"].clone()
}

// --------------------------------------------------------------------- Forget and Clear

#[tokio::test]
async fn forgetting_a_verdict_reinstalls_and_404s_when_unknown() {
    let harness = reviewing().await;
    let state = &harness.state;
    let now = now_secs();
    commit(
        state,
        vec![
            row("ads.example.net", "block", 0.95, now),
            row("more.example.net", "block", 0.95, now),
        ],
    )
    .await;
    rebuild(state, Rebuild::Ai).await.expect("installed");
    assert_eq!(applied(state, "ads.example.net"), Some(Action::Block));

    // Normalised like every other name the API takes.
    let (status, text) = call(
        state,
        "DELETE",
        "/api/v1/ai/verdicts/ADS.Example.NET.",
        None,
    )
    .await;
    assert_eq!(
        (status, parsed(&text)),
        (StatusCode::OK, json!({"data": {"deleted": true}}))
    );
    assert_eq!(
        applied(state, "ads.example.net"),
        None,
        "reinstalled before the answer"
    );
    assert_eq!(applied(state, "more.example.net"), Some(Action::Block));
    assert_eq!(state.ai.known("ads.example.net"), None);
    let stored = state.storage.ai_verdict("ads.example.net".to_owned()).await;
    assert_eq!(stored.expect("read"), None);

    let (status, text) = call(state, "DELETE", "/api/v1/ai/verdicts/ads.example.net", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(sentence(&text), "No AI verdict for that name.");
    let (status, text) = call(state, "DELETE", "/api/v1/ai/verdicts/localhost", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(sentence(&text), "\"localhost\" is not a domain name.");
}

#[tokio::test]
async fn clearing_the_ai_list_reinstalls_and_drops_its_answers() {
    let harness = reviewing().await;
    let now = now_secs();
    commit(
        &harness.state,
        vec![
            row("ads.example.net", "block", 0.95, now),
            row("more.example.net", "block", 0.95, now),
            row("quiet.example.net", "ignore", 0.6, now),
        ],
    )
    .await;
    // Loaded again, so the known map holds what the table holds.
    let (state, _tap) = harness.restarted_ai().await;
    rebuild(&state, Rebuild::Ai).await.expect("installed");
    assert_eq!(state.runtime.current_policy().ai.len(), 2);
    assert_eq!(state.ai.known_len(), 3);

    let (status, text) = call(&state, "DELETE", "/api/v1/ai/verdicts", None).await;
    assert_eq!(
        (status, parsed(&text)),
        (StatusCode::OK, json!({"data": {"deleted": 3}}))
    );
    assert!(state.runtime.current_policy().ai.is_empty());
    assert_eq!(state.ai.known_len(), 0, "every name is judged afresh");
    assert_eq!(
        state.ai.state(),
        State::Reviewing,
        "clearing does not halt review"
    );
    let (_, text) = call(&state, "GET", "/api/v1/ai/verdicts?view=all", None).await;
    assert_eq!(parsed(&text)["data"]["total"], 0);
}

// --------------------------------------------------------------------- /check

#[tokio::test]
async fn check_explains_an_ai_verdict_and_one_below_the_bar() {
    let harness = reviewing().await;
    let state = &harness.state;
    let now = now_secs();
    commit(
        state,
        vec![
            row("ads.example.net", "block", 0.95, now),
            // Stored as a block, but under the plain bar against the lists as they are.
            row("weak.example.net", "block", 0.8, now),
            row("quiet.example.net", "ignore", 0.6, now),
        ],
    )
    .await;
    rebuild(state, Rebuild::Ai).await.expect("installed");

    let decided = check(state, "ads.example.net").await;
    assert_eq!(
        (decided["verdict"].clone(), decided["reason"].clone()),
        (json!("block"), json!("ai"))
    );
    assert_eq!(
        decided["ai"],
        json!({"verdict": "block", "why": null, "choice": "block", "confidence": 0.95,
               "effect": null, "effect_confidence": null, "lists": "nothing",
               "site": "www.example.com", "conflict_site": null,
               "model": "typesafe/jev-1.13-20260917", "judged_at": now, "applied": true})
    );

    let below = check(state, "weak.example.net").await;
    assert_eq!(below["reason"], "no_match", "the lists decided");
    assert_eq!(
        (
            below["ai"]["verdict"].clone(),
            below["ai"]["applied"].clone()
        ),
        (json!("block"), json!(false))
    );
    assert_eq!(below["ai"]["confidence"], 0.8);

    let quiet = check(state, "quiet.example.net").await;
    assert_eq!(quiet["ai"]["verdict"], "ignore");
    assert_eq!(quiet["ai"]["why"], "unsure");
    assert_eq!(quiet["ai"]["applied"], false);

    assert_eq!(check(state, "example.org").await["ai"], Value::Null);
}

/// Forget removed the row and the rebuild has not landed yet: `/check` still reports the AI list
/// deciding, says so, and invents no site, model or confidence.
#[tokio::test]
async fn check_never_invents_provenance_in_the_race_case() {
    let harness = reviewing().await;
    let state = &harness.state;
    commit(
        state,
        vec![row("ads.example.net", "block", 0.95, now_secs())],
    )
    .await;
    rebuild(state, Rebuild::Ai).await.expect("installed");
    state
        .storage
        .delete_ai_verdict("ads.example.net".to_owned())
        .await
        .expect("deleted behind the policy's back");

    let decided = check(state, "ads.example.net").await;
    assert_eq!(decided["reason"], "ai");
    assert_eq!(
        decided["ai"],
        json!({"verdict": "block", "applied": true, "why": null, "choice": null,
               "confidence": null, "effect": null, "effect_confidence": null, "lists": null,
               "site": null, "conflict_site": null, "model": null, "judged_at": null})
    );
}

// --------------------------------------------------------------------- Clear log and the prune

/// §12: Clear log forgets the AI list's browsing history: every recorded website, the ordinary
/// ignores (in the table and in `known`), and the reviewer's in-memory site data. Blocks, allows
/// and contested rows are policy, and stay.
#[tokio::test]
async fn clearing_the_log_forgets_sites_and_negative_verdicts() {
    let harness = reviewing().await;
    let now = now_secs();
    let contested = AiVerdict {
        why: Some("contested".to_owned()),
        conflict_site: Some("www.other.org".to_owned()),
        review_after: now + 90 * DAY,
        ..row("cdn.example.net", "ignore", 0.9, now)
    };
    let allow = AiVerdict {
        lists: "block".to_owned(),
        ..row("pay.example.net", "allow", 0.95, now)
    };
    commit(
        &harness.state,
        vec![
            row("ads.example.net", "block", 0.95, now),
            allow,
            contested,
            row("quiet.example.net", "ignore", 0.6, now),
        ],
    )
    .await;
    let (state, _tap) = harness.restarted_ai().await;
    assert!(
        state
            .ai
            .known("ads.example.net")
            .is_some_and(|known| known.site_key.is_some())
    );

    // What the reviewer remembers of the household's browsing: the websites opened, and a site
    // load it holds as queued jobs.
    let _alive = state.ai.reviewer_alive();
    let mut pipeline = Pipeline::new(Arc::clone(&state.ai));
    let policy = state.runtime.current_policy();
    let visit = |pipeline: &mut Pipeline, t: i64, names: &[&str]| {
        for domain in names {
            pipeline.push(crate::ai::Seen {
                ts: u32::try_from(t).expect("a timestamp that fits"),
                client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                domain: Arc::from(*domain),
                blocked: false,
                reason: Reason::NoMatch,
            });
        }
        pipeline.tick(Now::from_secs(t + 10), &policy);
    };
    visit(
        &mut pipeline,
        now,
        &["www.news-site.com", "t1.site1.com", "t2.site2.com"],
    );
    assert_eq!(pipeline.waiting(), 2);
    // The home-context rule: another website's load does not put an opened website's names up.
    let other = ["www.other-site.org", "img.news-site.com", "t3.site3.com"];
    visit(&mut pipeline, now + 20, &other);
    assert!(!pipeline.is_pending("img.news-site.com"));
    assert_eq!(pipeline.waiting(), 3);
    let epoch = state.ai.sites_epoch();

    let (status, _) = call(&state, "DELETE", "/api/v1/queries", None).await;
    assert_eq!(status, StatusCode::OK);

    let left: Vec<(String, Option<String>, Option<String>)> = state
        .storage
        .list_ai_verdicts()
        .await
        .expect("read")
        .into_iter()
        .map(|row| (row.domain, row.site, row.conflict_site))
        .collect();
    let gone = |domain: &str| (domain.to_owned(), None, None);
    assert_eq!(
        left,
        [
            gone("ads.example.net"),
            gone("cdn.example.net"),
            gone("pay.example.net")
        ]
    );
    assert_eq!(state.ai.known("quiet.example.net"), None);
    assert!(
        state
            .ai
            .known("ads.example.net")
            .is_some_and(|known| known.site_key.is_none())
    );
    assert_eq!(
        state.ai.sites_epoch(),
        epoch + 1,
        "an answer in flight lands with no site"
    );
    pipeline.catch_up();
    assert_eq!((pipeline.waiting(), pipeline.bursts()), (0, 0));
    assert!(!pipeline.is_pending("t1.site1.com"));
    assert_eq!(state.ai.state(), State::Reviewing, "review stays on");
    // The opened websites went too: the same load now puts that name up.
    visit(&mut pipeline, now + 40, &other[..2]);
    assert!(pipeline.is_pending("img.news-site.com"));
}

#[tokio::test]
async fn pruning_ignore_rows_shrinks_the_known_map() {
    let harness = reviewing().await;
    let now = now_secs();
    commit(
        &harness.state,
        vec![
            row("expired.example.net", "ignore", 0.6, now - 31 * DAY),
            row("history.example.net", "ignore", 0.6, now - 2 * DAY),
            row("fresh.example.net", "ignore", 0.6, now - 60),
            row("kept.example.net", "block", 0.95, now - 2 * DAY),
        ],
    )
    .await;
    let (state, _tap) = harness.restarted_ai().await;
    assert_eq!(state.ai.known_len(), 4);

    // With one day of history, an ignore judged two days ago goes too; the block stays.
    crate::prune::prune_ai_list(&state, 1).await;
    for gone in ["expired.example.net", "history.example.net"] {
        assert_eq!(
            state.ai.known(gone),
            None,
            "{gone} left the table and memory"
        );
        let stored = state
            .storage
            .ai_verdict(gone.to_owned())
            .await
            .expect("read");
        assert_eq!(stored, None);
    }
    assert_eq!(state.ai.known_len(), 2);
    assert!(
        !installer_told(&state).await,
        "an ignore was never compiled"
    );

    commit(
        &state,
        vec![row("ancient.example.net", "block", 0.95, now - 91 * DAY)],
    )
    .await;
    crate::prune::prune_ai_list(&state, 1).await;
    assert!(
        installer_told(&state).await,
        "a decision went, so the AI list changes"
    );
}

// --------------------------------------------------------------------- route 27

/// Each row is read against the live policy: what DNS applies, why a stored verdict does not
/// apply, and what outranks the AI list on the name.
#[tokio::test]
async fn verdict_rows_report_applied_and_outranked_from_the_live_policy() {
    let harness = reviewing().await;
    let state = &harness.state;
    let source = state
        .storage
        .insert_source(NewSource {
            id: None,
            name: "ads".to_owned(),
            url: "https://lists.example.com/ads.txt".to_owned(),
            kind: "domains".to_owned(),
            enabled: true,
        })
        .await
        .expect("subscribe to a list");
    crate::tests::cache_body(
        &harness,
        &source.id,
        "listed.example.com\nagree.example.com\n",
    );
    rebuild(state, Rebuild::Lists)
        .await
        .expect("compile the list");

    let now = now_secs();
    let agree = AiVerdict {
        lists: "block".to_owned(),
        ..row("agree.example.com", "block", 0.95, now)
    };
    commit(
        state,
        vec![
            row("ads.example.net", "block", 0.95, now),
            // Judged when the lists had no opinion; they block it now.
            row("listed.example.com", "block", 0.95, now - 1),
            agree,
            row("weak.example.net", "block", 0.8, now - 2),
            row("news.example.net", "block", 0.95, now - 3),
            row("time.apple.com", "block", 0.95, now - 4),
            row("quiet.example.net", "ignore", 0.6, now - 5),
        ],
    )
    .await;
    // A household rule, whose rebuild installs the committed rows on the way.
    crate::api::rules::create(
        Extract(state.clone()),
        ApiJson(rule_input("news.example.net", "allow", None)),
    )
    .await
    .expect("a household rule");

    let rows = |text: &str| -> Vec<(String, Value, Value, Value, Value)> {
        parsed(text)["data"]["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| {
                (
                    row["domain"].as_str().unwrap_or_default().to_owned(),
                    row["applied"].clone(),
                    row["not_applied"].clone(),
                    row["outranked_by"].clone(),
                    row["lists_now"].clone(),
                )
            })
            .collect()
    };
    let (status, text) = call(state, "GET", "/api/v1/ai/verdicts?view=all&limit=50", None).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (yes, no, null) = (json!(true), json!(false), Value::Null);
    let at = |name: &str, applied: &Value, why: Value, outranked: Value, lists: &str| {
        (
            name.to_owned(),
            applied.clone(),
            why,
            outranked,
            json!(lists),
        )
    };
    assert_eq!(
        rows(&text),
        [
            at(
                "ads.example.net",
                &yes,
                null.clone(),
                null.clone(),
                "nothing"
            ),
            at(
                "agree.example.com",
                &no,
                json!("lists_agree"),
                null.clone(),
                "block"
            ),
            at(
                "listed.example.com",
                &no,
                json!("lists_changed"),
                null.clone(),
                "block"
            ),
            at(
                "weak.example.net",
                &no,
                json!("below_bar"),
                null.clone(),
                "nothing"
            ),
            at(
                "news.example.net",
                &yes,
                null.clone(),
                json!("household_rule"),
                "nothing"
            ),
            at(
                "time.apple.com",
                &no,
                json!("below_bar"),
                json!("protected"),
                "nothing"
            ),
            at(
                "quiet.example.net",
                &no,
                null.clone(),
                null.clone(),
                "nothing"
            ),
        ]
    );
    let page = parsed(&text)["data"].clone();
    assert_eq!(
        (page["total"].clone(), page["counts"].clone()),
        (json!(7), json!({"block": 6, "allow": 0, "ignore": 1}))
    );

    // The default view is the changes: blocks and allows only. Never kept in a browser's cache.
    let (_, headers, text) = exchange(state, "GET", "/api/v1/ai/verdicts", &[], None).await;
    assert_eq!(parsed(&text)["data"]["total"], 6);
    assert_eq!(
        headers
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let (_, text) = call(
        state,
        "GET",
        "/api/v1/ai/verdicts?view=all&q=EXAMPLE.NET&verdict=block",
        None,
    )
    .await;
    assert_eq!(parsed(&text)["data"]["total"], 3);

    // Off: nothing applies, and each row says why.
    let (status, _) = call(state, "PUT", "/api/v1/ai", Some(r#"{"enabled":false}"#)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, text) = call(state, "GET", "/api/v1/ai/verdicts?limit=1", None).await;
    assert_eq!(
        rows(&text),
        [at("ads.example.net", &no, json!("off"), null, "nothing")]
    );

    for query in [
        "view=everything",
        "verdict=maybe",
        "limit=0",
        "limit=501",
        "limit=many",
    ] {
        let (status, text) =
            call(state, "GET", &format!("/api/v1/ai/verdicts?{query}"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {text}");
        assert!(sentence(&text).ends_with('.'));
    }
}

// --------------------------------------------------------------------- installs

/// D9, the Devices trap: rows committed with no notify reach the policy through a device rebuild,
/// which keeps the cache, so it must take the invalidating path for exactly those names. That the
/// names' cached answers are then dropped is dns-core's
/// `an_invalidating_swap_drops_only_the_changed_names`: this crate cannot plant a cache entry.
#[tokio::test]
async fn a_devices_rebuild_installs_committed_verdicts_without_a_notify() {
    let harness = reviewing().await;
    let state = &harness.state;
    let device = devices::create(
        Extract(state.clone()),
        ApiJson(device_input("Tablet", "192.168.1.20")),
    )
    .await
    .expect("a device")
    .data;
    let now = now_secs();
    commit(
        state,
        vec![
            row("ads.example.net", "block", 0.95, now),
            row("more.example.net", "block", 0.95, now),
            row("quiet.example.net", "ignore", 0.6, now),
        ],
    )
    .await;
    assert!(!installer_told(state).await, "nobody told the installer");

    let stats = rebuild(state, Rebuild::Devices)
        .await
        .expect("a device rebuild");
    assert_eq!(
        stats.ai_changed, 2,
        "the targeted path, for exactly the committed names"
    );
    assert_eq!(applied(state, "ads.example.net"), Some(Action::Block));
    assert_eq!(applied(state, "more.example.net"), Some(Action::Block));

    // And through the route a device rename takes.
    commit(state, vec![row("late.example.net", "block", 0.95, now)]).await;
    devices::update(
        Extract(state.clone()),
        Path(device.id),
        ApiJson(device_input("Hallway tablet", "192.168.1.20")),
    )
    .await
    .expect("a rename");
    assert_eq!(applied(state, "late.example.net"), Some(Action::Block));
}

/// §5.3: a notify sent while the installer is busy is not lost. `Notify` keeps one permit when
/// nobody is waiting, so a commit that lands during a rebuild causes one more rebuild that reads it.
#[tokio::test(start_paused = true)]
async fn a_commit_during_a_rebuild_is_installed_by_the_next_one() {
    let harness = reviewing().await;
    let state = harness.state.clone();
    let installs = |state: &ServerState| state.ai.counters.installs.load(Ordering::Relaxed);
    let installer = tokio::spawn(install::task(state.clone()));
    let now = now_secs();

    // Paused time jumps to the next timer whenever nothing else can run, so a minute of it costs
    // nothing; the database's blocking threads hold it still while they work.
    let until = |count: u64| {
        let state = state.clone();
        async move {
            for _ in 0..600 {
                if installs(&state) >= count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            installs(&state)
        }
    };

    // 1. A is committed and installed after the debounce.
    commit(&state, vec![row("a.example.net", "block", 0.95, now)]).await;
    state.ai.notify_install();
    assert_eq!(until(1).await, 1);
    assert_eq!(applied(&state, "a.example.net"), Some(Action::Block));

    // 2. With the rebuild lock held, B's install blocks inside `rebuild`; C is committed and
    //    notified while it waits there, which leaves a permit.
    let held = state.rebuild_lock.lock().await;
    commit(&state, vec![row("b.example.net", "block", 0.95, now)]).await;
    state.ai.notify_install();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(installs(&state), 1, "blocked on the lock");
    commit(&state, vec![row("c.example.net", "block", 0.95, now)]).await;
    state.ai.notify_install();

    // 3. Released: the blocked install finishes, and the permit causes one more.
    drop(held);
    assert_eq!(until(3).await, 3);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        installs(&state),
        3,
        "two more installs, and no more than two"
    );
    for name in ["a.example.net", "b.example.net", "c.example.net"] {
        assert_eq!(applied(&state, name), Some(Action::Block), "{name}");
    }
    installer.abort();
}

/// The reviewer task dies (a panic or an abort drop its guard the same way): review reads
/// stopped, the gate is closed for good, and what the AI list already applies keeps applying.
#[tokio::test]
async fn a_dead_reviewer_reads_stopped_and_its_verdicts_keep_applying() {
    let mut harness = reviewing().await;
    let state = harness.state.clone();
    commit(
        &state,
        vec![row("ads.example.net", "block", 0.95, now_secs())],
    )
    .await;
    rebuild(&state, Rebuild::Ai).await.expect("installed");
    let before = state.runtime.current_policy();

    let reviewer = tokio::spawn(worker::task(state.clone(), harness.take_tap()));
    for _ in 0..100 {
        if state.ai.tap().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(state.ai.tap().is_some(), "a live reviewer opens the gate");
    reviewer.abort();
    assert!(reviewer.await.expect_err("aborted").is_cancelled());

    let (_, text) = call(&state, "GET", "/api/v1/ai", None).await;
    let status = parsed(&text)["data"].clone();
    assert_eq!(
        (status["state"].clone(), status["last_error"].clone()),
        (json!("stopped"), json!(STOPPED))
    );
    assert!(state.ai.tap().is_none());
    assert!(!state.ai.may_send(state.ai.generation()));
    assert!(Arc::ptr_eq(&before.ai, &state.runtime.current_policy().ai));
    assert_eq!(applied(&state, "ads.example.net"), Some(Action::Block));

    // Nothing written afterwards revives it: only a restart does.
    state.ai.resume();
    assert_eq!(state.ai.state(), State::Stopped);
    state.ai.halt(Halt::Off);
    assert!(state.ai.tap().is_none());
}
