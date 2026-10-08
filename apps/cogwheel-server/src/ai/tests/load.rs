//! `AiState::load` at boot: the known map from the table, consent forgotten whenever review is
//! unavailable (D13), and where the key comes from (§8).

use super::{KEY, config, consent, load, storage, verdict, with_env_key};
use crate::ai::{KEY_FILE_UNREADABLE, KeySource, ListState, State, Unavailable};
use crate::tests::TempDir;
use crate::tests::openrouter_stub::capture;
use cogwheel_policy::Action;
use cogwheel_storage::Storage;

#[tokio::test]
async fn the_known_map_is_loaded_from_the_table_only_while_review_is_on() {
    let storage = storage().await;
    let mut row = verdict("ads.example.net", "block", 1_791_480_000);
    row.lists = "exception".to_owned();
    row.site = Some("www.news.bbc.co.uk".to_owned());
    storage
        .record_ai_verdicts(
            vec![row, verdict("quiet.example.net", "ignore", 5)],
            "0 0 0 0".to_owned(),
        )
        .await
        .expect("store two rows");
    // Off: nothing reads it, so ADR 0002's "grows by nothing while off" holds for a full table.
    let (off, _rx) = load(&config(), &storage).await;
    assert_eq!(off.known_len(), 0);

    consent(&storage).await;
    let mut operator_off = config();
    operator_off.ai_available = false;
    let (unavailable, _rx) = load(&operator_off, &storage).await;
    assert_eq!(unavailable.known_len(), 0);

    consent(&storage).await;
    let (ai, _rx) = load(&config(), &storage).await;
    let entry = ai.known("ads.example.net").expect("loaded");
    assert_eq!(entry.verdict, Some(Action::Block));
    assert_eq!(entry.lists, ListState::Exception);
    assert_eq!(entry.site_key.as_deref(), Some("bbc.co.uk"));
    assert_eq!(
        ai.known("quiet.example.net").map(|entry| entry.verdict),
        Some(None)
    );
}

#[tokio::test]
async fn review_needs_a_fresh_enable_after_being_unavailable() {
    let storage = storage().await;
    consent(&storage).await;
    storage
        .record_ai_verdicts(
            vec![verdict("ads.example.net", "block", 1)],
            "0 0 0 0".to_owned(),
        )
        .await
        .expect("store a verdict");

    let mut off = with_env_key(config());
    off.ai_available = false;
    let (ai, _rx) = load(&off, &storage).await;
    assert_eq!(ai.state(), State::Unavailable);
    assert_eq!(ai.unavailable, Some(Unavailable::OperatorOff));
    assert!(!ai.applying(), "the AI list compiles empty");
    assert_eq!(storage.setting("ai_enabled").await.expect("read"), None);
    assert_eq!(
        storage.list_ai_verdicts().await.expect("read").len(),
        1,
        "the operator's switch keeps the verdicts"
    );
    assert_eq!(
        storage.setting("ai_model").await.expect("read").as_deref(),
        Some("typesafe/jev-1.13"),
        "and the model"
    );

    // Back on: it reads off, not reviewing, until the household turns it on again.
    let (ai, _rx) = load(&with_env_key(config()), &storage).await;
    assert_eq!(ai.state(), State::Off);
    assert!(!ai.applying());
}

#[tokio::test]
async fn history_days_zero_empties_the_ai_list_at_load() {
    let storage = storage().await;
    consent(&storage).await;
    storage
        .record_ai_verdicts(
            vec![verdict("ads.example.net", "block", 1)],
            "0 0 0 0".to_owned(),
        )
        .await
        .expect("store a verdict");
    let mut no_log = with_env_key(config());
    no_log.history_days = 0;
    let (ai, _rx) = load(&no_log, &storage).await;
    assert_eq!(ai.unavailable, Some(Unavailable::HistoryOff));
    assert_eq!(ai.state(), State::Unavailable);
    assert!(storage.list_ai_verdicts().await.expect("read").is_empty());
    assert_eq!(storage.setting("ai_enabled").await.expect("read"), None);
    assert_eq!(ai.known_len(), 0);
}

#[tokio::test]
async fn a_saved_key_is_loaded_and_the_environment_wins() {
    let dir = TempDir::new("gate-key");
    let mut config = config();
    config.database_url = format!("sqlite://{}/cogwheel.db", dir.path().display());
    let storage = Storage::open(&config.database_url)
        .await
        .expect("open a file database");
    let path = dir.path().join("openrouter.key");

    std::fs::write(&path, "not a key").expect("plant a bad key file");
    consent(&storage).await;
    let (ai, _rx) = load(&config, &storage).await;
    assert_eq!(ai.state(), State::NoKey, "on, and waiting for a key");
    assert_eq!(ai.last_error(), Some(KEY_FILE_UNREADABLE));
    assert!(ai.key().is_none());
    assert!(
        path.exists(),
        "the unreadable file is left for the household"
    );

    std::fs::write(&path, KEY).expect("save a key");
    let (ai, _rx) = load(&config, &storage).await;
    assert_eq!(ai.key().map(|slot| slot.source), Some(KeySource::Saved));
    assert_eq!((ai.state(), ai.last_error()), (State::Reviewing, None));

    // The environment wins, and a key saved earlier in the UI is still on disk and in backups:
    // the operator is told once, at boot, without the key.
    let (logs, _subscriber) = capture();
    let (ai, _rx) = load(&with_env_key(config.clone()), &storage).await;
    assert_eq!(
        ai.key().map(|slot| slot.source),
        Some(KeySource::Environment)
    );
    let logged = logs.text();
    assert!(
        logged.contains("a key saved earlier in the UI is still in this file"),
        "{logged}"
    );
    assert!(!logged.contains(KEY));
}
