//! `patch.rs` and `test_run.rs`: route 24's order of work and route 26's table, driven through
//! the functions the handlers call, against the loopback stub.

use super::KEY;
use super::stub::{Reply, Stub};
use super::{Scratch, env_key, fixture};
use crate::ai::{
    AiPatch, AiTestInput, KeySource, State, Unavailable, apply_patch, model_list, run_test,
};
use crate::http::ApiError;
use crate::state::now_secs;
use axum::http::StatusCode;
use cogwheel_storage::AiCounts;

fn patch(body: &str) -> AiPatch {
    serde_json::from_str(body).expect("a patch body")
}

fn refused(error: &ApiError, status: StatusCode, sentence: &str) {
    assert_eq!(
        (error.status(), error.to_string().as_str()),
        (status, sentence)
    );
}

const ANSWER: &str = r#"{"id":"gen-dec-1","model":"typesafe/jev-1.13-20260917","provider":"TypeSafe",
  "answers":{"role":{"type":"choice","choice":"block","confidence":0.91},
             "effect":{"type":"choice","choice":"works","confidence":0.94}},
  "usage":{"input_tokens":510,"output_tokens":70,"cost":0.0000213}}"#;

const LISTING: &str = r#"{"data":[{"id":"typesafe/jev-1.13","name":"TypeSafe: Jev 1.13",
  "description":"Jev","context_length":32000,"pricing":{"prompt":"0.000000042"}}]}"#;

#[tokio::test]
async fn the_operator_switch_refuses_every_write_but_removing_the_key() {
    let off = fixture(|config| config.ai_available = false, &[]).await;
    let sentence = Unavailable::OperatorOff.sentence();
    for body in [
        r#"{"enabled":true}"#,
        r#"{"enabled":false}"#,
        r#"{"model":"typesafe/jev-1.13"}"#,
        r#"{"daily_limit_usd":0.25}"#,
        r#"{"key":"sk-or-v1-fake-other-key-zxqw"}"#,
        r#"{"key":null,"enabled":false}"#,
    ] {
        let error = apply_patch(&off.state, patch(body))
            .await
            .expect_err("refused while unavailable");
        refused(&error, StatusCode::CONFLICT, sentence);
    }
    apply_patch(&off.state, patch(r#"{"key":null}"#))
        .await
        .expect("deleting a secret is never refused");
    let error = run_test(&off.state, AiTestInput::default())
        .await
        .expect_err("no Test either");
    refused(&error, StatusCode::CONFLICT, sentence);
    let error = model_list(&off.state)
        .await
        .expect_err("nor the model list");
    refused(&error, StatusCode::CONFLICT, sentence);
}

#[tokio::test]
async fn an_environment_key_cannot_be_replaced_but_the_rest_can_change() {
    let fixture = fixture(env_key, &[]).await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    let sentence = "The OpenRouter key is set in the environment \
                    (COGWHEEL_AI__OPENROUTER_API_KEY); change it there.";
    for body in [
        r#"{"key":"sk-or-v1-fake-other-key-zxqw"}"#,
        r#"{"key":null}"#,
    ] {
        let error = apply_patch(state, patch(body)).await.expect_err("refused");
        refused(&error, StatusCode::CONFLICT, sentence);
    }
    apply_patch(state, patch(r#"{"daily_limit_usd":0.25}"#))
        .await
        .expect("the limit changes");
    // The model list cannot be fetched (the closed port), so the model is taken unpriced.
    apply_patch(state, patch(r#"{"model":"typesafe/jev-1.13"}"#))
        .await
        .expect("the model changes");
    assert_eq!(ai.model(), Some(("typesafe/jev-1.13".to_owned(), None)));
    assert_eq!(ai.daily_limit_micro(), 250_000);
    assert_eq!(
        state
            .storage
            .setting("ai_daily_limit")
            .await
            .expect("read")
            .as_deref(),
        Some("0.25")
    );
    assert_eq!(
        ai.key().map(|slot| slot.source),
        Some(KeySource::Environment)
    );
}

#[tokio::test]
async fn enabling_needs_a_key_and_a_model_and_every_shape_is_checked() {
    let bare = fixture(|_| {}, &[]).await;
    let error = apply_patch(&bare.state, patch(r#"{"enabled":true}"#))
        .await
        .expect_err("no key");
    refused(
        &error,
        StatusCode::CONFLICT,
        "Add an OpenRouter key before turning AI review on.",
    );
    let keyed = fixture(env_key, &[]).await;
    let error = apply_patch(&keyed.state, patch(r#"{"enabled":true}"#))
        .await
        .expect_err("no model");
    refused(
        &error,
        StatusCode::CONFLICT,
        "Pick a model before turning AI review on.",
    );

    for limit in ["0.07", "2", "-0.05", "0", "0.1001"] {
        let error = apply_patch(
            &keyed.state,
            patch(&format!(r#"{{"daily_limit_usd":{limit}}}"#)),
        )
        .await
        .expect_err("not a preset");
        refused(
            &error,
            StatusCode::BAD_REQUEST,
            "Choose a daily limit of 5¢, 10¢, 25¢ or $1.",
        );
    }
    let error = apply_patch(&keyed.state, patch(r#"{"model":"Jev 1.13"}"#))
        .await
        .expect_err("not a model id");
    refused(
        &error,
        StatusCode::BAD_REQUEST,
        "That is not an OpenRouter model id.",
    );
    let error = apply_patch(&bare.state, patch(r#"{"key":"sk-or short"}"#))
        .await
        .expect_err("not a key");
    refused(
        &error,
        StatusCode::BAD_REQUEST,
        "That does not look like an OpenRouter key.",
    );
    // Nothing a refused write carried was saved.
    for key in ["ai_enabled", "ai_model", "ai_daily_limit"] {
        assert_eq!(keyed.state.storage.setting(key).await.expect("read"), None);
    }
}

#[tokio::test]
async fn turning_review_on_tests_it_and_turning_it_off_closes_the_gate_at_once() {
    let stub = Stub::serve(vec![
        Reply::json(200, LISTING),
        Reply::json(200, LISTING),
        Reply::json(200, ANSWER),
    ]);
    let base = stub.base.clone();
    let fixture = fixture(
        move |config| {
            env_key(config);
            config.ai_base_url = base;
        },
        &[],
    )
    .await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    let _alive = ai.reviewer_alive();
    assert!(ai.tap().is_none(), "off: the gate is shut");

    apply_patch(
        state,
        patch(r#"{"model":"typesafe/jev-1.13","enabled":true}"#),
    )
    .await
    .expect("a passing Test turns review on");
    assert_eq!(ai.state(), State::Reviewing);
    assert!(ai.tap().is_some());
    assert_eq!(ai.tested("typesafe/jev-1.13"), Some(true));
    assert_eq!(ai.today(now_secs()).requests, 1, "the Test is charged");
    for (key, value) in [
        ("ai_enabled", "1"),
        ("ai_model", "typesafe/jev-1.13"),
        ("ai_model_price", "0.042"),
    ] {
        assert_eq!(
            state.storage.setting(key).await.expect("read").as_deref(),
            Some(value)
        );
    }
    let sent = stub.requests();
    assert_eq!(sent.len(), 3, "both listings, then one Test");
    let test = &sent[2];
    assert_eq!(test.target, "/api/alpha/decisions");
    let body: serde_json::Value = serde_json::from_slice(&test.body).expect("JSON");
    assert_eq!(body["state"]["website"], "www.wikipedia.org");
    assert_eq!(
        body["provider"],
        serde_json::json!({"data_collection":"deny","zdr":true,"allow_fallbacks":true,
                           "max_price":{"prompt":"0.0525"}})
    );

    let generation = ai.generation();
    apply_patch(state, patch(r#"{"enabled":false}"#))
        .await
        .expect("turning it off is always possible");
    assert!(ai.tap().is_none());
    assert!(
        !ai.may_send(generation),
        "a job queued before the PUT never sends"
    );
    assert_eq!(ai.state(), State::Off);
    assert_eq!(
        state.storage.setting("ai_enabled").await.expect("read"),
        None
    );
    assert_eq!(stub.requests().len(), 3, "and turning off sent nothing");
}

#[tokio::test]
async fn a_key_is_checked_before_it_is_kept_and_only_its_limits_are_shown() {
    let label = "sk-or-v1-012...def";
    for (status, expected) in [
        (401, StatusCode::BAD_REQUEST),
        (402, StatusCode::CONFLICT),
        (404, StatusCode::SERVICE_UNAVAILABLE),
        (429, StatusCode::TOO_MANY_REQUESTS),
        (503, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let stub = Stub::serve(vec![Reply::json(status, "{}")]);
        let base = stub.base.clone();
        let fixture = fixture(move |config| config.ai_base_url = base, &[]).await;
        let error = apply_patch(&fixture.state, patch(&format!(r#"{{"key":"{KEY}"}}"#)))
            .await
            .expect_err("not kept");
        assert_eq!(error.status(), expected, "status {status}");
        assert!(fixture.state.ai.key().is_none(), "nothing was saved");
    }

    let body = format!(
        r#"{{"data":{{"label":"{label}","limit":5,"usage":0.88,"limit_remaining":4.12}}}}"#
    );
    let stub = Stub::serve(vec![Reply::json(200, body)]);
    let base = stub.base.clone();
    let fixture = fixture(move |config| config.ai_base_url = base, &[]).await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    apply_patch(state, patch(&format!(r#"{{"key":"{KEY}"}}"#)))
        .await
        .expect("an accepted key is kept");
    assert_eq!(ai.key().map(|slot| slot.source), Some(KeySource::Saved));
    assert_eq!(
        stub.requests()[0].header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    // An in-memory database has no data directory: the key is held in memory only.
    assert!(!std::path::Path::new("openrouter.key").exists());

    let status = ai.status(&state.runtime.current_policy(), AiCounts::default());
    assert_eq!(status.key.limit_usd, Some(5.0));
    assert_eq!(status.key.limit_remaining_usd, Some(4.12));
    let shown = serde_json::to_string(&(
        status,
        ai.settings_view(),
        ai.overview(&state.runtime.current_policy()),
    ))
    .expect("serialises");
    assert!(!shown.contains(label), "OpenRouter's label is a masked key");
    for window in KEY.as_bytes().windows(8) {
        let window = std::str::from_utf8(window).expect("ascii");
        assert!(
            !shown.contains(window),
            "{window:?} of the key reached a response: {shown}"
        );
    }

    apply_patch(state, patch(r#"{"key":null}"#))
        .await
        .expect("removed");
    assert!(ai.key().is_none());
    assert_eq!(stub.requests().len(), 1, "removing a key asks nobody");
}

#[tokio::test]
async fn a_saved_key_is_written_owner_only_and_removed_with_its_file() {
    let dir = Scratch::new("patch-key");
    let database = format!("sqlite://{}/cogwheel.db", dir.path().display());
    let stub = Stub::serve(vec![Reply::json(
        200,
        r#"{"data":{"limit":null,"limit_remaining":null}}"#,
    )]);
    let base = stub.base.clone();
    let fixture = fixture(
        move |config| {
            config.ai_base_url = base;
            config.database_url = database;
        },
        &[],
    )
    .await;
    let (state, ai) = (&fixture.state, &fixture.state.ai);
    let path = dir.path().join("openrouter.key");

    apply_patch(state, patch(&format!(r#"{{"key":"{KEY}"}}"#)))
        .await
        .expect("an accepted key is saved");
    assert_eq!(std::fs::read_to_string(&path).expect("saved"), KEY);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("saved")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Checked, and no per-key limit: the card can say so.
    let status = ai.status(&state.runtime.current_policy(), AiCounts::default());
    assert_eq!(status.key.limit_usd, None);
    assert!(status.key.checked_at.is_some());

    apply_patch(state, patch(r#"{"key":null}"#))
        .await
        .expect("removed");
    assert!(!path.exists(), "the file went with it");
    assert!(ai.key().is_none());
}
