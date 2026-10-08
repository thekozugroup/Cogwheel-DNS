//! Unit tests for AI review, one file per module (§16). All offline: the client tests talk to a
//! listener on loopback, and nothing here can reach OpenRouter.

mod burst;
mod candidates;
mod client;
mod gate;
mod install;
mod key;
mod load;
mod patch;
mod prompt;
pub(crate) mod review;
mod site;
mod spend;
mod test_run;
mod verdict;
mod worker;

use crate::ai::{AiPatch, AiState, Seen};
use crate::config::{AppConfig, Profile};
use crate::http::ApiError;
use crate::tests::openrouter_stub::keyed;
use axum::http::StatusCode;
use cogwheel_storage::{AiVerdict, Storage};
use std::sync::Arc;
use tokio::sync::mpsc;

/// A recognisable fake. Not OpenRouter's real shape (`sk-or-v1-` and 64 hex digits), which secret
/// scanning would rightly refuse to let anyone push.
pub const KEY: &str = "sk-or-v1-fake-test-key-qwzx-mnbv-plok-ijuh-ygtf-rdes";

/// The configuration the harness runs with: an in-memory database and a closed port for
/// OpenRouter.
pub fn config() -> AppConfig {
    let mut config = AppConfig::for_profile(Profile::Home);
    config.database_url = ":memory:".to_owned();
    config.ai_base_url = "http://127.0.0.1:1".parse().expect("a loopback url");
    config
}

/// `config` with [`KEY`] in `COGWHEEL_AI__OPENROUTER_API_KEY`.
pub fn with_env_key(mut config: AppConfig) -> AppConfig {
    keyed(KEY)(&mut config);
    config
}

pub async fn storage() -> Storage {
    Storage::open(":memory:").await.expect("open a database")
}

/// Stored consent and a model, as a household that turned review on leaves them.
pub async fn consent(storage: &Storage) {
    storage
        .set_setting("ai_enabled", Some("1".to_owned()))
        .await
        .expect("store consent");
    storage
        .set_setting("ai_model", Some("typesafe/jev-1.13".to_owned()))
        .await
        .expect("store the model");
}

pub async fn load(config: &AppConfig, storage: &Storage) -> (Arc<AiState>, mpsc::Receiver<Seen>) {
    AiState::load(config, storage)
        .await
        .expect("AI review's state loads")
}

pub fn verdict(domain: &str, verdict: &str, judged_at: i64) -> AiVerdict {
    AiVerdict {
        domain: domain.to_owned(),
        verdict: verdict.to_owned(),
        why: (verdict == "ignore").then(|| "unsure".to_owned()),
        choice: verdict.to_owned(),
        confidence: Some(0.95),
        effect: None,
        effect_confidence: None,
        lists: "nothing".to_owned(),
        site: Some("www.example.com".to_owned()),
        conflict_site: None,
        rechecks: 0,
        model: "typesafe/jev-1.13-20260917".to_owned(),
        judged_at,
        review_after: judged_at + 30 * 86_400,
    }
}

/// A model a household picked, as `settings` stores it.
pub const MODEL: (&str, &str) = ("ai_model", "typesafe/jev-1.13");

/// A `PUT /api/v1/ai` body.
pub fn patch(body: &str) -> AiPatch {
    serde_json::from_str(body).expect("a patch body")
}

/// `error` is this status with exactly this sentence.
pub fn refused(error: &ApiError, status: StatusCode, sentence: &str) {
    assert_eq!(
        (error.status(), error.to_string().as_str()),
        (status, sentence)
    );
}

/// A passing Test's answer.
pub const ANSWER: &str = r#"{"id":"gen-dec-1","model":"typesafe/jev-1.13-20260917","provider":"TypeSafe",
  "answers":{"role":{"type":"choice","choice":"block","confidence":0.91},
             "effect":{"type":"choice","choice":"works","confidence":0.94}},
  "usage":{"input_tokens":510,"output_tokens":70,"cost":0.0000213}}"#;
