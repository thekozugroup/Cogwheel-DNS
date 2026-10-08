//! Unit tests for AI review, one file per module (§16). All offline: the client tests talk to a
//! listener on loopback, and nothing here can reach OpenRouter.

// The parent allows unused imports while the routes it re-exports for are not written yet; that
// allowance is not for the tests.
#![warn(unused_imports)]

mod burst;
mod candidates;
mod client;
mod gate;
mod install;
mod key;
mod load;
mod patch;
mod prompt;
mod review;
mod site;
mod spend;
mod stub;
mod test_run;
mod verdict;
mod worker;

use crate::ai::key::SecretKey;
use crate::ai::{AiState, Seen};
use crate::config::{AppConfig, Profile};
use crate::state::ServerState;
use crate::tests::Harness;
use cogwheel_storage::{AiVerdict, Storage};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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

pub fn with_env_key(mut config: AppConfig) -> AppConfig {
    config.ai_api_key = SecretKey::from_env(KEY).expect("a header-safe key");
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

/// A harness whose AI review was loaded from a configuration of the test's choosing, over
/// settings stored first, the way a restart would load them.
pub struct Fixture {
    _harness: Harness,
    pub state: ServerState,
    _tap: mpsc::Receiver<Seen>,
}

pub async fn fixture(
    configure: impl FnOnce(&mut AppConfig),
    stored: &[(&'static str, &str)],
) -> Fixture {
    let harness = Harness::new().await;
    for (key, value) in stored {
        harness
            .state
            .storage
            .set_setting(key, Some((*value).to_owned()))
            .await
            .expect("store a setting");
    }
    let mut config = (*harness.state.config).clone();
    configure(&mut config);
    let (ai, tap) = AiState::load(&config, &harness.state.storage)
        .await
        .expect("AI review's state loads");
    let state = ServerState {
        config: Arc::new(config),
        ai,
        ..harness.state.clone()
    };
    Fixture {
        _harness: harness,
        state,
        _tap: tap,
    }
}

/// `COGWHEEL_AI__OPENROUTER_API_KEY`, set.
pub fn env_key(config: &mut AppConfig) {
    config.ai_api_key = SecretKey::from_env(KEY).expect("a header-safe key");
}

/// A directory under the system temp dir, removed when the test that made it ends.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "cogwheel-ai-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create a scratch directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
