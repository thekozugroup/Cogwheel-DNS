//! `PUT /api/v1/ai` (route 24): turning AI review on and off, picking the model, saving or
//! removing the key, and the daily limit.
//!
//! It holds `AiState.writes`, validates everything before it saves anything, and closes the send
//! gate before it writes a withdrawal of consent (D18). Error sentences are fixed text: nothing
//! the request carried, and nothing OpenRouter said, is repeated back.

use super::client::{self, KeyCheck, KeyInfo};
use super::key::{self, SecretKey};
use super::settings::{
    AI_DAILY_LIMIT, AI_ENABLED, AI_MODEL, AI_MODEL_PRICE, AiPatch, Settings, cents, model_shaped,
    spell_cents,
};
use super::test_run::{SLOW_DOWN, test_once};
use super::{AiState, Halt, KeySlot, KeySource, State, model_list};
use crate::http::ApiError;
use crate::policy_build::{self, Rebuild};
use crate::state::{ServerState, lock, now_secs, read, write};
use std::sync::atomic::Ordering;

const NOT_A_MODEL: &str = "That is not an OpenRouter model id.";
const NOT_LISTED: &str = "That model is not one of OpenRouter's decision models.";
const NO_ZERO_RETENTION: &str = "No zero-retention provider runs that model; pick another, or set \
                                 COGWHEEL_AI__ZERO_RETENTION=false.";
pub(super) const NOT_A_KEY: &str = "That does not look like an OpenRouter key.";
const NOT_A_LIMIT: &str = "Choose a daily limit of 5¢, 10¢, 25¢ or $1.";
const ENVIRONMENT_KEY: &str = "The OpenRouter key is set in the environment \
                               (COGWHEEL_AI__OPENROUTER_API_KEY); change it there.";
const ADD_A_KEY: &str = "Add an OpenRouter key before turning AI review on.";
const PICK_A_MODEL: &str = "Pick a model before turning AI review on.";

/// Route 24, steps 1–8. The handler answers with the status afterwards.
///
/// # Errors
///
/// The 400/409/429/503 of route 24's tables, a failing Test's own status and sentence, or a 500
/// when the database or the key file could not be written.
pub async fn apply_patch(state: &ServerState, patch: AiPatch) -> Result<(), ApiError> {
    let ai = &state.ai;
    let _writes = ai.writes.lock().await;

    // 1. Refusals that depend on the body. Removing a saved key is never refused: deleting a
    //    secret should not depend on the feature being available.
    let removing = matches!(patch.key, Some(None));
    let only_removing = removing
        && patch.enabled.is_none()
        && patch.model.is_none()
        && patch.daily_limit_usd.is_none();
    if let Some(reason) = ai.unavailable
        && !only_removing
    {
        return Err(ApiError::conflict(reason.sentence()));
    }
    let saved = ai.key();
    let environment = saved
        .as_ref()
        .is_some_and(|slot| slot.source == KeySource::Environment);
    if patch.key.is_some() && environment {
        return Err(ApiError::conflict(ENVIRONMENT_KEY));
    }

    // 2. Shapes.
    if patch
        .model
        .as_deref()
        .is_some_and(|model| !model_shaped(model))
    {
        return Err(ApiError::bad_request(NOT_A_MODEL));
    }
    let limit = match patch.daily_limit_usd {
        Some(usd) => Some(cents(usd).ok_or_else(|| ApiError::bad_request(NOT_A_LIMIT))?),
        None => None,
    };
    let new_key = match &patch.key {
        Some(Some(text)) => {
            Some(SecretKey::from_ui(text).ok_or_else(|| ApiError::bad_request(NOT_A_KEY))?)
        }
        _ => None,
    };
    let current = read(&ai.settings).clone();
    let enabled = patch.enabled.unwrap_or(current.enabled);
    let model = patch.model.clone().or_else(|| current.model.clone());
    let key = match (&new_key, removing) {
        (Some(key), _) => Some(key.clone()),
        (None, true) => None,
        (None, false) => saved.as_ref().map(|slot| slot.key.clone()),
    };
    if patch.enabled == Some(true) && key.is_none() {
        return Err(ApiError::conflict(ADD_A_KEY));
    }
    if patch.enabled == Some(true) && model.is_none() {
        return Err(ApiError::conflict(PICK_A_MODEL));
    }

    // 3. A new model must be one OpenRouter lists, if the list can be fetched; its price is
    //    recorded for the `max_price` ceiling and the spend estimate.
    let model_changed = patch.model.is_some() && patch.model != current.model;
    let mut price = current.model_price;
    if model_changed && let Some(id) = &patch.model {
        price = None;
        if let Ok(list) = model_list(state).await {
            let listed = list
                .get(id)
                .ok_or_else(|| ApiError::bad_request(NOT_LISTED))?;
            if ai.zero_retention && listed.zero_retention == Some(false) {
                return Err(ApiError::bad_request(NO_ZERO_RETENTION));
            }
            price = listed.prompt_usd_per_million;
        }
    }

    // 4. A new key must be one OpenRouter accepts. Only its limits are kept.
    let key_info = match &new_key {
        Some(key) => Some(
            client::key_info(ai.client(), &ai.base, key)
                .await
                .map_err(key_check_error)?,
        ),
        None => None,
    };

    // 5. The Test, when review will be on and what it was consented for changed. A failure
    //    passes through with the Test's own status and sentence.
    let turning_on = enabled && !current.enabled;
    let mut tested = false;
    if enabled
        && (new_key.is_some() || model_changed || turning_on)
        && let (Some(key), Some(model)) = (&key, &model)
    {
        if !ai.recently_passed(key, model) {
            test_once(state, key, model, price).await?;
        }
        tested = true;
    }

    // 6. Withdraw consent, or change its subject, before anything is written: once this returns
    //    no request starts under the old consent.
    let was_reviewing = matches!(ai.machine_state(), State::Reviewing | State::Retrying);
    let halt = if current.enabled && !enabled {
        Some(Halt::Off)
    } else if removing {
        Some(Halt::NoKey)
    } else if was_reviewing && new_key.is_some() {
        Some(Halt::KeyChanged)
    } else if was_reviewing && model_changed {
        Some(Halt::ModelChanged)
    } else {
        None
    };
    if let Some(reason) = halt {
        ai.halt(reason);
    }

    // 7. Persist the settings, then the key file.
    let next = Settings {
        enabled,
        model,
        model_price: price,
        daily_limit_cents: limit.unwrap_or(current.daily_limit_cents),
    };
    if let Err(error) = persist(state, &current, &next, new_key, removing, key_info).await {
        // A change that was going to resume review resumes it on what is still in force, which
        // the household had already consented to.
        if matches!(halt, Some(Halt::KeyChanged | Halt::ModelChanged)) {
            ai.resume();
        }
        return Err(error);
    }

    // 8. Install (or withdraw) the AI list inline, so the answer and the next GET agree; then
    //    reopen the gate on a new generation with an empty queue. This is the only way back to
    //    reviewing from a PUT.
    let installed = if next.enabled == current.enabled {
        Ok(())
    } else {
        policy_build::rebuild(state, Rebuild::Ai).await.map(|_| ())
    };
    if next.enabled && tested && (halt.is_some() || !was_reviewing) {
        ai.resume();
    }
    installed
}

/// Write what changed: the settings keys, then the key file, each into memory once it is on disk.
async fn persist(
    state: &ServerState,
    current: &Settings,
    next: &Settings,
    new_key: Option<SecretKey>,
    removing: bool,
    key_info: Option<KeyInfo>,
) -> Result<(), ApiError> {
    let (ai, storage) = (&state.ai, &state.storage);
    if next.enabled != current.enabled {
        let flag = next.enabled.then(|| "1".to_owned());
        storage.set_setting(AI_ENABLED, flag).await?;
    }
    if next.model != current.model {
        storage.set_setting(AI_MODEL, next.model.clone()).await?;
        let price = next.model_price.map(|price| price.to_string());
        storage.set_setting(AI_MODEL_PRICE, price).await?;
    }
    if next.daily_limit_cents != current.daily_limit_cents {
        let limit = spell_cents(next.daily_limit_cents);
        storage.set_setting(AI_DAILY_LIMIT, Some(limit)).await?;
    }
    *write(&ai.settings) = next.clone();

    if removing {
        // The gate closed in step 6, so nothing can use the key meanwhile. The file goes first:
        // if it cannot be removed, the key stays in memory too, and what the card shows still
        // matches what a restart would load.
        if let Some(path) = ai.key_path.clone() {
            blocking(move || key::remove(&path))
                .await
                .map_err(|error| {
                    tracing::error!(%error, "could not remove the saved OpenRouter key");
                    ApiError::internal(
                        "The OpenRouter key could not be removed from the data directory.",
                    )
                })?;
        }
        ai.replace_key(None);
    } else if let Some(key) = new_key {
        if let Some(path) = ai.key_path.clone() {
            let saved = key.clone();
            blocking(move || key::store(&path, &saved))
                .await
                .map_err(|error| {
                    tracing::error!(%error, "could not save the OpenRouter key");
                    ApiError::internal(
                        "The OpenRouter key could not be saved in the data directory.",
                    )
                })?;
        }
        ai.replace_key(Some(key));
        if let Some(info) = key_info {
            ai.set_key_info(info, now_secs());
        }
    }
    Ok(())
}

/// Run blocking file work off the async threads.
async fn blocking<F>(job: F) -> std::io::Result<()>
where
    F: FnOnce() -> std::io::Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(job)
        .await
        .unwrap_or_else(|error| Err(std::io::Error::other(error.to_string())))
}

/// Route 24's key-check table. Every row saves nothing.
fn key_check_error(check: KeyCheck) -> ApiError {
    match check {
        KeyCheck::Refused => ApiError::bad_request("OpenRouter did not accept that key."),
        KeyCheck::NoCredit => ApiError::conflict(
            "The OpenRouter account behind that key is out of credit; nothing was saved.",
        ),
        KeyCheck::Unchecked => {
            ApiError::unavailable("OpenRouter could not check that key, so nothing was saved.")
        }
        KeyCheck::RateLimited => ApiError::too_many_requests(SLOW_DOWN),
        KeyCheck::Unreachable => {
            ApiError::unavailable("OpenRouter could not be reached, so nothing was saved.")
        }
    }
}

impl AiState {
    /// Swap the saved key (or none) into memory. A new key starts a new generation, drops the
    /// cached Test pass and the old key's limits, and ends a state the old key caused.
    fn replace_key(&self, key: Option<SecretKey>) {
        let slot = key.map(|key| KeySlot {
            key,
            source: KeySource::Saved,
            generation: self.key_generations.fetch_add(1, Ordering::AcqRel) + 1,
        });
        *write(&self.key) = slot;
        *lock(&self.key_info) = None;
        *lock(&self.passed) = None;
        let mut machine = lock(&self.machine);
        if matches!(machine.state, State::KeyRefused | State::OutOfCredit) {
            machine.state = State::Off;
        }
        if machine.state != State::Stopped {
            machine.last_error = None;
        }
    }

    /// Whether this key and model passed a Test in the last ten minutes.
    pub(super) fn recently_passed(&self, key: &SecretKey, model: &str) -> bool {
        lock(&self.passed).as_ref().is_some_and(|passed| {
            passed.key == key.fingerprint()
                && passed.model == model
                && passed.at.elapsed() < super::test_run::TEST_REUSE
        })
    }
}
