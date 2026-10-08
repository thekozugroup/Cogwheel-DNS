//! The model picker (route 25): OpenRouter's decision models, marked by zero retention and by
//! the last Test of each, fetched without the key and reused for an hour.

use super::AiState;
use super::client::{self, ModelList};
use crate::http::ApiError;
use crate::state::{ServerState, now_secs, read};
use serde::Serialize;
use std::sync::Arc;

const NO_MODEL_LIST: &str = "OpenRouter's model list could not be fetched; try again in a minute.";

/// Prompt tokens a name costs, for the per-thousand estimate: about 500 a request.
const TOKENS_PER_NAME: f64 = 500.0;

/// The merged model list, fetched at most once an hour, without the key.
///
/// # Errors
///
/// 409 while AI review is unavailable; 503 when OpenRouter's list cannot be fetched.
pub async fn model_list(state: &ServerState) -> Result<Arc<ModelList>, ApiError> {
    let ai = &state.ai;
    if let Some(reason) = ai.unavailable {
        return Err(ApiError::conflict(reason.sentence()));
    }
    if let Some(list) = ai.models.get() {
        return Ok(list);
    }
    // One fetch at a time: a second caller waits for the first and reads what it stored.
    let _fetching = ai.models_fetch.lock().await;
    if let Some(list) = ai.models.get() {
        return Ok(list);
    }
    let list = client::models(&ai.client, &ai.base, now_secs())
        .await
        .map(Arc::new)
        .ok_or_else(|| ApiError::unavailable(NO_MODEL_LIST))?;
    ai.models.set(Arc::clone(&list));
    Ok(list)
}

/// Route 25's answer.
#[derive(Debug, Clone, Serialize)]
pub struct ModelsView {
    pub fetched_at: i64,
    /// Mirrors `COGWHEEL_AI__ZERO_RETENTION`: the picker greys out models without it.
    pub zero_retention_required: bool,
    pub models: Vec<ModelView>,
}

/// One model in the picker.
#[derive(Debug, Clone, Serialize)]
pub struct ModelView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub context_length: u64,
    pub prompt_usd_per_million: Option<f64>,
    /// An estimate: 500 prompt tokens a name.
    pub usd_per_thousand_names: Option<f64>,
    /// `None` when the zero-retention listing could not be fetched.
    pub zero_retention: Option<bool>,
    /// `"passed"`, `"failed"`, or `None` if never tested since boot.
    pub tested: Option<&'static str>,
}

impl AiState {
    /// The picker's view of `list`: each model marked by its last Test. The saved model of an
    /// enabled configuration reads passed unless a later Test failed, because enabling required
    /// a pass.
    pub fn models_view(&self, list: &ModelList) -> ModelsView {
        let settings = read(&self.settings).clone();
        ModelsView {
            fetched_at: list.fetched_at,
            zero_retention_required: self.zero_retention,
            models: list
                .models
                .iter()
                .map(|model| {
                    let in_force = settings.enabled && settings.model.as_deref() == Some(&model.id);
                    let tested = self.tested(&model.id).or(in_force.then_some(true));
                    ModelView {
                        id: model.id.clone(),
                        name: model.name.clone(),
                        description: model.description.clone(),
                        context_length: model.context_length,
                        prompt_usd_per_million: model.prompt_usd_per_million,
                        usd_per_thousand_names: model.prompt_usd_per_million.map(|price| {
                            client::round_price(price * TOKENS_PER_NAME * 1_000.0 / 1e6)
                        }),
                        zero_retention: model.zero_retention,
                        tested: tested.map(|passed| if passed { "passed" } else { "failed" }),
                    }
                })
                .collect(),
        }
    }

    /// A model's name for a sentence: the listed name without its vendor ("Jev 1.13"), or the id.
    pub(super) fn display_name(&self, id: &str) -> String {
        self.models
            .last()
            .as_ref()
            .and_then(|list| list.get(id))
            .map(|model| {
                model
                    .name
                    .split_once(": ")
                    .map_or(model.name.as_str(), |(_, name)| name)
                    .to_owned()
            })
            .unwrap_or_else(|| id.to_owned())
    }
}
