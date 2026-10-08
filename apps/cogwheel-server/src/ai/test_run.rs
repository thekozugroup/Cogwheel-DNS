//! The Test (route 26): one request about a fixed, public example, to check that a key and a
//! model answer Cogwheel's questions before review is turned on.
//!
//! It sends no household data. It is charged to today's spend like any other request, through
//! `settle`. A pass needs a role answer that says how sure it is: a model that never does would
//! otherwise pass, then spend the daily limit on rows that can never clear a bar (D6).

use super::client::{self, Class, Failure, Reply};
use super::key::SecretKey;
use super::patch::NOT_A_KEY;
use super::prompt::{self, Choice, Context, Effect, Parsed, Provider};
use super::spend::{Cost, charge_micro, micro_to_usd, reserve_micro};
use super::{AiState, KEY_REFUSED, OUT_OF_CREDIT, Passed, REDIRECTED, State, model_list};
use crate::http::ApiError;
use crate::state::{ServerState, lock, now_secs, read};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// One Test per this gap, the PUT's included.
pub const TEST_GAP: Duration = Duration::from_secs(10);
/// A passed Test is reused this long, so the Turn on that follows it does not pay again.
pub const TEST_REUSE: Duration = Duration::from_secs(600);
/// Models whose last Test is remembered for the picker.
const TESTED_CAP: usize = 64;

/// The fixed, public example the Test sends: no household data.
pub const TEST_WEBSITE: &str = "www.wikipedia.org";
pub const TEST_CANDIDATE: &str = "www.googletagmanager.com";
pub const TEST_CONTEXT: [&str; 2] = ["upload.wikimedia.org", "login.wikimedia.org"];

const NOT_A_MODEL: &str = "That is not an OpenRouter model id.";
const TEST_NO_KEY: &str = "Add an OpenRouter key first.";
const TEST_NO_MODEL: &str = "Pick a model first.";
const TEST_MODEL_GONE: &str = "OpenRouter would not run this model: no provider meets the privacy \
                               and price limits, or the model is gone. Pick another, or set \
                               COGWHEEL_AI__ZERO_RETENTION=false.";
const CANNOT_ANSWER: &str = "That model cannot answer Cogwheel's questions; pick another.";
const UNRATED: &str = "That model does not say how sure it is; pick another.";
pub(super) const SLOW_DOWN: &str = "OpenRouter is rate-limiting this key; try again in a minute.";
const NO_ANSWER: &str = "OpenRouter did not answer; try again in a minute.";
const NO_EFFECT_CONFIDENCE: &str = " It does not say how sure it is about whether a site breaks, \
                                    so it can block names but will never override your lists.";

/// A passed Test, as route 26 answers it.
#[derive(Debug, Clone, Serialize)]
pub struct AiTestResult {
    pub ok: bool,
    /// The dated snapshot that answered.
    pub model: String,
    pub provider: Option<String>,
    pub latency_ms: u64,
    pub cost_usd: f64,
    pub answer: TestAnswer,
    pub sentence: String,
}

/// What the model said about the fixed example.
#[derive(Debug, Clone, Serialize)]
pub struct TestAnswer {
    pub website: &'static str,
    pub candidate: &'static str,
    pub choice: &'static str,
    pub confidence: Option<f64>,
    pub effect: Option<&'static str>,
    pub effect_confidence: Option<f64>,
}

/// Route 26: ask `staged` (or the saved) model, with `staged` (or the saved) key, about a fixed
/// public example. Charged to today like any other request. A pass of the saved key and model
/// ends `key_refused`, `out_of_credit` and `model_refused`.
///
/// # Errors
///
/// Route 26's table: 400, 409, 429 or 503 with its sentence.
pub async fn run_test(
    state: &ServerState,
    staged: super::AiTestInput,
) -> Result<AiTestResult, ApiError> {
    let ai = &state.ai;
    let _writes = ai.writes.lock().await;
    if let Some(reason) = ai.unavailable {
        return Err(ApiError::conflict(reason.sentence()));
    }
    let saved = ai.key();
    let key = match staged.key.as_deref() {
        Some(text) => SecretKey::from_ui(text).ok_or_else(|| ApiError::bad_request(NOT_A_KEY))?,
        None => saved
            .as_ref()
            .map(|slot| slot.key.clone())
            .ok_or_else(|| ApiError::conflict(TEST_NO_KEY))?,
    };
    let current = read(&ai.settings).clone();
    let model = match staged.model {
        Some(model) if super::settings::model_shaped(&model) => model,
        Some(_) => return Err(ApiError::bad_request(NOT_A_MODEL)),
        None => current
            .model
            .clone()
            .ok_or_else(|| ApiError::conflict(TEST_NO_MODEL))?,
    };
    let price = if current.model.as_deref() == Some(model.as_str()) {
        current.model_price
    } else {
        model_list(state).await.ok().and_then(|list| {
            list.get(&model)
                .and_then(|listed| listed.prompt_usd_per_million)
        })
    };
    let result = test_once(state, &key, &model, price).await?;

    let in_force = saved.is_some_and(|slot| slot.key == key)
        && current.model.as_deref() == Some(model.as_str());
    let terminal = matches!(
        ai.machine_state(),
        State::KeyRefused | State::OutOfCredit | State::ModelRefused
    );
    if in_force && terminal && ai.applying() {
        ai.resume();
    }
    Ok(result)
}

/// One Test request, without the writes lock (the caller holds it: route 26, or the PUT's step 5).
pub(super) async fn test_once(
    state: &ServerState,
    key: &SecretKey,
    model: &str,
    price: Option<f64>,
) -> Result<AiTestResult, ApiError> {
    let ai = &state.ai;
    {
        let mut last = lock(&ai.last_test);
        if let Some(at) = *last
            && at.elapsed() < TEST_GAP
        {
            let wait = TEST_GAP.saturating_sub(at.elapsed()).as_secs() + 1;
            return Err(ApiError::too_many_requests(format!(
                "Tested a moment ago; try again in {wait} seconds."
            )));
        }
        *last = Some(Instant::now());
    }

    let context = Context {
        website: TEST_WEBSITE,
        candidate: TEST_CANDIDATE,
        looked_up_with_it: &TEST_CONTEXT,
    };
    let provider = Provider {
        zero_retention: ai.zero_retention,
        price_per_million: price,
    };
    let body = prompt::body(model, &context, Some(Effect::Blocked), &provider);
    let reserve = reserve_micro(body.len(), price);
    let started = Instant::now();
    let sent = client::decide(&ai.client, &ai.base, key, body).await;
    let latency = started.elapsed();
    let reply = match sent {
        Ok(reply) => reply,
        Err(failure) => {
            // Only the failures that are the model's say anything about it.
            if matches!(failure.class, Class::ModelRefused | Class::Drop) {
                ai.record_test(model, false);
            }
            return Err(test_failure(&failure));
        }
    };

    // Billed whatever the answer says, so charged before it is read.
    let parsed = match reply {
        Reply::Body(body) => prompt::parse(&body, true),
        Reply::Unreadable => Parsed::default(),
    };
    let (micro, unpriced) = charge_micro(parsed.usage.as_ref(), reserve, price);
    if unpriced {
        ai.counters.unpriced.fetch_add(1, Ordering::Relaxed);
    }
    // A failed write is logged by `settle` and stays counted in memory; the answer still stands.
    let _ = ai
        .settle(&state.storage, now_secs(), Cost::request(micro), Vec::new())
        .await;

    let Some(answer) = parsed.answer else {
        ai.counters.malformed.fetch_add(1, Ordering::Relaxed);
        ai.record_test(model, false);
        return Err(ApiError::conflict(CANNOT_ANSWER));
    };
    let Some(confidence) = answer.confidence else {
        ai.record_test(model, false);
        return Err(ApiError::conflict(UNRATED));
    };
    ai.record_test(model, true);
    *lock(&ai.passed) = Some(Passed {
        key: key.fingerprint(),
        model: model.to_owned(),
        at: Instant::now(),
    });

    let cost_usd = parsed
        .usage
        .and_then(|usage| usage.cost)
        .unwrap_or_else(|| micro_to_usd(micro));
    let effect_confidence = answer.effect.and_then(|(_, confidence)| confidence);
    let mut sentence = format!(
        "{name} answered in {seconds:.1} s{through}: {verdict} (the model was {percent:.0}% \
         sure). The test cost {cost}.",
        name = ai.display_name(model),
        seconds = latency.as_secs_f64(),
        through = parsed
            .provider
            .as_deref()
            .map(|provider| format!(" through {provider}"))
            .unwrap_or_default(),
        verdict = match answer.choice {
            Choice::Block => format!("{TEST_CANDIDATE} is not needed by {TEST_WEBSITE}"),
            Choice::Allow => format!("{TEST_CANDIDATE} is part of what {TEST_WEBSITE} needs"),
            Choice::Ignore => {
                format!("it could not tell what {TEST_CANDIDATE} does for {TEST_WEBSITE}")
            }
        },
        percent = (confidence * 100.0).round(),
        cost = dollars(cost_usd),
    );
    if effect_confidence.is_none() {
        sentence.push_str(NO_EFFECT_CONFIDENCE);
    }
    Ok(AiTestResult {
        ok: true,
        model: parsed.model.unwrap_or_else(|| model.to_owned()),
        provider: parsed.provider,
        latency_ms: u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
        cost_usd,
        answer: TestAnswer {
            website: TEST_WEBSITE,
            candidate: TEST_CANDIDATE,
            choice: answer.choice.as_str(),
            confidence: Some(confidence),
            effect: answer.effect.map(|(outcome, _)| outcome.as_str()),
            effect_confidence,
        },
        sentence,
    })
}

/// Route 26's failure table.
fn test_failure(failure: &Failure) -> ApiError {
    match failure.class {
        Class::KeyRefused => ApiError::bad_request(KEY_REFUSED),
        Class::OutOfCredit => ApiError::conflict(OUT_OF_CREDIT),
        Class::ModelRefused => ApiError::conflict(TEST_MODEL_GONE),
        Class::Drop => ApiError::conflict(CANNOT_ANSWER),
        Class::Redirected => ApiError::unavailable(REDIRECTED),
        Class::Retry {
            rate_limited: true, ..
        } => ApiError::too_many_requests(SLOW_DOWN),
        Class::Retry { .. } => ApiError::unavailable(NO_ANSWER),
    }
}

/// A cost the way the Test sentence says it: cents, or the first significant digit under a cent.
pub fn dollars(usd: f64) -> String {
    if !usd.is_finite() || usd <= 0.0 {
        return "$0.00".to_owned();
    }
    let decimals = if usd >= 0.01 {
        2
    } else {
        (-usd.log10()).ceil().clamp(2.0, 9.0) as usize
    };
    format!("${usd:.decimals$}")
}

impl AiState {
    /// Remember the last Test of `model` for the picker, keeping at most [`TESTED_CAP`] models.
    fn record_test(&self, model: &str, passed: bool) {
        let mut tested = lock(&self.tested);
        if tested.len() >= TESTED_CAP
            && !tested.contains_key(model)
            && let Some(evicted) = tested.keys().next().cloned()
        {
            tested.remove(&evicted);
        }
        tested.insert(model.to_owned(), passed);
    }
}
