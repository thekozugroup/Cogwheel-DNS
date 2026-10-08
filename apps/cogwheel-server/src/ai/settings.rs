//! Changing AI review: the settings keys, `PUT /api/v1/ai` (route 24), the Test (route 26), the
//! model list (route 25), and `settle`, the one writer of today's spend (§6.13).
//!
//! Every write here holds `AiState.writes`, validates everything before saving anything, and
//! closes the send gate before it writes a withdrawal of consent. Error sentences are fixed text:
//! nothing a request carried, and nothing OpenRouter said, is ever repeated back.

use super::client::{self, Class, Failure, KeyCheck, ModelList, Reply};
use super::key::{self, SecretKey};
use super::prompt::{self, Choice, Context, Effect, Parsed, Provider, Usage};
use super::{
    AiState, DAY, Halt, KEY_REFUSED, KeySlot, KeySource, OUT_OF_CREDIT, Passed, REDIRECTED, State,
};
use crate::config::AppConfig;
use crate::http::ApiError;
use crate::policy_build::{self, Rebuild};
use crate::state::{ServerState, lock, now_secs, read, write};
use cogwheel_storage::{AiVerdict, Storage, StorageError};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// `1`, or absent: review is on. Deleted at boot whenever review is unavailable (D13).
pub const AI_ENABLED: &str = "ai_enabled";
pub const AI_MODEL: &str = "ai_model";
/// USD per million prompt tokens, as listed when the model was picked; absent if unknown.
pub const AI_MODEL_PRICE: &str = "ai_model_price";
/// `0.05`, `0.10`, `0.25` or `1.00`; absent means `0.10`.
pub const AI_DAILY_LIMIT: &str = "ai_daily_limit";
/// `"<utc day> <micro-USD> <requests> <overrides>"`, written only by [`AiState::settle`].
pub const AI_SPEND: &str = "ai_spend";

/// The daily limits on offer, in cents. 10¢ unless the household picked another.
pub const DAILY_LIMITS_CENTS: [u32; 4] = [5, 10, 25, 100];
pub const DEFAULT_DAILY_LIMIT_CENTS: u32 = 10;

/// One Test per this gap, the PUT's included.
pub const TEST_GAP: Duration = Duration::from_secs(10);
/// A passed Test is reused this long, so the Turn on that follows it does not pay again.
pub const TEST_REUSE: Duration = Duration::from_secs(600);
/// Models whose last Test is remembered for the picker.
const TESTED_CAP: usize = 64;
const MAX_MODEL_ID: usize = 128;
/// The ceiling per million tokens when a model's price is unknown.
const UNKNOWN_PRICE_PER_MILLION: f64 = 1.0;

/// The fixed, public example the Test sends: no household data.
pub const TEST_WEBSITE: &str = "www.wikipedia.org";
pub const TEST_CANDIDATE: &str = "www.googletagmanager.com";
pub const TEST_CONTEXT: [&str; 2] = ["upload.wikimedia.org", "login.wikimedia.org"];

const NOT_A_MODEL: &str = "That is not an OpenRouter model id.";
const NOT_LISTED: &str = "That model is not one of OpenRouter's decision models.";
const NO_ZERO_RETENTION: &str = "No zero-retention provider runs that model; pick another, or set \
                                 COGWHEEL_AI__ZERO_RETENTION=false.";
const NOT_A_KEY: &str = "That does not look like an OpenRouter key.";
const NOT_A_LIMIT: &str = "Choose a daily limit of 5¢, 10¢, 25¢ or $1.";
const ENVIRONMENT_KEY: &str = "The OpenRouter key is set in the environment \
                               (COGWHEEL_AI__OPENROUTER_API_KEY); change it there.";
const ADD_A_KEY: &str = "Add an OpenRouter key before turning AI review on.";
const PICK_A_MODEL: &str = "Pick a model before turning AI review on.";
const TEST_NO_KEY: &str = "Add an OpenRouter key first.";
const TEST_NO_MODEL: &str = "Pick a model first.";
const TEST_MODEL_GONE: &str = "OpenRouter would not run this model: no provider meets the privacy \
                               and price limits, or the model is gone. Pick another, or set \
                               COGWHEEL_AI__ZERO_RETENTION=false.";
const CANNOT_ANSWER: &str = "That model cannot answer Cogwheel's questions; pick another.";
const UNRATED: &str = "That model does not say how sure it is; pick another.";
const SLOW_DOWN: &str = "OpenRouter is rate-limiting this key; try again in a minute.";
const NO_ANSWER: &str = "OpenRouter did not answer; try again in a minute.";
const NO_MODEL_LIST: &str = "OpenRouter's model list could not be fetched; try again in a minute.";
const NO_EFFECT_CONFIDENCE: &str = " It does not say how sure it is about whether a site breaks, \
                                    so it can block names but will never override your lists.";

// --------------------------------------------------------------------- the settings keys

/// The AI settings as stored, mirrored in memory.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub model: Option<String>,
    pub model_price: Option<f64>,
    pub daily_limit_cents: u32,
}

impl Settings {
    /// Read the settings keys. A value the API could not have written reads as unset.
    pub async fn load(storage: &Storage) -> Result<Self, StorageError> {
        let enabled = storage.setting(AI_ENABLED).await?.as_deref() == Some("1");
        let model = storage
            .setting(AI_MODEL)
            .await?
            .filter(|model| model_shaped(model));
        let model_price = storage
            .setting(AI_MODEL_PRICE)
            .await?
            .and_then(|price| price.parse::<f64>().ok())
            .filter(|price| price.is_finite() && *price >= 0.0);
        let daily_limit_cents = storage
            .setting(AI_DAILY_LIMIT)
            .await?
            .and_then(|limit| limit.parse::<f64>().ok())
            .and_then(cents)
            .unwrap_or(DEFAULT_DAILY_LIMIT_CENTS);
        Ok(Self {
            enabled,
            model,
            model_price,
            daily_limit_cents,
        })
    }
}

/// D13: AI review is unavailable at this boot, so consent is forgotten and must be given again
/// through the Turn on dialog. `HISTORY_DAYS=0` also empties the AI list. The model and the key
/// file are kept: they are not history.
pub async fn forget_consent(config: &AppConfig, storage: &Storage) -> Result<(), StorageError> {
    let was_enabled = storage.setting(AI_ENABLED).await?.is_some();
    storage.set_setting(AI_ENABLED, None).await?;
    if config.history_days == 0 {
        let cleared = storage.clear_ai_verdicts().await?;
        tracing::info!(
            cleared,
            "COGWHEEL_RETENTION__HISTORY_DAYS is 0: the AI list was cleared, AI review is \
             unavailable, and it stays off until it is turned on again"
        );
    } else if was_enabled {
        tracing::info!(
            "COGWHEEL_AI__AVAILABLE is false: AI review is unavailable, and it stays off until \
             it is turned on again"
        );
    }
    Ok(())
}

/// Whether `id` is shaped like an OpenRouter model id:
/// `^~?[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._:-]*$`, at most 128 characters.
pub fn model_shaped(id: &str) -> bool {
    if id.len() > MAX_MODEL_ID {
        return false;
    }
    let id = id.strip_prefix('~').unwrap_or(id);
    let Some((vendor, name)) = id.split_once('/') else {
        return false;
    };
    let starts = |part: &str| {
        part.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    };
    let made_of = |part: &str, extra: &[u8]| {
        part.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"._-".contains(&byte)
                || extra.contains(&byte)
        })
    };
    starts(vendor) && made_of(vendor, b"") && starts(name) && made_of(name, b":")
}

/// A daily limit in USD as one of the presets, in cents.
fn cents(usd: f64) -> Option<u32> {
    let hundredths = usd * 100.0;
    if !hundredths.is_finite() || (hundredths - hundredths.round()).abs() > 1e-6 {
        return None;
    }
    DAILY_LIMITS_CENTS
        .into_iter()
        .find(|preset| (f64::from(*preset) - hundredths).abs() < 0.5)
}

/// The stored spelling of a limit: `0.05`, `0.10`, `0.25`, `1.00`.
fn spell_cents(cents: u32) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

// --------------------------------------------------------------------- spend (§6.13)

/// What one settlement adds to today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cost {
    pub micro_usd: u64,
    pub requests: u32,
    pub overrides: u32,
}

impl Cost {
    /// One request that cost `micro_usd`.
    pub const fn request(micro_usd: u64) -> Self {
        Self {
            micro_usd,
            requests: 1,
            overrides: 0,
        }
    }
}

/// Today's spend, as `ai_spend` stores it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spend {
    /// Days since the epoch, UTC.
    pub day: u32,
    pub micro_usd: u64,
    pub requests: u32,
    pub overrides: u32,
}

impl Spend {
    /// Read the stored string; anything else is a fresh day 0, which the next roll-over resets.
    pub fn decode(text: Option<&str>) -> Self {
        let mut fields = text.unwrap_or_default().split_ascii_whitespace();
        let mut next = || fields.next().and_then(|field| field.parse::<u64>().ok());
        match (next(), next(), next(), next()) {
            (Some(day), Some(micro_usd), Some(requests), Some(overrides)) => Self {
                day: u32::try_from(day).unwrap_or(0),
                micro_usd,
                requests: u32::try_from(requests).unwrap_or(u32::MAX),
                overrides: u32::try_from(overrides).unwrap_or(u32::MAX),
            },
            _ => Self::default(),
        }
    }

    /// The stored string.
    pub fn encode(&self) -> String {
        format!(
            "{} {} {} {}",
            self.day, self.micro_usd, self.requests, self.overrides
        )
    }

    /// Start a new day's counts when `today` is not the day these are for.
    pub fn roll_over(&mut self, today: u32) {
        if self.day != today {
            *self = Self {
                day: today,
                ..Self::default()
            };
        }
    }

    pub fn add(&mut self, cost: Cost) {
        self.micro_usd = self.micro_usd.saturating_add(cost.micro_usd);
        self.requests = self.requests.saturating_add(cost.requests);
        self.overrides = self.overrides.saturating_add(cost.overrides);
    }
}

/// The UTC day `now` falls on, in days since the epoch.
pub fn utc_day(now: i64) -> u32 {
    u32::try_from(now.div_euclid(DAY)).unwrap_or(0)
}

pub fn micro_to_usd(micro: u64) -> f64 {
    micro as f64 / 1e6
}

/// USD to micro-USD, rounded up: a fraction of a micro-dollar errs towards stopping.
fn usd_to_micro(usd: f64) -> u64 {
    if usd.is_finite() && usd > 0.0 {
        (usd * 1e6).ceil() as u64
    } else {
        0
    }
}

/// USD per token at the price ceiling: the listed price × 1.25, or $1 per million if unknown.
pub fn ceiling_per_token(price_per_million: Option<f64>) -> f64 {
    price_per_million.map_or(UNKNOWN_PRICE_PER_MILLION, |price| price * 1.25) / 1e6
}

/// What a request is reserved before it is sent: `(body bytes / 3 + 64)` tokens at the ceiling.
pub fn reserve_micro(body_bytes: usize, price_per_million: Option<f64>) -> u64 {
    let tokens = (body_bytes / 3 + 64) as f64;
    usd_to_micro(tokens * ceiling_per_token(price_per_million)).max(1)
}

/// What a 200 is charged: `usage.cost` when it is usable; else the input tokens at the ceiling;
/// else twice the reservation. Never free. The flag is true when it was an estimate.
pub fn charge_micro(usage: Option<&Usage>, reserve: u64, price_per_million: Option<f64>) -> (u64, bool) {
    if let Some(cost) = usage.and_then(|usage| usage.cost) {
        return (usd_to_micro(cost), false);
    }
    if let Some(tokens) = usage.and_then(|usage| usage.input_tokens) {
        let estimate = usd_to_micro(tokens as f64 * ceiling_per_token(price_per_million));
        return (estimate.max(1), true);
    }
    (reserve.saturating_mul(2), true)
}

impl AiState {
    /// §6.13: the only writer of `ai_spend`; `rows` may be empty. Holds the lock across the write,
    /// so two settlements (the reviewer's and a Test's) persist in the order they were made and an
    /// older figure can never overwrite a newer one.
    ///
    /// # Errors
    ///
    /// The write failed. The in-memory spend stays raised, which errs towards stopping.
    pub async fn settle(
        &self,
        storage: &Storage,
        cost: Cost,
        rows: Vec<AiVerdict>,
    ) -> Result<(), StorageError> {
        let mut spend = self.spend.lock().await;
        spend.roll_over(utc_day(now_secs()));
        spend.add(cost);
        // Mirrored before the write, so admission sees it even if the write fails.
        self.spent_micro.store(spend.micro_usd, Ordering::Release);
        self.requests_today.store(spend.requests, Ordering::Release);
        self.overrides_today.store(spend.overrides, Ordering::Release);
        self.spend_day.store(spend.day, Ordering::Release);
        let result = storage.record_ai_verdicts(rows, spend.encode()).await;
        if let Err(error) = &result {
            tracing::warn!(%error, "recording AI review spend failed; it stays counted in memory");
        }
        result
    }

    /// Today's spend in micro-USD, requests and overrides, read without the lock.
    pub fn today(&self, now: i64) -> Cost {
        if self.spend_day.load(Ordering::Acquire) != utc_day(now) {
            return Cost::default();
        }
        Cost {
            micro_usd: self.spent_micro.load(Ordering::Acquire),
            requests: self.requests_today.load(Ordering::Acquire),
            overrides: self.overrides_today.load(Ordering::Acquire),
        }
    }
}

// --------------------------------------------------------------------- route 24

/// `PUT /api/v1/ai`. Every field is optional; for `key`, absent keeps it, `null` removes it and a
/// string replaces it. No `Debug` derive: the key must never reach a format string.
#[derive(Default, Deserialize)]
pub struct AiPatch {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub key: Option<Option<String>>,
    #[serde(default)]
    pub daily_limit_usd: Option<f64>,
}

impl std::fmt::Debug for AiPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiPatch")
            .field("enabled", &self.enabled)
            .field("model", &self.model)
            .field("key", &self.key.as_ref().map(|key| key.as_ref().map(|_| "..")))
            .field("daily_limit_usd", &self.daily_limit_usd)
            .finish()
    }
}

/// `POST /api/v1/ai/test`: staged values that fall back to the saved ones.
#[derive(Default, Deserialize)]
pub struct AiTestInput {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

impl std::fmt::Debug for AiTestInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiTestInput")
            .field("model", &self.model)
            .field("key", &self.key.as_ref().map(|_| ".."))
            .finish()
    }
}

/// Absent, `null` and a value are three different things for `key`: `None`, `Some(None)` and
/// `Some(Some(value))`.
pub fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Route 24, steps 1–8. The handler answers with the status afterwards.
///
/// # Errors
///
/// The 400/409/429/503 of route 24's tables, a failing Test's own status and sentence, or a 500
/// when the database or the key file could not be written.
pub async fn apply_patch(state: &ServerState, patch: AiPatch) -> Result<(), ApiError> {
    let ai = &state.ai;
    let _writes = ai.writes.lock().await;

    // 1. Refusals that depend on the body. Removing a saved key is never refused.
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
    if patch.key.is_some() && saved.as_ref().is_some_and(|slot| slot.source == KeySource::Environment)
    {
        return Err(ApiError::conflict(ENVIRONMENT_KEY));
    }

    // 2. Shapes.
    if patch.model.as_deref().is_some_and(|model| !model_shaped(model)) {
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
    let key = new_key
        .clone()
        .or_else(|| (!removing).then(|| saved.as_ref().map(|slot| slot.key.clone())).flatten());
    if patch.enabled == Some(true) && key.is_none() {
        return Err(ApiError::conflict(ADD_A_KEY));
    }
    if patch.enabled == Some(true) && model.is_none() {
        return Err(ApiError::conflict(PICK_A_MODEL));
    }

    // 3. A new model must be one OpenRouter lists, if the list can be fetched; record its price.
    let model_changed = patch.model.is_some() && patch.model != current.model;
    let mut price = current.model_price;
    if model_changed && let Some(id) = &patch.model {
        price = None;
        if let Ok(list) = model_list(state).await {
            let listed = list.get(id).ok_or_else(|| ApiError::bad_request(NOT_LISTED))?;
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

    // 5. The Test, when review will be on and what it was consented for changed.
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

    // 6. Withdraw consent, or change its subject, before anything is written.
    let was_reviewing = matches!(lock(&ai.machine).state, State::Reviewing | State::Retrying);
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
    let written = persist(state, &current, &next, new_key, removing, key_info).await;
    if let Err(error) = written {
        // A change that was going to resume review resumes it on what is still in force.
        if matches!(halt, Some(Halt::KeyChanged | Halt::ModelChanged)) {
            ai.resume();
        }
        return Err(error);
    }

    // 8. Install (or withdraw) the AI list, then reopen the gate on a new generation.
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
    key_info: Option<client::KeyInfo>,
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
        // Out of memory first: review has already halted, and nothing may use it again.
        ai.replace_key(None);
        if let Some(path) = ai.key_path.clone() {
            blocking(move || key::remove(&path)).await.map_err(|error| {
                tracing::error!(%error, "could not remove the saved OpenRouter key");
                ApiError::internal("The OpenRouter key could not be removed from the data directory.")
            })?;
        }
    } else if let Some(key) = new_key {
        if let Some(path) = ai.key_path.clone() {
            let saved = key.clone();
            blocking(move || key::store(&path, &saved)).await.map_err(|error| {
                tracing::error!(%error, "could not save the OpenRouter key");
                ApiError::internal("The OpenRouter key could not be saved in the data directory.")
            })?;
        }
        ai.replace_key(Some(key));
        if let Some(info) = key_info {
            ai.set_key_info(info);
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

/// Route 24's key-check table.
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
    fn recently_passed(&self, key: &SecretKey, model: &str) -> bool {
        lock(&self.passed).as_ref().is_some_and(|passed| {
            passed.key == key.fingerprint()
                && passed.model == model
                && passed.at.elapsed() < TEST_REUSE
        })
    }

    /// Remember the last Test of `model` for the picker.
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

// --------------------------------------------------------------------- route 26

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
pub async fn run_test(state: &ServerState, staged: AiTestInput) -> Result<AiTestResult, ApiError> {
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
        Some(model) if model_shaped(&model) => model,
        Some(_) => return Err(ApiError::bad_request(NOT_A_MODEL)),
        None => current
            .model
            .clone()
            .ok_or_else(|| ApiError::conflict(TEST_NO_MODEL))?,
    };
    let price = if current.model.as_deref() == Some(model.as_str()) {
        current.model_price
    } else {
        model_list(state)
            .await
            .ok()
            .and_then(|list| list.get(&model).and_then(|listed| listed.prompt_usd_per_million))
    };
    let result = test_once(state, &key, &model, price).await?;

    let in_force = saved.is_some_and(|slot| slot.key == key)
        && current.model.as_deref() == Some(model.as_str());
    let terminal = matches!(
        lock(&ai.machine).state,
        State::KeyRefused | State::OutOfCredit | State::ModelRefused
    );
    if in_force && terminal && ai.applying() {
        ai.resume();
    }
    Ok(result)
}

/// One Test request, without the writes lock (the PUT holds it already).
async fn test_once(
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
    let sent = client::decide(ai.client(), &ai.base, key, body).await;
    let latency = started.elapsed();
    let reply = match sent {
        Ok(reply) => reply,
        Err(failure) => {
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
        .settle(&state.storage, Cost::request(micro), Vec::new())
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
    let verdict = match answer.choice {
        Choice::Block => format!("{TEST_CANDIDATE} is not needed by {TEST_WEBSITE}"),
        Choice::Allow => format!("{TEST_CANDIDATE} is part of what {TEST_WEBSITE} needs"),
        Choice::Ignore => {
            format!("it could not tell what {TEST_CANDIDATE} does for {TEST_WEBSITE}")
        }
    };
    let through = parsed
        .provider
        .as_deref()
        .map(|provider| format!(" through {provider}"))
        .unwrap_or_default();
    let mut sentence = format!(
        "{name} answered in {seconds:.1} s{through}: {verdict} (the model was {percent:.0}% \
         sure). The test cost {cost}.",
        name = ai.display_name(model),
        seconds = latency.as_secs_f64(),
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

/// A cost the way the Test sentence says it: to the first significant digit under a cent.
fn dollars(usd: f64) -> String {
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

// --------------------------------------------------------------------- route 25

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
    let list = client::models(ai.client(), &ai.base, now_secs())
        .await
        .map(Arc::new)
        .ok_or_else(|| ApiError::unavailable(NO_MODEL_LIST))?;
    ai.models.set(Arc::clone(&list));
    *write(&ai.last_models) = Some(Arc::clone(&list));
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
    pub zero_retention: Option<bool>,
    /// `"passed"`, `"failed"`, or `None` if never tested since boot.
    pub tested: Option<&'static str>,
}

impl AiState {
    /// The picker's view of `list`: each model marked by its last Test. The saved model of an
    /// enabled configuration reads passed, because enabling required a pass.
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
                        usd_per_thousand_names: model
                            .prompt_usd_per_million
                            .map(|price| client::round_price(price * 0.5)),
                        zero_retention: model.zero_retention,
                        tested: tested.map(|passed| if passed { "passed" } else { "failed" }),
                    }
                })
                .collect(),
        }
    }

    /// A model's name for a sentence: the listed name without its vendor ("Jev 1.13"), or the id.
    fn display_name(&self, id: &str) -> String {
        read(&self.last_models)
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
