//! AI review's settings: the `settings` keys and their in-memory mirror, and the request types
//! of `PUT /api/v1/ai` (route 24) and the Test (route 26).
//!
//! The writes themselves are in `patch.rs` and `test_run.rs`; today's spend, the one key written
//! from elsewhere, is `spend.rs`'s. Neither request type derives `Debug`: each can carry the key,
//! and a derived `Debug` would print it into any format string it reached.

use crate::config::AppConfig;
use cogwheel_storage::{Storage, StorageError};
use serde::{Deserialize, Deserializer};

/// `1`, or absent: review is on. Deleted at boot whenever review is unavailable (D13).
pub const AI_ENABLED: &str = "ai_enabled";
/// The model id the household picked.
pub const AI_MODEL: &str = "ai_model";
/// USD per million prompt tokens, as listed when the model was picked; absent if unknown.
pub const AI_MODEL_PRICE: &str = "ai_model_price";
/// `0.05`, `0.10`, `0.25` or `1.00`; absent means `0.10`.
pub const AI_DAILY_LIMIT: &str = "ai_daily_limit";
/// `"<utc day> <micro-USD> <requests> <overrides>"`, written only by `AiState::settle`.
pub const AI_SPEND: &str = "ai_spend";

/// The daily limits on offer, in cents. 10¢ unless the household picked another.
pub const DAILY_LIMITS_CENTS: [u32; 4] = [5, 10, 25, 100];
pub const DEFAULT_DAILY_LIMIT_CENTS: u32 = 10;

/// The longest model id accepted.
const MAX_MODEL_ID: usize = 128;

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
    ///
    /// # Errors
    ///
    /// The database could not be read.
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
///
/// # Errors
///
/// The database could not be written.
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

/// A daily limit in USD as one of the presets, in cents; `None` for anything else.
pub fn cents(usd: f64) -> Option<u32> {
    let hundredths = usd * 100.0;
    if !hundredths.is_finite() || (hundredths - hundredths.round()).abs() > 1e-6 {
        return None;
    }
    DAILY_LIMITS_CENTS
        .into_iter()
        .find(|preset| (f64::from(*preset) - hundredths).abs() < 0.5)
}

/// The stored spelling of a limit: `0.05`, `0.10`, `0.25`, `1.00`.
pub fn spell_cents(cents: u32) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

// --------------------------------------------------------------------- the request types

/// `PUT /api/v1/ai`. Every field is optional; for `key`, absent keeps it, `null` removes it and a
/// string replaces it.
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
            .field(
                "key",
                &self.key.as_ref().map(|key| key.as_ref().map(|_| "..")),
            )
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
/// `Some(Some(value))`. Absent never reaches this (`#[serde(default)]` covers it).
///
/// # Errors
///
/// The value is neither `null` nor a `T`.
pub fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
