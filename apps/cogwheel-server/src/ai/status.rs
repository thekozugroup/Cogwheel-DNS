//! What the routes read about AI review: the status (route 23), the Overview's line and Settings'
//! read-only card. None of it contains any part of the key, and all of it comes from memory
//! except the row counts route 23's caller reads from storage.

use super::spend::{micro_to_usd, utc_day};
use super::{AiState, DAY, KeySource, State, Unavailable};
use crate::state::{lock, now_secs, read};
use cogwheel_policy::Policy;
use cogwheel_storage::AiCounts;
use serde::Serialize;
use std::sync::atomic::{AtomicU32, Ordering};

impl AiState {
    /// Route 23: `GET /api/v1/ai`.
    pub fn status(&self, policy: &Policy, counts: AiCounts) -> AiStatus {
        let settings = read(&self.settings).clone();
        let checked = *lock(&self.key_info);
        let today = utc_day(now_secs());
        // A spend from an earlier day has rolled over, even if nothing has settled since.
        let current = self.spend_day.load(Ordering::Acquire) == today;
        let counted = |value: &AtomicU32| {
            if current {
                value.load(Ordering::Acquire)
            } else {
                0
            }
        };
        let names = read(&self.last_models).clone();
        AiStatus {
            available: self.unavailable.is_none(),
            unavailable_reason: self.unavailable,
            enabled: settings.enabled && self.unavailable.is_none(),
            state: self.state(),
            key: KeyStatus {
                source: self.key_source(),
                limit_usd: checked.and_then(|(info, _)| info.limit),
                limit_remaining_usd: checked.and_then(|(info, _)| info.limit_remaining),
                checked_at: checked.map(|(_, at)| at),
            },
            model: settings.model.as_ref().map(|id| ModelStatus {
                name: names
                    .as_ref()
                    .and_then(|list| list.get(id))
                    .map(|model| model.name.clone()),
                id: id.clone(),
                prompt_usd_per_million: settings.model_price,
            }),
            daily_limit_usd: f64::from(settings.daily_limit_cents) / 100.0,
            today: Today {
                spent_usd: if current {
                    micro_to_usd(self.spent_micro.load(Ordering::Acquire))
                } else {
                    0.0
                },
                requests: counted(&self.requests_today),
                overrides: counted(&self.overrides_today),
                resets_at: (i64::from(today) + 1) * DAY,
            },
            verdicts: VerdictCounts {
                block: counts.block,
                allow: counts.allow,
                ignore: counts.ignore,
                applied_block: policy.ai.blocks(),
                applied_allow: policy.ai.allows(),
            },
            queue: Queue {
                waiting: self.counters.waiting.load(Ordering::Relaxed),
                dropped: self.counters.dropped.load(Ordering::Relaxed),
            },
            zero_retention: self.zero_retention,
            sends_to: self.sends_to(),
            last_review_at: Some(self.last_review_at.load(Ordering::Relaxed)).filter(|at| *at > 0),
            last_error: self.last_error(),
        }
    }

    /// The Overview's line: memory only, because that route is polled every five seconds.
    pub fn overview(&self, policy: &Policy) -> AiOverview {
        AiOverview {
            state: self.state(),
            applying: self.applying(),
            applied_block: policy.ai.blocks(),
            applied_allow: policy.ai.allows(),
        }
    }

    /// Settings' read-only card.
    pub fn settings_view(&self) -> AiSettingsView {
        let settings = read(&self.settings).clone();
        AiSettingsView {
            available: self.unavailable.is_none(),
            unavailable_reason: self.unavailable,
            enabled: settings.enabled && self.unavailable.is_none(),
            key_source: self.key_source(),
            model: settings.model,
            daily_limit_usd: f64::from(settings.daily_limit_cents) / 100.0,
            zero_retention: self.zero_retention,
            base_url: self.base.as_str().trim_end_matches('/').to_owned(),
        }
    }

    /// The last Test of `model` since boot: passed, failed, or never tested.
    pub fn tested(&self, model: &str) -> Option<bool> {
        lock(&self.tested).get(model).copied()
    }

    fn key_source(&self) -> KeySource {
        read(&self.key)
            .as_ref()
            .map_or(KeySource::None, |slot| slot.source)
    }

    /// The host names are sent to, as the card names it.
    fn sends_to(&self) -> String {
        let host = self.base.host_str().unwrap_or_default();
        match self.base.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        }
    }
}

/// Route 23: `GET /api/v1/ai`. Never contains any part of the key.
#[derive(Debug, Clone, Serialize)]
pub struct AiStatus {
    pub available: bool,
    pub unavailable_reason: Option<Unavailable>,
    pub enabled: bool,
    pub state: State,
    pub key: KeyStatus,
    pub model: Option<ModelStatus>,
    pub daily_limit_usd: f64,
    pub today: Today,
    pub verdicts: VerdictCounts,
    pub queue: Queue,
    pub zero_retention: bool,
    /// The host names go to, `openrouter.ai` unless the operator pointed it elsewhere.
    pub sends_to: String,
    pub last_review_at: Option<i64>,
    pub last_error: Option<&'static str>,
}

/// The key's source and limits. No `label`: OpenRouter's is a masked copy of the key (D10).
#[derive(Debug, Clone, Serialize)]
pub struct KeyStatus {
    pub source: KeySource,
    /// `None` until checked; after a check, `None` means the key has no limit of its own.
    pub limit_usd: Option<f64>,
    pub limit_remaining_usd: Option<f64>,
    pub checked_at: Option<i64>,
}

/// The model in force.
#[derive(Debug, Clone, Serialize)]
pub struct ModelStatus {
    pub id: String,
    /// `None` until the model list has been fetched.
    pub name: Option<String>,
    pub prompt_usd_per_million: Option<f64>,
}

/// Today's spend, which resets at 00:00 UTC.
#[derive(Debug, Clone, Serialize)]
pub struct Today {
    pub spent_usd: f64,
    pub requests: u32,
    /// Allows over a list block today, capped at 20.
    pub overrides: u32,
    /// The next 00:00 UTC.
    pub resets_at: i64,
}

/// Rows by verdict, applied or not, and what DNS is actually using.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictCounts {
    pub block: i64,
    pub allow: i64,
    pub ignore: i64,
    pub applied_block: usize,
    pub applied_allow: usize,
}

/// The reviewer's queue, as it last reported.
#[derive(Debug, Clone, Serialize)]
pub struct Queue {
    pub waiting: u64,
    pub dropped: u64,
}

/// The Overview's `ai`.
#[derive(Debug, Clone, Serialize)]
pub struct AiOverview {
    pub state: State,
    pub applying: bool,
    pub applied_block: usize,
    pub applied_allow: usize,
}

/// Settings' `ai`.
#[derive(Debug, Clone, Serialize)]
pub struct AiSettingsView {
    pub available: bool,
    pub unavailable_reason: Option<Unavailable>,
    pub enabled: bool,
    pub key_source: KeySource,
    pub model: Option<String>,
    pub daily_limit_usd: f64,
    pub zero_retention: bool,
    pub base_url: String,
}
