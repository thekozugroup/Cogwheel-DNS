//! Spend (§6.13): pricing a request, what it is charged, and `settle`, the one writer of today's
//! spend.
//!
//! Every figure is micro-USD in a `u64`, so adding never rounds and a day's limit compares
//! exactly. A response is never counted as free: no usable `usage.cost` means an estimate at the
//! price ceiling, and an unreadable answer is charged as well, since OpenRouter billed it.

use super::prompt::Usage;
use super::{AiState, DAY};
use crate::state::now_secs;
use cogwheel_storage::{AiVerdict, Storage, StorageError};
use std::sync::atomic::Ordering;

/// The ceiling per million tokens when a model's price is unknown.
const UNKNOWN_PRICE_PER_MILLION: f64 = 1.0;

/// The `max_price` multiplier: a provider may charge up to a quarter over the listed price.
pub const PRICE_CEILING: f64 = 1.25;

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

/// Today's spend, as `ai_spend` stores it: `"<utc day> <micro-USD> <requests> <overrides>"`.
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

    /// Add one settlement, saturating: a counter that cannot grow errs towards stopping.
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

/// Micro-USD as dollars, for the wire.
pub fn micro_to_usd(micro: u64) -> f64 {
    micro as f64 / 1e6
}

/// USD to micro-USD, rounded up: a fraction of a micro-dollar errs towards stopping.
pub fn usd_to_micro(usd: f64) -> u64 {
    if usd.is_finite() && usd > 0.0 {
        (usd * 1e6).ceil() as u64
    } else {
        0
    }
}

/// USD per token at the price ceiling: the listed price × 1.25, or $1 per million if unknown.
pub fn ceiling_per_token(price_per_million: Option<f64>) -> f64 {
    price_per_million
        .filter(|price| price.is_finite() && *price >= 0.0)
        .map_or(UNKNOWN_PRICE_PER_MILLION, |price| price * PRICE_CEILING)
        / 1e6
}

/// What a request is reserved before it is sent: `(body bytes / 3 + 64)` tokens at the ceiling.
/// Never zero, so a request always counts against the limit while it is in flight.
pub fn reserve_micro(body_bytes: usize, price_per_million: Option<f64>) -> u64 {
    let tokens = (body_bytes / 3 + 64) as f64;
    usd_to_micro(tokens * ceiling_per_token(price_per_million)).max(1)
}

/// What a 200 is charged: `usage.cost` when it is usable; else the input tokens at the ceiling;
/// else twice the reservation. Never free. The flag is true when it was an estimate, which is
/// what `counters.unpriced` counts.
pub fn charge_micro(
    usage: Option<&Usage>,
    reserve: u64,
    price_per_million: Option<f64>,
) -> (u64, bool) {
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
    /// older figure can never overwrite a newer one. The rows share the spend's transaction, so a
    /// crash can neither lose a billed response nor store a verdict that was never paid for.
    ///
    /// # Errors
    ///
    /// The write failed. It is logged here at WARN; the in-memory spend stays raised, which errs
    /// towards stopping.
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
        self.spend_day.store(spend.day, Ordering::Release);
        self.spent_micro.store(spend.micro_usd, Ordering::Release);
        self.requests_today.store(spend.requests, Ordering::Release);
        self.overrides_today
            .store(spend.overrides, Ordering::Release);
        let result = storage.record_ai_verdicts(rows, spend.encode()).await;
        if let Err(error) = &result {
            tracing::warn!(%error, "recording AI review spend failed; it stays counted in memory");
        }
        result
    }

    /// Today's spend in micro-USD, requests and overrides, read without the lock. A figure from
    /// an earlier UTC day reads as nothing: the day has rolled over.
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
