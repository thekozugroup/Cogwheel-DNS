//! AI review and the AI list (ADR 0002).
//!
//! A decision model on OpenRouter judges the names a household's websites load, and its verdicts
//! are compiled into the policy as the AI list. The model is never on the DNS path: the query-log
//! writer offers what has already been answered through a tap that drops rather than waits, a
//! reviewer task groups that into site loads and asks about each name once, and the answers are
//! stored rows that the next policy build compiles. Off by default; and off at once (D18): one
//! send gate, closed synchronously by [`AiState::halt`] before the write that withdraws consent
//! returns.
//!
//! This module is the state all of that shares: the gate and its generation, the state machine,
//! the settings and the key, today's spend, and the `known` map of names already judged.

// The AI routes (`api/ai.rs`) land after this, and they are what call most of what is left, through
// the re-exports below. Expected rather than allowed, so this goes the moment nothing is unused.
#![cfg_attr(
    not(test),
    expect(dead_code, unused_imports, reason = "the AI routes land next")
)]
#![cfg_attr(
    test,
    allow(dead_code, unused_imports, reason = "the AI routes land next")
)]

pub mod burst;
pub mod client;
mod gate;
pub mod install;
pub mod key;
mod known;
mod models;
mod patch;
pub mod prompt;
pub mod review;
pub mod settings;
pub mod site;
mod spend;
mod status;
mod test_run;
#[cfg(test)]
mod tests;
pub mod verdict;
pub mod worker;

use gate::Machine;
pub use gate::{AliveGuard, Halt};
pub use known::Known;
pub use models::{ModelView, ModelsView, model_list};
pub use patch::apply_patch;
pub use settings::{AiPatch, AiTestInput};
pub use spend::Cost;
pub use status::{AiOverview, AiSettingsView, AiStatus};
pub use test_run::{AiTestResult, run_test};

use crate::config::AppConfig;
use crate::state::{Cached, ServerState, lock, read};
use anyhow::Context as _;
use client::{KeyInfo, ModelList};
use cogwheel_dns_core::LogEntry;
use cogwheel_policy::{ListIndex, Policy, Reason};
use cogwheel_storage::Storage;
use key::SecretKey;
use serde::Serialize;
use settings::Settings;
use spend::Spend;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use url::Url;

/// `Seen` entries the tap holds before it drops (and counts) rather than wait.
pub const TAP_DEPTH: usize = 4_096;

/// The most names the `known` map holds: the 10,000-row table plus a day's 2,000 requests.
pub const KNOWN_CAP: usize = 12_000;

/// Seconds per day.
pub const DAY: i64 = 86_400;

/// How long the model list is reused before it is fetched again (route 25).
pub const MODEL_LIST_TTL: Duration = Duration::from_secs(3_600);

// The `last_error` sentences (route 23). A later success clears one, except a terminal state's,
// which stays until the state ends.
pub const KEY_REFUSED: &str = "OpenRouter refused the key.";
pub const OUT_OF_CREDIT: &str = "The OpenRouter account or this key is out of credit.";
pub const MODEL_GONE: &str = "OpenRouter would not run this model: no provider meets the privacy \
                              and price limits, or the model is gone.";
pub const MODEL_UNREADABLE: &str =
    "The model's answers could not be read three times in a row; pick another.";
pub const MODEL_UNRATED: &str =
    "The model answered three times without saying how sure it was; pick another.";
pub const REDIRECTED: &str =
    "OpenRouter redirected the request; Cogwheel never follows a redirect with your key.";
pub const RATE_LIMITED: &str = "OpenRouter is rate-limiting this key; retrying.";
pub const NO_ANSWER: &str = "OpenRouter did not answer; retrying.";
pub const STOPPED: &str = "AI review hit an internal error and stopped; restart the appliance.";
pub const KEY_FILE_UNREADABLE: &str = "The saved OpenRouter key could not be read; add it again.";

// --------------------------------------------------------------------- the tap

/// One answered lookup, as the reviewer sees it: integers and a refcounted name.
#[derive(Debug, Clone)]
pub struct Seen {
    pub ts: u32,
    pub client: IpAddr,
    pub domain: Arc<str>,
    pub blocked: bool,
    pub reason: Reason,
}

/// Offer one log entry to the reviewer. Integers first, then one refcount bump; never waits (a
/// full channel drops and counts).
///
/// Only A, AAAA and HTTPS lookups, and only names the lists or the AI list decided: never a rule's
/// name, a protected one, a paused or unfiltered device's, a CNAME-decided one, or PTR/TXT/SRV/MX.
pub fn offer(tap: &mpsc::Sender<Seen>, entry: &LogEntry, ai: &AiState) {
    if !matches!(entry.qtype, 1 | 28 | 65) {
        return;
    }
    let reason = entry.verdict.reason();
    if !matches!(
        reason,
        Reason::NoMatch | Reason::ListAllow | Reason::List | Reason::Ai
    ) {
        return;
    }
    let seen = Seen {
        ts: entry.ts,
        client: entry.client,
        domain: Arc::clone(&entry.domain),
        blocked: entry.verdict.is_blocked(),
        reason,
    };
    if tap.try_send(seen).is_err() {
        ai.counters.tap_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// --------------------------------------------------------------------- states

/// What AI review is doing, as route 23 reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Unavailable,
    Off,
    NoKey,
    Reviewing,
    PausedBudget,
    Retrying,
    KeyRefused,
    OutOfCredit,
    ModelRefused,
    Stopped,
}

/// Why AI review cannot run on this appliance at all. Fixed at boot: both come from the
/// environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
    /// `COGWHEEL_AI__AVAILABLE=false`.
    OperatorOff,
    /// `COGWHEEL_RETENTION__HISTORY_DAYS=0`.
    HistoryOff,
}

impl Unavailable {
    /// The 409 every write that needs AI review answers with.
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::OperatorOff => {
                "AI review is switched off on this appliance by COGWHEEL_AI__AVAILABLE."
            }
            Self::HistoryOff => {
                "AI review needs the activity log: COGWHEEL_RETENTION__HISTORY_DAYS is 0, which \
                 promises to keep no record of what is looked up, and AI review keeps one and \
                 sends names out. Keep at least one day of history to use it."
            }
        }
    }
}

/// What the household's lists do with a name, under a mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListState {
    Nothing,
    Block,
    Exception,
}

impl ListState {
    /// An exception under `mask` wins over a block, as it does in `evaluate`. `name` must be
    /// normalised.
    pub fn of(index: &ListIndex, mask: u64, name: &str) -> Self {
        let masks = index.lookup(name);
        if masks.allow & mask != 0 {
            Self::Exception
        } else if masks.block & mask != 0 {
            Self::Block
        } else {
            Self::Nothing
        }
    }

    /// The stored spelling (`ai_verdicts.lists`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nothing => "nothing",
            Self::Block => "block",
            Self::Exception => "exception",
        }
    }

    /// The stored spelling back; `None` for anything the schema would have refused.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "nothing" => Some(Self::Nothing),
            "block" => Some(Self::Block),
            "exception" => Some(Self::Exception),
            _ => None,
        }
    }
}

/// The household's lists on `name` under the live policy: its index and every enabled slot.
pub fn list_state(policy: &Policy, name: &str) -> ListState {
    ListState::of(&policy.index, policy.all_mask, name)
}

// --------------------------------------------------------------------- the shared state

/// Counts the reviewer, the tap and the installer keep, for the status and the DEBUG line.
#[derive(Debug, Default)]
pub struct AiCounters {
    /// Lookups the tap dropped because the reviewer was behind.
    pub tap_dropped: AtomicU64,
    /// AI list installs the installer task completed (§5.3).
    pub installs: AtomicU64,
    /// Jobs waiting in the reviewer's queue, as it last reported.
    pub waiting: AtomicU64,
    /// Jobs the full queue dropped, oldest first.
    pub dropped: AtomicU64,
    /// Answers that could not be read.
    pub malformed: AtomicU64,
    /// Responses with no usable `usage.cost`, charged an estimate instead.
    pub unpriced: AtomicU64,
}

/// Where the key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    None,
    Saved,
    Environment,
}

/// The key in force, and a generation that changes whenever it does.
#[derive(Debug, Clone)]
pub struct KeySlot {
    pub key: SecretKey,
    pub source: KeySource,
    pub generation: u64,
}

/// A passed Test, reused for ten minutes so the Turn on that follows it does not pay again. The
/// key is held as its in-process fingerprint, so a staged key that has not been saved yet is
/// recognised when the PUT that saves it arrives.
#[derive(Debug, Clone)]
struct Passed {
    key: u64,
    model: String,
    at: Instant,
}

/// AI review's shared state, one per process, in [`crate::state::ServerState`].
pub struct AiState {
    /// Woken by every commit of verdicts; the installer task rebuilds after a debounce.
    pub install: Notify,
    /// Serialises the writes to the AI settings: `PUT /ai`, a Test's state changes, key saves.
    pub writes: tokio::sync::Mutex<()>,
    pub counters: AiCounters,

    unavailable: Option<Unavailable>,
    history_days: u32,
    zero_retention: bool,
    base: Url,
    key_path: Option<PathBuf>,
    /// The appliance's own names (§6.3 rule 8): never sent.
    own_names: Vec<String>,
    client: reqwest::Client,

    // The send gate (D18).
    tap: mpsc::Sender<Seen>,
    tapping: AtomicBool,
    generation: AtomicU64,
    alive: AtomicBool,
    /// Wakes the reviewer after a halt, a resume or a Clear log, so it empties its queue.
    halted: Notify,
    /// Abort handles of the requests in flight, by job id; `halt` aborts every one.
    inflight: Mutex<HashMap<u64, AbortHandle>>,
    machine: Mutex<Machine>,

    settings: RwLock<Settings>,
    key: RwLock<Option<KeySlot>>,
    key_generations: AtomicU64,
    key_info: Mutex<Option<(KeyInfo, i64)>>,

    // Today's spend (§6.13): owned by `settle`, mirrored for lock-free reads.
    spend: tokio::sync::Mutex<Spend>,
    spent_micro: AtomicU64,
    spend_day: AtomicU32,
    requests_today: AtomicU32,
    overrides_today: AtomicU32,

    tested: Mutex<HashMap<String, bool>>,
    passed: Mutex<Option<Passed>>,
    last_test: Mutex<Option<Instant>>,
    models: Cached<Arc<ModelList>>,
    /// The last list fetched, however old, for the model's display name.
    last_models: RwLock<Option<Arc<ModelList>>>,
    models_fetch: tokio::sync::Mutex<()>,

    known: Mutex<HashMap<Arc<str>, Known>>,
    /// Bumped by Clear log: an answer in flight under an older one is stored with no site.
    sites_epoch: AtomicU64,
    last_review_at: AtomicI64,
}

impl std::fmt::Debug for AiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiState")
            .field("state", &self.state())
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl AiState {
    /// Builds the OpenRouter client (D19), and loads the settings, today's spend, the key and the
    /// known map. Whenever AI review is unavailable it deletes `ai_enabled` first, so review never
    /// resumes without a fresh Turn on, and `HISTORY_DAYS=0` empties the AI list (D13). `main`
    /// calls it before the boot rebuild, so that rebuild already sees the result.
    ///
    /// # Errors
    ///
    /// The client cannot be built, or the database cannot be read or written.
    pub async fn load(
        config: &AppConfig,
        storage: &Storage,
    ) -> anyhow::Result<(Arc<Self>, mpsc::Receiver<Seen>)> {
        let client =
            client::build(&config.ai_base_url, None).context("build the OpenRouter client")?;
        let unavailable = if !config.ai_available {
            Some(Unavailable::OperatorOff)
        } else if config.history_days == 0 {
            Some(Unavailable::HistoryOff)
        } else {
            None
        };
        if unavailable.is_some() {
            settings::forget_consent(config, storage)
                .await
                .context("forget AI review's consent")?;
        }
        let settings = Settings::load(storage)
            .await
            .context("read AI review's settings")?;
        let spend = Spend::decode(
            storage
                .setting(settings::AI_SPEND)
                .await
                .context("read AI review's spend")?
                .as_deref(),
        );

        let key_path = key::key_path(config);
        let (slot, key_error) = match (&config.ai_api_key, &key_path) {
            (Some(key), _) => (Some((key.clone(), KeySource::Environment)), None),
            (None, Some(path)) => {
                let path = path.clone();
                match tokio::task::spawn_blocking(move || key::load(&path))
                    .await
                    .unwrap_or(key::Saved::Unreadable)
                {
                    key::Saved::Key(key) => (Some((key, KeySource::Saved)), None),
                    key::Saved::Missing => (None, None),
                    key::Saved::Unreadable => (None, Some(KEY_FILE_UNREADABLE)),
                }
            }
            (None, None) => (None, None),
        };

        let known = storage
            .list_ai_verdicts()
            .await
            .context("read the AI list")?
            .iter()
            .map(|row| (Arc::from(row.domain.as_str()), Known::of(row)))
            .collect();

        let ready = unavailable.is_none() && settings.enabled && settings.model.is_some();
        let state = match (ready, slot.is_some()) {
            (_, false) => State::NoKey,
            (true, true) => State::Reviewing,
            (false, true) => State::Off,
        };
        let own_names = config
            .allowed_hosts
            .iter()
            .chain(&config.advertised_dns_targets)
            .filter(|name| name.parse::<IpAddr>().is_err())
            .map(|name| cogwheel_policy::normalize_domain(name))
            .collect();

        let (tap, tap_rx) = mpsc::channel(TAP_DEPTH);
        let ai = Self {
            install: Notify::new(),
            writes: tokio::sync::Mutex::new(()),
            counters: AiCounters::default(),
            unavailable,
            history_days: config.history_days,
            zero_retention: config.ai_zero_retention,
            base: config.ai_base_url.clone(),
            key_path,
            own_names,
            client,
            tap,
            tapping: AtomicBool::new(false),
            generation: AtomicU64::new(1),
            alive: AtomicBool::new(false),
            halted: Notify::new(),
            inflight: Mutex::new(HashMap::new()),
            machine: Mutex::new(Machine {
                state,
                last_error: key_error,
            }),
            settings: RwLock::new(settings),
            key: RwLock::new(slot.map(|(key, source)| KeySlot {
                key,
                source,
                generation: 1,
            })),
            key_generations: AtomicU64::new(1),
            key_info: Mutex::new(None),
            spent_micro: AtomicU64::new(spend.micro_usd),
            spend_day: AtomicU32::new(spend.day),
            requests_today: AtomicU32::new(spend.requests),
            overrides_today: AtomicU32::new(spend.overrides),
            spend: tokio::sync::Mutex::new(spend),
            tested: Mutex::new(HashMap::new()),
            passed: Mutex::new(None),
            last_test: Mutex::new(None),
            models: Cached::new(MODEL_LIST_TTL),
            last_models: RwLock::new(None),
            models_fetch: tokio::sync::Mutex::new(()),
            known: Mutex::new(known),
            sites_epoch: AtomicU64::new(0),
            last_review_at: AtomicI64::new(0),
        };
        Ok((Arc::new(ai), tap_rx))
    }

    /// Whether the AI list applies: available, and enabled. A missing key does not stop stored
    /// verdicts applying; it only stops new ones being asked for.
    pub fn applying(&self) -> bool {
        self.unavailable.is_none() && read(&self.settings).enabled
    }

    /// The tap, or `None` unless reviewing. One atomic load: the writer calls this once per
    /// batch, so a feature that is off costs one load per 500 lookups.
    pub fn tap(&self) -> Option<&mpsc::Sender<Seen>> {
        self.tapping.load(Ordering::Acquire).then_some(&self.tap)
    }

    // ----------------------------------------------------------------- what the reviewer reads

    /// The only client that talks to OpenRouter.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Where OpenRouter is (`COGWHEEL_AI__BASE_URL`).
    pub fn base(&self) -> &Url {
        &self.base
    }

    /// Why AI review cannot run here, if it cannot.
    pub fn unavailable(&self) -> Option<Unavailable> {
        self.unavailable
    }

    /// The appliance's own names, normalised: never sent (§6.3 rule 8).
    pub fn own_names(&self) -> &[String] {
        &self.own_names
    }

    /// The key in force, if any.
    pub fn key(&self) -> Option<KeySlot> {
        read(&self.key).clone()
    }

    /// The model in force and its listed price, if one is picked.
    pub fn model(&self) -> Option<(String, Option<f64>)> {
        let settings = read(&self.settings);
        settings
            .model
            .clone()
            .map(|model| (model, settings.model_price))
    }

    /// Today's spend limit, in micro-USD.
    pub fn daily_limit_micro(&self) -> u64 {
        u64::from(read(&self.settings).daily_limit_cents) * 10_000
    }

    /// Whether to ask for zero-retention providers only.
    pub const fn zero_retention(&self) -> bool {
        self.zero_retention
    }

    /// `COGWHEEL_RETENTION__HISTORY_DAYS`, for an ordinary ignore's `review_after`.
    pub const fn history_days(&self) -> u32 {
        self.history_days
    }

    /// Record a fresh `GET /api/v1/key` answer for the status.
    pub fn set_key_info(&self, info: KeyInfo, now: i64) {
        *lock(&self.key_info) = Some((info, now));
    }

    /// Wake the installer: verdicts were committed.
    pub fn notify_install(&self) {
        self.install.notify_one();
    }
}

/// Start AI review's background tasks: the installer, and the reviewer. Detached, the way the
/// prune is: neither is in `main`'s `select!`, so neither can take DNS down. `main` calls this
/// only when AI review is available and the activity log is kept.
pub fn spawn(state: &ServerState, tap_rx: mpsc::Receiver<Seen>) {
    tokio::spawn(install::task(state.clone()));
    tokio::spawn(worker::task(state.clone(), tap_rx));
}
