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

// The reviewer task (`worker.rs`, with `burst.rs` and `review.rs`) and the AI routes
// (`api/ai.rs`) land after this foundation, and they are what call most of it. Expected rather
// than allowed, so this goes the moment nothing here is unused.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the AI reviewer task and the AI routes land next")
)]
#![cfg_attr(test, allow(dead_code, reason = "the AI reviewer task and the AI routes land next"))]

pub mod client;
pub mod install;
pub mod key;
pub mod prompt;
pub mod settings;
pub mod site;
pub mod verdict;
#[cfg(test)]
mod tests;

pub use settings::{AiPatch, AiTestInput, AiTestResult, Cost, apply_patch, model_list, run_test};

use crate::config::AppConfig;
use crate::state::{Cached, lock, now_secs, read};
use anyhow::Context as _;
use client::{KeyInfo, ModelList};
use cogwheel_dns_core::LogEntry;
use cogwheel_policy::{Action, ListIndex, Policy, Reason};
use cogwheel_storage::{AiCounts, AiVerdict, Storage};
use key::SecretKey;
use serde::Serialize;
use settings::{Settings, Spend};
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

/// Why the send gate is being closed (D18). Every exit from `reviewing`/`retrying` is one of
/// these, and so is every write that withdraws consent or changes what it was given for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    Off,
    NoKey,
    KeyChanged,
    ModelChanged,
    Budget,
    KeyRefused,
    OutOfCredit,
    ModelRefused,
    Stopped,
}

impl Halt {
    /// The state it leaves review in; `None` keeps the state, for a change the same write
    /// resumes from.
    const fn state(self) -> Option<State> {
        match self {
            Self::Off => Some(State::Off),
            Self::NoKey => Some(State::NoKey),
            Self::KeyChanged | Self::ModelChanged => None,
            Self::Budget => Some(State::PausedBudget),
            Self::KeyRefused => Some(State::KeyRefused),
            Self::OutOfCredit => Some(State::OutOfCredit),
            Self::ModelRefused => Some(State::ModelRefused),
            Self::Stopped => Some(State::Stopped),
        }
    }

    /// The `last_error` it sets, when it is a failure. A 404 is the default `model_refused`.
    const fn sentence(self) -> Option<&'static str> {
        match self {
            Self::KeyRefused => Some(KEY_REFUSED),
            Self::OutOfCredit => Some(OUT_OF_CREDIT),
            Self::ModelRefused => Some(MODEL_GONE),
            Self::Stopped => Some(STOPPED),
            _ => None,
        }
    }
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

// --------------------------------------------------------------------- the known map

/// A name already judged: what the reviewer needs to decide whether it is due again (§6.6).
#[derive(Debug, Clone, PartialEq)]
pub struct Known {
    /// `None` for an ignore of any kind, contested included.
    pub verdict: Option<Action>,
    pub lists: ListState,
    pub judged_at: i64,
    pub review_after: i64,
    /// The site key of the website it was judged for; `None` once Clear log forgot it.
    pub site_key: Option<Box<str>>,
    pub rechecks: u8,
    /// The UTC day of the last cross-site re-check; 0 for none since boot.
    pub last_recheck_day: u32,
}

impl Known {
    /// The entry for a stored row.
    pub fn of(row: &AiVerdict) -> Self {
        Self {
            verdict: match row.verdict.as_str() {
                "block" => Some(Action::Block),
                "allow" => Some(Action::Allow),
                _ => None,
            },
            lists: ListState::parse(&row.lists).unwrap_or(ListState::Nothing),
            judged_at: row.judged_at,
            review_after: row.review_after,
            site_key: row
                .site
                .as_deref()
                .map(|site| Box::from(site::site_key(site))),
            rechecks: u8::try_from(row.rechecks.clamp(0, 2)).unwrap_or(0),
            last_recheck_day: 0,
        }
    }
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

/// The state machine's own value, and the sentence it last set. Behind one lock with the gate, so
/// a halt and a resume can never interleave into an open gate in a halted state.
#[derive(Debug)]
struct Machine {
    state: State,
    last_error: Option<&'static str>,
}

/// A passed Test, reused for ten minutes so the Turn on that follows it does not pay again.
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
    /// Wakes the reviewer after a halt or resume, so it empties its queue for the new generation.
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
    /// resumes without a fresh Turn on, and `HISTORY_DAYS=0` empties the AI list (D13).
    ///
    /// # Errors
    ///
    /// The client cannot be built, or the database cannot be read.
    pub async fn load(
        config: &AppConfig,
        storage: &Storage,
    ) -> anyhow::Result<(Arc<Self>, mpsc::Receiver<Seen>)> {
        let client = client::build(&config.ai_base_url, None)
            .context("build the OpenRouter client")?;
        let unavailable = if !config.ai_available {
            Some(Unavailable::OperatorOff)
        } else if config.history_days == 0 {
            Some(Unavailable::HistoryOff)
        } else {
            None
        };
        if unavailable.is_some() {
            settings::forget_consent(config, storage).await?;
        }
        let settings = Settings::load(storage).await?;
        let spend = Spend::decode(storage.setting(settings::AI_SPEND).await?.as_deref());

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
            .await?
            .iter()
            .map(|row| (Arc::from(row.domain.as_str()), Known::of(row)))
            .collect();

        let ready = unavailable.is_none() && settings.enabled && slot.is_some();
        let state = match (ready, settings.model.is_some()) {
            (true, true) => State::Reviewing,
            _ if slot.is_none() => State::NoKey,
            _ => State::Off,
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
        self.tapping
            .load(Ordering::Acquire)
            .then_some(&self.tap)
    }

    /// D18: close the send gate, bump the generation, abort every request in flight, set the
    /// state, wake the reviewer. Synchronous: once it returns no request starts, and a request
    /// already on the wire is cancelled and its answer discarded.
    pub fn halt(&self, reason: Halt) {
        self.halt_because(reason, reason.sentence());
    }

    /// [`Self::halt`] with a particular `last_error`, for the `model_refused` variants.
    pub fn halt_because(&self, reason: Halt, sentence: Option<&'static str>) {
        let mut machine = lock(&self.machine);
        self.tapping.store(false, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        for (_, job) in lock(&self.inflight).drain() {
            job.abort();
        }
        // A dead reviewer stays `stopped` whatever is written after it: nothing would review.
        if machine.state != State::Stopped
            && let Some(state) = reason.state()
        {
            machine.state = state;
        }
        if sentence.is_some() {
            machine.last_error = sentence;
        }
        drop(machine);
        self.halted.notify_one();
        tracing::info!(?reason, "AI review stopped sending");
    }

    /// Whether a job of `generation` may send now. Every job checks this as the last step before
    /// its request goes out.
    pub fn may_send(&self, generation: u64) -> bool {
        self.tapping.load(Ordering::Acquire) && self.generation.load(Ordering::Acquire) == generation
    }

    /// The current generation: a job carries the one it was queued under.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Start reviewing on a new generation with an empty queue: route 24 step 8, the UTC rollover,
    /// a key change. Ends any terminal state and its sentence. The gate opens only if everything
    /// review needs is present and the reviewer is alive.
    pub fn resume(&self) {
        let mut machine = lock(&self.machine);
        if machine.state == State::Stopped {
            return;
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        machine.state = State::Reviewing;
        machine.last_error = None;
        self.regate(&machine);
        drop(machine);
        self.halted.notify_one();
    }

    /// Open or close the gate to match the state, under the machine lock.
    fn regate(&self, machine: &Machine) {
        let open = self.alive.load(Ordering::Acquire)
            && matches!(machine.state, State::Reviewing | State::Retrying)
            && self.applying()
            && read(&self.key).is_some()
            && read(&self.settings).model.is_some();
        self.tapping.store(open, Ordering::Release);
    }

    /// Mark the reviewer alive for as long as the returned guard is held. The worker future holds
    /// it, so a panic, an abort or a return all drop it, and dropping it closes the gate with
    /// `stopped`: stored verdicts keep applying, and nothing more is sent.
    pub fn reviewer_alive(self: &Arc<Self>) -> AliveGuard {
        self.alive.store(true, Ordering::Release);
        self.regate(&lock(&self.machine));
        AliveGuard(Arc::clone(self))
    }

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

    /// The state route 23 reports: what the environment, the settings and the key allow first,
    /// then the machine.
    pub fn state(&self) -> State {
        if self.unavailable.is_some() {
            State::Unavailable
        } else if !read(&self.settings).enabled {
            State::Off
        } else if read(&self.key).is_none() {
            State::NoKey
        } else {
            lock(&self.machine).state
        }
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
    pub fn set_key_info(&self, info: KeyInfo) {
        *lock(&self.key_info) = Some((info, now_secs()));
    }

    /// Wake the installer: verdicts were committed.
    pub fn notify_install(&self) {
        self.install.notify_one();
    }

    /// The `known` entry for a name.
    pub fn known(&self, domain: &str) -> Option<Known> {
        lock(&self.known).get(domain).cloned()
    }

    /// Record a judged name. Past [`KNOWN_CAP`] the oldest tenth by `judged_at` is evicted, in
    /// one sort: eviction only costs a possible re-judgement, since the row itself stays stored
    /// and compiled.
    pub fn remember(&self, domain: Arc<str>, entry: Known) {
        let mut known = lock(&self.known);
        known.insert(domain, entry);
        if known.len() > KNOWN_CAP {
            let mut ages: Vec<(i64, Arc<str>)> = known
                .iter()
                .map(|(domain, entry)| (entry.judged_at, Arc::clone(domain)))
                .collect();
            ages.sort_unstable_by_key(|(judged_at, _)| *judged_at);
            for (_, domain) in ages.into_iter().take(KNOWN_CAP / 10) {
                known.remove(&domain);
            }
        }
    }

    /// Forget names whose rows were deleted (Forget, Clear log's negatives, the prune).
    pub fn forget_known(&self, domains: &[String]) {
        let mut known = lock(&self.known);
        for domain in domains {
            known.remove(domain.as_str());
        }
    }

    /// Forget every name (Clear AI list).
    pub fn forget_all_known(&self) {
        lock(&self.known).clear();
    }

    /// Clear log: forget which website every name was judged for, and bump the sites epoch, which
    /// tells the reviewer to empty its opened sites, bursts, queue, pending set and site caps, and
    /// an answer already in flight to land with no site. The gate stays open: review stays on.
    pub fn forget_sites(&self) {
        for entry in lock(&self.known).values_mut() {
            entry.site_key = None;
        }
        self.sites_epoch.fetch_add(1, Ordering::AcqRel);
        self.halted.notify_one();
    }

    /// The Clear log epoch an answer was asked under.
    pub fn sites_epoch(&self) -> u64 {
        self.sites_epoch.load(Ordering::Acquire)
    }

    // ----------------------------------------------------------------- what the routes read

    /// Route 23.
    pub fn status(&self, policy: &Policy, counts: AiCounts) -> AiStatus {
        let settings = read(&self.settings).clone();
        let source = self.key_source();
        let checked = *lock(&self.key_info);
        let today = settings::utc_day(now_secs());
        let current = self.spend_day.load(Ordering::Acquire) == today;
        let counted = |value: &AtomicU32| if current { value.load(Ordering::Acquire) } else { 0 };
        let names = read(&self.last_models).clone();
        AiStatus {
            available: self.unavailable.is_none(),
            unavailable_reason: self.unavailable,
            enabled: settings.enabled && self.unavailable.is_none(),
            state: self.state(),
            key: KeyStatus {
                source,
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
                    settings::micro_to_usd(self.spent_micro.load(Ordering::Acquire))
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
            last_review_at: Some(self.last_review_at.load(Ordering::Relaxed))
                .filter(|at| *at > 0),
            last_error: lock(&self.machine).last_error,
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
        let settings = read(&self.settings);
        AiSettingsView {
            available: self.unavailable.is_none(),
            unavailable_reason: self.unavailable,
            enabled: settings.enabled && self.unavailable.is_none(),
            key_source: self.key_source(),
            model: settings.model.clone(),
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

/// Held by the reviewer task for as long as it runs; see [`AiState::reviewer_alive`].
pub struct AliveGuard(Arc<AiState>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.alive.store(false, Ordering::Release);
        self.0.halt(Halt::Stopped);
    }
}

// --------------------------------------------------------------------- what the routes answer

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
    pub sends_to: String,
    pub last_review_at: Option<i64>,
    pub last_error: Option<&'static str>,
}

/// The key's source and limits. No `label`: OpenRouter's is a masked copy of the key (D10).
#[derive(Debug, Clone, Serialize)]
pub struct KeyStatus {
    pub source: KeySource,
    pub limit_usd: Option<f64>,
    pub limit_remaining_usd: Option<f64>,
    pub checked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelStatus {
    pub id: String,
    /// `None` until the model list has been fetched.
    pub name: Option<String>,
    pub prompt_usd_per_million: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Today {
    pub spent_usd: f64,
    pub requests: u32,
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
