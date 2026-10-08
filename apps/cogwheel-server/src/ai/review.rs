//! The reviewer's pipeline (§6.6, §6.12–§6.14): site loads in, one request at a time out, each
//! answer settled into a row and a charge.
//!
//! It decides everything and does none of the waiting. Every method takes the time it acts at, it
//! spawns nothing and sends nothing: [`Pipeline::next_start`] hands out the one job that may start
//! now, or none, the worker sends it, and hands what came back to [`Pipeline::settle`]. That split
//! is what makes the bounds testable: in flight ≤ 2, the 1 s gap, the daily caps, the queue's
//! drop-oldest and every per-site and per-device cap are each a unit test on a synthetic clock.
//!
//! It reads and writes `AiState`, which is memory: the send gate, the `known` map, today's spend.
//! The database writes a settlement asks for are the worker's.

mod settle;

pub use settle::{Outcome, Rechecked, Settlement};

use super::burst::{Bursts, Looked, SiteLoad};
use super::prompt::{self, Context, Effect, Provider};
use super::spend::{reserve_micro, utc_day};
use super::verdict::{self, IGNORE_DAYS};
use super::{AiState, DAY, Halt, Known, ListState, Seen, State, list_state, site};
use cogwheel_policy::{Action, Policy, Reason};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Jobs waiting to start. Past this the oldest is dropped and counted.
pub const QUEUE_CAP: usize = 1_024;
/// Websites remembered for the home-context rule, by site key; the oldest is forgotten first.
pub const OPENED_CAP: usize = 4_096;
/// Candidates one site load may yield.
pub const PER_LOAD: usize = 24;
/// Other names of the load sent with a candidate.
pub const CONTEXT_NAMES: usize = 24;
/// Names one site key may put up for review per UTC day…
pub const PER_SITE_DAY: u32 = 60;
/// …counted in a map of at most this many site keys.
pub const SITE_KEYS: usize = 4_096;
/// Names one device may put up for review per hour…
pub const PER_CLIENT_HOUR: u32 = 300;
/// …counted in a map of at most this many devices.
pub const CLIENTS: usize = 1_024;
/// Requests in flight at once.
pub const IN_FLIGHT: usize = 2;
/// The least time between two starts, in milliseconds.
pub const GAP_MS: i64 = 1_000;
/// Requests per UTC day, whatever they cost.
pub const REQUESTS_PER_DAY: u32 = 2_000;
/// Attempts a job gets before it is dropped and its name released, to be asked about again on its
/// next sighting.
pub const ATTEMPTS: u32 = 4;
/// Dropped jobs in a row that make the state `retrying`.
pub const DROPS_BEFORE_RETRYING: u32 = 5;
/// How long `retrying` pauses dispatch, doubling with each further dropped job…
pub const RETRYING_PAUSE: Duration = Duration::from_secs(60);
/// …up to this.
pub const RETRYING_CAP: Duration = Duration::from_secs(15 * 60);
/// Refused requests or unusable answers in a row, or answers with no confidence in a row, that
/// stop the model: it would otherwise spend the daily limit on nothing.
pub const STRIKES: u32 = 3;
/// How often the key's credit limits are read again while reviewing (§8 step 7).
pub const KEY_INFO_EVERY: Duration = Duration::from_secs(600);

const HOUR: i64 = 3_600;

// --------------------------------------------------------------------- the clock

/// A moment on the reviewer's clock, in Unix milliseconds. Every [`Pipeline`] method takes one, so
/// tests drive the pipeline on a synthetic clock and the worker on the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Now(i64);

impl Now {
    /// The wall clock.
    pub fn wall() -> Self {
        Self::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| {
                    i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
                }),
        )
    }

    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Whole seconds: what the tests' synthetic clock mostly counts in.
    #[cfg(test)]
    pub const fn from_secs(secs: i64) -> Self {
        Self(secs.saturating_mul(1_000))
    }

    pub const fn millis(self) -> i64 {
        self.0
    }

    pub const fn secs(self) -> i64 {
        self.0.div_euclid(1_000)
    }

    /// The UTC day, in days since the epoch.
    pub fn day(self) -> u32 {
        utc_day(self.secs())
    }

    /// `wait` from now, in milliseconds.
    fn after(self, wait: Duration) -> i64 {
        self.0
            .saturating_add(i64::try_from(wait.as_millis()).unwrap_or(i64::MAX))
    }
}

// --------------------------------------------------------------------- what goes in and out

/// One name to ask about. Built when its site load closed, so what it sends is fixed then; a
/// change of model or key halts, which discards it.
#[derive(Debug)]
struct Job {
    id: u64,
    generation: u64,
    /// The Clear log epoch it was asked under: an answer from an older one lands with no site.
    sites_epoch: u64,
    domain: Arc<str>,
    website: Arc<str>,
    website_key: Box<str>,
    /// The household's lists on the name when the request was built.
    lists: ListState,
    /// The stored verdict a cross-site re-check asks about; `None` for a fresh judgement.
    recheck: Option<Action>,
    /// Allows over a list block its site load has made, shared by the load's jobs (D6).
    allows: Arc<AtomicU32>,
    model: Arc<str>,
    price: Option<f64>,
    body: Vec<u8>,
    /// Micro-USD held against today's limit while it is in flight.
    reserve: u64,
    attempts: u32,
}

/// A job the worker may start now: the request body, and the generation it must still be in when
/// it goes to send.
#[derive(Debug)]
pub struct Start {
    pub id: u64,
    pub generation: u64,
    pub body: Vec<u8>,
}

// --------------------------------------------------------------------- bounded bookkeeping

/// Counts per key within a window (a UTC day, an hour), in a map of bounded size. Once the map is
/// full, a key it does not hold counts as capped until the window turns: the bound is on memory,
/// and it errs towards asking less.
#[derive(Debug)]
struct Caps<K> {
    window: i64,
    counts: HashMap<K, u32>,
    limit: u32,
    keys: usize,
}

impl<K: Eq + Hash> Caps<K> {
    fn new(limit: u32, keys: usize) -> Self {
        Self {
            window: i64::MIN,
            counts: HashMap::new(),
            limit,
            keys,
        }
    }

    fn roll(&mut self, window: i64) {
        if window != self.window {
            self.window = window;
            self.counts.clear();
        }
    }

    fn has_room<Q: Eq + Hash + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.counts
            .get(key)
            .map_or(self.counts.len() < self.keys, |count| *count < self.limit)
    }

    fn count(&mut self, key: K) {
        *self.counts.entry(key).or_insert(0) += 1;
    }
}

/// The websites opened lately, by site key: a set that forgets the oldest first.
#[derive(Debug, Default)]
struct Opened {
    order: VecDeque<Box<str>>,
    keys: HashSet<Box<str>>,
}

impl Opened {
    fn insert(&mut self, key: &str) {
        if self.keys.contains(key) {
            return;
        }
        if self.order.len() >= OPENED_CAP
            && let Some(oldest) = self.order.pop_front()
        {
            self.keys.remove(&oldest);
        }
        self.order.push_back(key.into());
        self.keys.insert(key.into());
    }

    fn contains(&self, key: &str) -> bool {
        self.keys.contains(key)
    }

    fn clear(&mut self) {
        self.order.clear();
        self.keys.clear();
    }
}

// --------------------------------------------------------------------- the pipeline

/// Bursts → candidates → queue → admission → settle. One per reviewer task.
#[derive(Debug)]
pub struct Pipeline {
    ai: Arc<AiState>,
    bursts: Bursts,
    opened: Opened,
    queue: VecDeque<Job>,
    /// Names queued or in flight, each with the job that holds it: a name is asked once at a time.
    pending: HashMap<Arc<str>, u64>,
    flights: HashMap<u64, Job>,
    next_id: u64,
    /// The gate's generation and the Clear log epoch, as this pipeline last caught up with them.
    generation: u64,
    sites_epoch: u64,
    last_start: Option<i64>,
    /// No job starts before this (milliseconds): a retry's wait pauses all dispatch together.
    paused_until: i64,
    /// The UTC day a `paused_budget` or `out_of_credit` began; the next one resumes it.
    paused_day: Option<u32>,
    drops: u32,
    strikes: u32,
    unrated: u32,
    key_info_at: Option<i64>,
    sites: Caps<Box<str>>,
    clients: Caps<IpAddr>,
}

impl Pipeline {
    pub fn new(ai: Arc<AiState>) -> Self {
        Self {
            generation: ai.generation(),
            sites_epoch: ai.sites_epoch(),
            ai,
            bursts: Bursts::default(),
            opened: Opened::default(),
            queue: VecDeque::new(),
            pending: HashMap::new(),
            flights: HashMap::new(),
            next_id: 1,
            last_start: None,
            paused_until: 0,
            paused_day: None,
            drops: 0,
            strikes: 0,
            unrated: 0,
            key_info_at: None,
            sites: Caps::new(PER_SITE_DAY, SITE_KEYS),
            clients: Caps::new(PER_CLIENT_HOUR, CLIENTS),
        }
    }

    /// One answered lookup from the tap. Dropped unless the gate is open on this pipeline's
    /// generation: what the tap still held when review was halted is never reviewed.
    pub fn push(&mut self, seen: Seen) {
        if self.ai.may_send(self.generation) {
            self.bursts.push(seen);
        }
    }

    /// Catch up with a halt, a resume or a Clear log. True when the generation changed: the
    /// caller then aborts everything it has in flight, as a backstop for the halt's own abort.
    pub fn catch_up(&mut self) -> bool {
        let epoch = self.ai.sites_epoch();
        if epoch != self.sites_epoch {
            self.sites_epoch = epoch;
            self.forget_sites();
        }
        if self.ai.generation() == self.generation {
            return false;
        }
        self.halt_local();
        true
    }

    /// D18, this side of the gate: empty the queue, the open bursts and the pending set. Jobs in
    /// flight stay until their outcome is settled, which charges each its reservation; an answer
    /// for the old generation is discarded unread, apart from its spend.
    pub fn halt_local(&mut self) {
        self.generation = self.ai.generation();
        self.queue.clear();
        self.bursts.clear();
        self.pending.clear();
        // What comes next is a new consent, or a new day: it starts with a clean slate.
        self.paused_until = 0;
        self.drops = 0;
        self.strikes = 0;
        self.unrated = 0;
        self.report();
    }

    /// Clear log: the opened sites, the bursts, the queue and the cap maps are browsing history
    /// too. Jobs in flight keep their names pending; their answers land with no site.
    fn forget_sites(&mut self) {
        self.opened.clear();
        self.bursts.clear();
        self.sites.counts.clear();
        self.clients.counts.clear();
        let queued: Vec<Job> = self.queue.drain(..).collect();
        for job in &queued {
            self.release(job);
        }
        self.report();
    }

    /// Close the bursts that are over and turn their site loads into queued jobs, under `policy`
    /// (the live one, read once per tick). Also the UTC rollover.
    pub fn tick(&mut self, now: Now, policy: &Policy) {
        self.catch_up();
        self.roll_over(now);
        if !self.ai.may_send(self.generation) {
            self.bursts.clear();
            return;
        }
        let Self { bursts, ai, .. } = self;
        let loads = bursts.tick(now.secs(), |name| shareable(ai, policy, name));
        for load in &loads {
            self.admit(now, policy, load);
        }
        self.report();
    }

    /// A new UTC day: the caps start again, and `paused_budget` and `out_of_credit` return to
    /// reviewing on a new generation.
    fn roll_over(&mut self, now: Now) {
        let today = now.day();
        self.sites.roll(i64::from(today));
        self.clients.roll(now.secs().div_euclid(HOUR));
        if !matches!(
            self.ai.machine_state(),
            State::PausedBudget | State::OutOfCredit
        ) {
            self.paused_day = None;
            return;
        }
        if *self.paused_day.get_or_insert(today) != today {
            self.paused_day = None;
            tracing::info!("a new UTC day: AI review resumes");
            self.ai.resume();
            self.catch_up();
        }
    }

    /// §6.6: queue a site load's candidates, at most [`PER_LOAD`], each with the load's other
    /// shareable names as its context.
    fn admit(&mut self, now: Now, policy: &Policy, load: &SiteLoad) {
        self.opened.insert(&load.anchor_key);
        let Some((model, price)) = self.ai.model() else {
            return;
        };
        let model: Arc<str> = Arc::from(model);
        let provider = Provider {
            zero_retention: self.ai.zero_retention(),
            price_per_million: price,
        };
        let shared: Vec<bool> = load
            .members
            .iter()
            .map(|member| shareable(&self.ai, policy, &member.domain))
            .collect();
        let allows = Arc::new(AtomicU32::new(0));
        let mut admitted = 0;
        for (index, member) in load.members.iter().enumerate() {
            if admitted == PER_LOAD {
                break;
            }
            // Rule 1: every name in a request may leave the house.
            if !shared[index] {
                continue;
            }
            let lists = list_state(policy, &member.domain);
            let Some(recheck) = self.ask(now, load, member, lists) else {
                continue;
            };
            // Rule 5, the home-context rule: a name of another website the household opened is
            // judged in that website's loads, so a hostile page cannot get `login.bank.com`
            // blocked in junk context.
            let key = site::site_key(&member.domain);
            if self.opened.contains(key) && key != &*load.anchor_key {
                continue;
            }
            // Rule 6: the caps.
            if !self.sites.has_room(key) || !self.clients.has_room(&load.client) {
                continue;
            }
            self.sites.count(key.into());
            self.clients.count(load.client);

            let context = context(load, &shared, index);
            let body = prompt::body(
                &model,
                &Context {
                    website: &load.anchor,
                    candidate: &member.domain,
                    looked_up_with_it: &context,
                },
                Effect::for_lists(lists),
                &provider,
            );
            let job = Job {
                id: self.next_id,
                generation: self.generation,
                sites_epoch: self.sites_epoch,
                domain: Arc::clone(&member.domain),
                website: Arc::clone(&load.anchor),
                website_key: load.anchor_key.clone(),
                lists,
                recheck,
                allows: Arc::clone(&allows),
                model: Arc::clone(&model),
                price,
                reserve: reserve_micro(body.len(), price),
                body,
                attempts: 0,
            };
            self.next_id += 1;
            self.enqueue(job);
            admitted += 1;
        }
    }

    /// Rules 2–4 of §6.6: a reviewable reason, not already asked, and new or due. `Some(None)` is
    /// a fresh judgement, `Some(Some(verdict))` a cross-site re-check of a stored verdict.
    fn ask(
        &self,
        now: Now,
        load: &SiteLoad,
        member: &Looked,
        lists: ListState,
    ) -> Option<Option<Action>> {
        // A name the AI list is applying is admitted too: otherwise its `review_after` could
        // never fire, and an applied verdict would stand unjudged until the 90-day prune.
        if !matches!(
            member.reason,
            Reason::NoMatch | Reason::ListAllow | Reason::List | Reason::Ai
        ) || self.is_pending(&member.domain)
        {
            return None;
        }
        let Some(known) = self.ai.known(&member.domain) else {
            return Some(None);
        };
        // Expired, or judged against lists that have since changed: judged afresh, and the old
        // verdict keeps applying until the answer lands. A contested row is the exception: it
        // waits out its 90 days whatever the lists do (§6.10).
        if now.secs() >= known.review_after || (known.lists != lists && !contested(&known)) {
            return Some(None);
        }
        verdict::recheck_due(&known, &load.anchor_key, now.day()).then_some(known.verdict)
    }

    fn enqueue(&mut self, job: Job) {
        if self.queue.len() >= QUEUE_CAP
            && let Some(oldest) = self.queue.pop_front()
        {
            self.release(&oldest);
            self.ai.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.pending.insert(Arc::clone(&job.domain), job.id);
        self.queue.push_back(job);
    }

    /// Put a job that will be retried back at the head of the queue; a full queue drops it as
    /// the oldest instead.
    fn requeue(&mut self, job: Job) {
        if self.queue.len() >= QUEUE_CAP {
            self.release(&job);
            self.ai.counters.dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            self.queue.push_front(job);
        }
    }

    /// The name is free to be asked about again, unless a newer job already holds it.
    fn release(&mut self, job: &Job) {
        if self.pending.get(&job.domain) == Some(&job.id) {
            self.pending.remove(&job.domain);
        }
    }

    /// §6.13: the job that may start now, if any. All of these must hold: fewer than two in
    /// flight, a second since the last start, no retry pause, the gate open on the job's
    /// generation, fewer than 2,000 requests today, and today's spend plus every reservation
    /// within the daily limit. Failing either of the last two pauses review until 00:00 UTC.
    pub fn next_start(&mut self, now: Now) -> Option<Start> {
        let job = self.queue.front()?;
        if self.flights.len() >= IN_FLIGHT
            || self
                .last_start
                .is_some_and(|at| now.millis().saturating_sub(at) < GAP_MS)
            || now.millis() < self.paused_until
            || !self.ai.may_send(job.generation)
        {
            return None;
        }
        let today = self.ai.today(now.secs());
        let flying = u32::try_from(self.flights.len()).unwrap_or(u32::MAX);
        let spend = today
            .micro_usd
            .saturating_add(self.reserved())
            .saturating_add(job.reserve);
        if today.requests.saturating_add(flying) >= REQUESTS_PER_DAY
            || spend > self.ai.daily_limit_micro()
        {
            self.stop(now, Halt::Budget, None, None);
            return None;
        }
        let job = self.queue.pop_front()?;
        self.last_start = Some(now.millis());
        let start = Start {
            id: job.id,
            generation: job.generation,
            body: job.body.clone(),
        };
        self.flights.insert(job.id, job);
        self.report();
        Some(start)
    }

    /// Whether the key's credit limits are due to be read again: at most every ten minutes, and
    /// only while the gate is open, so a refused key is not sent again.
    pub fn key_info_due(&mut self, now: Now) -> bool {
        let every = i64::try_from(KEY_INFO_EVERY.as_millis()).unwrap_or(i64::MAX);
        if !self.ai.may_send(self.generation)
            || self
                .key_info_at
                .is_some_and(|at| now.millis().saturating_sub(at) < every)
        {
            return false;
        }
        self.key_info_at = Some(now.millis());
        true
    }

    /// Jobs waiting to start.
    pub fn waiting(&self) -> usize {
        self.queue.len()
    }

    /// Jobs started and not yet settled.
    pub fn in_flight(&self) -> usize {
        self.flights.len()
    }

    /// Bursts open or waiting to be scored.
    pub fn bursts(&self) -> usize {
        self.bursts.len()
    }

    /// Whether a job for `name` is queued or in flight.
    pub fn is_pending(&self, name: &str) -> bool {
        self.pending.contains_key(name)
    }

    /// Micro-USD held against today's limit by the jobs in flight.
    pub fn reserved(&self) -> u64 {
        self.flights
            .values()
            .fold(0, |total: u64, job| total.saturating_add(job.reserve))
    }

    fn report(&self) {
        self.ai
            .counters
            .waiting
            .store(self.queue.len() as u64, Ordering::Relaxed);
    }
}

/// §6.3: whether a name may go into a request, as the website, the candidate or a name sent with
/// them. `sendable`, and no household rule covers it: a household rule is how a household keeps
/// a name of its own, and everything under it, out of review.
pub fn shareable(ai: &AiState, policy: &Policy, name: &str) -> bool {
    site::sendable(name, ai.own_names()) && policy.household.get_at_boundaries(name).is_none()
}

/// Up to [`CONTEXT_NAMES`] other shareable names of the load, nearest in time to the candidate
/// first; arrival order breaks a tie.
fn context<'a>(load: &'a SiteLoad, shared: &[bool], candidate: usize) -> Vec<&'a str> {
    let at = load
        .members
        .get(candidate)
        .map_or(0, |looked| looked.first_ts);
    let mut others: Vec<&Looked> = load
        .members
        .iter()
        .zip(shared)
        .enumerate()
        .filter(|(index, (_, shared))| *index != candidate && **shared)
        .map(|(_, (looked, _))| looked)
        .collect();
    others.sort_by_key(|looked| looked.first_ts.abs_diff(at));
    others
        .into_iter()
        .take(CONTEXT_NAMES)
        .map(|looked| &*looked.domain)
        .collect()
}

/// A contested row (§6.10) is the one ignore kept past an ordinary ignore's 30 days.
fn contested(known: &Known) -> bool {
    known.verdict.is_none()
        && known.review_after.saturating_sub(known.judged_at) > IGNORE_DAYS * DAY
}
