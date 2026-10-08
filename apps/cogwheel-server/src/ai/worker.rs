//! The reviewer task (§6.15): the loop that feeds the pipeline, starts what it allows, sends each
//! request and writes each settlement.
//!
//! Everything that decides is in `review.rs`; this is the part that waits. It is detached like the
//! prune, so it can never take DNS down, and it holds the reviewer's [`AliveGuard`] for as long as
//! it runs: a panic, an abort or a return all drop it, which closes the gate with `stopped` while
//! the stored verdicts keep applying.
//!
//! Nothing here logs a domain, a body or the key (§6.16): DEBUG carries counts only.
//!
//! [`AliveGuard`]: super::gate::AliveGuard

use super::client::{self, KeyCheck};
use super::key::SecretKey;
use super::review::{Now, Outcome, Pipeline, Rechecked, Settlement, Start};
use super::spend::{Cost, Written};
use super::{AiState, Halt, Seen, TAP_DEPTH};
use crate::state::{ServerState, now_secs, stopped};
use cogwheel_storage::AiVerdict;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::{Id, JoinSet};
use tokio::time::MissedTickBehavior;

/// How often bursts are closed and jobs started. The 1 s gap between starts is the pipeline's.
pub const TICK: Duration = Duration::from_secs(1);
/// `Seen` entries taken from the tap at once.
pub const RECEIVE_BATCH: usize = 256;
/// How long shutdown waits for the cancelled requests to settle their reservations.
pub const DRAIN: Duration = Duration::from_secs(2);

/// Review until shutdown. `main` spawns this only when AI review is available and the activity
/// log is kept; with review off it idles behind a closed gate.
pub async fn task(state: ServerState, mut tap: mpsc::Receiver<Seen>) {
    let ai = Arc::clone(&state.ai);
    let _alive = ai.reviewer_alive();
    let mut pipeline = Pipeline::new(Arc::clone(&ai));
    let mut jobs = Jobs::new(Arc::clone(&ai));
    let mut shutdown = state.shutdown.clone();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut received = Vec::with_capacity(RECEIVE_BATCH);
    loop {
        tokio::select! {
            count = tap.recv_many(&mut received, RECEIVE_BATCH) => {
                // The sender lives in `AiState`, which outlives this task: closed means gone.
                if count == 0 {
                    break;
                }
                for seen in received.drain(..) {
                    pipeline.push(seen);
                }
            }
            _ = ticker.tick() => {
                catch_up(&mut pipeline, &mut jobs, &mut tap);
                let now = Now::wall();
                pipeline.tick(now, &state.runtime.current_policy());
                while let Some(start) = pipeline.next_start(now) {
                    spawn_job(&mut jobs, start);
                }
                if pipeline.key_info_due(now) {
                    refresh_key_info(&ai, ai.generation());
                }
            }
            () = ai.halted() => catch_up(&mut pipeline, &mut jobs, &mut tap),
            Some((id, outcome)) = jobs.next(), if !jobs.is_empty() => {
                let now = Now::wall();
                let settlement = pipeline.settle(now, id, outcome);
                persist(&state, now.secs(), settlement).await;
                let counters = &ai.counters;
                tracing::debug!(
                    waiting = pipeline.waiting(),
                    in_flight = pipeline.in_flight(),
                    bursts = pipeline.bursts(),
                    bursts_dropped = pipeline.bursts_dropped(),
                    tap_dropped = counters.tap_dropped.load(Ordering::Relaxed),
                    malformed = counters.malformed.load(Ordering::Relaxed),
                    unpriced = counters.unpriced.load(Ordering::Relaxed),
                    installs = counters.installs.load(Ordering::Relaxed),
                    "AI review settled a request"
                );
            }
            () = stopped(&mut shutdown) => break,
        }
    }

    // Shutdown cancels what is in flight, and charges each its reservation, as a halt does.
    jobs.abort_all();
    let drained = tokio::time::timeout(DRAIN, async {
        while let Some((id, outcome)) = jobs.next().await {
            let now = Now::wall();
            let settlement = pipeline.settle(now, id, outcome);
            persist(&state, now.secs(), settlement).await;
        }
    })
    .await;
    if drained.is_err() {
        tracing::warn!("AI review requests did not settle before shutdown");
    }
}

/// After a halt, a resume or a Clear log. On a new generation everything this task still holds
/// is from the consent just withdrawn or replaced: the jobs are aborted (a backstop for a job
/// spawned between `halt`'s abort and now), and what the tap still buffers is discarded.
fn catch_up(pipeline: &mut Pipeline, jobs: &mut Jobs, tap: &mut mpsc::Receiver<Seen>) {
    if pipeline.catch_up() {
        jobs.abort_all();
        for _ in 0..TAP_DEPTH {
            if tap.try_recv().is_err() {
                break;
            }
        }
    }
}

// --------------------------------------------------------------------- jobs

/// The requests in flight: the `JoinSet` that owns them, and which job each task is, so a task
/// that was aborted still settles as its job.
pub struct Jobs {
    ai: Arc<AiState>,
    set: JoinSet<Outcome>,
    ids: HashMap<Id, u64>,
}

impl Jobs {
    pub fn new(ai: Arc<AiState>) -> Self {
        Self {
            ai,
            set: JoinSet::new(),
            ids: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Cancel every job. Each still comes back from [`Self::next`], as [`Outcome::Aborted`]
    /// unless it had already finished.
    pub fn abort_all(&mut self) {
        self.set.abort_all();
    }

    /// The next job to finish, and how; `None` once there are none.
    pub async fn next(&mut self) -> Option<(u64, Outcome)> {
        loop {
            let (task, outcome) = match self.set.join_next_with_id().await? {
                Ok(done) => done,
                // Aborted by a halt or shutdown, or a panic: it may have been sent, so it is
                // charged its reservation.
                Err(error) => (error.id(), Outcome::Aborted),
            };
            if let Some(id) = self.ids.remove(&task) {
                self.ai.untrack(id);
                return Some((id, outcome));
            }
        }
    }
}

/// Start one job: registered so that `halt()` aborts it, and checked against the gate as the very
/// last step before its request goes out. The worker starts every job here, and so do the
/// end-to-end tests, so what they test is what runs.
pub fn spawn_job(jobs: &mut Jobs, start: Start) {
    let ai = Arc::clone(&jobs.ai);
    let Start {
        id,
        generation,
        body,
    } = start;
    if !ai.may_send(generation) {
        // Halted since `next_start`: nothing is sent, so nothing is charged.
        let task = jobs.set.spawn(async { Outcome::Withdrawn });
        jobs.ids.insert(task.id(), id);
        return;
    }
    let key = ai.key().map(|slot| slot.key);
    let task = jobs.set.spawn(send(Arc::clone(&ai), generation, key, body));
    jobs.ids.insert(task.id(), id);
    ai.track(id, generation, task);
}

/// The job body. The gate is checked immediately before the send: once a halt has returned this
/// is false, so no request starts after the write that withdrew consent.
async fn send(ai: Arc<AiState>, generation: u64, key: Option<SecretKey>, body: Vec<u8>) -> Outcome {
    let Some(key) = key.filter(|_| ai.may_send(generation)) else {
        return Outcome::Withdrawn;
    };
    match client::decide(&ai.client, &ai.base, &key, body).await {
        Ok(reply) => Outcome::Answered(reply),
        Err(failure) => Outcome::Failed(failure),
    }
}

/// Write what a settlement asks for: the spend, the rows and a re-check in one transaction,
/// through `AiState::commit`, the one writer of today's spend; then wake the installer if a row
/// changed. `now` is the clock the settlement was made on.
pub async fn persist(state: &ServerState, now: i64, settlement: Settlement) {
    let Settlement {
        cost,
        rows,
        recheck,
        sites_epoch,
    } = settlement;
    let recheck = match recheck {
        Some(recheck) => rechecked(state, &recheck).await,
        None => None,
    };
    if cost == Cost::default() && rows.is_empty() && recheck.is_none() {
        return;
    }
    let fresh: Vec<String> = rows.iter().map(|row| row.domain.clone()).collect();
    let write = Written {
        cost,
        rows,
        recheck,
        sites_epoch: Some(sites_epoch),
    };
    match state.ai.commit(&state.storage, now, write).await {
        Ok(true) => state.ai.notify_install(),
        Ok(false) => {}
        // Logged by `commit`, and the spend stays counted in memory. Nothing was stored, so the
        // names are asked about when next seen, not skipped as judged for up to 30 days.
        Err(_) => state.ai.forget_known(&fresh),
    }
}

/// A re-check applied to the row as it is stored now; written only if the row is still a block or
/// an allow then. A row Forget removed meanwhile has nothing left to re-check: the name is judged
/// afresh when it is next seen.
async fn rechecked(state: &ServerState, recheck: &Rechecked) -> Option<AiVerdict> {
    match state.storage.ai_verdict(recheck.domain.to_string()).await {
        Ok(Some(row)) if matches!(row.verdict.as_str(), "block" | "allow") => {
            Some(recheck.apply(row))
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "reading an AI verdict to re-check failed");
            None
        }
    }
}

/// The id a key check is tracked under, so a halt aborts it like a request; jobs count from 1.
const KEY_CHECK: u64 = 0;

/// Read the key's credit limits again for the status card (§8 step 7), behind the send gate like
/// a decisions request (D18): checked as the last step before it is sent, and aborted by a halt.
/// The answer counts only if the same key is still in force. A key OpenRouter now refuses, or
/// that is out of credit, stops review: the first tick after a restart checks it, before any
/// site load can close, so a key refused before the restart sends no name.
pub(super) fn refresh_key_info(ai: &Arc<AiState>, generation: u64) {
    let Some(slot) = ai.key() else {
        return;
    };
    let checking = Arc::clone(ai);
    let task = tokio::spawn(async move {
        let ai = checking;
        if ai.may_send(generation) {
            let checked = client::key_info(&ai.client, &ai.base, &slot.key).await;
            if ai
                .key()
                .is_some_and(|current| current.generation == slot.generation)
            {
                match checked {
                    Ok(info) => ai.set_key_info(info, now_secs()),
                    Err(KeyCheck::Refused) => ai.halt(Halt::KeyRefused),
                    Err(KeyCheck::NoCredit) => ai.halt(Halt::OutOfCredit),
                    // The decisions requests classify everything else themselves.
                    Err(_) => {}
                }
            }
        }
        ai.untrack(KEY_CHECK);
    });
    ai.track(KEY_CHECK, generation, task.abort_handle());
}
