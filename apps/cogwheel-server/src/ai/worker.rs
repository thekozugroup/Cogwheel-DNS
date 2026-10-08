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
//! [`AliveGuard`]: super::AliveGuard

use super::client;
use super::key::SecretKey;
use super::review::{Now, Outcome, Pipeline, Rechecked, Settlement, Start};
use super::spend::Cost;
use super::{AiState, Seen, TAP_DEPTH};
use crate::state::{ServerState, now_secs, stopped};
use cogwheel_storage::AiVerdict;
use std::collections::HashMap;
use std::sync::Arc;
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
                    refresh_key_info(&ai);
                }
            }
            () = ai.halted() => catch_up(&mut pipeline, &mut jobs, &mut tap),
            Some((id, outcome)) = jobs.next(), if !jobs.is_empty() => {
                let settlement = pipeline.settle(Now::wall(), id, outcome);
                persist(&state, settlement).await;
                tracing::debug!(
                    waiting = pipeline.waiting(),
                    in_flight = pipeline.in_flight(),
                    bursts = pipeline.bursts(),
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
            let settlement = pipeline.settle(Now::wall(), id, outcome);
            persist(&state, settlement).await;
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
    match client::decide(ai.client(), ai.base(), &key, body).await {
        Ok(reply) => Outcome::Answered(reply),
        Err(failure) => Outcome::Failed(failure),
    }
}

/// Write what a settlement asks for: the spend and the rows in one transaction, through
/// `AiState::settle`, the one writer of today's spend; then wake the installer if a row changed.
pub async fn persist(state: &ServerState, settlement: Settlement) {
    let Settlement {
        cost,
        mut rows,
        recheck,
    } = settlement;
    if let Some(recheck) = recheck
        && let Some(row) = rechecked(state, &recheck).await
    {
        rows.push(row);
    }
    if cost == Cost::default() && rows.is_empty() {
        return;
    }
    let changed = !rows.is_empty();
    // A failed write is logged by `settle`, and its spend stays counted in memory.
    if state.ai.settle(&state.storage, cost, rows).await.is_ok() && changed {
        state.ai.notify_install();
    }
}

/// A re-check applied to the row as it is stored now. A row Forget removed meanwhile has nothing
/// left to re-check: the name is judged afresh when it is next seen.
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

/// Read the key's credit limits again for the status card (§8 step 7). The answer is kept only if
/// the same key is still in force; a failure changes nothing, since the decisions requests
/// classify the key themselves.
fn refresh_key_info(ai: &Arc<AiState>) {
    let Some(slot) = ai.key() else {
        return;
    };
    let ai = Arc::clone(ai);
    tokio::spawn(async move {
        if let Ok(info) = client::key_info(ai.client(), ai.base(), &slot.key).await
            && ai
                .key()
                .is_some_and(|current| current.generation == slot.generation)
        {
            ai.set_key_info(info, now_secs());
        }
    });
}
