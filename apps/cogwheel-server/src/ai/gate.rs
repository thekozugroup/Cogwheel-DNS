//! The send gate (D18) and the state machine behind it.
//!
//! One gate for everything that could send a name: `tapping`, read by the query-log writer
//! before it offers anything, and a generation every job carries and checks immediately before
//! its request goes out. [`AiState::halt`] closes both synchronously, so a write that withdraws
//! consent is not trusting a queue to drain: once it returns, no request starts, and the ones on
//! the wire are cancelled.

use super::{
    AiState, KEY_REFUSED, MODEL_GONE, NO_ANSWER, OUT_OF_CREDIT, RATE_LIMITED, STOPPED, State,
};
use crate::state::{lock, read};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::task::AbortHandle;

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

/// The state machine's own value, and the sentence it last set. Behind one lock with the gate, so
/// a halt and a resume can never interleave into an open gate in a halted state.
#[derive(Debug)]
pub(super) struct Machine {
    pub(super) state: State,
    pub(super) last_error: Option<&'static str>,
}

impl AiState {
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
        match sentence {
            Some(sentence) => machine.last_error = Some(sentence),
            // Whatever ended the retrying ended its sentence too; a terminal state's stays.
            None if matches!(machine.last_error, Some(RATE_LIMITED | NO_ANSWER)) => {
                machine.last_error = None;
            }
            None => {}
        }
        drop(machine);
        self.halted.notify_one();
        tracing::info!(?reason, "AI review stopped sending");
    }

    /// Whether a job of `generation` may send now. Every job checks this as the last step before
    /// its request goes out.
    pub fn may_send(&self, generation: u64) -> bool {
        self.tapping.load(Ordering::Acquire)
            && self.generation.load(Ordering::Acquire) == generation
    }

    /// The current generation: a job carries the one it was queued under.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Start reviewing on a new generation with an empty queue: route 24 step 8, the UTC rollover,
    /// a key change, a passing Test. Ends any terminal state and its sentence. The gate opens only
    /// if everything review needs is present and the reviewer is alive.
    pub fn resume(&self) {
        self.resume_from(&[]);
    }

    /// [`Self::resume`], only from one of the states in `from` (any but `stopped` when empty), as
    /// one step under the machine lock. The UTC rollover holds no lock a PUT takes, so a `PUT off`
    /// that halts between its read of the state and its resume must leave review off. Returns
    /// whether it resumed.
    pub fn resume_from(&self, from: &[State]) -> bool {
        let mut machine = lock(&self.machine);
        if machine.state == State::Stopped || !(from.is_empty() || from.contains(&machine.state)) {
            return false;
        }
        self.generation.fetch_add(1, Ordering::AcqRel);
        machine.state = State::Reviewing;
        machine.last_error = None;
        self.regate(&machine);
        drop(machine);
        self.halted.notify_one();
        true
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

    /// `retrying` (§6.12): requests keep failing, and dispatch backs off. The gate stays open,
    /// because this is not an exit from reviewing; `sentence` is [`RATE_LIMITED`] or [`NO_ANSWER`].
    pub fn mark_retrying(&self, sentence: &'static str) {
        let mut machine = lock(&self.machine);
        if machine.state == State::Reviewing {
            machine.state = State::Retrying;
            machine.last_error = Some(sentence);
        }
    }

    /// A request succeeded: back to `reviewing` from `retrying`, and a passing failure's sentence
    /// is cleared. A terminal state's is not: those end only by their own rules.
    pub fn mark_recovered(&self, now: i64) {
        self.last_review_at.store(now, Ordering::Relaxed);
        let mut machine = lock(&self.machine);
        if matches!(machine.state, State::Reviewing | State::Retrying) {
            machine.state = State::Reviewing;
            machine.last_error = None;
        }
    }

    /// The state the machine itself holds, before what the settings and the key override.
    pub fn machine_state(&self) -> State {
        lock(&self.machine).state
    }

    /// The `last_error` sentence route 23 reports, if any.
    pub fn last_error(&self) -> Option<&'static str> {
        lock(&self.machine).last_error
    }

    /// Register a request in flight so [`Self::halt`] can abort it. A job queued under an older
    /// generation is aborted here instead: a halt raced its spawn, and it must not send.
    pub fn track(&self, id: u64, generation: u64, job: AbortHandle) {
        let mut inflight = lock(&self.inflight);
        if self.generation.load(Ordering::Acquire) == generation {
            inflight.insert(id, job);
        } else {
            job.abort();
        }
    }

    /// A request finished, one way or another.
    pub fn untrack(&self, id: u64) {
        lock(&self.inflight).remove(&id);
    }

    /// Resolve when a halt, a resume or a Clear log asks the reviewer to empty its queue.
    pub async fn halted(&self) {
        self.halted.notified().await;
    }

    /// Mark the reviewer alive for as long as the returned guard is held. The worker future holds
    /// it, so a panic, an abort or a return all drop it, and dropping it closes the gate with
    /// `stopped`: stored verdicts keep applying, and nothing more is sent.
    pub fn reviewer_alive(self: &Arc<Self>) -> AliveGuard {
        let machine = lock(&self.machine);
        self.alive.store(true, Ordering::Release);
        self.regate(&machine);
        drop(machine);
        AliveGuard(Arc::clone(self))
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
