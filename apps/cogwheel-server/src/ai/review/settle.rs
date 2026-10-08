//! Settling a started job (§6.8, §6.9, §6.10, §6.12, §6.13): what its outcome costs, what it
//! stores, and what it does to the state. Every 200 is charged, readable or not; an answer to a
//! question asked under a generation since halted is discarded unread, apart from its spend; and
//! every exit from reviewing closes the gate before it returns.

use super::{
    ATTEMPTS, DROPS_BEFORE_RETRYING, Job, Now, Pipeline, RETRYING_CAP, RETRYING_PAUSE, STRIKES,
};
use crate::ai::client::{Class, Failure, Reply, backoff};
use crate::ai::prompt::{self, Effect, Parsed};
use crate::ai::spend::{Cost, charge_micro};
use crate::ai::verdict::{self, Allowed, Decision, Judgement, MAX_RECHECKS, Recheck, Why};
use crate::ai::{
    Halt, Known, MODEL_UNRATED, MODEL_UNREADABLE, NO_ANSWER, RATE_LIMITED, REDIRECTED, State,
};
use cogwheel_policy::Action;
use cogwheel_storage::AiVerdict;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// How a started job ended.
#[derive(Debug)]
pub enum Outcome {
    /// The gate was closed when it went to send, so nothing was sent and nothing is charged.
    Withdrawn,
    /// Cancelled by a halt or shutdown, possibly after its bytes were written: charged its
    /// reservation, since OpenRouter may bill it.
    Aborted,
    /// A 200, readable or not. Billed either way.
    Answered(Reply),
    /// Anything but a 200.
    Failed(Failure),
}

/// What a settled job asks the worker to write, all of it through `AiState::settle`.
#[derive(Debug, Default)]
pub struct Settlement {
    /// Charged to today; nothing when the request cannot have been billed.
    pub cost: Cost,
    /// Fresh judgements, each replacing any stored row outright.
    pub rows: Vec<AiVerdict>,
    /// A cross-site re-check, applied to the row as it is stored when it is written.
    pub recheck: Option<Rechecked>,
}

/// A cross-site re-check's result (§6.10).
#[derive(Debug, Clone)]
pub struct Rechecked {
    pub domain: Arc<str>,
    pub outcome: Recheck,
    /// The other website; `None` when Clear log ran while the request was in flight.
    pub site: Option<Arc<str>>,
    pub at: i64,
}

impl Rechecked {
    /// The stored row after this re-check.
    pub fn apply(&self, row: AiVerdict) -> AiVerdict {
        self.outcome.apply(row, self.site.as_deref(), self.at)
    }
}

impl Pipeline {
    /// A started job's outcome: what to charge and what to store. Updates the `known` map and
    /// the failure counters, and closes the gate on a terminal answer.
    pub fn settle(&mut self, now: Now, id: u64, outcome: Outcome) -> Settlement {
        let Some(job) = self.flights.remove(&id) else {
            return Settlement::default();
        };
        let current = job.generation == self.ai.generation();
        let settlement = match outcome {
            Outcome::Withdrawn => {
                self.release(&job);
                Settlement::default()
            }
            Outcome::Aborted => {
                self.release(&job);
                Settlement {
                    cost: Cost::request(job.reserve),
                    ..Settlement::default()
                }
            }
            Outcome::Failed(failure) => {
                if current {
                    self.failed(now, job, &failure);
                } else {
                    self.release(&job);
                }
                Settlement::default()
            }
            Outcome::Answered(reply) => self.answered(now, &job, reply, current),
        };
        self.report();
        settlement
    }

    /// A 200. Its spend is settled first, readable or not (§6.8); the answer is used only if it
    /// was asked under the current generation.
    fn answered(&mut self, now: Now, job: &Job, reply: Reply, current: bool) -> Settlement {
        self.release(job);
        let parsed = match reply {
            Reply::Body(body) => prompt::parse(&body, Effect::for_lists(job.lists).is_some()),
            Reply::Unreadable => Parsed::default(),
        };
        let (micro, unpriced) = charge_micro(parsed.usage.as_ref(), job.reserve, job.price);
        if unpriced {
            self.ai.counters.unpriced.fetch_add(1, Ordering::Relaxed);
        }
        let mut settlement = Settlement {
            cost: Cost::request(micro),
            ..Settlement::default()
        };
        if !current {
            return settlement;
        }
        self.drops = 0;
        self.ai.mark_recovered(now.secs());
        let Some(answer) = parsed.answer else {
            self.ai.counters.malformed.fetch_add(1, Ordering::Relaxed);
            self.strike(now, None);
            return settlement;
        };
        self.strikes = 0;

        let site = (self.ai.sites_epoch() == job.sites_epoch).then(|| Arc::clone(&job.website));
        match (job.recheck, self.ai.known(&job.domain)) {
            (Some(stored), Some(mut known)) if known.verdict.is_some() => {
                let outcome = verdict::contest(stored, &answer);
                known.rechecks = known.rechecks.saturating_add(1).min(MAX_RECHECKS);
                known.last_recheck_day = now.day();
                if outcome == Recheck::Contested {
                    known.verdict = None;
                    let contested = Decision::Ignore(Why::Contested);
                    known.review_after = verdict::review_after(contested, now.secs(), 0);
                }
                self.ai.remember(Arc::clone(&job.domain), known);
                settlement.recheck = Some(Rechecked {
                    domain: Arc::clone(&job.domain),
                    outcome,
                    site,
                    at: now.secs(),
                });
            }
            // A fresh judgement; also a re-check whose row Forget removed meanwhile, which is
            // what "judged again the next time it is looked up" promises.
            _ => {
                let allowed = Allowed {
                    this_load: job.allows.load(Ordering::Relaxed),
                    today: self.ai.today(now.secs()).overrides,
                };
                let decision = verdict::decide(job.lists, &answer, allowed);
                if decision == Decision::Allow {
                    job.allows.fetch_add(1, Ordering::Relaxed);
                    settlement.cost.overrides = 1;
                }
                let row = Judgement {
                    domain: &job.domain,
                    lists: job.lists,
                    answer,
                    decision,
                    site: site.as_deref(),
                    model: parsed.model_or(&job.model),
                    judged_at: now.secs(),
                }
                .row(self.ai.history_days());
                let known = Known {
                    verdict: applied(decision),
                    lists: job.lists,
                    judged_at: row.judged_at,
                    review_after: row.review_after,
                    site_key: site.map(|_| job.website_key.clone()),
                    rechecks: 0,
                    last_recheck_day: 0,
                };
                self.ai.remember(Arc::clone(&job.domain), known);
                settlement.rows.push(row);
            }
        }

        // D6: a model that never says how sure it is would spend the whole budget on rows that
        // can never apply. The third such answer is still stored, as unsure.
        if answer.confidence.is_some() {
            self.unrated = 0;
        } else {
            self.unrated += 1;
            if self.unrated >= STRIKES {
                self.stop(now, Halt::ModelRefused, Some(MODEL_UNRATED), None);
            }
        }
        settlement
    }

    /// §6.12: anything but a 200, under the current generation.
    fn failed(&mut self, now: Now, mut job: Job, failure: &Failure) {
        match failure.class {
            Class::Retry {
                after,
                rate_limited,
            } => {
                job.attempts += 1;
                // All dispatch pauses together, as the cookbook does.
                let wait = after.unwrap_or_else(|| backoff(job.attempts - 1, job.id));
                self.paused_until = self.paused_until.max(now.after(wait));
                if job.attempts < ATTEMPTS {
                    self.requeue(job);
                    return;
                }
                self.release(&job);
                self.drops += 1;
                if self.drops >= DROPS_BEFORE_RETRYING {
                    let doublings = (self.drops - DROPS_BEFORE_RETRYING).min(16);
                    let pause = RETRYING_PAUSE
                        .saturating_mul(1 << doublings)
                        .min(RETRYING_CAP);
                    self.paused_until = self.paused_until.max(now.after(pause));
                    if self.ai.machine_state() == State::Reviewing {
                        tracing::warn!(
                            status = failure.status,
                            code = failure.code,
                            limit_source = failure.limit_source.as_deref(),
                            "AI review requests keep failing; retrying with a longer pause"
                        );
                    }
                    self.ai.mark_retrying(if rate_limited {
                        RATE_LIMITED
                    } else {
                        NO_ANSWER
                    });
                }
            }
            Class::Drop => {
                self.release(&job);
                self.strike(now, Some(failure));
            }
            Class::KeyRefused => {
                self.release(&job);
                self.stop(now, Halt::KeyRefused, None, Some(failure));
            }
            Class::OutOfCredit => {
                self.release(&job);
                self.stop(now, Halt::OutOfCredit, None, Some(failure));
            }
            Class::ModelRefused => {
                self.release(&job);
                self.stop(now, Halt::ModelRefused, None, Some(failure));
            }
            Class::Redirected => {
                self.release(&job);
                self.stop(now, Halt::ModelRefused, Some(REDIRECTED), Some(failure));
            }
        }
    }

    /// A refused request (400, 413) or an unreadable answer; three in a row stop the model.
    fn strike(&mut self, now: Now, failure: Option<&Failure>) {
        self.strikes += 1;
        if self.strikes >= STRIKES {
            self.stop(now, Halt::ModelRefused, Some(MODEL_UNREADABLE), failure);
        }
    }

    /// A transition out of reviewing: logged once at WARN with only what may be logged (§6.16),
    /// the gate closed before this returns (D18), and everything queued here emptied.
    pub(super) fn stop(
        &mut self,
        now: Now,
        reason: Halt,
        sentence: Option<&'static str>,
        failure: Option<&Failure>,
    ) {
        tracing::warn!(
            ?reason,
            status = failure.and_then(|failure| failure.status),
            code = failure.and_then(|failure| failure.code),
            limit_source = failure.and_then(|failure| failure.limit_source.as_deref()),
            "AI review stopped sending"
        );
        if matches!(reason, Halt::Budget | Halt::OutOfCredit) {
            self.paused_day = Some(now.day());
        }
        match sentence {
            Some(sentence) => self.ai.halt_because(reason, Some(sentence)),
            None => self.ai.halt(reason),
        }
        self.halt_local();
    }
}

/// What the AI list applies for a decision.
const fn applied(decision: Decision) -> Option<Action> {
    match decision {
        Decision::Block => Some(Action::Block),
        Decision::Allow => Some(Action::Allow),
        Decision::Ignore(_) => None,
    }
}
