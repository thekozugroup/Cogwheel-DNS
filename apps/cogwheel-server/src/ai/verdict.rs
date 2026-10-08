//! From an answer to a stored verdict (§6.9), the cross-site rule (§6.10), how long each row
//! lasts (§6.11), and from stored verdicts to the AI list (§5.1). Pure: the clock is passed in.
//!
//! The AI list holds only the model's disagreements with the household's lists (D5). An answer
//! that agrees with them, is unsure or below its bar, hits an override cap, or is contradicted in
//! another website's context is stored as `ignore`, which never compiles: the lists decide.
//!
//! [`compile`] is the single place stored rows become policy, and it applies every bar again
//! against the *live* lists: a verdict judged against an older list state stops applying when the
//! lists change under it, and the name is judged again on its next sighting.

use super::prompt::{Answer, Choice, Outcome};
use super::{DAY, Known, ListState};
use cogwheel_policy::{
    Action, AiList, ListIndex, is_domain_shaped, is_protected, normalize_domain,
};
use cogwheel_storage::AiVerdict;

/// A plain block, with no list involved. A wrong one is visible (Activity says "AI list") and one
/// click to undo.
pub const BLOCK_BAR: f64 = 0.85;
/// The role answer, when it overrides a list in either direction.
pub const OVERRIDE_BAR: f64 = 0.92;
/// The second question ("if it stays blocked, does the site break?"), same case.
pub const EFFECT_BAR: f64 = 0.90;

/// Allows over a list block one site load may make (D6): a hostile page cannot whitelist a batch.
pub const ALLOWS_PER_LOAD: u32 = 3;
/// Allows over a list block one UTC day may make.
pub const ALLOWS_PER_DAY: u32 = 20;

/// Days a block or allow applies before a website loading it has it judged afresh.
pub const DECISION_DAYS: i64 = 30;
/// The most days an ordinary ignore is kept: it is only a negative cache, and a record of what the
/// household's websites loaded, so `HISTORY_DAYS` shortens it.
pub const IGNORE_DAYS: i64 = 30;
/// Days a contested row is kept. It is a decision, not a negative cache: dropping it sooner would
/// let one website's context flip it back with the conflict forgotten.
pub const CONTESTED_DAYS: i64 = 90;
/// Cross-site re-checks a verdict gets before it is judged afresh.
pub const MAX_RECHECKS: u8 = 2;

// --------------------------------------------------------------------- answer → verdict

/// Why an answer was stored as `ignore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The model agrees with the lists, which keep deciding and keep the attribution.
    Agrees,
    /// The model chose ignore, did not say how sure it was, or was below the bar.
    Unsure,
    /// It cleared the bar for an allow over a list, but an override cap was full.
    Limit,
    /// Two websites' contexts disagreed in opposite directions (§6.10).
    Contested,
}

impl Why {
    /// The stored spelling (`ai_verdicts.why`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Unsure => "unsure",
            Self::Limit => "limit",
            Self::Contested => "contested",
        }
    }
}

/// What an answer is stored as (§6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Block,
    /// Always over a list block, since an allow anywhere else agrees with the lists: each one
    /// counts towards the override caps.
    Allow,
    Ignore(Why),
}

impl Decision {
    /// The stored spelling (`ai_verdicts.verdict`).
    pub const fn verdict(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
            Self::Ignore(_) => "ignore",
        }
    }

    pub const fn why(self) -> Option<Why> {
        match self {
            Self::Ignore(why) => Some(why),
            Self::Block | Self::Allow => None,
        }
    }
}

/// Allows over a list block already made, in the site load being judged and today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Allowed {
    pub this_load: u32,
    pub today: u32,
}

impl Allowed {
    /// Whether one more fits under both caps.
    pub const fn has_room(self) -> bool {
        self.this_load < ALLOWS_PER_LOAD && self.today < ALLOWS_PER_DAY
    }
}

/// §6.9: what an answer about a name is stored as, given the household's lists on it when the
/// request was built. The bars are on `confidence`, never `probabilities` (D6); an answer that
/// does not say how sure it is is no decision. Overriding a list in either direction needs the
/// role answer at [`OVERRIDE_BAR`] and the effect answer at [`EFFECT_BAR`] the right way round.
pub fn decide(lists: ListState, answer: &Answer, allowed: Allowed) -> Decision {
    let Some(confidence) = answer
        .confidence
        .filter(|confidence| confidence.is_finite())
    else {
        return Decision::Ignore(Why::Unsure);
    };
    let effect = |want: Outcome| {
        answer.effect.is_some_and(|(outcome, confidence)| {
            outcome == want
                && confidence
                    .is_some_and(|confidence| confidence.is_finite() && confidence >= EFFECT_BAR)
        })
    };
    let overrides = confidence >= OVERRIDE_BAR;
    match (lists, answer.choice) {
        (ListState::Nothing, Choice::Block) if confidence >= BLOCK_BAR => Decision::Block,
        (ListState::Nothing, Choice::Allow)
        | (ListState::Block, Choice::Block)
        | (ListState::Exception, Choice::Allow) => Decision::Ignore(Why::Agrees),
        (ListState::Block, Choice::Allow) if overrides && effect(Outcome::Breaks) => {
            if allowed.has_room() {
                Decision::Allow
            } else {
                Decision::Ignore(Why::Limit)
            }
        }
        (ListState::Exception, Choice::Block) if overrides && effect(Outcome::Works) => {
            Decision::Block
        }
        _ => Decision::Ignore(Why::Unsure),
    }
}

/// §6.9, §6.11: when a row judged at `from` is next due. A block or allow after 30 days; an
/// ordinary ignore after `min(30, HISTORY_DAYS)` days, so it never outlives the activity log; a
/// contested row after 90, by which time the prune has deleted it.
pub fn review_after(decision: Decision, from: i64, history_days: u32) -> i64 {
    let days = match decision {
        Decision::Block | Decision::Allow => DECISION_DAYS,
        Decision::Ignore(Why::Contested) => CONTESTED_DAYS,
        Decision::Ignore(_) => IGNORE_DAYS.min(i64::from(history_days)),
    };
    from.saturating_add(days * DAY)
}

/// A fresh judgement of one name: everything its row is made from.
#[derive(Debug, Clone, Copy)]
pub struct Judgement<'a> {
    pub domain: &'a str,
    /// The household's lists on it when the request was built.
    pub lists: ListState,
    pub answer: Answer,
    /// What [`decide`] made of it.
    pub decision: Decision,
    /// The site load's website; `None` when Clear log ran while the request was in flight.
    pub site: Option<&'a str>,
    /// The dated snapshot that answered, or the requested id when the response named none.
    pub model: &'a str,
    pub judged_at: i64,
}

impl Judgement<'_> {
    /// The row it is stored as. A fresh judgement replaces any older row outright, with no
    /// re-checks. Every row keeps the model's answers, so "leaned block, the model was 62% sure"
    /// can be said without overstating anything or passing the model's confidence off as
    /// Cogwheel's.
    pub fn row(&self, history_days: u32) -> AiVerdict {
        AiVerdict {
            domain: self.domain.to_owned(),
            verdict: self.decision.verdict().to_owned(),
            why: self.decision.why().map(|why| why.as_str().to_owned()),
            choice: self.answer.choice.as_str().to_owned(),
            confidence: self.answer.confidence,
            effect: self
                .answer
                .effect
                .map(|(outcome, _)| outcome.as_str().to_owned()),
            effect_confidence: self.answer.effect.and_then(|(_, confidence)| confidence),
            lists: self.lists.as_str().to_owned(),
            site: self.site.map(str::to_owned),
            conflict_site: None,
            rechecks: 0,
            model: self.model.to_owned(),
            judged_at: self.judged_at,
            review_after: review_after(self.decision, self.judged_at, history_days),
        }
    }
}

// --------------------------------------------------------------------- cross-site re-checks

/// Whether a known block or allow is due a re-check in a load whose website has the site key
/// `anchor_key`, on UTC day `today` (§6.10): another website, fewer than two re-checks, none yet
/// today. The home-context rule is the reviewer's, on top. A site that Clear log forgot counts as
/// another website: a re-check can only keep the verdict or hand it back to the lists.
pub fn recheck_due(known: &Known, anchor_key: &str, today: u32) -> bool {
    known.verdict.is_some()
        && known.site_key.as_deref() != Some(anchor_key)
        && known.rechecks < MAX_RECHECKS
        && known.last_recheck_day != today
}

/// What a re-check in another website's context does to a stored block or allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recheck {
    /// The same direction, ignore, or below the bar: the verdict stands.
    Kept,
    /// The opposite direction above the plain bar: the name goes back to the lists (D8).
    Contested,
}

/// §6.10: a name that is core to one website and junk to another is outside what one global
/// verdict can decide, since DNS has no website context at query time. Opposite answers above
/// [`BLOCK_BAR`] hand it back to the lists; a household rule settles it either way.
pub fn contest(stored: Action, answer: &Answer) -> Recheck {
    let confidence = answer
        .confidence
        .filter(|confidence| confidence.is_finite())
        .unwrap_or(0.0);
    let opposite = matches!(
        (stored, answer.choice),
        (Action::Block, Choice::Allow) | (Action::Allow, Choice::Block)
    );
    if opposite && confidence >= BLOCK_BAR {
        Recheck::Contested
    } else {
        Recheck::Kept
    }
}

impl Recheck {
    /// The stored row after this re-check, made in `site`'s context at `now`. Either way it counts
    /// one more re-check. A contested row keeps the first answer and its website, names the other
    /// website, and stays 90 days; its `judged_at` is unchanged, so the first website is still
    /// forgotten on the activity log's schedule.
    pub fn apply(self, mut row: AiVerdict, site: Option<&str>, now: i64) -> AiVerdict {
        row.rechecks = (row.rechecks + 1).clamp(0, i64::from(MAX_RECHECKS));
        if self == Self::Contested {
            let contested = Decision::Ignore(Why::Contested);
            row.verdict = contested.verdict().to_owned();
            row.why = Some(Why::Contested.as_str().to_owned());
            row.conflict_site = site.map(str::to_owned);
            // `HISTORY_DAYS` bears only on ordinary ignores.
            row.review_after = review_after(contested, now, 0);
        }
        row
    }
}

// --------------------------------------------------------------------- compiling

/// The AI list a policy build installs: every stored block or allow that still clears its bar
/// against the household's lists as they are now (`index` under `all_mask`).
pub fn compile(rows: &[AiVerdict], index: &ListIndex, all_mask: u64) -> AiList {
    rows.iter()
        .filter_map(|row| {
            let action = match row.verdict.as_str() {
                "block" => Action::Block,
                "allow" => Action::Allow,
                _ => return None,
            };
            let domain = normalize_domain(&row.domain);
            if !is_domain_shaped(&domain) || is_protected(&domain) {
                return None;
            }
            let confidence = row
                .confidence
                .filter(|confidence| confidence.is_finite())
                .unwrap_or(0.0);
            let effect = |want: &str| {
                row.effect.as_deref() == Some(want)
                    && row.effect_confidence.is_some_and(|confidence| {
                        confidence.is_finite() && confidence >= EFFECT_BAR
                    })
            };
            let keep = match (action, ListState::of(index, all_mask, &domain)) {
                (Action::Block, ListState::Nothing) => confidence >= BLOCK_BAR,
                // The lists already block it, and keep the attribution.
                (Action::Block, ListState::Block) => false,
                (Action::Block, ListState::Exception) => {
                    confidence >= OVERRIDE_BAR && effect("works")
                }
                (Action::Allow, ListState::Block) => confidence >= OVERRIDE_BAR && effect("breaks"),
                // Nothing to whitelist; and never turn a list exception (which skips the CNAME
                // re-check) into an AI allow (which runs it). That inversion is how a
                // "whitelist" could block.
                (Action::Allow, ListState::Nothing | ListState::Exception) => false,
            };
            keep.then_some((domain, action))
        })
        .collect()
}
