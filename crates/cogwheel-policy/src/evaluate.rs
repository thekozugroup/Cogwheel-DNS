//! The decision itself: [`evaluate`], its [`Verdict`] and the [`Reason`] that names the tier.
//!
//! The precedence this implements is documented at the crate root. Allocation-free: every input
//! is already normalised by the time it reaches here.

use crate::ruleset::{Policy, Scope};
use crate::{Action, is_protected};
use serde::{Deserialize, Serialize};

/// Which tier decided a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Reason {
    /// Nothing matched; the default allow.
    NoMatch = 0,
    /// A rule for this device.
    DeviceRule = 1,
    /// A rule for everyone.
    HouseholdRule = 2,
    /// One of the [`crate::PROTECTED_SUFFIXES`].
    Protected = 3,
    /// A list exception (`@@`).
    ListAllow = 4,
    /// A list entry.
    List = 5,
    /// A list entry matched a CNAME target in the upstream answer.
    Cname = 6,
    /// Protection is paused.
    Paused = 7,
    /// The device has filtering switched off.
    Unfiltered = 8,
}

impl Reason {
    /// The stored form (`query_log.reason`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a stored reason.
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::NoMatch,
            1 => Self::DeviceRule,
            2 => Self::HouseholdRule,
            3 => Self::Protected,
            4 => Self::ListAllow,
            5 => Self::List,
            6 => Self::Cname,
            7 => Self::Paused,
            8 => Self::Unfiltered,
            _ => return None,
        })
    }
}

/// The outcome of evaluating one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Resolve normally. The `u8` is the list slot whose `@@` exception decided, for
    /// [`Reason::ListAllow`], and carries nothing otherwise.
    Allow(Reason, u8),
    /// Answer per the policy's [`crate::BlockMode`]. The `u8` is the list slot for
    /// [`Reason::List`] and [`Reason::Cname`] and carries nothing otherwise.
    Block(Reason, u8),
}

impl Verdict {
    /// An allow that no list is attributable for — every tier but [`Reason::ListAllow`].
    pub const fn allow(reason: Reason) -> Self {
        Self::Allow(reason, 0)
    }

    /// Whether the name is blocked.
    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::Block(..))
    }

    /// Which tier decided.
    pub const fn reason(self) -> Reason {
        match self {
            Self::Allow(reason, _) | Self::Block(reason, _) => reason,
        }
    }

    /// The list a verdict is attributed to, for the three list tiers: a block, a block on a
    /// CNAME target, and the `@@` exception that spared a name. The other tiers name no list.
    pub const fn slot(self) -> Option<u8> {
        match self {
            Self::Block(Reason::List | Reason::Cname, slot)
            | Self::Allow(Reason::ListAllow, slot) => Some(slot),
            _ => None,
        }
    }

    const fn from_rule(action: Action, reason: Reason) -> Self {
        match action {
            Action::Allow => Self::allow(reason),
            Action::Block => Self::Block(reason, 0),
        }
    }
}

/// Decide `name` for a client in `scope`, in the precedence described at the crate root.
///
/// Allocation-free: `name` must already be lowercase; a trailing dot is tolerated. A scope with
/// filtering off answers [`Reason::Unfiltered`] without probing anything — the runtime, which
/// alone knows whether that scope was reached through a pause, rewrites it to
/// [`Reason::Paused`].
pub fn evaluate(policy: &Policy, scope: &Scope, name: &str) -> Verdict {
    if !scope.filtering {
        return Verdict::allow(Reason::Unfiltered);
    }
    let name = name.trim_end_matches('.');
    if let Some(rules) = scope.rules.as_deref()
        && let Some(action) = rules.get_at_boundaries(name)
    {
        return Verdict::from_rule(action, Reason::DeviceRule);
    }
    if let Some(action) = policy.household.get_at_boundaries(name) {
        return Verdict::from_rule(action, Reason::HouseholdRule);
    }
    evaluate_lists(policy, scope.mask, name)
}

/// The protected and list tiers alone, for the lists in `mask`.
///
/// This is what a CNAME target in an upstream answer is re-checked against (user rules named
/// the query, not its aliases), and what `GET /check` reports for the list tier.
pub fn evaluate_lists(policy: &Policy, mask: u64, name: &str) -> Verdict {
    let name = name.trim_end_matches('.');
    if is_protected(name) {
        return Verdict::allow(Reason::Protected);
    }
    let masks = policy.index.lookup(name);
    let allowed = masks.allow & mask;
    if allowed != 0 {
        // Attributed like a block: the lowest matching slot, so "why is this allowed?" can name
        // the list whose exception spared it.
        return Verdict::Allow(Reason::ListAllow, allowed.trailing_zeros() as u8);
    }
    let blocked = masks.block & mask;
    if blocked != 0 {
        return Verdict::Block(Reason::List, blocked.trailing_zeros() as u8);
    }
    Verdict::allow(Reason::NoMatch)
}
