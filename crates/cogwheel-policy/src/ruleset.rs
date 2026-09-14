//! What a household and its devices decided for themselves: [`RuleSet`], [`Scope`], [`Policy`].
//!
//! These are the parts the server compiles from the database. The hot path only reads them, and
//! swaps the whole [`Policy`] rather than mutating any of it, so a query never sees half an edit.

use crate::index::ListIndex;
use crate::{Action, BlockMode, SCOPE_HOUSEHOLD, SCOPE_UNFILTERED, boundaries};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// User rules: a domain (covering its subdomains) mapped to one action.
///
/// One rule per domain — the server upserts on `(domain, device)`, so flipping allow to block
/// replaces rather than accumulates. Keys must be normalised with [`crate::normalize_rule_domain`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleSet(HashMap<Box<str>, Action>);

impl RuleSet {
    /// An empty rule set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the action for `domain`, returning the one it replaced.
    pub fn insert(&mut self, domain: &str, action: Action) -> Option<Action> {
        match self.0.get_mut(domain) {
            Some(existing) => Some(std::mem::replace(existing, action)),
            None => self.0.insert(Box::from(domain), action),
        }
    }

    /// The rule stored for exactly `domain`, ignoring parents.
    pub fn get(&self, domain: &str) -> Option<Action> {
        self.0.get(domain).copied()
    }

    /// The action for `name` after checking it and each parent on a label boundary.
    ///
    /// Any matching allow wins over any matching block, whichever is more specific: a household
    /// that allows `example.com` and blocks `ads.example.com` still resolves `ads.example.com`.
    /// That is the fixed "allow beats block within a tier" rule, not a bug to tighten.
    pub fn get_at_boundaries(&self, name: &str) -> Option<Action> {
        if self.0.is_empty() {
            return None;
        }
        let mut blocked = false;
        for candidate in boundaries(name) {
            match self.0.get(candidate) {
                Some(Action::Allow) => return Some(Action::Allow),
                Some(Action::Block) => blocked = true,
                None => {}
            }
        }
        blocked.then_some(Action::Block)
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no rules.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every rule, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Action)> {
        self.0.iter().map(|(domain, action)| (&**domain, *action))
    }
}

impl<S: Into<Box<str>>> FromIterator<(S, Action)> for RuleSet {
    fn from_iter<I: IntoIterator<Item = (S, Action)>>(rules: I) -> Self {
        Self(
            rules
                .into_iter()
                .map(|(domain, action)| (domain.into(), action))
                .collect(),
        )
    }
}

/// The effective filtering settings a group of clients shares.
///
/// Scopes are interned by the server: devices with identical settings share one id, and the
/// DNS cache is keyed by that id, so a query answered for one of them is answered for all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Cache-key id: [`SCOPE_HOUSEHOLD`], [`SCOPE_UNFILTERED`], or `2..` for a device group.
    pub id: u32,
    /// `false` means every name resolves (pause, or a device with filtering off).
    pub filtering: bool,
    /// The list slots that apply, ANDed against [`crate::Masks`] on lookup.
    pub mask: u64,
    /// Device-specific rules, checked before the household's. `None` for the reserved scopes.
    pub rules: Option<Arc<RuleSet>>,
}

impl Scope {
    /// The reserved household scope: filtering on, every enabled list, no device rules.
    pub fn household(all_mask: u64) -> Self {
        Self {
            id: SCOPE_HOUSEHOLD,
            filtering: true,
            mask: all_mask,
            rules: None,
        }
    }

    /// The reserved unfiltered scope.
    pub fn unfiltered() -> Self {
        Self {
            id: SCOPE_UNFILTERED,
            filtering: false,
            mask: 0,
            rules: None,
        }
    }
}

/// Everything the DNS runtime needs to decide a query, swapped wholesale on every change.
///
/// Construct through [`Policy::new`] or [`Policy::empty`]; the scope table behind
/// [`Policy::scope`] is derived from `by_ip` at that point.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Every enabled list, compiled.
    pub index: Arc<ListIndex>,
    /// Rules that apply to everyone.
    pub household: Arc<RuleSet>,
    /// Named devices by address. A client not listed here is in the household scope.
    pub by_ip: HashMap<IpAddr, Scope>,
    /// Bits of every enabled list slot; the household scope's mask.
    pub all_mask: u64,
    /// How blocked names are answered.
    pub block_mode: BlockMode,
    scopes: HashMap<u32, Scope>,
    household_scope: Scope,
    unfiltered_scope: Scope,
}

impl Policy {
    /// Assemble a policy; `by_ip` scopes carry the ids the server's allocator interned.
    pub fn new(
        index: Arc<ListIndex>,
        household: Arc<RuleSet>,
        by_ip: HashMap<IpAddr, Scope>,
        all_mask: u64,
        block_mode: BlockMode,
    ) -> Self {
        let scopes = by_ip
            .values()
            .filter(|scope| scope.id > SCOPE_UNFILTERED)
            .map(|scope| (scope.id, scope.clone()))
            .collect();
        Self {
            index,
            household,
            by_ip,
            all_mask,
            block_mode,
            scopes,
            household_scope: Scope::household(all_mask),
            unfiltered_scope: Scope::unfiltered(),
        }
    }

    /// A policy with no lists, rules or devices: what the runtime serves before the first
    /// list is compiled.
    pub fn empty(block_mode: BlockMode) -> Self {
        Self::new(
            Arc::new(ListIndex::default()),
            Arc::new(RuleSet::new()),
            HashMap::new(),
            0,
            block_mode,
        )
    }

    /// The scope behind a cache-key id. An id this policy does not know falls back to the
    /// household scope, the same treatment an unknown client gets.
    pub fn scope(&self, id: u32) -> &Scope {
        match id {
            SCOPE_HOUSEHOLD => &self.household_scope,
            SCOPE_UNFILTERED => &self.unfiltered_scope,
            _ => self.scopes.get(&id).unwrap_or(&self.household_scope),
        }
    }

    /// The scope a client resolves under: its device's, or the household's.
    pub fn scope_for(&self, client: IpAddr) -> &Scope {
        self.by_ip.get(&client).unwrap_or(&self.household_scope)
    }
}
