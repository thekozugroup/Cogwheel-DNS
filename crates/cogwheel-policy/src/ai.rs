//! The AI list (ADR 0002): exact names an AI review decided, compiled by the server.

use crate::Action;
use std::collections::{HashMap, HashSet};

/// Exact names only, deliberately. [`crate::RuleSet`] matches a name's parents and lets any allow
/// beat any block; here an allow of a site's apex would then whitelist every tracker under it.
/// Exact matching is also what makes the DNS cache's per-name invalidation complete.
///
/// Keys must be normalised with [`crate::normalize_domain`]; the server's compile step does that
/// before it collects them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AiList {
    names: HashMap<Box<str>, Action>,
    /// How many of `names` are blocks, counted once at build so the 5 s Overview poll is O(1).
    blocks: usize,
}

impl AiList {
    /// The verdict for exactly `name`. One hash probe, none when the list is empty; no allocation.
    pub fn get(&self, name: &str) -> Option<Action> {
        if self.names.is_empty() {
            return None;
        }
        self.names.get(name).copied()
    }

    /// How many names the list decides.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the list decides nothing (AI review off, or nothing cleared its bar).
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// How many names it blocks.
    pub fn blocks(&self) -> usize {
        self.blocks
    }

    /// How many names it allows over a list block.
    pub fn allows(&self) -> usize {
        self.names.len() - self.blocks
    }

    /// Every name and its verdict, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Action)> {
        self.names.iter().map(|(name, action)| (&**name, *action))
    }

    /// Names whose verdict differs between `self` and `next`: added, removed or flipped.
    /// Control-plane only; it allocates.
    pub fn changes(&self, next: &Self) -> HashSet<Box<str>> {
        // Removed or flipped: in `self`, and not with the same verdict in `next`.
        let gone = self
            .names
            .iter()
            .filter(|(name, action)| next.names.get(*name) != Some(*action))
            .map(|(name, _)| name);
        let added = next
            .names
            .keys()
            .filter(|name| !self.names.contains_key(*name));
        gone.chain(added).cloned().collect()
    }
}

/// Like [`crate::RuleSet`]'s: a name given twice keeps its last verdict, and is counted once.
impl<S: Into<Box<str>>> FromIterator<(S, Action)> for AiList {
    fn from_iter<I: IntoIterator<Item = (S, Action)>>(verdicts: I) -> Self {
        let names: HashMap<Box<str>, Action> = verdicts
            .into_iter()
            .map(|(name, action)| (name.into(), action))
            .collect();
        // Counted after collecting, so a repeated name cannot be counted twice.
        let blocks = names
            .values()
            .filter(|action| **action == Action::Block)
            .count();
        Self { names, blocks }
    }
}
