//! The compiled blocklist index: which lists name a domain, as a bitmask (§6 step 1).
//!
//! Built once per list change and read on every cache miss, so everything here is sized for
//! lookup: two `HashMap`s, no allocation on the query path, and at most
//! [`crate::MAX_BOUNDARIES`](crate::MAX_BOUNDARIES) probes per name whatever its depth.

use crate::{Action, boundaries};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// How a list entry matches a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pattern {
    /// Matches only this exact name (a hosts-file line).
    Exact,
    /// Matches this name and every subdomain beneath it (`||name^`, a domains-list line).
    Suffix,
}

/// Which enabled lists mention a name, one bit per list slot.
///
/// Bit `i` belongs to slot `i`; the server assigns slots to enabled lists at build time, so a
/// scope's mask (the lists that apply to it) can be ANDed straight against these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Masks {
    /// Slots whose lists block the name.
    pub block: u64,
    /// Slots whose lists carry an exception (`@@`) for the name.
    pub allow: u64,
}

impl std::ops::BitOrAssign for Masks {
    fn bitor_assign(&mut self, other: Self) {
        self.block |= other.block;
        self.allow |= other.allow;
    }
}

/// Every enabled list, compiled into two hash maps for allocation-free lookup.
///
/// Built once per list refresh or toggle and shared behind an `Arc`; a lookup is at most one
/// exact probe plus at most sixteen suffix probes, each borrowing a slice of the query name.
#[derive(Debug, Default)]
pub struct ListIndex {
    exact: HashMap<Box<str>, Masks>,
    suffix: HashMap<Box<str>, Masks>,
    names: Vec<Arc<str>>,
}

impl ListIndex {
    /// Start an index; insert entries slot by slot, then [`ListIndexBuilder::build`].
    pub fn builder() -> ListIndexBuilder {
        ListIndexBuilder::default()
    }

    /// The bits every list sets for `name`, ORed across its exact and suffix matches.
    ///
    /// `name` must be normalised (see [`crate::normalize_domain`]). No allocation.
    pub fn lookup(&self, name: &str) -> Masks {
        let mut masks = self.exact.get(name).copied().unwrap_or_default();
        if !self.suffix.is_empty() {
            for suffix in boundaries(name) {
                if let Some(found) = self.suffix.get(suffix) {
                    masks |= *found;
                }
            }
        }
        masks
    }

    /// List names by slot; `names()[slot]` is the list bit `slot` belongs to.
    pub fn names(&self) -> &[Arc<str>] {
        &self.names
    }

    /// The name of the list that owns `slot`, if that slot was registered.
    pub fn name(&self, slot: u8) -> Option<&Arc<str>> {
        self.names.get(usize::from(slot))
    }

    /// Distinct names indexed (exact and suffix entries counted separately).
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len()
    }

    /// Whether no list contributed an entry.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty()
    }
}

/// Accumulates list entries into a [`ListIndex`].
#[derive(Debug, Default)]
pub struct ListIndexBuilder {
    index: ListIndex,
}

impl ListIndexBuilder {
    /// Register the list that owns `slot` so verdicts can be attributed by name.
    ///
    /// Slots are `0..64`; anything higher is ignored, matching [`Self::insert`].
    pub fn name(&mut self, slot: u8, name: impl Into<Arc<str>>) -> &mut Self {
        if u32::from(slot) >= u64::BITS {
            return self;
        }
        let at = usize::from(slot);
        if self.index.names.len() <= at {
            self.index.names.resize_with(at + 1, || Arc::from(""));
        }
        self.index.names[at] = name.into();
        self
    }

    /// Add one entry from list `slot`. `domain` must already be normalised.
    ///
    /// Slots `64..` have no bit and are silently dropped; the server refuses a 65th enabled
    /// list before it gets here.
    pub fn insert(
        &mut self,
        slot: u8,
        action: Action,
        pattern: Pattern,
        domain: &str,
    ) -> &mut Self {
        let Some(bit) = 1u64.checked_shl(u32::from(slot)) else {
            return self;
        };
        let map = match pattern {
            Pattern::Exact => &mut self.index.exact,
            Pattern::Suffix => &mut self.index.suffix,
        };
        // Two probes on a first sighting, one on every duplicate; duplicates dominate across a
        // handful of overlapping lists and `entry` would need an owned key for both cases.
        let masks = match map.get_mut(domain) {
            Some(masks) => masks,
            None => map.entry(Box::from(domain)).or_default(),
        };
        match action {
            Action::Allow => masks.allow |= bit,
            Action::Block => masks.block |= bit,
        }
        self
    }

    /// Finish the index.
    pub fn build(self) -> ListIndex {
        let mut index = self.index;
        index.exact.shrink_to_fit();
        index.suffix.shrink_to_fit();
        index
    }
}
