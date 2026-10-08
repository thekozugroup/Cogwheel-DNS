//! The `known` map (§6.6): every name already judged, so a repeat visit sends nothing.
//!
//! It supplies the "first seen" notion dns-core lacks, and it is what decides whether a name is
//! due to be judged again. Loaded from the table while review is on (at boot, or when it is
//! turned on), then kept in step by every path that writes the table: the reviewer's answers,
//! Forget, Clear, Clear log and the prune. Off, nothing reads it, so it is not kept: ADR 0002
//! lets RSS grow by nothing while review is off. Capped, because the table it mirrors is:
//! eviction only costs a possible re-judgement, since an evicted row is still stored and still
//! compiled.

use super::{AiState, KNOWN_CAP, ListState, site};
use crate::state::lock;
use cogwheel_policy::Action;
use cogwheel_storage::{AiVerdict, Storage, StorageError};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// A name already judged: what the reviewer needs to decide whether it is due again (§6.6).
#[derive(Debug, Clone, PartialEq)]
pub struct Known {
    /// `None` for an ignore of any kind, contested included.
    pub verdict: Option<Action>,
    /// The household's lists on the name when it was judged; a change makes it due.
    pub lists: ListState,
    pub judged_at: i64,
    pub review_after: i64,
    /// The site key of the website it was judged for; `None` once Clear log forgot it.
    pub site_key: Option<Box<str>>,
    pub rechecks: u8,
    /// The UTC day of the last cross-site re-check; 0 for none since boot.
    pub last_recheck_day: u32,
}

impl Known {
    /// The entry for a stored row.
    pub fn of(row: &AiVerdict) -> Self {
        Self {
            verdict: match row.verdict.as_str() {
                "block" => Some(Action::Block),
                "allow" => Some(Action::Allow),
                _ => None,
            },
            // The schema admits nothing else; a hand-edited row reads as "the lists had no
            // opinion", which at worst makes the name due again.
            lists: ListState::parse(&row.lists).unwrap_or(ListState::Nothing),
            judged_at: row.judged_at,
            review_after: row.review_after,
            site_key: row
                .site
                .as_deref()
                .map(|site| Box::from(site::site_key(site))),
            rechecks: u8::try_from(row.rechecks.clamp(0, 2)).unwrap_or(0),
            last_recheck_day: 0,
        }
    }
}

impl AiState {
    /// The `known` entry for a name.
    pub fn known(&self, domain: &str) -> Option<Known> {
        lock(&self.known).get(domain).cloned()
    }

    /// How many names are known.
    #[cfg(test)]
    pub fn known_len(&self) -> usize {
        lock(&self.known).len()
    }

    /// Fill the map from the table: at boot while review is on, and when it is turned on. Read
    /// again if a Forget, a Clear, a prune or Clear log changed the map meanwhile, so a name
    /// forgotten while the table was being read does not come back.
    ///
    /// # Errors
    ///
    /// The table could not be read; the map is left as it was.
    pub async fn load_known(&self, storage: &Storage) -> Result<(), StorageError> {
        loop {
            let epoch = self.known_epoch.load(Ordering::Acquire);
            let rows = storage.list_ai_verdicts().await?;
            let mut loaded = HashMap::with_capacity(rows.len());
            for row in &rows {
                loaded.insert(Arc::from(row.domain.as_str()), Known::of(row));
            }
            drop(rows);
            let mut known = lock(&self.known);
            if self.known_epoch.load(Ordering::Acquire) == epoch {
                *known = loaded;
                return Ok(());
            }
        }
    }

    /// Review was turned off: nothing reads the map until it is turned on again, which reloads it.
    pub fn unload_known(&self) {
        let mut known = lock(&self.known);
        *known = HashMap::new();
        self.known_epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Record a judged name. Past [`KNOWN_CAP`] the oldest tenth by `judged_at` is evicted, in
    /// one sort; the next eviction is then at least that many inserts away.
    pub fn remember(&self, domain: Arc<str>, entry: Known) {
        let mut known = lock(&self.known);
        known.insert(domain, entry);
        if known.len() > KNOWN_CAP {
            let mut ages: Vec<(i64, Arc<str>)> = known
                .iter()
                .map(|(domain, entry)| (entry.judged_at, Arc::clone(domain)))
                .collect();
            ages.sort_unstable_by_key(|(judged_at, _)| *judged_at);
            for (_, domain) in ages.into_iter().take(KNOWN_CAP / 10) {
                known.remove(&domain);
            }
        }
    }

    /// Forget names whose rows were deleted (Forget, Clear log's negatives, the prune).
    pub fn forget_known(&self, domains: &[String]) {
        let mut known = lock(&self.known);
        for domain in domains {
            known.remove(domain.as_str());
        }
        self.known_epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Forget every name (Clear AI list).
    pub fn forget_all_known(&self) {
        let mut known = lock(&self.known);
        known.clear();
        self.known_epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Clear log: forget which website every name was judged for, and bump the sites epoch, which
    /// tells the reviewer to empty its opened sites, bursts, queue, pending set and site caps, and
    /// an answer already in flight to land with no site. The gate stays open: review stays on.
    pub fn forget_sites(&self) {
        let mut known = lock(&self.known);
        for entry in known.values_mut() {
            entry.site_key = None;
        }
        self.known_epoch.fetch_add(1, Ordering::AcqRel);
        drop(known);
        self.sites_epoch.fetch_add(1, Ordering::AcqRel);
        self.halted.notify_one();
    }

    /// The Clear log epoch an answer was asked under.
    pub fn sites_epoch(&self) -> u64 {
        self.sites_epoch.load(Ordering::Acquire)
    }
}
