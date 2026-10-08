//! Installing a policy that changes the verdict of a few exact names (ADR 0002's AI list) without
//! emptying the cache. A child module so it can reach the private `WireCache` and `Shard`.

use super::{DnsRuntime, Policy, Shard, WireCache};
use crate::runtime_support::{read_recover, write_recover};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl DnsRuntime {
    /// Install `policy`, whose verdicts differ from the installed one's only for the exact names
    /// in `changed` (not their subdomains), and drop every cached answer for those names under
    /// every scope and type. Returns how many entries were dropped.
    ///
    /// Complete because a cached answer depends on the AI list only through its own name: the
    /// AI tier is not part of the CNAME re-check (`evaluate_lists`). Epoch before sweep, as in
    /// [`Self::swap_policy`], so a miss decided under the old policy cannot land after the sweep.
    ///
    /// Walks every shard, so the caller runs it off the async workers (`spawn_blocking`); each
    /// shard's write lock is held only for that shard's own `retain`.
    pub fn swap_policy_invalidating(
        &self,
        policy: Arc<Policy>,
        changed: &HashSet<Box<str>>,
    ) -> usize {
        self.swap_policy_keep_cache(policy);
        self.cache_epoch.fetch_add(1, Ordering::Release);
        self.cache.invalidate_names(changed)
    }
}

impl WireCache {
    /// Drop every entry whose name is in `names`, whatever its scope or type. Returns how many.
    fn invalidate_names(&self, names: &HashSet<Box<str>>) -> usize {
        if names.is_empty() {
            return 0;
        }
        let mut dropped = 0;
        for shard in &self.shards {
            // A read pass first: most shards hold none of the names, and a hit only ever waits on
            // a writer, so the write lock is taken only where there is something to remove.
            if !read_recover(shard)
                .entries
                .keys()
                .any(|key| names.contains(&*key.domain))
            {
                continue;
            }
            let mut guard = write_recover(shard);
            let Shard { entries, order } = &mut *guard;
            let before = entries.len();
            entries.retain(|key, _| !names.contains(&*key.domain));
            // Keeps `order` exactly the keys of `entries`, which eviction relies on.
            order.retain(|key| !names.contains(&*key.domain));
            dropped += before - entries.len();
        }
        dropped
    }
}
