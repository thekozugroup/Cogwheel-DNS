//! Bookkeeping and process-level plumbing the hot path leans on but does not read as.
//!
//! Counters, the two lock-recovery helpers and the file-descriptor pre-warm live here so that
//! `lib.rs` is the runtime and its miss pipeline and nothing else. Nothing in this file makes a
//! DNS decision; everything in it is either a `Relaxed` atomic or a one-off at startup.

use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub(crate) struct DnsRuntimeStats {
    pub(crate) queries_total: AtomicU64,
    pub(crate) blocked_total: AtomicU64,
    pub(crate) cache_hits_total: AtomicU64,
    pub(crate) cache_expired_total: AtomicU64,
    pub(crate) upstream_failures_total: AtomicU64,
    pub(crate) stale_served_total: AtomicU64,
    pub(crate) cname_blocks_total: AtomicU64,
    pub(crate) dropped_total: AtomicU64,
    pub(crate) log_dropped_total: AtomicU64,
    pub(crate) cache_hit_latency_total_ns: AtomicU64,
    pub(crate) cache_hit_samples: AtomicU64,
    pub(crate) cache_miss_latency_total_ns: AtomicU64,
    pub(crate) cache_miss_samples: AtomicU64,
}

impl DnsRuntimeStats {
    pub(crate) fn record_hit(&self, elapsed: Duration) {
        self.cache_hit_latency_total_ns
            .fetch_add(saturating_ns(elapsed), Ordering::Relaxed);
        bump(&self.cache_hit_samples);
    }

    pub(crate) fn record_miss(&self, elapsed: Duration) {
        self.cache_miss_latency_total_ns
            .fetch_add(saturating_ns(elapsed), Ordering::Relaxed);
        bump(&self.cache_miss_samples);
    }
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn saturating_ns(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

pub(crate) fn average_ns(total: &AtomicU64, samples: u64) -> u64 {
    total
        .load(Ordering::Relaxed)
        .checked_div(samples)
        .unwrap_or(0)
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Grow the process's file-descriptor table to `slots` while the process is still
/// single-threaded. Returns how many descriptors were actually opened, which is fewer than
/// asked when `RLIMIT_NOFILE` is smaller.
///
/// Every upstream send binds a fresh UDP socket, and a retry wave against a dead upstream opens
/// a batch of them at once. Linux doubles the descriptor table on demand, and once a process has
/// more than one thread each doubling waits out an RCU grace period — 7 to 20 ms measured
/// here — with every concurrent `socket()` queued behind it. Four workers stuck in that wait is
/// four receive loops not answering hits. Opening and closing the descriptors before the
/// runtime spawns its workers pays for the growth once, when it is cheap; the table never
/// shrinks.
pub fn reserve_descriptor_table(slots: usize) -> usize {
    let Ok(anchor) = std::fs::File::open("/dev/null") else {
        return 0;
    };
    let mut held = Vec::with_capacity(slots);
    while held.len() < slots {
        match anchor.try_clone() {
            Ok(descriptor) => held.push(descriptor),
            Err(_) => break,
        }
    }
    held.len()
}

/// Read an `RwLock`, recovering the value even when the lock is poisoned.
///
/// Poisoning only signals that some thread panicked while holding the lock. The policy is swapped
/// wholesale — an `Arc` replacement — so the last committed value is still coherent, and
/// recovering it keeps one panicking task from taking DNS resolution down for the remaining life
/// of the process. Failing open is the right posture for a household resolver: losing the policy
/// should mean "resolve normally", never "take the network offline".
pub(crate) fn read_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// See [`read_recover`].
pub(crate) fn write_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::reserve_descriptor_table;

    #[test]
    fn reserving_descriptors_reports_how_many_were_opened() {
        assert_eq!(reserve_descriptor_table(0), 0);
        // Well inside any sane RLIMIT_NOFILE, so all of them fit.
        assert_eq!(reserve_descriptor_table(128), 128);
    }
}
