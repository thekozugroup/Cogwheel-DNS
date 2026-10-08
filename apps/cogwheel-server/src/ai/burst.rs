//! Site loads (§6.5): each device's lookups grouped into bursts, and the website each burst opened
//! picked out. Pure: the clock is passed in.
//!
//! DNS carries no referrer, so this is a stated heuristic. Opening a page makes a device look up
//! the website's name and then, within a few seconds, every name the page pulls in; a few quiet
//! seconds end it. The website (the anchor) is the name most of the others share a site with,
//! never one that was blocked, so a tracker can never be the context another name is judged in.
//! Client addresses are keys in memory and nothing more: a load carries one only for the
//! per-client cap, and no request ever does.

use super::Seen;
use super::site::site_key;
use cogwheel_policy::Reason;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

/// Seconds of quiet that end a burst.
pub const QUIET: i64 = 3;
/// The longest a burst lasts, in seconds.
pub const SPAN: i64 = 15;
/// How late a lookup can reach the log: a miss is logged when it completes, up to about 4 s after
/// it was admitted (2 s for each of two upstream attempts), stamped with its admission time.
pub const LATE: i64 = 4;
/// Distinct names a burst keeps.
pub const MAX_NAMES: usize = 32;
/// Open bursts, one per device. Past this the oldest is closed early.
pub const MAX_CLIENTS: usize = 256;
/// Closed bursts waiting for the next tick. Past this the oldest waiting is dropped and counted.
pub const MAX_CLOSED: usize = MAX_CLIENTS;

/// One name a burst looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Looked {
    pub domain: Arc<str>,
    /// Blocked for this device at any sighting in the burst.
    pub blocked: bool,
    pub reason: Reason,
    /// Unix seconds of its earliest sighting.
    pub first_ts: u32,
}

/// A closed burst with its website picked out: what the reviewer draws candidates from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteLoad {
    /// The device, for the per-client cap only. Never sent.
    pub client: IpAddr,
    /// The website that was opened (a guess).
    pub anchor: Arc<str>,
    pub anchor_key: Box<str>,
    /// Every other name, in first-seen order. Never the anchor: "is evil.com core to evil.com?"
    /// is a tautology, so the anchor is judged when it shows up in another website's load.
    pub members: Vec<Looked>,
}

/// One device's open burst.
#[derive(Debug, Clone)]
struct Burst {
    client: IpAddr,
    start: i64,
    last: i64,
    names: Vec<Looked>,
}

/// Every device's open burst, and the bursts closed since the last tick.
#[derive(Debug, Default)]
pub struct Bursts {
    open: HashMap<IpAddr, Burst>,
    /// Closed by `push` (a gap, the span, or the client table filling) and scored at the next
    /// tick, under that tick's policy.
    closed: VecDeque<Burst>,
    dropped: u64,
}

impl Bursts {
    /// Add one answered lookup to its device's burst. It joins the open burst when
    /// `start - LATE ≤ ts ≤ min(last + QUIET, start + SPAN)`; one older than that is dropped;
    /// one newer closes the open burst and starts the next.
    pub fn push(&mut self, seen: Seen) {
        let ts = i64::from(seen.ts);
        if let Some(burst) = self.open.get_mut(&seen.client) {
            if ts < burst.start - LATE {
                return;
            }
            if ts <= (burst.last + QUIET).min(burst.start + SPAN) {
                burst.add(seen);
                return;
            }
        }
        if let Some(burst) = self.open.remove(&seen.client) {
            self.close(burst);
        } else if self.open.len() >= MAX_CLIENTS
            && let Some(oldest) = self
                .open
                .values()
                .min_by_key(|burst| (burst.start, burst.last))
                .map(|burst| burst.client)
            && let Some(burst) = self.open.remove(&oldest)
        {
            self.close(burst);
        }
        self.open.insert(
            seen.client,
            Burst {
                client: seen.client,
                start: ts,
                last: ts,
                names: vec![Looked::from(seen)],
            },
        );
    }

    /// Close every burst that is over at `now`, and turn each burst closed since the last tick
    /// into a site load. `shareable` says whether a name may be sent; only a shareable name that
    /// was not blocked can be the website. Bursts with no such name, or nothing besides it, are
    /// discarded.
    pub fn tick(&mut self, now: i64, shareable: impl Fn(&str) -> bool) -> Vec<SiteLoad> {
        let due: Vec<IpAddr> = self
            .open
            .values()
            .filter(|burst| burst.over(now))
            .map(|burst| burst.client)
            .collect();
        let mut over: Vec<Burst> = due
            .iter()
            .filter_map(|client| self.open.remove(client))
            .collect();
        // Oldest first, so the same lookups give the same loads in the same order.
        over.sort_by_key(|burst| (burst.start, burst.client));
        for burst in over {
            self.close(burst);
        }
        self.closed
            .drain(..)
            .filter_map(|burst| burst.site_load(&shareable))
            .collect()
    }

    /// Forget every burst, open or closed: review was halted, or Clear log ran.
    pub fn clear(&mut self) {
        self.open.clear();
        self.closed.clear();
    }

    /// Bursts open or waiting for a tick.
    pub fn len(&self) -> usize {
        self.open.len() + self.closed.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Closed bursts dropped because too many were waiting for a tick.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    fn close(&mut self, burst: Burst) {
        if self.closed.len() >= MAX_CLOSED {
            self.closed.pop_front();
            self.dropped += 1;
        }
        self.closed.push_back(burst);
    }
}

impl From<Seen> for Looked {
    fn from(seen: Seen) -> Self {
        Self {
            domain: seen.domain,
            blocked: seen.blocked,
            reason: seen.reason,
            first_ts: seen.ts,
        }
    }
}

impl Burst {
    /// One more sighting: a name already in the burst is not added twice, and past
    /// [`MAX_NAMES`] a new one is not kept, though it still keeps the burst open.
    fn add(&mut self, seen: Seen) {
        self.last = self.last.max(i64::from(seen.ts));
        if let Some(looked) = self
            .names
            .iter_mut()
            .find(|looked| looked.domain == seen.domain)
        {
            looked.first_ts = looked.first_ts.min(seen.ts);
            // Blocked once is blocked: such a name can never be the website.
            if seen.blocked && !looked.blocked {
                looked.blocked = true;
                looked.reason = seen.reason;
            }
        } else if self.names.len() < MAX_NAMES {
            self.names.push(Looked::from(seen));
        }
    }

    /// Whether the burst is over at `now`, leaving [`LATE`] for misses still to be logged.
    const fn over(&self, now: i64) -> bool {
        now >= self.last + QUIET + LATE || now >= self.start + SPAN + LATE
    }

    /// Pick the website and return the rest. A name's score is the number of names in the burst
    /// that share its site key, plus 2 for the earliest name that could be the website, plus 1 for
    /// a `www` name or a site's own name; the highest wins and a tie goes to the earliest.
    fn site_load(mut self, shareable: &impl Fn(&str) -> bool) -> Option<SiteLoad> {
        // Stable, so arrival order breaks a tie in time.
        self.names.sort_by_key(|looked| looked.first_ts);
        let keys: Vec<&str> = self
            .names
            .iter()
            .map(|looked| site_key(&looked.domain))
            .collect();
        let mut best: Option<(usize, usize)> = None;
        let mut earliest = true;
        for (index, (looked, key)) in self.names.iter().zip(&keys).enumerate() {
            if looked.blocked || !shareable(&looked.domain) {
                continue;
            }
            let mut score = keys.iter().filter(|other| *other == key).count();
            if earliest {
                score += 2;
                earliest = false;
            }
            if looked.domain.starts_with("www.") || *looked.domain == **key {
                score += 1;
            }
            if best.is_none_or(|(top, _)| score > top) {
                best = Some((score, index));
            }
        }
        let (_, index) = best?;
        if self.names.len() < 2 {
            return None;
        }
        let anchor_key = Box::from(keys[index]);
        let anchor = self.names.remove(index).domain;
        Some(SiteLoad {
            client: self.client,
            anchor,
            anchor_key,
            members: self.names,
        })
    }
}
