//! What every handler and background task shares.
//!
//! The state is all `Arc`s and cheap to clone, because axum hands each handler its own copy.
//! Two things in here outlive any single request and are the reason this type exists rather
//! than a bag of globals: the scope allocator, whose ids are baked into DNS cache keys and must
//! therefore survive a policy rebuild, and the refresh gate, which is what stops two list
//! refreshes from running at once.

use crate::config::AppConfig;
use crate::http::{ApiError, Readiness};
use crate::querylog::EventBus;
use cogwheel_dns_core::DnsRuntime;
use cogwheel_policy::{Action, RuleSet, SCOPE_HOUSEHOLD, SCOPE_UNFILTERED};
use cogwheel_storage::Storage;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Minimum gap between two manual refreshes (§2.7). Long enough that a double-click is one
/// refresh, short enough that a person fixing a list URL is not left waiting.
pub const MANUAL_REFRESH_GAP: Duration = Duration::from_secs(30);

/// How long the Overview's top-domain tables are reused before the log is scanned again (§7).
pub const TOP_DOMAIN_TTL: Duration = Duration::from_secs(60);

/// Device names by address, for attributing live query frames.
///
/// Rebuilt whole on every policy build and handed over as one `Arc`, so the query-log writer
/// reads a consistent snapshot without locking per entry. The device id §6 step 5 pairs with the
/// name is dropped: the only consumer is the SSE frame of §3 route 8, which carries `deviceName`
/// and no id.
pub type DeviceNames = HashMap<IpAddr, Arc<str>>;

/// Unix seconds, the clock every timestamp on the wire and in the database uses.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// A value recomputed at most once per interval, behind its own lock.
///
/// Used for the two things on the Overview that are expensive and do not need to be exact: the
/// top-domain scans over the query log, and the `hostname -I` shell-out. The page polls every
/// five seconds; neither answer changes meaningfully that fast.
///
/// It owns the mutex rather than being wrapped in one, so a caller cannot hold the lock across
/// the `await` that recomputes the value — which is the mistake this shape exists to prevent,
/// and the reason every method takes `&self`.
#[derive(Debug)]
pub struct Cached<T> {
    slot: Mutex<Option<(Instant, T)>>,
    ttl: Duration,
}

impl<T: Clone> Cached<T> {
    /// An empty cache with this refresh interval.
    pub const fn new(ttl: Duration) -> Self {
        Self {
            slot: Mutex::new(None),
            ttl,
        }
    }

    /// The stored value, if it is still current.
    pub fn get(&self) -> Option<T> {
        lock(&self.slot)
            .as_ref()
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, value)| value.clone())
    }

    /// Store a freshly computed value.
    pub fn set(&self, value: T) {
        *lock(&self.slot) = Some((Instant::now(), value));
    }

    /// Forget it, so the next read recomputes.
    pub fn clear(&self) {
        *lock(&self.slot) = None;
    }
}

/// The settings that make one device's filtering differ from another's: filtering on or off,
/// the list slots that apply, and its own rules in a canonical order (§6 step 3).
type ScopeSignature = (bool, u64, Vec<(Box<str>, Action)>);

/// Hands out cache-scope ids by signature, so devices with identical settings share one.
///
/// This lives in [`ServerState`] rather than being rebuilt with each policy because the ids are
/// baked into DNS cache keys. A device edit keeps the cache, so an id that meant "these rules"
/// before the edit must not mean different rules after it: a device whose settings changed gets
/// a fresh id and its old entries age out unread. Ids are never reused. A list rebuild or a
/// household-rule change — which drops the cache anyway — starts a fresh table, because the same
/// mask value no longer names the same lists.
#[derive(Debug)]
pub struct ScopeAllocator {
    by_signature: HashMap<ScopeSignature, u32>,
    next: u32,
}

impl ScopeAllocator {
    /// An allocator that has handed out nothing but the two reserved ids.
    pub fn new() -> Self {
        Self {
            by_signature: HashMap::new(),
            next: SCOPE_UNFILTERED + 1,
        }
    }

    /// Forget every signature; the next rebuild interns afresh, above every id ever handed out.
    pub fn reset(&mut self) {
        self.by_signature.clear();
    }

    /// The scope id for a device with these settings (§6 step 4).
    ///
    /// A device whose settings equal the household's shares the household's scope and its
    /// cache, so a family of default devices costs nothing extra; filtering off is the reserved
    /// unfiltered scope whatever else is set.
    pub fn scope_id(&mut self, all_mask: u64, filtering: bool, mask: u64, rules: &RuleSet) -> u32 {
        if !filtering {
            return SCOPE_UNFILTERED;
        }
        if mask == all_mask && rules.is_empty() {
            return SCOPE_HOUSEHOLD;
        }
        let mut sorted = rules
            .iter()
            .map(|(domain, action)| (Box::<str>::from(domain), action))
            .collect::<Vec<_>>();
        sorted.sort_by(|left, right| left.0.cmp(&right.0));
        let Self { by_signature, next } = self;
        *by_signature
            .entry((filtering, mask, sorted))
            .or_insert_with(|| {
                let id = *next;
                // Saturating rather than wrapping: reaching u32::MAX would take billions of
                // edits, and reusing id 2 after that would hand a device somebody else's
                // cached answers.
                *next = next.saturating_add(1);
                id
            })
    }
}

impl Default for ScopeAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialises everything that touches a list body: one pass in flight, and a minimum gap between
/// manual refreshes (§2.7).
///
/// It is a lock and not a flag because list *edits* have to take it too. Deleting a list, or
/// repointing one at a new url, deletes the cached body — and a scheduler pass already inside
/// `refresh_one` for that same id would then write the body it had been fetching back over the
/// top, stamping `last_ok_at` on a row the user has just changed. The list the user replaced
/// would keep filtering for a whole refresh interval, with a green "Last updated" beside it.
#[derive(Debug, Default)]
pub struct RefreshGate {
    running: tokio::sync::Mutex<()>,
    last_manual: Mutex<Option<Instant>>,
}

/// Held for the duration of a refresh or a list edit; releases the gate however it ends.
pub type RefreshLease<'a> = tokio::sync::MutexGuard<'a, ()>;

impl RefreshGate {
    /// Claim the gate without waiting — what the scheduler and `POST /lists/refresh` do.
    ///
    /// # Errors
    ///
    /// 429 when a pass is already running, or when a manual refresh arrives inside
    /// [`MANUAL_REFRESH_GAP`] of the previous one.
    pub fn begin(&self, manual: bool) -> Result<RefreshLease<'_>, ApiError> {
        if manual && let Some(last) = *lock(&self.last_manual) {
            let elapsed = last.elapsed();
            if elapsed < MANUAL_REFRESH_GAP {
                let wait = (MANUAL_REFRESH_GAP - elapsed).as_secs() + 1;
                return Err(ApiError::too_many_requests(format!(
                    "Lists were refreshed a moment ago; try again in {wait} seconds."
                )));
            }
        }
        let lease = self
            .running
            .try_lock()
            .map_err(|_| ApiError::too_many_requests("A list refresh is already running."))?;
        if manual {
            *lock(&self.last_manual) = Some(Instant::now());
        }
        Ok(lease)
    }

    /// Claim the gate, waiting for an in-flight pass — what a list edit does.
    ///
    /// Waiting rather than refusing because the alternative is a 409 on a button the user is
    /// entitled to press, and the wait is bounded by the fetch timeout.
    pub async fn acquire(&self) -> RefreshLease<'_> {
        self.running.lock().await
    }
}

/// The Overview's two top-ten tables, memoized together because they are one scan apiece.
pub type TopDomains = (
    Vec<cogwheel_storage::DomainCount>,
    Vec<cogwheel_storage::DomainCount>,
);

/// Everything shared between handlers and background tasks.
#[derive(Clone)]
pub struct ServerState {
    pub config: Arc<AppConfig>,
    pub storage: Storage,
    pub runtime: Arc<DnsRuntime>,
    pub readiness: Arc<Readiness>,
    pub events: EventBus,
    /// Where the list bodies of §2.6 are cached.
    pub lists_dir: Arc<PathBuf>,
    /// Device names by address, replaced wholesale by each policy build.
    pub device_names: Arc<RwLock<Arc<DeviceNames>>>,
    /// The enabled source ids, in slot order, that the installed index was built from.
    ///
    /// Slot order is `sources.id` ascending and the ids are random uuids, so a list added in the
    /// middle of that order shifts every slot after it. A rebuild that reuses the index has to
    /// know the enabled set has not moved under it, or a device's mask would name the wrong
    /// lists — this is what it compares against.
    pub indexed_lists: Arc<RwLock<Vec<String>>>,
    pub scopes: Arc<Mutex<ScopeAllocator>>,
    /// Serialises policy rebuilds, so a device edit landing mid-refresh cannot install a policy
    /// compiled from the lists the refresh is about to replace.
    pub rebuild_lock: Arc<tokio::sync::Mutex<()>>,
    pub refresh_gate: Arc<RefreshGate>,
    pub top_domains: Arc<Cached<TopDomains>>,
    /// Addresses to point a router at, memoized because discovering them shells out.
    pub connect_targets: Arc<Cached<Vec<String>>>,
    pub http: reqwest::Client,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

impl ServerState {
    /// The device-name snapshot the query-log writer attributes frames with.
    pub fn device_names(&self) -> Arc<DeviceNames> {
        Arc::clone(&read(&self.device_names))
    }

    /// Install a fresh device-name snapshot (§6 step 5).
    pub fn set_device_names(&self, names: DeviceNames) {
        *write(&self.device_names) = Arc::new(names);
    }
}

/// Resolve once the shutdown signal has been sent.
///
/// A thin wrapper because `watch::Receiver::wait_for` yields a borrow guard, and holding that
/// type inside a `tokio::select!` arm makes the whole task future non-`Send` — which only shows
/// up as an error at the `tokio::spawn` on the other side of the program.
pub async fn stopped(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stopping| *stopping).await;
}

/// Read an `RwLock`, recovering the value even when the lock is poisoned.
///
/// Poisoning only records that some thread panicked while holding the lock. Everything guarded
/// this way is replaced wholesale, so the last committed value is still coherent, and recovering
/// it keeps one panicking request from disabling the control plane for the life of the process.
pub fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write to an `RwLock`, recovering the value even when the lock is poisoned. See [`read`].
pub fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Lock a `Mutex`, recovering the value even when it is poisoned. See [`read`].
pub fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{Cached, RefreshGate, ScopeAllocator};
    use cogwheel_policy::{Action, RuleSet, SCOPE_HOUSEHOLD, SCOPE_UNFILTERED};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn a_device_matching_the_household_shares_its_scope() {
        let mut scopes = ScopeAllocator::new();
        assert_eq!(
            scopes.scope_id(0b11, true, 0b11, &RuleSet::new()),
            SCOPE_HOUSEHOLD
        );
        assert_eq!(
            scopes.scope_id(0b11, false, 0b11, &RuleSet::new()),
            SCOPE_UNFILTERED
        );
    }

    #[test]
    fn identical_devices_share_an_id_and_an_edit_takes_a_fresh_one() {
        let mut scopes = ScopeAllocator::new();
        let mut rules = RuleSet::new();
        rules.insert("ads.example.com", Action::Block);
        let first = scopes.scope_id(0b11, true, 0b01, &rules);
        let second = scopes.scope_id(0b11, true, 0b01, &rules);
        assert_eq!(first, second, "same signature, same scope");

        rules.insert("more.example.com", Action::Block);
        let edited = scopes.scope_id(0b11, true, 0b01, &rules);
        assert_ne!(edited, first, "an edit must not inherit cached answers");

        scopes.reset();
        let after_reset = scopes.scope_id(0b11, true, 0b01, &rules);
        assert!(
            after_reset > edited,
            "a list rebuild must never reuse an id that meant different lists"
        );
    }

    #[test]
    fn one_refresh_runs_at_a_time() {
        let gate = Arc::new(RefreshGate::default());
        let lease = gate.begin(false).expect("first refresh starts");
        let refused = gate.begin(false).expect_err("second refresh is refused");
        assert_eq!(refused.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        drop(lease);
        drop(
            gate.begin(false)
                .expect("the gate reopens when the lease drops"),
        );
    }

    #[tokio::test]
    async fn a_list_edit_waits_for_the_pass_it_would_have_raced() {
        let gate = RefreshGate::default();
        let pass = gate.begin(false).expect("a scheduled pass starts");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), gate.acquire())
                .await
                .is_err(),
            "an edit must not delete a body while a pass is fetching it"
        );
        drop(pass);
        let _edit = tokio::time::timeout(Duration::from_millis(50), gate.acquire())
            .await
            .expect("the gate reopens when the pass ends");
    }

    #[test]
    fn a_manual_refresh_inside_the_gap_is_refused() {
        let gate = Arc::new(RefreshGate::default());
        drop(gate.begin(true).expect("first manual refresh"));
        let refused = gate.begin(true).expect_err("second manual refresh");
        assert_eq!(refused.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        // The scheduler is not subject to the manual gap.
        drop(gate.begin(false).expect("a scheduled refresh still runs"));
    }

    #[test]
    fn a_cached_value_expires() {
        let cached = Cached::new(Duration::from_millis(0));
        cached.set(7);
        assert_eq!(cached.get(), None, "a zero ttl is always stale");

        let cached = Cached::new(Duration::from_secs(60));
        assert_eq!(cached.get(), None);
        cached.set(7);
        assert_eq!(cached.get(), Some(7));
        cached.clear();
        assert_eq!(cached.get(), None);
    }
}
