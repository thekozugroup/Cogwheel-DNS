//! Domain policy evaluation for Cogwheel.
//!
//! This is the leaf crate: [`evaluate`] turns a client scope and a domain name into a
//! [`Verdict`], and everything that filters DNS traffic (`cogwheel-lists`, `cogwheel-dns-core`,
//! the server) is built on top of it. No I/O, no clocks, no allocation on the query path.
//!
//! # Precedence
//!
//! [`evaluate`] applies these tiers in order; within a tier an allow beats a block:
//!
//! 1. the scope has filtering off (pause, or a bypassed device) — allow;
//! 2. the device's own rules ([`Scope::rules`]);
//! 3. the household rules ([`Policy::household`]);
//! 4. the [`PROTECTED_SUFFIXES`];
//! 5. list exceptions (`@@`) under the scope's mask;
//! 6. list blocks under the scope's mask, attributed to the lowest matching slot;
//! 7. otherwise allow.
//!
//! Explicit rules outrank the protected suffixes because a rule is a choice someone made on
//! purpose; a list entry covering `pool.ntp.org` is almost always an accident upstream.
//! [`evaluate_lists`] runs tiers 4–6 alone — that is the CNAME re-check and the "why?" probe.
//!
//! # Matching
//!
//! Every tier matches a name and its subdomains on a label boundary: `example.com` covers
//! `www.example.com` but not `notexample.com`. The only exception is a list entry inserted as
//! [`Pattern::Exact`] (hosts-file lines), which matches that one name.
//!
//! # Normalisation
//!
//! Rules and lookups must agree on case and trailing-dot form or matching silently fails.
//! [`normalize_domain`] is the one routine for both; the DNS runtime lowercases the query name
//! once when it builds the cache key, so [`evaluate`] never has to.

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

/// Domain suffixes that a subscribed blocklist is never allowed to take out.
///
/// Every entry is infrastructure a device needs in order to *stay* on the
/// network and to *tell you* what is wrong when it is not: resolver bootstrap
/// and captive-portal detection, NTP (a drifted clock fails certificate
/// validation for every TLS connection, and the symptom points nowhere near
/// DNS), and the certificate-status endpoints of the major CAs. Blocking any of
/// them looks nothing like "the ad blocker broke this site" -- it looks like
/// the device is broken -- which is why they are protected here rather than
/// left to whichever list happens to be subscribed.
///
/// These outrank subscribed lists, and only subscribed lists: a rule the
/// operator wrote by hand still wins, because that is a choice someone made
/// deliberately, whereas a list entry covering `pool.ntp.org` is almost always
/// an accident upstream. Deliberately absent are banking, government,
/// OS-vendor and health domains -- blocking those is bad, but it is visible,
/// attributable and reversible by the person who did it.
///
/// Matched on a label boundary, like every other suffix in this crate:
/// `time.apple.com` also covers `ntp.time.apple.com`, but never `notapple.com`.
pub const PROTECTED_SUFFIXES: [&str; 21] = [
    // Resolver bootstrap and connectivity checks.
    "one.one.one.one",
    "dns.google",
    "resolver1.opendns.com",
    "cloudflare-dns.com",
    "quad9.net",
    "connectivity-check.ubuntu.com",
    "captive.apple.com",
    "detectportal.firefox.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "connectivitycheck.gstatic.com",
    // Time. A wrong clock breaks TLS everywhere.
    "pool.ntp.org",
    "ntp.org",
    "time.apple.com",
    "time.windows.com",
    "time.google.com",
    // Certificate validation.
    "digicert.com",
    "letsencrypt.org",
    "sectigo.com",
    "globalsign.com",
    "identrust.com",
];

static PROTECTED_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| PROTECTED_SUFFIXES.into_iter().collect());

/// Scope id shared by unknown clients and by every device whose effective settings equal the
/// household's (filtering on, all lists, no device rules).
pub const SCOPE_HOUSEHOLD: u32 = 0;
/// Scope id for clients that are not filtered at all: the whole household while paused, and
/// devices with filtering switched off.
pub const SCOPE_UNFILTERED: u32 = 1;

/// How many label boundaries a lookup probes, counted from the right.
///
/// `a.b.c.example.com` probes `com`, `example.com`, `c.example.com`, … so a rule of up to this
/// many labels always matches, whatever the query's depth. Real rules have two to five labels;
/// the cap only bounds the work a pathological 127-label name can cause.
const MAX_BOUNDARIES: usize = 16;

/// What a client receives for a blocked name.
///
/// One value for the whole [`Policy`]: every block under it answers the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockMode {
    /// Answer with an all-zeros address (`0.0.0.0` / `::`) in place of the real one.
    #[serde(rename = "null_ip")]
    NullIp,
    /// Answer `NXDOMAIN`, as if the name did not exist.
    #[serde(rename = "nxdomain")]
    NxDomain,
    /// Answer `NOERROR` with an empty answer section.
    #[serde(rename = "nodata")]
    NoData,
    /// Answer `REFUSED`.
    #[serde(rename = "refused")]
    Refused,
}

impl BlockMode {
    /// The configuration spelling (`null_ip`, `nxdomain`, `nodata`, `refused`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NullIp => "null_ip",
            Self::NxDomain => "nxdomain",
            Self::NoData => "nodata",
            Self::Refused => "refused",
        }
    }
}

impl std::str::FromStr for BlockMode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, ()> {
        match value {
            "null_ip" => Ok(Self::NullIp),
            "nxdomain" => Ok(Self::NxDomain),
            "nodata" => Ok(Self::NoData),
            "refused" => Ok(Self::Refused),
            _ => Err(()),
        }
    }
}

/// Whether a rule or list entry allows or blocks the names it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Permit resolution. Beats `Block` within the same tier.
    Allow,
    /// Deny resolution, answered per the policy's [`BlockMode`].
    Block,
}

impl Action {
    /// The API and database spelling (`allow` / `block`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

impl std::str::FromStr for Action {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, ()> {
        match value {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            _ => Err(()),
        }
    }
}

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
/// exact probe plus [`MAX_BOUNDARIES`] suffix probes, each borrowing a slice of the query name.
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
    /// `name` must be normalised (see [`normalize_domain`]). No allocation.
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

/// User rules: a domain (covering its subdomains) mapped to one action.
///
/// One rule per domain — the server upserts on `(domain, device)`, so flipping allow to block
/// replaces rather than accumulates. Keys must be normalised with [`normalize_rule_domain`].
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
    /// The list slots that apply, ANDed against [`Masks`] on lookup.
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
    /// One of the [`PROTECTED_SUFFIXES`].
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

    /// The API spelling, identical to the serde form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatch => "no_match",
            Self::DeviceRule => "device_rule",
            Self::HouseholdRule => "household_rule",
            Self::Protected => "protected",
            Self::ListAllow => "list_allow",
            Self::List => "list",
            Self::Cname => "cname",
            Self::Paused => "paused",
            Self::Unfiltered => "unfiltered",
        }
    }
}

/// The outcome of evaluating one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Resolve normally.
    Allow(Reason),
    /// Answer per the policy's [`BlockMode`]. The `u8` is the list slot for
    /// [`Reason::List`] and [`Reason::Cname`] and carries nothing otherwise.
    Block(Reason, u8),
}

impl Verdict {
    /// Whether the name is blocked.
    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::Block(..))
    }

    /// Which tier decided.
    pub const fn reason(self) -> Reason {
        match self {
            Self::Allow(reason) | Self::Block(reason, _) => reason,
        }
    }

    /// The list slot a block is attributed to, for list-tier blocks only.
    pub const fn slot(self) -> Option<u8> {
        match self {
            Self::Block(Reason::List | Reason::Cname, slot) => Some(slot),
            _ => None,
        }
    }

    const fn from_rule(action: Action, reason: Reason) -> Self {
        match action {
            Action::Allow => Self::Allow(reason),
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
        return Verdict::Allow(Reason::Unfiltered);
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
        return Verdict::Allow(Reason::Protected);
    }
    let masks = policy.index.lookup(name);
    if masks.allow & mask != 0 {
        return Verdict::Allow(Reason::ListAllow);
    }
    let blocked = masks.block & mask;
    if blocked != 0 {
        return Verdict::Block(Reason::List, blocked.trailing_zeros() as u8);
    }
    Verdict::Allow(Reason::NoMatch)
}

/// Whether `name` is one of the [`PROTECTED_SUFFIXES`] or beneath one.
pub fn is_protected(name: &str) -> bool {
    boundaries(name).any(|candidate| PROTECTED_SET.contains(candidate))
}

/// `name` and each of its parents on a label boundary, shortest first, at most
/// [`MAX_BOUNDARIES`] of them: `com`, `example.com`, `www.example.com`.
fn boundaries(name: &str) -> impl Iterator<Item = &str> {
    name.rmatch_indices('.')
        .map(|(dot, _)| &name[dot + 1..])
        .chain(std::iter::once(name))
        .take(MAX_BOUNDARIES)
}

/// Canonicalise a domain the same way for both rule storage and lookup.
///
/// Trims whitespace, strips trailing root dots (`"example.com."` → `"example.com"`) and
/// lowercases ASCII. Every stored name and every looked-up name must have been through this, or
/// names that look identical to a human will not match.
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// [`normalize_domain`] for a user-entered rule: also drops a leading `*.`, since a rule already
/// covers its subdomains and people paste wildcards from other blockers.
pub fn normalize_rule_domain(domain: &str) -> String {
    let normalized = normalize_domain(domain);
    match normalized.strip_prefix("*.") {
        Some(bare) => bare.to_owned(),
        None => normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    type Entries<'a> = Vec<(Action, Pattern, &'a str)>;

    /// One list per slot; each list is `(action, pattern, domain)` entries.
    fn index_of(lists: &[Entries<'_>]) -> Arc<ListIndex> {
        let mut builder = ListIndex::builder();
        for (slot, entries) in lists.iter().enumerate() {
            let slot = u8::try_from(slot).expect("test lists fit in 64 slots");
            builder.name(slot, format!("list {slot}"));
            for (action, pattern, domain) in entries {
                builder.insert(slot, *action, *pattern, domain);
            }
        }
        Arc::new(builder.build())
    }

    fn blocklist<'a>(domains: &[&'a str]) -> Entries<'a> {
        domains
            .iter()
            .map(|domain| (Action::Block, Pattern::Suffix, *domain))
            .collect()
    }

    fn rules(entries: &[(&str, Action)]) -> Arc<RuleSet> {
        Arc::new(entries.iter().map(|(d, a)| (*d, *a)).collect())
    }

    fn all_mask(lists: usize) -> u64 {
        (1u64 << lists) - 1
    }

    /// A policy with only lists: the household scope sees every slot.
    fn list_policy(lists: &[Entries<'_>]) -> Policy {
        Policy::new(
            index_of(lists),
            Arc::new(RuleSet::new()),
            HashMap::new(),
            all_mask(lists.len()),
            BlockMode::NullIp,
        )
    }

    fn household_verdict(policy: &Policy, name: &str) -> Verdict {
        evaluate(policy, policy.scope(SCOPE_HOUSEHOLD), name)
    }

    /// The gap this closes: a blocklist covering an OCSP responder or an NTP
    /// pool could take a device off the network.
    #[test]
    fn a_protected_domain_outranks_a_blocklist_entry() {
        let policy = list_policy(&[blocklist(&["letsencrypt.org"])]);
        assert_eq!(
            household_verdict(&policy, "letsencrypt.org"),
            Verdict::Allow(Reason::Protected)
        );
    }

    /// Protection used to be an exact match, so the apex was covered and every
    /// name actually looked up during certificate validation was not.
    #[test]
    fn protection_covers_subdomains_not_just_the_apex() {
        let policy = list_policy(&[blocklist(&["letsencrypt.org"])]);
        for host in ["r3.letsencrypt.org", "ocsp.int-x3.letsencrypt.org"] {
            assert_eq!(
                household_verdict(&policy, host),
                Verdict::Allow(Reason::Protected),
                "{host} should be protected"
            );
        }
    }

    /// Suffix matching must stop at a label boundary, or protecting
    /// `apple.com` would quietly protect `evil-apple.com` too.
    #[test]
    fn protection_stops_at_a_label_boundary() {
        let policy = list_policy(&[blocklist(&["notapple.com", "evil-apple.com"])]);
        for host in ["notapple.com", "evil-apple.com"] {
            assert!(
                household_verdict(&policy, host).is_blocked(),
                "{host} must NOT inherit protection from apple.com"
            );
        }
    }

    #[test]
    fn an_unprotected_domain_is_still_blocked_normally() {
        let policy = list_policy(&[blocklist(&["doubleclick.net"])]);
        assert_eq!(
            household_verdict(&policy, "ads.doubleclick.net"),
            Verdict::Block(Reason::List, 0)
        );
    }

    /// Suffix matching must only match on a label boundary, and must not allocate to do it.
    #[test]
    fn suffix_entries_match_only_on_label_boundaries() {
        let policy = list_policy(&[blocklist(&["example.com"])]);
        for blocked in ["example.com", "ads.example.com", "a.b.example.com"] {
            assert!(
                household_verdict(&policy, blocked).is_blocked(),
                "{blocked} should match the suffix entry"
            );
        }
        for allowed in ["notexample.com", "example.com.evil.net", "myexample.com"] {
            assert_eq!(
                household_verdict(&policy, allowed),
                Verdict::Allow(Reason::NoMatch),
                "{allowed} must NOT match the suffix entry"
            );
        }
    }

    /// A hosts-file line names one host; its subdomains are not implied.
    #[test]
    fn exact_entries_do_not_cover_subdomains() {
        let policy = list_policy(&[vec![(Action::Block, Pattern::Exact, "ads.example.com")]]);
        assert!(household_verdict(&policy, "ads.example.com").is_blocked());
        assert!(!household_verdict(&policy, "www.ads.example.com").is_blocked());
        assert!(!household_verdict(&policy, "example.com").is_blocked());
    }

    #[test]
    fn allow_precedes_block() {
        let policy = list_policy(&[vec![
            (Action::Block, Pattern::Suffix, "ads.example.com"),
            (Action::Allow, Pattern::Exact, "ads.example.com"),
        ]]);
        assert_eq!(
            household_verdict(&policy, "ads.example.com"),
            Verdict::Allow(Reason::ListAllow)
        );

        let household = rules(&[
            ("example.com", Action::Allow),
            ("ads.example.com", Action::Block),
        ]);
        let policy = Policy::new(
            Arc::new(ListIndex::default()),
            household,
            HashMap::new(),
            0,
            BlockMode::NullIp,
        );
        assert_eq!(
            household_verdict(&policy, "ads.example.com"),
            Verdict::Allow(Reason::HouseholdRule)
        );
    }

    /// The fixed precedence: pause → filtering off → device rules → household rules →
    /// protected → list allow → list block → allow.
    #[test]
    fn precedence_table() {
        // Slot 0 blocks broadly (including a protected name); slot 1 carries the exceptions.
        let index = index_of(&[
            blocklist(&[
                "pool.ntp.org",
                "tracker.example",
                "example.com",
                "shared.example",
                "ads.example",
            ]),
            vec![
                (Action::Allow, Pattern::Suffix, "cdn.ads.example"),
                (Action::Block, Pattern::Suffix, "shared.example"),
            ],
        ]);
        let household = rules(&[
            ("pool.ntp.org", Action::Block),
            ("tracker.example", Action::Allow),
            ("home.example", Action::Block),
        ]);
        let device_rules = rules(&[
            ("home.example", Action::Allow),
            ("time.apple.com", Action::Block),
        ]);
        let device = Scope {
            id: 2,
            filtering: true,
            mask: 0b01,
            rules: Some(device_rules),
        };
        let mut by_ip = HashMap::new();
        by_ip.insert(CLIENT, device);
        let policy = Policy::new(index, household, by_ip, 0b11, BlockMode::NxDomain);
        let household_scope = policy.scope(SCOPE_HOUSEHOLD);
        let device_scope = policy.scope_for(CLIENT);
        let unfiltered = policy.scope(SCOPE_UNFILTERED);

        let table: &[(&Scope, &str, Verdict)] = &[
            // device block beats protected
            (
                device_scope,
                "ntp.time.apple.com",
                Verdict::Block(Reason::DeviceRule, 0),
            ),
            // device allow beats household block
            (
                device_scope,
                "home.example",
                Verdict::Allow(Reason::DeviceRule),
            ),
            (
                household_scope,
                "home.example",
                Verdict::Block(Reason::HouseholdRule, 0),
            ),
            // household block beats protected
            (
                household_scope,
                "pool.ntp.org",
                Verdict::Block(Reason::HouseholdRule, 0),
            ),
            // household allow beats a list block
            (
                household_scope,
                "tracker.example",
                Verdict::Allow(Reason::HouseholdRule),
            ),
            // protected beats a list block
            (
                household_scope,
                "time.google.com",
                Verdict::Allow(Reason::Protected),
            ),
            (
                device_scope,
                "time.google.com",
                Verdict::Allow(Reason::Protected),
            ),
            // list @@ beats a list block
            (
                household_scope,
                "cdn.ads.example",
                Verdict::Allow(Reason::ListAllow),
            ),
            (
                household_scope,
                "ads.example",
                Verdict::Block(Reason::List, 0),
            ),
            // ...unless the mask excludes the slot carrying the exception
            (
                device_scope,
                "cdn.ads.example",
                Verdict::Block(Reason::List, 0),
            ),
            // a block is attributed to the lowest slot inside the mask
            (
                household_scope,
                "shared.example",
                Verdict::Block(Reason::List, 0),
            ),
            // a suffix entry covers subdomains but not a longer-label lookalike
            (
                household_scope,
                "www.example.com",
                Verdict::Block(Reason::List, 0),
            ),
            (
                household_scope,
                "notexample.com",
                Verdict::Allow(Reason::NoMatch),
            ),
            // the unfiltered scope allows everything without probing
            (
                unfiltered,
                "pool.ntp.org",
                Verdict::Allow(Reason::Unfiltered),
            ),
            (
                unfiltered,
                "tracker.example",
                Verdict::Allow(Reason::Unfiltered),
            ),
            (
                unfiltered,
                "home.example",
                Verdict::Allow(Reason::Unfiltered),
            ),
        ];
        for (scope, name, expected) in table {
            assert_eq!(
                evaluate(&policy, scope, name),
                *expected,
                "{name} in scope {}",
                scope.id
            );
        }
    }

    #[test]
    fn a_mask_excludes_a_slot_and_attribution_skips_it() {
        let policy = list_policy(&[blocklist(&["ads.example"]), blocklist(&["ads.example"])]);
        assert_eq!(
            evaluate_lists(&policy, 0b11, "ads.example"),
            Verdict::Block(Reason::List, 0)
        );
        assert_eq!(
            evaluate_lists(&policy, 0b10, "ads.example"),
            Verdict::Block(Reason::List, 1)
        );
        assert_eq!(
            evaluate_lists(&policy, 0, "ads.example"),
            Verdict::Allow(Reason::NoMatch)
        );
        assert_eq!(policy.index.name(1).map(|n| &**n), Some("list 1"));
        assert_eq!(policy.index.name(2), None);
    }

    #[test]
    fn reserved_and_unknown_scope_ids_resolve() {
        let policy = list_policy(&[blocklist(&["ads.example"])]);
        assert_eq!(policy.scope(SCOPE_HOUSEHOLD).mask, 0b1);
        assert!(policy.scope(SCOPE_HOUSEHOLD).filtering);
        assert!(!policy.scope(SCOPE_UNFILTERED).filtering);
        assert_eq!(policy.scope(99).id, SCOPE_HOUSEHOLD);
        assert_eq!(policy.scope_for(CLIENT).id, SCOPE_HOUSEHOLD);
        assert!(!evaluate(&policy, policy.scope(SCOPE_UNFILTERED), "ads.example").is_blocked());
    }

    #[test]
    fn an_empty_policy_allows_everything() {
        let policy = Policy::empty(BlockMode::Refused);
        assert_eq!(
            household_verdict(&policy, "ads.example"),
            Verdict::Allow(Reason::NoMatch)
        );
        assert!(policy.index.is_empty());
        assert_eq!(policy.block_mode, BlockMode::Refused);
    }

    #[test]
    fn a_trailing_root_dot_is_tolerated_on_lookup() {
        let policy = list_policy(&[blocklist(&["ads.example"])]);
        assert!(household_verdict(&policy, "ads.example.").is_blocked());
        assert!(evaluate_lists(&policy, u64::MAX, "www.ads.example.").is_blocked());
    }

    #[test]
    fn verdict_slot_is_only_reported_for_list_blocks() {
        assert_eq!(Verdict::Block(Reason::List, 3).slot(), Some(3));
        assert_eq!(Verdict::Block(Reason::Cname, 3).slot(), Some(3));
        assert_eq!(Verdict::Block(Reason::DeviceRule, 0).slot(), None);
        assert_eq!(Verdict::Allow(Reason::NoMatch).slot(), None);
        assert_eq!(Verdict::Block(Reason::Cname, 3).reason(), Reason::Cname);
    }

    #[test]
    fn reason_round_trips_through_its_stored_form() {
        for value in 0..=8u8 {
            let reason = Reason::from_u8(value).expect("every code below 9 is a reason");
            assert_eq!(reason.as_u8(), value);
            assert_eq!(
                serde_json::to_string(&reason).expect("serialises"),
                format!("\"{}\"", reason.as_str())
            );
        }
        assert_eq!(Reason::from_u8(9), None);
    }

    #[test]
    fn rule_set_upserts_and_walks_boundaries() {
        let mut set = RuleSet::new();
        assert_eq!(set.insert("example.com", Action::Block), None);
        assert_eq!(
            set.insert("example.com", Action::Allow),
            Some(Action::Block)
        );
        assert_eq!(set.len(), 1);
        assert_eq!(set.get("example.com"), Some(Action::Allow));
        assert_eq!(set.get("www.example.com"), None);
        assert_eq!(
            set.get_at_boundaries("www.example.com"),
            Some(Action::Allow)
        );
        assert_eq!(set.get_at_boundaries("notexample.com"), None);
        assert_eq!(set.iter().count(), 1);
    }

    #[test]
    fn deep_names_still_match_short_rules() {
        let deep = "a.".repeat(40) + "example.com";
        let policy = list_policy(&[blocklist(&["example.com"])]);
        assert!(household_verdict(&policy, &deep).is_blocked());
        assert!(is_protected(&("x.".repeat(30) + "pool.ntp.org")));
    }

    #[test]
    fn slots_beyond_the_mask_width_are_ignored() {
        let mut builder = ListIndex::builder();
        builder.insert(64, Action::Block, Pattern::Suffix, "ads.example");
        builder.name(64, "overflow");
        let index = builder.build();
        assert!(index.is_empty());
        assert!(index.names().is_empty());
    }

    #[test]
    fn normalisation() {
        assert_eq!(normalize_domain("  Example.COM. "), "example.com");
        assert_eq!(normalize_rule_domain("*.Example.com"), "example.com");
        assert_eq!(normalize_rule_domain("example.com"), "example.com");
        assert_eq!("nxdomain".parse::<BlockMode>(), Ok(BlockMode::NxDomain));
        assert_eq!(BlockMode::NullIp.as_str(), "null_ip");
        assert_eq!("block".parse::<Action>(), Ok(Action::Block));
        assert_eq!(
            serde_json::to_string(&BlockMode::NoData).expect("serialises"),
            "\"nodata\""
        );
        assert_eq!(
            serde_json::to_string(&Action::Allow).expect("serialises"),
            "\"allow\""
        );
    }
}
