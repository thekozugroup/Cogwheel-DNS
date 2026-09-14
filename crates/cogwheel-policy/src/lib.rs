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
use std::collections::HashSet;
use std::sync::LazyLock;

mod evaluate;
mod index;
mod ruleset;
#[cfg(test)]
mod tests;

pub use evaluate::{Reason, Verdict, evaluate, evaluate_lists};
pub use index::{ListIndex, ListIndexBuilder, Masks, Pattern};
pub use ruleset::{Policy, RuleSet, Scope};

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

/// Whether `name` is one of the [`PROTECTED_SUFFIXES`] or beneath one.
pub fn is_protected(name: &str) -> bool {
    boundaries(name).any(|candidate| PROTECTED_SET.contains(candidate))
}

/// `name` and each of its parents on a label boundary, shortest first, at most
/// [`MAX_BOUNDARIES`] of them: `com`, `example.com`, `www.example.com`.
pub(crate) fn boundaries(name: &str) -> impl Iterator<Item = &str> {
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

/// Whether a normalised name is `^[a-z0-9_-]+(\.[a-z0-9_-]+)+$` — two or more labels of the
/// characters a name can hold.
///
/// Here rather than at one API handler because "a domain" has to mean the same thing everywhere
/// a person types one: a string that `POST /rules` refuses must not be a string `GET /check`
/// answers confidently about. Punycode (`xn--…`) passes; a URL, an address with a port and a
/// bare TLD do not.
///
/// The underscore widens §3 route 14's regex by one character, deliberately. Underscore labels
/// are what discovery protocols are built out of — `_dns.resolver.arpa` is queried by every
/// current iOS and Windows stub, `_dmarc.<domain>` by every mail check — so they show up in the
/// query log, and a name a person can see in Activity has to be one they can ask "why?" about
/// and write a rule for. Refusing them would have made the two the spec was reconciling differ
/// again, in the other direction.
#[must_use]
pub fn is_domain_shaped(domain: &str) -> bool {
    let mut count = 0;
    for label in domain.split('.') {
        if label.is_empty()
            || !label.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
        {
            return false;
        }
        count += 1;
    }
    count >= 2 && domain.len() <= 253
}
