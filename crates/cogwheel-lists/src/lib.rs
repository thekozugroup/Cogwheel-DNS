//! Turning blocklist/allowlist sources into a compiled [`cogwheel_policy::RulesetArtifact`].
//!
//! This is a control-plane crate — it fetches over HTTP, so it is deliberately not on the DNS hot
//! path. The pipeline it implements:
//!
//! 1. [`fetch_and_parse_source`] (or [`parse_source`] directly, for an already-fetched body) turns
//!    one [`SourceDefinition`] into a [`ParsedSource`] of [`Rule`]s, tolerating bad lines rather
//!    than failing the whole source outright.
//! 2. [`verify_candidate`] checks a batch of [`ParsedSource`]s for signs of a bad or hostile
//!    upstream list — see its own docs — before anything is promoted.
//! 3. [`compile_ruleset`] / [`build_policy_engine`] flatten verified sources into a
//!    [`RulesetArtifact`] / [`PolicyEngine`] ready to serve queries.
//!
//! # Untrusted input
//!
//! A source's body is attacker-influenced: the operator picks the URL, but whoever controls that
//! URL controls the payload. [`fetch_and_parse_source`] enforces [`MAX_SOURCE_BODY_BYTES`] for
//! exactly this reason — see its docs for the incident that established the bound.

#![warn(missing_docs)]

use base64::Engine;
use chrono::{DateTime, Utc};
use cogwheel_policy::{
    BlockMode, DecisionKind, PolicyEngine, Rule, RuleAction, RulePattern, RulesetArtifact,
    normalize_domain,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use url::Url;
use uuid::Uuid;

/// The line format a [`SourceDefinition`] should be parsed as.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceKind {
    /// One domain per line, blocked exactly (no wildcards).
    Domains,
    /// `/etc/hosts` format (`<ip> <hostname> ...`); only the hostname field is used.
    Hosts,
    /// Adblock Plus filter syntax (`||domain^` blocks, `@@` exceptions). Modifier rules (`$...`)
    /// and path/regex rules are rejected rather than approximated.
    Adblock,
}

/// A configured blocklist/allowlist source, as the operator defined it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDefinition {
    /// Stable identifier for this source.
    pub id: Uuid,
    /// Operator-facing display name; also stamped onto every [`Rule`] it produces, via
    /// [`Rule::source`], for attribution in a matched [`cogwheel_policy::Decision`].
    pub name: String,
    /// Where to fetch the list from. A `data:` URL marks a source with an inline body rather than
    /// a remote fetch.
    pub url: Url,
    /// Line format to parse the fetched body as.
    pub kind: SourceKind,
    /// Whether this source currently contributes rules. Disabling is expected to be enforced by
    /// the caller (e.g. by not including the source in a fetch batch) rather than by this crate.
    pub enabled: bool,
    /// Free-form, lowercased name of the policy profile this source belongs to. Sources sharing a
    /// profile are compiled into one named [`PolicyEngine`] that a device can be pinned to.
    pub profile: String,
    /// Which invalid-line-ratio threshold this source is held to; see [`verify_candidate`] for
    /// the mapping from strictness name to threshold.
    pub verification_strictness: String,
}

/// One source's rules after fetching and parsing, ready to be checked by [`verify_candidate`]
/// and folded into a ruleset by [`compile_ruleset`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSource {
    /// The source this was parsed from.
    pub source: SourceDefinition,
    /// When parsing happened (not necessarily when the body was fetched over the network).
    pub fetched_at: DateTime<Utc>,
    /// Reserved for conditional-GET support; always `None` today, since fetching neither sends
    /// nor records an ETag.
    pub etag: Option<String>,
    /// Hex SHA-256 of the raw body bytes.
    pub checksum: String,
    /// Rules successfully parsed from this source.
    pub rules: Vec<Rule>,
    /// Number of lines that failed to parse as a rule and were skipped rather than aborting the
    /// parse. Feeds the invalid-line ratio checked by [`verify_candidate`].
    pub invalid_lines: usize,
}

/// Outcome of [`verify_candidate`] for a batch of parsed sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// `true` only when `notes` is empty. `false` means this candidate must **not** be promoted
    /// to the live ruleset.
    pub passed: bool,
    /// Aggregate invalid-line ratio across every source checked.
    pub invalid_ratio: f32,
    /// Protected domains that this candidate would block if it were promoted.
    pub blocked_protected_domains: Vec<String>,
    /// Human-readable reasons the candidate failed verification. Empty if and only if `passed`.
    pub notes: Vec<String>,
}

/// Fetch a source over HTTP(S) and parse it into rules.
///
/// # Errors
///
/// Returns [`FetchError::TooLarge`] if the body exceeds [`MAX_SOURCE_BODY_BYTES`], or
/// [`FetchError::Http`] for transport and status failures.
pub async fn fetch_and_parse_source(
    client: &Client,
    source: SourceDefinition,
) -> Result<ParsedSource, FetchError> {
    let body = fetch_source_body(client, &source.url).await?;
    Ok(parse_source(source, &body))
}

/// Parse a fetched body into rules, tolerating bad lines instead of failing.
///
/// Blank lines and lines starting with `#` or `!` are skipped. Every other line is handed to the
/// parser for `source.kind`; a line the parser rejects increments
/// [`ParsedSource::invalid_lines`] instead of aborting the parse, so one malformed line in an
/// otherwise-good list does not lose the rest of it. `SourceKind::Domains` bodies never reject a
/// line, so their `invalid_lines` is always `0`. See [`verify_candidate`] for how the invalid
/// count is later used to decide whether the result is trustworthy.
pub fn parse_source(source: SourceDefinition, body: &str) -> ParsedSource {
    let mut rules = Vec::new();
    let mut invalid_lines = 0usize;

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let parsed = match source.kind {
            SourceKind::Domains => parse_domain_line(trimmed, &source.name),
            SourceKind::Hosts => parse_hosts_line(trimmed, &source.name),
            SourceKind::Adblock => parse_adblock_line(trimmed, &source.name),
        };

        match parsed {
            Some(rule) => rules.push(rule),
            None => invalid_lines += 1,
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());

    ParsedSource {
        source,
        fetched_at: Utc::now(),
        etag: None,
        checksum: format!("{:x}", hasher.finalize()),
        rules,
        invalid_lines,
    }
}

/// Check freshly parsed sources for signs of a bad or hostile upstream list before they are
/// promoted into a live ruleset.
///
/// This is the gate between "we downloaded a list" and "a household's DNS enforces it" — a
/// corrupted mirror, a truncated download, or a compromised upstream is meant to fail here rather
/// than silently become the running ruleset. Two independent checks feed [`VerificationResult`]:
///
/// * **Invalid-line ratio.** Each source's `invalid_lines / (rules + invalid_lines)` is compared
///   against a threshold chosen by that source's `verification_strictness`
///   (`"strict"` → 5%, `"relaxed"` → 40%, anything else, including `"balanced"`, → 20%); the
///   ratio aggregated across all sources is separately compared against a hardcoded 20%. A high
///   ratio usually means the parser and the list's actual format disagree, or the list is
///   truncated or garbled.
/// * **Protected-domain safety.** Every parsed rule is compiled into a throwaway
///   [`PolicyEngine`] (empty protected set, [`BlockMode::NullIp`]), and each domain in the
///   caller's `protected_domains` is evaluated against it. Any that comes back
///   [`DecisionKind::Blocked`] is reported in
///   [`VerificationResult::blocked_protected_domains`] — this is what stops a bad blocklist from
///   taking out a router's captive-portal check or an OS's update servers.
///
/// [`VerificationResult::passed`] is `notes.is_empty()` — strictly "nothing to report". `false`
/// means the candidate must **not** be promoted; the caller should keep serving the current
/// ruleset.
pub fn verify_candidate(
    parsed: &[ParsedSource],
    protected_domains: &HashSet<String>,
) -> VerificationResult {
    let total_rules: usize = parsed
        .iter()
        .map(|entry| entry.rules.len() + entry.invalid_lines)
        .sum();
    let invalid_lines: usize = parsed.iter().map(|entry| entry.invalid_lines).sum();
    let invalid_ratio = if total_rules == 0 {
        0.0
    } else {
        invalid_lines as f32 / total_rules as f32
    };

    let probe_engine = PolicyEngine::new(RulesetArtifact::new(
        parsed
            .iter()
            .flat_map(|entry| entry.rules.iter().cloned())
            .collect(),
        HashSet::new(),
        BlockMode::NullIp,
    ));
    let blocked_protected_domains = protected_domains
        .iter()
        .filter_map(|domain| match probe_engine.evaluate(domain).kind {
            DecisionKind::Blocked(_) => Some(domain.clone()),
            DecisionKind::Allowed => None,
        })
        .collect::<Vec<_>>();

    let mut notes = Vec::new();
    if invalid_ratio > 0.2 {
        notes.push("invalid ratio exceeds 20%".to_string());
    }
    for entry in parsed {
        let total_lines = entry.rules.len() + entry.invalid_lines;
        let per_source_invalid_ratio = if total_lines == 0 {
            0.0
        } else {
            entry.invalid_lines as f32 / total_lines as f32
        };
        let allowed_invalid_ratio = invalid_ratio_threshold(&entry.source.verification_strictness);
        if per_source_invalid_ratio > allowed_invalid_ratio {
            notes.push(format!(
                "source {} exceeds {} invalid ratio threshold {:.0}%",
                entry.source.name,
                entry.source.verification_strictness,
                allowed_invalid_ratio * 100.0,
            ));
        }
    }
    if !blocked_protected_domains.is_empty() {
        notes.push("candidate blocks protected domains".to_string());
    }

    VerificationResult {
        passed: notes.is_empty(),
        invalid_ratio,
        blocked_protected_domains,
        notes,
    }
}

/// Flatten parsed sources into one [`RulesetArtifact`], discarding per-source metadata.
///
/// Does not call [`verify_candidate`] itself — callers are expected to verify a candidate before
/// compiling the artifact that will actually be served.
pub fn compile_ruleset(
    parsed: Vec<ParsedSource>,
    protected_domains: HashSet<String>,
    block_mode: BlockMode,
) -> RulesetArtifact {
    let rules = parsed
        .into_iter()
        .flat_map(|entry| entry.rules.into_iter())
        .collect();
    RulesetArtifact::new(rules, protected_domains, block_mode)
}

/// Build a ready-to-serve [`PolicyEngine`] directly from parsed sources, via [`compile_ruleset`].
///
/// Convenience for callers that already trust the input (e.g. bootstrapping the first ruleset)
/// and do not need the intermediate [`RulesetArtifact`]. Like [`compile_ruleset`], this does not
/// call [`verify_candidate`].
pub fn build_policy_engine(
    parsed: Vec<ParsedSource>,
    protected_domains: HashSet<String>,
    block_mode: BlockMode,
) -> PolicyEngine {
    PolicyEngine::new(compile_ruleset(parsed, protected_domains, block_mode))
}

/// Largest blocklist body accepted from a remote source.
///
/// Blocklists are attacker-influenced input: the operator supplies a URL, but whoever controls that
/// URL controls the payload. Measured before this bound existed, a 44 MB list drove resident memory
/// from 27 MB to 695 MB — roughly 16x amplification, because the body string, the parsed rules,
/// verification's copy of them and the compiled artifact all coexist. A 616 MB body peaked at 10 GB
/// and would have been an OOM kill on the 4 GB Raspberry Pi this product targets.
///
/// 32 MiB comfortably exceeds the largest lists in real use (StevenBlack's hosts file is ~3 MB,
/// HaGeZi Pro ~5 MB) while keeping worst-case amplification inside the budget of the smallest
/// supported device.
pub const MAX_SOURCE_BODY_BYTES: u64 = 32 * 1024 * 1024;

/// Why a source body was rejected before parsing.
#[derive(Debug)]
pub enum FetchError {
    /// Transport or status failure.
    Http(reqwest::Error),
    /// The body exceeded [`MAX_SOURCE_BODY_BYTES`].
    TooLarge {
        /// Bytes read before the limit tripped, or the advertised length.
        bytes: u64,
        /// The limit that was exceeded.
        limit: u64,
    },
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => write!(f, "{error}"),
            Self::TooLarge { bytes, limit } => write!(
                f,
                "blocklist body of {bytes} bytes exceeds the {limit} byte limit"
            ),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::TooLarge { .. } => None,
        }
    }
}

impl From<reqwest::Error> for FetchError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

/// Fetch a source body, refusing anything over [`MAX_SOURCE_BODY_BYTES`].
///
/// The body is streamed and the running total checked per chunk, so an oversized or
/// `Content-Length`-lying response is abandoned mid-transfer rather than buffered in full.
async fn fetch_source_body(client: &Client, url: &Url) -> Result<String, FetchError> {
    match url.scheme() {
        "data" => Ok(parse_data_url(url)),
        _ => {
            let response = client.get(url.clone()).send().await?.error_for_status()?;

            // Reject early when the server is honest about an oversized body.
            if let Some(length) = response.content_length()
                && length > MAX_SOURCE_BODY_BYTES
            {
                return Err(FetchError::TooLarge {
                    bytes: length,
                    limit: MAX_SOURCE_BODY_BYTES,
                });
            }

            // Content-Length may be absent or a lie, so enforce the bound while streaming.
            let mut body = Vec::with_capacity(64 * 1024);
            let mut response = response;
            while let Some(chunk) = response.chunk().await? {
                if body.len() as u64 + chunk.len() as u64 > MAX_SOURCE_BODY_BYTES {
                    return Err(FetchError::TooLarge {
                        bytes: body.len() as u64 + chunk.len() as u64,
                        limit: MAX_SOURCE_BODY_BYTES,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(String::from_utf8_lossy(&body).into_owned())
        }
    }
}

fn parse_data_url(url: &Url) -> String {
    let path = url.path();
    let Some((metadata, encoded)) = path.split_once(',') else {
        return String::new();
    };
    if metadata.ends_with(";base64") {
        return String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap_or_default(),
        )
        .unwrap_or_default();
    }
    encoded.replace("%0A", "\n").replace("%0D", "\r")
}

fn invalid_ratio_threshold(strictness: &str) -> f32 {
    match strictness {
        "strict" => 0.05,
        "relaxed" => 0.40,
        _ => 0.20,
    }
}

fn parse_domain_line(line: &str, source: &str) -> Option<Rule> {
    Some(Rule {
        pattern: RulePattern::Exact(normalize_domain(line)),
        action: RuleAction::Block,
        source: source.to_string(),
        comment: None,
    })
}

fn parse_hosts_line(line: &str, source: &str) -> Option<Rule> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    Some(Rule {
        pattern: RulePattern::Exact(normalize_domain(parts[1])),
        action: RuleAction::Block,
        source: source.to_string(),
        comment: Some(format!("mapped from {}", parts[0])),
    })
}

fn parse_adblock_line(line: &str, source: &str) -> Option<Rule> {
    let (action, candidate) = if let Some(rest) = line.strip_prefix("@@") {
        (RuleAction::Allow, rest)
    } else {
        (RuleAction::Block, line)
    };

    if let Some(domain) = candidate
        .strip_prefix("||")
        .and_then(|item| item.strip_suffix('^'))
    {
        return Some(Rule {
            pattern: RulePattern::Suffix(normalize_domain(domain)),
            action,
            source: source.to_string(),
            comment: None,
        });
    }

    if candidate.contains('$') || candidate.starts_with('/') {
        return None;
    }

    Some(Rule {
        pattern: RulePattern::Exact(normalize_domain(candidate)),
        action,
        source: source.to_string(),
        comment: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adblock_suffix_and_allow_parse() {
        let source = SourceDefinition {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            url: Url::parse("https://example.com/list.txt").expect("valid test url"),
            kind: SourceKind::Adblock,
            enabled: true,
            profile: "balanced".to_string(),
            verification_strictness: "balanced".to_string(),
        };
        let parsed = parse_source(source, "||ads.example.com^\n@@||cdn.example.com^");
        assert_eq!(parsed.rules.len(), 2);
        assert!(matches!(parsed.rules[0].pattern, RulePattern::Suffix(_)));
        assert!(matches!(parsed.rules[1].action, RuleAction::Allow));
    }

    #[test]
    fn data_url_body_parses() {
        let body = parse_data_url(
            &Url::parse("data:text/plain,ads.example.com%0Atracker.example.com")
                .expect("valid data url"),
        );
        assert!(body.contains("ads.example.com"));
        assert!(body.contains("tracker.example.com"));
    }

    #[test]
    fn suffix_rule_can_fail_protected_domain_verification() {
        let source = SourceDefinition {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            url: Url::parse("https://example.com/list.txt").expect("valid test url"),
            kind: SourceKind::Adblock,
            enabled: true,
            profile: "balanced".to_string(),
            verification_strictness: "balanced".to_string(),
        };
        let parsed = parse_source(source, "||gstatic.com^");
        let protected = HashSet::from(["connectivitycheck.gstatic.com".to_string()]);
        let verification = verify_candidate(&[parsed], &protected);
        assert!(!verification.passed);
        assert_eq!(
            verification.blocked_protected_domains,
            vec!["connectivitycheck.gstatic.com"]
        );
    }

    #[test]
    fn strict_source_rejects_high_invalid_ratio() {
        let source = SourceDefinition {
            id: Uuid::new_v4(),
            name: "strict-source".to_string(),
            url: Url::parse("https://example.com/list.txt").expect("valid test url"),
            kind: SourceKind::Adblock,
            enabled: true,
            profile: "strict".to_string(),
            verification_strictness: "strict".to_string(),
        };
        let parsed = parse_source(source, "||good.example^\n$badmodifier");
        let verification = verify_candidate(&[parsed], &HashSet::new());
        assert!(!verification.passed);
        assert!(
            verification
                .notes
                .iter()
                .any(|note| note.contains("strict-source exceeds strict invalid ratio threshold"))
        );
    }
}
