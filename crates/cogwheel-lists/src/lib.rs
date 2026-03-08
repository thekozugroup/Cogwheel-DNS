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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceKind {
    Domains,
    Hosts,
    Adblock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDefinition {
    pub id: Uuid,
    pub name: String,
    pub url: Url,
    pub kind: SourceKind,
    pub enabled: bool,
    pub verification_strictness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSource {
    pub source: SourceDefinition,
    pub fetched_at: DateTime<Utc>,
    pub etag: Option<String>,
    pub checksum: String,
    pub rules: Vec<Rule>,
    pub invalid_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub passed: bool,
    pub invalid_ratio: f32,
    pub blocked_protected_domains: Vec<String>,
    pub notes: Vec<String>,
}

pub fn synthetic_source(name: &str, rules: Vec<Rule>) -> ParsedSource {
    let source = SourceDefinition {
        id: Uuid::new_v4(),
        name: name.to_string(),
        url: Url::parse("data:text/plain,").expect("valid synthetic url"),
        kind: SourceKind::Domains,
        enabled: true,
        verification_strictness: "balanced".to_string(),
    };

    let mut hasher = Sha256::new();
    for rule in &rules {
        hasher.update(format!(
            "{:?}:{:?}:{}",
            rule.action, rule.pattern, rule.source
        ));
    }

    ParsedSource {
        source,
        fetched_at: Utc::now(),
        etag: None,
        checksum: format!("{:x}", hasher.finalize()),
        rules,
        invalid_lines: 0,
    }
}

pub async fn fetch_and_parse_source(
    client: &Client,
    source: SourceDefinition,
) -> Result<ParsedSource, reqwest::Error> {
    let body = fetch_source_body(client, &source.url).await?;
    Ok(parse_source(source, &body))
}

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

pub fn build_policy_engine(
    parsed: Vec<ParsedSource>,
    protected_domains: HashSet<String>,
    block_mode: BlockMode,
) -> PolicyEngine {
    PolicyEngine::new(compile_ruleset(parsed, protected_domains, block_mode))
}

async fn fetch_source_body(client: &Client, url: &Url) -> Result<String, reqwest::Error> {
    match url.scheme() {
        "data" => Ok(parse_data_url(url)),
        _ => {
            client
                .get(url.clone())
                .send()
                .await?
                .error_for_status()?
                .text()
                .await
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
            url: Url::parse("https://example.com/list.txt").unwrap(),
            kind: SourceKind::Adblock,
            enabled: true,
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
            &Url::parse("data:text/plain,ads.example.com%0Atracker.example.com").unwrap(),
        );
        assert!(body.contains("ads.example.com"));
        assert!(body.contains("tracker.example.com"));
    }

    #[test]
    fn suffix_rule_can_fail_protected_domain_verification() {
        let source = SourceDefinition {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            url: Url::parse("https://example.com/list.txt").unwrap(),
            kind: SourceKind::Adblock,
            enabled: true,
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
    fn synthetic_source_preserves_rules() {
        let source = synthetic_source(
            "service-toggles",
            vec![Rule {
                pattern: RulePattern::Suffix("tiktokv.com".to_string()),
                action: RuleAction::Block,
                source: "service:tiktok".to_string(),
                comment: None,
            }],
        );
        assert_eq!(source.source.name, "service-toggles");
        assert_eq!(source.rules.len(), 1);
    }

    #[test]
    fn strict_source_rejects_high_invalid_ratio() {
        let source = SourceDefinition {
            id: Uuid::new_v4(),
            name: "strict-source".to_string(),
            url: Url::parse("https://example.com/list.txt").unwrap(),
            kind: SourceKind::Adblock,
            enabled: true,
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
