use chrono::{DateTime, Utc};
use cogwheel_policy::{Rule, RuleAction, RulePattern, normalize_domain};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceToggleMode {
    Inherit,
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceManifest {
    pub service_id: String,
    pub display_name: String,
    pub category: String,
    pub risk_notes: String,
    pub allow_domains: Vec<String>,
    pub block_domains: Vec<String>,
    pub exceptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceToggle {
    pub service_id: String,
    pub mode: ServiceToggleMode,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceToggleSnapshot {
    pub toggles: Vec<ServiceToggle>,
}

impl ServiceToggleSnapshot {
    pub fn mode_for(&self, service_id: &str) -> ServiceToggleMode {
        self.toggles
            .iter()
            .find(|toggle| toggle.service_id == service_id)
            .map(|toggle| toggle.mode.clone())
            .unwrap_or(ServiceToggleMode::Inherit)
    }

    pub fn upsert(&mut self, service_id: &str, mode: ServiceToggleMode) {
        if let Some(existing) = self
            .toggles
            .iter_mut()
            .find(|toggle| toggle.service_id == service_id)
        {
            existing.mode = mode;
            existing.updated_at = Utc::now();
            return;
        }

        self.toggles.push(ServiceToggle {
            service_id: service_id.to_string(),
            mode,
            updated_at: Utc::now(),
        });
    }

    pub fn from_json(value: &str) -> serde_json::Result<Self> {
        serde_json::from_str(value)
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRuleLayer {
    pub active_toggles: Vec<ServiceToggle>,
    pub rules: Vec<Rule>,
    pub notes: Vec<String>,
}

pub fn built_in_service_manifests() -> Vec<ServiceManifest> {
    vec![
        ServiceManifest {
            service_id: "google-ads".to_string(),
            display_name: "Google Ads".to_string(),
            category: "advertising".to_string(),
            risk_notes: "Placeholder manifest until curated domain coverage is finalized."
                .to_string(),
            allow_domains: vec![
                "doubleclick.net".to_string(),
                "googleadservices.com".to_string(),
            ],
            block_domains: vec![
                "doubleclick.net".to_string(),
                "googleadservices.com".to_string(),
            ],
            exceptions: vec!["pagead2.googlesyndication.com".to_string()],
        },
        ServiceManifest {
            service_id: "tiktok".to_string(),
            display_name: "TikTok".to_string(),
            category: "social".to_string(),
            risk_notes: "Placeholder manifest until curated domain coverage is finalized."
                .to_string(),
            allow_domains: vec!["tiktokv.com".to_string(), "byteoversea.com".to_string()],
            block_domains: vec!["tiktokv.com".to_string(), "byteoversea.com".to_string()],
            exceptions: vec![],
        },
        ServiceManifest {
            service_id: "nintendo".to_string(),
            display_name: "Nintendo Services".to_string(),
            category: "gaming".to_string(),
            risk_notes: "Blocking may affect multiplayer, updates, and account sign-in."
                .to_string(),
            allow_domains: vec!["nintendo.net".to_string(), "nintendo.com".to_string()],
            block_domains: vec!["nintendo.net".to_string(), "nintendo.com".to_string()],
            exceptions: vec!["accounts.nintendo.com".to_string()],
        },
    ]
}

pub fn compile_service_rule_layer(
    manifests: &[ServiceManifest],
    snapshot: &ServiceToggleSnapshot,
) -> ServiceRuleLayer {
    let manifest_map = manifests
        .iter()
        .map(|manifest| (manifest.service_id.as_str(), manifest))
        .collect::<HashMap<_, _>>();

    let mut active_toggles = Vec::new();
    let mut rules = Vec::new();
    let mut notes = Vec::new();

    for toggle in &snapshot.toggles {
        let Some(manifest) = manifest_map.get(toggle.service_id.as_str()) else {
            notes.push(format!(
                "unknown service toggle ignored: {}",
                toggle.service_id
            ));
            continue;
        };

        if matches!(toggle.mode, ServiceToggleMode::Inherit) {
            continue;
        }

        active_toggles.push(toggle.clone());
        match toggle.mode {
            ServiceToggleMode::Allow => {
                for domain in manifest
                    .allow_domains
                    .iter()
                    .chain(manifest.block_domains.iter())
                    .chain(manifest.exceptions.iter())
                {
                    rules.push(service_rule(
                        domain,
                        RuleAction::Allow,
                        &manifest.service_id,
                    ));
                }
                notes.push(format!("allowing service {}", manifest.display_name));
            }
            ServiceToggleMode::Block => {
                for domain in &manifest.block_domains {
                    rules.push(service_rule(
                        domain,
                        RuleAction::Block,
                        &manifest.service_id,
                    ));
                }
                for domain in &manifest.exceptions {
                    rules.push(service_rule(
                        domain,
                        RuleAction::Allow,
                        &manifest.service_id,
                    ));
                }
                notes.push(format!("blocking service {}", manifest.display_name));
            }
            ServiceToggleMode::Inherit => {}
        }
    }

    ServiceRuleLayer {
        active_toggles,
        rules,
        notes,
    }
}

fn service_rule(domain: &str, action: RuleAction, service_id: &str) -> Rule {
    Rule {
        pattern: RulePattern::Suffix(normalize_domain(domain)),
        action,
        source: format!("service:{service_id}"),
        comment: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_toggle_emits_block_and_exception_rules() {
        let manifests = built_in_service_manifests();
        let snapshot = ServiceToggleSnapshot {
            toggles: vec![ServiceToggle {
                service_id: "nintendo".to_string(),
                mode: ServiceToggleMode::Block,
                updated_at: Utc::now(),
            }],
        };

        let layer = compile_service_rule_layer(&manifests, &snapshot);
        assert!(
            layer
                .rules
                .iter()
                .any(|rule| matches!(rule.action, RuleAction::Block))
        );
        assert!(
            layer
                .rules
                .iter()
                .any(|rule| matches!(rule.action, RuleAction::Allow))
        );
    }

    #[test]
    fn allow_toggle_emits_allow_rules() {
        let manifests = built_in_service_manifests();
        let mut snapshot = ServiceToggleSnapshot::default();
        snapshot.upsert("google-ads", ServiceToggleMode::Allow);

        let layer = compile_service_rule_layer(&manifests, &snapshot);
        assert!(!layer.rules.is_empty());
        assert!(
            layer
                .rules
                .iter()
                .all(|rule| matches!(rule.action, RuleAction::Allow))
        );
    }
}
