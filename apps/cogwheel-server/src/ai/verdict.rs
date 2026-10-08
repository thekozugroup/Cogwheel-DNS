//! From answers to verdicts, and from verdicts to the AI list (§5.1, §6.9–6.10). Pure.
//!
//! [`compile`] is the single place stored rows become policy, and it applies every bar again
//! against the *live* lists: a verdict judged against an older list state stops applying when the
//! lists change under it, and the name is judged again on its next sighting.

use super::ListState;
use cogwheel_policy::{Action, AiList, ListIndex, is_domain_shaped, is_protected, normalize_domain};
use cogwheel_storage::AiVerdict;

/// A plain block, with no list involved. A wrong one is visible (Activity says "AI list") and one
/// click to undo.
pub const BLOCK_BAR: f64 = 0.85;
/// The role answer, when it overrides a list in either direction.
pub const OVERRIDE_BAR: f64 = 0.92;
/// The second question ("if it stays blocked, does the site break?"), same case.
pub const EFFECT_BAR: f64 = 0.90;

/// The AI list a policy build installs: every stored block or allow that still clears its bar
/// against the household's lists as they are now (`index` under `all_mask`).
pub fn compile(rows: &[AiVerdict], index: &ListIndex, all_mask: u64) -> AiList {
    rows.iter()
        .filter_map(|row| {
            let action = match row.verdict.as_str() {
                "block" => Action::Block,
                "allow" => Action::Allow,
                _ => return None,
            };
            let domain = normalize_domain(&row.domain);
            if !is_domain_shaped(&domain) || is_protected(&domain) {
                return None;
            }
            let confidence = row
                .confidence
                .filter(|confidence| confidence.is_finite())
                .unwrap_or(0.0);
            let effect = |want: &str| {
                row.effect.as_deref() == Some(want)
                    && row
                        .effect_confidence
                        .is_some_and(|confidence| confidence.is_finite() && confidence >= EFFECT_BAR)
            };
            let keep = match (action, ListState::of(index, all_mask, &domain)) {
                (Action::Block, ListState::Nothing) => confidence >= BLOCK_BAR,
                // The lists already block it, and keep the attribution.
                (Action::Block, ListState::Block) => false,
                (Action::Block, ListState::Exception) => {
                    confidence >= OVERRIDE_BAR && effect("works")
                }
                (Action::Allow, ListState::Block) => confidence >= OVERRIDE_BAR && effect("breaks"),
                // Nothing to whitelist; and never turn a list exception (which skips the CNAME
                // re-check) into an AI allow (which runs it). That inversion is how a
                // "whitelist" could block.
                (Action::Allow, ListState::Nothing | ListState::Exception) => false,
            };
            keep.then_some((domain, action))
        })
        .collect()
}
