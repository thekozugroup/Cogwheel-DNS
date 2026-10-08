//! Retention (§7).
//!
//! Two bounds, both enforced here: an age in days and a hard row cap. A household at ten queries
//! a second reaches the row cap long before the week is up, and a quiet one keeps its week — the
//! point is that neither can grow the database without limit on an appliance whose whole purpose
//! is to stop somebody else keeping that record.

use crate::state::{ServerState, now_secs};
use cogwheel_storage::AiPruned;

/// How long the hourly rollups are kept. They are counts, not browsing history, and at roughly
/// 15 KB a day three months of them is smaller than one day of raw rows.
const ROLLUP_DAYS: u32 = 90;

/// The most rows the AI list keeps (§6.14), oldest judged first to go.
const AI_MAX_ROWS: u32 = 10_000;

/// Prune on the configured interval, starting immediately.
///
/// The first pass runs without waiting because an upgrade from a build that kept everything
/// should not leave an already-large database alone for an hour.
pub async fn task(state: ServerState) {
    let mut shutdown = state.shutdown.clone();
    let config = std::sync::Arc::clone(&state.config);
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(config.prune_interval_secs));
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = crate::state::stopped(&mut shutdown) => break,
        }
        match state
            .storage
            .prune_query_log(
                now_secs(),
                config.history_days,
                config.max_rows,
                ROLLUP_DAYS,
            )
            .await
        {
            Ok(outcome) if outcome != cogwheel_storage::PruneOutcome::default() => tracing::info!(
                by_age = outcome.by_age,
                by_cap = outcome.by_cap,
                rollups = outcome.rollups,
                "pruned the query log"
            ),
            Ok(_) => tracing::debug!("nothing to prune"),
            // A failed prune must not take the appliance down: resolution does not depend on it,
            // and a database busy with a flush is a transient the next tick handles.
            Err(error) => tracing::warn!(%error, "prune pass failed"),
        }
        // With no activity log there is no AI list to prune: startup emptied it (§12).
        if config.logging() {
            prune_ai_list(&state, config.history_days).await;
        }
    }
}

/// The AI list's retention (§12): ordinary ignores live no longer than the activity log, the
/// websites verdicts were judged for are forgotten at `HISTORY_DAYS`, and nothing lives past 90
/// days or the row cap. Every failure is logged and left for the next pass.
pub(crate) async fn prune_ai_list(state: &ServerState, history_days: u32) {
    let now = now_secs();
    match state
        .storage
        .prune_ai_verdicts(now, history_days, AI_MAX_ROWS)
        .await
    {
        Ok(pruned) => {
            // Every deleted name, of any verdict, so the reviewer's map shrinks with the table.
            if !pruned.domains.is_empty() {
                state.ai.forget_known(&pruned.domains);
            }
            // Only a decision changes the AI list; an expired ignore was never compiled.
            if pruned.decisions > 0 {
                state.ai.notify_install();
            }
            if pruned != AiPruned::default() {
                tracing::info!(
                    deleted = pruned.domains.len(),
                    decisions = pruned.decisions,
                    "pruned the AI list"
                );
            }
        }
        Err(error) => tracing::warn!(%error, "AI list prune failed"),
    }
    let cutoff = now - i64::from(history_days) * 86_400;
    if let Err(error) = state.storage.scrub_ai_sites(Some(cutoff)).await {
        tracing::warn!(%error, "scrubbing AI list sites failed");
    }
}
