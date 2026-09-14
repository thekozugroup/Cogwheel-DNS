//! Retention (§7).
//!
//! Two bounds, both enforced here: an age in days and a hard row cap. A household at ten queries
//! a second reaches the row cap long before the week is up, and a quiet one keeps its week — the
//! point is that neither can grow the database without limit on an appliance whose whole purpose
//! is to stop somebody else keeping that record.

use crate::state::{ServerState, now_secs};

/// How long the hourly rollups are kept. They are counts, not browsing history, and at roughly
/// 15 KB a day three months of them is smaller than one day of raw rows.
const ROLLUP_DAYS: u32 = 90;

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
    }
}
