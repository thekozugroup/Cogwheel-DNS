//! Installing committed verdicts (§5.3).
//!
//! The reviewer never builds a policy and never holds `rebuild_lock`: it commits rows, then calls
//! `notify_install`. `Notify` keeps one permit when nobody is waiting, so a commit that lands
//! while a rebuild is running causes one more rebuild that reads it, and a burst of commits
//! collapses into one. No write is lost.

use crate::policy_build::{self, Rebuild};
use crate::state::{ServerState, stopped};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// How long after a commit the install waits, so a site load's verdicts go in together.
pub const INSTALL_DEBOUNCE: Duration = Duration::from_secs(5);

/// How long a failed install waits before it tries again.
pub const INSTALL_RETRY: Duration = Duration::from_secs(30);

/// Install the AI list whenever verdicts are committed, until shutdown.
pub async fn task(state: ServerState) {
    let mut shutdown = state.shutdown.clone();
    loop {
        tokio::select! {
            () = state.ai.install.notified() => {}
            () = stopped(&mut shutdown) => break,
        }
        tokio::select! {
            () = tokio::time::sleep(INSTALL_DEBOUNCE) => {}
            () = stopped(&mut shutdown) => break,
        }
        match policy_build::rebuild(&state, Rebuild::Ai).await {
            Ok(stats) => {
                state.ai.counters.installs.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(changed = stats.ai_changed, "AI list install finished");
            }
            Err(error) => {
                tracing::warn!(%error, "installing the AI list failed; retrying in 30 s");
                tokio::select! {
                    () = tokio::time::sleep(INSTALL_RETRY) => state.ai.notify_install(),
                    () = stopped(&mut shutdown) => break,
                }
            }
        }
    }
}
