//! Pause and resume (§3 routes 4–5, §5.3).
//!
//! Two places hold the deadline: an atomic the hot path reads on every query, and the settings
//! row that survives a restart. The atomic is the authority while the process runs — a paused
//! client reads the reserved unfiltered scope, so no cache invalidation is involved either way.

use crate::http::{ApiError, ApiJson, ApiResult, ok};
use crate::state::{ServerState, now_secs};
use axum::extract::State;
use serde::{Deserialize, Serialize};

/// Longest pause the UI offers, and the longest this accepts (§3).
const MAX_PAUSE_MINUTES: u32 = 1_440;

/// `{minutes}` — how long protection goes off for.
#[derive(Debug, Deserialize)]
pub struct PauseRequest {
    pub minutes: u32,
}

/// When protection comes back, or `null` when it is on.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PauseState {
    pub paused_until: Option<i64>,
}

/// Route 4: pause protection for a number of minutes.
pub async fn pause(
    State(state): State<ServerState>,
    ApiJson(request): ApiJson<PauseRequest>,
) -> ApiResult<PauseState> {
    if request.minutes == 0 || request.minutes > MAX_PAUSE_MINUTES {
        return Err(ApiError::bad_request(
            "Pause for between 1 and 1440 minutes.",
        ));
    }
    let until = now_secs() + i64::from(request.minutes) * 60;
    state
        .runtime
        .set_pause_until(u64::try_from(until).unwrap_or(0));
    // Written after the atomic: if the database write fails the household is still unpaused on
    // the next restart, which is the safe direction for a filter to fail in.
    state.storage.set_pause_until(Some(until)).await?;
    tracing::info!(minutes = request.minutes, until, "protection paused");
    ok(PauseState {
        paused_until: Some(until),
    })
}

/// Route 5: resume protection now.
pub async fn resume(State(state): State<ServerState>) -> ApiResult<PauseState> {
    state.runtime.set_pause_until(0);
    state.storage.set_pause_until(None).await?;
    tracing::info!("protection resumed");
    ok(PauseState { paused_until: None })
}

/// The pause deadline if one is in force, `None` once it has passed.
pub fn paused_until(state: &ServerState) -> Option<i64> {
    let until = i64::try_from(state.runtime.pause_until()).unwrap_or(0);
    (until > now_secs()).then_some(until)
}

/// Restore the deadline a previous run stored (§5.3).
///
/// An expired value is ignored rather than cleared: nothing reads it once the process is up, and
/// leaving the row alone keeps the boot path read-only against a database that may still be
/// being restored from a backup.
pub async fn restore(state: &ServerState) {
    match state.storage.pause_until().await {
        Ok(Some(until)) if until > now_secs() => {
            state
                .runtime
                .set_pause_until(u64::try_from(until).unwrap_or(0));
            tracing::info!(until, "protection is still paused from the previous run");
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "could not read the stored pause deadline"),
    }
}
