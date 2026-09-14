//! Fetching subscribed lists and turning them into a policy (§2.6, §2.7).
//!
//! The pipeline is conditional-GET first: a daily refresh of a list that has not changed costs
//! one round trip and no parse. Every body that does arrive and verifies is written to the
//! on-disk cache beside the database, which is what makes a boot with no network produce a
//! filtering appliance instead of an open resolver.

use crate::http::ApiError;
use crate::policy_build::{self, Rebuild, body_path, enabled_slots};
use crate::state::{RefreshLease, ServerState, now_secs};
use cogwheel_lists::{
    FetchOutcome, ParsedList, SourceKind, build_index, fetch_source_body, parse_list,
    protected_hits, verify_list,
};
use cogwheel_storage::{FetchStatus, Source};
use serde::Serialize;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

/// How often the scheduler looks for a due list (§2.7).
const SCHEDULER_TICK: Duration = Duration::from_secs(60);

/// How long a list that failed waits before it is tried again (§2.7).
///
/// Separate from the refresh interval so a broken list recovers within minutes while a healthy
/// one is still only fetched daily.
const RETRY_AFTER_SECS: i64 = 300;

/// Which lists a refresh pass covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshTarget {
    /// Every enabled list, whatever its schedule says — what a manual "Refresh all" does.
    All,
    /// The enabled lists the schedule says are due — what the 60-second tick does.
    Due,
    /// One list by id, enabled or not: the user asked for this one specifically.
    One(String),
}

/// What a refresh did with one list (§3 route 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// A new body arrived, verified, and is now in force.
    Updated,
    /// The server answered 304; the cached body is still current.
    Unchanged,
    /// A body arrived but failed verification; the previous one is still in force.
    Rejected,
    /// The fetch itself failed; the previous body is still in force.
    Failed,
}

/// One row of a refresh's report.
#[derive(Debug, Clone, Serialize)]
pub struct RefreshResult {
    pub id: String,
    pub name: String,
    pub outcome: Outcome,
    /// Entries the list contributes now — the previous count when nothing was installed.
    pub rule_count: i64,
    pub note: Option<String>,
}

/// Run one refresh pass and, if anything changed, recompile the policy.
///
/// # Errors
///
/// 429 when a refresh is already running or a manual one arrives inside the 30-second gap, 404
/// for an unknown list id, and 500 for a storage failure. A list that fails to fetch is not an
/// error: it is a row in the report.
pub async fn refresh(
    state: &ServerState,
    target: RefreshTarget,
    manual: bool,
) -> Result<Vec<RefreshResult>, ApiError> {
    let lease = state.refresh_gate.begin(manual)?;
    refresh_leased(state, target, &lease).await
}

/// The body of [`refresh`], for a caller that already holds the gate.
///
/// A list edit takes the lease before it deletes the cached body (see `api::lists`), so the fetch
/// it then runs has to reuse that lease rather than deadlock against itself.
///
/// # Errors
///
/// 404 for an unknown list id, 500 for a storage failure.
pub async fn refresh_leased(
    state: &ServerState,
    target: RefreshTarget,
    _lease: &RefreshLease<'_>,
) -> Result<Vec<RefreshResult>, ApiError> {
    let sources = state.storage.list_sources().await?;
    let now = now_secs();
    let interval = i64::try_from(state.config.refresh_interval_secs).unwrap_or(i64::MAX);

    let selected: Vec<Source> = match &target {
        RefreshTarget::All => enabled_slots(&sources).cloned().collect(),
        RefreshTarget::Due => enabled_slots(&sources)
            .filter(|source| source_is_due(source, now, interval))
            .cloned()
            .collect(),
        RefreshTarget::One(id) => vec![
            sources
                .iter()
                .find(|source| &source.id == id)
                .cloned()
                .ok_or_else(|| ApiError::not_found("That list does not exist."))?,
        ],
    };

    let mut results = Vec::with_capacity(selected.len());
    for source in &selected {
        results.push(refresh_one(state, source).await);
    }

    // The policy is compiled from every cached body, never only the fetched subset: a list that
    // answered 304 still has to be in the index.
    if results
        .iter()
        .any(|result| result.outcome == Outcome::Updated)
    {
        policy_build::rebuild(state, Rebuild::Lists).await?;
    }
    Ok(results)
}

/// Fetch one list, record what happened against its row, and cache the body on success.
async fn refresh_one(state: &ServerState, source: &Source) -> RefreshResult {
    let at = now_secs();

    let url = match Url::parse(&source.url) {
        Ok(url) => url,
        Err(error) => {
            return failed(state, source, at, format!("the url is not valid: {error}")).await;
        }
    };
    // A conditional GET is only honest while the body it refers to is still on disk. With the
    // cache file missing — deleted by hand, lost with a volume, or dropped because the list's url
    // just changed — a 304 would leave this list contributing nothing for as long as the server
    // keeps answering 304, which for an `If-Modified-Since` against a different file on the same
    // host is indefinitely.
    let cached = tokio::fs::try_exists(body_path(&state.lists_dir, &source.id))
        .await
        .unwrap_or(false);
    let (etag, last_modified) = if cached {
        (source.etag.as_deref(), source.last_modified.as_deref())
    } else {
        (None, None)
    };
    let fetched = fetch_source_body(&state.http, &url, etag, last_modified).await;

    let (text, etag, last_modified) = match fetched {
        Ok(FetchOutcome::Body {
            text,
            etag,
            last_modified,
        }) => (text, etag, last_modified),
        Ok(FetchOutcome::NotModified) => {
            record(state, source, FetchStatus::Unchanged { at }).await;
            return kept(source, Outcome::Unchanged);
        }
        Err(error) => return failed(state, source, at, error.to_string()).await,
    };

    let kind = SourceKind::from_str(&source.kind).unwrap_or(SourceKind::Domains);
    let parsed = parse_list(kind, &text);
    if let Err(reason) = verify_list(&parsed) {
        // A rejected body is not written: the previous one keeps filtering, and the reason is on
        // the list's row for the operator to read.
        record(state, source, FetchStatus::Failed { at, error: reason }).await;
        return kept(source, Outcome::Rejected);
    }

    let note = protected_note(&source.name, &parsed);
    let rule_count = i64::try_from(parsed.entries.len()).unwrap_or(i64::MAX);
    if let Err(error) = store_body(&state.lists_dir, &source.id, text).await {
        // The body parsed but could not be cached. Recording it as fetched would leave the next
        // boot compiling from a body that is not there, so this is a failure like any other.
        tracing::warn!(list = %source.name, %error, "could not cache the list body");
        return failed(
            state,
            source,
            at,
            format!("could not write the cache file: {error}"),
        )
        .await;
    }
    record(
        state,
        source,
        FetchStatus::Ok {
            at,
            etag,
            last_modified,
            rule_count,
            note: note.clone(),
        },
    )
    .await;
    row(source, Outcome::Updated, rule_count, note)
}

/// The row a list contributes when its previous body is still the one in force: whatever that
/// body already said about it, under the outcome that left it there.
fn kept(source: &Source, outcome: Outcome) -> RefreshResult {
    row(source, outcome, source.rule_count, source.note.clone())
}

/// One row of a refresh's report, for the list it is about.
fn row(source: &Source, outcome: Outcome, rule_count: i64, note: Option<String>) -> RefreshResult {
    RefreshResult {
        id: source.id.clone(),
        name: source.name.clone(),
        outcome,
        rule_count,
        note,
    }
}

/// Record a failed fetch and report it, keeping whatever body was already cached.
async fn failed(state: &ServerState, source: &Source, at: i64, error: String) -> RefreshResult {
    tracing::warn!(list = %source.name, url = %source.url, %error, "list refresh failed");
    record(state, source, FetchStatus::Failed { at, error }).await;
    kept(source, Outcome::Failed)
}

/// Write a fetch outcome to the list's row; a storage failure here is logged, not propagated.
async fn record(state: &ServerState, source: &Source, status: FetchStatus) {
    if let Err(error) = state.storage.update_fetch_status(&source.id, status).await {
        tracing::warn!(list = %source.name, %error, "could not record the fetch status");
    }
}

/// The note the UI shows under a list that blocks names protection keeps reachable.
///
/// Advisory only: the evaluator allows these whatever a list says, so the list is still
/// installed. The operator is told because a list overreaching this way usually means the wrong
/// list was subscribed to.
fn protected_note(name: &str, parsed: &ParsedList) -> Option<String> {
    let hits = protected_hits(&build_index([(name, parsed)]));
    if hits.is_empty() {
        return None;
    }
    let plural = if hits.len() == 1 { "name" } else { "names" };
    Some(format!(
        "contains {} protected {plural} ({}), which stay reachable",
        hits.len(),
        hits.join(", ")
    ))
}

/// Write a list body to the cache atomically (§2.6).
///
/// Write-then-rename rather than write-in-place, because a power cut halfway through a 6 MB
/// write would otherwise leave a truncated file that the next boot parses as a short list and
/// compiles into a policy that blocks almost nothing.
async fn store_body(lists_dir: &Path, source_id: &str, text: String) -> std::io::Result<()> {
    tokio::fs::create_dir_all(lists_dir).await?;
    let temporary = lists_dir.join(format!("{source_id}.tmp"));
    tokio::fs::write(&temporary, text).await?;
    tokio::fs::rename(&temporary, body_path(lists_dir, source_id)).await
}

/// Drop a list's cached body, on delete.
pub async fn remove_body(lists_dir: &Path, source_id: &str) {
    let path = body_path(lists_dir, source_id);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "could not delete the cached body")
        }
    }
}

/// Whether the scheduler should fetch this list now (§2.7).
///
/// Never fetched at all is always due. Otherwise a list is due once its last *success* is older
/// than the refresh interval, but not within [`RETRY_AFTER_SECS`] of its last *attempt* — which
/// is what makes a failing list retry every five minutes while a healthy one is fetched daily.
pub fn source_is_due(source: &Source, now: i64, refresh_interval_secs: i64) -> bool {
    let Some(last_fetched_at) = source.last_fetched_at else {
        return true;
    };
    if now - last_fetched_at < RETRY_AFTER_SECS {
        return false;
    }
    source
        .last_ok_at
        .is_none_or(|last_ok_at| now - last_ok_at >= refresh_interval_secs)
}

/// The 60-second scheduler, and the first refresh of the process's life (§2.7).
///
/// The first pass runs immediately rather than after a tick, so a fresh install — every list
/// with no `last_fetched_at` — starts downloading the moment the listeners are up, while the
/// appliance is already serving from whatever the cache held.
pub async fn scheduler(state: ServerState) {
    let mut shutdown = state.shutdown.clone();
    let mut ticker = tokio::time::interval(SCHEDULER_TICK);
    loop {
        match refresh(&state, RefreshTarget::Due, false).await {
            Ok(results) if results.is_empty() => {}
            Ok(results) => {
                for result in &results {
                    tracing::info!(
                        list = %result.name,
                        outcome = ?result.outcome,
                        rules = result.rule_count,
                        "list refreshed"
                    );
                }
            }
            Err(error) => tracing::warn!(%error, "scheduled refresh did not run"),
        }
        tokio::select! {
            _ = ticker.tick() => {}
            () = crate::state::stopped(&mut shutdown) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RETRY_AFTER_SECS, source_is_due};
    use cogwheel_storage::Source;

    fn source(last_fetched_at: Option<i64>, last_ok_at: Option<i64>) -> Source {
        Source {
            id: "00000000-0000-4000-8000-000000000001".to_owned(),
            name: "oisd small".to_owned(),
            url: "https://small.oisd.nl".to_owned(),
            kind: "adblock".to_owned(),
            enabled: true,
            etag: None,
            last_modified: None,
            last_fetched_at,
            last_ok_at,
            rule_count: 0,
            last_error: None,
            note: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    const NOW: i64 = 1_800_000_000;
    const DAILY: i64 = 86_400;

    #[test]
    fn a_list_that_has_never_been_fetched_is_due() {
        assert!(source_is_due(&source(None, None), NOW, DAILY));
    }

    #[test]
    fn a_healthy_list_is_due_once_a_day() {
        let fresh = source(Some(NOW - 3_600), Some(NOW - 3_600));
        assert!(!source_is_due(&fresh, NOW, DAILY));
        let stale = source(Some(NOW - DAILY - 1), Some(NOW - DAILY - 1));
        assert!(source_is_due(&stale, NOW, DAILY));
    }

    #[test]
    fn a_failing_list_retries_every_five_minutes_not_every_tick() {
        let just_tried = source(Some(NOW - 60), None);
        assert!(
            !source_is_due(&just_tried, NOW, DAILY),
            "a list that failed a minute ago must not be hammered every tick"
        );
        let waited = source(Some(NOW - RETRY_AFTER_SECS), None);
        assert!(source_is_due(&waited, NOW, DAILY));
    }

    #[test]
    fn a_list_whose_last_success_is_old_retries_even_though_it_keeps_failing() {
        let failing = source(Some(NOW - RETRY_AFTER_SECS - 1), Some(NOW - 10 * DAILY));
        assert!(source_is_due(&failing, NOW, DAILY));
    }
}
