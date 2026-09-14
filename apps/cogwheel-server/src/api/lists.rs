//! Subscribed lists: the catalogue, the editor and the refresh button (§3 routes 16–20).

use crate::api::Deleted;
use crate::http::{ApiError, ApiJson, ApiResult, ok};
use crate::policy_build::{MAX_LIST_SLOTS, Rebuild, rebuild};
use crate::refresh::{self, Outcome, RefreshResult, RefreshTarget, source_is_due};
use crate::state::{RefreshLease, ServerState, now_secs};
use axum::extract::{Path, State};
use cogwheel_lists::SourceKind;
use cogwheel_storage::{NewSource, Source, SourcePatch, StorageError};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;

/// The two preset families whose entries differ only by filename.
macro_rules! hagezi {
    ($file:literal) => {
        concat!(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/",
            $file,
            ".txt"
        )
    };
}
macro_rules! steven_black {
    ($path:literal) => {
        concat!(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/",
            $path
        )
    };
}

/// DNSNet's preset catalogue (§2.5). The web ships the same table so the picker is populated
/// before the first response lands; this copy is what a script or a second client sees.
const PRESETS: [Preset; 11] = [
    Preset::new("oisd small", "https://small.oisd.nl", "adblock"),
    Preset::new("oisd big", "https://big.oisd.nl", "adblock"),
    Preset::new("HaGeZi Light", hagezi!("light"), "adblock"),
    Preset::new("HaGeZi Multi", hagezi!("multi"), "adblock"),
    Preset::new("HaGeZi Pro", hagezi!("pro"), "adblock"),
    Preset::new("HaGeZi Pro++", hagezi!("pro.plus"), "adblock"),
    Preset::new("HaGeZi Ultimate", hagezi!("ultimate"), "adblock"),
    Preset::new("StevenBlack unified", steven_black!("hosts"), "hosts"),
    Preset::new(
        "StevenBlack gambling",
        steven_black!("alternates/gambling-only/hosts"),
        "hosts",
    ),
    Preset::new(
        "StevenBlack porn",
        steven_black!("alternates/porn-only/hosts"),
        "hosts",
    ),
    Preset::new(
        "StevenBlack social",
        steven_black!("alternates/social-only/hosts"),
        "hosts",
    ),
];

/// One subscribed list, as the Lists page shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ListSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub kind: String,
    pub enabled: bool,
    pub rule_count: i64,
    pub last_ok_at: Option<i64>,
    pub last_fetched_at: Option<i64>,
    pub last_error: Option<String>,
    /// Advisory, e.g. that the list blocks names protection keeps reachable.
    pub note: Option<String>,
    /// Whether the scheduler would fetch it on its next tick.
    pub due: bool,
}

/// A list somebody might want to subscribe to.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Preset {
    pub name: &'static str,
    pub url: &'static str,
    pub kind: &'static str,
}

impl Preset {
    const fn new(name: &'static str, url: &'static str, kind: &'static str) -> Self {
        Self { name, url, kind }
    }
}

/// Route 16's body.
#[derive(Debug, Clone, Serialize)]
pub struct ListCatalogue {
    pub lists: Vec<ListSource>,
    pub presets: Vec<Preset>,
}

/// `{name, url, kind, enabled?}`.
#[derive(Debug, Deserialize)]
pub struct ListInput {
    pub name: String,
    pub url: String,
    pub kind: String,
    pub enabled: Option<bool>,
}

/// `{name?, url?, kind?, enabled?}` — an absent key leaves that column alone.
#[derive(Debug, Default, Deserialize)]
pub struct ListPatch {
    pub name: Option<String>,
    pub url: Option<String>,
    pub kind: Option<String>,
    pub enabled: Option<bool>,
}

/// What adding a list did.
#[derive(Debug, Clone, Serialize)]
pub struct ListCreated {
    pub list: ListSource,
    pub outcome: Outcome,
    pub note: Option<String>,
}

/// `{id?}` — no id means every list.
#[derive(Debug, Default, Deserialize)]
pub struct RefreshRequest {
    pub id: Option<String>,
}

/// Route 16: every subscribed list, and the presets.
pub async fn catalogue(State(state): State<ServerState>) -> ApiResult<ListCatalogue> {
    let sources = state.storage.list_sources().await?;
    ok(ListCatalogue {
        lists: views(&state, sources),
        presets: PRESETS.to_vec(),
    })
}

/// Route 17: subscribe to a list, and fetch it now.
pub async fn create(
    State(state): State<ServerState>,
    ApiJson(input): ApiJson<ListInput>,
) -> ApiResult<ListCreated> {
    let name = non_empty(&input.name, "Give the list a name.")?;
    let url = valid_url(&input.url)?;
    let kind = valid_kind(&input.kind)?;
    let enabled = input.enabled.unwrap_or(true);
    if enabled {
        refuse_65th(&state, None).await?;
    }
    let lease = state.refresh_gate.acquire().await;

    let source = state
        .storage
        .insert_source(NewSource {
            id: None,
            name,
            url,
            kind: kind.as_str().to_owned(),
            enabled,
        })
        .await
        .map_err(duplicate_name)?;
    tracing::info!(list = %source.name, url = %source.url, "list added");

    let (outcome, note) = fetch_now(&state, &source.id, &lease).await?;
    if outcome != Outcome::Updated {
        // Even with nothing downloaded the list now holds a slot, and slots are assigned from
        // the enabled set: the policy has to be rebuilt against it before anything else reads a
        // mask.
        rebuild(&state, Rebuild::Lists).await?;
    }
    let list = reread(&state, &source.id).await?;
    ok(ListCreated {
        list,
        note: note.or_else(|| list_error(&outcome)),
        outcome,
    })
}

/// Route 18: edit a list. A changed url or kind re-fetches; an enable toggle only recompiles.
pub async fn update(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    ApiJson(patch): ApiJson<ListPatch>,
) -> ApiResult<ListSource> {
    // Held across the read, the row edit, the body delete and the refetch. Without it a
    // scheduler pass already inside `refresh_one` for this id finishes afterwards, writes the
    // *old* url's body back to the cache and stamps `last_ok_at` — after which the list is not
    // due again for a full refresh interval and the one the user replaced keeps filtering,
    // under a green "Last updated".
    let lease = state.refresh_gate.acquire().await;
    let current = state
        .storage
        .get_source(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("That list does not exist."))?;

    let name = patch
        .name
        .as_deref()
        .map(|name| non_empty(name, "Give the list a name."))
        .transpose()?;
    let url = patch.url.as_deref().map(valid_url).transpose()?;
    let kind = patch.kind.as_deref().map(valid_kind).transpose()?;
    if patch.enabled == Some(true) && !current.enabled {
        refuse_65th(&state, Some(&current.id)).await?;
    }

    let refetch = url.as_ref().is_some_and(|url| url != &current.url)
        || kind.is_some_and(|kind| kind.as_str() != current.kind);
    state
        .storage
        .update_source(
            &id,
            SourcePatch {
                name,
                url,
                kind: kind.map(|kind| kind.as_str().to_owned()),
                enabled: patch.enabled,
            },
        )
        .await
        .map_err(duplicate_name)?
        .ok_or_else(|| ApiError::not_found("That list does not exist."))?;

    if refetch {
        // The cached body belongs to the old url or the old format, so it goes before the fetch
        // rather than after it: with no cached body the fetch is unconditional (see refresh.rs),
        // which is what stops a server answering 304 for a file this list no longer points at.
        refresh::remove_body(&state.lists_dir, &id).await;
        let (outcome, _) = fetch_now(&state, &id, &lease).await?;
        if outcome != Outcome::Updated {
            rebuild(&state, Rebuild::Lists).await?;
        }
    } else {
        rebuild(&state, Rebuild::Lists).await?;
    }
    ok(reread(&state, &id).await?)
}

/// Route 19: unsubscribe. The cached body and any device selections go with it.
pub async fn remove(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Deleted> {
    // As in `update`: a pass mid-fetch for this id would otherwise write its body back after the
    // row is gone, leaving a file `compile_index` never reads and nothing ever deletes.
    let _lease = state.refresh_gate.acquire().await;
    if !state.storage.delete_source(&id).await? {
        return Err(ApiError::not_found("That list does not exist."));
    }
    refresh::remove_body(&state.lists_dir, &id).await;
    rebuild(&state, Rebuild::Lists).await?;
    tracing::info!(list = %id, "list deleted");
    ok(Deleted { deleted: true })
}

/// Route 20: fetch one list, or all of them, now.
pub async fn refresh(
    State(state): State<ServerState>,
    request: Option<ApiJson<RefreshRequest>>,
) -> ApiResult<Vec<RefreshResult>> {
    let target = request
        .and_then(|ApiJson(request)| request.id)
        .map_or(RefreshTarget::All, RefreshTarget::One);
    ok(refresh::refresh(&state, target, true).await?)
}

/// Fetch one list as part of a write, under the gate the caller is already holding.
async fn fetch_now(
    state: &ServerState,
    id: &str,
    lease: &RefreshLease<'_>,
) -> Result<(Outcome, Option<String>), ApiError> {
    let results = refresh::refresh_leased(state, RefreshTarget::One(id.to_owned()), lease).await?;
    Ok(results
        .into_iter()
        .next()
        .map_or((Outcome::Failed, None), |result| {
            (result.outcome, result.note)
        }))
}

/// The sentence a failed or rejected fetch leaves on the list, when there is no note.
fn list_error(outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::Rejected => Some("The list was downloaded but could not be parsed.".to_owned()),
        Outcome::Failed => Some("The list could not be downloaded.".to_owned()),
        Outcome::Updated | Outcome::Unchanged => None,
    }
}

/// Read one list back after a write, so the response shows what was actually stored.
async fn reread(state: &ServerState, id: &str) -> Result<ListSource, ApiError> {
    let source = state
        .storage
        .get_source(id)
        .await?
        .ok_or_else(|| ApiError::not_found("That list does not exist."))?;
    views(state, vec![source])
        .pop()
        .ok_or_else(|| ApiError::internal("The list could not be read back."))
}

/// Turn stored rows into the page's view, answering "is it due" as the scheduler would.
fn views(state: &ServerState, sources: Vec<Source>) -> Vec<ListSource> {
    let now = now_secs();
    let interval = i64::try_from(state.config.refresh_interval_secs).unwrap_or(i64::MAX);
    sources
        .into_iter()
        .map(|source| ListSource {
            due: source.enabled && source_is_due(&source, now, interval),
            id: source.id,
            name: source.name,
            url: source.url,
            kind: source.kind,
            enabled: source.enabled,
            rule_count: source.rule_count,
            last_ok_at: source.last_ok_at,
            last_fetched_at: source.last_fetched_at,
            last_error: source.last_error,
            note: source.note,
        })
        .collect()
}

/// Refuse the enabled list that would not fit in the 64-bit scope mask (§6).
async fn refuse_65th(state: &ServerState, enabling: Option<&str>) -> Result<(), ApiError> {
    let enabled = state
        .storage
        .list_sources()
        .await?
        .into_iter()
        .filter(|source| source.enabled && Some(source.id.as_str()) != enabling)
        .count();
    if enabled >= MAX_LIST_SLOTS {
        return Err(ApiError::conflict(format!(
            "{MAX_LIST_SLOTS} lists can be enabled at once; disable one first."
        )));
    }
    Ok(())
}

/// Trim a field and refuse it if nothing is left.
fn non_empty(value: &str, message: &'static str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(message));
    }
    Ok(trimmed.to_owned())
}

/// A list url has to be something the fetcher can actually retrieve.
fn valid_url(value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let url = Url::parse(trimmed)
        .map_err(|_| ApiError::bad_request(format!("{trimmed:?} is not a url.")))?;
    if !matches!(url.scheme(), "http" | "https" | "data") {
        return Err(ApiError::bad_request(
            "A list url must be http, https or data.",
        ));
    }
    Ok(trimmed.to_owned())
}

/// The three formats the parser understands.
fn valid_kind(value: &str) -> Result<SourceKind, ApiError> {
    SourceKind::from_str(value.trim())
        .map_err(|()| ApiError::bad_request("A list is one of hosts, domains or adblock."))
}

/// Two lists cannot share a name: the name is what a blocked query is attributed to.
fn duplicate_name(error: StorageError) -> ApiError {
    if error.is_unique_violation() {
        return ApiError::conflict("A list with that name already exists.");
    }
    error.into()
}
