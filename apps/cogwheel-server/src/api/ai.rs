//! AI review and the AI list (§10 routes 23–29): the status, the PUT that turns review on and off,
//! the model picker, the Test, and the AI list itself, with Forget and Clear.
//!
//! The work is in `crate::ai`; this is the HTTP edge. Every route that writes, spends, sends
//! anything to OpenRouter or touches the key is behind [`guard_local`], and the two whose body can
//! carry the key read it through [`QuietJson`], which never logs a rejection. None of these
//! answers contains any part of the key: no type here has a field that could hold it.

use crate::ai::{
    self, AiPatch, AiStatus, AiTestInput, AiTestResult, ListState, ModelsView, verdict,
};
use crate::api::Deleted;
use crate::api::queries::Cleared;
use crate::config::AppConfig;
use crate::http::{ApiEnvelope, ApiError, ApiQuery, ApiResult, ok, rejection_sentence};
use crate::policy_build::{Rebuild, rebuild};
use crate::state::ServerState;
use axum::Json;
use axum::extract::{FromRequest, OptionalFromRequest, Path, Request, State};
use axum::http::uri::Authority;
use axum::http::{HeaderMap, Uri, header};
use axum::response::IntoResponse;
use cogwheel_policy::{Action, Policy, is_domain_shaped, is_protected, normalize_domain};
use cogwheel_storage::{AiCounts, AiVerdict, AiVerdictFilter};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// --------------------------------------------------------------------- the guard

/// What every guarded route answers a request from anywhere else.
const NOT_LOCAL: &str = "Change AI review from Cogwheel's own address or a local name. Behind a \
                         reverse proxy, add its name to COGWHEEL_SERVER__ALLOWED_HOSTS.";

/// The suffixes a home network's own names end in. A DNS-rebinding page reaches the appliance
/// under a public name its attacker controls, and none of these is one.
const LOCAL_SUFFIXES: [&str; 6] = [
    ".local",
    ".lan",
    ".home",
    ".home.arpa",
    ".internal",
    ".localdomain",
];

/// Refuse a request that did not come from Cogwheel's own address or a local name.
///
/// A rebinding page can drive the API through the household's own browser (SECURITY.md); on these
/// routes that would mean swapping in an attacker's key, spending credit, or wiping the AI list.
/// Three checks, all of which must pass: every name the request was addressed to (the `Host`
/// header and the request line's authority) is local or allowed; an `Origin`, if sent, is this
/// appliance; and the browser did not mark it `Sec-Fetch-Site: cross-site`, which it does even on
/// the no-cors GETs that carry no `Origin`. A client that sends none of these headers passes: it
/// is not a browser, and so not what a rebinding page can drive.
///
/// # Errors
///
/// 400 with [`NOT_LOCAL`].
pub fn guard_local(headers: &HeaderMap, uri: &Uri, config: &AppConfig) -> Result<(), ApiError> {
    let refuse = |check: &'static str| {
        // Which check, never the value: a header is the requester's text.
        tracing::debug!(check, "refused an AI review request from outside");
        ApiError::bad_request(NOT_LOCAL)
    };

    // Host. The header and the URI authority are both checked: an absolute-form request line
    // (or, later, HTTP/2's `:authority`) carries the name there instead.
    let host = match headers.get(header::HOST) {
        Some(value) => Some(value.to_str().map_err(|_| refuse("host"))?),
        None => None,
    };
    let authority = uri.authority().map(Authority::as_str);
    for name in [host, authority].into_iter().flatten() {
        if !hostname(name).is_some_and(|name| is_local(&name, config)) {
            return Err(refuse("host"));
        }
    }

    // Origin: absent, this appliance, an allowed name, or loopback on both sides (the Vite dev
    // server). `null` (a sandboxed frame, a file, a redirect) has no `://` and is refused.
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().map_err(|_| refuse("origin"))?;
        let (_, origin) = origin.split_once("://").ok_or_else(|| refuse("origin"))?;
        let addressed = host.or(authority);
        let origin_name = hostname(origin);
        let same = addressed.is_some_and(|addressed| addressed.eq_ignore_ascii_case(origin));
        let allowed = origin_name
            .as_ref()
            .is_some_and(|name| config.allowed_hosts.contains(name));
        let loopback = origin_name.as_deref().is_some_and(is_loopback)
            && addressed
                .and_then(hostname)
                .as_deref()
                .is_some_and(is_loopback);
        if !(same || allowed || loopback) {
            return Err(refuse("origin"));
        }
    }

    // Fetch metadata. `same-site` is the Vite dev server, a port away.
    if let Some(site) = headers.get("sec-fetch-site") {
        let accepted = site.to_str().is_ok_and(|site| {
            ["same-origin", "same-site", "none"]
                .iter()
                .any(|accepted| site.eq_ignore_ascii_case(accepted))
        });
        if !accepted {
            return Err(refuse("fetch-site"));
        }
    }
    Ok(())
}

/// The hostname of a `host[:port]`: lowercase, without its port, brackets or trailing dot.
fn hostname(authority: &str) -> Option<String> {
    let parsed = authority.parse::<Authority>().ok()?;
    let host = parsed
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// An IP literal, `localhost` or any single label, a home network's own suffix, or a name the
/// operator allowed.
fn is_local(name: &str, config: &AppConfig) -> bool {
    name.parse::<IpAddr>().is_ok()
        || !name.contains('.')
        || LOCAL_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        || config.allowed_hosts.iter().any(|allowed| allowed == name)
}

fn is_loopback(name: &str) -> bool {
    name == "localhost" || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

// --------------------------------------------------------------------- the quiet body

/// A JSON body read like `ApiJson`, with the same sentences and the same `Option<…>` support, but
/// whose rejection is never logged: serde's text can quote a field's value ("invalid type: string
/// \"sk-or-…\""), and a field here can be the key.
pub struct QuietJson<T>(pub T);

impl<T, S> FromRequest<S> for QuietJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        <Json<T> as FromRequest<S>>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| ApiError::bad_request(rejection_sentence(&rejection)))
    }
}

impl<T, S> OptionalFromRequest<S> for QuietJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// The Test takes staged values or nothing at all; a body that is present and malformed is
    /// still refused.
    async fn from_request(request: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        Option::<Json<T>>::from_request(request, state)
            .await
            .map(|value| value.map(|Json(value)| Self(value)))
            .map_err(|rejection| ApiError::bad_request(rejection_sentence(&rejection)))
    }
}

// --------------------------------------------------------------------- routes 23–26

/// Route 23: what AI review is doing. Unguarded, like every read-only route.
pub async fn status(State(state): State<ServerState>) -> ApiResult<AiStatus> {
    ok(current_status(&state).await?)
}

/// The status as route 23 answers it; the PUT answers with it too.
async fn current_status(state: &ServerState) -> Result<AiStatus, ApiError> {
    let counts = state.storage.ai_counts().await?;
    Ok(state.ai.status(&state.runtime.current_policy(), counts))
}

/// Route 24: turn review on or off, pick the model, save or remove the key, set the daily limit.
/// The work and its order are `ai::apply_patch`'s; the answer is the status afterwards.
pub async fn update(
    State(state): State<ServerState>,
    headers: HeaderMap,
    uri: Uri,
    QuietJson(patch): QuietJson<AiPatch>,
) -> ApiResult<AiStatus> {
    guard_local(&headers, &uri, &state.config)?;
    ai::apply_patch(&state, patch).await?;
    ok(current_status(&state).await?)
}

/// Route 25: OpenRouter's decision models, fetched without the key and reused for an hour.
/// Guarded although it is a GET: it makes the appliance fetch something.
pub async fn models(
    State(state): State<ServerState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ModelsView> {
    guard_local(&headers, &uri, &state.config)?;
    let list = ai::model_list(&state).await?;
    ok(state.ai.models_view(&list))
}

/// Route 26: one request about a fixed, public example, with staged values that fall back to the
/// saved ones.
pub async fn test(
    State(state): State<ServerState>,
    headers: HeaderMap,
    uri: Uri,
    staged: Option<QuietJson<AiTestInput>>,
) -> ApiResult<AiTestResult> {
    guard_local(&headers, &uri, &state.config)?;
    let staged = staged.map(|QuietJson(staged)| staged).unwrap_or_default();
    ok(ai::run_test(&state, staged).await?)
}

// --------------------------------------------------------------------- routes 27–29

/// Rows per page when the caller does not say.
const DEFAULT_LIMIT: u32 = 200;

/// Rows per page the caller may ask for at most; refused above it, as the query log does.
const MAX_LIMIT: u32 = 500;

/// `?view=changes|all&verdict=block|allow|ignore&q=&limit=`.
#[derive(Debug, Default, Deserialize)]
pub struct VerdictQuery {
    pub view: Option<String>,
    pub verdict: Option<String>,
    pub q: Option<String>,
    pub limit: Option<u32>,
}

/// One page of the AI list.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictPage {
    /// Every row the filter matches, not only the ones on this page.
    pub total: i64,
    /// The whole table's counts, whatever the filter.
    pub counts: AiCounts,
    pub rows: Vec<VerdictRow>,
}

/// One stored verdict, and what the live policy makes of it.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictRow {
    pub domain: String,
    pub verdict: String,
    pub why: Option<String>,
    pub choice: String,
    pub confidence: Option<f64>,
    pub effect: Option<String>,
    pub effect_confidence: Option<f64>,
    /// The household's lists on the name when it was judged.
    pub lists: String,
    /// The same, now.
    pub lists_now: ListState,
    /// Whether DNS is using it: the AI list holds exactly this verdict.
    pub applied: bool,
    pub not_applied: Option<NotApplied>,
    /// What decides the name before the AI list does. Device rules are per device, so not here.
    pub outranked_by: Option<Outranked>,
    pub site: Option<String>,
    pub conflict_site: Option<String>,
    pub model: String,
    pub judged_at: i64,
    pub review_after: i64,
}

/// Why a block or allow is stored but not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotApplied {
    /// AI review is off or unavailable, so the AI list compiles empty.
    Off,
    /// The lists changed since it was judged; it is judged again when next seen.
    ListsChanged,
    /// A block the lists already make, which they keep the credit for.
    ListsAgree,
    /// It no longer clears its bar against the lists as they are.
    BelowBar,
    /// It clears its bar and is waiting for the next install, a few seconds after it was stored.
    Pending,
}

/// What outranks the AI list on a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outranked {
    HouseholdRule,
    Protected,
}

/// Route 27: a page of the AI list, newest judgement first, each row read against the live policy.
/// Unguarded, like the query log: it is the same kind of record, and SECURITY says so. Marked
/// `no-store`, so the websites a household opened never sit in a browser's cache.
pub async fn verdicts(
    State(state): State<ServerState>,
    ApiQuery(query): ApiQuery<VerdictQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let changes_only = match query.view.as_deref().map(str::trim) {
        None | Some("" | "changes") => true,
        Some("all") => false,
        Some(_) => return Err(ApiError::bad_request("Show either the changes or all.")),
    };
    let verdict = match query.verdict.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(verdict @ ("block" | "allow" | "ignore")) => Some(verdict.to_owned()),
        Some(_) => {
            return Err(ApiError::bad_request(
                "A verdict is block, allow or ignore.",
            ));
        }
    };
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(ApiError::bad_request(format!(
            "Ask for between 1 and {MAX_LIMIT} rows."
        )));
    }
    let page = state
        .storage
        .page_ai_verdicts(AiVerdictFilter {
            changes_only,
            verdict,
            q: query
                .q
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty()),
            limit,
        })
        .await?;
    let policy = state.runtime.current_policy();
    let applying = state.ai.applying();
    let data = VerdictPage {
        total: page.total,
        counts: page.counts,
        rows: page
            .rows
            .into_iter()
            .map(|row| VerdictRow::of(row, &policy, applying))
            .collect(),
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], ApiEnvelope { data }))
}

impl VerdictRow {
    fn of(row: AiVerdict, policy: &Policy, applying: bool) -> Self {
        let action = action_of(&row.verdict);
        let applied = action.is_some() && policy.ai.get(&row.domain) == action;
        let lists_now = ai::list_state(policy, &row.domain);
        let not_applied = match action {
            None => None,
            Some(_) if applied => None,
            Some(_) if !applying => Some(NotApplied::Off),
            Some(_) if ListState::parse(&row.lists) != Some(lists_now) => {
                Some(NotApplied::ListsChanged)
            }
            Some(Action::Block) if lists_now == ListState::Block => Some(NotApplied::ListsAgree),
            // Committed, and clearing its bar: the installer has not put it in yet.
            Some(action)
                if !is_protected(&row.domain)
                    && verdict::clears(
                        action,
                        lists_now,
                        (row.confidence, row.effect.as_deref(), row.effect_confidence),
                    ) =>
            {
                Some(NotApplied::Pending)
            }
            Some(_) => Some(NotApplied::BelowBar),
        };
        let outranked_by = if policy.household.get_at_boundaries(&row.domain).is_some() {
            Some(Outranked::HouseholdRule)
        } else if is_protected(&row.domain) {
            Some(Outranked::Protected)
        } else {
            None
        };
        Self {
            domain: row.domain,
            verdict: row.verdict,
            why: row.why,
            choice: row.choice,
            confidence: row.confidence,
            effect: row.effect,
            effect_confidence: row.effect_confidence,
            lists: row.lists,
            lists_now,
            applied,
            not_applied,
            outranked_by,
            site: row.site,
            conflict_site: row.conflict_site,
            model: row.model,
            judged_at: row.judged_at,
            review_after: row.review_after,
        }
    }
}

/// The action a stored verdict applies, if it applies one.
fn action_of(verdict: &str) -> Option<Action> {
    match verdict {
        "block" => Some(Action::Block),
        "allow" => Some(Action::Allow),
        _ => None,
    }
}

/// Route 28: empty the AI list. Review is not halted: names are judged afresh, and paid for again,
/// as websites load them.
pub async fn clear(
    State(state): State<ServerState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Cleared> {
    guard_local(&headers, &uri, &state.config)?;
    let deleted = state.storage.clear_ai_verdicts().await?;
    state.ai.forget_all_known();
    // Told first: if this request is dropped, or the install fails, the installer withdraws the
    // rows within seconds rather than leaving them applying (§5.3).
    state.ai.notify_install();
    rebuild(&state, Rebuild::Ai).await?;
    tracing::info!(deleted, "AI list cleared");
    ok(Cleared { deleted })
}

/// Route 29: forget one name. The lists decide for it until it is judged again, which is the next
/// time a website loads it while review is on.
pub async fn forget(
    State(state): State<ServerState>,
    headers: HeaderMap,
    uri: Uri,
    Path(domain): Path<String>,
) -> ApiResult<Deleted> {
    guard_local(&headers, &uri, &state.config)?;
    let domain = normalize_domain(&domain);
    if !is_domain_shaped(&domain) {
        return Err(ApiError::bad_request(format!(
            "{domain:?} is not a domain name."
        )));
    }
    state
        .storage
        .delete_ai_verdict(domain.clone())
        .await?
        .ok_or_else(|| ApiError::not_found("No AI verdict for that name."))?;
    state.ai.forget_known(std::slice::from_ref(&domain));
    // As in Clear: told first, so a dropped request or a failed install still withdraws it.
    state.ai.notify_install();
    rebuild(&state, Rebuild::Ai).await?;
    ok(Deleted { deleted: true })
}

// --------------------------------------------------------------------- /check's provenance

/// What `/check` says about the AI list on a name: the stored row whenever there is one, whether
/// the AI list decided, was outranked, or fell below its bar. Every field but `verdict` and
/// `applied` is null in the race case, where nothing is invented.
#[derive(Debug, Clone, Serialize)]
pub struct AiExplanation {
    pub verdict: String,
    pub why: Option<String>,
    pub choice: Option<String>,
    pub confidence: Option<f64>,
    pub effect: Option<String>,
    pub effect_confidence: Option<f64>,
    pub lists: Option<String>,
    pub site: Option<String>,
    pub conflict_site: Option<String>,
    pub model: Option<String>,
    pub judged_at: Option<i64>,
    /// Read from the live policy.
    pub applied: bool,
}

/// The AI list's provenance for `domain` (normalised). `decided` is the action when the AI list
/// decided this lookup: if its row is already gone (Forget, before the rebuild lands), the answer
/// says only that, and invents no site, model or confidence.
///
/// # Errors
///
/// A storage failure, as a 500.
pub async fn explain(
    state: &ServerState,
    policy: &Policy,
    domain: &str,
    decided: Option<Action>,
) -> Result<Option<AiExplanation>, ApiError> {
    let Some(row) = state.storage.ai_verdict(domain.to_owned()).await? else {
        return Ok(decided.map(|action| AiExplanation {
            verdict: action.as_str().to_owned(),
            why: None,
            choice: None,
            confidence: None,
            effect: None,
            effect_confidence: None,
            lists: None,
            site: None,
            conflict_site: None,
            model: None,
            judged_at: None,
            applied: true,
        }));
    };
    let action = action_of(&row.verdict);
    Ok(Some(AiExplanation {
        applied: action.is_some() && policy.ai.get(domain) == action,
        verdict: row.verdict,
        why: row.why,
        choice: Some(row.choice),
        confidence: row.confidence,
        effect: row.effect,
        effect_confidence: row.effect_confidence,
        lists: Some(row.lists),
        site: row.site,
        conflict_site: row.conflict_site,
        model: Some(row.model),
        judged_at: Some(row.judged_at),
    }))
}
