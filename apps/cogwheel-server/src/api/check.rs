//! "Why is this blocked?" (§3 route 21).
//!
//! Runs the real evaluator against the policy the resolver is using right now, for the scope the
//! named client resolves under. It is the one place a person can see which of the twelve
//! precedence steps of §6 decided a name, which is the difference between trusting the appliance
//! and guessing at it.

use crate::api::runtime::paused_until;
use crate::http::{ApiError, ApiQuery, ApiResult, ok};
use crate::state::ServerState;
use axum::extract::State;
use cogwheel_policy::{Reason, evaluate, is_domain_shaped, normalize_domain};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// `?domain=&client=`.
#[derive(Debug, Deserialize)]
pub struct CheckQuery {
    /// Optional only so that a missing one is refused in the same envelope as an empty one.
    pub domain: Option<String>,
    pub client: Option<String>,
}

/// What the evaluator decided, and which step decided it.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub domain: String,
    /// `allow` or `block`.
    pub verdict: &'static str,
    pub reason: Reason,
    /// The list that decided, for the list tiers.
    pub list: Option<String>,
    /// Which set of settings answered: `household`, `device`, `unfiltered` or `paused`.
    pub scope: &'static str,
    pub device_name: Option<String>,
}

/// Route 21: evaluate one name as one client.
pub async fn check(
    State(state): State<ServerState>,
    ApiQuery(query): ApiQuery<CheckQuery>,
) -> ApiResult<CheckResult> {
    let domain = normalize_domain(query.domain.as_deref().unwrap_or_default());
    if domain.is_empty() {
        return Err(ApiError::bad_request("Enter a domain to check."));
    }
    // The same shape `POST /rules` enforces. Answering "allowed" for a string that is not a
    // domain is worse than refusing it: the evaluator will happily report `no_match` for
    // anything, and the page renders that as a confident verdict about a typo.
    if !is_domain_shaped(&domain) {
        return Err(ApiError::bad_request(format!(
            "{domain:?} is not a domain name."
        )));
    }
    let client = match query
        .client
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        Some(text) => Some(
            text.parse::<IpAddr>()
                .map_err(|_| ApiError::bad_request(format!("{text:?} is not an IP address.")))?,
        ),
        None => None,
    };

    let policy = state.runtime.current_policy();
    let names = state.device_names();
    let device_name = client
        .and_then(|ip| names.get(&ip))
        .map(|name| name.to_string());

    // Pause is the first step of §6 and is not part of the policy, so it is answered here the
    // same way the hot path answers it: as the unfiltered scope, with the reason rewritten.
    if paused_until(&state).is_some() {
        return ok(CheckResult {
            domain,
            verdict: "allow",
            reason: Reason::Paused,
            list: None,
            scope: "paused",
            device_name,
        });
    }

    let scope = client.map_or_else(
        || policy.scope(cogwheel_policy::SCOPE_HOUSEHOLD),
        |ip| policy.scope_for(ip),
    );
    let known_device = client.is_some_and(|ip| policy.by_ip.contains_key(&ip));
    let verdict = evaluate(&policy, scope, &domain);
    let list = verdict
        .slot()
        .and_then(|slot| policy.index.name(slot))
        .map(|name| name.to_string());

    ok(CheckResult {
        domain,
        verdict: if verdict.is_blocked() {
            "block"
        } else {
            "allow"
        },
        reason: verdict.reason(),
        list,
        scope: match (known_device, scope.filtering) {
            (_, false) => "unfiltered",
            (true, true) => "device",
            (false, true) => "household",
        },
        device_name,
    })
}
