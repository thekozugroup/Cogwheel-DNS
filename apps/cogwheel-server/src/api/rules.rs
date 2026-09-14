//! Allow and block rules, for everyone or for one device (§3 routes 13–15).
//!
//! A rule is the one thing in the product that outranks a subscribed list *and* the protected
//! suffixes, so the domain is normalised and shape-checked before it is stored: a rule that
//! silently never matches is worse than a rejected one.

use crate::api::Deleted;
use crate::http::{ApiError, ApiJson, ApiQuery, ApiResult, ok};
use crate::policy_build::{Rebuild, rebuild};
use crate::state::ServerState;
use axum::extract::{Path, State};
use cogwheel_policy::{Action, is_domain_shaped, normalize_rule_domain};
use cogwheel_storage::Rule;
use serde::Deserialize;
use std::str::FromStr;

/// `?device_id=` — absent means every rule, household ones included.
#[derive(Debug, Default, Deserialize)]
pub struct RuleQuery {
    pub device_id: Option<String>,
}

/// `{domain, action, device_id?}`; the key is omitted entirely for a household rule.
#[derive(Debug, Deserialize)]
pub struct RuleInput {
    pub domain: String,
    pub action: String,
    pub device_id: Option<String>,
}

/// Route 13: the rules, optionally for one device.
pub async fn list(
    State(state): State<ServerState>,
    ApiQuery(query): ApiQuery<RuleQuery>,
) -> ApiResult<Vec<Rule>> {
    let device_id = query
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    ok(state.storage.list_rules(device_id).await?)
}

/// Route 14: add a rule, or change the action of one that already exists.
pub async fn create(
    State(state): State<ServerState>,
    ApiJson(input): ApiJson<RuleInput>,
) -> ApiResult<Rule> {
    let domain = normalize_rule_domain(&input.domain);
    if !is_domain_shaped(&domain) {
        return Err(ApiError::bad_request(format!(
            "{:?} is not a domain name.",
            input.domain.trim()
        )));
    }
    let action = Action::from_str(input.action.trim())
        .map_err(|()| ApiError::bad_request("A rule either allows or blocks."))?;
    let device_id = input
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    if let Some(device_id) = device_id
        && state.storage.get_device(device_id).await?.is_none()
    {
        return Err(ApiError::not_found("That device does not exist."));
    }

    let rule = state
        .storage
        .upsert_rule(&domain, action.as_str(), device_id)
        .await?;
    // A household rule changes what every scope decides, so the cache goes; a device rule only
    // changes that one device's scope.
    rebuild(&state, rebuild_kind(device_id.is_none())).await?;
    tracing::info!(domain = %rule.domain, action = %rule.action, device = ?rule.device_name, "rule saved");
    ok(rule)
}

/// Route 15: remove a rule.
///
/// The id is taken as text and parsed here so that a malformed one answers 404 in the same
/// envelope as an unknown one; an `i64` path extractor would reject it with a bare 400 that the
/// UI cannot show.
pub async fn remove(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Deleted> {
    let id: i64 = id
        .parse()
        .map_err(|_| ApiError::not_found("That rule does not exist."))?;
    // The delete hands back the row it took, because which rebuild this needs depends on whether
    // the rule applied to everyone and there is nothing left to ask afterwards.
    let deleted = state
        .storage
        .delete_rule(id)
        .await?
        .ok_or_else(|| ApiError::not_found("That rule does not exist."))?;
    rebuild(&state, rebuild_kind(deleted.device_id.is_none())).await?;
    ok(Deleted { deleted: true })
}

/// Which rebuild a rule change needs.
const fn rebuild_kind(household: bool) -> Rebuild {
    if household {
        Rebuild::Household
    } else {
        Rebuild::Devices
    }
}
