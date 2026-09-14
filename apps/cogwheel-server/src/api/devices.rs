//! Devices: a name for an address, and what filtering that address gets (§3 routes 9–12, §6).
//!
//! A device edit only re-maps clients onto scopes, so every write here rebuilds with
//! [`Rebuild::Devices`] and the DNS cache survives it. The one exception is deletion, which is
//! the same kind of change: the address falls back to the household scope, whose cached answers
//! were already correct for it.

use crate::api::{Deleted, non_empty};
use crate::http::{ApiError, ApiJson, ApiResult, ok};
use crate::policy_build::{Rebuild, rebuild};
use crate::state::{ServerState, now_secs};
use axum::extract::{Path, State};
use cogwheel_storage::{ClientStats, Device, DeviceUpsert, Rule, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// One of a device's own rules, as the Devices page lists them.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRule {
    pub id: i64,
    pub domain: String,
    pub action: String,
}

/// A device with everything the page shows about it.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub ip_address: String,
    pub filtering: bool,
    pub all_lists: bool,
    /// Source ids; meaningful only when `all_lists` is false.
    pub lists: Vec<String>,
    pub rules: Vec<DeviceRule>,
    pub queries_24h: i64,
    pub blocked_24h: i64,
    pub last_seen_at: Option<i64>,
}

/// A client that has resolved something but has no device row.
#[derive(Debug, Clone, Serialize)]
pub struct UnnamedClient {
    pub ip: String,
    pub queries_24h: i64,
    pub blocked_24h: i64,
    pub last_seen_at: i64,
}

/// Route 9's body.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceCatalogue {
    pub devices: Vec<DeviceView>,
    pub unnamed_clients: Vec<UnnamedClient>,
}

/// The body POST and PUT both take. The UI always sends all five fields.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInput {
    pub name: String,
    pub ip_address: String,
    pub filtering: Option<bool>,
    pub all_lists: Option<bool>,
    pub lists: Option<Vec<String>>,
}

impl DeviceInput {
    /// The row to write, with `id` for the caller to fill in, and the list selection to replace
    /// this device's with.
    fn validate(self) -> Result<(DeviceUpsert, Vec<String>), ApiError> {
        let name = non_empty(&self.name, "Give the device a name.")?;
        let address = self.ip_address.trim();
        let ip: IpAddr = address
            .parse()
            .map_err(|_| ApiError::bad_request(format!("{address:?} is not an IP address.")))?;
        let mut lists = self.lists.unwrap_or_default();
        lists.sort_unstable();
        lists.dedup();
        Ok((
            DeviceUpsert {
                id: None,
                name,
                // Stored canonically so that the query log's `client` text — which is an address
                // formatted by the runtime — joins against it.
                ip_address: ip.to_string(),
                filtering: self.filtering.unwrap_or(true),
                all_lists: self.all_lists.unwrap_or(true),
            },
            lists,
        ))
    }
}

/// Route 9: every device, plus the addresses that have no device yet.
pub async fn list(State(state): State<ServerState>) -> ApiResult<DeviceCatalogue> {
    let now = now_secs();
    let devices = state.storage.list_devices().await?;
    let links = state.storage.list_device_lists(None).await?;
    let rules = state.storage.list_rules(None).await?;
    let stats: HashMap<String, ClientStats> = state
        .storage
        .per_client_24h(now)
        .await?
        .into_iter()
        .map(|client| (client.client.clone(), client))
        .collect();

    let views = devices
        .iter()
        .map(|device| {
            view(
                device,
                links
                    .iter()
                    .filter(|link| link.device_id == device.id)
                    .map(|link| link.source_id.clone())
                    .collect(),
                &rules,
                stats.get(&device.ip_address),
            )
        })
        .collect();

    ok(DeviceCatalogue {
        devices: views,
        unnamed_clients: state
            .storage
            .unnamed_clients_24h(now)
            .await?
            .into_iter()
            .map(|client| UnnamedClient {
                ip: client.client,
                queries_24h: client.queries,
                blocked_24h: client.blocked,
                last_seen_at: client.last_seen,
            })
            .collect(),
    })
}

/// Route 10: name an address.
pub async fn create(
    State(state): State<ServerState>,
    ApiJson(input): ApiJson<DeviceInput>,
) -> ApiResult<DeviceView> {
    let (device, lists) = input.validate()?;
    ok(store(&state, device, lists).await?)
}

/// Route 11: rename, re-address, or change what a device filters.
pub async fn update(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<DeviceInput>,
) -> ApiResult<DeviceView> {
    let (mut device, lists) = input.validate()?;
    // Checked first because the upsert's conflict target is the id: a PUT to an id that does not
    // exist would otherwise create a device rather than answering 404.
    if state.storage.get_device(&id).await?.is_none() {
        return Err(ApiError::not_found("That device does not exist."));
    }
    device.id = Some(id);
    ok(store(&state, device, lists).await?)
}

/// Route 12: forget a device. Its list selection and its own rules go with it.
pub async fn remove(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Deleted> {
    if !state.storage.delete_device(&id).await? {
        return Err(ApiError::not_found("That device does not exist."));
    }
    rebuild(&state, Rebuild::Devices).await?;
    tracing::info!(device = %id, "device deleted");
    ok(Deleted { deleted: true })
}

/// Write a device and its list selection, then re-scope.
async fn store(
    state: &ServerState,
    upsert: DeviceUpsert,
    lists: Vec<String>,
) -> Result<DeviceView, ApiError> {
    // The row and the selection go in together, in storage's one transaction: a refused
    // selection must leave no device behind, and a device subscribed to nothing filters nothing.
    // The selection is sent whole every time, including the empty one an `all_lists` device has,
    // so a device switching back to "every list" does not keep a stale selection.
    let device = state
        .storage
        .upsert_device(upsert, lists.clone())
        .await
        .map_err(rejected)?;
    rebuild(state, Rebuild::Devices).await?;

    let rules = state.storage.list_rules(Some(&device.id)).await?;
    let stats = state
        .storage
        .per_client_24h(now_secs())
        .await?
        .into_iter()
        .find(|client| client.client == device.ip_address);
    tracing::info!(device = %device.name, address = %device.ip_address, "device saved");
    Ok(view(&device, lists, &rules, stats.as_ref()))
}

/// Assemble one device's view from the rows that belong to it.
fn view(
    device: &Device,
    lists: Vec<String>,
    rules: &[Rule],
    stats: Option<&ClientStats>,
) -> DeviceView {
    DeviceView {
        id: device.id.clone(),
        name: device.name.clone(),
        ip_address: device.ip_address.clone(),
        filtering: device.filtering,
        all_lists: device.all_lists,
        lists,
        rules: rules
            .iter()
            .filter(|rule| rule.device_id.as_deref() == Some(device.id.as_str()))
            .map(|rule| DeviceRule {
                id: rule.id,
                domain: rule.domain.clone(),
                action: rule.action.clone(),
            })
            .collect(),
        queries_24h: stats.map_or(0, |stats| stats.queries),
        blocked_24h: stats.map_or(0, |stats| stats.blocked),
        last_seen_at: stats.map(|stats| stats.last_seen),
    }
}

/// The two ways a device write is the caller's mistake rather than a fault: an address another
/// device already answers to — the address is how a query is attributed — and a selection naming
/// a list that does not exist.
fn rejected(error: StorageError) -> ApiError {
    if error.is_unique_violation() {
        return ApiError::conflict("Another device already uses that address.");
    }
    if error.is_foreign_key_violation() {
        return ApiError::bad_request("That selection names a list that does not exist.");
    }
    error.into()
}
