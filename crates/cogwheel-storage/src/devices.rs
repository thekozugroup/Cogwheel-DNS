//! Named clients — the `devices` and `device_lists` tables.
//!
//! A device is a name attached to an IP. Everything else about it is two flags and a set of list
//! subscriptions; per-device rules live in `rules` with the device's id (see [`crate::Rule`]).
//! Clients that have queried but have no row here are "unnamed", and are discovered from the
//! rollups rather than from this table — see [`Storage::unnamed_clients_24h`].

use crate::sources::now_seconds;
use crate::{NEW_UUID, Storage, StorageError};
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;

/// Every column of `devices`, in the order [`row_to_device`] reads them.
const COLUMNS: &str = "id, name, ip_address, filtering, all_lists, created_at, updated_at";

/// One named client.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    /// TEXT UUID; stable across upgrades.
    pub id: String,
    /// What the household calls it.
    pub name: String,
    /// The client address its queries arrive from; unique across the table.
    pub ip_address: String,
    /// `false` = bypass: every name resolves for this device, and is still logged.
    pub filtering: bool,
    /// `true` = every enabled list applies; `false` = only its `device_lists` rows do.
    pub all_lists: bool,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

/// One `device_lists` row: a device's subscription to one list.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceList {
    /// The device.
    pub device_id: String,
    /// The list it subscribes to.
    pub source_id: String,
}

/// The fields a caller supplies when creating or replacing a device.
#[derive(Debug, Clone)]
pub struct DeviceUpsert {
    /// `Some` updates that row in place; `None` creates one with a SQL-minted v4 UUID.
    pub id: Option<String>,
    /// Display name.
    pub name: String,
    /// Client address; a collision is a [`StorageError::is_unique_violation`].
    pub ip_address: String,
    /// `false` to bypass filtering entirely.
    pub filtering: bool,
    /// `false` to restrict this device to its `device_lists` rows.
    pub all_lists: bool,
}

impl Storage {
    /// Every named device, by name.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn list_devices(&self) -> Result<Vec<Device>, StorageError> {
        self.with_connection(|connection| {
            let mut query =
                connection.prepare(&format!("SELECT {COLUMNS} FROM devices ORDER BY name, id"))?;
            let rows = query.query_map([], row_to_device)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// One device by id, or `None` if it is gone.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn get_device(&self, id: &str) -> Result<Option<Device>, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| {
            Ok(connection
                .query_row(
                    &format!("SELECT {COLUMNS} FROM devices WHERE id = ?1"),
                    [&id],
                    row_to_device,
                )
                .optional()?)
        })
        .await
    }

    /// Create or replace a device, returning the stored row.
    ///
    /// The conflict target is the id alone, on purpose: a request that re-uses another device's
    /// IP is a mistake worth a 409, not an instruction to silently merge two devices into one.
    ///
    /// # Errors
    ///
    /// A duplicate `ip_address` is a [`StorageError::is_unique_violation`].
    pub async fn upsert_device(&self, device: DeviceUpsert) -> Result<Device, StorageError> {
        self.with_connection(move |connection| {
            let now = now_seconds(connection)?;
            Ok(connection.query_row(
                &format!(
                    "INSERT INTO devices (id, name, ip_address, filtering, all_lists, created_at, updated_at)
                     VALUES (COALESCE(?1, {NEW_UUID}), ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(id) DO UPDATE SET
                         name = excluded.name,
                         ip_address = excluded.ip_address,
                         filtering = excluded.filtering,
                         all_lists = excluded.all_lists,
                         updated_at = excluded.updated_at
                     RETURNING {COLUMNS}"
                ),
                params![
                    device.id,
                    device.name,
                    device.ip_address,
                    device.filtering,
                    device.all_lists,
                    now
                ],
                row_to_device,
            )?)
        })
        .await
    }

    /// Forget a device. Returns whether a row was there to remove.
    ///
    /// Cascades to its `device_lists` rows and its per-device `rules`.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn delete_device(&self, id: &str) -> Result<bool, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| {
            Ok(connection.execute("DELETE FROM devices WHERE id = ?1", [&id])? > 0)
        })
        .await
    }

    /// The `device_lists` rows, for one device or for all of them.
    ///
    /// The `None` form is what the policy build and `GET /api/v1/devices` use: one query for the
    /// whole table beats one per device on a household with thirty of them.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn list_device_lists(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<DeviceList>, StorageError> {
        let device_id = device_id.map(ToOwned::to_owned);
        self.with_connection(move |connection| {
            let mut query = connection.prepare(
                "SELECT device_id, source_id FROM device_lists
                 WHERE (?1 IS NULL OR device_id = ?1)
                 ORDER BY device_id, source_id",
            )?;
            let rows = query.query_map([&device_id], |row| {
                Ok(DeviceList {
                    device_id: row.get(0)?,
                    source_id: row.get(1)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Replace a device's list subscriptions with exactly `source_ids`.
    ///
    /// Replace rather than merge because the UI sends the full selection every time; duplicates in
    /// the request collapse against the primary key.
    ///
    /// # Errors
    ///
    /// An id that names no list is a [`StorageError::is_foreign_key_violation`], and nothing is
    /// written — the delete and the inserts share one transaction, so a bad id cannot leave the
    /// device with no lists at all.
    pub async fn set_device_lists(
        &self,
        device_id: &str,
        source_ids: Vec<String>,
    ) -> Result<(), StorageError> {
        let device_id = device_id.to_owned();
        self.with_connection(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "DELETE FROM device_lists WHERE device_id = ?1",
                [&device_id],
            )?;
            {
                let mut insert = transaction.prepare(
                    "INSERT OR IGNORE INTO device_lists (device_id, source_id) VALUES (?1, ?2)",
                )?;
                for source_id in &source_ids {
                    insert.execute(params![device_id, source_id])?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
        .await
    }
}

/// Read a full `devices` row in [`COLUMNS`] order.
fn row_to_device(row: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: row.get(0)?,
        name: row.get(1)?,
        ip_address: row.get(2)?,
        filtering: row.get(3)?,
        all_lists: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}
