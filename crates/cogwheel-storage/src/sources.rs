//! Subscribed lists — the `sources` table.
//!
//! Rows are listed in `id` order everywhere because that order *is* the slot assignment: the
//! enabled sources take bits 0..63 of a device's list mask in `id` order (§6), so a listing that
//! sorted by name would hand the policy builder a different mask for the same subscriptions.

use crate::{NEW_UUID, Storage, StorageError};
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;

/// Every column of `sources`, in the order [`row_to_source`] reads them.
const COLUMNS: &str = "id, name, url, kind, enabled, etag, last_modified, last_fetched_at, \
                       last_ok_at, rule_count, last_error, note, created_at, updated_at";

/// One subscribed list.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    /// TEXT UUID; stable across upgrades.
    pub id: String,
    /// Display name, unique across the table.
    pub name: String,
    /// Where the body is fetched from: `http(s):` or `data:`.
    pub url: String,
    /// Parser to use: `hosts`, `domains` or `adblock`.
    pub kind: String,
    /// Whether the list contributes to the compiled index at all.
    pub enabled: bool,
    /// Validator from the last successful fetch, sent back as `If-None-Match`.
    pub etag: Option<String>,
    /// Validator from the last successful fetch, sent back as `If-Modified-Since`.
    pub last_modified: Option<String>,
    /// When a fetch was last *attempted*, successful or not. Drives the retry schedule.
    pub last_fetched_at: Option<i64>,
    /// When a fetch last succeeded. Drives the daily refresh schedule.
    pub last_ok_at: Option<i64>,
    /// Entries the last accepted body parsed to.
    pub rule_count: i64,
    /// Why the last attempt failed, cleared by the next success.
    pub last_error: Option<String>,
    /// Advisory note from verification — protected names this list would have taken out.
    pub note: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

/// The fields a caller supplies when subscribing to a list.
#[derive(Debug, Clone)]
pub struct NewSource {
    /// Supply an id to keep one the caller already minted; `None` mints a v4 UUID in SQL.
    pub id: Option<String>,
    /// Display name; a collision is a [`StorageError::is_unique_violation`].
    pub name: String,
    /// Fetch URL.
    pub url: String,
    /// Parser kind.
    pub kind: String,
    /// Whether it starts enabled.
    pub enabled: bool,
}

/// A partial edit: `None` leaves the column as it is.
#[derive(Debug, Clone, Default)]
pub struct SourcePatch {
    /// New display name.
    pub name: Option<String>,
    /// New fetch URL — the caller refetches after this.
    pub url: Option<String>,
    /// New parser kind — the caller refetches after this.
    pub kind: Option<String>,
    /// New enabled flag — the caller rebuilds from the cached body, no network.
    pub enabled: Option<bool>,
}

/// The outcome of one refresh attempt, as the refresh pipeline records it (§2.7).
///
/// Three variants and not four: a body that failed verification and a body that never arrived both
/// leave the previous cached body in place and record why, which is the only distinction the table
/// needs. The API's "rejected" versus "failed" wording is the server's to make.
#[derive(Debug, Clone)]
pub enum FetchStatus {
    /// A new body was fetched, parsed and accepted.
    Ok {
        /// Unix seconds; sets both `last_fetched_at` and `last_ok_at`.
        at: i64,
        /// `ETag` for the next conditional request.
        etag: Option<String>,
        /// `Last-Modified` for the next conditional request.
        last_modified: Option<String>,
        /// Entries the body parsed to.
        rule_count: i64,
        /// Advisory note from verification.
        note: Option<String>,
    },
    /// Upstream answered 304; the cached body and its rule count still stand.
    Unchanged {
        /// Unix seconds; sets `last_fetched_at` and `last_ok_at`, since the list is current.
        at: i64,
    },
    /// The fetch failed, or the body was rejected. The previous body keeps serving.
    Failed {
        /// Unix seconds; sets `last_fetched_at` only, so the retry schedule backs off.
        at: i64,
        /// Message shown against the list in the UI.
        error: String,
    },
}

impl Storage {
    /// Every subscribed list, in slot order.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn list_sources(&self) -> Result<Vec<Source>, StorageError> {
        self.with_connection(|connection| {
            let mut query =
                connection.prepare(&format!("SELECT {COLUMNS} FROM sources ORDER BY id"))?;
            let rows = query.query_map([], row_to_source)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// One list by id, or `None` if it is gone.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn get_source(&self, id: &str) -> Result<Option<Source>, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| {
            Ok(connection
                .query_row(
                    &format!("SELECT {COLUMNS} FROM sources WHERE id = ?1"),
                    [&id],
                    row_to_source,
                )
                .optional()?)
        })
        .await
    }

    /// Subscribe to a list, returning the stored row.
    ///
    /// # Errors
    ///
    /// A duplicate name is a [`StorageError::is_unique_violation`]; an unknown `kind` fails the
    /// column's `CHECK`.
    pub async fn insert_source(&self, source: NewSource) -> Result<Source, StorageError> {
        self.with_connection(move |connection| {
            let now = now_seconds(connection)?;
            Ok(connection.query_row(
                &format!(
                    "INSERT INTO sources (id, name, url, kind, enabled, created_at, updated_at)
                     VALUES (COALESCE(?1, {NEW_UUID}), ?2, ?3, ?4, ?5, ?6, ?6)
                     RETURNING {COLUMNS}"
                ),
                params![
                    source.id,
                    source.name,
                    source.url,
                    source.kind,
                    source.enabled,
                    now
                ],
                row_to_source,
            )?)
        })
        .await
    }

    /// Apply a partial edit, returning the updated row or `None` if the id is unknown.
    ///
    /// # Errors
    ///
    /// A name that collides with another list is a [`StorageError::is_unique_violation`].
    pub async fn update_source(
        &self,
        id: &str,
        patch: SourcePatch,
    ) -> Result<Option<Source>, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| {
            let now = now_seconds(connection)?;
            Ok(connection
                .query_row(
                    &format!(
                        "UPDATE sources SET
                             name = COALESCE(?2, name),
                             url = COALESCE(?3, url),
                             kind = COALESCE(?4, kind),
                             enabled = COALESCE(?5, enabled),
                             updated_at = ?6
                         WHERE id = ?1
                         RETURNING {COLUMNS}"
                    ),
                    params![id, patch.name, patch.url, patch.kind, patch.enabled, now],
                    row_to_source,
                )
                .optional()?)
        })
        .await
    }

    /// Unsubscribe. Returns whether a row was there to remove.
    ///
    /// Cascades to `device_lists`; the caller removes the cached body file.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn delete_source(&self, id: &str) -> Result<bool, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| {
            Ok(connection.execute("DELETE FROM sources WHERE id = ?1", [&id])? > 0)
        })
        .await
    }

    /// Record what one refresh attempt did. Returns whether the list still exists.
    ///
    /// A failure deliberately leaves `rule_count`, `etag` and `last_modified` alone: the cached
    /// body is still the one being served, so the numbers describing it must keep describing it,
    /// and the validators must still match it or the next conditional GET asks about the wrong
    /// body.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn update_fetch_status(
        &self,
        id: &str,
        status: FetchStatus,
    ) -> Result<bool, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| {
            let changed = match status {
                FetchStatus::Ok {
                    at,
                    etag,
                    last_modified,
                    rule_count,
                    note,
                } => connection.execute(
                    "UPDATE sources SET etag = ?2, last_modified = ?3, last_fetched_at = ?4,
                         last_ok_at = ?4, rule_count = ?5, last_error = NULL, note = ?6,
                         updated_at = ?4
                     WHERE id = ?1",
                    params![id, etag, last_modified, at, rule_count, note],
                )?,
                FetchStatus::Unchanged { at } => connection.execute(
                    "UPDATE sources SET last_fetched_at = ?2, last_ok_at = ?2, last_error = NULL,
                         updated_at = ?2
                     WHERE id = ?1",
                    params![id, at],
                )?,
                FetchStatus::Failed { at, error } => connection.execute(
                    "UPDATE sources SET last_fetched_at = ?2, last_error = ?3, updated_at = ?2
                     WHERE id = ?1",
                    params![id, at, error],
                )?,
            };
            Ok(changed > 0)
        })
        .await
    }
}

/// Read a full `sources` row in [`COLUMNS`] order.
fn row_to_source(row: &Row<'_>) -> rusqlite::Result<Source> {
    Ok(Source {
        id: row.get(0)?,
        name: row.get(1)?,
        url: row.get(2)?,
        kind: row.get(3)?,
        enabled: row.get(4)?,
        etag: row.get(5)?,
        last_modified: row.get(6)?,
        last_fetched_at: row.get(7)?,
        last_ok_at: row.get(8)?,
        rule_count: row.get(9)?,
        last_error: row.get(10)?,
        note: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

/// Current unix seconds, from SQLite rather than the system clock.
///
/// One clock for every timestamp this crate writes. `unixepoch()` is also what the migration uses,
/// so an upgraded row and a row written a second later are on the same scale even if the host's
/// `SystemTime` disagrees with SQLite's idea of now.
pub(crate) fn now_seconds(connection: &rusqlite::Connection) -> rusqlite::Result<i64> {
    connection.query_row("SELECT unixepoch()", [], |row| row.get(0))
}
