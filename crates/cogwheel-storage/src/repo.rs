//! The five small tables: `sources`, `devices`, `device_lists`, `rules`, `settings`, and the
//! 24-hour reads over `query_stats_hourly`.
//!
//! They are together because they are the same shape — a handful of columns, a list, an upsert and
//! a delete apiece — and splitting one file per table bought nothing but five copies of the same
//! row-mapping boilerplate. The raw query log is the exception and lives in `query_log.rs`: it is
//! the only table with a write path on a timer, a keyset reader and a retention policy.
//!
//! `sources` rows are listed in `id` order everywhere because that order *is* the slot assignment:
//! the enabled sources take bits 0..63 of a device's list mask in `id` order (§6), so a listing
//! sorted by name would hand the policy builder a different mask for the same subscriptions.

use crate::{NEW_UUID, Storage, StorageError};
use rusqlite::{Connection, OptionalExtension, params};

/// Seconds per rollup bucket, and how many of them the 24-hour reads cover.
const HOUR: i64 = 3600;
const BUCKETS: i64 = 24;

/// The one key `settings` holds.
///
/// `pause_until` is stored rather than only held in the runtime's `AtomicU64` so that a pause
/// survives a restart: someone who pauses for an hour and reboots the appliance should not find
/// filtering back on. Everything else that could be a setting is an environment variable by
/// design (§8), which is why this table has one key and no schema for a second.
const PAUSE_UNTIL: &str = "pause_until";

record! {
    /// One subscribed list.
    Source from "sources" {
        id: String,
        name: String,
        url: String,
        kind: String,
        /// Whether it contributes to the compiled index at all.
        enabled: bool,
        /// Validators from the last successful fetch, replayed on the next conditional GET.
        etag: Option<String>,
        last_modified: Option<String>,
        /// When a fetch was last *attempted*, successful or not. Drives the retry schedule.
        last_fetched_at: Option<i64>,
        /// When one last succeeded. Drives the daily refresh schedule.
        last_ok_at: Option<i64>,
        rule_count: i64,
        last_error: Option<String>,
        /// Advisory: the protected names this list would have blocked, which stay reachable.
        note: Option<String>,
        created_at: i64,
        updated_at: i64,
    }
}

record! {
    /// One named client.
    Device from "devices" {
        id: String,
        name: String,
        ip_address: String,
        /// `false` = bypass: every name resolves for this device, and is still logged.
        filtering: bool,
        /// `true` = every enabled list applies; `false` = only its `device_lists` rows do.
        all_lists: bool,
        created_at: i64,
        updated_at: i64,
    }
}

record! {
    /// One `device_lists` row: a device's subscription to one list.
    DeviceList from "device_lists" {
        device_id: String,
        source_id: String,
    }
}

record! {
    /// One allow or block rule.
    ///
    /// Uniqueness is on `(domain, COALESCE(device_id, ''))` — one verdict per domain per scope.
    /// The `COALESCE` is what makes it work at all: SQL `UNIQUE` treats every `NULL` as distinct,
    /// so a plain `UNIQUE (domain, device_id)` would hold ten conflicting household rules for the
    /// same name.
    Rule {
        id: i64,
        /// Normalised, no leading `*.`; matches on label boundaries.
        domain: String,
        action: String,
        /// The device this applies to, or `None` for everyone.
        device_id: Option<String>,
        /// That device's current name, resolved at read time so a rename relabels its rules.
        device_name: Option<String>,
        created_at: i64,
    }
}

record! {
    /// One hour of the Overview's bar chart.
    HourBucket from "query_stats_hourly" {
        /// Unix seconds, truncated to the hour.
        hour: i64,
        queries: i64,
        blocked: i64,
    }
}

record! {
    /// One client's last 24 hours.
    ClientStats {
        client: String,
        queries: i64,
        blocked: i64,
        last_seen: i64,
    }
}

/// The fields a caller supplies when subscribing to a list.
#[derive(Debug, Clone)]
pub struct NewSource {
    /// Supply an id to keep one the caller already minted; `None` mints a v4 UUID in SQL.
    pub id: Option<String>,
    pub name: String,
    pub url: String,
    pub kind: String,
    pub enabled: bool,
}

/// A partial edit of a list: `None` leaves the column as it is.
#[derive(Debug, Clone, Default)]
pub struct SourcePatch {
    pub name: Option<String>,
    pub url: Option<String>,
    pub kind: Option<String>,
    pub enabled: Option<bool>,
}

/// The fields a caller supplies when creating or replacing a device.
#[derive(Debug, Clone)]
pub struct DeviceUpsert {
    /// `Some` updates that row in place; `None` creates one with a SQL-minted v4 UUID.
    pub id: Option<String>,
    pub name: String,
    pub ip_address: String,
    pub filtering: bool,
    pub all_lists: bool,
}

/// The outcome of one refresh attempt, as the refresh pipeline records it (§2.7).
///
/// Three variants and not four: a body that failed verification and a body that never arrived both
/// leave the previous cached body in place and record why, which is the only distinction the table
/// needs. The API's "rejected" versus "failed" wording is the server's to make.
#[derive(Debug, Clone)]
pub enum FetchStatus {
    /// A new body was fetched, parsed and accepted. Sets `last_fetched_at` and `last_ok_at`.
    Ok {
        at: i64,
        etag: Option<String>,
        last_modified: Option<String>,
        rule_count: i64,
        note: Option<String>,
    },
    /// Upstream answered 304; the cached body and its rule count still stand.
    Unchanged { at: i64 },
    /// The fetch failed, or the body was rejected. The previous body keeps serving, so this sets
    /// `last_fetched_at` only and the retry schedule backs off.
    Failed { at: i64, error: String },
}

/// The joined projection [`Rule::from_row`] reads, column for column.
const SELECT_RULES: &str = "SELECT r.id, r.domain, r.action, r.device_id, d.name, r.created_at \
                            FROM rules r LEFT JOIN devices d ON d.id = r.device_id";

impl Storage {
    // ---- sources ----------------------------------------------------------------------------

    /// Every subscribed list, in slot order.
    ///
    /// # Errors
    ///
    /// Every method here propagates SQLite failures as [`StorageError::Sqlite`]; only the ones
    /// whose failure means something to a *user* — a duplicate name, an id that names nothing —
    /// say so again below.
    pub async fn list_sources(&self) -> Result<Vec<Source>, StorageError> {
        self.with_connection(|connection| Source::all(connection, "ORDER BY id", []))
            .await
    }

    /// One list by id, or `None` if it is gone.
    pub async fn get_source(&self, id: &str) -> Result<Option<Source>, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| Source::one(connection, "WHERE id = ?1", [&id]))
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
                     RETURNING {}",
                    Source::COLUMNS
                ),
                params![
                    source.id,
                    source.name,
                    source.url,
                    source.kind,
                    source.enabled,
                    now
                ],
                Source::from_row,
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
                             name = COALESCE(?2, name), url = COALESCE(?3, url),
                             kind = COALESCE(?4, kind), enabled = COALESCE(?5, enabled),
                             updated_at = ?6
                         WHERE id = ?1
                         RETURNING {}",
                        Source::COLUMNS
                    ),
                    params![id, patch.name, patch.url, patch.kind, patch.enabled, now],
                    Source::from_row,
                )
                .optional()?)
        })
        .await
    }

    /// Unsubscribe, cascading to `device_lists`. The caller removes the cached body file.
    pub async fn delete_source(&self, id: &str) -> Result<bool, StorageError> {
        self.delete("DELETE FROM sources WHERE id = ?1", id.to_owned())
            .await
    }

    /// Record what one refresh attempt did. Returns whether the list still exists.
    ///
    /// A failure deliberately leaves `rule_count`, `etag` and `last_modified` alone: the cached
    /// body is still the one being served, so the numbers describing it must keep describing it,
    /// and the validators must still match it or the next conditional GET asks about the wrong
    /// body.
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

    // ---- devices ----------------------------------------------------------------------------

    /// Every named device, by name.
    pub async fn list_devices(&self) -> Result<Vec<Device>, StorageError> {
        self.with_connection(|connection| Device::all(connection, "ORDER BY name, id", []))
            .await
    }

    /// One device by id, or `None` if it is gone.
    pub async fn get_device(&self, id: &str) -> Result<Option<Device>, StorageError> {
        let id = id.to_owned();
        self.with_connection(move |connection| Device::one(connection, "WHERE id = ?1", [&id]))
            .await
    }

    /// Create or replace a device together with the lists it subscribes to, returning the stored
    /// row.
    ///
    /// One method and one transaction rather than an upsert followed by a selection write,
    /// because the two are one change: a selection naming a list that does not exist would
    /// otherwise leave a device row with `all_lists = 0` and no `device_lists` rows behind, and
    /// that device matches no list at all — it resolves everything, silently, after a request the
    /// caller was told had failed.
    ///
    /// The conflict target is the id alone, on purpose: a request that re-uses another device's IP
    /// is a mistake worth a 409, not an instruction to silently merge two devices into one. The
    /// selection is replaced rather than merged, because the UI sends all of it every time;
    /// duplicates within one request collapse against the primary key.
    ///
    /// # Errors
    ///
    /// A duplicate `ip_address` is a [`StorageError::is_unique_violation`] and a `source_id` that
    /// names no list is a [`StorageError::is_foreign_key_violation`]. Neither writes anything.
    pub async fn upsert_device(
        &self,
        device: DeviceUpsert,
        source_ids: Vec<String>,
    ) -> Result<Device, StorageError> {
        self.with_connection(move |connection| {
            let transaction = connection.transaction()?;
            let now = now_seconds(&transaction)?;
            let stored = transaction.query_row(
                &format!(
                    "INSERT INTO devices (id, name, ip_address, filtering, all_lists, created_at, updated_at)
                     VALUES (COALESCE(?1, {NEW_UUID}), ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(id) DO UPDATE SET
                         name = excluded.name, ip_address = excluded.ip_address,
                         filtering = excluded.filtering, all_lists = excluded.all_lists,
                         updated_at = excluded.updated_at
                     RETURNING {}",
                    Device::COLUMNS
                ),
                params![
                    device.id,
                    device.name,
                    device.ip_address,
                    device.filtering,
                    device.all_lists,
                    now
                ],
                Device::from_row,
            )?;
            transaction.execute("DELETE FROM device_lists WHERE device_id = ?1", [&stored.id])?;
            {
                let mut insert = transaction.prepare(
                    "INSERT OR IGNORE INTO device_lists (device_id, source_id) VALUES (?1, ?2)",
                )?;
                for source_id in &source_ids {
                    insert.execute(params![stored.id, source_id])?;
                }
            }
            transaction.commit()?;
            Ok(stored)
        })
        .await
    }

    /// Forget a device, cascading to its `device_lists` rows and its per-device `rules`.
    pub async fn delete_device(&self, id: &str) -> Result<bool, StorageError> {
        self.delete("DELETE FROM devices WHERE id = ?1", id.to_owned())
            .await
    }

    /// The `device_lists` rows, for one device or for all of them.
    ///
    /// The `None` form is what the policy build and `GET /api/v1/devices` use: one query for the
    /// whole table beats one per device on a household with thirty of them.
    pub async fn list_device_lists(
        &self,
        device_id: Option<&str>,
    ) -> Result<Vec<DeviceList>, StorageError> {
        let device_id = device_id.map(ToOwned::to_owned);
        self.with_connection(move |connection| {
            DeviceList::all(
                connection,
                "WHERE (?1 IS NULL OR device_id = ?1) ORDER BY device_id, source_id",
                [&device_id],
            )
        })
        .await
    }

    // ---- rules ------------------------------------------------------------------------------

    /// Rules for one device, or every rule when `device_id` is `None`.
    ///
    /// The `None` form returns household *and* per-device rules: the policy build wants the whole
    /// table in one query and partitions it itself.
    pub async fn list_rules(&self, device_id: Option<&str>) -> Result<Vec<Rule>, StorageError> {
        let device_id = device_id.map(ToOwned::to_owned);
        self.with_connection(move |connection| {
            collect(
                connection,
                &format!(
                    "{SELECT_RULES} WHERE (?1 IS NULL OR r.device_id = ?1) ORDER BY r.domain, r.id"
                ),
                [&device_id],
                Rule::from_row,
            )
        })
        .await
    }

    /// Set the verdict for one domain in one scope, returning the stored rule.
    ///
    /// Flipping a rule from block to allow keeps the row and its id, because the UI is showing that
    /// id in a list the user is still looking at and a delete-plus-insert would make their next
    /// click hit a row that no longer exists.
    ///
    /// # Errors
    ///
    /// An `action` other than `allow`/`block` fails the column's `CHECK`; a `device_id` naming no
    /// device is a [`StorageError::is_foreign_key_violation`].
    pub async fn upsert_rule(
        &self,
        domain: &str,
        action: &str,
        device_id: Option<&str>,
    ) -> Result<Rule, StorageError> {
        let (domain, action) = (domain.to_owned(), action.to_owned());
        let device_id = device_id.map(ToOwned::to_owned);
        self.with_connection(move |connection| {
            let id: i64 = connection.query_row(
                "INSERT INTO rules (domain, action, device_id, created_at)
                 VALUES (?1, ?2, ?3, unixepoch())
                 ON CONFLICT (domain, COALESCE(device_id, '')) DO UPDATE SET action = excluded.action
                 RETURNING id",
                params![domain, action, device_id],
                |row| row.get(0),
            )?;
            Ok(connection.query_row(
                &format!("{SELECT_RULES} WHERE r.id = ?1"),
                [id],
                Rule::from_row,
            )?)
        })
        .await
    }

    /// Remove a rule, returning the row that was removed, or `None` if the id names nothing.
    ///
    /// The row comes back because which policy rebuild a delete needs turns on whether the rule
    /// applied to everyone, and after the delete there is nothing left to ask. Read and delete are
    /// one statement apart rather than in a transaction because this crate has one connection and
    /// the caller holds its mutex for both.
    pub async fn delete_rule(&self, id: i64) -> Result<Option<Rule>, StorageError> {
        self.with_connection(move |connection| {
            let rule = connection
                .query_row(
                    &format!("{SELECT_RULES} WHERE r.id = ?1"),
                    [id],
                    Rule::from_row,
                )
                .optional()?;
            if rule.is_some() {
                connection.execute("DELETE FROM rules WHERE id = ?1", [id])?;
            }
            Ok(rule)
        })
        .await
    }

    // ---- settings ---------------------------------------------------------------------------

    /// When protection is paused until, or `None` if it is not paused.
    ///
    /// A stored `0` and a value that will not parse both read as "not paused" — §2.1 defines absent
    /// and 0 as the same state, and a garbled row should fail open to filtering rather than leave
    /// the household unprotected while the UI insists everything is fine.
    pub async fn pause_until(&self) -> Result<Option<i64>, StorageError> {
        self.with_connection(|connection| {
            let stored: Option<String> = connection
                .query_row(
                    "SELECT value FROM settings WHERE key = ?1",
                    [PAUSE_UNTIL],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(stored
                .and_then(|value| value.trim().parse::<i64>().ok())
                .filter(|until| *until > 0))
        })
        .await
    }

    /// Set or clear the pause deadline.
    ///
    /// `None` deletes the row rather than writing a zero, so the table is empty whenever nothing is
    /// paused and "is there a settings row at all" stays a meaningful question.
    pub async fn set_pause_until(&self, until: Option<i64>) -> Result<(), StorageError> {
        self.with_connection(move |connection| {
            match until.filter(|until| *until > 0) {
                Some(until) => {
                    let now = now_seconds(connection)?;
                    connection.execute(
                        "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
                         ON CONFLICT(key) DO UPDATE SET
                             value = excluded.value, updated_at = excluded.updated_at",
                        params![PAUSE_UNTIL, until.to_string(), now],
                    )?;
                }
                None => {
                    connection.execute("DELETE FROM settings WHERE key = ?1", [PAUSE_UNTIL])?;
                }
            }
            Ok(())
        })
        .await
    }

    // ---- 24-hour rollup reads ---------------------------------------------------------------
    //
    // Everything here reads `query_stats_hourly` and never the raw log, which is what makes the
    // Overview's 5-second poll affordable and what makes the numbers survive both a cleared log
    // and `HISTORY_DAYS=0`.

    /// The last 24 hourly totals across all clients, zero-filled and in order.
    ///
    /// Zero-filled because the chart has 24 bars whether or not anything was resolved in an hour,
    /// and a caller that had to reconstruct the missing hours would get the boundary arithmetic
    /// wrong in a different way on every page that drew it.
    pub async fn hourly_24h(&self, now: i64) -> Result<Vec<HourBucket>, StorageError> {
        self.with_connection(move |connection| {
            let start = window_start(now);
            let stored = HourBucket::all(connection, "WHERE client = '' AND hour >= ?1", [start])?;
            let mut buckets: Vec<HourBucket> = (0..BUCKETS)
                .map(|offset| HourBucket {
                    hour: start + offset * HOUR,
                    queries: 0,
                    blocked: 0,
                })
                .collect();
            for row in stored {
                // A rollup written in a future hour (a clock that jumped forward and back) falls
                // outside the window; dropping it beats indexing past the end of the chart.
                if let Ok(index) = usize::try_from((row.hour - start) / HOUR)
                    && let Some(bucket) = buckets.get_mut(index)
                {
                    *bucket = row;
                }
            }
            Ok(buckets)
        })
        .await
    }

    /// Per-client totals for the last 24 hours, busiest first.
    pub async fn per_client_24h(&self, now: i64) -> Result<Vec<ClientStats>, StorageError> {
        self.client_stats_24h(now, false).await
    }

    /// The same, restricted to clients with no `devices` row — the "unnamed" list the Devices page
    /// offers to name.
    pub async fn unnamed_clients_24h(&self, now: i64) -> Result<Vec<ClientStats>, StorageError> {
        self.client_stats_24h(now, true).await
    }

    /// Shared body of the two per-client reads.
    ///
    /// The `client <> ''` is what excludes the all-devices bucket that shares the table; without it
    /// every household would appear to have one enormous extra device.
    async fn client_stats_24h(
        &self,
        now: i64,
        unnamed_only: bool,
    ) -> Result<Vec<ClientStats>, StorageError> {
        self.with_connection(move |connection| {
            collect(
                connection,
                "SELECT s.client, sum(s.queries), sum(s.blocked), max(s.last_seen)
                 FROM query_stats_hourly s
                 WHERE s.client <> '' AND s.hour >= ?1
                   AND (?2 = 0
                        OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.ip_address = s.client))
                 GROUP BY s.client
                 ORDER BY 2 DESC, s.client ASC",
                params![window_start(now), unnamed_only],
                ClientStats::from_row,
            )
        })
        .await
    }

    /// The shared body of the deletes-by-id.
    async fn delete<I>(&self, sql: &'static str, id: I) -> Result<bool, StorageError>
    where
        I: rusqlite::ToSql + Send + 'static,
    {
        self.with_connection(move |connection| Ok(connection.execute(sql, [id])? > 0))
            .await
    }
}

/// Run a query and read every row with `map`.
pub(crate) fn collect<T, P, F>(
    connection: &Connection,
    sql: &str,
    params: P,
    map: F,
) -> Result<Vec<T>, StorageError>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut query = connection.prepare_cached(sql)?;
    let rows = query.query_map(params, map)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The start of the 24-hour window, truncated to the hour.
fn window_start(now: i64) -> i64 {
    now - now.rem_euclid(HOUR) - (BUCKETS - 1) * HOUR
}

/// Current unix seconds, from SQLite rather than the system clock.
///
/// One clock for every timestamp this crate writes. `unixepoch()` is also what the migration uses,
/// so an upgraded row and a row written a second later are on the same scale even if the host's
/// `SystemTime` disagrees with SQLite's idea of now.
fn now_seconds(connection: &Connection) -> rusqlite::Result<i64> {
    connection.query_row("SELECT unixepoch()", [], |row| row.get(0))
}
