//! The query log and its hourly rollups — `query_log` and `query_stats_hourly`.
//!
//! Two tables and not one because they answer two different questions and age at two different
//! rates. `query_log` is browsing history: it is what "which device asked for that?" reads, it is
//! the largest thing on disk, and it is the thing a household is entitled to have deleted. The
//! rollups are counts — a number of queries and a number of blocks per hour per client — which is
//! not browsing history, costs ~15 KB/day, and is what every 24-hour figure in the UI is computed
//! from. Keeping them apart is what lets "Clear log" mean it without zeroing the dashboard, and
//! lets `HISTORY_DAYS=0` turn off history while the dashboard keeps working.
//!
//! It is also a performance property: no screen in the product ever runs `GROUP BY` over the raw
//! log. At 250,000 rows on a Raspberry Pi's SD card that is the difference between a dashboard
//! that paints and one that stalls the runtime for a second every five seconds.

use crate::{Storage, StorageError};
use rusqlite::{Row, params};
use serde::Serialize;
use std::collections::HashMap;

/// Seconds per rollup bucket.
const HOUR: i64 = 3600;

/// Seconds per day, for the retention arithmetic.
const DAY: i64 = 86_400;

/// One resolved query, on its way into the log.
#[derive(Debug, Clone)]
pub struct QueryLogEntry {
    /// Unix seconds.
    pub ts: i64,
    /// Client address, as text — the same spelling `devices.ip_address` uses.
    pub client: String,
    /// Queried name, already normalised to lower case by the resolver.
    pub domain: String,
    /// DNS query type, as its numeric code.
    pub qtype: u16,
    /// Whether the answer was a block.
    pub blocked: bool,
    /// `cogwheel_policy::Reason` as its numeric code; this crate does not interpret it.
    pub reason: u8,
    /// Name of the list that matched, when a list was what matched.
    pub list: Option<String>,
}

/// One logged query, on its way out, with its device resolved.
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogRow {
    /// Row id; also the keyset cursor.
    pub id: i64,
    /// Unix seconds.
    pub ts: i64,
    /// Client address.
    pub client: String,
    /// The device that address belongs to *now*, if any.
    pub device_id: Option<String>,
    /// That device's current name — renaming a device relabels its history.
    pub device_name: Option<String>,
    /// Queried name.
    pub domain: String,
    /// DNS query type code.
    pub qtype: u16,
    /// Whether the answer was a block.
    pub blocked: bool,
    /// Reason code.
    pub reason: u8,
    /// Name of the list that matched.
    pub list: Option<String>,
}

/// What `GET /api/v1/queries` asks for.
#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    /// Page size. Zero returns nothing, which is what a `limit=0` query string should do.
    pub limit: u32,
    /// Keyset cursor: return rows with an id strictly below this one.
    pub before: Option<i64>,
    /// Only this client address.
    pub client: Option<String>,
    /// Only clients with no `devices` row.
    pub unnamed: bool,
    /// Only blocked (`Some(true)`) or only allowed (`Some(false)`) queries.
    pub blocked: Option<bool>,
    /// Only domains containing this substring; matched case-insensitively.
    pub contains: Option<String>,
}

/// One page of the log.
#[derive(Debug, Clone, Serialize)]
pub struct QueryPage {
    /// Newest first.
    pub rows: Vec<QueryLogRow>,
    /// Cursor for the next page, or `None` when this page is the end of the log.
    pub next_before: Option<i64>,
}

/// A domain and how many times it appeared — the Overview's two top-ten tables.
#[derive(Debug, Clone, Serialize)]
pub struct DomainCount {
    /// The queried name.
    pub domain: String,
    /// How many rows matched.
    pub count: i64,
}

/// What one retention pass removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PruneOutcome {
    /// Log rows older than the retention window.
    pub by_age: usize,
    /// Log rows beyond the hard row cap.
    pub by_cap: usize,
    /// Rollup buckets older than the rollup window.
    pub rollups: usize,
}

/// A `(hour, client)` bucket being accumulated in memory before it is upserted.
#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    queries: i64,
    blocked: i64,
    last_seen: i64,
}

impl Storage {
    /// Write one batch of resolved queries: the rows, and the rollups they belong to, in one
    /// transaction.
    ///
    /// `write_rows` is `history_days != 0`. When it is false the raw rows are skipped and only the
    /// rollups are written — the counts survive, the browsing history is never on disk at all.
    ///
    /// One transaction for both because a crash between them would leave the dashboard's counts
    /// and the log disagreeing, and the counts are the thing nothing else can reconstruct.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure; the caller drops the batch and logs, because DNS must never
    /// wait on this.
    pub async fn insert_batch_with_rollups(
        &self,
        entries: Vec<QueryLogEntry>,
        write_rows: bool,
    ) -> Result<(), StorageError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.with_connection(move |connection| {
            let transaction = connection.transaction()?;
            if write_rows {
                let mut insert = transaction.prepare_cached(
                    "INSERT INTO query_log (ts, client, domain, qtype, blocked, reason, list)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )?;
                for entry in &entries {
                    insert.execute(params![
                        entry.ts,
                        entry.client,
                        entry.domain,
                        entry.qtype,
                        entry.blocked,
                        entry.reason,
                        entry.list
                    ])?;
                }
            }

            // Accumulate in memory first: a batch of 1,024 queries from one household is a handful
            // of distinct (hour, client) pairs, so this turns a thousand upserts into a dozen.
            let mut buckets: HashMap<(i64, String), Bucket> = HashMap::new();
            for entry in &entries {
                let hour = entry.ts - entry.ts.rem_euclid(HOUR);
                let blocked = i64::from(entry.blocked);
                for client in [String::new(), entry.client.clone()] {
                    let bucket = buckets.entry((hour, client)).or_default();
                    bucket.queries += 1;
                    bucket.blocked += blocked;
                    bucket.last_seen = bucket.last_seen.max(entry.ts);
                }
            }

            {
                let mut upsert = transaction.prepare_cached(
                    "INSERT INTO query_stats_hourly (hour, client, queries, blocked, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(hour, client) DO UPDATE SET
                         queries = queries + excluded.queries,
                         blocked = blocked + excluded.blocked,
                         last_seen = max(last_seen, excluded.last_seen)",
                )?;
                for ((hour, client), bucket) in &buckets {
                    upsert.execute(params![
                        hour,
                        client,
                        bucket.queries,
                        bucket.blocked,
                        bucket.last_seen
                    ])?;
                }
            }

            transaction.commit()?;
            Ok(())
        })
        .await
    }

    /// One page of the log, newest first.
    ///
    /// Keyset and not `OFFSET`: the log is being appended to while someone pages through it, so an
    /// offset would show them rows twice. The device columns come from a `LEFT JOIN` on the
    /// address, which is why renaming a device relabels every row it ever produced.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn query_page(&self, filter: QueryFilter) -> Result<QueryPage, StorageError> {
        self.with_connection(move |connection| {
            // Domains are stored lower-cased by the resolver, so lowering the needle is the whole
            // of case-insensitive matching and it keeps `instr` on a plain byte compare.
            let contains = filter
                .contains
                .as_deref()
                .map(str::to_lowercase)
                .filter(|needle| !needle.is_empty());
            let mut query = connection.prepare_cached(
                "SELECT q.id, q.ts, q.client, d.id, d.name, q.domain, q.qtype, q.blocked,
                        q.reason, q.list
                 FROM query_log q LEFT JOIN devices d ON d.ip_address = q.client
                 WHERE (?1 IS NULL OR q.id < ?1)
                   AND (?2 IS NULL OR q.client = ?2)
                   AND (?3 = 0 OR d.id IS NULL)
                   AND (?4 IS NULL OR q.blocked = ?4)
                   AND (?5 IS NULL OR instr(q.domain, ?5) > 0)
                 ORDER BY q.id DESC
                 LIMIT ?6",
            )?;
            let rows = query.query_map(
                params![
                    filter.before,
                    filter.client,
                    filter.unnamed,
                    filter.blocked,
                    contains,
                    filter.limit
                ],
                row_to_query_log_row,
            )?;
            let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;

            // A full page means there may be more; the caller finds out by asking for the next one
            // and getting nothing back. Cheaper than a second count over the same predicate.
            let next_before = rows
                .last()
                .filter(|_| rows.len() as u64 >= u64::from(filter.limit))
                .map(|row| row.id);
            Ok(QueryPage { rows, next_before })
        })
        .await
    }

    /// The most-seen domains since `since`.
    ///
    /// `blocked` selects which of the Overview's two tables this is: `true` counts blocked rows
    /// only ("Top blocked"), `false` counts every row ("Top queried"). Ties break on the domain so
    /// a quiet household's table does not reshuffle between polls.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn top_domains(
        &self,
        blocked: bool,
        since: i64,
        limit: u32,
    ) -> Result<Vec<DomainCount>, StorageError> {
        self.with_connection(move |connection| {
            let mut query = connection.prepare_cached(
                "SELECT domain, count(*) AS hits FROM query_log
                 WHERE ts >= ?1 AND (?2 = 0 OR blocked = 1)
                 GROUP BY domain
                 ORDER BY hits DESC, domain ASC
                 LIMIT ?3",
            )?;
            let rows = query.query_map(params![since, blocked, limit], |row| {
                Ok(DomainCount {
                    domain: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Delete every logged query, keeping the rollups. Returns how many rows went.
    ///
    /// This is the "clear my history" button, and it clears history: the counts that remain say
    /// how much was resolved and how much was blocked, and nothing about what was asked for.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn clear_query_log(&self) -> Result<usize, StorageError> {
        self.with_connection(|connection| Ok(connection.execute("DELETE FROM query_log", [])?))
            .await
    }

    /// Enforce retention: the age window, the hard row cap, and the rollup window (§7).
    ///
    /// `history_days == 0` skips the age delete entirely. It must: with logging switched off
    /// nothing is being written, so an age delete would find every remaining row older than a
    /// zero-day window and wipe a log the operator only meant to stop adding to.
    ///
    /// The cap keeps exactly `max_rows`: the subquery names the id of the row one past the cap
    /// counting back from the newest, and everything at or below it goes. Fewer rows than the cap
    /// leaves the subquery `NULL`, and `id <= NULL` matches nothing.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn prune_query_log(
        &self,
        now: i64,
        history_days: u32,
        max_rows: u64,
        rollup_days: u32,
    ) -> Result<PruneOutcome, StorageError> {
        self.with_connection(move |connection| {
            let max_rows = i64::try_from(max_rows).unwrap_or(i64::MAX);
            let transaction = connection.transaction()?;

            let by_age = if history_days == 0 {
                0
            } else {
                let cutoff = now - i64::from(history_days) * DAY;
                transaction.execute("DELETE FROM query_log WHERE ts < ?1", [cutoff])?
            };

            let by_cap = transaction.execute(
                "DELETE FROM query_log
                 WHERE id <= (SELECT id FROM query_log ORDER BY id DESC LIMIT 1 OFFSET ?1)",
                [max_rows],
            )?;

            let rollup_cutoff = now - i64::from(rollup_days) * DAY;
            let rollups = transaction.execute(
                "DELETE FROM query_stats_hourly WHERE hour < ?1",
                [rollup_cutoff],
            )?;

            transaction.commit()?;
            Ok(PruneOutcome {
                by_age,
                by_cap,
                rollups,
            })
        })
        .await
    }
}

/// Read a row of the [`Storage::query_page`] projection.
fn row_to_query_log_row(row: &Row<'_>) -> rusqlite::Result<QueryLogRow> {
    Ok(QueryLogRow {
        id: row.get(0)?,
        ts: row.get(1)?,
        client: row.get(2)?,
        device_id: row.get(3)?,
        device_name: row.get(4)?,
        domain: row.get(5)?,
        qtype: row.get(6)?,
        blocked: row.get(7)?,
        reason: row.get(8)?,
        list: row.get(9)?,
    })
}
