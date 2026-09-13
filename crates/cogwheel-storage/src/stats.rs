//! Twenty-four-hour figures, read from `query_stats_hourly`.
//!
//! Everything here reads the rollups and never the raw log, which is what makes the Overview's
//! 5-second poll affordable and what makes the numbers survive both a cleared log and
//! `HISTORY_DAYS=0`.

use crate::{Storage, StorageError};
use rusqlite::params;
use serde::Serialize;

/// Seconds per rollup bucket.
const HOUR: i64 = 3600;

/// How many buckets the Overview's bar chart draws.
const BUCKETS: i64 = 24;

/// One hour of the Overview's bar chart.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HourBucket {
    /// Unix seconds, truncated to the hour.
    pub hour: i64,
    /// Queries resolved in that hour.
    pub queries: i64,
    /// How many of them were blocked.
    pub blocked: i64,
}

/// One client's last 24 hours.
#[derive(Debug, Clone, Serialize)]
pub struct ClientStats {
    /// Client address.
    pub client: String,
    /// Queries in the window.
    pub queries: i64,
    /// How many of them were blocked.
    pub blocked: i64,
    /// Unix seconds of its most recent query.
    pub last_seen: i64,
}

impl Storage {
    /// The last 24 hourly totals across all clients, zero-filled and in order.
    ///
    /// Zero-filled because the chart has 24 bars whether or not anything was resolved in an hour,
    /// and a caller that had to reconstruct the missing hours would get the boundary arithmetic
    /// wrong in a different way on every page that drew it.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn hourly_24h(&self, now: i64) -> Result<Vec<HourBucket>, StorageError> {
        self.with_connection(move |connection| {
            let current = now - now.rem_euclid(HOUR);
            let start = current - (BUCKETS - 1) * HOUR;

            let mut query = connection.prepare_cached(
                "SELECT hour, queries, blocked FROM query_stats_hourly
                 WHERE client = '' AND hour >= ?1",
            )?;
            let rows = query.query_map([start], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;

            let mut buckets: Vec<HourBucket> = (0..BUCKETS)
                .map(|offset| HourBucket {
                    hour: start + offset * HOUR,
                    queries: 0,
                    blocked: 0,
                })
                .collect();
            for row in rows {
                let (hour, queries, blocked) = row?;
                // A rollup written in a future hour (a clock that jumped forward and back) falls
                // outside the window; dropping it beats indexing past the end of the chart.
                let offset = (hour - start) / HOUR;
                if let Ok(index) = usize::try_from(offset)
                    && let Some(bucket) = buckets.get_mut(index)
                {
                    bucket.queries = queries;
                    bucket.blocked = blocked;
                }
            }
            Ok(buckets)
        })
        .await
    }

    /// Per-client totals for the last 24 hours, busiest first.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn per_client_24h(&self, now: i64) -> Result<Vec<ClientStats>, StorageError> {
        self.client_stats_24h(now, false).await
    }

    /// The same, restricted to clients with no `devices` row — the "unnamed" list the Devices page
    /// offers to name.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn unnamed_clients_24h(&self, now: i64) -> Result<Vec<ClientStats>, StorageError> {
        self.client_stats_24h(now, true).await
    }

    /// Shared body of the two per-client reads.
    ///
    /// The `client <> ''` is what excludes the all-devices bucket that shares the table; without
    /// it every household would appear to have one enormous extra device.
    async fn client_stats_24h(
        &self,
        now: i64,
        unnamed_only: bool,
    ) -> Result<Vec<ClientStats>, StorageError> {
        self.with_connection(move |connection| {
            let start = now - now.rem_euclid(HOUR) - (BUCKETS - 1) * HOUR;
            let mut query = connection.prepare_cached(
                "SELECT s.client, sum(s.queries), sum(s.blocked), max(s.last_seen)
                 FROM query_stats_hourly s
                 WHERE s.client <> '' AND s.hour >= ?1
                   AND (?2 = 0
                        OR NOT EXISTS (SELECT 1 FROM devices d WHERE d.ip_address = s.client))
                 GROUP BY s.client
                 ORDER BY 2 DESC, s.client ASC",
            )?;
            let rows = query.query_map(params![start, unnamed_only], |row| {
                Ok(ClientStats {
                    client: row.get(0)?,
                    queries: row.get(1)?,
                    blocked: row.get(2)?,
                    last_seen: row.get(3)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }
}
