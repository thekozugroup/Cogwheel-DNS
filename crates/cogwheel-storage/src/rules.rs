//! Allow/deny rules — the `rules` table.
//!
//! A rule is a domain, an action, and either a device or `NULL` for the whole household. It is the
//! one thing in the product that outranks both the subscribed lists and the protected suffixes, so
//! it is also the one thing a household can use to fix a list that is wrong about a site they need.
//!
//! Uniqueness is on `(domain, COALESCE(device_id, ''))`: one verdict per domain per scope. The
//! `COALESCE` is what makes it work at all — SQL `UNIQUE` treats every `NULL` as distinct, so a
//! plain `UNIQUE (domain, device_id)` would happily hold ten conflicting household rules for the
//! same name.

use crate::{Storage, StorageError};
use rusqlite::{Row, params};
use serde::Serialize;

/// The joined projection [`row_to_rule`] reads.
///
/// The device name comes from a `LEFT JOIN` rather than a copy in the row, so renaming a device
/// relabels its rules too.
const SELECT_RULES: &str = "SELECT r.id, r.domain, r.action, r.device_id, d.name, r.created_at \
                            FROM rules r LEFT JOIN devices d ON d.id = r.device_id";

/// One allow or block rule.
#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    /// Row id — the handle `DELETE /api/v1/rules/{id}` takes.
    pub id: i64,
    /// Normalised domain, no leading `*.`; matches on label boundaries.
    pub domain: String,
    /// `allow` or `block`.
    pub action: String,
    /// The device this applies to, or `None` for everyone.
    pub device_id: Option<String>,
    /// That device's current name, resolved at read time.
    pub device_name: Option<String>,
    /// Unix seconds.
    pub created_at: i64,
}

impl Storage {
    /// Rules for one device, or every rule when `device_id` is `None`.
    ///
    /// The `None` form returns household *and* per-device rules: the policy build wants the whole
    /// table in one query and partitions it itself.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn list_rules(&self, device_id: Option<&str>) -> Result<Vec<Rule>, StorageError> {
        let device_id = device_id.map(ToOwned::to_owned);
        self.with_connection(move |connection| {
            let mut query = connection.prepare(&format!(
                "{SELECT_RULES} WHERE (?1 IS NULL OR r.device_id = ?1) ORDER BY r.domain, r.id"
            ))?;
            let rows = query.query_map([&device_id], row_to_rule)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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
        let domain = domain.to_owned();
        let action = action.to_owned();
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
                row_to_rule,
            )?)
        })
        .await
    }

    /// Remove a rule. Returns whether a row was there to remove.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn delete_rule(&self, id: i64) -> Result<bool, StorageError> {
        self.with_connection(move |connection| {
            Ok(connection.execute("DELETE FROM rules WHERE id = ?1", [id])? > 0)
        })
        .await
    }
}

/// Read a row of the [`SELECT_RULES`] projection.
fn row_to_rule(row: &Row<'_>) -> rusqlite::Result<Rule> {
    Ok(Rule {
        id: row.get(0)?,
        domain: row.get(1)?,
        action: row.get(2)?,
        device_id: row.get(3)?,
        device_name: row.get(4)?,
        created_at: row.get(5)?,
    })
}
