//! The `settings` table, which holds exactly one key.
//!
//! `pause_until` is here rather than only in the runtime's `AtomicU64` so that a pause survives a
//! restart: someone who pauses protection for an hour and then reboots the appliance should not
//! find filtering back on, and someone who pauses and then forgets should not have it stay off
//! forever either. Everything else that could be a setting is an environment variable by design
//! (§8), which is why this table has one key and no schema for a second.

use crate::sources::now_seconds;
use crate::{Storage, StorageError};
use rusqlite::{OptionalExtension, params};

/// The one key.
const PAUSE_UNTIL: &str = "pause_until";

impl Storage {
    /// When protection is paused until, or `None` if it is not paused.
    ///
    /// A stored `0` and a value that will not parse both read as "not paused" — §2.1 defines
    /// absent and 0 as the same state, and a garbled row should fail open to filtering rather than
    /// leave the household unprotected while the UI insists everything is fine.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
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
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
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
}
