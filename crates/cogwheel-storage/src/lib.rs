use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_ruleset_artifacts.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_source_metadata.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_source_verification_strictness.sql");
const MIGRATION_0005: &str = include_str!("../migrations/0005_devices_security_events.sql");
const MIGRATION_0006: &str = include_str!("../migrations/0006_device_protection_override.sql");
const MIGRATION_0007: &str = include_str!("../migrations/0007_device_allowed_domains.sql");
const MIGRATION_0008: &str = include_str!("../migrations/0008_device_service_overrides.sql");
const MIGRATION_0009: &str = include_str!("../migrations/0009_notification_deliveries.sql");
const MIGRATION_0010: &str = include_str!("../migrations/0010_config_version.sql");
const MIGRATION_0011: &str = include_str!("../migrations/0011_retention_indexes.sql");

pub const SCHEMA_VERSION: u32 = 11;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    Chrono(#[from] chrono::ParseError),
    #[error("internal storage error: {0}")]
    Internal(String),
}

/// Lock the SQLite connection.
///
/// Every public method funnels through here. A poisoned mutex means another thread panicked while
/// holding the connection; returning an error lets the caller surface a failed request instead of
/// cascading that one panic through every subsequent database call for the life of the process.
fn lock_connection(
    connection: &Mutex<Connection>,
) -> Result<std::sync::MutexGuard<'_, Connection>, StorageError> {
    connection
        .lock()
        .map_err(|_| StorageError::Internal("storage connection lock poisoned".to_string()))
}

/// Decode a UUID stored as text in a result row.
///
/// A malformed id means the database is damaged — an appliance's SQLite file can be truncated by a
/// power cut mid-write. That should fail the query it appears in, not abort the process, so this
/// converts the parse failure into a row-level conversion error the caller can propagate.
fn row_uuid(column: usize, value: &str) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

/// Decode an optional UUID column, preserving `NULL` as `None`.
fn row_uuid_opt(column: usize, value: Option<&str>) -> rusqlite::Result<Option<Uuid>> {
    value.map(|raw| row_uuid(column, raw)).transpose()
}

#[derive(Debug, Clone)]
pub struct Storage {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub kind: String,
    pub enabled: bool,
    pub refresh_interval_minutes: i64,
    pub profile: String,
    pub verification_strictness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub event_type: String,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceServiceOverrideRecord {
    pub service_id: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub name: String,
    pub ip_address: String,
    pub policy_mode: String,
    pub blocklist_profile_override: Option<String>,
    pub protection_override: String,
    pub allowed_domains: Vec<String>,
    pub service_overrides: Vec<DeviceServiceOverrideRecord>,
}

/// How many rows a retention pass removed, per table.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrunedHistory {
    pub security_events: usize,
    pub audit_events: usize,
    pub notification_deliveries: usize,
}

impl PrunedHistory {
    /// Total rows removed, across every table.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.security_events + self.audit_events + self.notification_deliveries
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventRecord {
    pub id: Uuid,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub client_ip: String,
    pub domain: String,
    pub classifier_score: f64,
    pub severity: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationDeliveryRecord {
    pub id: Uuid,
    pub event_type: String,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub domain: String,
    pub device_name: Option<String>,
    pub client_ip: String,
    pub attempts: usize,
    pub created_at: DateTime<Utc>,
}

impl Storage {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let path = database_url
            .strip_prefix("sqlite://")
            .unwrap_or(database_url);
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        apply_migrations(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub async fn upsert_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            params![key, value],
        )?;
        Ok(())
    }

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1 LIMIT 1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub async fn insert_source(&self, source: &SourceRecord) -> Result<(), StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT OR REPLACE INTO sources (id, name, url, kind, enabled, refresh_interval_minutes, profile, verification_strictness, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                source.id.to_string(),
                source.name,
                source.url,
                source.kind,
                source.enabled,
                source.refresh_interval_minutes,
                source.profile,
                source.verification_strictness,
            ],
        )?;
        Ok(())
    }

    pub async fn list_sources(&self) -> Result<Vec<SourceRecord>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT id, name, url, kind, enabled, refresh_interval_minutes, profile, verification_strictness FROM sources ORDER BY name ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(SourceRecord {
                id: row_uuid(0, &row.get::<_, String>(0)?)?,
                name: row.get(1)?,
                url: row.get(2)?,
                kind: row.get(3)?,
                enabled: row.get(4)?,
                refresh_interval_minutes: row.get(5)?,
                profile: row.get(6)?,
                verification_strictness: row.get(7)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub async fn delete_source(&self, source_id: Uuid) -> Result<bool, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let changed = connection.execute(
            "DELETE FROM sources WHERE id = ?1",
            params![source_id.to_string()],
        )?;
        Ok(changed > 0)
    }

    pub async fn upsert_device(&self, device: &DeviceRecord) -> Result<(), StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT OR REPLACE INTO devices (id, name, ip_address, policy_mode, blocklist_profile_override, protection_override, allowed_domains_json, service_overrides_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                device.id.to_string(),
                device.name,
                device.ip_address,
                device.policy_mode,
                device.blocklist_profile_override,
                device.protection_override,
                serde_json::to_string(&device.allowed_domains)?,
                serde_json::to_string(&device.service_overrides)?,
            ],
        )?;
        Ok(())
    }

    pub async fn delete_device(&self, device_id: Uuid) -> Result<bool, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let changed = connection.execute(
            "DELETE FROM devices WHERE id = ?1",
            params![device_id.to_string()],
        )?;
        Ok(changed > 0)
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceRecord>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT id, name, ip_address, policy_mode, blocklist_profile_override, protection_override, allowed_domains_json, service_overrides_json FROM devices ORDER BY name ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(DeviceRecord {
                id: row_uuid(0, &row.get::<_, String>(0)?)?,
                name: row.get(1)?,
                ip_address: row.get(2)?,
                policy_mode: row.get(3)?,
                blocklist_profile_override: row.get(4)?,
                protection_override: row.get(5)?,
                allowed_domains: serde_json::from_str(&row.get::<_, String>(6)?)
                    .unwrap_or_default(),
                service_overrides: serde_json::from_str(&row.get::<_, String>(7)?)
                    .unwrap_or_default(),
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub async fn find_device_by_ip(
        &self,
        ip_address: &str,
    ) -> Result<Option<DeviceRecord>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT id, name, ip_address, policy_mode, blocklist_profile_override, protection_override, allowed_domains_json, service_overrides_json FROM devices WHERE ip_address = ?1",
        )?;

        statement
            .query_row(params![ip_address], |row| {
                Ok(DeviceRecord {
                    id: row_uuid(0, &row.get::<_, String>(0)?)?,
                    name: row.get(1)?,
                    ip_address: row.get(2)?,
                    policy_mode: row.get(3)?,
                    blocklist_profile_override: row.get(4)?,
                    protection_override: row.get(5)?,
                    allowed_domains: serde_json::from_str(&row.get::<_, String>(6)?)
                        .unwrap_or_default(),
                    service_overrides: serde_json::from_str(&row.get::<_, String>(7)?)
                        .unwrap_or_default(),
                })
            })
            .optional()
            .map_err(StorageError::from)
    }

    pub async fn record_security_event(
        &self,
        event: &SecurityEventRecord,
    ) -> Result<(), StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT INTO security_events (id, device_id, device_name, client_ip, domain, classifier_score, severity, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.id.to_string(),
                event.device_id.map(|value| value.to_string()),
                event.device_name,
                event.client_ip,
                event.domain,
                event.classifier_score,
                event.severity,
                event.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Delete history older than `cutoff`, returning how many rows went.
    ///
    /// Nothing used to delete from these tables at all. On a household resolver
    /// that means two problems that look like one: the database grows without
    /// limit on an appliance disk, and a permanent record of everything the
    /// house has ever looked up accumulates on a box in the hall. For a product
    /// whose entire purpose is to stop other people building that record,
    /// keeping an unbounded copy is the wrong default.
    ///
    /// `created_at` is stored as RFC 3339, which for a fixed offset sorts
    /// lexicographically in time order, so a string comparison is a correct
    /// range query and uses the indexes added in migration 0011. The cutoff is
    /// rendered the same way the writers render it.
    ///
    /// Not deleted here: `rulesets` (a handful of rows holding hashes, and the
    /// active one is referenced), `devices`, `sources` and settings. Those are
    /// configuration, not history -- pruning them would delete what the
    /// operator set up rather than what the appliance observed.
    pub async fn prune_history_before(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<PrunedHistory, StorageError> {
        let cutoff = cutoff.to_rfc3339();
        let connection = lock_connection(&self.connection)?;

        let security_events = connection.execute(
            "DELETE FROM security_events WHERE created_at < ?1",
            params![cutoff],
        )?;
        let audit_events = connection.execute(
            "DELETE FROM audit_events WHERE created_at < ?1",
            params![cutoff],
        )?;
        let notification_deliveries = connection.execute(
            "DELETE FROM notification_deliveries WHERE created_at < ?1",
            params![cutoff],
        )?;

        Ok(PrunedHistory {
            security_events,
            audit_events,
            notification_deliveries,
        })
    }

    pub async fn recent_security_events(
        &self,
        limit: i64,
    ) -> Result<Vec<SecurityEventRecord>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT id, device_id, device_name, client_ip, domain, classifier_score, severity, created_at FROM security_events ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            let device_id = row.get::<_, Option<String>>(1)?;
            Ok(SecurityEventRecord {
                id: row_uuid(0, &row.get::<_, String>(0)?)?,
                device_id: row_uuid_opt(1, device_id.as_deref())?,
                device_name: row.get(2)?,
                client_ip: row.get(3)?,
                domain: row.get(4)?,
                classifier_score: row.get(5)?,
                severity: row.get(6)?,
                created_at: parse_datetime(&row.get::<_, String>(7)?).map_err(to_sqlite_error)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub async fn record_audit_event(&self, event: &AuditEvent) -> Result<(), StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT INTO audit_events (id, event_type, payload, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                event.id.to_string(),
                event.event_type,
                event.payload,
                event.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub async fn recent_audit_events(&self, limit: i64) -> Result<Vec<AuditEvent>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT id, event_type, payload, created_at FROM audit_events ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            Ok(AuditEvent {
                id: row_uuid(0, &row.get::<_, String>(0)?)?,
                event_type: row.get(1)?,
                payload: row.get(2)?,
                created_at: parse_datetime(&row.get::<_, String>(3)?).map_err(to_sqlite_error)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub async fn record_notification_delivery(
        &self,
        delivery: &NotificationDeliveryRecord,
    ) -> Result<(), StorageError> {
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT INTO notification_deliveries (id, event_type, status, severity, title, summary, domain, device_name, client_ip, attempts, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                delivery.id.to_string(),
                delivery.event_type,
                delivery.status,
                delivery.severity,
                delivery.title,
                delivery.summary,
                delivery.domain,
                delivery.device_name,
                delivery.client_ip,
                delivery.attempts as i64,
                delivery.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub async fn recent_notification_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<NotificationDeliveryRecord>, StorageError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT id, event_type, status, severity, title, summary, domain, device_name, client_ip, attempts, created_at FROM notification_deliveries ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            Ok(NotificationDeliveryRecord {
                id: row_uuid(0, &row.get::<_, String>(0)?)?,
                event_type: row.get(1)?,
                status: row.get(2)?,
                severity: row.get(3)?,
                title: row.get(4)?,
                summary: row.get(5)?,
                domain: row.get(6)?,
                device_name: row.get(7)?,
                client_ip: row.get(8)?,
                attempts: row.get::<_, i64>(9)? as usize,
                created_at: parse_datetime(&row.get::<_, String>(10)?).map_err(to_sqlite_error)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }
}

/// Whether a migration error just means "this migration is already applied".
///
/// Migrations 0002+ are additive `ALTER TABLE ADD COLUMN` / `CREATE ... IF NOT EXISTS` batches with
/// no version ledger, so re-running them on an up-to-date database is expected to fail in exactly
/// these ways. Everything else -- a full disk, a locked database, a genuine SQL error -- is a real
/// failure that must stop startup rather than leave the server running against a schema that is
/// missing tables or columns, turning every dependent query into an opaque 500 later.
fn is_already_applied(error: &rusqlite::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("duplicate column name")
        || message.contains("already exists")
        || message.contains("duplicate index")
}

fn apply_migrations(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(MIGRATION_0001)?;

    const ADDITIVE_MIGRATIONS: [(&str, &str); 10] = [
        ("0002", MIGRATION_0002),
        ("0003", MIGRATION_0003),
        ("0004", MIGRATION_0004),
        ("0005", MIGRATION_0005),
        ("0006", MIGRATION_0006),
        ("0007", MIGRATION_0007),
        ("0008", MIGRATION_0008),
        ("0009", MIGRATION_0009),
        ("0010", MIGRATION_0010),
        ("0011", MIGRATION_0011),
    ];

    for (name, sql) in ADDITIVE_MIGRATIONS {
        match connection.execute_batch(sql) {
            Ok(()) => {}
            Err(error) if is_already_applied(&error) => {
                tracing::debug!(migration = name, "migration already applied");
            }
            Err(error) => {
                tracing::error!(migration = name, %error, "migration failed");
                return Err(StorageError::Internal(format!(
                    "migration {name} failed: {error}"
                )));
            }
        }
    }
    Ok(())
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sqlite_error(error: chrono::ParseError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Migrations run on every boot, so they must be safe to apply repeatedly.
    ///
    /// Regression guard for a real outage: migration 0010 ended with a plain
    /// `INSERT INTO config_migrations`, whose `version` column is UNIQUE. That failure was
    /// invisible while migration results were discarded, but once they became fatal it meant the
    /// server refused to start against ANY pre-existing database — every install would have been
    /// bricked by the upgrade that was meant to make failures visible.
    #[test]
    fn migrations_are_idempotent_across_restarts() {
        let connection = Connection::open_in_memory().expect("open in-memory database");

        apply_migrations(&connection).expect("first boot should migrate cleanly");
        apply_migrations(&connection).expect("second boot must not fail on an existing database");
        apply_migrations(&connection).expect("third boot must still succeed");

        // The seeded row must exist exactly once, not be duplicated by the re-runs.
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM config_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .expect("query seeded migration row");
        assert_eq!(
            count, 1,
            "re-running migrations must not duplicate seeded rows"
        );
    }

    /// A genuine SQL failure must stop startup rather than leaving the server running against a
    /// schema that is missing tables or columns.
    #[test]
    fn a_real_migration_error_is_not_mistaken_for_already_applied() {
        let duplicate_column = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(1),
            Some("duplicate column name: foo".to_string()),
        );
        assert!(is_already_applied(&duplicate_column));

        let disk_full = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(13),
            Some("database or disk is full".to_string()),
        );
        assert!(
            !is_already_applied(&disk_full),
            "a real failure must not be treated as an already-applied migration"
        );
    }

    async fn storage_with_events(ages_in_days: &[i64]) -> Storage {
        let storage = Storage::connect("sqlite://:memory:")
            .await
            .expect("in-memory storage");
        for (index, age) in ages_in_days.iter().enumerate() {
            let created_at = Utc::now() - chrono::Duration::days(*age);
            storage
                .record_security_event(&SecurityEventRecord {
                    id: Uuid::new_v4(),
                    device_id: None,
                    device_name: None,
                    client_ip: "192.0.2.1".to_string(),
                    domain: format!("host{index}.example"),
                    classifier_score: 0.9,
                    severity: "medium".to_string(),
                    created_at,
                })
                .await
                .expect("record security event");
            storage
                .record_audit_event(&AuditEvent {
                    id: Uuid::new_v4(),
                    event_type: "test.event".to_string(),
                    payload: "{}".to_string(),
                    created_at,
                })
                .await
                .expect("record audit event");
        }
        storage
    }

    #[tokio::test]
    async fn pruning_removes_history_older_than_the_cutoff_and_keeps_the_rest() {
        // 1 and 5 days old are inside a 30-day window; 45 and 400 are outside.
        let storage = storage_with_events(&[1, 5, 45, 400]).await;
        let cutoff = Utc::now() - chrono::Duration::days(30);

        let pruned = storage
            .prune_history_before(cutoff)
            .await
            .expect("prune should succeed");

        assert_eq!(
            pruned.security_events, 2,
            "two events are older than 30 days"
        );
        assert_eq!(pruned.audit_events, 2);
        assert_eq!(pruned.total(), 4);

        let remaining = storage
            .recent_security_events(100)
            .await
            .expect("read remaining");
        assert_eq!(remaining.len(), 2, "the recent events must survive");
    }

    /// A prune on a database with nothing old enough must be a no-op, not an
    /// error and not a table sweep. It runs hourly on every appliance.
    #[tokio::test]
    async fn pruning_is_a_no_op_when_nothing_is_old_enough() {
        let storage = storage_with_events(&[0, 1, 2]).await;

        let pruned = storage
            .prune_history_before(Utc::now() - chrono::Duration::days(30))
            .await
            .expect("prune should succeed");

        assert_eq!(pruned.total(), 0);
        assert_eq!(
            storage
                .recent_security_events(100)
                .await
                .expect("read")
                .len(),
            3
        );
    }

    /// Pruning is repeated forever on a long-running appliance; the second pass
    /// over already-pruned data must remove nothing rather than error.
    #[tokio::test]
    async fn pruning_twice_removes_nothing_the_second_time() {
        let storage = storage_with_events(&[100, 200]).await;
        let cutoff = Utc::now() - chrono::Duration::days(30);

        let first = storage.prune_history_before(cutoff).await.expect("first");
        let second = storage.prune_history_before(cutoff).await.expect("second");

        assert_eq!(first.security_events, 2);
        assert_eq!(second.total(), 0);
    }

    /// Configuration is not history. Deleting a device or a source would throw
    /// away what the operator set up rather than what the appliance observed.
    #[tokio::test]
    async fn pruning_never_touches_configuration() {
        let storage = storage_with_events(&[400]).await;
        storage
            .insert_source(&SourceRecord {
                id: Uuid::from_u128(7),
                name: "kept".to_string(),
                url: "data:text/plain,example.com".to_string(),
                kind: "domains".to_string(),
                enabled: true,
                refresh_interval_minutes: 60,
                profile: "essential".to_string(),
                verification_strictness: "strict".to_string(),
            })
            .await
            .expect("insert source");

        storage
            .prune_history_before(Utc::now())
            .await
            .expect("prune");

        let sources = storage.list_sources().await.expect("list sources");
        assert!(
            sources.iter().any(|source| source.name == "kept"),
            "configuration must survive a prune that deletes all history"
        );
    }
}
