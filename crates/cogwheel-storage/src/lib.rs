use chrono::{DateTime, Utc};
use cogwheel_policy::RulesetArtifact;
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
pub struct RulesetRecord {
    pub id: Uuid,
    pub hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub artifact_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub event_type: String,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub name: String,
    pub ip_address: String,
    pub policy_mode: String,
    pub blocklist_profile_override: Option<String>,
    pub protection_override: String,
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
        let connection = self.connection.lock().expect("storage mutex poisoned");
        connection.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            params![key, value],
        )?;
        Ok(())
    }

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
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
        let connection = self.connection.lock().expect("storage mutex poisoned");
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
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT id, name, url, kind, enabled, refresh_interval_minutes, profile, verification_strictness FROM sources ORDER BY name ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(SourceRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
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
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let changed = connection.execute(
            "DELETE FROM sources WHERE id = ?1",
            params![source_id.to_string()],
        )?;
        Ok(changed > 0)
    }

    pub async fn upsert_device(&self, device: &DeviceRecord) -> Result<(), StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        connection.execute(
            "INSERT OR REPLACE INTO devices (id, name, ip_address, policy_mode, blocklist_profile_override, protection_override, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                device.id.to_string(),
                device.name,
                device.ip_address,
                device.policy_mode,
                device.blocklist_profile_override,
                device.protection_override,
            ],
        )?;
        Ok(())
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT id, name, ip_address, policy_mode, blocklist_profile_override, protection_override FROM devices ORDER BY name ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(DeviceRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
                name: row.get(1)?,
                ip_address: row.get(2)?,
                policy_mode: row.get(3)?,
                blocklist_profile_override: row.get(4)?,
                protection_override: row.get(5)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub async fn find_device_by_ip(
        &self,
        ip_address: &str,
    ) -> Result<Option<DeviceRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT id, name, ip_address, policy_mode, blocklist_profile_override, protection_override FROM devices WHERE ip_address = ?1",
        )?;

        statement
            .query_row(params![ip_address], |row| {
                Ok(DeviceRecord {
                    id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
                    name: row.get(1)?,
                    ip_address: row.get(2)?,
                    policy_mode: row.get(3)?,
                    blocklist_profile_override: row.get(4)?,
                    protection_override: row.get(5)?,
                })
            })
            .optional()
            .map_err(StorageError::from)
    }

    pub async fn record_security_event(
        &self,
        event: &SecurityEventRecord,
    ) -> Result<(), StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
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

    pub async fn recent_security_events(
        &self,
        limit: i64,
    ) -> Result<Vec<SecurityEventRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT id, device_id, device_name, client_ip, domain, classifier_score, severity, created_at FROM security_events ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            let device_id = row.get::<_, Option<String>>(1)?;
            Ok(SecurityEventRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
                device_id: device_id
                    .as_deref()
                    .map(Uuid::parse_str)
                    .transpose()
                    .expect("valid optional uuid in database"),
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

    pub async fn record_ruleset(&self, ruleset: &RulesetRecord) -> Result<(), StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        connection.execute(
            "INSERT INTO rulesets (id, hash, status, created_at, artifact_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ruleset.id.to_string(),
                ruleset.hash,
                ruleset.status,
                ruleset.created_at.to_rfc3339(),
                ruleset.artifact_json,
            ],
        )?;
        Ok(())
    }

    pub async fn list_rulesets(&self) -> Result<Vec<RulesetRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT id, hash, status, created_at, artifact_json FROM rulesets ORDER BY created_at DESC",
        )?;
        let rows = statement.query_map([], decode_ruleset_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub async fn activate_ruleset(&self, ruleset_id: Uuid) -> Result<(), StorageError> {
        let mut connection = self.connection.lock().expect("storage mutex poisoned");
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE rulesets SET status = 'previous' WHERE status = 'active'",
            [],
        )?;
        transaction.execute(
            "UPDATE rulesets SET status = 'active' WHERE id = ?1",
            params![ruleset_id.to_string()],
        )?;
        transaction.execute(
            "UPDATE active_ruleset SET ruleset_id = ?1, activated_at = CURRENT_TIMESTAMP WHERE slot = 1",
            params![ruleset_id.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub async fn active_ruleset(&self) -> Result<Option<RulesetRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        connection
            .query_row(
                "SELECT id, hash, status, created_at, artifact_json FROM rulesets WHERE status = 'active' LIMIT 1",
                [],
                decode_ruleset_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub async fn previous_ruleset(&self) -> Result<Option<RulesetRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        connection
            .query_row(
                "SELECT id, hash, status, created_at, artifact_json FROM rulesets WHERE status = 'previous' ORDER BY created_at DESC LIMIT 1",
                [],
                decode_ruleset_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub async fn rollback_to_previous_ruleset(
        &self,
    ) -> Result<Option<RulesetArtifact>, StorageError> {
        let Some(previous) = self.previous_ruleset().await? else {
            return Ok(None);
        };

        self.activate_ruleset(previous.id).await?;
        let artifact = serde_json::from_str::<RulesetArtifact>(&previous.artifact_json)?;
        Ok(Some(artifact))
    }

    pub async fn record_audit_event(&self, event: &AuditEvent) -> Result<(), StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
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
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT id, event_type, payload, created_at FROM audit_events ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            Ok(AuditEvent {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
                event_type: row.get(1)?,
                payload: row.get(2)?,
                created_at: parse_datetime(&row.get::<_, String>(3)?).map_err(to_sqlite_error)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }
}

fn apply_migrations(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(MIGRATION_0001)?;
    let _ = connection.execute_batch(MIGRATION_0002);
    let _ = connection.execute_batch(MIGRATION_0003);
    let _ = connection.execute_batch(MIGRATION_0004);
    let _ = connection.execute_batch(MIGRATION_0005);
    let _ = connection.execute_batch(MIGRATION_0006);
    Ok(())
}

fn decode_ruleset_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RulesetRecord> {
    Ok(RulesetRecord {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
        hash: row.get(1)?,
        status: row.get(2)?,
        created_at: parse_datetime(&row.get::<_, String>(3)?).map_err(to_sqlite_error)?,
        artifact_json: row.get(4)?,
    })
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sqlite_error(error: chrono::ParseError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}
