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
            "INSERT OR REPLACE INTO sources (id, name, url, kind, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                source.id.to_string(),
                source.name,
                source.url,
                source.kind,
                source.enabled,
            ],
        )?;
        Ok(())
    }

    pub async fn list_sources(&self) -> Result<Vec<SourceRecord>, StorageError> {
        let connection = self.connection.lock().expect("storage mutex poisoned");
        let mut statement = connection
            .prepare("SELECT id, name, url, kind, enabled FROM sources ORDER BY name ASC")?;
        let rows = statement.query_map([], |row| {
            Ok(SourceRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).expect("valid uuid in database"),
                name: row.get(1)?,
                url: row.get(2)?,
                kind: row.get(3)?,
                enabled: row.get(4)?,
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
