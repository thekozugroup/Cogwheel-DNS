//! SQLite persistence for Cogwheel.
//!
//! This is a leaf crate: it depends on nothing else in the workspace, and it knows nothing about
//! DNS, blocklist syntax or HTTP. It owns one database file and the seven tables of the v1 schema
//! (§2.1), and it hands the server plain records to build a `Policy` from and to serve the API
//! with.
//!
//! # One connection, always off the runtime
//!
//! There is exactly one `Connection`, behind a `Mutex`, and **every** public method is `async` and
//! runs its closure under [`tokio::task::spawn_blocking`]. SQLite calls block; the DNS receive
//! loops and the axum handlers share a small pool of runtime workers with everything else in the
//! process, and one slow `fsync` on a Raspberry Pi's SD card parked on a worker stalls query
//! resolution that has nothing to do with the database. A single connection rather than a pool
//! because the write load is one transaction every five seconds (§7) and WAL readers would gain
//! nothing worth the extra file handles on an appliance.
//!
//! # Ids
//!
//! `sources` and `devices` keep TEXT UUIDs so every row that existed before the v1 schema keeps
//! its id across the upgrade. This crate stores them as `String` and never parses them — the
//! server validates at the API edge, and `seed_if_empty` mints the one id it needs in SQL, so
//! nothing here needs a UUID dependency.
//!
//! # Errors the API must distinguish
//!
//! [`StorageError::is_unique_violation`] and [`StorageError::is_foreign_key_violation`] exist so
//! the server can answer 409 and 400 without matching on `rusqlite` codes itself — a duplicate
//! device IP and an unknown `source_id` are user errors, not faults. Every other failure is a
//! fault and reaches the caller as itself.

use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

#[macro_use]
mod record;
mod migrate;
mod query_log;
mod repo;

pub use query_log::{
    DomainCount, PruneOutcome, QueryFilter, QueryLogEntry, QueryLogRow, QueryPage,
};
pub use repo::{
    ClientStats, Device, DeviceList, DeviceUpsert, FetchStatus, HourBucket, NewSource, Rule,
    Source, SourcePatch,
};

/// Schema version this build writes, reads and refuses to go above.
pub const SCHEMA_VERSION: i64 = 1;

/// The whole v1 schema, executed verbatim on a fresh database.
const SCHEMA_V1: &str = include_str!("schema_v1.sql");

/// The one list a fresh install subscribes to (§2.4).
const SEED_SOURCE: (&str, &str, &str) = ("oisd small", "https://small.oisd.nl", "adblock");

/// A SQL expression yielding a fresh v4 UUID in the canonical hyphenated form.
///
/// Minting ids in SQL rather than in Rust is what lets this crate drop its `uuid` dependency while
/// still writing the TEXT UUIDs the rest of the system expects. `abs(random() % 4)` and not
/// `abs(random()) % 4` because `abs()` of `i64::MIN` is an overflow error in SQLite, and a startup
/// that fails once in 2^64 boots is a bug nobody would ever reproduce.
pub(crate) const NEW_UUID: &str = "lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' \
     || substr(hex(randomblob(2)), 2) || '-' \
     || substr('89ab', 1 + abs(random() % 4), 1) || substr(hex(randomblob(2)), 2) || '-' \
     || hex(randomblob(6)))";

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A SQLite call failed. Constraint violations arrive here; see
    /// [`is_unique_violation`](Self::is_unique_violation).
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// The file was written by a newer Cogwheel. Starting anyway would mean reading columns that
    /// may have changed meaning, so this refuses instead of guessing.
    #[error(
        "database at {path} is from a newer Cogwheel: its schema version is {found}, and this build understands {supported}"
    )]
    NewerSchema {
        /// The database file that was opened.
        path: PathBuf,
        /// The `user_version` found in it.
        found: i64,
        /// The highest version this build knows, [`SCHEMA_VERSION`].
        supported: i64,
    },

    /// `user_version` is 0 but the file is neither empty nor a recognisable legacy database.
    #[error(
        "database at {path} has an unrecognised layout: schema version 0, a `sources` table but no `rulesets` table. Refusing to touch it"
    )]
    UnknownSchema {
        /// The database file that was opened.
        path: PathBuf,
    },

    /// The legacy upgrade failed and was rolled back. The v0 file is untouched, and a copy of it
    /// taken before the attempt is at `backup`.
    #[error(
        "upgrade from the legacy schema failed and was rolled back; the database is unchanged and a copy taken before the attempt is at {backup}: {message}"
    )]
    Migration {
        /// The `.pre-v1` copy taken by `VACUUM INTO` before the transaction opened.
        backup: PathBuf,
        /// What actually failed.
        message: String,
    },

    /// Creating the data directory or clearing a stale backup failed.
    #[error("storage file error: {0}")]
    Io(#[from] std::io::Error),

    /// A blocking task panicked, or the connection mutex was poisoned by an earlier panic.
    #[error("internal storage error: {0}")]
    Internal(String),
}

impl StorageError {
    /// True when the failure is a `UNIQUE`/`PRIMARY KEY` conflict — the server answers 409.
    ///
    /// Both extended codes count: a duplicate list name trips the `UNIQUE` index, while a re-used
    /// `sources.id` trips the primary key, and to the person typing them in they are the same
    /// mistake.
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self.extended_code(),
            Some(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
                | Some(rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
        )
    }

    /// True when the failure is a foreign-key violation — the server answers 400.
    ///
    /// This is how "assign this device a list id that does not exist" surfaces: the request names
    /// something that is not there, which is the caller's error and not a fault.
    #[must_use]
    pub fn is_foreign_key_violation(&self) -> bool {
        self.extended_code() == Some(rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY)
    }

    fn extended_code(&self) -> Option<std::ffi::c_int> {
        match self {
            Self::Sqlite(rusqlite::Error::SqliteFailure(error, _)) => Some(error.extended_code),
            _ => None,
        }
    }
}

/// Handle on the one open database. Cheap to clone; every clone shares the same connection.
#[derive(Debug, Clone)]
pub struct Storage {
    connection: Arc<Mutex<Connection>>,
}

impl Storage {
    /// Open (creating if needed), bring the schema to v1, and seed a fresh install.
    ///
    /// `database_url` may carry the `sqlite://` prefix the config uses. The sequence is §2.2:
    /// PRAGMAs, then `user_version` — 1 is ready to use, 0 with no `sources` table is a fresh file
    /// that gets `schema_v1.sql`, 0 with a `rulesets` table is a legacy database that gets the
    /// guarded upgrade in `migrate.rs`, and anything else is refused.
    ///
    /// # Errors
    ///
    /// [`StorageError::NewerSchema`] for a database from a later build,
    /// [`StorageError::UnknownSchema`] for a v0 file this crate does not recognise, and
    /// [`StorageError::Migration`] if the legacy upgrade rolled back — that one names the backup
    /// the operator can fall back to.
    pub async fn open(database_url: &str) -> Result<Self, StorageError> {
        let database_url = database_url.to_owned();
        spawn_blocking(move || Self::open_blocking(&database_url)).await
    }

    fn open_blocking(database_url: &str) -> Result<Self, StorageError> {
        let path = PathBuf::from(
            database_url
                .strip_prefix("sqlite://")
                .unwrap_or(database_url),
        );
        // An empty parent is `:memory:` or a bare filename in the working directory; neither has a
        // directory to create, and `create_dir_all("")` would fail on both.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(&path)?;
        apply_pragmas(&connection)?;

        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            SCHEMA_VERSION => {}
            0 if table_exists(&connection, "rulesets")? => {
                migrate::upgrade_v0_to_v1(&mut connection, &path)?;
            }
            0 if table_exists(&connection, "sources")? => {
                return Err(StorageError::UnknownSchema { path });
            }
            // One transaction, so a half-built schema can never be left behind.
            0 => {
                let transaction = connection.unchecked_transaction()?;
                transaction.execute_batch(SCHEMA_V1)?;
                transaction.commit()?;
            }
            found => {
                return Err(StorageError::NewerSchema {
                    path,
                    found,
                    supported: SCHEMA_VERSION,
                });
            }
        }

        seed_if_empty(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Total size of the database, in bytes.
    ///
    /// Read from SQLite rather than by stat-ing the file so that pages still sitting in the WAL
    /// are counted — `GET /api/v1/settings` reports this, and a figure that jumps around with the
    /// checkpoint schedule reads as a bug.
    ///
    /// # Errors
    ///
    /// Propagates any SQLite failure.
    pub async fn database_size_bytes(&self) -> Result<i64, StorageError> {
        self.with_connection(|connection| {
            let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
            let page_size: i64 =
                connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
            Ok(pages.saturating_mul(page_size))
        })
        .await
    }

    /// Run `job` with the connection locked, on the blocking pool.
    ///
    /// Every public method funnels through here, which is what makes "no rusqlite on a runtime
    /// worker" a property of the crate rather than a habit.
    pub(crate) async fn with_connection<T, F>(&self, job: F) -> Result<T, StorageError>
    where
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
        T: Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        spawn_blocking(move || {
            // A poisoned mutex means another thread panicked while holding it. Failing the one
            // request that hit it beats cascading that single panic through every database call
            // for the remaining life of the process.
            let mut guard: MutexGuard<'_, Connection> = connection
                .lock()
                .map_err(|_| StorageError::Internal("connection lock poisoned".to_owned()))?;
            job(&mut guard)
        })
        .await
    }
}

/// Await a blocking task, turning a panicked worker into an error rather than a second panic.
async fn spawn_blocking<T, F>(job: F) -> Result<T, StorageError>
where
    F: FnOnce() -> Result<T, StorageError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|error| StorageError::Internal(format!("storage task failed: {error}")))?
}

/// How much memory SQLite may hold as cached pages, in KiB (negative = a size, not a page count).
///
/// Stated rather than left at the build default, because the default is a per-connection figure
/// that changes between SQLite releases and this process has a fixed memory budget to answer for
/// (§12: 45 MB with a full list loaded). One megabyte holds the whole of `sources`, `devices` and
/// `rules` many times over; the query log is written append-only and read one page at a time, so
/// nothing here benefits from caching more of it.
const PAGE_CACHE_KIB: i32 = -1024;

/// The connection PRAGMAs of §1.4, plus an explicit page-cache budget.
///
/// WAL so a reader (the API) never blocks the writer (the query-log flush); `synchronous=NORMAL`
/// because in WAL mode that risks at most the last transaction on a power cut, and the last
/// transaction is five seconds of query log; `busy_timeout` so a contended write waits rather than
/// returning `SQLITE_BUSY` to a user's click.
fn apply_pragmas(connection: &Connection) -> Result<(), StorageError> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 1000)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "busy_timeout", 5000)?;
    connection.pragma_update(None, "cache_size", PAGE_CACHE_KIB)?;
    Ok(())
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool, StorageError> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Subscribe a list-less install to oisd small (§2.4).
///
/// Runs on fresh *and* upgraded databases: an upgrade that dropped the two-name `baseline` data
/// URL and found nothing else would otherwise leave an appliance filtering nothing at all. The
/// `WHERE NOT EXISTS` makes the whole thing one atomic statement, so two processes racing to open
/// the same file cannot both seed.
fn seed_if_empty(connection: &Connection) -> Result<(), StorageError> {
    let inserted = connection.execute(
        &format!(
            "INSERT INTO sources (id, name, url, kind, enabled, rule_count, created_at, updated_at)
             SELECT {NEW_UUID}, ?1, ?2, ?3, 1, 0, unixepoch(), unixepoch()
             WHERE NOT EXISTS (SELECT 1 FROM sources)"
        ),
        SEED_SOURCE,
    )?;
    if inserted > 0 {
        tracing::info!(
            list = SEED_SOURCE.0,
            "first boot: subscribed to the default list"
        );
    }
    Ok(())
}
