//! Fixtures and helpers shared by the storage test binaries.
//!
//! Each test file compiles this module separately, so anything one of them does not use is dead
//! code there; the allows keep that from being a warning in three binaries at once.
#![allow(dead_code, unused_imports)]

pub use cogwheel_storage::{
    DeviceUpsert, FetchStatus, NewSource, QueryFilter, QueryLogEntry, SourcePatch, Storage,
};
pub use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A fixed "now" every time-dependent test anchors to, so a test that runs at 23:59 behaves like
/// one that runs at noon. 2023-11-14T22:13:20Z; the hour it falls in starts at 1_699_999_200.
pub const NOW: i64 = 1_700_000_000;

/// Seconds per hour and per day, spelled out where the tests do retention arithmetic.
pub const HOUR: i64 = 3600;
pub const DAY: i64 = 86_400;

/// The eleven v0 migration files, kept as fixtures now that nothing executes them in production.
pub const LEGACY_MIGRATIONS: [&str; 11] = [
    include_str!("../fixtures/legacy/0001_init.sql"),
    include_str!("../fixtures/legacy/0002_ruleset_artifacts.sql"),
    include_str!("../fixtures/legacy/0003_source_metadata.sql"),
    include_str!("../fixtures/legacy/0004_source_verification_strictness.sql"),
    include_str!("../fixtures/legacy/0005_devices_security_events.sql"),
    include_str!("../fixtures/legacy/0006_device_protection_override.sql"),
    include_str!("../fixtures/legacy/0007_device_allowed_domains.sql"),
    include_str!("../fixtures/legacy/0008_device_service_overrides.sql"),
    include_str!("../fixtures/legacy/0009_notification_deliveries.sql"),
    include_str!("../fixtures/legacy/0010_config_version.sql"),
    include_str!("../fixtures/legacy/0011_retention_indexes.sql"),
];

/// The baseline `data:` source every v0 install carried.
pub const BASELINE_ID: &str = "00000000-0000-0000-0000-000000000001";
/// The one real subscription in the fixture; its id must survive the upgrade.
pub const USER_SOURCE_ID: &str = "11111111-2222-3333-4444-555555555555";
/// The custom-mode, bypassing device.
pub const TABLET_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
/// The global-mode device whose allowed domains must NOT be imported.
pub const LAPTOP_ID: &str = "99999999-8888-7777-6666-555555555555";
/// The device whose JSON columns are garbage.
pub const BROKEN_ID: &str = "12121212-3434-5656-7878-909090909090";

/// A directory under the system temp dir, removed when the test ends.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cogwheel-storage-{}-{label}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    pub fn database(&self) -> PathBuf {
        self.path.join("cogwheel.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Open a [`Storage`] at `path`, failing the test on any error.
pub async fn open(path: &Path) -> Storage {
    Storage::open(&path.to_string_lossy())
        .await
        .expect("open storage")
}

/// Open a fresh database in its own temp directory.
pub async fn fresh(label: &str) -> (TempDir, Storage) {
    let dir = TempDir::new(label);
    let storage = open(&dir.database()).await;
    (dir, storage)
}

/// `<path>.pre-v1`.
pub fn backup_of(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_owned();
    backup.push(".pre-v1");
    PathBuf::from(backup)
}

/// `PRAGMA user_version` of a database file.
pub fn user_version(path: &Path) -> i64 {
    let connection = Connection::open(path).expect("open for user_version");
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read user_version")
}

/// Does that file have a table of this name?
pub fn has_table(path: &Path, table: &str) -> bool {
    let connection = Connection::open(path).expect("open for table check");
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .expect("count tables");
    count > 0
}

/// Build a v0 database at `path` by running the eleven legacy migrations and seeding the rows the
/// upgrade has to reason about: the baseline source, one real subscription, a custom-mode device
/// that bypasses filtering and carries every dropped setting, a global-mode device with allowed
/// domains, and a device whose JSON will not parse.
pub fn build_v0_fixture(path: &Path) {
    let connection = Connection::open(path).expect("create fixture");
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .expect("wal");
    for migration in LEGACY_MIGRATIONS {
        connection
            .execute_batch(migration)
            .expect("legacy migration");
    }

    connection
        .execute(
            "INSERT INTO sources (id, name, url, kind, enabled, created_at, updated_at)
             VALUES (?1, 'baseline', 'data:text/plain,ads.example.com%0Atracker.example.com',
                     'domains', 1, '2024-01-01 00:00:00', '2024-01-01 00:00:00')",
            [BASELINE_ID],
        )
        .expect("insert baseline source");
    // `updated_at` is deliberately unparseable: the upgrade must fall back to now rather than
    // refuse to start over one bad timestamp.
    connection
        .execute(
            "INSERT INTO sources (id, name, url, kind, enabled, created_at, updated_at)
             VALUES (?1, 'HaGeZi Pro', 'https://example.invalid/pro.txt', 'ADBLOCK', 1,
                     '2024-03-01 10:00:00', 'whenever')",
            [USER_SOURCE_ID],
        )
        .expect("insert user source");

    let mut device = connection
        .prepare(
            "INSERT INTO devices (id, name, ip_address, policy_mode, blocklist_profile_override,
                                  protection_override, allowed_domains_json, service_overrides_json,
                                  created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '2024-02-02 12:00:00', '2024-02-02 12:00:00')",
        )
        .expect("prepare device insert");
    device
        .execute(rusqlite::params![
            TABLET_ID,
            "Kids Tablet",
            "192.168.1.50",
            "custom",
            "strict",
            "bypass",
            r#"["Games.Example.com","  games.example.com  ","","school.example.org"]"#,
            r#"[{"service_id":"tiktok","mode":"block"}]"#,
        ])
        .expect("insert tablet");
    device
        .execute(rusqlite::params![
            LAPTOP_ID,
            "Work Laptop",
            "192.168.1.51",
            "global",
            None::<String>,
            "inherit",
            r#"["work.example.net"]"#,
            "[]",
        ])
        .expect("insert laptop");
    device
        .execute(rusqlite::params![
            BROKEN_ID,
            "Old Console",
            "192.168.1.52",
            "custom",
            None::<String>,
            "inherit",
            "{not json at all",
            "[]",
        ])
        .expect("insert broken device");
    drop(device);
    drop(connection);
}

/// Everything `table_info`, `foreign_key_list` and `index_list` say about a database, sorted so a
/// fresh schema and an upgraded one can be compared directly.
pub fn schema_fingerprint(path: &Path) -> Vec<String> {
    let connection = Connection::open(path).expect("open for fingerprint");
    let tables: Vec<String> = {
        let mut query = connection
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("prepare table list");
        let rows = query.query_map([], |row| row.get(0)).expect("query tables");
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .expect("collect tables")
    };

    let mut lines = Vec::new();
    for table in &tables {
        lines.push(format!("table {table}"));
        for pragma in ["table_info", "foreign_key_list", "index_list"] {
            lines.extend(pragma_rows(&connection, pragma, table));
        }
    }
    lines
}

/// Every row of `PRAGMA <pragma>(<table>)` rendered as text, sorted.
pub fn pragma_rows(connection: &Connection, pragma: &str, table: &str) -> Vec<String> {
    let mut query = connection
        .prepare(&format!("PRAGMA {pragma}({table})"))
        .expect("prepare pragma");
    let mut rows = query.query([]).expect("run pragma");
    let mut lines = Vec::new();
    while let Some(row) = rows.next().expect("pragma row") {
        let columns = row.as_ref().column_count();
        let mut fields = Vec::with_capacity(columns);
        for index in 0..columns {
            let value: rusqlite::types::Value = row.get(index).expect("pragma value");
            fields.push(format!("{value:?}"));
        }
        lines.push(format!("{pragma}({table}): {}", fields.join(" | ")));
    }
    lines.sort();
    lines
}

/// A log entry with the fields most tests do not care about filled in.
pub fn entry(ts: i64, client: &str, domain: &str, blocked: bool) -> QueryLogEntry {
    QueryLogEntry {
        ts,
        client: client.to_owned(),
        domain: domain.to_owned(),
        qtype: 1,
        blocked,
        reason: if blocked { 5 } else { 0 },
        list: blocked.then(|| "oisd small".to_owned()),
    }
}
