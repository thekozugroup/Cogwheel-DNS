//! Integration tests for the storage crate.
//!
//! They run against real files rather than `:memory:` because half of what is worth testing here
//! only exists on disk: `VACUUM INTO` writes a sibling file, WAL mode changes what a second opener
//! sees, and the legacy upgrade is defined by what it leaves behind when it fails.

use cogwheel_storage::{
    DeviceUpsert, FetchStatus, NewSource, QueryFilter, QueryLogEntry, SourcePatch, Storage,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A fixed "now" every time-dependent test anchors to, so a test that runs at 23:59 behaves like
/// one that runs at noon. 2023-11-14T22:13:20Z; the hour it falls in starts at 1_699_999_200.
const NOW: i64 = 1_700_000_000;

/// Seconds per hour and per day, spelled out where the tests do retention arithmetic.
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;

/// The eleven v0 migration files, kept as fixtures now that nothing executes them in production.
const LEGACY_MIGRATIONS: [&str; 11] = [
    include_str!("fixtures/legacy/0001_init.sql"),
    include_str!("fixtures/legacy/0002_ruleset_artifacts.sql"),
    include_str!("fixtures/legacy/0003_source_metadata.sql"),
    include_str!("fixtures/legacy/0004_source_verification_strictness.sql"),
    include_str!("fixtures/legacy/0005_devices_security_events.sql"),
    include_str!("fixtures/legacy/0006_device_protection_override.sql"),
    include_str!("fixtures/legacy/0007_device_allowed_domains.sql"),
    include_str!("fixtures/legacy/0008_device_service_overrides.sql"),
    include_str!("fixtures/legacy/0009_notification_deliveries.sql"),
    include_str!("fixtures/legacy/0010_config_version.sql"),
    include_str!("fixtures/legacy/0011_retention_indexes.sql"),
];

/// The baseline `data:` source every v0 install carried.
const BASELINE_ID: &str = "00000000-0000-0000-0000-000000000001";
/// The one real subscription in the fixture; its id must survive the upgrade.
const USER_SOURCE_ID: &str = "11111111-2222-3333-4444-555555555555";
/// The custom-mode, bypassing device.
const TABLET_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
/// The global-mode device whose allowed domains must NOT be imported.
const LAPTOP_ID: &str = "99999999-8888-7777-6666-555555555555";
/// The device whose JSON columns are garbage.
const BROKEN_ID: &str = "12121212-3434-5656-7878-909090909090";

/// A directory under the system temp dir, removed when the test ends.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cogwheel-storage-{}-{label}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn database(&self) -> PathBuf {
        self.path.join("cogwheel.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Open a [`Storage`] at `path`, failing the test on any error.
async fn open(path: &Path) -> Storage {
    Storage::open(&path.to_string_lossy())
        .await
        .expect("open storage")
}

/// Open a fresh database in its own temp directory.
async fn fresh(label: &str) -> (TempDir, Storage) {
    let dir = TempDir::new(label);
    let storage = open(&dir.database()).await;
    (dir, storage)
}

/// `<path>.pre-v1`.
fn backup_of(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_owned();
    backup.push(".pre-v1");
    PathBuf::from(backup)
}

/// `PRAGMA user_version` of a database file.
fn user_version(path: &Path) -> i64 {
    let connection = Connection::open(path).expect("open for user_version");
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read user_version")
}

/// Does that file have a table of this name?
fn has_table(path: &Path, table: &str) -> bool {
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
fn build_v0_fixture(path: &Path) {
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
fn schema_fingerprint(path: &Path) -> Vec<String> {
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
fn pragma_rows(connection: &Connection, pragma: &str, table: &str) -> Vec<String> {
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
fn entry(ts: i64, client: &str, domain: &str, blocked: bool) -> QueryLogEntry {
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

// ---------------------------------------------------------------- open and schema

#[tokio::test]
async fn opening_twice_changes_nothing() {
    let dir = TempDir::new("idempotent");
    let storage = open(&dir.database()).await;
    let first = storage.list_sources().await.expect("list");
    drop(storage);

    let storage = open(&dir.database()).await;
    let second = storage.list_sources().await.expect("list");

    assert_eq!(first.len(), 1, "the fresh open seeds exactly one list");
    assert_eq!(second.len(), 1, "the second open seeds nothing further");
    assert_eq!(first[0].id, second[0].id, "and keeps the same row");
    assert_eq!(user_version(&dir.database()), 1);
}

#[tokio::test]
async fn a_fresh_database_is_subscribed_to_oisd_small() {
    let (_dir, storage) = fresh("seed").await;
    let sources = storage.list_sources().await.expect("list");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].name, "oisd small");
    assert_eq!(sources[0].url, "https://small.oisd.nl");
    assert_eq!(sources[0].kind, "adblock");
    assert!(sources[0].enabled);
    assert_eq!(sources[0].rule_count, 0);
    assert!(!sources[0].id.is_empty(), "the id is minted in SQL");
}

#[tokio::test]
async fn an_in_memory_database_opens() {
    // The server's handler tests run against `:memory:`, which has no parent directory to create
    // and no file for the upgrade paths to look at.
    let storage = Storage::open(":memory:").await.expect("open in memory");
    assert_eq!(storage.list_sources().await.expect("list").len(), 1);
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let dir = TempDir::new("newer");
    {
        let connection = Connection::open(dir.database()).expect("create");
        connection
            .pragma_update(None, "user_version", 9)
            .expect("set version");
    }

    let error = Storage::open(&dir.database().to_string_lossy())
        .await
        .expect_err("a newer database must be refused");
    let message = error.to_string();
    assert!(message.contains('9'), "names the version found: {message}");
    assert!(message.contains("newer Cogwheel"), "{message}");
}

#[tokio::test]
async fn an_unrecognised_v0_layout_is_refused() {
    let dir = TempDir::new("unknown");
    {
        let connection = Connection::open(dir.database()).expect("create");
        connection
            .execute_batch("CREATE TABLE sources (id TEXT PRIMARY KEY, whatever TEXT)")
            .expect("create sources");
    }

    let error = Storage::open(&dir.database().to_string_lossy())
        .await
        .expect_err("an unknown v0 layout must be refused");
    assert!(error.to_string().contains("unrecognised layout"), "{error}");
    assert!(
        has_table(&dir.database(), "sources"),
        "and must not have touched the file"
    );
}

// ---------------------------------------------------------------- the legacy upgrade

#[tokio::test]
async fn a_v0_database_upgrades_to_v1() {
    let dir = TempDir::new("upgrade");
    let path = dir.database();
    build_v0_fixture(&path);
    assert_eq!(user_version(&path), 0);

    let storage = open(&path).await;

    let backup = backup_of(&path);
    assert!(backup.exists(), "the pre-upgrade copy is kept");
    assert_eq!(user_version(&backup), 0, "and is still the v0 file");
    assert!(has_table(&backup, "rulesets"), "legacy tables and all");

    assert_eq!(user_version(&path), 1);

    let sources = storage.list_sources().await.expect("list sources");
    assert_eq!(sources.len(), 1, "the baseline data: URL is not a list");
    assert_eq!(sources[0].id, USER_SOURCE_ID, "ids are kept");
    assert_eq!(sources[0].name, "HaGeZi Pro");
    assert_eq!(
        sources[0].kind, "adblock",
        "kind is normalised, not dropped"
    );
    assert!(sources[0].created_at > 0 && sources[0].updated_at > 0);
    assert!(
        sources.iter().all(|source| source.name != "oisd small"),
        "a database that already had a list is not re-seeded"
    );

    let devices = storage.list_devices().await.expect("list devices");
    assert_eq!(devices.len(), 3);
    let tablet = devices
        .iter()
        .find(|device| device.id == TABLET_ID)
        .expect("the tablet keeps its id");
    assert!(!tablet.filtering, "a bypassing device keeps bypassing");
    assert!(tablet.all_lists, "all_lists is always 1 after an upgrade");
    assert!(
        devices
            .iter()
            .filter(|device| device.id != TABLET_ID)
            .all(|device| device.filtering),
        "nothing else starts bypassing"
    );

    let tablet_rules = storage
        .list_rules(Some(TABLET_ID))
        .await
        .expect("tablet rules");
    let domains: Vec<&str> = tablet_rules
        .iter()
        .map(|rule| rule.domain.as_str())
        .collect();
    assert_eq!(
        domains,
        ["games.example.com", "school.example.org"],
        "allowed domains are lower-cased, trimmed, de-duplicated and blanks dropped"
    );
    assert!(tablet_rules.iter().all(|rule| rule.action == "allow"));
    assert_eq!(tablet_rules[0].device_name.as_deref(), Some("Kids Tablet"));

    let all_rules = storage.list_rules(None).await.expect("all rules");
    assert!(
        all_rules
            .iter()
            .all(|rule| rule.domain != "work.example.net"),
        "a global-mode device's allowed domains were ignored at runtime and stay ignored"
    );
    assert!(
        all_rules
            .iter()
            .all(|rule| rule.device_id != Some(BROKEN_ID.to_owned())),
        "a device with malformed JSON contributes nothing"
    );

    let household: Vec<&str> = all_rules
        .iter()
        .filter(|rule| rule.device_id.is_none())
        .map(|rule| rule.domain.as_str())
        .collect();
    assert_eq!(
        household,
        ["ads.example.com", "tracker.example.com"],
        "the baseline list's two names survive as household block rules"
    );
    assert!(
        all_rules
            .iter()
            .filter(|rule| rule.device_id.is_none())
            .all(|rule| rule.action == "block")
    );

    for legacy in [
        "rulesets",
        "active_ruleset",
        "audit_events",
        "security_events",
        "notification_deliveries",
        "config_schema",
        "config_migrations",
    ] {
        assert!(!has_table(&path, legacy), "{legacy} should be gone");
    }
    for current in [
        "settings",
        "sources",
        "devices",
        "device_lists",
        "rules",
        "query_log",
        "query_stats_hourly",
    ] {
        assert!(has_table(&path, current), "{current} should be there");
        assert!(
            !has_table(&path, &format!("{current}_v1")),
            "{current}_v1 should have been renamed away"
        );
    }
}

#[tokio::test]
async fn a_second_open_takes_no_new_backup() {
    let dir = TempDir::new("no-second-backup");
    let path = dir.database();
    build_v0_fixture(&path);
    drop(open(&path).await);

    // Replacing the backup with a sentinel is the only way to tell "not overwritten" from
    // "overwritten with identical bytes".
    let backup = backup_of(&path);
    std::fs::write(&backup, b"sentinel").expect("overwrite backup");

    drop(open(&path).await);

    assert_eq!(
        std::fs::read(&backup).expect("read backup"),
        b"sentinel",
        "an already-v1 database is opened without touching the backup"
    );
}

#[tokio::test]
async fn an_upgraded_schema_matches_a_fresh_one() {
    let upgraded_dir = TempDir::new("upgraded-shape");
    let upgraded = upgraded_dir.database();
    build_v0_fixture(&upgraded);
    drop(open(&upgraded).await);

    let fresh_dir = TempDir::new("fresh-shape");
    let fresh_path = fresh_dir.database();
    drop(open(&fresh_path).await);

    assert_eq!(
        schema_fingerprint(&upgraded),
        schema_fingerprint(&fresh_path),
        "the upgrade must produce the same schema as schema_v1.sql"
    );
}

#[tokio::test]
async fn a_failed_upgrade_rolls_back_and_names_the_backup() {
    let dir = TempDir::new("poisoned");
    let path = dir.database();
    build_v0_fixture(&path);
    // v0 had no CHECK on `kind`, so a value v1 refuses is reachable from a real database.
    {
        let connection = Connection::open(&path).expect("open fixture");
        connection
            .execute(
                "UPDATE sources SET kind = 'nonsense' WHERE id = ?1",
                [USER_SOURCE_ID],
            )
            .expect("poison the source kind");
    }

    let error = Storage::open(&path.to_string_lossy())
        .await
        .expect_err("the upgrade must fail");
    let backup = backup_of(&path);
    let message = error.to_string();
    assert!(
        message.contains(&backup.to_string_lossy().to_string()),
        "the error names the backup: {message}"
    );
    assert_eq!(user_version(&path), 0, "the database is untouched");
    assert!(has_table(&path, "rulesets"), "and still v0");
    assert!(
        !has_table(&path, "sources_v1"),
        "the rollback took the half-built tables"
    );
    assert!(backup.exists());

    // A stale backup from the failed attempt must not stop, or be mistaken for, the next one.
    std::fs::write(&backup, b"stale").expect("stale the backup");
    {
        let connection = Connection::open(&path).expect("open fixture");
        connection
            .execute(
                "UPDATE sources SET kind = 'adblock' WHERE id = ?1",
                [USER_SOURCE_ID],
            )
            .expect("fix the source kind");
    }

    let storage = open(&path).await;
    assert_eq!(user_version(&path), 1, "the retry succeeds");
    assert_eq!(user_version(&backup), 0, "on a freshly taken backup");
    assert_eq!(storage.list_sources().await.expect("list").len(), 1);
}

// ---------------------------------------------------------------- sources

#[tokio::test]
async fn sources_round_trip_and_names_are_unique() {
    let (_dir, storage) = fresh("sources").await;

    let created = storage
        .insert_source(NewSource {
            id: None,
            name: "HaGeZi Pro".to_owned(),
            url: "https://example.invalid/pro.txt".to_owned(),
            kind: "adblock".to_owned(),
            enabled: true,
        })
        .await
        .expect("insert");
    assert!(created.enabled);
    assert_eq!(created.rule_count, 0);
    assert!(created.last_error.is_none());

    let fetched = storage
        .get_source(&created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched.name, "HaGeZi Pro");

    let updated = storage
        .update_source(
            &created.id,
            SourcePatch {
                enabled: Some(false),
                ..SourcePatch::default()
            },
        )
        .await
        .expect("update")
        .expect("present");
    assert!(!updated.enabled);
    assert_eq!(updated.name, "HaGeZi Pro", "an absent field is left alone");
    assert_eq!(updated.url, created.url);

    let duplicate = storage
        .insert_source(NewSource {
            id: None,
            name: "HaGeZi Pro".to_owned(),
            url: "https://example.invalid/other.txt".to_owned(),
            kind: "hosts".to_owned(),
            enabled: true,
        })
        .await
        .expect_err("a duplicate name must be rejected");
    assert!(duplicate.is_unique_violation(), "{duplicate}");
    assert!(!duplicate.is_foreign_key_violation());

    assert!(storage.delete_source(&created.id).await.expect("delete"));
    assert!(!storage.delete_source(&created.id).await.expect("delete"));
    assert!(
        storage
            .get_source(&created.id)
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn fetch_status_transitions_keep_what_still_describes_the_cached_body() {
    let (_dir, storage) = fresh("fetch-status").await;
    let source = storage.list_sources().await.expect("list").remove(0);

    storage
        .update_fetch_status(
            &source.id,
            FetchStatus::Ok {
                at: NOW,
                etag: Some("\"abc\"".to_owned()),
                last_modified: Some("Tue, 14 Nov 2023 22:00:00 GMT".to_owned()),
                rule_count: 1234,
                note: Some("covers pool.ntp.org".to_owned()),
            },
        )
        .await
        .expect("ok status");
    let after_ok = storage
        .get_source(&source.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(after_ok.last_ok_at, Some(NOW));
    assert_eq!(after_ok.last_fetched_at, Some(NOW));
    assert_eq!(after_ok.rule_count, 1234);
    assert_eq!(after_ok.etag.as_deref(), Some("\"abc\""));
    assert!(after_ok.last_error.is_none());

    storage
        .update_fetch_status(
            &source.id,
            FetchStatus::Failed {
                at: NOW + 60,
                error: "connection refused".to_owned(),
            },
        )
        .await
        .expect("failed status");
    let after_failure = storage
        .get_source(&source.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        after_failure.last_error.as_deref(),
        Some("connection refused")
    );
    assert_eq!(after_failure.last_fetched_at, Some(NOW + 60));
    assert_eq!(
        after_failure.last_ok_at,
        Some(NOW),
        "a failure is not an update"
    );
    assert_eq!(
        after_failure.rule_count, 1234,
        "the cached body still serves"
    );
    assert_eq!(after_failure.etag.as_deref(), Some("\"abc\""));

    storage
        .update_fetch_status(&source.id, FetchStatus::Unchanged { at: NOW + 120 })
        .await
        .expect("unchanged status");
    let after_304 = storage
        .get_source(&source.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(after_304.last_ok_at, Some(NOW + 120));
    assert_eq!(after_304.rule_count, 1234);
    assert!(
        after_304.last_error.is_none(),
        "a 304 clears the previous error"
    );

    assert!(
        !storage
            .update_fetch_status("no-such-list", FetchStatus::Unchanged { at: NOW })
            .await
            .expect("missing list")
    );
}

// ---------------------------------------------------------------- devices

#[tokio::test]
async fn devices_upsert_in_place_and_addresses_are_unique() {
    let (_dir, storage) = fresh("devices").await;

    let created = storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Kids Tablet".to_owned(),
            ip_address: "192.168.1.50".to_owned(),
            filtering: true,
            all_lists: true,
        })
        .await
        .expect("create");

    let renamed = storage
        .upsert_device(DeviceUpsert {
            id: Some(created.id.clone()),
            name: "Tablet".to_owned(),
            ip_address: "192.168.1.60".to_owned(),
            filtering: false,
            all_lists: false,
        })
        .await
        .expect("update");
    assert_eq!(renamed.id, created.id, "an update keeps the row");
    assert_eq!(renamed.name, "Tablet");
    assert_eq!(renamed.ip_address, "192.168.1.60");
    assert!(!renamed.filtering);
    assert!(!renamed.all_lists);
    assert_eq!(renamed.created_at, created.created_at);
    assert_eq!(storage.list_devices().await.expect("list").len(), 1);

    let duplicate = storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Someone else".to_owned(),
            ip_address: "192.168.1.60".to_owned(),
            filtering: true,
            all_lists: true,
        })
        .await
        .expect_err("two devices cannot share an address");
    assert!(duplicate.is_unique_violation(), "{duplicate}");

    assert!(storage.delete_device(&created.id).await.expect("delete"));
    assert!(!storage.delete_device(&created.id).await.expect("delete"));
}

#[tokio::test]
async fn device_lists_are_replaced_deduped_and_cascade() {
    let (_dir, storage) = fresh("device-lists").await;
    let seeded = storage.list_sources().await.expect("list").remove(0);
    let second = storage
        .insert_source(NewSource {
            id: None,
            name: "StevenBlack".to_owned(),
            url: "https://example.invalid/hosts".to_owned(),
            kind: "hosts".to_owned(),
            enabled: true,
        })
        .await
        .expect("insert");
    let device = storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Console".to_owned(),
            ip_address: "192.168.1.70".to_owned(),
            filtering: true,
            all_lists: false,
        })
        .await
        .expect("device");

    storage
        .set_device_lists(
            &device.id,
            vec![seeded.id.clone(), seeded.id.clone(), second.id.clone()],
        )
        .await
        .expect("set lists");
    let selected = storage
        .list_device_lists(Some(&device.id))
        .await
        .expect("read lists");
    assert_eq!(selected.len(), 2, "a repeated id is stored once");

    storage
        .set_device_lists(&device.id, vec![second.id.clone()])
        .await
        .expect("replace lists");
    let selected = storage.list_device_lists(None).await.expect("read lists");
    assert_eq!(selected.len(), 1, "the selection is replaced, not merged");
    assert_eq!(selected[0].source_id, second.id);

    let unknown = storage
        .set_device_lists(&device.id, vec!["no-such-list".to_owned()])
        .await
        .expect_err("an unknown list id is a foreign key violation");
    assert!(unknown.is_foreign_key_violation(), "{unknown}");
    assert_eq!(
        storage.list_device_lists(None).await.expect("read").len(),
        1,
        "and the transaction left the previous selection alone"
    );

    storage
        .set_device_lists(&device.id, vec![seeded.id.clone(), second.id.clone()])
        .await
        .expect("set lists");
    assert!(
        storage
            .delete_source(&second.id)
            .await
            .expect("delete list")
    );
    assert_eq!(
        storage.list_device_lists(None).await.expect("read").len(),
        1,
        "deleting a list takes its device_lists rows with it"
    );

    storage
        .delete_device(&device.id)
        .await
        .expect("delete device");
    assert!(
        storage
            .list_device_lists(None)
            .await
            .expect("read")
            .is_empty(),
        "and so does deleting the device"
    );
}

// ---------------------------------------------------------------- rules

#[tokio::test]
async fn rules_upsert_per_scope_and_cascade_with_their_device() {
    let (_dir, storage) = fresh("rules").await;
    let device = storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Tablet".to_owned(),
            ip_address: "192.168.1.80".to_owned(),
            filtering: true,
            all_lists: true,
        })
        .await
        .expect("device");

    let household = storage
        .upsert_rule("ads.example.com", "block", None)
        .await
        .expect("household rule");
    assert!(household.device_id.is_none());
    assert!(household.device_name.is_none());

    let flipped = storage
        .upsert_rule("ads.example.com", "allow", None)
        .await
        .expect("flip");
    assert_eq!(flipped.id, household.id, "flipping keeps the row id");
    assert_eq!(flipped.action, "allow");
    assert_eq!(flipped.created_at, household.created_at);

    let per_device = storage
        .upsert_rule("ads.example.com", "block", Some(&device.id))
        .await
        .expect("device rule");
    assert_ne!(
        per_device.id, household.id,
        "the same domain in another scope is another rule"
    );
    assert_eq!(per_device.device_name.as_deref(), Some("Tablet"));

    assert_eq!(storage.list_rules(None).await.expect("all").len(), 2);
    assert_eq!(
        storage
            .list_rules(Some(&device.id))
            .await
            .expect("device")
            .len(),
        1
    );

    let orphan = storage
        .upsert_rule("ads.example.com", "block", Some("no-such-device"))
        .await
        .expect_err("a rule for a device that does not exist is a foreign key violation");
    assert!(orphan.is_foreign_key_violation(), "{orphan}");

    storage
        .delete_device(&device.id)
        .await
        .expect("delete device");
    let remaining = storage.list_rules(None).await.expect("all");
    assert_eq!(remaining.len(), 1, "device rules go with the device");
    assert!(remaining[0].device_id.is_none());

    assert!(storage.delete_rule(remaining[0].id).await.expect("delete"));
    assert!(!storage.delete_rule(remaining[0].id).await.expect("delete"));
}

// ---------------------------------------------------------------- query log and rollups

#[tokio::test]
async fn rollups_accumulate_across_batches() {
    let (_dir, storage) = fresh("rollups").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW, "10.0.0.1", "news.example.com", false),
                entry(NOW, "10.0.0.2", "cdn.example.com", false),
            ],
            true,
        )
        .await
        .expect("first batch");
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW + 10, "10.0.0.1", "ads.example.com", true),
                entry(NOW + 20, "10.0.0.2", "tracker.example.com", true),
            ],
            true,
        )
        .await
        .expect("second batch");

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    let current = hours.last().expect("24 buckets");
    assert_eq!(current.queries, 5, "both batches land in the same bucket");
    assert_eq!(current.blocked, 3);

    let clients = storage.per_client_24h(NOW).await.expect("per client");
    assert_eq!(clients.len(), 2, "the all-devices bucket is not a client");
    assert_eq!(clients[0].client, "10.0.0.1");
    assert_eq!(clients[0].queries, 3);
    assert_eq!(clients[0].blocked, 2);
    assert_eq!(clients[0].last_seen, NOW + 10, "last_seen is the maximum");
    assert_eq!(clients[1].client, "10.0.0.2");
    assert_eq!(clients[1].queries, 2);
    assert_eq!(clients[1].blocked, 1);
    assert_eq!(clients[1].last_seen, NOW + 20);
}

#[tokio::test]
async fn history_days_zero_writes_rollups_but_no_rows() {
    let (_dir, storage) = fresh("no-history").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW, "10.0.0.1", "news.example.com", false),
            ],
            false,
        )
        .await
        .expect("batch");

    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert!(
        page.rows.is_empty(),
        "no browsing history is written at all"
    );

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    assert_eq!(
        hours.last().expect("bucket").queries,
        2,
        "but the counts are"
    );
    assert_eq!(hours.last().expect("bucket").blocked, 1);
}

#[tokio::test]
async fn the_hourly_chart_always_has_twenty_four_buckets() {
    let (_dir, storage) = fresh("hourly").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "a.example.com", true),
                entry(NOW - 5 * HOUR, "10.0.0.1", "b.example.com", false),
                // Older than the window: it must not appear, and must not shift the buckets.
                entry(NOW - 30 * HOUR, "10.0.0.1", "c.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    assert_eq!(hours.len(), 24);
    assert!(
        hours
            .windows(2)
            .all(|pair| pair[1].hour - pair[0].hour == HOUR),
        "buckets are contiguous and in order"
    );
    assert_eq!(hours[23].queries, 1);
    assert_eq!(hours[23].blocked, 1);
    assert_eq!(hours[18].queries, 1, "five hours back");
    assert_eq!(hours[18].blocked, 0);
    assert_eq!(
        hours.iter().map(|bucket| bucket.queries).sum::<i64>(),
        2,
        "the out-of-window hour is not folded in anywhere"
    );
}

#[tokio::test]
async fn paging_walks_the_log_newest_first() {
    let (_dir, storage) = fresh("paging").await;
    let batch = (0..4)
        .map(|index| {
            entry(
                NOW + index,
                "10.0.0.1",
                &format!("d{index}.example.com"),
                false,
            )
        })
        .collect();
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let empty = storage
        .query_page(QueryFilter {
            limit: 0,
            ..QueryFilter::default()
        })
        .await
        .expect("limit 0");
    assert!(empty.rows.is_empty());
    assert!(empty.next_before.is_none(), "limit 0 is not a cursor");

    let first = storage
        .query_page(QueryFilter {
            limit: 2,
            ..QueryFilter::default()
        })
        .await
        .expect("first page");
    assert_eq!(
        first
            .rows
            .iter()
            .map(|row| row.domain.as_str())
            .collect::<Vec<_>>(),
        ["d3.example.com", "d2.example.com"]
    );

    let second = storage
        .query_page(QueryFilter {
            limit: 2,
            before: first.next_before,
            ..QueryFilter::default()
        })
        .await
        .expect("second page");
    assert_eq!(
        second
            .rows
            .iter()
            .map(|row| row.domain.as_str())
            .collect::<Vec<_>>(),
        ["d1.example.com", "d0.example.com"]
    );

    // The log ended exactly on a page boundary, so the cursor is still set and the page after it
    // is what tells the caller there is nothing more.
    assert!(second.next_before.is_some());
    let third = storage
        .query_page(QueryFilter {
            limit: 2,
            before: second.next_before,
            ..QueryFilter::default()
        })
        .await
        .expect("third page");
    assert!(third.rows.is_empty());
    assert!(third.next_before.is_none());
}

#[tokio::test]
async fn page_filters_narrow_the_log() {
    let (_dir, storage) = fresh("filters").await;
    storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Kids Tablet".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            filtering: true,
            all_lists: true,
        })
        .await
        .expect("device");
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW + 1, "10.0.0.1", "news.example.com", false),
                entry(NOW + 2, "10.0.0.2", "ADS.example.org", true),
                entry(NOW + 3, "10.0.0.2", "cdn.example.org", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let all = QueryFilter {
        limit: 100,
        ..QueryFilter::default()
    };

    let named = storage
        .query_page(QueryFilter {
            client: Some("10.0.0.1".to_owned()),
            ..all.clone()
        })
        .await
        .expect("client filter");
    assert_eq!(named.rows.len(), 2);
    assert!(
        named
            .rows
            .iter()
            .all(|row| row.device_name.as_deref() == Some("Kids Tablet")),
        "the join relabels history with the device's current name"
    );

    let unnamed = storage
        .query_page(QueryFilter {
            unnamed: true,
            ..all.clone()
        })
        .await
        .expect("unnamed filter");
    assert_eq!(unnamed.rows.len(), 2);
    assert!(
        unnamed
            .rows
            .iter()
            .all(|row| row.client == "10.0.0.2" && row.device_id.is_none())
    );

    let blocked = storage
        .query_page(QueryFilter {
            blocked: Some(true),
            ..all.clone()
        })
        .await
        .expect("blocked filter");
    assert_eq!(blocked.rows.len(), 2);
    assert!(blocked.rows.iter().all(|row| row.blocked));

    let allowed = storage
        .query_page(QueryFilter {
            blocked: Some(false),
            ..all.clone()
        })
        .await
        .expect("allowed filter");
    assert_eq!(allowed.rows.len(), 2);
    assert!(allowed.rows.iter().all(|row| !row.blocked));

    let searched = storage
        .query_page(QueryFilter {
            contains: Some("ADS.".to_owned()),
            ..all.clone()
        })
        .await
        .expect("substring filter");
    assert_eq!(
        searched.rows.len(),
        1,
        "the needle is case-insensitive; stored domains are already lower case"
    );
    assert_eq!(searched.rows[0].domain, "ads.example.com");

    let combined = storage
        .query_page(QueryFilter {
            blocked: Some(true),
            unnamed: true,
            ..all
        })
        .await
        .expect("combined filters");
    assert_eq!(combined.rows.len(), 1);
    assert_eq!(combined.rows[0].client, "10.0.0.2");
}

#[tokio::test]
async fn unnamed_clients_are_the_ones_without_a_device_row() {
    let (_dir, storage) = fresh("unnamed").await;
    storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Kids Tablet".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            filtering: true,
            all_lists: true,
        })
        .await
        .expect("device");
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "a.example.com", false),
                entry(NOW, "10.0.0.2", "b.example.com", true),
                entry(NOW, "10.0.0.3", "c.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    assert_eq!(storage.per_client_24h(NOW).await.expect("all").len(), 3);
    let unnamed = storage.unnamed_clients_24h(NOW).await.expect("unnamed");
    assert_eq!(
        unnamed
            .iter()
            .map(|client| client.client.as_str())
            .collect::<Vec<_>>(),
        ["10.0.0.2", "10.0.0.3"]
    );
    assert_eq!(unnamed[0].blocked, 1);
    assert_eq!(unnamed[0].last_seen, NOW);
}

#[tokio::test]
async fn top_domains_ranks_blocked_and_queried_separately() {
    let (_dir, storage) = fresh("top").await;
    let mut batch = Vec::new();
    for _ in 0..5 {
        batch.push(entry(NOW, "10.0.0.1", "ads.example.com", true));
    }
    for _ in 0..9 {
        batch.push(entry(NOW, "10.0.0.1", "cdn.example.com", false));
    }
    batch.push(entry(NOW, "10.0.0.1", "tracker.example.com", true));
    // Before the window: counted by neither.
    batch.push(entry(NOW - 2 * DAY, "10.0.0.1", "old.example.com", true));
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let blocked = storage
        .top_domains(true, NOW - DAY, 10)
        .await
        .expect("top blocked");
    assert_eq!(
        blocked
            .iter()
            .map(|row| (row.domain.as_str(), row.count))
            .collect::<Vec<_>>(),
        [("ads.example.com", 5), ("tracker.example.com", 1)]
    );

    let queried = storage
        .top_domains(false, NOW - DAY, 10)
        .await
        .expect("top queried");
    assert_eq!(queried[0].domain, "cdn.example.com");
    assert_eq!(queried[0].count, 9);
    assert_eq!(queried.len(), 3, "allowed and blocked names both count");

    let capped = storage
        .top_domains(false, NOW - DAY, 1)
        .await
        .expect("limit");
    assert_eq!(capped.len(), 1);
}

#[tokio::test]
async fn clearing_the_log_keeps_the_counts() {
    let (_dir, storage) = fresh("clear").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW, "10.0.0.1", "news.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    assert_eq!(storage.clear_query_log().await.expect("clear"), 2);
    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert!(page.rows.is_empty());

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    assert_eq!(
        hours.last().expect("bucket").queries,
        2,
        "counts are not browsing history and survive a clear"
    );
    assert_eq!(storage.per_client_24h(NOW).await.expect("clients").len(), 1);
}

#[tokio::test]
async fn pruning_drops_rows_past_the_retention_window() {
    let (_dir, storage) = fresh("prune-days").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW - 10 * DAY, "10.0.0.1", "old.example.com", false),
                entry(NOW - 8 * DAY, "10.0.0.1", "older.example.com", false),
                entry(NOW - DAY, "10.0.0.1", "recent.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW, 7, u64::MAX, 90)
        .await
        .expect("prune");
    assert_eq!(outcome.by_age, 2);
    assert_eq!(outcome.by_cap, 0);

    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].domain, "recent.example.com");
}

#[tokio::test]
async fn pruning_with_history_off_keeps_what_is_already_there() {
    let (_dir, storage) = fresh("prune-off").await;
    storage
        .insert_batch_with_rollups(
            vec![entry(NOW - 10 * DAY, "10.0.0.1", "old.example.com", false)],
            true,
        )
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW, 0, u64::MAX, 90)
        .await
        .expect("prune");
    assert_eq!(
        outcome.by_age, 0,
        "turning logging off must not wipe the log"
    );
    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(page.rows.len(), 1);
}

#[tokio::test]
async fn the_row_cap_keeps_exactly_max_rows() {
    let (_dir, storage) = fresh("prune-cap").await;
    let batch = (0..5)
        .map(|index| {
            entry(
                NOW + index,
                "10.0.0.1",
                &format!("d{index}.example.com"),
                false,
            )
        })
        .collect();
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW + 10, 7, 2, 90)
        .await
        .expect("prune");
    assert_eq!(outcome.by_cap, 3);

    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(
        page.rows
            .iter()
            .map(|row| row.domain.as_str())
            .collect::<Vec<_>>(),
        ["d4.example.com", "d3.example.com"],
        "the cap keeps the newest max_rows rows and no more"
    );

    let again = storage
        .prune_query_log(NOW + 10, 7, 2, 90)
        .await
        .expect("prune again");
    assert_eq!(again.by_cap, 0, "a log already at the cap is left alone");
}

#[tokio::test]
async fn old_rollup_buckets_are_pruned_on_their_own_schedule() {
    let (_dir, storage) = fresh("prune-rollups").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW - 100 * DAY, "10.0.0.1", "ancient.example.com", false),
                entry(NOW, "10.0.0.1", "today.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW, 0, u64::MAX, 90)
        .await
        .expect("prune");
    assert_eq!(
        outcome.rollups, 2,
        "the all-devices bucket and the client bucket for that hour"
    );
    assert_eq!(storage.per_client_24h(NOW).await.expect("clients").len(), 1);
}

// ---------------------------------------------------------------- settings

#[tokio::test]
async fn pause_until_round_trips() {
    let (_dir, storage) = fresh("pause").await;
    assert!(storage.pause_until().await.expect("read").is_none());

    storage
        .set_pause_until(Some(NOW + 1800))
        .await
        .expect("pause");
    assert_eq!(storage.pause_until().await.expect("read"), Some(NOW + 1800));

    storage.set_pause_until(None).await.expect("resume");
    assert!(
        storage.pause_until().await.expect("read").is_none(),
        "resuming clears the row rather than storing a zero"
    );

    storage.set_pause_until(Some(0)).await.expect("zero");
    assert!(
        storage.pause_until().await.expect("read").is_none(),
        "a zero deadline is not a pause"
    );
}

// ---------------------------------------------------------------- API shapes

#[tokio::test]
async fn records_the_api_returns_serialize() {
    let (_dir, storage) = fresh("serde").await;
    let device = storage
        .upsert_device(DeviceUpsert {
            id: None,
            name: "Tablet".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            filtering: true,
            all_lists: true,
        })
        .await
        .expect("device");
    storage
        .upsert_rule("ads.example.com", "block", Some(&device.id))
        .await
        .expect("rule");
    storage
        .insert_batch_with_rollups(vec![entry(NOW, "10.0.0.1", "ads.example.com", true)], true)
        .await
        .expect("batch");

    let source = serde_json::to_value(&storage.list_sources().await.expect("sources")[0])
        .expect("serialize source");
    assert_eq!(source["name"], "oisd small");
    assert!(source.get("last_ok_at").is_some());

    let device = serde_json::to_value(&device).expect("serialize device");
    assert_eq!(device["ip_address"], "10.0.0.1");
    assert_eq!(device["filtering"], true);

    let rule = serde_json::to_value(&storage.list_rules(None).await.expect("rules")[0])
        .expect("serialize rule");
    assert_eq!(rule["device_name"], "Tablet");

    let page = storage
        .query_page(QueryFilter {
            limit: 10,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    let page = serde_json::to_value(&page).expect("serialize page");
    assert_eq!(page["rows"][0]["domain"], "ads.example.com");
    assert_eq!(page["rows"][0]["device_name"], "Tablet");

    let hours = serde_json::to_value(storage.hourly_24h(NOW).await.expect("hourly"))
        .expect("serialize hours");
    assert_eq!(hours.as_array().expect("array").len(), 24);
}
