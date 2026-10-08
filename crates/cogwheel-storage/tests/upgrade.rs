//! Opening a database, the one-way v0 -> v1 upgrade (spec sections 2.2 and 2.3), and the additive
//! v1 -> v2 step (ADR 0002).
//!
//! These run against real files rather than `:memory:` because that is where the behaviour lives:
//! `VACUUM INTO` writes a sibling file, WAL mode changes what a second opener sees, and a failed
//! upgrade is defined by what it leaves behind.

mod common;

use common::*;
use std::path::Path;

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
    assert_eq!(user_version(&dir.database()), SCHEMA_VERSION);
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
    assert!(
        storage
            .list_ai_verdicts()
            .await
            .expect("v2 table")
            .is_empty()
    );
    // An in-memory database goes v0 -> v1 -> v2 like a fresh file, and takes no copy on the way:
    // one would land in the working directory and race between parallel tests.
    for version in [1, 2] {
        let litter = backup_of(Path::new(":memory:"), version);
        assert!(!litter.exists(), "{} was written", litter.display());
    }
}

#[tokio::test]
async fn a_fresh_database_takes_no_backup() {
    let (dir, storage) = fresh("fresh-no-backup").await;
    drop(storage);
    let path = dir.database();
    assert_eq!(user_version(&path), SCHEMA_VERSION);
    for version in [1, 2] {
        assert!(
            !backup_of(&path, version).exists(),
            "a fresh file has nothing worth a .pre-v{version}"
        );
    }
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let dir = TempDir::new("newer");
    {
        let connection = Connection::open(dir.database()).expect("create");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("set version");
    }

    let error = Storage::open(&dir.database().to_string_lossy())
        .await
        .expect_err("a newer database must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version is {}, and this build understands {SCHEMA_VERSION}",
            SCHEMA_VERSION + 1
        )),
        "names the version found and the one supported: {message}"
    );
    assert!(message.contains("newer Cogwheel"), "{message}");
    assert_eq!(
        user_version(&dir.database()),
        SCHEMA_VERSION + 1,
        "and is left alone"
    );
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
async fn a_v0_database_upgrades_to_the_current_schema() {
    let dir = TempDir::new("upgrade");
    let path = dir.database();
    build_v0_fixture(&path);
    assert_eq!(user_version(&path), 0);

    let storage = open(&path).await;

    let backup = backup_of(&path, 1);
    assert!(backup.exists(), "the pre-upgrade copy is kept");
    assert_eq!(user_version(&backup), 0, "and is still the v0 file");
    assert!(has_table(&backup, "rulesets"), "legacy tables and all");
    assert!(
        !backup_of(&path, 2).exists(),
        "v0 -> v2 is one jump with one copy: the .pre-v1 file already holds the state to go back to"
    );

    assert_eq!(user_version(&path), SCHEMA_VERSION);

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
        "ai_verdicts",
    ] {
        assert!(has_table(&path, current), "{current} should be there");
    }
    for moved_aside in ["settings_v0", "sources_v0", "devices_v0"] {
        assert!(
            !has_table(&path, moved_aside),
            "{moved_aside} should have been dropped once its rows were copied across"
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
    let backup = backup_of(&path, 1);
    std::fs::write(&backup, b"sentinel").expect("overwrite backup");

    drop(open(&path).await);

    assert_eq!(
        std::fs::read(&backup).expect("read backup"),
        b"sentinel",
        "an already-current database is opened without touching the backup"
    );
    assert!(
        !backup_of(&path, 2).exists(),
        "and without taking a new one"
    );
}

#[tokio::test]
async fn an_upgraded_schema_matches_a_fresh_one() {
    let from_v0_dir = TempDir::new("upgraded-shape-v0");
    let from_v0 = from_v0_dir.database();
    build_v0_fixture(&from_v0);
    drop(open(&from_v0).await);

    let from_v1_dir = TempDir::new("upgraded-shape-v1");
    let from_v1 = from_v1_dir.database();
    build_v1_fixture(&from_v1);
    drop(open(&from_v1).await);

    let fresh_dir = TempDir::new("fresh-shape");
    let fresh_path = fresh_dir.database();
    drop(open(&fresh_path).await);

    let fresh = schema_fingerprint(&fresh_path);
    assert!(
        fresh.iter().any(|line| line == "table ai_verdicts"),
        "a fresh file is built to v2"
    );
    assert_eq!(
        schema_fingerprint(&from_v0),
        fresh,
        "v0 -> v2 must leave the schema a fresh install has, and nothing beside it"
    );
    assert_eq!(schema_fingerprint(&from_v1), fresh, "and so must v1 -> v2");
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
    let backup = backup_of(&path, 1);
    let message = error.to_string();
    assert!(
        message.contains(&backup.to_string_lossy().to_string()),
        "the error names the backup: {message}"
    );
    assert_eq!(user_version(&path), 0, "the database is untouched");
    assert!(has_table(&path, "rulesets"), "and still v0");
    assert!(
        !has_table(&path, "sources_v0"),
        "the rollback put the tables the upgrade moved aside back"
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
    assert_eq!(user_version(&path), SCHEMA_VERSION, "the retry succeeds");
    assert_eq!(user_version(&backup), 0, "on a freshly taken backup");
    assert_eq!(storage.list_sources().await.expect("list").len(), 1);
}

// ---------------------------------------------------------------- the v1 -> v2 step

#[tokio::test]
async fn a_v1_database_upgrades_to_v2_with_a_backup() {
    let dir = TempDir::new("v1-upgrade");
    let path = dir.database();
    build_v1_fixture(&path);
    assert_eq!(user_version(&path), 1);

    let storage = open(&path).await;

    assert_eq!(user_version(&path), SCHEMA_VERSION);
    assert!(has_table(&path, "ai_verdicts"));
    let backup = backup_of(&path, 2);
    assert!(backup.exists(), "a real v1 file is copied before the step");
    assert_eq!(user_version(&backup), 1, "and the copy is still v1");
    assert!(!has_table(&backup, "ai_verdicts"), "from before the step");
    assert!(
        !backup_of(&path, 1).exists(),
        "a v1 file takes no .pre-v1: it was never v0"
    );

    // Every row survives, and a list-holding file is not re-seeded.
    let sources = storage.list_sources().await.expect("sources");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].id, V1_SOURCE_ID);
    assert_eq!(sources[0].rule_count, 4200);
    let devices = storage.list_devices().await.expect("devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, V1_DEVICE_ID);
    assert!(!devices[0].all_lists);
    let lists = storage.list_device_lists(None).await.expect("device lists");
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].source_id, V1_SOURCE_ID);
    let rules = storage.list_rules(None).await.expect("rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].domain, "ads.example.com");
    assert_eq!(
        storage.pause_until().await.expect("pause"),
        Some(NOW + 1800)
    );
    let page = storage
        .query_page(QueryFilter {
            limit: 10,
            ..QueryFilter::default()
        })
        .await
        .expect("query log");
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].domain, "ads.example.com");
    let hours = storage.hourly_24h(NOW).await.expect("rollups");
    assert_eq!(hours.last().expect("24 buckets").queries, 1);
    assert!(storage.list_ai_verdicts().await.expect("ai").is_empty());
    drop(storage);

    // The next open is a v2 open: the copy is neither retaken nor touched.
    std::fs::write(&backup, b"sentinel").expect("overwrite backup");
    drop(open(&path).await);
    assert_eq!(std::fs::read(&backup).expect("read backup"), b"sentinel");
}

#[tokio::test]
async fn a_failed_v1_upgrade_rolls_back_and_names_the_backup() {
    let dir = TempDir::new("v1-poisoned");
    let path = dir.database();
    build_v1_fixture(&path);
    // A table already holding the name v2 creates is the simplest way to make the step fail.
    {
        let connection = Connection::open(&path).expect("open fixture");
        connection
            .execute_batch("CREATE TABLE ai_verdicts (squatter TEXT)")
            .expect("squat on the v2 table name");
    }

    let error = Storage::open(&path.to_string_lossy())
        .await
        .expect_err("the step must fail");
    let backup = backup_of(&path, 2);
    assert!(
        matches!(&error, StorageError::Migration { backup: named, .. } if *named == backup),
        "the error is a migration failure naming .pre-v2: {error:?}"
    );
    assert!(
        error.to_string().contains(&*backup.to_string_lossy()),
        "and says where it is: {error}"
    );
    assert_eq!(user_version(&path), 1, "the database is still v1");
    let connection = Connection::open(&path).expect("open after failure");
    assert_eq!(
        pragma_rows(&connection, "table_info", "ai_verdicts").len(),
        1,
        "and the squatting table is as it was"
    );
    drop(connection);
    assert!(backup.exists());
    assert_eq!(user_version(&backup), 1);

    // Clearing the obstruction lets the next open through, on a freshly taken copy.
    std::fs::write(&backup, b"stale").expect("stale the backup");
    {
        let connection = Connection::open(&path).expect("open fixture");
        connection
            .execute_batch("DROP TABLE ai_verdicts")
            .expect("remove the squatter");
    }
    let storage = open(&path).await;
    assert_eq!(user_version(&path), SCHEMA_VERSION, "the retry succeeds");
    assert_eq!(user_version(&backup), 1, "on a freshly taken backup");
    assert_eq!(storage.list_sources().await.expect("list").len(), 1);
}
