//! Opening a database, and the one-way v0 -> v1 upgrade (spec sections 2.2 and 2.3).
//!
//! These run against real files rather than `:memory:` because that is where the behaviour lives:
//! `VACUUM INTO` writes a sibling file, WAL mode changes what a second opener sees, and a failed
//! upgrade is defined by what it leaves behind.

mod common;

use common::*;

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
        "the upgrade must leave the same schema schema_v1.sql produces, and nothing beside it"
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
    assert_eq!(user_version(&path), 1, "the retry succeeds");
    assert_eq!(user_version(&backup), 0, "on a freshly taken backup");
    assert_eq!(storage.list_sources().await.expect("list").len(), 1);
}
