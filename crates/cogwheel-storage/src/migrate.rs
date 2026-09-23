//! The one-way upgrade from the pre-v1 ("v0") schema to schema v1 (§2.3).
//!
//! v0 was eleven incremental migration files and a dozen tables for features that no longer exist:
//! compiled ruleset artifacts, audit and security events, notification deliveries, a config
//! version table. v1 is seven tables. Rather than eleven more `ALTER TABLE`s, this moves the old
//! shape aside, builds v1 in the space it leaves, copies across the three things a household would
//! miss — its lists, its device names, and which devices bypass filtering — and drops the rest.
//!
//! # Why a backup and not a rollback alone
//!
//! The transaction *does* roll back cleanly on failure, so in principle the file is safe. The
//! `VACUUM INTO` copy is for the failure modes a transaction cannot cover: a bug in this module
//! that commits something wrong, or an operator who needs to put the previous image back after the
//! upgrade succeeded but the household hated the result. `VACUUM INTO` rather than a file copy
//! because the WAL may hold committed pages that the `.db` file does not, and copying the three
//! files by hand is exactly the sort of thing that produces a corrupt "backup" nobody discovers
//! until they need it.
//!
//! # One schema file, not two
//!
//! The v1 tables here are the ones `schema_v1.sql` creates, because this executes that file: the
//! three legacy tables whose names v1 re-uses are renamed aside first, the schema is built in the
//! space they leave, and the data is copied across. An upgraded database is therefore the fresh
//! schema by construction rather than by a second copy of the DDL that has to be kept in step with
//! it.
//!
//! # What is deliberately not carried over
//!
//! `blocklist_profile_override` never reached DNS evaluation in v0 — it was read by an API that
//! composed profiles and then thrown away — so mapping it to `all_lists`/`device_lists` would
//! *start* filtering a device differently than it was yesterday. `service_overrides_json` is the
//! same story. Global-mode devices' `allowed_domains_json` was ignored at runtime, so importing it
//! would silently unblock names that are blocked today. Each is dropped with a WARN naming the
//! device, so the change is visible in the first boot's logs rather than discovered months later.

use crate::{SCHEMA_V1, StorageError};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::path::{Path, PathBuf};

/// The built-in two-name `data:` list every v0 install carried.
///
/// It is not copied — a `data:` URL masquerading as a subscription is not a list anyone chose —
/// but its presence means the install was answering `0.0.0.0` for those two names, and §2.3 step 7
/// keeps that true by re-creating them as household block rules.
const BASELINE_SOURCE_ID: &str = "00000000-0000-0000-0000-000000000001";

/// The two names the baseline list blocked, kept as household rules so `docs/DEPLOYMENT.md` §7's
/// verification step still passes after an upgrade.
const BASELINE_RULE_DOMAINS: [&str; 2] = ["ads.example.com", "tracker.example.com"];

/// The three legacy tables whose names schema v1 re-uses, moved aside.
///
/// Renaming rather than dropping because their rows are what the upgrade copies across, and the
/// rename is what leaves `settings`, `sources` and `devices` free for `schema_v1.sql` to create.
/// Renaming a parent also rewrites the `REFERENCES` clauses of its children, so `security_events`
/// follows `devices` across and the drop below still takes it cleanly — and, just as importantly,
/// the v1 `rules` and `device_lists` end up pointing at the v1 `devices` and `sources`, never at
/// the legacy rows that are about to be deleted.
const RENAME_LEGACY_ASIDE: &str = "
ALTER TABLE settings RENAME TO settings_v0;
ALTER TABLE sources RENAME TO sources_v0;
ALTER TABLE devices RENAME TO devices_v0;
";

/// Legacy objects, dropped children-first.
///
/// §2.3 lists these in a different order; children have to go first because `DROP TABLE` with
/// `foreign_keys=ON` performs an implicit `DELETE FROM`, and deleting `rulesets` while
/// `active_ruleset` still references a row of it is an immediate constraint failure. The indexes
/// go first for the same reason they are listed at all — explicitness; `DROP TABLE` would take
/// them anyway.
const DROP_LEGACY: &str = "
DROP INDEX IF EXISTS idx_security_events_created_at;
DROP INDEX IF EXISTS idx_audit_events_created_at;
DROP INDEX IF EXISTS idx_notification_deliveries_created_at;
DROP TABLE IF EXISTS active_ruleset;
DROP TABLE IF EXISTS rulesets;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS config_migrations;
DROP TABLE IF EXISTS config_schema;
DROP TABLE IF EXISTS settings_v0;
DROP TABLE IF EXISTS sources_v0;
DROP TABLE IF EXISTS devices_v0;
";

/// Upgrade an open v0 database in place, guarded by a `.pre-v1` copy.
///
/// # Errors
///
/// Anything that fails after the backup is taken produces [`StorageError::Migration`] naming that
/// backup, with the transaction rolled back and the database exactly as it was.
pub(crate) fn upgrade_v0_to_v1(
    connection: &mut Connection,
    path: &Path,
) -> Result<(), StorageError> {
    let backup = backup_path(path);
    // `VACUUM INTO` refuses to write over an existing file, and a stale copy from an upgrade that
    // failed on a previous boot is worth less than a copy of what is on disk right now.
    if backup.exists() {
        std::fs::remove_file(&backup)?;
    }
    // Outside the transaction, and it has to be: VACUUM cannot run inside one.
    connection.execute("VACUUM INTO ?1", [backup.to_string_lossy()])?;
    tracing::info!(
        backup = %backup.display(),
        "upgrading the database to schema v1; a copy of the previous file is at this path"
    );

    match upgrade_in_transaction(connection) {
        Ok(()) => {
            tracing::info!("database upgraded to schema v1");
            Ok(())
        }
        Err(error) => Err(StorageError::Migration {
            backup,
            message: error.to_string(),
        }),
    }
}

/// Steps 2–9 of §2.3. Every early return drops the [`Transaction`], which rolls back.
fn upgrade_in_transaction(connection: &mut Connection) -> Result<(), StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

    transaction.execute_batch(RENAME_LEGACY_ASIDE)?;
    // The same file a fresh install executes, `PRAGMA user_version = 1` and all: one definition of
    // what v1 is, so an upgraded database cannot end up a version of it that only looks right.
    transaction.execute_batch(SCHEMA_V1)?;

    // Step 7 needs to know whether this install was answering for the baseline names.
    let had_baseline: bool = transaction.query_row(
        "SELECT EXISTS (SELECT 1 FROM sources_v0 WHERE id = ?1)",
        [BASELINE_SOURCE_ID],
        |row| row.get(0),
    )?;

    copy_sources(&transaction)?;
    copy_devices(&transaction)?;
    import_device_allow_rules(&transaction)?;
    if had_baseline {
        seed_baseline_rules(&transaction)?;
    }
    warn_about_dropped_device_settings(&transaction)?;

    transaction.execute_batch(DROP_LEGACY)?;

    // The copies wrote rows across three foreign keys; this is the check that every one of them
    // names a row that is still there. A violation means the migration built something
    // inconsistent, and the rollback is the whole point of doing it inside a transaction.
    let mut check = transaction.prepare("PRAGMA foreign_key_check")?;
    let mut violations = check.query([])?;
    if violations.next()?.is_some() {
        return Err(StorageError::Internal(
            "foreign key check failed on the upgraded schema".to_owned(),
        ));
    }
    drop(violations);
    drop(check);

    transaction.commit()?;
    Ok(())
}

/// Step 4: every source except the built-in baseline.
///
/// `refresh_interval_minutes`, `profile` and `verification_strictness` are dropped — the refresh
/// interval is one config variable now, and the other two named a classifier that no longer
/// exists. `lower(trim(kind))` because v1 puts a `CHECK` on the column that v0 did not have and
/// the v0 writer normalised on the way in, so anything that survives that trim was already valid.
/// Text timestamps become unix seconds; a value SQLite cannot parse falls back to now, which is
/// wrong by at most the age of the install and is only ever displayed.
fn copy_sources(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO sources
             (id, name, url, kind, enabled, rule_count, created_at, updated_at)
         SELECT id, name, url, lower(trim(kind)), enabled, 0,
                COALESCE(unixepoch(created_at), unixepoch()),
                COALESCE(unixepoch(updated_at), unixepoch())
         FROM sources_v0
         WHERE id <> ?1",
        [BASELINE_SOURCE_ID],
    )?;
    Ok(())
}

/// Step 5: every device keeps its id, name and IP.
///
/// A device that was both `custom` and `bypass` was resolving everything yesterday and keeps doing
/// so as `filtering = 0`. `all_lists` is always 1: see the module docs on why a
/// `blocklist_profile_override` is not mapped.
fn copy_devices(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO devices
             (id, name, ip_address, filtering, all_lists, created_at, updated_at)
         SELECT id, name, ip_address,
                CASE WHEN policy_mode = 'custom' AND protection_override = 'bypass'
                     THEN 0 ELSE 1 END,
                1,
                COALESCE(unixepoch(created_at), unixepoch()),
                COALESCE(unixepoch(updated_at), unixepoch())
         FROM devices_v0",
        [],
    )?;
    Ok(())
}

/// Step 6: a custom-mode device's `allowed_domains_json` becomes per-device allow rules.
///
/// The `CASE` around the `json_each` argument is load-bearing: `json_each` raises on malformed
/// JSON, and a `WHERE json_valid(…)` clause does not stop the table-valued function from being
/// called for that row. Substituting `'[]'` skips the device instead of failing the upgrade for
/// everyone. `INSERT OR IGNORE` against `rules_unique` collapses entries that differ only in case
/// or surrounding space, which the v0 UI allowed.
fn import_device_allow_rules(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT OR IGNORE INTO rules (domain, action, device_id, created_at)
         SELECT lower(trim(j.value)), 'allow', d.id, unixepoch()
         FROM devices_v0 d,
              json_each(CASE WHEN json_valid(d.allowed_domains_json)
                             THEN d.allowed_domains_json ELSE '[]' END) j
         WHERE d.policy_mode = 'custom'
           AND j.type = 'text'
           AND trim(j.value) <> ''",
        [],
    )?;
    Ok(())
}

/// Step 7: keep answering for the names the baseline list covered.
fn seed_baseline_rules(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    let mut insert = transaction.prepare(
        "INSERT OR IGNORE INTO rules (domain, action, device_id, created_at)
         VALUES (?1, 'block', NULL, unixepoch())",
    )?;
    for domain in BASELINE_RULE_DOMAINS {
        insert.execute([domain])?;
    }
    Ok(())
}

/// Name, in the logs, every device whose v0 settings this upgrade does not carry forward.
///
/// One WARN per device per dropped setting, with the device's name and IP, because "my kid's
/// tablet stopped being different" is otherwise an unattributable behaviour change on an appliance
/// nobody logs into.
fn warn_about_dropped_device_settings(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    let mut query = transaction.prepare(
        "SELECT name, ip_address,
                blocklist_profile_override IS NOT NULL
                    AND trim(COALESCE(blocklist_profile_override, '')) <> '',
                CASE WHEN json_valid(service_overrides_json)
                     THEN json_array_length(service_overrides_json) > 0 ELSE 0 END,
                CASE WHEN policy_mode <> 'custom' AND json_valid(allowed_domains_json)
                     THEN json_array_length(allowed_domains_json) > 0 ELSE 0 END,
                NOT (json_valid(allowed_domains_json) AND json_valid(service_overrides_json))
         FROM devices_v0",
    )?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let ip: String = row.get(1)?;
        if row.get::<_, bool>(2)? {
            tracing::warn!(
                device = %name, ip = %ip,
                "device had a blocklist profile override; it never reached DNS evaluation in the previous release and is not carried forward"
            );
        }
        if row.get::<_, bool>(3)? {
            tracing::warn!(
                device = %name, ip = %ip,
                "device had per-service overrides; services are no longer a concept and they are not carried forward"
            );
        }
        if row.get::<_, bool>(4)? {
            tracing::warn!(
                device = %name, ip = %ip,
                "device was in global mode with allowed domains; those were ignored when resolving and are not imported as rules -- add them by hand if they were meant to apply"
            );
        }
        if row.get::<_, bool>(5)? {
            tracing::warn!(
                device = %name, ip = %ip,
                "device had malformed JSON in its allowed-domains or service-override column; it was skipped"
            );
        }
    }
    Ok(())
}

/// `<db path>.pre-v1`, built on the raw OS string so a non-UTF-8 path survives.
fn backup_path(path: &Path) -> PathBuf {
    let mut backup = path.as_os_str().to_owned();
    backup.push(".pre-v1");
    PathBuf::from(backup)
}
