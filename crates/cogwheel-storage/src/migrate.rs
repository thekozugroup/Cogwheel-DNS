//! The one-way upgrade from the pre-v1 ("v0") schema to schema v1 (§2.3).
//!
//! v0 was eleven incremental migration files and a dozen tables for features that no longer exist:
//! compiled ruleset artifacts, audit and security events, notification deliveries, a config
//! version table. v1 is seven tables. Rather than eleven more `ALTER TABLE`s, this builds the v1
//! shape alongside the old one, copies across the three things a household would miss — its
//! lists, its device names, and which devices bypass filtering — and drops the rest.
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
//! # What is deliberately not carried over
//!
//! `blocklist_profile_override` never reached DNS evaluation in v0 — it was read by an API that
//! composed profiles and then thrown away — so mapping it to `all_lists`/`device_lists` would
//! *start* filtering a device differently than it was yesterday. `service_overrides_json` is the
//! same story. Global-mode devices' `allowed_domains_json` was ignored at runtime, so importing it
//! would silently unblock names that are blocked today. Each is dropped with a WARN naming the
//! device, so the change is visible in the first boot's logs rather than discovered months later.

use crate::{SCHEMA_VERSION, StorageError};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::path::{Path, PathBuf};

/// The built-in two-name `data:` list every v0 install carried.
///
/// It is not copied — a `data:` URL masquerading as a subscription is not a list anyone chose —
/// but its presence means the install was answering `0.0.0.0` for those two names, and §2.3 step 7
/// keeps that true by re-creating them as household block rules.
const BASELINE_SOURCE_ID: &str = "00000000-0000-0000-0000-000000000001";

/// The two names the baseline list blocked, kept as household rules so `DEPLOYMENT.md` §7's
/// verification step still passes after an upgrade.
const BASELINE_RULE_DOMAINS: [&str; 2] = ["ads.example.com", "tracker.example.com"];

/// The seven v1 tables and three indexes, built under `_v1` names beside the legacy ones.
///
/// The column definitions are `schema_v1.sql` verbatim; only the table names differ. The indexes
/// carry their *final* names because `ALTER TABLE … RENAME` leaves index names alone, and an
/// upgraded database whose indexes are called something else would be a schema that only looks
/// like v1. `upgraded_schema_matches_a_fresh_schema` in tests/storage.rs is the check that these
/// two definitions have not drifted apart.
///
/// The foreign keys point at the `_v1` tables, not at the final names. Pointing them at the final
/// names would make the legacy `devices` table the parent of the rules imported in step 6, and
/// `DROP TABLE devices` with `foreign_keys=ON` runs an implicit `DELETE FROM` — which, through
/// `ON DELETE CASCADE`, would delete every rule this migration had just imported. The rename in
/// step 8 repoints them.
const CREATE_V1_TABLES: &str = "
CREATE TABLE settings_v1 (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE sources_v1 (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('hosts','domains','adblock')),
  enabled INTEGER NOT NULL DEFAULT 1,
  etag TEXT, last_modified TEXT, last_fetched_at INTEGER, last_ok_at INTEGER,
  rule_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, note TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE devices_v1 (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE,
  filtering INTEGER NOT NULL DEFAULT 1,
  all_lists INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE device_lists_v1 (
  device_id TEXT NOT NULL REFERENCES devices_v1(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES sources_v1(id) ON DELETE CASCADE,
  PRIMARY KEY (device_id, source_id));

CREATE TABLE rules_v1 (
  id INTEGER PRIMARY KEY, domain TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('allow','block')),
  device_id TEXT REFERENCES devices_v1(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL);
CREATE UNIQUE INDEX rules_unique ON rules_v1 (domain, COALESCE(device_id, ''));

CREATE TABLE query_log_v1 (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL,
  qtype INTEGER NOT NULL, blocked INTEGER NOT NULL, reason INTEGER NOT NULL, list TEXT);
CREATE INDEX query_log_ts ON query_log_v1 (ts);
CREATE INDEX query_log_client_id ON query_log_v1 (client, id);

CREATE TABLE query_stats_hourly_v1 (
  hour INTEGER NOT NULL, client TEXT NOT NULL,
  queries INTEGER NOT NULL, blocked INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (hour, client));
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
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS sources;
DROP TABLE IF EXISTS devices;
";

/// Swap the freshly built tables into the names the rest of the crate uses.
///
/// Renaming a parent rewrites the `REFERENCES` clauses of its children, so this is also what
/// repoints `device_lists`/`rules` from `devices_v1` to `devices`.
const RENAME_V1: &str = "
ALTER TABLE settings_v1 RENAME TO settings;
ALTER TABLE sources_v1 RENAME TO sources;
ALTER TABLE devices_v1 RENAME TO devices;
ALTER TABLE device_lists_v1 RENAME TO device_lists;
ALTER TABLE rules_v1 RENAME TO rules;
ALTER TABLE query_log_v1 RENAME TO query_log;
ALTER TABLE query_stats_hourly_v1 RENAME TO query_stats_hourly;
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

    transaction.execute_batch(CREATE_V1_TABLES)?;

    // Read before anything is dropped: step 7 needs to know whether this install was answering for
    // the baseline names.
    let had_baseline: bool = transaction.query_row(
        "SELECT EXISTS (SELECT 1 FROM sources WHERE id = ?1)",
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
    transaction.execute_batch(RENAME_V1)?;

    // The rename rewrote every foreign key; this is the check that it rewrote them to rows that
    // exist. A violation here means the migration built something inconsistent, and the rollback
    // below is the whole point of doing it inside a transaction.
    let mut check = transaction.prepare("PRAGMA foreign_key_check")?;
    let mut violations = check.query([])?;
    if violations.next()?.is_some() {
        return Err(StorageError::Internal(
            "foreign key check failed on the upgraded schema".to_owned(),
        ));
    }
    drop(violations);
    drop(check);

    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
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
        "INSERT INTO sources_v1
             (id, name, url, kind, enabled, rule_count, created_at, updated_at)
         SELECT id, name, url, lower(trim(kind)), enabled, 0,
                COALESCE(unixepoch(created_at), unixepoch()),
                COALESCE(unixepoch(updated_at), unixepoch())
         FROM sources
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
        "INSERT INTO devices_v1
             (id, name, ip_address, filtering, all_lists, created_at, updated_at)
         SELECT id, name, ip_address,
                CASE WHEN policy_mode = 'custom' AND protection_override = 'bypass'
                     THEN 0 ELSE 1 END,
                1,
                COALESCE(unixepoch(created_at), unixepoch()),
                COALESCE(unixepoch(updated_at), unixepoch())
         FROM devices",
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
        "INSERT OR IGNORE INTO rules_v1 (domain, action, device_id, created_at)
         SELECT lower(trim(j.value)), 'allow', d.id, unixepoch()
         FROM devices d,
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
        "INSERT OR IGNORE INTO rules_v1 (domain, action, device_id, created_at)
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
         FROM devices",
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
