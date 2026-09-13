-- Migration 0010: Config Version Tracking
-- Adds schema version tracking for forward/backward compatibility

-- Track the config schema version for migration compatibility
CREATE TABLE IF NOT EXISTS config_schema (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL DEFAULT 1,
    upgraded_at TEXT NOT NULL DEFAULT (datetime('now')),
    cogwheel_version TEXT
);

-- Insert initial version
INSERT OR IGNORE INTO config_schema (id, version, upgraded_at) VALUES (1, 1, datetime('now'));

-- Track individual config migrations applied
CREATE TABLE IF NOT EXISTS config_migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL UNIQUE,
    applied_at TEXT NOT NULL DEFAULT (datetime('now')),
    description TEXT
);

-- Record initial state
-- OR IGNORE: migrations are re-run on every boot, and `version` is UNIQUE, so a plain INSERT
-- failed on the second start of any existing install. That failure used to be swallowed; now that
-- migration errors are fatal, it would refuse to start.
INSERT OR IGNORE INTO config_migrations (version, description) VALUES (1, 'Initial config schema version');
