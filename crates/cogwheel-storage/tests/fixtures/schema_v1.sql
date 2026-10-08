-- Cogwheel schema v1 -- the whole database, in one file.
--
-- Seven tables and one index hold everything the product persists: the
-- three user concepts (Device, List, Rule), the query log and its hourly
-- rollups, and one settings row. This file is also what `migrate.rs` executes
-- to upgrade a legacy v0 database, so there is one definition of schema v1 and
-- nothing for an upgraded file to drift away from.
--
-- Every timestamp is INTEGER unix seconds, not the text the v0 schema used:
-- text timestamps sort correctly but cost a parse on every comparison, and the
-- prune and the 24-hour rollup reads compare timestamps constantly.

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
  -- only key: 'pause_until' (unix secs; absent/0 = not paused)

CREATE TABLE sources (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('hosts','domains','adblock')),
  enabled INTEGER NOT NULL DEFAULT 1,
  etag TEXT, last_modified TEXT, last_fetched_at INTEGER, last_ok_at INTEGER,
  rule_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, note TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE devices (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, ip_address TEXT NOT NULL UNIQUE,
  filtering INTEGER NOT NULL DEFAULT 1,      -- 0 = bypass: resolve everything, still logged
  all_lists INTEGER NOT NULL DEFAULT 1,      -- 0 = only device_lists rows apply
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE device_lists (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  PRIMARY KEY (device_id, source_id));

CREATE TABLE rules (
  id INTEGER PRIMARY KEY, domain TEXT NOT NULL,           -- normalized, no leading '*.'
  action TEXT NOT NULL CHECK (action IN ('allow','block')),
  device_id TEXT REFERENCES devices(id) ON DELETE CASCADE, -- NULL = everyone
  created_at INTEGER NOT NULL);
CREATE UNIQUE INDEX rules_unique ON rules (domain, COALESCE(device_id, ''));

-- No index on query_log, per spec section 2.1, which leaves `rules_unique` above
-- as the only index in this file. `id` is the rowid and the log is append-only
-- in timestamp order, so the table's own order already is the (ts, id) order
-- every read wants: paging is newest-first from the end, pruning is oldest-first
-- from the start, and both stop as soon as they have what they came for.
--
-- Measured before deciding: with `query_log_ts ON query_log (ts)` and
-- `query_log_client_id ON query_log (client, id)` present, EXPLAIN QUERY PLAN on
-- the client-filtered page still reports `SCAN q`, because `(?2 IS NULL OR
-- q.client = ?2)` is not sargable; the page took 0.6 ms either way on a
-- 250,000-row log. The two measured 42 B per row between them -- three
-- quarters of what the row itself costs -- which at the 250,000-row cap is
-- 10 MB of index on a Raspberry Pi's SD card to accelerate scans that already
-- exit early. The one read that groups rather than pages, the Overview's
-- top-ten, bounds itself to the window's rows by rowid and is memoized for
-- 60 s; a covering (ts, domain) index measured no faster than that bound and
-- cost 8.7 MB at the 250,000-row cap.
CREATE TABLE query_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL,
  qtype INTEGER NOT NULL, blocked INTEGER NOT NULL, reason INTEGER NOT NULL, list TEXT);

CREATE TABLE query_stats_hourly (
  hour INTEGER NOT NULL, client TEXT NOT NULL,            -- client '' = all devices
  queries INTEGER NOT NULL, blocked INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (hour, client));
PRAGMA user_version = 1;
