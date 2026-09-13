CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  ip_address TEXT NOT NULL UNIQUE,
  policy_mode TEXT NOT NULL DEFAULT 'global',
  blocklist_profile_override TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  device_id TEXT,
  device_name TEXT,
  client_ip TEXT NOT NULL,
  domain TEXT NOT NULL,
  classifier_score REAL NOT NULL,
  severity TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id)
);
