CREATE TABLE IF NOT EXISTS notification_deliveries (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    domain TEXT NOT NULL,
    device_name TEXT,
    client_ip TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_created_at
    ON notification_deliveries(created_at DESC);
