ALTER TABLE devices
ADD COLUMN service_overrides_json TEXT NOT NULL DEFAULT '[]';
