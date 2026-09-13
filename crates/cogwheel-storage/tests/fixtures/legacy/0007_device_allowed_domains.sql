ALTER TABLE devices
ADD COLUMN allowed_domains_json TEXT NOT NULL DEFAULT '[]';
