ALTER TABLE devices
ADD COLUMN protection_override TEXT NOT NULL DEFAULT 'inherit';
