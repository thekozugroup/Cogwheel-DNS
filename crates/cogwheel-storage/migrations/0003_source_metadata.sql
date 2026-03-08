ALTER TABLE sources ADD COLUMN refresh_interval_minutes INTEGER NOT NULL DEFAULT 60;
ALTER TABLE sources ADD COLUMN profile TEXT NOT NULL DEFAULT 'balanced';
