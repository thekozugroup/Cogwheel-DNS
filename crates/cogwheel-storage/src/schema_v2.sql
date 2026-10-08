-- Cogwheel schema v2 step: the AI list (ADR 0002). Additive: the seven v1 tables are untouched.
-- Fresh installs run schema_v1.sql then this file, exactly as a v1 upgrade does, so there is one
-- definition of v2. schema_v1.sql stays frozen: v0 upgrades execute it.
-- From v2, `settings` also holds ai_enabled, ai_model, ai_model_price, ai_daily_limit and ai_spend.
-- The OpenRouter key is never stored here: it lives in <data dir>/openrouter.key (mode 0600).
CREATE TABLE ai_verdicts (
  domain            TEXT PRIMARY KEY,   -- normalize_domain form; an exact name, never a suffix
  verdict           TEXT NOT NULL CHECK (verdict IN ('block','allow','ignore')),
  why               TEXT CHECK (why IS NULL OR why IN ('agrees','unsure','limit','contested')),
  choice            TEXT NOT NULL CHECK (choice IN ('block','allow','ignore')),   -- the role answer
  confidence        REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  effect            TEXT CHECK (effect IS NULL OR effect IN ('breaks','works','unsure')),
  effect_confidence REAL CHECK (effect_confidence IS NULL OR (effect_confidence >= 0 AND effect_confidence <= 1)),
  lists             TEXT NOT NULL CHECK (lists IN ('nothing','block','exception')), -- household lists when judged
  site              TEXT,               -- the site load's website; NULLed at HISTORY_DAYS and on Clear log
  conflict_site     TEXT,               -- the other website, for why='contested'; NULLed with site
  rechecks          INTEGER NOT NULL DEFAULT 0 CHECK (rechecks BETWEEN 0 AND 2), -- 0 on every fresh judgement
  model             TEXT NOT NULL,      -- the dated snapshot the response named
  judged_at         INTEGER NOT NULL,   -- unix seconds
  review_after      INTEGER NOT NULL    -- judged_at + 30 days; + min(30, HISTORY_DAYS) days for an
                                        -- ordinary ignore; + 90 days for a contested one
) WITHOUT ROWID;
PRAGMA user_version = 2;
